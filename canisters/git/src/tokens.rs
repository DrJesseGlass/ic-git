//! Push tokens: the credential git presents over HTTPS, as the password in
//! the remote URL. A token is 16 random bytes, returned once when minted and
//! stored only as its sha256 (the TOKENS key). Each one authorizes pushes to
//! one repo until it expires or is revoked.
//!
//! Every token expires. The minter picks a lifetime in days (default
//! `DEFAULT_DAYS`, at most `MAX_DAYS`); a leaked token stops working on its
//! own, without anyone noticing the leak. Tokens minted before expiry
//! existed are given `LEGACY_GRACE_DAYS` from the upgrade that introduced it
//! (`migrate_legacy`), so nothing breaks at the upgrade and nothing lives
//! forever.
//!
//! A token's id is the first 16 hex characters of its key. It names the
//! token without being it -- the key is a hash, and the id a prefix of the
//! hash -- so the list of a repo's tokens is public and a writer can revoke
//! one by id without holding the token.

use crate::store;
use crate::tenancy::now_ns;
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

pub const DEFAULT_DAYS: u32 = 30;
pub const MAX_DAYS: u32 = 365;
pub const LEGACY_GRACE_DAYS: u32 = 30;
const DAY_NS: u64 = 86_400 * 1_000_000_000;
/// Hex characters of the key that make up a token's id: 64 bits.
pub const ID_LEN: usize = 16;

/// A TOKENS value. Values written before expiry existed are the bare repo
/// name; repo names cannot start with '{', so the two never collide.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Stored {
    repo: String,
    /// `None` for a legacy token: nobody recorded who minted it, or when.
    minted_by: Option<Principal>,
    created_ns: Option<u64>,
    expires_ns: u64,
}

enum Entry {
    Legacy(String),
    Stored(Stored),
}

fn parse(value: String) -> Entry {
    match serde_json::from_str::<Stored>(&value) {
        Ok(s) => Entry::Stored(s),
        Err(_) => Entry::Legacy(value),
    }
}

fn put(key: &str, s: &Stored) {
    if let Ok(json) = serde_json::to_string(s) {
        store::token_put(key, json);
    }
}

/// A token as a writer sees it: never the token itself.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PushTokenInfo {
    pub id: String,
    pub repo: String,
    pub minted_by: Option<Principal>,
    pub created_ns: Option<u64>,
    pub expires_ns: u64,
}

fn info(key: &str, s: Stored) -> PushTokenInfo {
    PushTokenInfo {
        id: key[..ID_LEN].to_string(),
        repo: s.repo,
        minted_by: s.minted_by,
        created_ns: s.created_ns,
        expires_ns: s.expires_ns,
    }
}

/// Store a freshly minted token for `repo`, valid for `days` (default
/// `DEFAULT_DAYS`). Returns its info. Expired tokens are swept out first, so
/// the map does not grow with every token ever minted.
pub fn mint(repo: &str, token: &str, minted_by: Principal, days: Option<u32>) -> Result<PushTokenInfo, String> {
    let days = days.unwrap_or(DEFAULT_DAYS);
    if days == 0 || days > MAX_DAYS {
        return Err(format!("a push token lives 1 to {MAX_DAYS} days"));
    }
    purge_expired();
    let now = now_ns();
    let key = store::token_key(token);
    let s = Stored {
        repo: repo.to_string(),
        minted_by: Some(minted_by),
        created_ns: Some(now),
        expires_ns: now.saturating_add(u64::from(days) * DAY_NS),
    };
    put(&key, &s);
    Ok(info(&key, s))
}

/// The repo a presented token authorizes right now, if any. An expired
/// token authorizes nothing. A legacy value only exists between an upgrade's
/// install and its post_upgrade, which migrates them all; it is honored
/// rather than refused so that window cannot lock anyone out.
pub fn authorize(token: &str) -> Option<String> {
    match parse(store::token_get(&store::token_key(token))?) {
        Entry::Legacy(repo) => Some(repo),
        Entry::Stored(s) => (now_ns() < s.expires_ns).then_some(s.repo),
    }
}

/// The repo a token belongs to, expired or not: who may revoke it.
pub fn repo_of(token: &str) -> Option<String> {
    Some(match parse(store::token_get(&store::token_key(token))?) {
        Entry::Legacy(repo) => repo,
        Entry::Stored(s) => s.repo,
    })
}

pub fn revoke(token: &str) -> bool {
    store::token_remove(&store::token_key(token))
}

/// The live tokens of `repo`, soonest to expire first.
pub fn list(repo: &str) -> Vec<PushTokenInfo> {
    let now = now_ns();
    let mut out: Vec<PushTokenInfo> = store::token_entries("")
        .into_iter()
        .filter_map(|(key, value)| match parse(value) {
            Entry::Stored(s) if s.repo == repo && now < s.expires_ns => Some(info(&key, s)),
            _ => None,
        })
        .collect();
    out.sort_by_key(|t| t.expires_ns);
    out
}

/// The key and repo of the token with this id. Refused unless it names
/// exactly one token.
pub fn find_id(id: &str) -> Result<(String, String), String> {
    if id.len() != ID_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("a token id is {ID_LEN} hex characters"));
    }
    let mut hits = store::token_entries(&id.to_ascii_lowercase()).into_iter();
    let (key, value) = hits.next().ok_or("no push token with that id")?;
    if hits.next().is_some() {
        return Err("that id names more than one token; revoke it with the token itself".into());
    }
    let repo = match parse(value) {
        Entry::Legacy(repo) => repo,
        Entry::Stored(s) => s.repo,
    };
    Ok((key, repo))
}

pub fn revoke_key(key: &str) -> bool {
    store::token_remove(key)
}

/// Drop every expired token.
pub fn purge_expired() {
    let now = now_ns();
    for (key, value) in store::token_entries("") {
        if matches!(parse(value), Entry::Stored(s) if now >= s.expires_ns) {
            store::token_remove(&key);
        }
    }
}

/// Give every token minted before expiry existed `LEGACY_GRACE_DAYS` from
/// now. For post_upgrade; a no-op once they are all migrated.
pub fn migrate_legacy() {
    let expires_ns = now_ns().saturating_add(u64::from(LEGACY_GRACE_DAYS) * DAY_NS);
    for (key, value) in store::token_entries("") {
        if let Entry::Legacy(repo) = parse(value) {
            put(
                &key,
                &Stored {
                    repo,
                    minted_by: None,
                    created_ns: None,
                    expires_ns,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenancy::set_test_now;

    const T0: u64 = 1_000 * DAY_NS;

    fn alice() -> Principal {
        Principal::from_slice(&[9; 8])
    }

    #[test]
    fn a_token_authorizes_its_repo_until_it_expires() {
        set_test_now(T0);
        let t = mint("exp", "tok-exp", alice(), Some(2)).unwrap();
        assert_eq!(t.expires_ns, T0 + 2 * DAY_NS);
        assert_eq!(t.minted_by, Some(alice()));
        assert_eq!(authorize("tok-exp").as_deref(), Some("exp"));
        set_test_now(T0 + 2 * DAY_NS - 1);
        assert_eq!(authorize("tok-exp").as_deref(), Some("exp"));
        set_test_now(T0 + 2 * DAY_NS);
        assert_eq!(authorize("tok-exp"), None);
        // Still revocable, and gone from the listing.
        assert_eq!(repo_of("tok-exp").as_deref(), Some("exp"));
        assert!(list("exp").is_empty());
        set_test_now(T0);
    }

    #[test]
    fn lifetime_defaults_and_is_bounded() {
        set_test_now(T0);
        let t = mint("life", "tok-life", alice(), None).unwrap();
        assert_eq!(t.expires_ns, T0 + u64::from(DEFAULT_DAYS) * DAY_NS);
        assert!(mint("life", "tok-zero", alice(), Some(0)).is_err());
        assert!(mint("life", "tok-long", alice(), Some(MAX_DAYS + 1)).is_err());
        assert!(mint("life", "tok-max", alice(), Some(MAX_DAYS)).is_ok());
        assert_eq!(authorize("tok-zero"), None);
    }

    #[test]
    fn listing_shows_live_tokens_of_one_repo_by_id() {
        set_test_now(T0);
        let a = mint("lst", "tok-a", alice(), Some(5)).unwrap();
        let b = mint("lst", "tok-b", alice(), Some(1)).unwrap();
        mint("other", "tok-c", alice(), Some(1)).unwrap();
        let ids: Vec<String> = list("lst").into_iter().map(|t| t.id).collect();
        assert_eq!(ids, vec![b.id.clone(), a.id.clone()]);
        assert_eq!(a.id, store::token_key("tok-a")[..ID_LEN]);
        // Revoke by id: the token stops working.
        let (key, repo) = find_id(&a.id).unwrap();
        assert_eq!(repo, "lst");
        assert!(revoke_key(&key));
        assert_eq!(authorize("tok-a"), None);
        assert!(find_id(&a.id).is_err());
        assert!(find_id("not-hex").is_err());
    }

    #[test]
    fn minting_sweeps_expired_tokens() {
        set_test_now(T0);
        mint("swp", "tok-old", alice(), Some(1)).unwrap();
        set_test_now(T0 + 2 * DAY_NS);
        mint("swp", "tok-new", alice(), Some(1)).unwrap();
        assert_eq!(repo_of("tok-old"), None);
        assert_eq!(authorize("tok-new").as_deref(), Some("swp"));
        set_test_now(T0);
    }

    #[test]
    fn legacy_tokens_get_a_grace_period() {
        set_test_now(T0);
        store::token_put(&store::token_key("tok-legacy"), "leg".to_string());
        assert_eq!(authorize("tok-legacy").as_deref(), Some("leg"));
        migrate_legacy();
        let t = list("leg");
        assert_eq!(t.len(), 1);
        assert_eq!((t[0].minted_by, t[0].created_ns), (None, None));
        assert_eq!(t[0].expires_ns, T0 + u64::from(LEGACY_GRACE_DAYS) * DAY_NS);
        // Migrating again changes nothing.
        set_test_now(T0 + DAY_NS);
        migrate_legacy();
        assert_eq!(list("leg")[0].expires_ns, T0 + u64::from(LEGACY_GRACE_DAYS) * DAY_NS);
        set_test_now(T0 + u64::from(LEGACY_GRACE_DAYS) * DAY_NS);
        assert_eq!(authorize("tok-legacy"), None);
        set_test_now(T0);
    }
}
