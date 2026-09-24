//! Push tokens: the credential git presents over HTTPS, as the password in
//! the remote URL. A token is 16 random bytes, returned once when minted and
//! stored only as its sha256 (the TOKENS key). Each one authorizes pushes to
//! one repo until it expires or is revoked.
//!
//! Every token expires. The minter picks a lifetime in days (default
//! `DEFAULT_DAYS`, at most `MAX_DAYS`); a leaked token stops working on its
//! own, without anyone noticing the leak. Tokens minted before expiry
//! existed are given `LEGACY_GRACE_DAYS` from the upgrade that introduced it
//! (`migrate`), so nothing breaks at the upgrade and nothing lives forever.
//!
//! A token lasts only as long as its minter may write: when a writer is
//! removed, demoted, or hands the repo on, `revoke_unless` drops the tokens
//! they minted (legacy tokens record no minter and run out their grace).
//!
//! TOKENS is keyed by hash, which is what a push presents. The TOKEN_INDEX
//! map adds two secondary keys per record, `r\0<repo>\0<key>` and
//! `e\0<expires_ns, 20 digits>\0<key>`, so listing a repo and sweeping
//! the expired are range reads, not scans of every token on the canister.
//! Every write goes through `store_record` and `remove_key`, which keep the
//! two in step.
//!
//! Nothing here reads an amount of the map that one tenant controls in a
//! single message. A repo holds at most `MAX_LIVE_PER_REPO` live tokens, so
//! the map is bounded by the number of repos (each paid for); a sweep
//! removes at most `PURGE_BATCH` expired tokens per mint, which outpaces the
//! one token a mint adds; and the full scan in `migrate` runs once, on the
//! upgrade that introduces the record format, over the legacy tokens that
//! existed then.
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
/// Live tokens one repo may hold at once. A person needs a handful (a
/// laptop, CI, a deploy script); the cap is what keeps one tenant from
/// growing the shared map without bound.
pub const MAX_LIVE_PER_REPO: usize = 20;
/// Expired tokens one sweep removes at most.
const PURGE_BATCH: usize = 64;
/// META key recording that `migrate` has run.
const MIGRATED_KEY: &str = "tokens:migrated";

/// A TOKENS value. Values written before expiry existed are the bare repo
/// name; repo names cannot start with '{', so the first byte tells the two
/// apart.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Stored {
    repo: String,
    /// `None` for a legacy token: nobody recorded who minted it, or when.
    minted_by: Option<Principal>,
    created_ns: Option<u64>,
    expires_ns: u64,
    /// The SSH public key the token is bound to (canonical
    /// `ssh-ed25519 <base64>`), if any: a push with the token must then
    /// carry a certificate that key signed (signed_push.rs).
    #[serde(default)]
    key: Option<String>,
}

enum Entry {
    Legacy(String),
    Stored(Stored),
    /// A record that does not decode. It authorizes nothing, and is never
    /// mistaken for a legacy repo name (which would authorize forever).
    Unreadable,
}

impl Entry {
    /// The repo this entry belongs to, expired or not.
    fn repo(self) -> Option<String> {
        match self {
            Entry::Legacy(repo) | Entry::Stored(Stored { repo, .. }) => Some(repo),
            Entry::Unreadable => None,
        }
    }
}

fn parse(value: String) -> Entry {
    if !value.starts_with('{') {
        return Entry::Legacy(value);
    }
    serde_json::from_str::<Stored>(&value).map_or(Entry::Unreadable, Entry::Stored)
}

fn repo_prefix(repo: &str) -> (String, String) {
    (format!("r\0{repo}\0"), format!("r\0{repo}\x01"))
}

fn index_keys(key: &str, s: &Stored) -> [String; 2] {
    [
        format!("{}{key}", repo_prefix(&s.repo).0),
        format!("e\0{:020}\0{key}", s.expires_ns),
    ]
}

/// The TOKENS key at the end of an index key.
fn key_of(index_key: &str) -> &str {
    index_key.rsplit('\0').next().unwrap_or_default()
}

/// Write a record and its index entries.
fn store_record(key: &str, s: &Stored) {
    if let Ok(json) = serde_json::to_string(s) {
        store::token_put(key, json);
        for k in index_keys(key, s) {
            store::token_index_put(k);
        }
    }
}

/// Remove a record and its index entries.
fn remove_key(key: &str) -> bool {
    if let Some(Entry::Stored(s)) = store::token_get(key).map(parse) {
        for k in index_keys(key, &s) {
            store::token_index_remove(&k);
        }
    }
    store::token_remove(key)
}

fn stored(key: &str) -> Option<Stored> {
    match parse(store::token_get(key)?) {
        Entry::Stored(s) => Some(s),
        _ => None,
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
    /// The bound SSH public key, if any. Public, like the rest of this.
    pub key: Option<String>,
}

fn info(key: &str, s: Stored) -> PushTokenInfo {
    PushTokenInfo {
        id: key[..ID_LEN].to_string(),
        repo: s.repo,
        minted_by: s.minted_by,
        created_ns: s.created_ns,
        expires_ns: s.expires_ns,
        key: s.key,
    }
}

/// A requested lifetime in days: `DEFAULT_DAYS` when unset, refused outside
/// 1..=`MAX_DAYS`.
pub fn lifetime(days: Option<u32>) -> Result<u32, String> {
    match days.unwrap_or(DEFAULT_DAYS) {
        d @ 1..=MAX_DAYS => Ok(d),
        _ => Err(format!("a push token lives 1 to {MAX_DAYS} days")),
    }
}

/// The canonical form of a key to bind, refused unless it is an
/// ssh-ed25519 public key.
pub fn bindable_key(key: Option<&str>) -> Result<Option<String>, String> {
    key.map(|k| crate::signed_push::parse_public_key(k).map(|k| k.text)).transpose()
}

/// Store a freshly minted token for `repo`, valid for `days` (default
/// `DEFAULT_DAYS`), bound to the SSH public key `key` if one is given.
/// Returns its info. Expired tokens are swept out first, so the map does
/// not grow with every token ever minted.
pub fn mint(
    repo: &str,
    token: &str,
    minted_by: Principal,
    days: Option<u32>,
    key: Option<&str>,
) -> Result<PushTokenInfo, String> {
    let days = lifetime(days)?;
    let key = bindable_key(key)?;
    purge_expired();
    check_room(repo)?;
    let now = now_ns();
    let s = Stored {
        repo: repo.to_string(),
        minted_by: Some(minted_by),
        created_ns: Some(now),
        expires_ns: now.saturating_add(u64::from(days) * DAY_NS),
        key,
    };
    let id = store::token_key(token);
    store_record(&id, &s);
    Ok(info(&id, s))
}

/// What a token lets its holder do: push to `repo`, and only with a
/// certificate `key` signed when it is bound.
#[derive(Clone, Debug, PartialEq)]
pub struct Grant {
    pub repo: String,
    pub key: Option<String>,
}

/// What a presented token authorizes right now, if anything. An expired
/// token authorizes nothing, and neither does one whose minter fails
/// `may_write(repo, minter)`: a token lasts only as long as its minter may
/// write, however that access was lost (a membership change, or an operator
/// leaving the allowlist). A legacy value is honored only until `migrate`
/// has run; one written after that (by a rolled-back wasm) would otherwise
/// authorize forever, unlisted and unswept.
pub fn authorize_if(token: &str, may_write: impl Fn(&str, &Principal) -> bool) -> Option<Grant> {
    match parse(store::token_get(&store::token_key(token))?) {
        Entry::Stored(s) => (now_ns() < s.expires_ns
            && s.minted_by.as_ref().is_none_or(|p| may_write(&s.repo, p)))
        .then_some(Grant { repo: s.repo, key: s.key }),
        Entry::Legacy(repo) => (!migrated()).then_some(Grant { repo, key: None }),
        Entry::Unreadable => None,
    }
}

/// The repo `authorize_if` grants, with every minter still a writer.
#[cfg(test)]
pub fn authorize(token: &str) -> Option<String> {
    authorize_if(token, |_, _| true).map(|g| g.repo)
}

/// The repo a token belongs to, expired or not: who may revoke it.
pub fn repo_of(token: &str) -> Option<String> {
    parse(store::token_get(&store::token_key(token))?).repo()
}

pub fn revoke(token: &str) -> bool {
    remove_key(&store::token_key(token))
}

/// Refused when `repo` already holds `MAX_LIVE_PER_REPO` live tokens.
/// `create_push_token` asks before paying for randomness; `mint` asks again.
pub fn check_room(repo: &str) -> Result<(), String> {
    let now = now_ns();
    let live = of_repo(repo).iter().filter(|(_, s)| now < s.expires_ns).count();
    if live >= MAX_LIVE_PER_REPO {
        return Err(format!(
            "{repo} already has {MAX_LIVE_PER_REPO} live push tokens; revoke one first"
        ));
    }
    Ok(())
}

/// Every token of `repo`, expired or not, as (key, record). Bounded: the
/// repo's live tokens are capped, and its expired ones are swept.
fn of_repo(repo: &str) -> Vec<(String, Stored)> {
    let (start, end) = repo_prefix(repo);
    store::token_index_range(&start, &end, usize::MAX)
        .iter()
        .filter_map(|ik| {
            let key = key_of(ik);
            stored(key).map(|s| (key.to_string(), s))
        })
        .collect()
}

/// The live tokens of `repo`, soonest to expire first.
pub fn list(repo: &str) -> Vec<PushTokenInfo> {
    let now = now_ns();
    let mut out: Vec<PushTokenInfo> = of_repo(repo)
        .into_iter()
        .filter(|(_, s)| now < s.expires_ns)
        .map(|(key, s)| info(&key, s))
        .collect();
    out.sort_by_key(|t| t.expires_ns);
    out
}

/// Revoke every token of `repo` whose minter fails `keep`: for after a
/// membership change, with `keep` asking whether the minter may still
/// write. Legacy tokens have no minter and are left to expire. Returns how
/// many were revoked.
pub fn revoke_unless(repo: &str, keep: impl Fn(&Principal) -> bool) -> usize {
    of_repo(repo)
        .into_iter()
        .filter(|(_, s)| s.minted_by.as_ref().is_some_and(|p| !keep(p)))
        .filter(|(key, _)| remove_key(key))
        .count()
}

/// Refused unless `id` has the shape of a token id.
pub fn check_id(id: &str) -> Result<(), String> {
    if id.len() != ID_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("a token id is {ID_LEN} hex characters"));
    }
    Ok(())
}

/// The key and repo of the token with this id. Refused unless it names
/// exactly one token.
pub fn find_id(id: &str) -> Result<(String, String), String> {
    check_id(id)?;
    let mut hits = store::token_entries(&id.to_ascii_lowercase()).into_iter();
    let (key, value) = hits.next().ok_or("no push token with that id")?;
    if hits.next().is_some() {
        return Err("that id names more than one token; revoke it with the token itself".into());
    }
    let repo = parse(value).repo().ok_or("that push token's record is unreadable")?;
    Ok((key, repo))
}

pub fn revoke_key(key: &str) -> bool {
    remove_key(key)
}

/// Drop up to `PURGE_BATCH` expired tokens, oldest expiry first, read off
/// the front of the expiry index. Run on every mint; a backlog drains over
/// several mints rather than in one message.
pub fn purge_expired() {
    let end = format!("e\0{:020}", now_ns().saturating_add(1));
    for ik in store::token_index_range("e\0", &end, PURGE_BATCH) {
        remove_key(key_of(&ik));
        // Drop the entry itself too, in case it outlived its record: a stale
        // entry left here would hold a slot of every later sweep.
        store::token_index_remove(&ik);
    }
}

/// Has `migrate` run on this canister?
fn migrated() -> bool {
    store::meta_get_json::<bool>(MIGRATED_KEY) == Some(true)
}

/// For post_upgrade: give every token minted before expiry existed
/// `LEGACY_GRACE_DAYS` from now, and index every record. Runs once: the
/// scan covers the legacy tokens of the upgrade that introduces the record
/// format, and every later upgrade finds the marker and returns.
pub fn migrate() {
    if migrated() {
        return;
    }
    let expires_ns = now_ns().saturating_add(u64::from(LEGACY_GRACE_DAYS) * DAY_NS);
    for (key, value) in store::token_entries("") {
        match parse(value) {
            Entry::Legacy(repo) => store_record(
                &key,
                &Stored {
                    repo,
                    minted_by: None,
                    created_ns: None,
                    expires_ns,
                    key: None,
                },
            ),
            Entry::Stored(s) => {
                for k in index_keys(&key, &s) {
                    store::token_index_put(k);
                }
            }
            Entry::Unreadable => {}
        }
    }
    store::meta_set_json(MIGRATED_KEY, &true);
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
        let t = mint("exp", "tok-exp", alice(), Some(2), None).unwrap();
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
        let t = mint("life", "tok-life", alice(), None, None).unwrap();
        assert_eq!(t.expires_ns, T0 + u64::from(DEFAULT_DAYS) * DAY_NS);
        assert!(mint("life", "tok-zero", alice(), Some(0), None).is_err());
        assert!(mint("life", "tok-long", alice(), Some(MAX_DAYS + 1), None).is_err());
        assert!(mint("life", "tok-max", alice(), Some(MAX_DAYS), None).is_ok());
        assert_eq!(authorize("tok-zero"), None);
    }

    #[test]
    fn listing_shows_live_tokens_of_one_repo_by_id() {
        set_test_now(T0);
        let a = mint("lst", "tok-a", alice(), Some(5), None).unwrap();
        let b = mint("lst", "tok-b", alice(), Some(1), None).unwrap();
        mint("other", "tok-c", alice(), Some(1), None).unwrap();
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
        mint("swp", "tok-old", alice(), Some(1), None).unwrap();
        set_test_now(T0 + 2 * DAY_NS);
        mint("swp", "tok-new", alice(), Some(1), None).unwrap();
        assert_eq!(repo_of("tok-old"), None);
        assert_eq!(authorize("tok-new").as_deref(), Some("swp"));
        set_test_now(T0);
    }

    fn bob() -> Principal {
        Principal::from_slice(&[10; 8])
    }

    /// The index follows every write: a repo lists only its own tokens, a
    /// revoked token leaves no index entry behind, and the sweep removes
    /// exactly the expired ones.
    #[test]
    fn the_index_follows_mint_revoke_and_sweep() {
        set_test_now(T0);
        mint("idx", "tok-1", alice(), Some(1), None).unwrap();
        mint("idx", "tok-2", alice(), Some(3), None).unwrap();
        mint("idx-other", "tok-3", alice(), Some(1), None).unwrap();
        assert_eq!(list("idx").len(), 2);
        assert_eq!(list("idx-other").len(), 1);
        assert!(revoke("tok-2"));
        assert_eq!(list("idx").len(), 1);
        assert_eq!(store::token_index_range("", "\u{7f}", usize::MAX).len(), 4);
        set_test_now(T0 + DAY_NS);
        purge_expired();
        assert_eq!(repo_of("tok-1"), None);
        assert_eq!(repo_of("tok-3"), None);
        assert!(store::token_index_range("", "\u{7f}", usize::MAX).is_empty());
        set_test_now(T0);
    }

    /// A membership change revokes the tokens of minters who may no longer
    /// write; others' tokens, and legacy tokens with no minter, stay.
    #[test]
    fn revoke_unless_drops_only_the_named_minters_tokens() {
        set_test_now(T0);
        mint("mem", "tok-alice", alice(), Some(5), None).unwrap();
        mint("mem", "tok-bob", bob(), Some(5), None).unwrap();
        mint("mem-other", "tok-alice-2", alice(), Some(5), None).unwrap();
        store::token_put(&store::token_key("tok-old"), "mem".to_string());
        migrate();
        assert_eq!(revoke_unless("mem", |p| *p != alice()), 1);
        assert_eq!(authorize("tok-alice"), None);
        assert_eq!(authorize("tok-bob").as_deref(), Some("mem"));
        assert_eq!(authorize("tok-old").as_deref(), Some("mem"));
        // Another repo's token by the same minter is untouched.
        assert_eq!(authorize("tok-alice-2").as_deref(), Some("mem-other"));
    }

    /// Against the real write rule: removing a writer, demoting one to
    /// voter, and transferring the repo each revoke the tokens of whoever
    /// lost write access, and only theirs.
    #[test]
    fn losing_write_access_revokes_your_tokens() {
        use crate::tenancy::{self, Role};
        set_test_now(T0);
        let (owner, w1, w2, next) = (alice(), bob(), Principal::from_slice(&[11; 8]), Principal::from_slice(&[12; 8]));
        tenancy::credit(&owner, 10_000_000_000);
        tenancy::create_repo("acl", &owner, false).unwrap();
        tenancy::add_member("acl", &owner, false, w1, Role::Writer).unwrap();
        tenancy::add_member("acl", &owner, false, w2, Role::Writer).unwrap();
        mint("acl", "tok-owner", owner, None, None).unwrap();
        mint("acl", "tok-w1", w1, None, None).unwrap();
        mint("acl", "tok-w2", w2, None, None).unwrap();
        let sweep = || revoke_unless("acl", |p| tenancy::can_write("acl", p, false).is_ok());

        tenancy::remove_member("acl", &owner, false, w1).unwrap();
        assert_eq!(sweep(), 1);
        assert_eq!(authorize("tok-w1"), None);

        tenancy::add_member("acl", &owner, false, w2, Role::Voter).unwrap();
        assert_eq!(sweep(), 1);
        assert_eq!(authorize("tok-w2"), None);

        assert_eq!(authorize("tok-owner").as_deref(), Some("acl"));
        tenancy::transfer_repo("acl", &owner, false, next).unwrap();
        assert_eq!(sweep(), 1);
        assert_eq!(authorize("tok-owner"), None);
    }

    /// A repo holds at most MAX_LIVE_PER_REPO live tokens; revoking one or
    /// letting one expire makes room again, and other repos are unaffected.
    #[test]
    fn live_tokens_per_repo_are_capped() {
        set_test_now(T0);
        for i in 0..MAX_LIVE_PER_REPO {
            mint("cap", &format!("tok-cap-{i}"), alice(), Some(1 + (i == 0) as u32 * 9), None).unwrap();
        }
        let err = mint("cap", "tok-over", alice(), None, None).unwrap_err();
        assert!(err.contains("revoke one first"), "{err}");
        assert!(check_room("cap").is_err());
        assert!(mint("cap-other", "tok-elsewhere", alice(), None, None).is_ok());
        assert!(revoke("tok-cap-1"));
        assert!(mint("cap", "tok-over", alice(), None, None).is_ok());
        // All but tok-cap-0 expire after a day, which frees their slots.
        set_test_now(T0 + DAY_NS);
        assert!(check_room("cap").is_ok());
        assert!(mint("cap", "tok-later", alice(), None, None).is_ok());
        set_test_now(T0);
    }

    /// A sweep removes at most PURGE_BATCH expired tokens, oldest first; a
    /// backlog drains over several mints.
    #[test]
    fn a_sweep_is_bounded() {
        set_test_now(T0);
        let n = PURGE_BATCH + 10;
        for i in 0..n {
            // Spread over repos to stay under the per-repo cap.
            mint(&format!("sw{}", i / MAX_LIVE_PER_REPO), &format!("tok-sw-{i}"), alice(), Some(1), None).unwrap();
        }
        set_test_now(T0 + DAY_NS);
        purge_expired();
        let left = (0..n).filter(|i| repo_of(&format!("tok-sw-{i}")).is_some()).count();
        assert_eq!(left, 10);
        purge_expired();
        assert!((0..n).all(|i| repo_of(&format!("tok-sw-{i}")).is_none()));
        set_test_now(T0);
    }

    /// The migration's full scan runs once; later upgrades skip it.
    #[test]
    fn migrate_runs_once() {
        set_test_now(T0);
        migrate();
        store::token_put(&store::token_key("tok-late"), "late".to_string());
        migrate();
        // Not rewritten: still the legacy value, and it authorizes nothing.
        assert_eq!(store::token_get(&store::token_key("tok-late")).as_deref(), Some("late"));
        assert_eq!(authorize("tok-late"), None);
    }

    /// A token stops authorizing once its minter may no longer write, even
    /// when no membership change swept it (an operator leaving the allowlist).
    #[test]
    fn a_token_needs_a_minter_who_may_still_write() {
        set_test_now(T0);
        mint("mw", "tok-mw", alice(), None, None).unwrap();
        assert_eq!(authorize_if("tok-mw", |_, p| *p == alice()).map(|g| g.repo).as_deref(), Some("mw"));
        assert_eq!(authorize_if("tok-mw", |_, p| *p != alice()), None);
    }

    /// A token can be bound to an ssh-ed25519 key, which its grant carries
    /// and its listing shows; anything else is refused at mint.
    #[test]
    fn a_token_can_be_bound_to_an_ssh_key() {
        set_test_now(T0);
        const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKX+WM3RHsIaqzeD1rg3zUF4Y9Py92QmWG7n+3f2051F";
        let t = mint("bound", "tok-bound", alice(), None, Some(&format!("{KEY} me@laptop"))).unwrap();
        // Stored canonical: the comment is dropped.
        assert_eq!(t.key.as_deref(), Some(KEY));
        assert_eq!(list("bound")[0].key.as_deref(), Some(KEY));
        let g = authorize_if("tok-bound", |_, _| true).unwrap();
        assert_eq!((g.repo.as_str(), g.key.as_deref()), ("bound", Some(KEY)));
        let plain = authorize_if(&{ mint("bound", "tok-plain", alice(), None, None).unwrap(); "tok-plain".to_string() }, |_, _| true);
        assert_eq!(plain.unwrap().key, None);
        assert!(mint("bound", "tok-rsa", alice(), None, Some("ssh-rsa AAAAB3NzaC1yc2E x")).is_err());
        assert!(authorize("tok-rsa").is_none());
    }

    /// Records written before the index existed are indexed by migrate.
    #[test]
    fn migrate_indexes_unindexed_records() {
        set_test_now(T0);
        let s = Stored { repo: "unidx".into(), minted_by: Some(alice()), created_ns: Some(T0), expires_ns: T0 + DAY_NS, key: None };
        store::token_put(&store::token_key("tok-u"), serde_json::to_string(&s).unwrap());
        assert!(list("unidx").is_empty());
        migrate();
        assert_eq!(list("unidx").len(), 1);
        migrate();
        assert_eq!(list("unidx").len(), 1);
    }

    #[test]
    fn an_unreadable_record_authorizes_nothing() {
        let key = store::token_key("tok-bad");
        store::token_put(&key, "{\"repo\":\"bad\"}".to_string());
        assert_eq!(authorize("tok-bad"), None);
        migrate();
        assert_eq!(store::token_get(&key).as_deref(), Some("{\"repo\":\"bad\"}"));
    }

    #[test]
    fn legacy_tokens_get_a_grace_period() {
        set_test_now(T0);
        store::token_put(&store::token_key("tok-legacy"), "leg".to_string());
        assert_eq!(authorize("tok-legacy").as_deref(), Some("leg"));
        migrate();
        let t = list("leg");
        assert_eq!(t.len(), 1);
        assert_eq!((t[0].minted_by, t[0].created_ns), (None, None));
        assert_eq!(t[0].expires_ns, T0 + u64::from(LEGACY_GRACE_DAYS) * DAY_NS);
        // Migrating again changes nothing.
        set_test_now(T0 + DAY_NS);
        migrate();
        assert_eq!(list("leg")[0].expires_ns, T0 + u64::from(LEGACY_GRACE_DAYS) * DAY_NS);
        set_test_now(T0 + u64::from(LEGACY_GRACE_DAYS) * DAY_NS);
        assert_eq!(authorize("tok-legacy"), None);
        set_test_now(T0);
    }
}
