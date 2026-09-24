//! Optional hook into ic-name-service (its DESIGN.md, section 8).
//!
//! After a successful deploy with a wasm leg (and its EVM leg, if the repo
//! has one), tell the name service what was deployed: `announce(name, canister, repo, commit, module_hash)`. The
//! name service trusts the call because THIS canister's principal is on its
//! deployer list, not because of anything in the payload, so there is no
//! secret here and nothing to verify on our side.
//!
//! Off by default. The operator turns it on with `names_set_config`, naming
//! the name service canister and the handle every repo of this instance is
//! announced under: repo "foo" becomes "<handle>/foo". A failed announce is
//! appended to the deploy status message and never fails the deploy.
//!
//! The call runs inside a deploy (the queue, which deploys one job at a
//! time for every repo, or `deploy_now`), so it is a bounded-wait call with
//! `ANNOUNCE_TIMEOUT_S`: a name service that hangs costs one deploy that
//! long, not the queue forever, and cannot hold an open call context that
//! blocks stopping this canister for an upgrade. A timeout leaves the
//! outcome unknown, and the note says so rather than "failed".
//!
//! ic-name-service names are lower kebab case only. The handle is checked
//! against its segment rule (`check_segment`, a copy of ic-name-service's)
//! when it is configured; a repo is announced under its label
//! (`store::repo_label`: "My_App" -> "my-app"), which `create_repo` makes
//! unique across repos, so two repos can never announce the same name. A
//! repo from before labels existed that holds none is skipped with a note.
//!
//! Direction of dependency: nothing here depends on ic-name-service code;
//! the argument record is a candid mirror of its `Announcement` type.

use crate::store;
use candid::{CandidType, Principal};
use ic_cdk::call::{Call, CallFailed, RejectCode};
use serde::{Deserialize, Serialize};

const CONFIG_KEY: &str = "names:config";
/// How long a deploy waits on the name service before giving up.
const ANNOUNCE_TIMEOUT_S: u32 = 60;
/// ic-name-service's MAX_SEGMENT, which repo labels share.
const MAX_SEGMENT: usize = store::MAX_LABEL;

/// ic-name-service's rule for a handle or a label: 1 to 63 bytes of a-z,
/// 0-9 and '-', not starting or ending with '-'.
fn check_segment(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_SEGMENT {
        return Err(format!("{what} must be 1 to {MAX_SEGMENT} bytes"));
    }
    if !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err(format!("{what} may only contain a-z, 0-9 and '-'"));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(format!("{what} may not start or end with '-'"));
    }
    Ok(())
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct NamesConfig {
    /// The ic-name-service canister (text principal).
    pub canister: String,
    /// Handle this instance announces under.
    pub handle: String,
}

/// Mirror of ic-name-service's `Announcement`. `name` is
/// `<handle>/<label>`; `repo` is the repo's own name.
#[derive(CandidType, Deserialize, Clone, Debug)]
struct Announcement {
    name: String,
    canister: Principal,
    repo: String,
    commit: String,
    module_hash: String,
}

pub fn set_config(canister: String, handle: String) -> Result<(), String> {
    Principal::from_text(&canister).map_err(|e| format!("bad names canister principal: {e}"))?;
    check_segment("handle", &handle)?;
    store::meta_set_json(CONFIG_KEY, &Some(NamesConfig { canister, handle }));
    Ok(())
}

pub fn clear_config() {
    store::meta_set_json(CONFIG_KEY, &Option::<NamesConfig>::None);
}

pub fn get_config() -> Option<NamesConfig> {
    store::meta_get_json::<Option<NamesConfig>>(CONFIG_KEY).flatten()
}

/// Announce a successful deploy. Returns a note to append to the deploy
/// status when the hook is configured, None when it is off.
pub async fn announce(repo: &str, target: &str, commit: &str, module_hash: &str) -> Option<String> {
    let cfg = get_config()?;
    let names = match Principal::from_text(&cfg.canister) {
        Ok(p) => p,
        Err(e) => return Some(format!(" (announce skipped: bad names canister: {e})")),
    };
    let canister = match Principal::from_text(target) {
        Ok(p) => p,
        Err(e) => return Some(format!(" (announce skipped: bad target: {e})")),
    };
    let label = match store::repo_label(repo) {
        Ok(l) if store::label_holder(&l).as_deref() == Some(repo) => l,
        Ok(l) => return Some(format!(" (announce skipped: label '{l}' is not held by this repo)")),
        Err(e) => return Some(format!(" (announce skipped: {e})")),
    };
    let name = format!("{}/{}", cfg.handle, label);
    let arg = Announcement {
        name: name.clone(),
        canister,
        repo: repo.to_string(),
        commit: commit.to_string(),
        module_hash: module_hash.to_string(),
    };
    let reply = Call::bounded_wait(names, "announce")
        .with_arg(arg)
        .change_timeout(ANNOUNCE_TIMEOUT_S)
        .await;
    match reply.map(|r| r.candid::<Result<(), String>>()) {
        Ok(Ok(Ok(()))) => Some(format!(" (announced as {name})")),
        Ok(Ok(Err(e))) => Some(format!(" (announce refused: {e})")),
        Ok(Err(e)) => Some(format!(" (announce reply undecodable: {e})")),
        Err(CallFailed::CallRejected(e)) if e.reject_code() == Ok(RejectCode::SysUnknown) => {
            Some(format!(" (announce outcome unknown: {e})"))
        }
        Err(e) => Some(format!(" (announce failed: {e})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_follow_the_name_service_rule() {
        for ok in ["ic-git", "ic-vote", "a", "x1", &"a".repeat(MAX_SEGMENT)] {
            assert!(check_segment("s", ok).is_ok(), "{ok}");
        }
        for bad in ["", "My_App", "app.v2", "Upper", "-lead", "trail-", "a/b", &"a".repeat(MAX_SEGMENT + 1)] {
            assert!(check_segment("s", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn config_refuses_a_handle_the_name_service_would() {
        let names = "aaaaa-aa".to_string();
        assert!(set_config(names.clone(), "Solo".into()).is_err());
        assert!(set_config(names.clone(), "a/b".into()).is_err());
        assert!(set_config("not a principal".into(), "solo".into()).is_err());
        set_config(names.clone(), "solo".into()).unwrap();
        assert_eq!(get_config().unwrap().handle, "solo");
        clear_config();
        assert!(get_config().is_none());
    }
}
