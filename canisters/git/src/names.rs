//! Optional hook into ic-name-service (its DESIGN.md, section 8).
//!
//! After a successful wasm install, tell the name service what was
//! deployed: `announce(name, canister, repo, commit, module_hash)`. The
//! name service trusts the call because THIS canister's principal is on its
//! deployer list, not because of anything in the payload, so there is no
//! secret here and nothing to verify on our side.
//!
//! Off by default. The operator turns it on with `names_set_config`, naming
//! the name service canister and the handle every repo of this instance is
//! announced under: repo "foo" becomes "<handle>/foo". A failed announce is
//! appended to the deploy status message and never fails the deploy.
//!
//! Direction of dependency: nothing here depends on ic-name-service code;
//! the argument record is a candid mirror of its `Announcement` type.

use crate::kv;
use candid::{CandidType, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};

const CONFIG_KEY: &str = "names:config";

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct NamesConfig {
    /// The ic-name-service canister (text principal).
    pub canister: String,
    /// Handle this instance announces under.
    pub handle: String,
}

/// Mirror of ic-name-service's `Announcement`.
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
    if handle.is_empty() || handle.contains('/') {
        return Err("handle must be non-empty and contain no '/'".into());
    }
    kv::set_json(CONFIG_KEY, &NamesConfig { canister, handle });
    Ok(())
}

pub fn clear_config() {
    kv::set_json(CONFIG_KEY, &Option::<NamesConfig>::None);
}

pub fn get_config() -> Option<NamesConfig> {
    kv::get_json(CONFIG_KEY)
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
    let name = format!("{}/{}", cfg.handle, repo);
    let arg = Announcement {
        name: name.clone(),
        canister,
        repo: repo.to_string(),
        commit: commit.to_string(),
        module_hash: module_hash.to_string(),
    };
    match intercanister::call::<(Announcement,), (Result<(), String>,)>(names, "announce", (arg,))
        .await
    {
        Ok((Ok(()),)) => Some(format!(" (announced as {name})")),
        Ok((Err(e),)) => Some(format!(" (announce refused: {e})")),
        Err(e) => Some(format!(" (announce failed: {e})")),
    }
}
