//! Everything the authority asks of the git side (docs/CANISTER_SPLIT.md,
//! section 4), in one place: phase 3 turns each of these into a message,
//! and an authority module that reaches the git side any other way is a
//! dependency the cut would break.

pub use crate::mirror::PushPolicy;
use ic_git_types::deploy::DeployConfig;
use ic_git_types::oid::Oid;

/// A repo's wasm deploy config, for the policy checks that depend on one
/// (an install mode needs a config to set it on; governing needs it to
/// name a committed .wasm).
pub fn deploy_config(repo: &str) -> Option<DeployConfig> {
    crate::jobs::get_config(repo)
}

/// The push-policy mirror (mirror.rs).
pub fn set_push_policy(repo: &str, policy: crate::mirror::PushPolicy) {
    crate::mirror::set_push_policy(repo, policy)
}

/// The approved-commits mirror (mirror.rs).
pub fn set_approved(repo: &str, approved: Option<Vec<String>>) {
    crate::mirror::set_approved(repo, approved)
}

/// Does the repo exist on the git side?
pub fn repo_exists(repo: &str) -> bool {
    crate::store::repo_exists(repo)
}

/// Would a repo of this name be created? The authority asks before it
/// charges the creation fee.
pub fn check_new_repo(name: &str) -> Result<String, String> {
    crate::store::check_new_repo(name)
}

/// Create the repo, once the authority has recorded its owner.
pub fn create_repo(name: &str) -> Result<(), String> {
    crate::store::create_repo(name)
}

/// Does the git side hold this commit? A ballot on one it does not is
/// refused.
pub fn has_commit(oid: &Oid) -> bool {
    crate::store::has_object(oid)
}

/// The repo holding a label, if any (store.rs indexes them).
pub fn label_holder(label: &str) -> Option<String> {
    crate::store::label_holder(label)
}
