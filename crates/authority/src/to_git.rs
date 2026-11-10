//! Everything the authority asks of the git side (docs/CANISTER_SPLIT.md,
//! section 4), through one interface (ic_git_types::git_side::GitSide).
//! This crate does not depend on the git side: the canister installs its
//! implementation at init and upgrade, and phase 3 installs one that sends
//! messages instead. The free functions here are what the rest of the
//! authority calls.

use candid::Principal;
use ic_git_types::git_side::{DeployConfigs, GitSide};
pub use ic_git_types::git_side::PushPolicy;
use ic_git_types::oid::Oid;
use std::sync::OnceLock;

static GIT: OnceLock<&'static (dyn GitSide + Sync)> = OnceLock::new();

/// Install the git side. The first installation stands: a canister has one
/// git side for its lifetime.
pub fn install(git: &'static (dyn GitSide + Sync)) {
    let _ = GIT.set(git);
}

fn git() -> &'static dyn GitSide {
    if let Some(g) = GIT.get() {
        return *g;
    }
    // Tests, here and in the crates that test against this one, run against
    // the real git side without installing it.
    #[cfg(any(test, feature = "testing"))]
    {
        &ic_git_git::for_authority::Git
    }
    #[cfg(not(any(test, feature = "testing")))]
    {
        panic!("the git side is not installed (the canister installs it at init and post_upgrade)")
    }
}

/// The deploy-config mirror (configs.rs owns the configs).
pub fn set_deploy_configs(repo: &str, configs: DeployConfigs) {
    git().set_deploy_configs(repo, configs)
}

/// The push-policy mirror. Operators, by the authority's rule, keep their
/// tokens when the writers change.
pub fn set_push_policy(repo: &str, policy: PushPolicy) {
    git().set_push_policy(repo, policy, &|p: &Principal| crate::tenancy::is_operator(p))
}

/// The approved-commits mirror.
pub fn set_approved(repo: &str, approved: Option<Vec<String>>) {
    git().set_approved(repo, approved)
}

/// Does the repo exist on the git side?
pub fn repo_exists(repo: &str) -> bool {
    git().repo_exists(repo)
}

/// Would a repo of this name be created? The authority asks before it
/// charges the creation fee.
pub fn check_new_repo(name: &str) -> Result<String, String> {
    git().check_new_repo(name)
}

/// Create the repo, once the authority has recorded its owner.
pub fn create_repo(name: &str) -> Result<(), String> {
    git().create_repo(name)
}

/// Does the git side hold this commit?
pub fn has_commit(oid: &Oid) -> bool {
    git().has_commit(oid)
}

/// The repo holding a label, if any.
pub fn label_holder(label: &str) -> Option<String> {
    git().label_holder(label)
}
