//! The git side's answer to the authority (ic_git_types::git_side): one
//! implementation of the interface, over this crate's store and mirrors.
//! The canister installs it into the authority at init and upgrade.

use crate::{mirror, store};
use candid::Principal;
use ic_git_types::git_side::{DeployConfigs, GitSide, PushPolicy};
use ic_git_types::oid::Oid;

/// This crate, as the authority sees it.
pub struct Git;

impl GitSide for Git {
    fn set_deploy_configs(&self, repo: &str, configs: DeployConfigs) {
        mirror::set_deploy_configs(repo, configs)
    }

    fn set_push_policy(&self, repo: &str, policy: PushPolicy, is_operator: &dyn Fn(&Principal) -> bool) {
        mirror::set_push_policy(repo, policy, is_operator)
    }

    fn set_approved(&self, repo: &str, approved: Option<Vec<String>>) {
        mirror::set_approved(repo, approved)
    }

    fn repo_exists(&self, repo: &str) -> bool {
        store::repo_exists(repo)
    }

    fn check_new_repo(&self, name: &str) -> Result<String, String> {
        store::check_new_repo(name)
    }

    fn create_repo(&self, name: &str) -> Result<(), String> {
        store::create_repo(name)
    }

    fn has_commit(&self, oid: &Oid) -> bool {
        store::has_object(oid)
    }

    fn label_holder(&self, label: &str) -> Option<String> {
        store::label_holder(label)
    }
}
