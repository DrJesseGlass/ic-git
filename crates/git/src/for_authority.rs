//! The git side's answer to the authority (ic_git_types::git_side): one
//! implementation of the interface, over this crate's store and mirrors.
//! The canister installs it into the authority at init and upgrade. Each
//! call is a plain function behind a future (phase 3, step 8): in one
//! canister nothing is lost, so every reply is `Ok`. One of them,
//! `set_approved`, tells the authority something back on the way (a job,
//! through the outbox), which in one canister is answered at once too.

use crate::{mirror, store};
use candid::Principal;
use ic_git_types::git_side::{Attested, DeployConfigs, GitSide, PushPolicy, RecordKind, Release, Retry};
use ic_git_types::oid::Oid;
use ic_git_types::side::{ready, Fut, Reply};

/// This crate, as the authority sees it. `is_operator` is this side's own
/// operator rule (operators are not mirrored), which spares an operator's
/// push tokens when a push policy drops them as a writer.
pub struct Git {
    pub is_operator: fn(&Principal) -> bool,
}

impl GitSide for Git {
    fn set_deploy_configs<'a>(&'a self, repo: &'a str, seq: u64, configs: DeployConfigs) -> Fut<'a, Reply<()>> {
        if mirror::set_deploy_configs(repo, seq, configs) {
            // A job built under the old configs would be refused.
            crate::outbox::rebuild_jobs(repo, |commit| {
                let oid = ic_git_types::oid::parse_oid(commit).ok()?;
                Some(crate::jobs::resolve(repo, &oid))
            });
        }
        ready(Ok(()))
    }

    fn set_push_policy<'a>(&'a self, repo: &'a str, seq: u64, policy: PushPolicy) -> Fut<'a, Reply<()>> {
        mirror::set_push_policy(repo, seq, policy, self.is_operator);
        ready(Ok(()))
    }

    /// A write that is taken is followed (jobs::follow_approvals): what
    /// the repo serves is recorded, and its job submitted when that moved
    /// or `retry` says to. A stale write changes nothing, so it moves
    /// nothing either.
    fn set_approved<'a>(&'a self, repo: &'a str, seq: u64, approved: Option<Vec<String>>, retry: Option<Retry>) -> Fut<'a, Reply<()>> {
        Box::pin(async move {
            if mirror::set_approved(repo, seq, approved) {
                crate::jobs::follow_approvals(repo, retry.as_ref()).await;
            }
            Ok(())
        })
    }

    fn check_new_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<String, String>>> {
        ready(Ok(store::check_new_repo(name)))
    }

    /// Idempotent, as the interface requires: the authority holds the name
    /// (tenancy::create_repo reserves it), so a repo of that name is its own
    /// earlier call having landed.
    fn create_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<(), String>>> {
        if store::repo_exists(name) {
            return ready(Ok(Ok(())));
        }
        ready(Ok(store::create_repo(name)))
    }

    fn has_commit<'a>(&'a self, oid: &'a Oid) -> Fut<'a, Reply<bool>> {
        ready(Ok(store::has_object(oid)))
    }

    fn record_artifact<'a>(&'a self, repo: &'a str, kind: RecordKind) -> Fut<'a, Reply<Result<Attested, String>>> {
        ready(Ok(crate::attest::record_artifact(repo, &kind)))
    }

    fn release_job<'a>(&'a self, repo: &'a str) -> Fut<'a, Reply<Result<Release, String>>> {
        ready(Ok(crate::jobs::release(repo)))
    }
}
