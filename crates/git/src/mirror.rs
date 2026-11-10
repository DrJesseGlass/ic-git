//! The git side's copy of what the authority decides about a repo
//! (docs/CANISTER_SPLIT.md, section 4 and phase 2 step 5): who may push,
//! whether pushes must be signed, which commits the voters approve, and
//! (phase 3 step 6) the deploy configs.
//! Push authorization and site serving read these and nothing of tenancy,
//! so phase 3 replaces the calls that keep them current with messages and
//! leaves the readers alone.
//!
//! The authority writes them (its mirrors.rs, for tenancy.rs and
//! configs.rs) whenever what they reflect changes: a repo's metadata, a
//! ballot on one of its commits, or a deploy config.
//! Operators are not mirrored: each canister keeps its own.
//!
//! Each write carries a sequence number from one counter per repo at the
//! authority (phase 3, step 8). A write older than the newest this side
//! holds for that mirror is ignored: a retry that lands after a later write
//! cannot roll the mirror back. The writers below take the number and say
//! whether they applied the write.

use crate::store;
use candid::Principal;
use ic_multisig::Subject;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub use ic_git_types::git_side::{DeployConfigs, PushPolicy};

fn push_key(repo: &str) -> String {
    format!("mirror:push:{repo}")
}

fn deploy_key(repo: &str) -> String {
    format!("mirror:deploy:{repo}")
}

fn approved_key(repo: &str) -> String {
    format!("mirror:approved:{repo}")
}

fn seq_key(repo: &str) -> String {
    format!("mirror:seq:{repo}")
}

/// The newest write each mirror of a repo has taken.
#[derive(Serialize, Deserialize, Default)]
struct Seqs {
    push: Option<u64>,
    approved: Option<u64>,
    deploy: Option<u64>,
}

/// Take a write of `seq` for the mirror `pick` names, unless a newer one
/// landed: then it is stale and `false`.
fn admit(repo: &str, seq: u64, pick: impl Fn(&mut Seqs) -> &mut Option<u64>) -> bool {
    let mut seqs: Seqs = crate::kv::get_json(&seq_key(repo)).unwrap_or_default();
    let held = pick(&mut seqs);
    if held.is_some_and(|h| h >= seq) {
        return false;
    }
    *held = Some(seq);
    crate::kv::set_json(&seq_key(repo), &seqs);
    true
}

/// Record a repo's push policy. A push token lasts only as long as its
/// minter may write, so when the writers change, the repo's tokens minted
/// by anyone no longer among them (and not an operator, by `is_operator`,
/// the canister's own rule) are revoked. Returns whether the write was
/// applied (see `admit`).
pub fn set_push_policy(repo: &str, seq: u64, policy: PushPolicy, is_operator: impl Fn(&Principal) -> bool) -> bool {
    if !admit(repo, seq, |s| &mut s.push) {
        return false;
    }
    let prev: Option<PushPolicy> = crate::kv::get_json(&push_key(repo));
    let writers_changed = prev.as_ref().map(|p| &p.writers) != Some(&policy.writers);
    crate::kv::set_json(&push_key(repo), &policy);
    if writers_changed {
        crate::tokens::revoke_unless(repo, |p| is_operator(p) || policy.writers.contains(p));
    }
    true
}

fn push_policy(repo: &str) -> PushPolicy {
    crate::kv::get_json(&push_key(repo)).unwrap_or_default()
}

/// May `p` push to `repo`? The owner, a writer, or an operator.
pub fn may_write(repo: &str, p: &Principal, operator: bool) -> Result<(), String> {
    if !store::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    if operator || push_policy(repo).writers.contains(p) {
        Ok(())
    } else {
        Err(format!("{p} may not write to repo {repo}"))
    }
}

pub fn requires_signed_push(repo: &str) -> bool {
    push_policy(repo).require_signed_push
}

/// The key a commit's ballots are stored under, which is how the approved
/// set names it: the authority lists approved commits by these keys, since
/// they are what its ballot store holds, and the git side derives the same
/// key for each commit it walks.
pub fn commit_key(oid: &[u8]) -> String {
    Subject::of_short_hash("commit", oid).key()
}

/// Record which commits of a repo reach its vote threshold, by
/// `commit_key`. `None` when the repo requires no votes: then the tip is
/// served and deploys on push. Returns whether the write was applied.
pub fn set_approved(repo: &str, seq: u64, approved: Option<Vec<String>>) -> bool {
    if !admit(repo, seq, |s| &mut s.approved) {
        return false;
    }
    crate::kv::set_json(&approved_key(repo), &approved);
    true
}

/// The approved set, or `None` when the repo requires no votes.
pub fn approved(repo: &str) -> Option<Approved> {
    crate::kv::get_json::<Option<Vec<String>>>(&approved_key(repo))
        .flatten()
        .map(|keys| Approved(keys.into_iter().collect()))
}

/// A repo's approved commits, by `commit_key`.
pub struct Approved(BTreeSet<String>);

impl Approved {
    pub fn contains(&self, oid: &store::Oid) -> bool {
        self.0.contains(&commit_key(oid.as_slice()))
    }
}

/// Empty a repo's mirrors and forget the writes they took: the state a
/// release before the mirrors existed leaves, for tests of the catch-up.
#[cfg(any(test, feature = "testing"))]
pub fn clear(repo: &str) {
    for key in [push_key(repo), approved_key(repo), deploy_key(repo), seq_key(repo)] {
        crate::kv::remove(&key);
    }
}

/// Record a repo's deploy configs, as the authority holds them. Returns
/// whether the write was applied.
pub fn set_deploy_configs(repo: &str, seq: u64, configs: DeployConfigs) -> bool {
    if !admit(repo, seq, |s| &mut s.deploy) {
        return false;
    }
    crate::kv::set_json(&deploy_key(repo), &configs);
    true
}

/// A repo's deploy configs: what a job proves (`jobs::resolve`), whether a
/// push queues one, and which artifact a registry record hashes.
pub fn deploy_configs(repo: &str) -> DeployConfigs {
    crate::kv::get_json(&deploy_key(repo)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A write older than the newest a mirror holds is ignored, each mirror
    /// by its own count, so a retry that lands late cannot roll a mirror
    /// back; a newer one is taken.
    #[test]
    fn an_older_mirror_write_is_ignored() {
        store::create_repo("seq").unwrap();
        let w = Principal::from_slice(&[1; 8]);
        let policy = |writers: &[Principal]| PushPolicy {
            writers: writers.to_vec(),
            require_signed_push: false,
        };
        assert!(set_push_policy("seq", 2, policy(&[w]), |_| false));
        assert!(!set_push_policy("seq", 1, policy(&[]), |_| false), "older");
        assert!(!set_push_policy("seq", 2, policy(&[]), |_| false), "the same write again");
        assert!(may_write("seq", &w, false).is_ok());
        // Another mirror of the repo has its own count: the push policy's
        // 2 does not make an approved set at 1 stale.
        assert!(set_approved("seq", 1, Some(Vec::new())));
        assert!(approved("seq").is_some());
        assert!(!set_approved("seq", 1, None));
        assert!(set_approved("seq", 3, None));
        assert!(approved("seq").is_none());
        assert!(set_deploy_configs("seq", 1, DeployConfigs::default()));
        assert!(!set_deploy_configs("seq", 0, DeployConfigs::default()));
        // A newer push policy is taken, and only the writers it drops lose
        // their tokens, as before.
        assert!(set_push_policy("seq", 3, policy(&[]), |_| false));
        assert!(may_write("seq", &w, false).is_err());
    }
}
