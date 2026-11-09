//! The git side's copy of what the authority decides about a repo
//! (docs/CANISTER_SPLIT.md, section 4 and phase 2 step 5): who may push,
//! whether pushes must be signed, and which commits the voters approve.
//! Push authorization and site serving read these and nothing of tenancy,
//! so phase 3 replaces the calls that keep them current with messages and
//! leaves the readers alone.
//!
//! The authority writes them (`tenancy::sync_mirrors`) whenever what they
//! reflect changes: a repo's metadata, or a ballot on one of its commits.
//! Operators are not mirrored: each canister keeps its own.

use crate::store;
use candid::Principal;
use ic_multisig::Subject;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Who may push to a repo: its owner and its writers. Operators may too,
/// by each canister's own list.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PushPolicy {
    pub writers: Vec<Principal>,
    pub require_signed_push: bool,
}

fn push_key(repo: &str) -> String {
    format!("mirror:push:{repo}")
}

fn approved_key(repo: &str) -> String {
    format!("mirror:approved:{repo}")
}

/// Record a repo's push policy. A push token lasts only as long as its
/// minter may write, so when the writers change, the repo's tokens minted
/// by anyone no longer among them (and not an operator, by `is_operator`,
/// the canister's own rule) are revoked.
pub fn set_push_policy(repo: &str, policy: PushPolicy, is_operator: impl Fn(&Principal) -> bool) {
    let prev: Option<PushPolicy> = crate::kv::get_json(&push_key(repo));
    let writers_changed = prev.as_ref().map(|p| &p.writers) != Some(&policy.writers);
    crate::kv::set_json(&push_key(repo), &policy);
    if writers_changed {
        crate::tokens::revoke_unless(repo, |p| is_operator(p) || policy.writers.contains(p));
    }
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
/// served and deploys on push.
pub fn set_approved(repo: &str, approved: Option<Vec<String>>) {
    crate::kv::set_json(&approved_key(repo), &approved);
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
