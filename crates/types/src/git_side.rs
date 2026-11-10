//! Everything the authority asks of the git side (docs/CANISTER_SPLIT.md,
//! section 4), as one interface. The git crate implements it; the
//! authority crate holds only this trait, so the compiler refuses any other
//! way across. Every call is awaited and answers a `Reply` (side.rs): in one
//! canister a plain function behind a ready future, across the cut a
//! message (phase 3, step 8).
//!
//! The mirrors carry a sequence number, one counter per repo at the
//! authority: the git side ignores a write older than the newest it holds
//! for that mirror, so a retry that lands after a later write cannot roll
//! the mirror back. A mirror write is the mirror's whole state, so any one
//! of them can be sent again.

use crate::deploy::{DeployConfig, EvmDeployConfig};
use crate::oid::Oid;
use crate::side::{Fut, Reply};
use candid::Principal;
use serde::{Deserialize, Serialize};

/// Who may push to a repo: its owner and its writers. Operators may too,
/// by each canister's own rule.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PushPolicy {
    pub writers: Vec<Principal>,
    pub require_signed_push: bool,
}

/// A repo's deploy configs, as the authority holds them (phase 3, step 6):
/// the git side mirrors them to know which paths a job proves.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DeployConfigs {
    pub wasm: Option<DeployConfig>,
    pub evm: Option<EvmDeployConfig>,
}

pub trait GitSide {
    /// Write the deploy-config mirror: the repo's configs as the authority
    /// holds them.
    fn set_deploy_configs<'a>(&'a self, repo: &'a str, seq: u64, configs: DeployConfigs) -> Fut<'a, Reply<()>>;

    /// Write the push-policy mirror. The git side revokes the tokens of
    /// writers the policy drops, sparing operators by its own rule.
    fn set_push_policy<'a>(&'a self, repo: &'a str, seq: u64, policy: PushPolicy) -> Fut<'a, Reply<()>>;

    /// Write the approved-commits mirror: the approved commits by ballot
    /// key, or `None` when the repo requires no votes.
    fn set_approved<'a>(&'a self, repo: &'a str, seq: u64, approved: Option<Vec<String>>) -> Fut<'a, Reply<()>>;

    /// Would a repo of this name be created? Returns its label. The
    /// authority asks before it charges the creation fee.
    fn check_new_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<String, String>>>;

    /// Create the repo, once the authority has reserved the name and
    /// recorded its owner. Idempotent: a repo that exists already is `Ok`,
    /// so a lost answer is settled by asking again. Only the authority
    /// creates repos, and it holds the name, so an existing repo of that
    /// name is its own earlier call having landed.
    fn create_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<(), String>>>;

    /// Does the git side hold this commit? A ballot on one it does not is
    /// refused.
    fn has_commit<'a>(&'a self, oid: &'a Oid) -> Fut<'a, Reply<bool>>;
}
