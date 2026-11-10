//! Everything the authority asks of the git side (docs/CANISTER_SPLIT.md,
//! section 4), as one interface. The git crate implements it; the
//! authority crate holds only this trait, so the compiler refuses any other
//! way across. Phase 3 replaces the implementation with messages.

use crate::deploy::{DeployConfig, EvmDeployConfig};
use crate::oid::Oid;
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
    fn set_deploy_configs(&self, repo: &str, configs: DeployConfigs);

    /// Write the push-policy mirror. The git side revokes the tokens of
    /// writers the policy drops, sparing operators by `is_operator`.
    fn set_push_policy(&self, repo: &str, policy: PushPolicy, is_operator: &dyn Fn(&Principal) -> bool);

    /// Write the approved-commits mirror: the approved commits by ballot
    /// key, or `None` when the repo requires no votes.
    fn set_approved(&self, repo: &str, approved: Option<Vec<String>>);

    /// Would a repo of this name be created? Returns its label. The
    /// authority asks before it charges the creation fee.
    fn check_new_repo(&self, name: &str) -> Result<String, String>;

    /// Create the repo, once the authority has recorded its owner.
    fn create_repo(&self, name: &str) -> Result<(), String>;

    /// Does the git side hold this commit? A ballot on one it does not is
    /// refused.
    fn has_commit(&self, oid: &Oid) -> bool;
}
