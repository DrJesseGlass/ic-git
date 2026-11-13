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

use crate::deploy::{DeployConfig, EvmDeployConfig, Job};
use crate::oid::Oid;
use crate::proof::Artifact;
use crate::side::{Fut, Reply};
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

/// Who may push to a repo: its owner and its writers. Operators may too,
/// by each canister's own rule.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct PushPolicy {
    pub writers: Vec<Principal>,
    pub require_signed_push: bool,
}

/// A repo's deploy configs, as the authority holds them (phase 3, step 6):
/// the git side mirrors them to know which paths a job proves.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DeployConfigs {
    pub wasm: Option<DeployConfig>,
    pub evm: Option<EvmDeployConfig>,
}

/// A ballot's ask, carried on the approved set's write (phase 3, step 9):
/// retry the served commit's deploy, unless the app runs it already.
/// `running` is what the authority's app runs as far as its deploys say:
/// the commit every configured leg last deployed successfully, the wasm
/// leg's into the target configured now; `None` when a leg failed, never
/// ran, or the legs disagree, and then whatever is served is retried.
/// Which commit is served only the git side knows, so it makes the
/// comparison; the authority still checks the job it is handed.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Retry {
    pub running: Option<String>,
}

/// Which registry record the authority asks the git side to resolve
/// (phase 3, step 10: `record_artifact`).
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum RecordKind {
    /// The served site's entrypoint: the site root, or its `index.html`,
    /// in the commit the site serves. Which file that is the git side
    /// says, since it holds the site config.
    Site,
    /// The release commit's EVM artifact at `path`, the source path of the
    /// authority's own EVM deploy config.
    Release { path: String },
}

/// A record's artifact as the git side resolves it: the commit (40 hex
/// digits), the path within it, and the blob with its proof. The authority
/// checks the proof against the commit and the path, requires the commit to
/// be approved when the repo requires votes, and hashes the blob itself.
#[derive(CandidType, Deserialize)]
pub struct Attested {
    pub commit: String,
    pub path: String,
    pub artifact: Artifact,
}

/// `deploy_now`'s job (phase 3, step 10: `release_job`): the release
/// commit (40 hex digits) and its job, built as the push path builds one.
/// The authority runs it as it runs any job: its own configs, its own
/// ballots, and only the bytes the proofs show.
#[derive(CandidType, Deserialize)]
pub struct Release {
    pub commit: String,
    pub job: Job,
}

pub trait GitSide {
    /// Write the deploy-config mirror: the repo's configs as the authority
    /// holds them.
    fn set_deploy_configs<'a>(&'a self, repo: &'a str, seq: u64, configs: DeployConfigs) -> Fut<'a, Reply<()>>;

    /// Write the push-policy mirror. The git side revokes the tokens of
    /// writers the policy drops, sparing operators by its own rule.
    fn set_push_policy<'a>(&'a self, repo: &'a str, seq: u64, policy: PushPolicy) -> Fut<'a, Reply<()>>;

    /// Write the approved-commits mirror: the approved commits by ballot
    /// key, or `None` when the repo requires no votes. A write it takes
    /// makes the git side follow the approvals (phase 3, step 9): it
    /// records what the repo now serves and, when that moved -- or on a
    /// `retry`, when it did not and the app does not run it -- submits
    /// the served commit's job. A ballot sends the `Retry`, so voters can
    /// get an app whose deploy failed back in step with the site; the
    /// authority drops a job for a commit the app already runs or a
    /// deploy of which is queued.
    fn set_approved<'a>(&'a self, repo: &'a str, seq: u64, approved: Option<Vec<String>>, retry: Option<Retry>) -> Fut<'a, Reply<()>>;

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

    /// The artifact behind a registry record, with its proof (phase 3,
    /// step 10). The git side picks the commit -- the release commit, which
    /// with votes required is the approved commit the site serves -- and,
    /// for the site, the entrypoint; it refuses an entrypoint it would not
    /// serve, or that the record could not cover. Read-only, so a lost
    /// answer is settled by asking again.
    fn record_artifact<'a>(&'a self, repo: &'a str, kind: RecordKind) -> Fut<'a, Reply<Result<Attested, String>>>;

    /// The release commit's job, for `deploy_now` (phase 3, step 10).
    /// Read-only, like `record_artifact`.
    fn release_job<'a>(&'a self, repo: &'a str) -> Fut<'a, Reply<Result<Release, String>>>;
}
