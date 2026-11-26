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

/// Where a commit with ballots stands in its repo, as the git side sees
/// it (`GitSide::standings`). The authority keeps the ballots; only the
/// git side has the history, so it is asked which of them can still come
/// to anything.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// No commit of the repo: no ref reaches it (a branch was deleted),
    /// or it never was one. It cannot be served.
    Gone,
    /// A commit of the repo, off the deploy branch's first parents: on
    /// another branch, or brought in by a merge.
    Held,
    /// On the deploy branch, this many first parents from its tip (the
    /// tip is 0), within the walk the served commit is looked for along;
    /// or what a withdrawal falls back to, which a merge can leave off the
    /// tip's first parents: then the place, on the line of commits the
    /// site moved forward to (newest 0), of the one it falls back after.
    Deploy(u32),
}

/// The most commits one `standings` ask may name. The authority's list is
/// shorter (tenancy.rs); a longer ask is answered `Gone` past here.
pub const MAX_STANDINGS: usize = 1_000;

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

/// How many domains one site may have, and so how long a list
/// `set_site_domains` takes: both sides refuse a longer one before doing
/// anything with it.
pub const MAX_SITE_DOMAINS: usize = 8;

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

    /// Turn on site serving for the repo from `root` (phase 3, step 12c:
    /// the authority decides who may, the git side holds the config and
    /// serves). The whole config, so a lost answer is settled by asking
    /// again; the git side refuses a repo it does not hold.
    fn set_site<'a>(&'a self, repo: &'a str, root: String) -> Fut<'a, Reply<Result<(), String>>>;

    /// Name the site's own domains (docs/TENANCY.md, "Custom domains"),
    /// replacing what it had: the whole list, so a lost answer is settled
    /// by asking again. The authority decides who may and charges for it;
    /// the git side refuses a list of more than `MAX_SITE_DOMAINS`
    /// before it reads anything, checks each name, refuses one another
    /// repo holds, and serves a request whose Host is one of them as the
    /// site.
    fn set_site_domains<'a>(&'a self, repo: &'a str, domains: Vec<String>) -> Fut<'a, Reply<Result<(), String>>>;

    /// Would a repo of this name be created? Returns its label. The
    /// authority asks before it charges the creation fee.
    fn check_new_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<String, String>>>;

    /// Create the repo, once the authority has reserved the name and
    /// recorded its owner. Idempotent: a repo that exists already is `Ok`,
    /// so a lost answer is settled by asking again. Only the authority
    /// creates repos, and it holds the name, so an existing repo of that
    /// name is its own earlier call having landed.
    fn create_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<(), String>>>;

    /// Is this a commit of the repo: a commit object, within reach of one
    /// of the repo's refs? A ballot on anything else is refused. The
    /// objects are one store for every repo, so "held" alone was any
    /// blob or tree, and any other repo's commit.
    fn has_commit<'a>(&'a self, repo: &'a str, oid: &'a Oid) -> Fut<'a, Reply<bool>>;

    /// Where each of these commits stands in the repo, in the order asked,
    /// by the key its ballots are stored under (the approved set's keys).
    /// The authority asks when the list of commits it counts ballots for
    /// is full, to choose what leaves it. Read-only.
    fn standings<'a>(&'a self, repo: &'a str, keys: Vec<String>) -> Fut<'a, Reply<Vec<Standing>>>;

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
