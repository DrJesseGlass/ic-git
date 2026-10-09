//! The governor: the ic-git canister's only controller (docs/GOVERNANCE.md,
//! section 5).
//!
//! ic-git cannot move to a new canister id (its threshold signing keys are
//! bound to its principal), so instead of governing itself it is governed
//! by this one: a small canister whose only power is to change the target
//! canister's code or controllers, and only when its approvers have voted
//! for exactly that change under the K-of-N rule ic-git's own voters use
//! (ic-multisig: approvals less objections must reach K).
//!
//! A change is a proposal of one of three kinds:
//!
//! - **Upgrade**: install a module into the target in upgrade mode. The
//!   proposal names the module's sha256, the ic-git commit it is built from
//!   and the install argument; an approver stages the module's bytes here
//!   in chunks, and ballots are accepted only once the staged bytes hash to
//!   the named sha256. Approvers check that hash the way verified.json is
//!   made: rebuild the commit with tools/reproducible-build.sh. After the
//!   install, the target is asked to publish `ic-git#canister` (commit,
//!   module hash) to the registry, so the chain says what ic-git runs.
//! - **Policy**: replace the approvers and the threshold. K is never 0 and
//!   never above N.
//! - **Handover**: make another principal the target's only controller --
//!   a successor governor, or anyone the approvers choose. After it this
//!   canister is inert.
//!
//! A proposal executes the moment a ballot brings it to K. There is no
//! emergency path and no other way in: the governor has no controllers
//! (it is made immutable once installed), so its own rules cannot be
//! changed either, only handed over from.
//!
//! The canister never upgrades, so its state lives on the heap.

use candid::{CandidType, Principal};
use ic_cdk::call::Call;
use ic_multisig::{Approval, Approver, Decision, MemoryStore, Policy, Store, Subject, Tally};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// At most this many proposals open at once, so staged modules cannot fill
/// the heap.
pub const MAX_OPEN: usize = 4;
/// The largest module that can be staged. ic-git's is under 2 MiB gzipped;
/// the IC takes chunked modules up to 100 MiB.
pub const MAX_MODULE_BYTES: usize = 32 << 20;
/// The largest install argument. ic-git's upgrade takes none.
pub const MAX_ARG_BYTES: usize = 64 << 10;
/// The IC caps a policy at ten controllers' worth of approvers by habit;
/// here it bounds the tally loop and the log's size.
pub const MAX_APPROVERS: usize = 16;
/// The management canister's chunk size limit.
const CHUNK_BYTES: usize = 1 << 20;

// --- types on the wire --------------------------------------------------------

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {
    /// The canister this governor controls: ic-git (umobs on mainnet).
    pub target: Principal,
    pub approvers: Vec<Principal>,
    pub threshold: u32,
}

/// What a proposal would do.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Install the module whose sha256 is `module_sha256` (hex) into the
    /// target in upgrade mode, with `arg`. `commit` is the ic-git commit
    /// (40 hex digits) it is built from.
    Upgrade {
        commit: String,
        module_sha256: String,
        arg: Vec<u8>,
    },
    /// Replace the approvers and the threshold.
    Policy {
        approvers: Vec<Principal>,
        threshold: u32,
    },
    /// Make `successor` the target's only controller.
    Handover { successor: Principal },
}

#[derive(CandidType, Clone, Debug)]
pub struct Ballot {
    pub approver: Principal,
    pub decision: Decision,
    pub reason: Option<String>,
    pub at_ns: u64,
}

#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
pub struct Count {
    pub approvals: u32,
    pub objections: u32,
    pub required: u32,
    pub reached: bool,
}

#[derive(CandidType, Clone, Debug)]
pub struct ProposalView {
    pub id: u64,
    pub change: Change,
    pub proposer: Principal,
    pub at_ns: u64,
    /// Upgrade only: bytes staged so far, their sha256, and whether that is
    /// the proposal's module (ballots are taken only then).
    pub staged_bytes: u64,
    pub staged_sha256: String,
    pub ready: bool,
    pub ballots: Vec<Ballot>,
    pub count: Count,
    /// Why the last attempt to execute it failed, if one did.
    pub last_error: Option<String>,
}

#[derive(CandidType, Clone, Debug)]
pub struct StageStatus {
    pub staged_bytes: u64,
    pub staged_sha256: String,
    pub ready: bool,
}

#[derive(CandidType, Clone, Debug)]
pub struct VoteOutcome {
    pub count: Count,
    /// Present when this ballot brought the proposal to K: what executing
    /// it did, or why it failed (it can then be retried with `execute`).
    pub executed: Option<Result<String, String>>,
}

#[derive(CandidType, Clone, Debug)]
pub struct LogEntry {
    pub id: u64,
    pub change: Change,
    pub proposer: Principal,
    pub ballots: Vec<Ballot>,
    pub at_ns: u64,
    /// "executed: ...", or "withdrawn".
    pub outcome: String,
}

#[derive(CandidType, Clone, Debug)]
pub struct Info {
    pub target: Principal,
    pub approvers: Vec<Principal>,
    pub threshold: u32,
    /// Set once a Handover has executed; the governor is inert after it.
    pub handed_over_to: Option<Principal>,
    pub version: String,
}

// --- state ----------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Open,
    Executing,
}

#[derive(Clone, Debug)]
struct Proposal {
    id: u64,
    change: Change,
    proposer: Principal,
    at_ns: u64,
    module: Vec<u8>,
    phase: Phase,
    last_error: Option<String>,
}

struct State {
    me: Principal,
    target: Principal,
    policy: Policy,
    next_id: u64,
    proposals: BTreeMap<u64, Proposal>,
    ballots: MemoryStore,
    log: Vec<LogEntry>,
    handed_over_to: Option<Principal>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(s.borrow_mut().as_mut().expect("initialized")))
}

// --- rules (host-testable) ------------------------------------------------------

/// A policy as the governor accepts it: 1 to MAX_APPROVERS approvers, none
/// anonymous, and a threshold of at least 1 and at most N.
pub fn policy_of(approvers: &[Principal], threshold: u32) -> Result<Policy, String> {
    if approvers.is_empty() || approvers.len() > MAX_APPROVERS {
        return Err(format!("name 1 to {MAX_APPROVERS} approvers"));
    }
    if approvers.contains(&Principal::anonymous()) {
        return Err("the anonymous principal cannot be an approver".into());
    }
    let p = Policy::new(approvers.iter().map(|a| Approver::from(*a)), threshold);
    if threshold == 0 {
        return Err("the threshold must be at least 1".into());
    }
    if threshold as usize > p.approvers.len() {
        return Err(format!(
            "the threshold {threshold} is above the {} approvers",
            p.approvers.len()
        ));
    }
    p.validate().map_err(|e| e.to_string())?;
    Ok(p)
}

/// Lowercase hex of exactly 2 * n digits.
fn hex_of_len(s: &str, n: usize, what: &str) -> Result<Vec<u8>, String> {
    if s.len() != 2 * n || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(format!("{what} must be {} lowercase hex digits", 2 * n));
    }
    hex::decode(s).map_err(|e| e.to_string())
}

/// Refuse a change that could never execute, before anyone votes on it.
pub fn check(change: &Change, target: Principal) -> Result<(), String> {
    match change {
        Change::Upgrade { commit, module_sha256, arg } => {
            hex_of_len(commit, 20, "commit")?;
            hex_of_len(module_sha256, 32, "module_sha256")?;
            if arg.len() > MAX_ARG_BYTES {
                return Err(format!("the install argument is over {MAX_ARG_BYTES} bytes"));
            }
            Ok(())
        }
        Change::Policy { approvers, threshold } => policy_of(approvers, *threshold).map(|_| ()),
        Change::Handover { successor } => {
            if *successor == Principal::anonymous() {
                Err("the successor cannot be the anonymous principal".into())
            } else if *successor == target {
                Err("the target cannot control itself through a handover".into())
            } else {
                Ok(())
            }
        }
    }
}

/// What the ballots on a proposal are cast on: everything that would
/// happen if it executed, bound to this governor, its target and the
/// proposal's id, so a ballot means one change and nothing else.
pub fn subject(me: Principal, target: Principal, id: u64, change: &Change) -> Subject {
    let what = match change {
        Change::Upgrade { commit, module_sha256, arg } => format!(
            "upgrade {commit} {module_sha256} {}",
            hex::encode(Sha256::digest(arg))
        ),
        Change::Policy { approvers, threshold } => {
            let mut a: Vec<String> = approvers.iter().map(|p| p.to_text()).collect();
            a.sort();
            a.dedup();
            format!("policy {threshold} {}", a.join(" "))
        }
        Change::Handover { successor } => format!("handover {successor}"),
    };
    let bytes = format!("ic-git-governor/v1\n{me}\n{target}\n{id}\n{what}");
    Subject::of_bytes("governor", bytes.as_bytes())
}

fn count(t: &Tally) -> Count {
    Count {
        approvals: t.approvals,
        objections: t.objections,
        required: t.required,
        reached: t.reached,
    }
}

fn ballots_view(list: &[Approval]) -> Vec<Ballot> {
    list.iter()
        .filter_map(|a| {
            Some(Ballot {
                approver: a.approver.principal()?,
                decision: a.decision,
                reason: a.reason.clone(),
                at_ns: a.at_ns,
            })
        })
        .collect()
}

impl State {
    fn subject_of(&self, p: &Proposal) -> Subject {
        subject(self.me, self.target, p.id, &p.change)
    }

    fn tally_of(&self, p: &Proposal) -> Tally {
        let s = self.subject_of(p);
        let ballots = ic_multisig::Ballots::assume_checked(&s, self.ballots.load(&s));
        ic_multisig::tally_checked(&self.policy, &s, &ballots)
    }

    fn ready(p: &Proposal) -> bool {
        match &p.change {
            Change::Upgrade { module_sha256, .. } => {
                hex::encode(Sha256::digest(&p.module)) == *module_sha256
            }
            _ => true,
        }
    }

    fn view(&self, p: &Proposal) -> ProposalView {
        let s = self.subject_of(p);
        ProposalView {
            id: p.id,
            change: p.change.clone(),
            proposer: p.proposer,
            at_ns: p.at_ns,
            staged_bytes: p.module.len() as u64,
            staged_sha256: hex::encode(Sha256::digest(&p.module)),
            ready: Self::ready(p),
            ballots: ballots_view(&self.ballots.load(&s)),
            count: count(&self.tally_of(p)),
            last_error: p.last_error.clone(),
        }
    }

    fn require_approver(&self, who: Principal) -> Result<(), String> {
        if self.policy.is_approver(&Approver::from(who)) {
            Ok(())
        } else {
            Err("only an approver of this governor can do that".into())
        }
    }

    fn require_live(&self) -> Result<(), String> {
        match self.handed_over_to {
            Some(s) => Err(format!("the target was handed over to {s}; this governor is inert")),
            None => Ok(()),
        }
    }

    fn open(&mut self, who: Principal, change: Change, now: u64) -> Result<u64, String> {
        self.require_live()?;
        self.require_approver(who)?;
        check(&change, self.target)?;
        if self.proposals.len() >= MAX_OPEN {
            return Err(format!(
                "{MAX_OPEN} proposals are open; execute or withdraw one first"
            ));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.proposals.insert(
            id,
            Proposal {
                id,
                change,
                proposer: who,
                at_ns: now,
                module: Vec::new(),
                phase: Phase::Open,
                last_error: None,
            },
        );
        Ok(id)
    }

    /// Write `chunk` at `offset`. Only the next offset extends the module;
    /// a chunk the governor already holds at that offset is accepted and
    /// changes nothing, so a call retried after an unknown outcome cannot
    /// add its bytes twice.
    fn stage(&mut self, who: Principal, id: u64, offset: u64, chunk: &[u8]) -> Result<StageStatus, String> {
        self.require_live()?;
        self.require_approver(who)?;
        let p = self.proposals.get_mut(&id).ok_or("no such open proposal")?;
        if !matches!(p.change, Change::Upgrade { .. }) {
            return Err("only an upgrade proposal has a module to stage".into());
        }
        if p.phase != Phase::Open {
            return Err("the proposal is executing".into());
        }
        let held = p.module.len() as u64;
        let end = offset.checked_add(chunk.len() as u64).ok_or("offset overflow")?;
        if offset < held && end <= held {
            if p.module[offset as usize..end as usize] != *chunk {
                return Err(format!("different bytes are already staged at offset {offset}"));
            }
        } else if offset != held {
            return Err(format!("expected offset {held}"));
        } else if Self::ready(p) {
            return Err("the module is already staged".into());
        } else if p.module.len() + chunk.len() > MAX_MODULE_BYTES {
            return Err(format!("the module would exceed {MAX_MODULE_BYTES} bytes"));
        } else {
            p.module.extend_from_slice(chunk);
        }
        Ok(StageStatus {
            staged_bytes: p.module.len() as u64,
            staged_sha256: hex::encode(Sha256::digest(&p.module)),
            ready: Self::ready(p),
        })
    }

    /// Record a ballot; returns the new count and whether to execute now.
    fn cast(
        &mut self,
        who: Principal,
        id: u64,
        decision: Decision,
        reason: Option<String>,
        now: u64,
    ) -> Result<Count, String> {
        self.require_live()?;
        let p = self.proposals.get(&id).ok_or("no such open proposal")?.clone();
        if p.phase != Phase::Open {
            return Err("the proposal is executing".into());
        }
        if !Self::ready(&p) {
            return Err("stage the whole module before voting: the staged bytes do not hash to module_sha256".into());
        }
        let mut approval = Approval::new(Approver::from(who), decision, now);
        if let Some(r) = reason {
            approval = approval.with_reason(r);
        }
        let s = self.subject_of(&p);
        let t = ic_multisig::record(&mut self.ballots, &self.policy, &s, approval)
            .map_err(|e| e.to_string())?;
        Ok(count(&t))
    }

    fn withdraw(&mut self, who: Principal, id: u64, now: u64) -> Result<(), String> {
        let p = self.proposals.get(&id).ok_or("no such open proposal")?;
        if p.proposer != who {
            return Err("only the proposer can withdraw a proposal".into());
        }
        if p.phase != Phase::Open {
            return Err("the proposal is executing".into());
        }
        let p = self.proposals.remove(&id).expect("present");
        self.close(p, now, "withdrawn".into());
        Ok(())
    }

    fn close(&mut self, p: Proposal, now: u64, outcome: String) {
        let s = self.subject_of(&p);
        let ballots = ballots_view(&self.ballots.load(&s));
        self.ballots.save(&s, Vec::new());
        self.log.push(LogEntry {
            id: p.id,
            change: p.change,
            proposer: p.proposer,
            ballots,
            at_ns: now,
            outcome,
        });
    }

    /// Claim a reached proposal for execution.
    fn begin(&mut self, id: u64) -> Result<Proposal, String> {
        self.require_live()?;
        if self.proposals.values().any(|p| p.phase == Phase::Executing) {
            return Err("another proposal is executing; retry with execute".into());
        }
        let p = self.proposals.get(&id).ok_or("no such open proposal")?.clone();
        if !Self::ready(&p) {
            return Err("the module is not staged".into());
        }
        if !self.tally_of(&p).reached {
            return Err("the proposal has not reached its threshold".into());
        }
        self.proposals.get_mut(&id).expect("present").phase = Phase::Executing;
        Ok(p)
    }

    fn finish(&mut self, id: u64, result: &Result<String, String>, now: u64) {
        let Some(p) = self.proposals.get_mut(&id) else { return };
        p.phase = Phase::Open;
        match result {
            Ok(note) => {
                let p = self.proposals.remove(&id).expect("present");
                match &p.change {
                    Change::Policy { approvers, threshold } => {
                        // Checked when proposed; the approvers cannot have
                        // changed since, the policy being the only way.
                        if let Ok(pol) = policy_of(approvers, *threshold) {
                            self.policy = pol;
                        }
                    }
                    Change::Handover { successor } => self.handed_over_to = Some(*successor),
                    Change::Upgrade { .. } => {}
                }
                self.close(p, now, format!("executed: {note}"));
            }
            Err(e) => p.last_error = Some(e.clone()),
        }
    }
}

// --- the management canister ------------------------------------------------------
// Minimal candid mirrors, as in the git canister's deploy.rs: a record or
// variant with fewer fields is a valid subtype of the management canister's.

#[derive(CandidType)]
struct UploadChunkArgs {
    canister_id: Principal,
    chunk: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone)]
struct ChunkHash {
    hash: Vec<u8>,
}

#[derive(CandidType)]
struct CanisterIdRecord {
    canister_id: Principal,
}

#[derive(CandidType, Deserialize)]
enum InstallMode {
    #[serde(rename = "upgrade")]
    Upgrade(Option<UpgradeFlags>),
}

#[derive(CandidType, Deserialize)]
struct UpgradeFlags {
    skip_pre_upgrade: Option<bool>,
}

#[derive(CandidType)]
struct InstallChunkedCodeArgs {
    mode: InstallMode,
    target_canister: Principal,
    store_canister: Option<Principal>,
    chunk_hashes_list: Vec<ChunkHash>,
    wasm_module_hash: Vec<u8>,
    arg: Vec<u8>,
}

#[derive(CandidType)]
struct Settings {
    controllers: Option<Vec<Principal>>,
}

#[derive(CandidType)]
struct UpdateSettingsArgs {
    canister_id: Principal,
    settings: Settings,
}

/// The parts of ic-git's registry_publish_canister reply the log keeps.
#[derive(CandidType, Deserialize)]
struct TxOutcome {
    tx_hash: String,
}

#[derive(CandidType, Deserialize)]
enum PublishResult {
    Ok(TxOutcome),
    Err(String),
}

async fn management<A: CandidType, R: CandidType + for<'de> Deserialize<'de>>(
    method: &str,
    arg: A,
) -> Result<R, String> {
    let reply = Call::unbounded_wait(Principal::management_canister(), method)
        .with_arg(arg)
        .await
        .map_err(|e| format!("{method}: {e}"))?;
    reply.candid::<R>().map_err(|e| format!("{method}: {e}"))
}

/// Install `module` into `target` in upgrade mode, through the target's own
/// chunk store (the governor controls it; the governor itself, having no
/// controllers, could not upload chunks to its own).
async fn install(target: Principal, module: &[u8], sha: &[u8], arg: Vec<u8>) -> Result<(), String> {
    let _: () = management("clear_chunk_store", CanisterIdRecord { canister_id: target }).await?;
    let mut hashes = Vec::new();
    for chunk in module.chunks(CHUNK_BYTES) {
        let h: ChunkHash = management(
            "upload_chunk",
            UploadChunkArgs { canister_id: target, chunk: chunk.to_vec() },
        )
        .await?;
        hashes.push(h);
    }
    let installed: Result<(), String> = management(
        "install_chunked_code",
        InstallChunkedCodeArgs {
            mode: InstallMode::Upgrade(Some(UpgradeFlags { skip_pre_upgrade: Some(false) })),
            target_canister: target,
            store_canister: None,
            chunk_hashes_list: hashes,
            wasm_module_hash: sha.to_vec(),
            arg,
        },
    )
    .await;
    // Free the target's chunk storage either way; a failure here costs only
    // storage until the next install clears it.
    let _: Result<(), String> =
        management("clear_chunk_store", CanisterIdRecord { canister_id: target }).await;
    installed
}

/// Run a reached proposal. The result says what happened, for the log.
async fn execute_change(target: Principal, p: &Proposal) -> Result<String, String> {
    match &p.change {
        Change::Upgrade { commit, module_sha256, arg } => {
            let sha = hex::decode(module_sha256).map_err(|e| e.to_string())?;
            install(target, &p.module, &sha, arg.clone()).await?;
            // The new code publishes ic-git#canister. Its failure (no
            // registry, an RPC error) does not undo the install; the log says.
            let record = match Call::unbounded_wait(target, "registry_publish_canister")
                .with_args(&(commit.clone(), module_sha256.clone()))
                .await
            {
                Ok(r) => match r.candid::<PublishResult>() {
                    Ok(PublishResult::Ok(tx)) => format!("record tx {}", tx.tx_hash),
                    Ok(PublishResult::Err(e)) => format!("record not published: {e}"),
                    Err(e) => format!("record not published: {e}"),
                },
                Err(e) => format!("record not published: {e}"),
            };
            Ok(format!("upgraded {target} to {module_sha256} (commit {commit}); {record}"))
        }
        Change::Policy { approvers, threshold } => Ok(format!(
            "policy is now {threshold} of {}",
            approvers.iter().collect::<std::collections::BTreeSet<_>>().len()
        )),
        Change::Handover { successor } => {
            let _: () = management(
                "update_settings",
                UpdateSettingsArgs {
                    canister_id: target,
                    settings: Settings { controllers: Some(vec![*successor]) },
                },
            )
            .await?;
            Ok(format!("{target} is now controlled by {successor} alone"))
        }
    }
}

async fn run(id: u64) -> Result<String, String> {
    let (target, p) = with(|s| s.begin(id).map(|p| (s.target, p)))?;
    let result = execute_change(target, &p).await;
    with(|s| s.finish(id, &result, ic_cdk::api::time()));
    result
}

// --- endpoints ---------------------------------------------------------------------

fn caller() -> Principal {
    ic_cdk::api::msg_caller()
}

#[ic_cdk::init]
fn init(args: InitArgs) {
    let policy = policy_of(&args.approvers, args.threshold).unwrap_or_else(|e| ic_cdk::trap(e));
    let me = ic_cdk::api::canister_self();
    if args.target == me {
        ic_cdk::trap("the governor cannot govern itself");
    }
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            me,
            target: args.target,
            policy,
            next_id: 1,
            proposals: BTreeMap::new(),
            ballots: MemoryStore::default(),
            log: Vec::new(),
            handed_over_to: None,
        })
    });
}

/// Open a proposal. Approvers only. Ballots are separate (`vote`); an
/// upgrade's module must be staged (`stage`) before any are taken.
#[ic_cdk::update]
fn propose(change: Change) -> Result<u64, String> {
    with(|s| s.open(caller(), change, ic_cdk::api::time()))
}

/// Write a chunk of an upgrade proposal's module at `offset`, which must be
/// the bytes staged so far (`staged_bytes`). Resending a chunk already
/// held is harmless. Approvers only; nothing extends a module whose staged
/// bytes already hash to the proposal's module_sha256.
#[ic_cdk::update]
fn stage(id: u64, offset: u64, chunk: Vec<u8>) -> Result<StageStatus, String> {
    with(|s| s.stage(caller(), id, offset, &chunk))
}

/// Approve, reject or object (with a reason). A later ballot replaces the
/// caller's earlier one. The ballot that brings the proposal to K executes
/// it in the same call.
#[ic_cdk::update]
async fn vote(id: u64, decision: Decision, reason: Option<String>) -> Result<VoteOutcome, String> {
    let c = with(|s| s.cast(caller(), id, decision, reason, ic_cdk::api::time()))?;
    let executed = if c.reached { Some(run(id).await) } else { None };
    Ok(VoteOutcome { count: c, executed })
}

/// Retry a proposal that reached K but failed to execute (or reached it by
/// a policy change). Approvers only.
#[ic_cdk::update]
async fn execute(id: u64) -> Result<String, String> {
    with(|s| s.require_approver(caller()))?;
    run(id).await
}

/// Drop an open proposal. Its proposer only.
#[ic_cdk::update]
fn withdraw(id: u64) -> Result<(), String> {
    with(|s| s.withdraw(caller(), id, ic_cdk::api::time()))
}

#[ic_cdk::query]
fn info() -> Info {
    with(|s| Info {
        target: s.target,
        approvers: s.policy.approvers.iter().filter_map(|a| a.principal()).collect(),
        threshold: s.policy.threshold,
        handed_over_to: s.handed_over_to,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[ic_cdk::query]
fn proposals() -> Vec<ProposalView> {
    with(|s| s.proposals.values().map(|p| s.view(p)).collect())
}

/// Every executed or withdrawn proposal, oldest first, with its ballots.
#[ic_cdk::query]
fn log() -> Vec<LogEntry> {
    with(|s| s.log.clone())
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 29])
    }

    fn state(approvers: &[Principal], k: u32) -> State {
        State {
            me: p(100),
            target: p(101),
            policy: policy_of(approvers, k).unwrap(),
            next_id: 1,
            proposals: BTreeMap::new(),
            ballots: MemoryStore::default(),
            log: Vec::new(),
            handed_over_to: None,
        }
    }

    fn upgrade(module: &[u8]) -> Change {
        Change::Upgrade {
            commit: "ab".repeat(20),
            module_sha256: hex::encode(Sha256::digest(module)),
            arg: vec![],
        }
    }

    #[test]
    fn policy_rules() {
        assert!(policy_of(&[], 1).is_err());
        assert!(policy_of(&[p(1)], 0).unwrap_err().contains("at least 1"));
        assert!(policy_of(&[p(1)], 2).unwrap_err().contains("above"));
        // A duplicate counts once, so 2 of [a, a] is above N.
        assert!(policy_of(&[p(1), p(1)], 2).is_err());
        assert!(policy_of(&[Principal::anonymous()], 1).is_err());
        assert!(policy_of(&[p(1), p(2)], 2).is_ok());
    }

    #[test]
    fn changes_are_checked_when_proposed() {
        let t = p(101);
        let bad = Change::Upgrade { commit: "xyz".into(), module_sha256: "00".repeat(32), arg: vec![] };
        assert!(check(&bad, t).unwrap_err().contains("commit"));
        let upper = Change::Upgrade { commit: "AB".repeat(20), module_sha256: "00".repeat(32), arg: vec![] };
        assert!(check(&upper, t).is_err());
        assert!(check(&Change::Handover { successor: t }, t).is_err());
        assert!(check(&Change::Handover { successor: Principal::anonymous() }, t).is_err());
        assert!(check(&Change::Policy { approvers: vec![p(1)], threshold: 0 }, t).is_err());
        assert!(check(&upgrade(b"m"), t).is_ok());
    }

    #[test]
    fn the_subject_binds_everything() {
        let (me, t) = (p(100), p(101));
        let a = subject(me, t, 1, &upgrade(b"m"));
        assert_ne!(a, subject(me, t, 2, &upgrade(b"m")), "the id");
        assert_ne!(a, subject(p(99), t, 1, &upgrade(b"m")), "the governor");
        assert_ne!(a, subject(me, p(98), 1, &upgrade(b"m")), "the target");
        assert_ne!(a, subject(me, t, 1, &upgrade(b"n")), "the module");
        let mut with_arg = upgrade(b"m");
        if let Change::Upgrade { arg, .. } = &mut with_arg {
            arg.push(1);
        }
        assert_ne!(a, subject(me, t, 1, &with_arg), "the argument");
        // Approver order and repeats do not matter; the set does.
        let x = Change::Policy { approvers: vec![p(1), p(2)], threshold: 1 };
        let y = Change::Policy { approvers: vec![p(2), p(1), p(2)], threshold: 1 };
        assert_eq!(subject(me, t, 1, &x), subject(me, t, 1, &y));
    }

    #[test]
    fn only_approvers_propose_stage_and_vote() {
        let mut s = state(&[p(1)], 1);
        assert!(s.open(p(2), upgrade(b"m"), 0).unwrap_err().contains("approver"));
        let id = s.open(p(1), upgrade(b"m"), 0).unwrap();
        assert!(s.stage(p(2), id, 0, b"m").unwrap_err().contains("approver"));
        s.stage(p(1), id, 0, b"m").unwrap();
        assert!(s.cast(p(2), id, Decision::Approve, None, 1).is_err());
    }

    #[test]
    fn ballots_wait_for_the_whole_module() {
        let mut s = state(&[p(1)], 1);
        let id = s.open(p(1), upgrade(b"module"), 0).unwrap();
        assert!(s.cast(p(1), id, Decision::Approve, None, 1).unwrap_err().contains("stage"));
        let st = s.stage(p(1), id, 0, b"mod").unwrap();
        assert!(!st.ready);
        assert!(s.stage(p(1), id, 5, b"le").unwrap_err().contains("expected offset 3"));
        // A retry of a chunk already held changes nothing; different bytes
        // at a held offset are refused.
        assert_eq!(s.stage(p(1), id, 0, b"mod").unwrap().staged_bytes, 3);
        assert!(s.stage(p(1), id, 0, b"MOD").unwrap_err().contains("different bytes"));
        let st = s.stage(p(1), id, 3, b"ule").unwrap();
        assert!(st.ready);
        assert!(s.stage(p(1), id, 3, b"ule").unwrap().ready, "a retry after the last chunk");
        assert!(s.stage(p(1), id, 6, b"x").unwrap_err().contains("already staged"));
        assert!(s.cast(p(1), id, Decision::Approve, None, 1).unwrap().reached);
    }

    #[test]
    fn objections_hold_and_policy_changes_apply_on_finish() {
        let (a, b, c) = (p(1), p(2), p(3));
        let mut s = state(&[a], 1);
        let grow = Change::Policy { approvers: vec![a, b, c], threshold: 2 };
        let id = s.open(a, grow, 0).unwrap();
        assert!(s.cast(a, id, Decision::Approve, None, 1).unwrap().reached);
        s.begin(id).unwrap();
        s.finish(id, &Ok("policy".into()), 2);
        assert_eq!(s.policy.threshold, 2);
        assert_eq!(s.log.len(), 1);
        assert!(s.log[0].outcome.starts_with("executed"));

        let id = s.open(b, Change::Handover { successor: p(9) }, 3).unwrap();
        assert!(!s.cast(a, id, Decision::Approve, None, 4).unwrap().reached);
        assert!(s.cast(c, id, Decision::Object, None, 5).is_err(), "an objection needs a reason");
        let n = s.cast(c, id, Decision::Object, Some("not yet".into()), 5).unwrap();
        assert_eq!(n.objections, 1);
        // 2 approvals - 1 objection < 2.
        assert!(!s.cast(b, id, Decision::Approve, None, 6).unwrap().reached);
        assert!(s.begin(id).unwrap_err().contains("not reached"));
        // Withdrawing the objection (approving instead) lets it through.
        assert!(s.cast(c, id, Decision::Approve, None, 7).unwrap().reached);
        s.begin(id).unwrap();
        s.finish(id, &Ok("handed over".into()), 8);
        assert_eq!(s.handed_over_to, Some(p(9)));
        assert!(s.open(a, upgrade(b"m"), 9).unwrap_err().contains("inert"));
    }

    #[test]
    fn a_failed_execution_stays_open_for_retry() {
        let mut s = state(&[p(1)], 1);
        let id = s.open(p(1), Change::Handover { successor: p(9) }, 0).unwrap();
        s.cast(p(1), id, Decision::Approve, None, 1).unwrap();
        s.begin(id).unwrap();
        assert!(s.begin(id).unwrap_err().contains("executing"), "one at a time");
        s.finish(id, &Err("update_settings: rejected".into()), 2);
        assert_eq!(s.proposals[&id].last_error.as_deref(), Some("update_settings: rejected"));
        assert_eq!(s.handed_over_to, None);
        s.begin(id).unwrap();
    }

    #[test]
    fn withdraw_is_the_proposers() {
        let mut s = state(&[p(1), p(2)], 1);
        let id = s.open(p(1), upgrade(b"m"), 0).unwrap();
        assert!(s.withdraw(p(2), id, 1).is_err());
        s.withdraw(p(1), id, 1).unwrap();
        assert!(s.proposals.is_empty());
        assert_eq!(s.log[0].outcome, "withdrawn");
    }

    #[test]
    fn open_proposals_are_capped() {
        let mut s = state(&[p(1)], 1);
        for _ in 0..MAX_OPEN {
            s.open(p(1), upgrade(b"m"), 0).unwrap();
        }
        assert!(s.open(p(1), upgrade(b"m"), 0).unwrap_err().contains("open"));
    }

    #[test]
    fn the_interface_matches_governor_did() {
        let did = include_str!("../governor.did");
        candid_parser_free_compare(did, &__export_service());
    }

    // The checked-in .did must be what the code exports, up to whitespace.
    fn candid_parser_free_compare(a: &str, b: &str) {
        let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(norm(a), norm(b), "regenerate canisters/governor/governor.did");
    }
}
