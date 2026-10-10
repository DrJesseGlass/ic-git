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
//!   in chunks, and approvals are accepted only once the staged bytes hash
//!   to the named sha256. Approvers check that hash the way verified.json is
//!   made: rebuild the commit with tools/reproducible-build.sh. After the
//!   install, the target is asked to publish `ic-git#canister` (commit,
//!   module hash) to the registry, so the chain says what ic-git runs.
//! - **Policy**: replace the approvers and the threshold. K is never 0 and
//!   never above N.
//! - **Handover**: make another principal the target's only controller --
//!   a successor governor, or anyone the approvers choose. After it this
//!   canister is inert.
//!
//! A proposal executes the moment a ballot brings it to K. One its
//! approvers have turned down -- more of them reject or object than N - K,
//! so the rest cannot reach K alone -- can be withdrawn by any approver,
//! not only its proposer, so nobody can hold the open slots. There is no
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
/// An execution that has not finished after this long is presumed lost (a
/// trap after an await leaves its proposal marked executing), and the
/// proposal can be executed again or withdrawn. Every call an execution
/// makes returns well within it.
pub const STUCK_NS: u64 = 24 * 3600 * 1_000_000_000;
/// The most log entries one `log` call returns, and roughly the most bytes
/// (an Upgrade carries its install argument), well under the IC's reply
/// limit.
pub const LOG_PAGE_ENTRIES: usize = 100;
const LOG_PAGE_BYTES: usize = 1 << 20;

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
    /// the proposal's module (approvals are taken only then).
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
pub struct LogPage {
    /// Entries from the requested position on, oldest first.
    pub entries: Vec<LogEntry>,
    /// The position to ask for next, if there are more.
    pub next: Option<u64>,
    /// How many entries the log holds.
    pub total: u64,
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
    /// Claimed by the execution that started at `since_ns`.
    Executing { since_ns: u64 },
}

#[derive(Clone, Debug)]
struct Proposal {
    id: u64,
    change: Change,
    proposer: Principal,
    at_ns: u64,
    module: Vec<u8>,
    /// The running hash of `module` and its hex digest, kept as chunks
    /// arrive so nothing rehashes the whole module.
    hasher: Sha256,
    staged_sha256: String,
    phase: Phase,
    last_error: Option<String>,
}

impl Proposal {
    /// Executing, and not presumed lost (STUCK_NS).
    fn executing(&self, now: u64) -> bool {
        match self.phase {
            Phase::Executing { since_ns } => now.saturating_sub(since_ns) < STUCK_NS,
            Phase::Open => false,
        }
    }

    /// Whether the staged bytes are the proposal's module (always, for a
    /// change with no module).
    fn ready(&self) -> bool {
        match &self.change {
            Change::Upgrade { module_sha256, .. } => self.staged_sha256 == *module_sha256,
            _ => true,
        }
    }
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

/// Refuse a change that could never execute, or would leave the target
/// beyond any vote, before anyone votes on it. `me` is the governor.
pub fn check(change: &Change, me: Principal, target: Principal) -> Result<(), String> {
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
            } else if *successor == me {
                // The governor is inert after a handover, so the target
                // would be left with an inert controller and nothing else.
                Err("a handover must be to someone other than this governor".into())
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

    /// Whether the approvers have turned the proposal down: more of them
    /// reject or object than N - K, so the rest cannot reach K alone.
    fn refused(&self, p: &Proposal) -> bool {
        let t = self.tally_of(p);
        let n = self.policy.approvers.len() as u32;
        t.rejections + t.objections > n - self.policy.threshold
    }

    fn view(&self, p: &Proposal) -> ProposalView {
        let s = self.subject_of(p);
        ProposalView {
            id: p.id,
            change: p.change.clone(),
            proposer: p.proposer,
            at_ns: p.at_ns,
            staged_bytes: p.module.len() as u64,
            staged_sha256: p.staged_sha256.clone(),
            ready: p.ready(),
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
        check(&change, self.me, self.target)?;
        if self.proposals.len() >= MAX_OPEN {
            return Err(format!(
                "{MAX_OPEN} proposals are open; execute or withdraw one first \
                 (any approver can withdraw one the approvers have turned down)"
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
                hasher: Sha256::new(),
                staged_sha256: hex::encode(Sha256::digest(b"")),
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
    fn stage(&mut self, who: Principal, id: u64, offset: u64, chunk: &[u8], now: u64) -> Result<StageStatus, String> {
        self.require_live()?;
        self.require_approver(who)?;
        let p = self.proposals.get_mut(&id).ok_or("no such open proposal")?;
        if !matches!(p.change, Change::Upgrade { .. }) {
            return Err("only an upgrade proposal has a module to stage".into());
        }
        if p.executing(now) {
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
        } else if p.ready() {
            return Err("the module is already staged".into());
        } else if p.module.len() + chunk.len() > MAX_MODULE_BYTES {
            return Err(format!("the module would exceed {MAX_MODULE_BYTES} bytes"));
        } else {
            p.module.extend_from_slice(chunk);
            p.hasher.update(chunk);
            p.staged_sha256 = hex::encode(p.hasher.clone().finalize());
        }
        Ok(StageStatus {
            staged_bytes: p.module.len() as u64,
            staged_sha256: p.staged_sha256.clone(),
            ready: p.ready(),
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
        let p = self.proposals.get(&id).ok_or("no such open proposal")?;
        if p.executing(now) {
            return Err("the proposal is executing".into());
        }
        // Only an approval waits for the module: turning a proposal down
        // must not depend on anyone staging it.
        if decision == Decision::Approve && !p.ready() {
            return Err("stage the whole module before approving: the staged bytes do not hash to module_sha256".into());
        }
        let s = self.subject_of(p);
        let mut approval = Approval::new(Approver::from(who), decision, now);
        if let Some(r) = reason {
            approval = approval.with_reason(r);
        }
        let t = ic_multisig::record(&mut self.ballots, &self.policy, &s, approval)
            .map_err(|e| e.to_string())?;
        Ok(count(&t))
    }

    /// Drop an open proposal: its proposer's at any time, any approver's
    /// once the approvers have turned it down.
    fn withdraw(&mut self, who: Principal, id: u64, now: u64) -> Result<(), String> {
        self.require_live()?;
        let p = self.proposals.get(&id).ok_or("no such open proposal")?;
        if p.proposer != who {
            self.require_approver(who)?;
            if !self.refused(p) {
                return Err("only the proposer can withdraw a proposal the approvers have not turned down".into());
            }
        }
        if p.executing(now) {
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

    /// Claim a reached proposal for execution, as of `now` (which also
    /// names this attempt for `finish`). An execution older than
    /// STUCK_NS no longer holds its claim.
    fn begin(&mut self, id: u64, now: u64) -> Result<Proposal, String> {
        self.require_live()?;
        if self.proposals.values().any(|p| p.executing(now)) {
            return Err("another proposal is executing; retry with execute".into());
        }
        let p = self.proposals.get(&id).ok_or("no such open proposal")?;
        if !p.ready() {
            return Err("the module is not staged".into());
        }
        if !self.tally_of(p).reached {
            return Err("the proposal has not reached its threshold".into());
        }
        let p = self.proposals.get_mut(&id).expect("present");
        p.phase = Phase::Executing { since_ns: now };
        Ok(p.clone())
    }

    /// Record the outcome of the attempt that `begin` started at
    /// `started`. An attempt that lost its claim (STUCK_NS) and was
    /// superseded records nothing; the attempt that holds it will.
    fn finish(&mut self, id: u64, started: u64, result: Result<Executed, String>, now: u64) {
        let Some(p) = self.proposals.get_mut(&id) else { return };
        if p.phase != (Phase::Executing { since_ns: started }) {
            return;
        }
        p.phase = Phase::Open;
        match result {
            Ok(done) => {
                let p = self.proposals.remove(&id).expect("present");
                if let Some(pol) = done.policy {
                    self.policy = pol;
                }
                if let Change::Handover { successor } = &p.change {
                    self.handed_over_to = Some(*successor);
                }
                self.close(p, now, format!("executed: {}", done.note));
            }
            Err(e) => p.last_error = Some(e),
        }
    }

    /// The log from position `from`, at most `max` entries and about
    /// LOG_PAGE_BYTES (at least one entry, if any remain).
    fn log_page(&self, from: u64, max: u32) -> LogPage {
        let total = self.log.len() as u64;
        let start = from.min(total) as usize;
        let max = (max as usize).clamp(1, LOG_PAGE_ENTRIES);
        let mut entries = Vec::new();
        let mut bytes = 0;
        for e in &self.log[start..] {
            let size = entry_size(e);
            if entries.len() == max || (!entries.is_empty() && bytes + size > LOG_PAGE_BYTES) {
                break;
            }
            bytes += size;
            entries.push(e.clone());
        }
        let end = (start + entries.len()) as u64;
        LogPage {
            entries,
            next: (end < total).then_some(end),
            total,
        }
    }
}

/// A generous estimate of a log entry's encoded size.
fn entry_size(e: &LogEntry) -> usize {
    let change = match &e.change {
        Change::Upgrade { arg, .. } => arg.len(),
        Change::Policy { approvers, .. } => approvers.len() * 32,
        Change::Handover { .. } => 0,
    };
    let ballots: usize = e.ballots.iter().map(|b| 64 + b.reason.as_ref().map_or(0, |r| r.len())).sum();
    256 + change + ballots + e.outcome.len()
}

/// What an execution did: a note for the log and, for a Policy change,
/// the policy now in force.
struct Executed {
    note: String,
    policy: Option<Policy>,
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
async fn execute_change(target: Principal, p: &Proposal) -> Result<Executed, String> {
    let note = |note: String| Executed { note, policy: None };
    match &p.change {
        Change::Upgrade { commit, module_sha256, arg } => {
            let sha = hex::decode(module_sha256).map_err(|e| e.to_string())?;
            install(target, &p.module, &sha, arg.clone()).await?;
            // The new code publishes ic-git#canister. Its failure (no
            // registry, an RPC error, no reply in time) does not undo the
            // install; the log says. The wait is bounded so that code that
            // never replies cannot hold the proposal executing.
            let record = match Call::bounded_wait(target, "registry_publish_canister")
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
            Ok(note(format!("upgraded {target} to {module_sha256} (commit {commit}); {record}")))
        }
        Change::Policy { approvers, threshold } => {
            let policy = policy_of(approvers, *threshold)?;
            Ok(Executed {
                note: format!("policy is now {threshold} of {}", policy.approvers.len()),
                policy: Some(policy),
            })
        }
        Change::Handover { successor } => {
            let _: () = management(
                "update_settings",
                UpdateSettingsArgs {
                    canister_id: target,
                    settings: Settings { controllers: Some(vec![*successor]) },
                },
            )
            .await?;
            Ok(note(format!("{target} is now controlled by {successor} alone")))
        }
    }
}

async fn run(id: u64) -> Result<String, String> {
    let started = ic_cdk::api::time();
    let (target, p) = with(|s| s.begin(id, started).map(|p| (s.target, p)))?;
    let result = execute_change(target, &p).await;
    let reply = result.as_ref().map(|d| d.note.clone()).map_err(Clone::clone);
    with(|s| s.finish(id, started, result, ic_cdk::api::time()));
    reply
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
/// upgrade's module must be staged (`stage`) before it can be approved.
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
    with(|s| s.stage(caller(), id, offset, &chunk, ic_cdk::api::time()))
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

/// Drop an open proposal: its proposer, or any approver once the approvers
/// have turned it down (more reject or object than N - K).
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

/// Executed and withdrawn proposals with their ballots, oldest first, from
/// position `from`: at most `max` (and at most 100) per call; `next` is
/// where the following page starts.
#[ic_cdk::query]
fn log(from: u64, max: u32) -> LogPage {
    with(|s| s.log_page(from, max))
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

    fn done(note: &str) -> Result<Executed, String> {
        Ok(Executed { note: note.into(), policy: None })
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
        let (me, t) = (p(100), p(101));
        let bad = Change::Upgrade { commit: "xyz".into(), module_sha256: "00".repeat(32), arg: vec![] };
        assert!(check(&bad, me, t).unwrap_err().contains("commit"));
        let upper = Change::Upgrade { commit: "AB".repeat(20), module_sha256: "00".repeat(32), arg: vec![] };
        assert!(check(&upper, me, t).is_err());
        assert!(check(&Change::Handover { successor: t }, me, t).is_err());
        assert!(check(&Change::Handover { successor: me }, me, t).unwrap_err().contains("this governor"));
        assert!(check(&Change::Handover { successor: Principal::anonymous() }, me, t).is_err());
        assert!(check(&Change::Policy { approvers: vec![p(1)], threshold: 0 }, me, t).is_err());
        assert!(check(&upgrade(b"m"), me, t).is_ok());
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
        assert!(s.stage(p(2), id, 0, b"m", 0).unwrap_err().contains("approver"));
        s.stage(p(1), id, 0, b"m", 0).unwrap();
        assert!(s.cast(p(2), id, Decision::Approve, None, 1).is_err());
    }

    #[test]
    fn ballots_wait_for_the_whole_module() {
        let mut s = state(&[p(1)], 1);
        let id = s.open(p(1), upgrade(b"module"), 0).unwrap();
        assert!(s.cast(p(1), id, Decision::Approve, None, 1).unwrap_err().contains("stage"));
        let st = s.stage(p(1), id, 0, b"mod", 0).unwrap();
        assert!(!st.ready);
        assert!(s.stage(p(1), id, 5, b"le", 0).unwrap_err().contains("expected offset 3"));
        // A retry of a chunk already held changes nothing; different bytes
        // at a held offset are refused.
        assert_eq!(s.stage(p(1), id, 0, b"mod", 0).unwrap().staged_bytes, 3);
        assert!(s.stage(p(1), id, 0, b"MOD", 0).unwrap_err().contains("different bytes"));
        let st = s.stage(p(1), id, 3, b"ule", 0).unwrap();
        assert!(st.ready);
        assert!(s.stage(p(1), id, 3, b"ule", 0).unwrap().ready, "a retry after the last chunk");
        assert!(s.stage(p(1), id, 6, b"x", 0).unwrap_err().contains("already staged"));
        assert!(s.cast(p(1), id, Decision::Approve, None, 1).unwrap().reached);
    }

    #[test]
    fn objections_hold_and_policy_changes_apply_on_finish() {
        let (a, b, c) = (p(1), p(2), p(3));
        let mut s = state(&[a], 1);
        let grow = Change::Policy { approvers: vec![a, b, c], threshold: 2 };
        let id = s.open(a, grow, 0).unwrap();
        assert!(s.cast(a, id, Decision::Approve, None, 1).unwrap().reached);
        s.begin(id, 2).unwrap();
        let pol = policy_of(&[a, b, c], 2).unwrap();
        s.finish(id, 2, Ok(Executed { note: "policy".into(), policy: Some(pol) }), 2);
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
        assert!(s.begin(id, 7).unwrap_err().contains("not reached"));
        // Withdrawing the objection (approving instead) lets it through.
        assert!(s.cast(c, id, Decision::Approve, None, 7).unwrap().reached);
        s.begin(id, 8).unwrap();
        s.finish(id, 8, done("handed over"), 8);
        assert_eq!(s.handed_over_to, Some(p(9)));
        assert!(s.open(a, upgrade(b"m"), 9).unwrap_err().contains("inert"));
        assert!(s.withdraw(a, 99, 9).unwrap_err().contains("inert"));
    }

    #[test]
    fn a_failed_execution_stays_open_for_retry() {
        let mut s = state(&[p(1)], 1);
        let id = s.open(p(1), Change::Handover { successor: p(9) }, 0).unwrap();
        s.cast(p(1), id, Decision::Approve, None, 1).unwrap();
        s.begin(id, 2).unwrap();
        assert!(s.begin(id, 2).unwrap_err().contains("executing"), "one at a time");
        s.finish(id, 2, Err("update_settings: rejected".into()), 3);
        assert_eq!(s.proposals[&id].last_error.as_deref(), Some("update_settings: rejected"));
        assert_eq!(s.handed_over_to, None);
        s.begin(id, 4).unwrap();
    }

    #[test]
    fn a_lost_execution_does_not_hold_the_governor() {
        let mut s = state(&[p(1)], 1);
        let id = s.open(p(1), Change::Handover { successor: p(9) }, 0).unwrap();
        s.cast(p(1), id, Decision::Approve, None, 1).unwrap();
        // An attempt that never finishes (a trap after an await)...
        s.begin(id, 10).unwrap();
        assert!(s.begin(id, 10 + STUCK_NS - 1).unwrap_err().contains("executing"));
        // ...stops holding its claim after STUCK_NS.
        let later = 10 + STUCK_NS;
        s.begin(id, later).unwrap();
        // If the lost attempt does come back, it records nothing.
        s.finish(id, 10, done("late"), later + 1);
        assert!(s.log.is_empty());
        assert!(s.proposals[&id].executing(later + 1));
        s.finish(id, later, done("handed over"), later + 2);
        assert_eq!(s.handed_over_to, Some(p(9)));
    }

    #[test]
    fn a_failed_policy_change_is_not_logged_as_executed() {
        let mut s = state(&[p(1)], 1);
        let id = s.open(p(1), Change::Policy { approvers: vec![p(1), p(2)], threshold: 2 }, 0).unwrap();
        s.cast(p(1), id, Decision::Approve, None, 1).unwrap();
        s.begin(id, 2).unwrap();
        s.finish(id, 2, Err("refused".into()), 3);
        assert_eq!(s.policy.threshold, 1);
        assert!(s.log.is_empty());
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
    fn a_proposal_turned_down_can_be_withdrawn_by_any_approver() {
        // 2 of 3: one approver fills every slot with modules nobody can stage.
        let (a, b, c) = (p(1), p(2), p(3));
        let mut s = state(&[a, b, c], 2);
        let junk = |n: u8| Change::Upgrade { commit: "ab".repeat(20), module_sha256: hex::encode([n; 32]), arg: vec![] };
        let ids: Vec<u64> = (0..MAX_OPEN as u8).map(|n| s.open(a, junk(n), 0).unwrap()).collect();
        assert!(s.open(b, Change::Policy { approvers: vec![b, c], threshold: 2 }, 0).is_err());
        let id = ids[0];
        // Approving waits for the module; turning it down does not.
        assert!(s.cast(b, id, Decision::Approve, None, 1).unwrap_err().contains("stage"));
        s.cast(b, id, Decision::Reject, None, 1).unwrap();
        // One rejection of three leaves two who could still reach 2.
        assert!(s.withdraw(b, id, 2).unwrap_err().contains("turned down"));
        s.cast(c, id, Decision::Object, Some("no such build".into()), 2).unwrap();
        assert!(s.withdraw(p(4), id, 3).unwrap_err().contains("approver"));
        s.withdraw(b, id, 3).unwrap();
        assert_eq!(s.log[0].outcome, "withdrawn");
        s.open(b, Change::Policy { approvers: vec![b, c], threshold: 2 }, 4).unwrap();
    }

    #[test]
    fn staging_keeps_a_running_hash() {
        let mut s = state(&[p(1)], 1);
        let module: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        let id = s.open(p(1), upgrade(&module), 0).unwrap();
        let mut off = 0;
        for chunk in module.chunks(1500) {
            let st = s.stage(p(1), id, off, chunk, 0).unwrap();
            off += chunk.len() as u64;
            assert_eq!(st.staged_sha256, hex::encode(Sha256::digest(&module[..off as usize])));
        }
        assert!(s.view(&s.proposals[&id]).ready);
    }

    #[test]
    fn the_log_is_paged() {
        let mut s = state(&[p(1)], 1);
        for _ in 0..250 {
            let id = s.open(p(1), Change::Handover { successor: p(9) }, 0).unwrap();
            s.withdraw(p(1), id, 1).unwrap();
        }
        let page = s.log_page(0, 1000);
        assert_eq!((page.entries.len(), page.next, page.total), (LOG_PAGE_ENTRIES, Some(100), 250));
        let page = s.log_page(200, 1000);
        assert_eq!((page.entries.len(), page.next), (50, None));
        assert_eq!(page.entries[0].id, 201);
        assert!(s.log_page(250, 10).entries.is_empty());
        assert!(s.log_page(999, 10).next.is_none());
        // Large install arguments end a page early, but never at zero entries.
        let big = Change::Upgrade { commit: "ab".repeat(20), module_sha256: "00".repeat(32), arg: vec![0; MAX_ARG_BYTES] };
        for _ in 0..40 {
            let id = s.open(p(1), big.clone(), 0).unwrap();
            s.withdraw(p(1), id, 1).unwrap();
        }
        let page = s.log_page(250, 100);
        assert!(page.entries.len() < 40 && !page.entries.is_empty());
        assert_eq!(page.next, Some(250 + page.entries.len() as u64));
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
