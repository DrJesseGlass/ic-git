//! Deploy path -- first slice of milestone 4 (see ../../../ARCHITECTURE.md and
//! ROADMAP.md). On a push to the deploy branch, read the configured source out
//! of the pushed commit's tree, build (or validate) it on-chain, and install
//! the resulting wasm into a target canister via the management canister's
//! `install_code`.
//!
//! This closes the loop the ROADMAP calls for: `git push` -> compile -> deploy,
//! entirely on-chain. Pushes enqueue a job; the deploy itself runs from a
//! timer-driven queue, off the push path.

use crate::{compile, evm};
use ic_git_types::oid::{commit20, oid_hex, parse_oid, Oid};
pub use ic_git_types::deploy::{DeployConfig, DeployMode, EvmDeployConfig, Job, SourceKind};
use ic_git_types::deploy::bytecode_of;
use ic_git_types::proof::Artifact;
use candid::{CandidType, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// Outcome of the most recent deploy attempt for a repo.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct DeployStatus {
    /// Commit that triggered this deploy (hex oid).
    pub commit: String,
    /// Whether install_code succeeded.
    pub ok: bool,
    /// Human-readable result or error.
    pub message: String,
    /// Size of the compiled wasm (0 if compilation was not reached).
    pub wasm_len: u64,
    /// sha256 of the compiled wasm ("" if compilation was not reached).
    pub wasm_sha256: String,
}

/// Turn the committed source blob into deployable wasm. Either way the
/// result is validated before it can be installed. The authority's side of
/// `SourceKind`: it builds, the git side only names the kind.
fn build(kind: SourceKind, path: &str, bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let source = |bytes: Vec<u8>| {
        String::from_utf8(bytes).map_err(|_| format!("{path} is not valid UTF-8"))
    };
    match kind {
        SourceKind::Wat => compile::compile_wat_checked(&source(bytes)?),
        SourceKind::Lang => crate::lang::compile_checked(&source(bytes)?),
        SourceKind::Wasm => {
            compile::validate_wasm(&bytes)?;
            Ok(bytes)
        }
    }
}

/// Outcome of the most recent EVM deploy attempt for a repo.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmDeployStatus {
    /// Commit that triggered this deploy (hex oid).
    pub commit: String,
    pub ok: bool,
    /// Human-readable result or error.
    pub message: String,
    /// Deterministic CREATE address ("" until a broadcast succeeds).
    pub contract_address: String,
    /// Transaction hash ("" until a broadcast succeeds).
    pub tx_hash: String,
}

// META keys for this module's persisted state (JSON via kv::set_json).
const EVM_STATUS_PREFIX: &str = "deploy_evm_status:";
fn evm_status_key(repo: &str) -> String {
    format!("{EVM_STATUS_PREFIX}{repo}")
}
const STATUS_PREFIX: &str = "deploy_status:";
fn status_key(repo: &str) -> String {
    format!("{STATUS_PREFIX}{repo}")
}
fn log_key(repo: &str) -> String {
    format!("deploy_log:{repo}")
}
const QUEUE_KEY: &str = "deploy_queue";
/// Status message both legs write at job start, before their first await, so
/// a poll during the (tens of seconds) deploy sees progress, not null or a
/// stale result.
const DEPLOYING: &str = "deploying";

pub fn get_evm_status(repo: &str) -> Option<EvmDeployStatus> {
    crate::kv::get_json(&evm_status_key(repo))
}

pub fn get_status(repo: &str) -> Option<DeployStatus> {
    crate::kv::get_json(&status_key(repo))
}

fn put_status(repo: &str, st: &DeployStatus) {
    crate::kv::set_json(&status_key(repo), st);
}

/// One entry in a repo's append-only deploy provenance log: the binding of an
/// on-chain commit to the wasm hash that was deployed from it. Because the
/// commit oid content-addresses the exact source tree and the wasm hash is
/// recorded here, this is a tamper-proof record of "commit C produced binary H"
/// that anyone can re-verify by reproducibly rebuilding commit C.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct DeployRecord {
    pub commit: String,
    /// The canister the wasm was installed into (text principal). Records
    /// written before this field existed load as "".
    #[serde(default)]
    pub target: String,
    pub source_path: String,
    pub wasm_sha256: String,
    pub wasm_len: u64,
    pub ok: bool,
    pub message: String,
    /// IC time (nanoseconds since the epoch) when the deploy was recorded.
    pub at_ns: u64,
}

/// Keep the most recent N records per repo to bound stable-memory growth.
const MAX_LOG: usize = 200;

pub fn get_history(repo: &str) -> Vec<DeployRecord> {
    crate::kv::get_json(&log_key(repo)).unwrap_or_default()
}

/// For the canister's tests: record a deploy outcome as the queue would,
/// as the repo's status and in its log.
#[cfg(feature = "testing")]
pub fn record_for_tests(repo: &str, cfg: &DeployConfig, st: &DeployStatus) {
    put_status(repo, st);
    record(repo, cfg, st)
}

/// For the canister's tests: empty the queue, as the drain would have.
#[cfg(feature = "testing")]
pub fn clear_queue_for_tests() {
    queue_save(&[]);
}

/// Append the binding for this deploy to the provenance log.
pub(crate) fn record(repo: &str, cfg: &DeployConfig, st: &DeployStatus) {
    let mut log = get_history(repo);
    let rec = DeployRecord {
        commit: st.commit.clone(),
        target: cfg.target.clone(),
        source_path: cfg.source_path.clone(),
        wasm_sha256: st.wasm_sha256.clone(),
        wasm_len: st.wasm_len,
        ok: st.ok,
        message: st.message.clone(),
        at_ns: crate::clock::now_ns(),
    };
    crate::feed::deployed(repo, &rec);
    log.push(rec);
    if log.len() > MAX_LOG {
        let drop = log.len() - MAX_LOG;
        log.drain(0..drop);
    }
    crate::kv::set_json(&log_key(repo), &log);
}

// --- deploy queue (timer-driven; see ARCHITECTURE.md) ------------------------
// Pushes enqueue a job and return immediately; the deploy runs from a
// zero-delay timer, off the push path, so the push response is not blocked on
// compile + install_code. The queue lives in stable memory (survives upgrades);
// the timer does not, so post_upgrade re-arms it via `resume_pending`.

#[derive(Serialize, Deserialize, Clone)]
struct DeployJob {
    repo: String,
    /// Commit that triggered the deploy, as a hex oid.
    commit: String,
}

/// Where a queued job's payload is stored. A commit is 40 hex digits, so the
/// key cannot be read two ways whatever the repo is called.
fn job_key(repo: &str, commit_hex: &str) -> String {
    format!("{commit_hex}:{repo}")
}

fn job_save(repo: &str, commit: &Oid, job: &Job) {
    // Encoding a struct of blobs, strings and integers cannot fail.
    if let Ok(bytes) = candid::encode_one(job) {
        crate::records::deploy_job_put(&job_key(repo, &oid_hex(commit)), bytes);
    }
}

// Reached only from the drain, which tests never run.
#[cfg_attr(any(test, feature = "testing"), allow(dead_code))]
fn job_take(repo: &str, commit_hex: &str) -> Option<Job> {
    crate::records::deploy_job_take(&job_key(repo, commit_hex))
        .and_then(|bytes| candid::decode_one(&bytes).ok())
}

fn queue_load() -> Vec<DeployJob> {
    crate::kv::get_json(QUEUE_KEY).unwrap_or_default()
}

fn queue_save(jobs: &[DeployJob]) {
    crate::kv::set_json(QUEUE_KEY, &jobs);
}

/// Number of jobs waiting in the queue.
pub fn queue_len() -> usize {
    queue_load().len()
}

/// Take a job the git side submitted (section 4's submit_job): queue it
/// and arm the drain timer, without deploying. The job is dropped when the
/// app already runs the commit (`is_live`, by this side's configs) or a
/// deploy of it is queued or running (`in_flight`), which would install
/// it twice and charge twice; an unapproved commit's job is queued, and
/// the drain refuses it with a status that says so. The git side submits
/// a job whenever what a repo serves moves, and again on a ballot while
/// the app is not in step (phase 3, step 9), so a failed deploy of the
/// approved commit is retried without this side asking the git side
/// anything. Returns whether the job was queued.
pub fn accept(repo: &str, commit: Oid, job: Job) -> bool {
    let hex = oid_hex(&commit);
    let cfg = crate::configs::get(repo);
    let mut jobs = queue_load();
    let in_flight = in_queue(&jobs, repo, &hex) || deploying(repo, &hex);
    if in_flight || is_live(repo, &hex, cfg.wasm.as_ref().map(|c| c.target.as_str()), cfg.evm.is_some()) {
        return false;
    }
    job_save(repo, &commit, &job);
    jobs.push(DeployJob {
        repo: repo.to_string(),
        commit: hex,
    });
    queue_save(&jobs);
    arm_timer();
    true
}

/// A job the git side submitted that this side will never run -- too
/// large to carry across, or not readable once it arrived -- recorded as
/// the commit's failed deploy, so the status says why nothing happened.
/// Not while a deploy runs: the running one's status is what `accept`
/// reads to queue nothing twice, and it writes its own outcome.
pub fn refuse_submitted(repo: &str, commit_hex: &str, why: &str) {
    if get_status(repo).is_some_and(|s| s.message == DEPLOYING) {
        return;
    }
    put_status(
        repo,
        &DeployStatus {
            commit: commit_hex.to_string(),
            ok: false,
            message: format!("the submitted job was refused: {why}"),
            wasm_len: 0,
            wasm_sha256: String::new(),
        },
    );
}

/// Re-arm the drain timer if jobs are pending. Called from post_upgrade, since
/// timers do not survive upgrades. A payload whose job is gone -- drained by
/// a release that does not know the map, after a rollback -- is dropped, or
/// nothing would ever free it; a job whose payload is gone is left for the
/// drain, which records it as failed.
pub fn resume_pending() {
    let jobs = queue_load();
    let queued: std::collections::BTreeSet<String> =
        jobs.iter().map(|j| job_key(&j.repo, &j.commit)).collect();
    for key in crate::records::deploy_job_keys() {
        if !queued.contains(&key) {
            crate::records::deploy_job_take(&key);
        }
    }
    // A deploy the upgrade interrupted: its job left the queue before it
    // ran, and its status says "deploying" with nothing deploying. Left
    // so, the commit would count as in flight forever and no retry of it
    // would be taken (`accept`). It is recorded as the failure it is, and
    // a ballot retries it.
    const INTERRUPTED: &str = "interrupted by an upgrade; a ballot retries it, or deploy_now";
    for key in crate::kv::keys_with_prefix(STATUS_PREFIX) {
        let repo = &key[STATUS_PREFIX.len()..];
        if let Some(mut st) = get_status(repo).filter(|s| s.message == DEPLOYING && !in_queue(&jobs, repo, &s.commit)) {
            st.message = INTERRUPTED.into();
            put_status(repo, &st);
        }
    }
    for key in crate::kv::keys_with_prefix(EVM_STATUS_PREFIX) {
        let repo = &key[EVM_STATUS_PREFIX.len()..];
        if let Some(mut st) = get_evm_status(repo).filter(|s| s.message == DEPLOYING && !in_queue(&jobs, repo, &s.commit)) {
            st.message = INTERRUPTED.into();
            crate::kv::set_json(&evm_status_key(repo), &st);
        }
    }
    if !jobs.is_empty() {
        arm_timer();
    }
}

/// Arm a zero-delay timer to drain one job. Safe to call redundantly: a timer
/// that fires on an empty queue is a no-op. In ic-cdk-timers 1.0 the timer
/// drives the future directly (its only await is the install_code call).
#[cfg(not(any(test, feature = "testing")))]
fn arm_timer() {
    ic_cdk_timers::set_timer(std::time::Duration::ZERO, drain_one());
}

/// Tests read the queue and never drain it (a deploy is an install_code
/// call); a timer cannot fire outside a canister.
#[cfg(any(test, feature = "testing"))]
fn arm_timer() {}

thread_local! {
    /// True while a drain chain is awaiting a deploy. Every push arms its own
    /// timer, so two rapid pushes would otherwise run two concurrent chains
    /// whose EVM legs race on the EOA nonce; a timer that fires while one is
    /// active bails, and the active chain re-arms for the jobs that remain.
    /// Heap state: an upgrade clears it and resume_pending re-arms.
    static DRAINING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Pop the front job, run it, and re-arm if more remain. The job is removed
/// (and the removal persisted) before running, so a job can never loop forever;
/// `run` records its own outcome and is written never to trap.
#[cfg_attr(any(test, feature = "testing"), allow(dead_code))]
async fn drain_one() {
    if DRAINING.with(|f| f.replace(true)) {
        return;
    }
    let mut jobs = queue_load();
    if jobs.is_empty() {
        DRAINING.with(|f| f.set(false));
        return;
    }
    let job = jobs.remove(0);
    queue_save(&jobs);
    let payload = job_take(&job.repo, &job.commit);

    if let Ok(commit) = parse_oid(&job.commit) {
        match payload {
            Some(payload) => {
                run(&job.repo, commit, payload, false).await;
            }
            // accept writes the payload with the job, so this is one that
            // no longer decodes, or one queued by a release before jobs
            // carried their artifacts (a rollback).
            None => put_status(
                &job.repo,
                &DeployStatus {
                    commit: job.commit,
                    ok: false,
                    message: "the queued job could not be read; deploy_now retries".into(),
                    wasm_len: 0,
                    wasm_sha256: String::new(),
                },
            ),
        }
    }
    DRAINING.with(|f| f.set(false));
    // Re-read the queue rather than trusting the pre-run snapshot: a push
    // that arrived during the await armed a timer that bailed on DRAINING
    // above, so its job is ours to pick up.
    if !queue_load().is_empty() {
        arm_timer();
    }
}

// --- management canister install_code ---------------------------------------
// Minimal candid mirror of the management canister's install_code argument.
// Defined here rather than pulled from a management-types crate to stay
// independent of ic-cdk's module layout. `sender_canister_version` is optional
// on the wire and omitted; a variant with fewer arms/fields is a valid candid
// subtype of the management canister's fuller type.

#[derive(CandidType, Deserialize)]
enum CanisterInstallMode {
    #[serde(rename = "install")]
    Install,
    #[serde(rename = "reinstall")]
    Reinstall,
    #[serde(rename = "upgrade")]
    Upgrade(Option<UpgradeArgs>),
}

#[derive(CandidType, Deserialize)]
struct UpgradeArgs {
    skip_pre_upgrade: Option<bool>,
    wasm_memory_persistence: Option<WasmMemoryPersistence>,
}

#[derive(CandidType, Deserialize)]
enum WasmMemoryPersistence {
    #[serde(rename = "keep")]
    Keep,
    #[serde(rename = "replace")]
    Replace,
}

#[derive(CandidType, Deserialize)]
struct InstallCodeArgument {
    mode: CanisterInstallMode,
    canister_id: Principal,
    wasm_module: Vec<u8>,
    arg: Vec<u8>,
}

#[derive(CandidType)]
struct CanisterIdRecord {
    canister_id: Principal,
}

// Only the field we need; candid ignores the rest of canister_status's reply.
#[derive(CandidType, Deserialize)]
struct StatusReply {
    module_hash: Option<Vec<u8>>,
}

/// Whether the target already has a module installed. Requires the git canister
/// to be a controller of `target` (it must be, to install into it).
async fn target_has_module(target: Principal) -> Result<bool, String> {
    let reply: StatusReply = intercanister::call(
        Principal::management_canister(),
        "canister_status",
        (CanisterIdRecord {
            canister_id: target,
        },),
    )
    .await?;
    Ok(reply.module_hash.is_some())
}

/// Install `wasm` into `target`. An empty target always gets a plain install;
/// a target that already has a module gets `mode` (Upgrade preserves stable
/// memory, Reinstall discards it). Returns the mode label actually used.
///
/// `allowed` runs after the last await and before `install_code` goes out,
/// with nothing in between: what it checks cannot change between its
/// answer and the install.
async fn install(
    target: Principal,
    wasm: Vec<u8>,
    mode: DeployMode,
    allowed: impl Fn() -> Result<(), String>,
) -> Result<&'static str, String> {
    let fail = |e: String| format!("install_code failed: {e}");
    let (install_mode, label) = if !target_has_module(target).await.map_err(fail)? {
        (CanisterInstallMode::Install, "install")
    } else {
        match mode {
            DeployMode::Upgrade => (CanisterInstallMode::Upgrade(None), "upgrade"),
            DeployMode::Reinstall => (CanisterInstallMode::Reinstall, "reinstall"),
        }
    };
    let arg = InstallCodeArgument {
        mode: install_mode,
        canister_id: target,
        wasm_module: wasm,
        arg: vec![],
    };
    allowed()?;
    // Unbounded wait on purpose: the reply (or reject) is definite, so the
    // deploy log never records an install whose outcome is unknown. The
    // names announce relies on that (see `run`).
    intercanister::call::<(InstallCodeArgument,), ()>(
        Principal::management_canister(),
        "install_code",
        (arg,),
    )
    .await
    .map_err(fail)?;
    Ok(label)
}

/// The fallible steps of a deploy: resolve the source blob, build it, install
/// it. Fills in `st`'s wasm summary as soon as the build succeeds, so failed
/// installs still record what was built. Returns the success message.
async fn attempt(
    repo: &str,
    cfg: &DeployConfig,
    commit_oid: &Oid,
    artifact: Result<Artifact, String>,
    st: &mut DeployStatus,
) -> Result<String, String> {
    let target =
        Principal::from_text(&cfg.target).map_err(|e| format!("bad target principal: {e}"))?;
    // Checked as the job runs, not only when configured: a job queued
    // before the repo was governed carries the config of that time. And
    // again just before install_code, since the repo can be governed while
    // this job awaits the target's status.
    let kind_now = || SourceKind::for_repo(crate::tenancy::is_governed(repo), &cfg.source_path);
    let kind = kind_now()?;
    let src_bytes = artifact?.verified(&commit20(commit_oid)?, &cfg.source_path)?;
    let wasm = build(kind, &cfg.source_path, src_bytes)
        .map_err(|e| format!("build {}: {e}", cfg.source_path))?;
    let info = compile::info_of(&wasm);
    st.wasm_len = info.wasm_len;
    st.wasm_sha256 = info.sha256_hex;
    let label = install(target, wasm, cfg.mode, || kind_now().map(|_| ())).await?;
    Ok(format!("{label} to {}", cfg.target))
}

/// The fallible steps of an EVM deploy: verify and decode the job's hex
/// artifact, then hand the bytes to evm::deploy_bytecode, which signs a CREATE
/// with the commit oid threaded into the provenance record.
///
/// Returns the broadcast outcome together with the artifact's sha256, which is
/// the bundle hash the registry publish then attests -- computed once here,
/// from the exact bytes that were deployed.
async fn attempt_evm(
    repo: &str,
    cfg: &EvmDeployConfig,
    commit_oid: &Oid,
    artifact: Result<Artifact, String>,
) -> Result<(crate::evm::TxOutcome, [u8; 32]), evm::SendError> {
    // Chain-side preconditions first: an unconfigured canister or an unpayable
    // gas limit should say so before anything about the artifact.
    evm::require_deploy_target(cfg.gas_limit).map_err(evm::SendError::before)?;
    let bytecode = artifact
        .and_then(|a| a.verified(&commit20(commit_oid)?, &cfg.source_path))
        .and_then(|bytes| bytecode_of(&cfg.source_path, bytes))
        .map_err(evm::SendError::before)?;
    let bundle: [u8; 32] = sha2::Sha256::digest(&bytecode).into();
    let out = evm::deploy_bytecode(
        repo.to_string(),
        bytecode,
        cfg.gas_limit,
        oid_hex(commit_oid),
    )
    .await?;
    Ok((out, bundle))
}

/// Run a repo's configured EVM deploy and persist its status. Never traps.
/// Unless `force`, a commit the provenance log already shows accepted (and
/// not reverted) is skipped -- the guard against double-push and
/// push-then-impatient-deploy_now duplicates. After a fresh broadcast, the
/// repo's provenance is auto-published to the registry when one is set.
///
/// Also returns how much of `price` (the evm_action charged for this leg) to
/// give back: all of it for a skipped commit, and for a failed deploy what
/// `SendError::refundable` says it did not use.
async fn run_evm(
    repo: &str,
    cfg: &EvmDeployConfig,
    commit_oid: &Oid,
    artifact: Result<Artifact, String>,
    force: bool,
    price: u64,
) -> (EvmDeployStatus, u64) {
    let commit = oid_hex(commit_oid);
    let mut st = EvmDeployStatus {
        commit: commit.clone(),
        ok: false,
        message: DEPLOYING.into(),
        contract_address: String::new(),
        tx_hash: String::new(),
    };
    if !force {
        if let Some(prev) = evm::latest_deploy(repo, &commit) {
            // An accepted broadcast, or an unknown one whose receipt has since
            // shown it mined, is a deploy; an unknown one not yet seen may be.
            st.ok = prev.ok || prev.receipt_status == evm::RECEIPT_SUCCESS;
            st.contract_address = prev.contract_address;
            st.tx_hash = prev.tx_hash;
            st.message = if st.ok {
                format!(
                    "already deployed at {} (tx {}); skipped (deploy_now redeploys)",
                    st.contract_address, st.tx_hash
                )
            } else {
                format!(
                    "an earlier deploy of this commit may be live at {} (tx {}, broadcast \
                     outcome unknown); skipped. Check evm_receipt; deploy_now redeploys",
                    st.contract_address, st.tx_hash
                )
            };
            crate::kv::set_json(&evm_status_key(repo), &st);
            return (st, price);
        }
    }
    let mut unused = 0;
    crate::kv::set_json(&evm_status_key(repo), &st);
    match attempt_evm(repo, cfg, commit_oid, artifact).await {
        Ok((out, bundle)) => {
            st.ok = true;
            st.contract_address = out.contract_address.unwrap_or_default();
            st.tx_hash = out.tx_hash;
            st.message = format!("deployed to {} (chain via evm config)", st.contract_address);
            if evm::get_registry().is_some() {
                // Publish the hash of the bytes this deploy actually sent, not
                // a fresh resolve: re-reading the repo would both redo the tree
                // walk and read the object store this leg never touches.
                match crate::provenance::publish_commit(repo, commit_oid, bundle).await {
                    Ok(reg) => {
                        st.message = format!("{}; registry publish {}", st.message, reg.tx_hash)
                    }
                    Err(e) => {
                        st.message = format!("{}; registry publish failed: {e}", st.message)
                    }
                }
            }
        }
        Err(e) => {
            unused = e.refundable(price);
            st.message = e.message;
        }
    }
    crate::kv::set_json(&evm_status_key(repo), &st);
    crate::feed::evm_deployed(repo, &commit, st.ok, &st.message);
    (st, unused)
}

/// Run every deploy leg `job` carries for this commit -- wasm-to-canister,
/// EVM CREATE, or both -- from its verified artifacts alone, once its configs
/// are shown to be the repo's (`configs::check_job`). Each leg
/// persists its own status and provenance; the returned DeployStatus carries
/// the wasm leg's summary plus the EVM leg's outcome folded into the message.
/// Never traps. `force` redeploys a commit the EVM provenance log already
/// shows accepted (deploy_now); the push path passes false and dedupes.
async fn run(repo: &str, commit_oid: Oid, job: Job, force: bool) -> DeployStatus {
    let mut st = DeployStatus {
        commit: oid_hex(&commit_oid),
        ok: false,
        message: String::new(),
        wasm_len: 0,
        wasm_sha256: String::new(),
    };
    // The configs are this side's (configs.rs): a job runs only when the
    // ones it carries are the repo's, so where it installs is the repo's
    // choice and not the job builder's.
    let job = match crate::configs::check_job(repo, job) {
        Ok(job) => job,
        Err(e) => {
            st.message = e;
            put_status(repo, &st);
            return st;
        }
    };
    let (wasm_cfg, wasm_artifact) = job.wasm.unzip();
    let (evm_cfg, evm_artifact) = job.evm.unzip();
    if wasm_cfg.is_none() && evm_cfg.is_none() {
        // Nothing to record against: the logs are keyed to a config's source.
        st.message = "no deploy config for repo".into();
        put_status(repo, &st);
        return st;
    }

    // Tenancy (docs/TENANCY.md): a repo can require voter approval before a
    // commit deploys, and the owner pays for each action up front. Both are
    // recorded as the outcome rather than trapped on; the job is consumed.
    if !crate::tenancy::approved(repo, &st.commit) {
        st.message = "awaiting voter approval; see get_votes".into();
        put_status(repo, &st);
        return st;
    }
    let pricing = crate::tenancy::pricing();
    // A governed repo's install into its app canister is recorded on chain
    // as <repo>#app (docs/GOVERNANCE.md, section 3): one EVM action, charged
    // with the deploy and refunded if the publish fails before broadcast.
    let app_record = wasm_cfg.as_ref().is_some_and(|cfg| crate::tenancy::governed_target(repo, &cfg.target))
        && crate::evm::get_registry().is_some();
    let cost = wasm_cfg.as_ref().map_or(0, |_| pricing.ic_deploy)
        + evm_cfg.as_ref().map_or(0, |_| pricing.evm_action)
        + if app_record { pricing.evm_action } else { 0 };
    let payer = match crate::tenancy::charge_action(repo, cost, "deploy") {
        Ok(payer) => payer,
        Err(e) => {
            st.message = e;
            put_status(repo, &st);
            return st;
        }
    };

    put_status(
        repo,
        &DeployStatus {
            message: DEPLOYING.into(),
            ..st.clone()
        },
    );

    match (&wasm_cfg, wasm_artifact) {
        (Some(cfg), Some(artifact)) => {
            match attempt(repo, cfg, &commit_oid, artifact, &mut st).await {
                Ok(message) => {
                    st.ok = true;
                    st.message = message;
                }
                Err(e) => st.message = e,
            }
            put_status(repo, &st);
            record(repo, cfg, &st);
        }
        // EVM-only repo: the wasm leg vacuously succeeds.
        _ => st.ok = true,
    }
    // Whether the wasm leg installed, before the EVM leg folds its outcome
    // into `st.ok`: the announce is about what the canister runs, which the
    // EVM leg does not change.
    let wasm_installed = wasm_cfg.is_some() && st.ok;

    // The backend record, right after the install it describes: the commit
    // and the hash of the module now running. Like the announce below it
    // never affects `ok` -- the install happened -- and its outcome lands in
    // the message. A failed install publishes nothing: the canister still
    // runs what the last record says.
    if app_record {
        if wasm_installed {
            // As for the announce below: deploy_now runs outside the queue,
            // so a newer deploy can write its status during the publish
            // await; annotate only while the status is still this one.
            let before = st.clone();
            let note = match crate::provenance::app_record(repo, &commit_oid, &st.wasm_sha256) {
                Ok(rec) => match crate::provenance::publish(&rec).await {
                    // Broadcast, not mined: the record exists once the
                    // chain includes the transaction (evm_receipt shows
                    // that), and only then does the backend check's read
                    // of the registry see it.
                    Ok(reg) => format!("; app record tx {}", reg.tx_hash),
                    Err(e) => {
                        crate::tenancy::refund_action(payer, e.refundable(pricing.evm_action));
                        format!("; app record failed: {}", e.message)
                    }
                },
                Err(e) => {
                    crate::tenancy::refund_action(payer, pricing.evm_action);
                    format!("; app record failed: {e}")
                }
            };
            st.message.push_str(&note);
            if is_current(repo, &before) {
                put_status(repo, &st);
            }
        } else {
            crate::tenancy::refund_action(payer, pricing.evm_action);
        }
    }

    if let (Some(cfg), Some(artifact)) = (evm_cfg, evm_artifact) {
        let (evm_st, unused) =
            run_evm(repo, &cfg, &commit_oid, artifact, force, pricing.evm_action).await;
        crate::tenancy::refund_action(payer, unused);
        let leg = if evm_st.ok {
            format!("evm: {} ({})", evm_st.contract_address, evm_st.tx_hash)
        } else {
            format!("evm: {}", evm_st.message)
        };
        st.ok = st.ok && evm_st.ok;
        st.message = if st.message.is_empty() {
            leg
        } else {
            format!("{}; {leg}", st.message)
        };
        // The wasm arm persisted before this fold, and the push path discards
        // the return value: without this write, get_deploy_status would report
        // ok even when the EVM leg failed.
        put_status(repo, &st);
    }

    // Optional ic-name-service hook (names.rs): announce the wasm install
    // whenever it succeeded, whatever the EVM leg did -- the record names
    // the canister and the module it runs, which is true once install_code
    // returns, and a deploy whose EVM leg failed would otherwise leave the
    // name on an older commit than the canister runs, with no later deploy
    // to announce it. It runs last, so the EVM leg never waits on the name
    // service. Never affects `ok`; the note, like any EVM failure, lands in
    // the deploy status message, so what failed is recorded there and only
    // what succeeded reaches the name service.
    //
    // deploy_now runs outside the queue, so a newer deploy of this repo can
    // run while this one awaits. So:
    // - before sending: if a newer deploy has since installed, the target no
    //   longer runs this commit and that deploy owns the announce; skip, or
    //   the name service could end up on an older commit than the target
    //   runs. A newer deploy that was refused or failed its install leaves
    //   the target on this commit, so it does not count. announce() has no
    //   await before its call, so this check and the send are one message
    //   execution, and a deploy installing after it announces later, which
    //   the IC delivers after ours (calls between two canisters stay in
    //   order).
    // - the deploy log's record of each install is definite: install_code
    //   is an unbounded-wait call, which on the IC always gets a reply or a
    //   definite reject, never an unknown outcome (only bounded-wait calls
    //   can time out with SYS_UNKNOWN). So an install logged as failed did
    //   not happen, and cannot leave the target running code that no
    //   announce names. Switching install_code to a bounded-wait call would
    //   break that and must then log an unknown outcome as one.
    // - after the reply: annotate only while the status is still this one.
    if let (Some(cfg), true, Some(names_cfg)) = (&wasm_cfg, wasm_installed, crate::names::get_config()) {
        if !is_latest_install(repo, &cfg.target, &st) {
            return st;
        }
        let before = st.clone();
        let note =
            crate::names::announce(&names_cfg, repo, &cfg.target, &st.commit, &st.wasm_sha256)
                .await;
        st.message.push_str(&note);
        if is_current(repo, &before) {
            put_status(repo, &st);
        }
    }
    st
}

/// The repo's latest successful install recorded in its deploy log.
fn latest_install(repo: &str) -> Option<DeployRecord> {
    get_history(repo).into_iter().rev().find(|r| r.ok)
}

/// Whether `st`'s install into `target` is still the repo's latest
/// successful one, i.e. no other deploy of the repo has installed since.
/// The target counts too: after a config change, the same commit installed
/// into a new target takes the announce over from the old one.
fn is_latest_install(repo: &str, target: &str, st: &DeployStatus) -> bool {
    latest_install(repo).is_some_and(|r| {
        r.target == target && r.commit == st.commit && r.wasm_sha256 == st.wasm_sha256
    })
}

/// Whether the repo's stored deploy status is still `st`, i.e. no other
/// deploy of the repo has written its status since `st` was stored.
fn is_current(repo: &str, st: &DeployStatus) -> bool {
    get_status(repo).is_some_and(|s| s.commit == st.commit && s.message == st.message)
}

/// deploy_now's job: the git side's release commit -- the deploy-branch
/// tip, or with votes required the approved commit the site serves -- and
/// its job (phase 3, step 10: `release_job`). Nothing here believes it:
/// `run` checks its configs against this side's, its commit against this
/// side's ballots, and each artifact's proof against the commit.
pub async fn release_job(repo: &str) -> Result<(Oid, Job), String> {
    let r = crate::to_git::release_job(repo)
        .await
        .map_err(|f| format!("the git side did not answer ({f}); nothing was charged, ask again"))??;
    Ok((parse_oid(&r.commit)?, r.job))
}

/// Run `job` for `commit` now, without the queue. Always deploys, even if
/// the commit is already in the provenance log -- the explicit-redeploy
/// escape hatch (deploy_now), and the retry for a failed deploy of an
/// approved commit below an unapproved tip.
pub async fn run_now(repo: &str, commit: Oid, job: Job) -> DeployStatus {
    run(repo, commit, job, true).await
}

/// Is the app already running `commit`? The wasm leg is when the latest
/// successful install recorded for the repo is that commit, into the
/// target configured now -- a failed attempt does not count, so a retry is
/// not mistaken for a no-op, and neither does an install into a target the
/// config has since left; the EVM leg is when that commit's contract was
/// deployed. A leg that is not configured has nothing to run.
pub fn is_live(repo: &str, commit_hex: &str, wasm_target: Option<&str>, evm_configured: bool) -> bool {
    let wasm = wasm_target.is_none_or(|target| latest_install(repo).is_some_and(|r| r.commit == commit_hex && r.target == target));
    let evm = !evm_configured || evm::latest_deploy(repo, commit_hex).is_some();
    wasm && evm
}

fn in_queue(jobs: &[DeployJob], repo: &str, commit_hex: &str) -> bool {
    jobs.iter().any(|j| j.repo == repo && j.commit == commit_hex)
}

fn deploying(repo: &str, commit_hex: &str) -> bool {
    get_status(repo).is_some_and(|s| s.commit == commit_hex && s.message == DEPLOYING)
}

/// Is a deploy of `commit` waiting in the queue or running now? Queueing it
/// again would install it twice and charge twice.
pub fn in_flight(repo: &str, commit_hex: &str) -> bool {
    in_queue(&queue_load(), repo, commit_hex) || deploying(repo, commit_hex)
}

/// What the app runs, as far as this side's deploys say: the commit every
/// configured leg last deployed successfully, the wasm leg's into the
/// target configured now; `None` when a leg failed, never ran, or the
/// legs disagree, or nothing is configured. A ballot's retry ask carries
/// it (mirrors.rs), so the git side, which alone knows the served commit,
/// can tell whether there is anything to retry before it builds a job.
/// The intake (`accept`) still checks the job it is handed.
pub fn running(repo: &str) -> Option<String> {
    let cfg = crate::configs::get(repo);
    let wasm = cfg.wasm.map(|c| {
        let st = get_status(repo).filter(|s| s.ok)?;
        latest_install(repo).filter(|r| r.commit == st.commit && r.target == c.target).map(|r| r.commit)
    });
    let evm = cfg.evm.map(|_| get_evm_status(repo).filter(|s| s.ok).map(|s| s.commit));
    let mut commit: Option<String> = None;
    for leg in [wasm, evm].into_iter().flatten() {
        let c = leg?;
        if commit.as_ref().is_some_and(|x| *x != c) {
            return None;
        }
        commit = Some(c);
    }
    commit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::{get_config, resolve};
    use crate::store::ObjectType;
    use crate::{gitproof, store};

    /// The config setter (configs.rs), which also writes the git side's
    /// mirror that `resolve` reads.
    fn set_config(repo: &str, target: String, source_path: String) -> Result<(), String> {
        futures::executor::block_on(crate::configs::set_wasm(repo, target, source_path))
    }

    /// A commit whose root tree holds `files` (plain names only).
    fn commit_of(files: &[(&str, &[u8])]) -> Oid {
        let mut root = Vec::new();
        let mut files = files.to_vec();
        files.sort_by_key(|(name, _)| *name);
        for (name, bytes) in files {
            root.extend_from_slice(format!("100644 {name}\0").as_bytes());
            root.extend_from_slice(store::put_object(ObjectType::Blob, bytes).as_slice());
        }
        let tree = store::put_object(ObjectType::Tree, &root);
        let commit = format!("tree {}\n\ncommit\n", store::oid_hex(&tree));
        store::put_object(ObjectType::Commit, commit.as_bytes())
    }

    /// deploy_now asks the git side for the release commit's job: the tip
    /// and the job built for it; an unanswered ask fails with nothing run,
    /// and a job whose artifact is not what the commit holds is refused by
    /// the run, as a queued one is.
    #[test]
    fn deploy_now_asks_the_git_side_for_the_release_job() {
        use crate::to_git::flaky::{Flaky, Inject};
        crate::tenancy::test_repo("released");
        set_config("released", "aaaaa-aa".into(), "app.wasm".into()).unwrap();
        let tip = store::commit_file_for_tests("released", "app.wasm", b"\0asm\x01\0\0\0", None);
        let git = std::rc::Rc::new(Flaky::new());
        crate::to_git::set_test_side(Some(git.clone()));
        git.inject("release_job", Inject::Lost);
        let e = futures::executor::block_on(release_job("released")).err().unwrap();
        assert!(e.contains("ask again"), "{e}");
        let (commit, mut job) = futures::executor::block_on(release_job("released")).unwrap();
        assert_eq!(commit, tip);
        crate::to_git::set_test_side(None);
        // A forged blob: the run refuses it, as it refuses a queued one.
        let Some((_, Ok(a))) = job.wasm.as_mut() else { panic!("the release job carries the wasm leg") };
        a.blob = b"\0asm\x01\0\0\0forged".to_vec();
        let st = futures::executor::block_on(run_now("released", commit, job));
        assert!(!st.ok);
        assert!(st.message.contains("refused"), "{}", st.message);
    }

    /// A queued job keeps the config and bytes it was queued with, and a
    /// module of megabytes survives the trip through its stable map. Editing
    /// the config afterwards changes nothing it would deploy: the queue
    /// refuses it instead (configs::check_job), and deploy_now runs the
    /// current config.
    #[test]
    fn a_job_is_fixed_when_queued() {
        crate::tenancy::test_repo("fixed");
        let module = vec![7u8; 3 << 20];
        let commit = commit_of(&[("app.wasm", &module), ("other.wasm", b"other")]);
        set_config("fixed", "aaaaa-aa".into(), "app.wasm".into()).unwrap();
        job_save("fixed", &commit, &resolve("fixed", &commit));
        set_config("fixed", "aaaaa-aa".into(), "other.wasm".into()).unwrap();

        let hex = store::oid_hex(&commit);
        let job = job_take("fixed", &hex).expect("the job decodes");
        assert!(job.evm.is_none());
        assert_eq!(job.wasm.as_ref().unwrap().0.source_path, "app.wasm");
        assert!(job_take("fixed", &hex).is_none(), "taking a job removes it");
        let e = crate::configs::check_job("fixed", job).err().unwrap();
        assert!(e.contains("the job installs app.wasm") && e.contains("other.wasm"), "{e}");

        set_config("fixed", "aaaaa-aa".into(), "app.wasm".into()).unwrap();
        job_save("fixed", &commit, &resolve("fixed", &commit));
        let job = crate::configs::check_job("fixed", job_take("fixed", &hex).unwrap()).unwrap();
        let (cfg, artifact) = job.wasm.unwrap();
        assert_eq!(artifact.unwrap().verified(&c20(&commit), &cfg.source_path).unwrap(), module);
    }

    /// The drain deploys only bytes whose proof checks against the job's
    /// commit and path; what could not be resolved is carried as the reason.
    #[test]
    fn a_job_deploys_only_proven_bytes() {
        crate::tenancy::test_repo("proven");
        let commit = commit_of(&[("app.wasm", b"good"), ("c.hex", b"0x6001")]);
        let other = commit_of(&[("app.wasm", b"evil")]);
        let a = || resolve_one(&commit, "app.wasm");

        let mut swapped = a();
        swapped.blob = b"evil".to_vec();
        let refused = swapped.verified(&c20(&commit), "app.wasm").unwrap_err();
        assert!(refused.starts_with("proof of app.wasm refused"), "{refused}");
        assert!(a().verified(&c20(&other), "app.wasm").is_err(), "another commit");
        assert!(a().verified(&c20(&commit), "c.hex").is_err(), "another path");
        assert_eq!(a().verified(&c20(&commit), "/app.wasm").unwrap(), b"good");

        set_config("proven", "aaaaa-aa".into(), "missing.wasm".into()).unwrap();
        let (_, missing) = resolve("proven", &commit).wasm.unwrap();
        assert!(missing.err().unwrap().starts_with("resolve missing.wasm: "));
    }

    /// A payload whose job was drained without it (a rollback to a release
    /// that does not know the map) is freed on the next upgrade.
    #[test]
    fn an_upgrade_frees_payloads_no_job_names() {
        crate::records::deploy_job_put(&job_key("gone", &"ab".repeat(20)), vec![1, 2, 3]);
        resume_pending();
        assert!(crate::records::deploy_job_keys().is_empty());
    }

    fn c20(commit: &Oid) -> [u8; 20] {
        ic_git_types::oid::commit20(commit).unwrap()
    }

    fn resolve_one(commit: &Oid, path: &str) -> Artifact {
        let (blob, proof) = gitproof::prove(commit, path).unwrap();
        Artifact { blob, proof }
    }

    /// Only .wasm passes for a governed repo; an ungoverned one may still
    /// compile .wat and .lang.
    #[test]
    fn governed_sources_are_wasm_only() {
        for path in ["a.wat", "a.lang", "a.wasm"] {
            assert!(SourceKind::for_repo(false, path).is_ok(), "{path}");
        }
        assert_eq!(SourceKind::for_repo(true, "a.wasm"), Ok(SourceKind::Wasm));
        for path in ["a.wat", "a.lang"] {
            let e = SourceKind::for_repo(true, path).unwrap_err();
            assert!(e.contains(".wasm only"), "{e}");
        }
        assert!(SourceKind::for_repo(true, "a.txt").unwrap_err().contains("must end in"));
    }

    fn status(commit: &str, ok: bool, message: &str) -> DeployStatus {
        DeployStatus {
            commit: commit.into(),
            ok,
            message: message.into(),
            wasm_len: 0,
            wasm_sha256: String::new(),
        }
    }

    /// What the app runs is the latest *successful* install: a failed
    /// attempt at a commit must not read as live, or an approval could
    /// never retry it. Rolling back to an older commit is not live until it
    /// is installed again.
    #[test]
    fn live_means_last_successful_install() {
        crate::tenancy::test_repo("live");
        let t = Some("aaaaa-aa");
        // Nothing configured: nothing to run, so any commit is live.
        assert!(is_live("live", "c1", None, false));
        set_config("live", "aaaaa-aa".into(), "app.wasm".into()).unwrap();
        let cfg = get_config("live").unwrap();
        assert!(!is_live("live", "c1", t, false));
        record("live", &cfg, &status("c1", true, "installed"));
        assert!(is_live("live", "c1", t, false));
        record("live", &cfg, &status("c2", false, "install_code failed"));
        assert!(!is_live("live", "c2", t, false));
        assert!(is_live("live", "c1", t, false));
        record("live", &cfg, &status("c2", true, "installed"));
        assert!(is_live("live", "c2", t, false));
        assert!(!is_live("live", "c1", t, false));
        // The target moved: the install into the old one does not count.
        assert!(!is_live("live", "c2", Some("2vxsx-fae"), false));
    }

    /// What the app runs is the commit every configured leg last deployed
    /// successfully, the wasm leg's into the target configured now, and
    /// nothing this side can vouch for otherwise.
    #[test]
    fn running_is_the_last_successful_deploy_at_the_target() {
        crate::tenancy::test_repo("step");
        assert_eq!(running("step"), None, "nothing configured");
        set_config("step", "aaaaa-aa".into(), "app.wasm".into()).unwrap();
        let cfg = get_config("step").unwrap();
        assert_eq!(running("step"), None, "never deployed");
        put_status("step", &status("c1", false, "install_code failed"));
        record("step", &cfg, &status("c1", false, "install_code failed"));
        assert_eq!(running("step"), None);
        put_status("step", &status("c1", true, "installed"));
        record("step", &cfg, &status("c1", true, "installed"));
        assert_eq!(running("step").as_deref(), Some("c1"));
        put_status("step", &status("c2", false, DEPLOYING));
        assert_eq!(running("step"), None, "deploying: the retry is dropped as in flight instead");
        put_status("step", &status("c1", true, "installed"));
        set_config("step", "2vxsx-fae".into(), "app.wasm".into()).unwrap();
        assert_eq!(running("step"), None, "the target moved");
        // Both legs configured: they must agree. (The EVM config is written
        // as its setter would, which needs a chain configured first.)
        set_config("step", "aaaaa-aa".into(), "app.wasm".into()).unwrap();
        crate::kv::set_json(
            "deploy_evm:step",
            &ic_git_types::deploy::EvmDeployConfig {
                source_path: "c.hex".into(),
                gas_limit: 1_000_000,
            },
        );
        assert!(crate::configs::get("step").evm.is_some());
        assert_eq!(running("step"), None, "the EVM leg never ran");
        let evm = |commit: &str, ok: bool| EvmDeployStatus {
            commit: commit.into(),
            ok,
            message: String::new(),
            contract_address: String::new(),
            tx_hash: String::new(),
        };
        crate::kv::set_json(&evm_status_key("step"), &evm("c2", true));
        assert_eq!(running("step"), None, "the legs disagree");
        crate::kv::set_json(&evm_status_key("step"), &evm("c1", true));
        assert_eq!(running("step").as_deref(), Some("c1"));
    }

    /// A deploy an upgrade interrupted is recorded as a failure, so the
    /// commit is not in flight forever and a ballot can retry it; one
    /// whose job still waits in the queue is left deploying.
    #[test]
    fn an_upgrade_records_an_interrupted_deploy_as_failed() {
        put_status("cut", &status("c1", false, DEPLOYING));
        crate::kv::set_json(&evm_status_key("cut"), &EvmDeployStatus {
            commit: "c1".into(),
            ok: false,
            message: DEPLOYING.into(),
            contract_address: String::new(),
            tx_hash: String::new(),
        });
        put_status("still", &status("c2", false, DEPLOYING));
        queue_save(&[DeployJob { repo: "still".into(), commit: "c2".into() }]);
        crate::records::deploy_job_put(&job_key("still", "c2"), vec![1]);
        resume_pending();
        assert!(!in_flight("cut", "c1"));
        assert!(get_status("cut").unwrap().message.contains("interrupted"));
        assert!(get_evm_status("cut").unwrap().message.contains("interrupted"));
        assert!(in_flight("still", "c2"));
        assert_eq!(get_status("still").unwrap().message, DEPLOYING);
        queue_save(&[]);
    }

    /// The announce guard: a newer deploy that failed or was refused leaves
    /// the target on the older install, which is still announced; a newer
    /// successful install takes the announce over.
    #[test]
    fn a_newer_install_takes_the_announce_over() {
        crate::tenancy::test_repo("ann");
        set_config("ann", "aaaaa-aa".into(), "app.wasm".into()).unwrap();
        let cfg = get_config("ann").unwrap();
        let older = status("c1", true, "installed");
        assert!(!is_latest_install("ann", &cfg.target, &older));
        record("ann", &cfg, &older);
        assert!(is_latest_install("ann", &cfg.target, &older));
        put_status("ann", &status("c2", false, "awaiting voter approval; see get_votes"));
        record("ann", &cfg, &status("c2", false, "install_code failed"));
        assert!(is_latest_install("ann", &cfg.target, &older));
        record("ann", &cfg, &status("c2", true, "installed"));
        assert!(!is_latest_install("ann", &cfg.target, &older));
        // The same commit installed into a new target takes it over too.
        record("ann", &cfg, &older);
        assert!(is_latest_install("ann", &cfg.target, &older));
        set_config("ann", "2vxsx-fae".into(), "app.wasm".into()).unwrap();
        let moved = get_config("ann").unwrap();
        record("ann", &moved, &older);
        assert!(!is_latest_install("ann", &cfg.target, &older));
        assert!(is_latest_install("ann", &moved.target, &older));
    }

    /// A deploy already queued or running is not queued again.
    #[test]
    fn in_flight_covers_queued_and_running() {
        assert!(!in_flight("fly", "c1"));
        queue_save(&[DeployJob { repo: "fly".into(), commit: "c1".into() }]);
        assert!(in_flight("fly", "c1"));
        assert!(!in_flight("fly", "c2"));
        queue_save(&[]);
        put_status("fly", &status("c2", false, DEPLOYING));
        assert!(in_flight("fly", "c2"));
        put_status("fly", &status("c2", false, "install_code failed"));
        assert!(!in_flight("fly", "c2"));
    }

    /// A job the git side submitted is queued once: not again while it
    /// waits or runs, and not at all once the app runs the commit. A
    /// failed attempt is not running it, so a ballot's retry (the git side
    /// submits the served commit's job again) is queued.
    #[test]
    fn a_submitted_job_is_queued_unless_live_or_in_flight() {
        crate::tenancy::test_repo("accept");
        set_config("accept", "aaaaa-aa".into(), "app.wasm".into()).unwrap();
        let cfg = get_config("accept").unwrap();
        let commit = commit_of(&[("app.wasm", b"v1")]);
        let hex = store::oid_hex(&commit);
        let job = || resolve("accept", &commit);
        let queued = || queue_load().iter().filter(|j| j.repo == "accept").count();

        assert!(accept("accept", commit, job()));
        assert!(in_flight("accept", &hex));
        assert!(!accept("accept", commit, job()), "waiting already");
        assert_eq!(queued(), 1);
        // Running now: not queued again.
        queue_save(&[]);
        put_status("accept", &status(&hex, false, DEPLOYING));
        assert!(!accept("accept", commit, job()));
        // It failed: the app is not running it, so a retry is queued.
        put_status("accept", &status(&hex, false, "install_code failed"));
        record("accept", &cfg, &status(&hex, false, "install_code failed"));
        assert!(accept("accept", commit, job()));
        assert_eq!(queued(), 1);
        // It installed: nothing to queue.
        queue_save(&[]);
        put_status("accept", &status(&hex, true, "installed"));
        record("accept", &cfg, &status(&hex, true, "installed"));
        assert!(!accept("accept", commit, job()));
        assert_eq!(queued(), 0);
        // Another commit is not live, whatever this one did.
        let next = commit_of(&[("app.wasm", b"v2")]);
        assert!(accept("accept", next, resolve("accept", &next)));
    }
}
