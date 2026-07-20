//! Deploy path -- first slice of milestone 4 (see ../../../ARCHITECTURE.md and
//! ROADMAP.md). On a push to the deploy branch, read the configured source out
//! of the pushed commit's tree, build (or validate) it on-chain, and install
//! the resulting wasm into a target canister via the management canister's
//! `install_code`.
//!
//! This closes the loop the ROADMAP calls for: `git push` -> compile -> deploy,
//! entirely on-chain. Pushes enqueue a job; the deploy itself runs from a
//! timer-driven queue, off the push path.

use crate::store::{self, ObjectType, Oid};
use crate::{compile, evm, object};
use candid::{CandidType, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How to install the compiled wasm into the target.
///
/// `Upgrade` preserves the target's stable memory (the default -- safe for
/// stateful targets); `Reinstall` wipes all state. The very first deploy to an
/// empty target always uses plain install regardless, since upgrade requires an
/// existing module.
#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
pub enum DeployMode {
    #[default]
    #[serde(rename = "upgrade")]
    Upgrade,
    #[serde(rename = "reinstall")]
    Reinstall,
}

impl DeployMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "upgrade" => Ok(Self::Upgrade),
            "reinstall" => Ok(Self::Reinstall),
            _ => Err(format!("mode must be 'upgrade' or 'reinstall', got '{s}'")),
        }
    }
}

/// What to build and where to install it, per repo.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct DeployConfig {
    /// Target canister principal (text form) to install the compiled wasm into.
    /// The git canister must be one of its controllers.
    pub target: String,
    /// Path to the source within the repo tree. The compiler is chosen by
    /// extension: `.wat` (R0 assembler) or `.lang` (R1 language). Aliased from
    /// the old `wat_path` field so existing configs still load.
    #[serde(alias = "wat_path")]
    pub source_path: String,
    /// Install mode; defaults to Upgrade for configs written before this field
    /// existed.
    #[serde(default)]
    pub mode: DeployMode,
}

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

/// What builds the configured source, chosen by file extension. The single
/// place the extension list lives: `set_config` validates by parsing it, `run`
/// dispatches on it.
enum SourceKind {
    /// R0 assembler.
    Wat,
    /// R1 language compiler.
    Lang,
    /// A prebuilt artifact (build locally with real rustc, commit the wasm),
    /// validated and used as-is.
    Wasm,
}

impl SourceKind {
    fn from_path(path: &str) -> Result<Self, String> {
        if path.ends_with(".wat") {
            Ok(Self::Wat)
        } else if path.ends_with(".lang") {
            Ok(Self::Lang)
        } else if path.ends_with(".wasm") {
            Ok(Self::Wasm)
        } else {
            Err("source_path must end in .wat, .lang, or .wasm".into())
        }
    }

    /// Turn the committed source blob into deployable wasm. Either way the
    /// result is validated before it can be installed.
    fn build(self, path: &str, bytes: Vec<u8>) -> Result<Vec<u8>, String> {
        let source = |bytes: Vec<u8>| {
            String::from_utf8(bytes).map_err(|_| format!("{path} is not valid UTF-8"))
        };
        match self {
            Self::Wat => compile::compile_wat_checked(&source(bytes)?),
            Self::Lang => crate::lang::compile_checked(&source(bytes)?),
            Self::Wasm => {
                compile::validate_wasm(&bytes)?;
                Ok(bytes)
            }
        }
    }
}

/// Track A, phase E2: what a push deploys to an EVM chain, per repo. The
/// artifact is a committed hex file (creation bytecode) at `source_path` --
/// build-locally-commit-the-artifact, same rung as the wasm path's `.wasm`
/// SourceKind. The chain, key, and RPC provider come from the global
/// evm::EvmConfig; this only names the artifact and its gas budget.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EvmDeployConfig {
    /// Path within the repo tree to the creation bytecode as hex text (.hex).
    pub source_path: String,
    /// Gas limit for the CREATE transaction.
    pub gas_limit: u64,
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

// META keys for this module's persisted state (JSON via store::meta_*_json).
fn config_key(repo: &str) -> String {
    format!("deploy:{repo}")
}
fn evm_config_key(repo: &str) -> String {
    format!("deploy_evm:{repo}")
}
fn evm_status_key(repo: &str) -> String {
    format!("deploy_evm_status:{repo}")
}
fn status_key(repo: &str) -> String {
    format!("deploy_status:{repo}")
}
fn log_key(repo: &str) -> String {
    format!("deploy_log:{repo}")
}
const QUEUE_KEY: &str = "deploy_queue";

/// Set (or replace) a repo's deploy config, preserving any previously-chosen
/// install mode.
pub fn set_config(repo: &str, target: String, source_path: String) -> Result<(), String> {
    if !store::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    Principal::from_text(&target).map_err(|e| format!("bad target principal: {e}"))?;
    SourceKind::from_path(&source_path)?;
    let mode = get_config(repo).map(|c| c.mode).unwrap_or_default();
    let cfg = DeployConfig {
        target,
        source_path,
        mode,
    };
    store::meta_set_json(&config_key(repo), &cfg);
    Ok(())
}

/// Change a repo's install mode (upgrade vs reinstall) without touching the
/// rest of its config.
pub fn set_mode(repo: &str, mode: DeployMode) -> Result<(), String> {
    let mut cfg = get_config(repo).ok_or("no deploy config for repo")?;
    cfg.mode = mode;
    store::meta_set_json(&config_key(repo), &cfg);
    Ok(())
}

pub fn get_config(repo: &str) -> Option<DeployConfig> {
    store::meta_get_json(&config_key(repo))
}

/// Set (or replace) a repo's EVM deploy config. Requires the global EVM
/// signing config to exist first: a target with no way to reach it is a
/// misconfiguration better rejected here than discovered at push time.
pub fn set_evm_config(repo: &str, source_path: String, gas_limit: u64) -> Result<(), String> {
    if !store::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    if !source_path.ends_with(".hex") {
        return Err("source_path must end in .hex (creation bytecode as hex text)".into());
    }
    if evm::get_config().is_none() {
        return Err("no global EVM config; call evm_set_config first".into());
    }
    if gas_limit < 53_000 {
        return Err("gas_limit below the 53k floor of any CREATE".into());
    }
    store::meta_set_json(
        &evm_config_key(repo),
        &EvmDeployConfig {
            source_path,
            gas_limit,
        },
    );
    Ok(())
}

pub fn get_evm_config(repo: &str) -> Option<EvmDeployConfig> {
    store::meta_get_json(&evm_config_key(repo))
}

pub fn get_evm_status(repo: &str) -> Option<EvmDeployStatus> {
    store::meta_get_json(&evm_status_key(repo))
}

pub fn get_status(repo: &str) -> Option<DeployStatus> {
    store::meta_get_json(&status_key(repo))
}

fn put_status(repo: &str, st: &DeployStatus) {
    store::meta_set_json(&status_key(repo), st);
}

/// One entry in a repo's append-only deploy provenance log: the binding of an
/// on-chain commit to the wasm hash that was deployed from it. Because the
/// commit oid content-addresses the exact source tree and the wasm hash is
/// recorded here, this is a tamper-proof record of "commit C produced binary H"
/// that anyone can re-verify by reproducibly rebuilding commit C.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct DeployRecord {
    pub commit: String,
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
    store::meta_get_json(&log_key(repo)).unwrap_or_default()
}

/// Append the binding for this deploy to the provenance log.
fn record(repo: &str, cfg: &DeployConfig, st: &DeployStatus) {
    let mut log = get_history(repo);
    log.push(DeployRecord {
        commit: st.commit.clone(),
        source_path: cfg.source_path.clone(),
        wasm_sha256: st.wasm_sha256.clone(),
        wasm_len: st.wasm_len,
        ok: st.ok,
        message: st.message.clone(),
        at_ns: ic_cdk::api::time(),
    });
    if log.len() > MAX_LOG {
        let drop = log.len() - MAX_LOG;
        log.drain(0..drop);
    }
    store::meta_set_json(&log_key(repo), &log);
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

fn queue_load() -> Vec<DeployJob> {
    store::meta_get_json(QUEUE_KEY).unwrap_or_default()
}

fn queue_save(jobs: &[DeployJob]) {
    store::meta_set_json(QUEUE_KEY, &jobs);
}

/// Number of jobs waiting in the queue.
pub fn queue_len() -> usize {
    queue_load().len()
}

/// Append a deploy job and arm the drain timer. Returns immediately.
pub fn enqueue(repo: &str, commit: Oid) {
    let mut jobs = queue_load();
    jobs.push(DeployJob {
        repo: repo.to_string(),
        commit: store::oid_hex(&commit),
    });
    queue_save(&jobs);
    arm_timer();
}

/// Re-arm the drain timer if jobs are pending. Called from post_upgrade, since
/// timers do not survive upgrades.
pub fn resume_pending() {
    if !queue_load().is_empty() {
        arm_timer();
    }
}

/// Arm a zero-delay timer to drain one job. Safe to call redundantly: a timer
/// that fires on an empty queue is a no-op. In ic-cdk-timers 1.0 the timer
/// drives the future directly (its only await is the install_code call).
fn arm_timer() {
    ic_cdk_timers::set_timer(Duration::ZERO, drain_one());
}

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

    if let Ok(commit) = store::parse_oid(&job.commit) {
        run(&job.repo, commit).await;
    }
    DRAINING.with(|f| f.set(false));
    // Re-read the queue rather than trusting the pre-run snapshot: a push
    // that arrived during the await armed a timer that bailed on DRAINING
    // above, so its job is ours to pick up.
    if !queue_load().is_empty() {
        arm_timer();
    }
}

/// The trimmed hex text of an EVM artifact at `path` within a commit's tree.
/// The one resolution path shared by the deploy leg and the registry
/// publisher, so both end up hashing the same bytes.
pub fn evm_artifact_hex(commit_oid: &Oid, path: &str) -> Result<String, String> {
    let bytes = blob_at_path(commit_oid, path).map_err(|e| format!("resolve {path}: {e}"))?;
    let text = String::from_utf8(bytes).map_err(|_| format!("{path} is not valid UTF-8"))?;
    Ok(text.trim().to_string())
}

/// Resolve a slash-separated path within a commit's tree to the blob content.
fn blob_at_path(commit_oid: &Oid, path: &str) -> Result<Vec<u8>, String> {
    let (ty, content) = store::get_object_parsed(commit_oid).ok_or("commit object missing")?;
    if ty != ObjectType::Commit {
        return Err("ref tip is not a commit".into());
    }
    let mut tree_oid = object::commit_refs(&content)?.tree;

    // Look up `comp` in the tree at `tree_oid`.
    let lookup = |tree_oid: &Oid, comp: &str| -> Result<Oid, String> {
        let (tty, tcontent) = store::get_object_parsed(tree_oid).ok_or("tree object missing")?;
        if tty != ObjectType::Tree {
            return Err(format!("path component '{comp}' is not a directory"));
        }
        Ok(object::tree_entries(&tcontent)?
            .into_iter()
            .find(|e| e.name == comp.as_bytes())
            .ok_or_else(|| format!("path not found: {comp}"))?
            .oid)
    };

    let comps: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let Some((file, dirs)) = comps.split_last() else {
        return Err("empty path".into());
    };
    for comp in dirs {
        tree_oid = lookup(&tree_oid, comp)?;
    }
    let blob_oid = lookup(&tree_oid, file)?;
    let (bty, bcontent) = store::get_object_parsed(&blob_oid).ok_or("blob object missing")?;
    if bty != ObjectType::Blob {
        return Err(format!("'{file}' is not a file"));
    }
    Ok(bcontent)
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
async fn install(
    target: Principal,
    wasm: Vec<u8>,
    mode: DeployMode,
) -> Result<&'static str, String> {
    let (install_mode, label) = if !target_has_module(target).await? {
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
    intercanister::call::<(InstallCodeArgument,), ()>(
        Principal::management_canister(),
        "install_code",
        (arg,),
    )
    .await?;
    Ok(label)
}

/// The fallible steps of a deploy: resolve the source blob, build it, install
/// it. Fills in `st`'s wasm summary as soon as the build succeeds, so failed
/// installs still record what was built. Returns the success message.
async fn attempt(
    cfg: &DeployConfig,
    commit_oid: &Oid,
    st: &mut DeployStatus,
) -> Result<String, String> {
    let target =
        Principal::from_text(&cfg.target).map_err(|e| format!("bad target principal: {e}"))?;
    let src_bytes = blob_at_path(commit_oid, &cfg.source_path)
        .map_err(|e| format!("resolve {}: {e}", cfg.source_path))?;
    let wasm = SourceKind::from_path(&cfg.source_path)
        .and_then(|kind| kind.build(&cfg.source_path, src_bytes))
        .map_err(|e| format!("build {}: {e}", cfg.source_path))?;
    let info = compile::info_of(&wasm);
    st.wasm_len = info.wasm_len;
    st.wasm_sha256 = info.sha256_hex;
    let label = install(target, wasm, cfg.mode)
        .await
        .map_err(|e| format!("install_code failed: {e}"))?;
    Ok(format!("{label} to {}", cfg.target))
}

/// The fallible steps of an EVM deploy: resolve the committed hex artifact,
/// decode-check it, and hand it to evm::deploy_bytecode, which signs a CREATE
/// with the commit oid threaded into the provenance record.
async fn attempt_evm(
    repo: &str,
    cfg: &EvmDeployConfig,
    commit_oid: &Oid,
) -> Result<crate::evm::TxOutcome, String> {
    let hex_text = evm_artifact_hex(commit_oid, &cfg.source_path)?;
    evm::deploy_bytecode(
        repo.to_string(),
        hex_text,
        cfg.gas_limit,
        store::oid_hex(commit_oid),
    )
    .await
}

/// Run a repo's configured EVM deploy and persist its status. Never traps.
async fn run_evm(repo: &str, cfg: &EvmDeployConfig, commit_oid: &Oid) -> EvmDeployStatus {
    let mut st = EvmDeployStatus {
        commit: store::oid_hex(commit_oid),
        ok: false,
        message: String::new(),
        contract_address: String::new(),
        tx_hash: String::new(),
    };
    match attempt_evm(repo, cfg, commit_oid).await {
        Ok(out) => {
            st.ok = true;
            st.contract_address = out.contract_address.unwrap_or_default();
            st.tx_hash = out.tx_hash;
            st.message = format!("deployed to {} (chain via evm config)", st.contract_address);
        }
        Err(e) => st.message = e,
    }
    store::meta_set_json(&evm_status_key(repo), &st);
    st
}

/// Whether a push to the deploy branch should enqueue a deploy: true when
/// either the wasm-to-canister or the EVM target is configured.
pub fn any_config(repo: &str) -> bool {
    get_config(repo).is_some() || get_evm_config(repo).is_some()
}

/// Run every configured deploy leg for this commit -- wasm-to-canister,
/// EVM CREATE, or both. Each leg persists its own status and provenance;
/// the returned DeployStatus carries the wasm leg's summary plus the EVM
/// leg's outcome folded into the message. Never traps.
pub async fn run(repo: &str, commit_oid: Oid) -> DeployStatus {
    let mut st = DeployStatus {
        commit: store::oid_hex(&commit_oid),
        ok: false,
        message: String::new(),
        wasm_len: 0,
        wasm_sha256: String::new(),
    };
    let wasm_cfg = get_config(repo);
    let evm_cfg = get_evm_config(repo);
    if wasm_cfg.is_none() && evm_cfg.is_none() {
        // Nothing to record against: the logs are keyed to a config's source.
        st.message = "no deploy config for repo".into();
        put_status(repo, &st);
        return st;
    }

    match &wasm_cfg {
        Some(cfg) => {
            match attempt(cfg, &commit_oid, &mut st).await {
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
        None => st.ok = true,
    }

    if let Some(cfg) = evm_cfg {
        let evm_st = run_evm(repo, &cfg, &commit_oid).await;
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
    st
}

/// The branch whose pushes trigger deploys: the repo's HEAD symref target
/// (e.g. refs/heads/main). None if the repo does not exist.
pub fn deploy_branch(repo: &str) -> Option<String> {
    store::head_target(repo)
}

/// Run the configured deploy against the repo's current deploy-branch tip,
/// without waiting for a push.
pub async fn run_current(repo: &str) -> Result<DeployStatus, String> {
    let branch = deploy_branch(repo).ok_or(format!("no such repo: {repo}"))?;
    let tip = store::get_ref(repo, &branch).ok_or("deploy branch has no commits")?;
    Ok(run(repo, tip).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build blob -> subtree -> tree -> commit in the store, then resolve.
    #[test]
    fn resolves_nested_blob_path() {
        let blob = store::put_object(ObjectType::Blob, b"(module)");

        let mut subtree = Vec::new();
        subtree.extend_from_slice(b"100644 app.wat\0");
        subtree.extend_from_slice(blob.as_slice());
        let subtree_oid = store::put_object(ObjectType::Tree, &subtree);

        let mut tree = Vec::new();
        tree.extend_from_slice(b"40000 build\0");
        tree.extend_from_slice(subtree_oid.as_slice());
        let tree_oid = store::put_object(ObjectType::Tree, &tree);

        let commit = format!(
            "tree {}\nauthor a <a@a> 0 +0000\ncommitter a <a@a> 0 +0000\n\nmsg\n",
            store::oid_hex(&tree_oid)
        );
        let commit_oid = store::put_object(ObjectType::Commit, commit.as_bytes());

        assert_eq!(blob_at_path(&commit_oid, "build/app.wat").unwrap(), b"(module)");
        assert!(blob_at_path(&commit_oid, "build/missing.wat").is_err());
        assert!(blob_at_path(&commit_oid, "nope").is_err());
        // A file where a directory is expected.
        assert!(blob_at_path(&commit_oid, "build/app.wat/x").is_err());
    }
}
