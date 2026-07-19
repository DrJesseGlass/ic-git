//! Deploy path -- first slice of milestone 4 (see ../../../ARCHITECTURE.md and
//! ROADMAP.md). On a push to the deploy branch, read a WAT file out of the
//! pushed commit's tree, compile and validate it on-chain, and install the
//! resulting wasm into a target canister via the management canister's
//! `install_code`.
//!
//! This closes the loop the ROADMAP calls for: `git push` -> compile -> deploy,
//! entirely on-chain. It runs inline on the push's update call for now; the
//! ARCHITECTURE's timer-driven queue can move it off the push path later.

use crate::store::{self, ObjectType, Oid};
use crate::{compile, object};
use candid::{CandidType, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// What to build and where to install it, per repo.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct DeployConfig {
    /// Target canister principal (text form) to install the compiled wasm into.
    /// The git canister must be one of its controllers.
    pub target: String,
    /// Path to the WAT source within the repo tree, e.g. "main.wat" or
    /// "build/app.wat".
    pub wat_path: String,
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

pub fn set_config(repo: &str, cfg: &DeployConfig) -> Result<(), String> {
    Principal::from_text(&cfg.target).map_err(|e| format!("bad target principal: {e}"))?;
    if cfg.wat_path.is_empty() {
        return Err("wat_path is empty".into());
    }
    let bytes = serde_json::to_vec(cfg).map_err(|e| e.to_string())?;
    store::set_deploy_config(repo, bytes);
    Ok(())
}

pub fn get_config(repo: &str) -> Option<DeployConfig> {
    store::get_deploy_config(repo).and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn get_status(repo: &str) -> Option<DeployStatus> {
    store::get_deploy_status(repo).and_then(|b| serde_json::from_slice(&b).ok())
}

fn put_status(repo: &str, st: &DeployStatus) {
    if let Ok(bytes) = serde_json::to_vec(st) {
        store::set_deploy_status(repo, bytes);
    }
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
    store::get_deploy_queue()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn queue_save(jobs: &[DeployJob]) {
    if let Ok(bytes) = serde_json::to_vec(jobs) {
        store::set_deploy_queue(bytes);
    }
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
pub fn arm_timer() {
    ic_cdk_timers::set_timer(Duration::ZERO, drain_one());
}

/// Pop the front job, run it, and re-arm if more remain. The job is removed
/// (and the removal persisted) before running, so a job can never loop forever;
/// `run` records its own outcome and is written never to trap.
async fn drain_one() {
    let mut jobs = queue_load();
    if jobs.is_empty() {
        return;
    }
    let job = jobs.remove(0);
    let more_remain = !jobs.is_empty();
    queue_save(&jobs);

    if let Ok(commit) = store::parse_oid(&job.commit) {
        run(&job.repo, commit).await;
    }
    if more_remain {
        arm_timer();
    }
}

/// Resolve a slash-separated path within a commit's tree to the blob content.
fn blob_at_path(commit_oid: &Oid, path: &str) -> Result<Vec<u8>, String> {
    let (ty, content) = store::get_object_parsed(commit_oid).ok_or("commit object missing")?;
    if ty != ObjectType::Commit {
        return Err("ref tip is not a commit".into());
    }
    let mut tree_oid = object::commit_refs(&content)?.tree;

    let comps: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if comps.is_empty() {
        return Err("empty path".into());
    }
    for (i, comp) in comps.iter().enumerate() {
        let (tty, tcontent) = store::get_object_parsed(&tree_oid).ok_or("tree object missing")?;
        if tty != ObjectType::Tree {
            return Err(format!("path component '{comp}' is not a directory"));
        }
        let entry = object::tree_entries(&tcontent)?
            .into_iter()
            .find(|e| e.name == comp.as_bytes())
            .ok_or_else(|| format!("path not found: {comp}"))?;
        if i + 1 == comps.len() {
            let (bty, bcontent) =
                store::get_object_parsed(&entry.oid).ok_or("blob object missing")?;
            if bty != ObjectType::Blob {
                return Err(format!("'{comp}' is not a file"));
            }
            return Ok(bcontent);
        }
        tree_oid = entry.oid;
    }
    unreachable!("loop returns on the last component")
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
}

#[derive(CandidType, Deserialize)]
struct InstallCodeArgument {
    mode: CanisterInstallMode,
    canister_id: Principal,
    wasm_module: Vec<u8>,
    arg: Vec<u8>,
}

async fn install(target: Principal, wasm: Vec<u8>) -> Result<(), String> {
    // reinstall works whether or not the target already has a module, and
    // always yields exactly the module we built. State is discarded -- fine for
    // the trivial modules this rung deploys; upgrade mode comes later.
    let arg = InstallCodeArgument {
        mode: CanisterInstallMode::Reinstall,
        canister_id: target,
        wasm_module: wasm,
        arg: vec![],
    };
    intercanister::call::<(InstallCodeArgument,), ()>(
        Principal::management_canister(),
        "install_code",
        (arg,),
    )
    .await
}

/// Compile the configured WAT from the commit's tree, validate it, and install
/// it into the target canister. Records and returns the outcome; never traps.
pub async fn run(repo: &str, commit_oid: Oid) -> DeployStatus {
    let mut st = DeployStatus {
        commit: store::oid_hex(&commit_oid),
        ok: false,
        message: String::new(),
        wasm_len: 0,
        wasm_sha256: String::new(),
    };

    let cfg = match get_config(repo) {
        Some(c) => c,
        None => {
            st.message = "no deploy config for repo".into();
            put_status(repo, &st);
            return st;
        }
    };
    let target = match Principal::from_text(&cfg.target) {
        Ok(p) => p,
        Err(e) => {
            st.message = format!("bad target principal: {e}");
            put_status(repo, &st);
            return st;
        }
    };
    let wat_bytes = match blob_at_path(&commit_oid, &cfg.wat_path) {
        Ok(b) => b,
        Err(e) => {
            st.message = format!("resolve {}: {e}", cfg.wat_path);
            put_status(repo, &st);
            return st;
        }
    };
    let wat = match String::from_utf8(wat_bytes) {
        Ok(s) => s,
        Err(_) => {
            st.message = format!("{} is not valid UTF-8", cfg.wat_path);
            put_status(repo, &st);
            return st;
        }
    };
    let wasm = match compile::compile_wat_checked(&wat) {
        Ok(w) => w,
        Err(e) => {
            st.message = format!("compile/validate failed: {e}");
            put_status(repo, &st);
            return st;
        }
    };
    st.wasm_len = wasm.len() as u64;
    st.wasm_sha256 = hex::encode(Sha256::digest(&wasm));

    match install(target, wasm).await {
        Ok(()) => {
            st.ok = true;
            st.message = format!("installed to {}", cfg.target);
        }
        Err(e) => st.message = format!("install_code failed: {e}"),
    }
    put_status(repo, &st);
    st
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
