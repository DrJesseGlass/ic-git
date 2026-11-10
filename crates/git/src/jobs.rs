//! The git side of deploying (docs/CANISTER_SPLIT.md, section 3): each
//! repo's deploy configs, and the job builder that snapshots them and proves
//! each leg's artifact out of a commit. The authority (deploy.rs) queues
//! and runs what this builds and reads nothing here while it does.

use crate::gitproof;
use crate::object;
use crate::store::{self, Oid};
use ic_git_types::deploy::{bytecode_of, DeployConfig, DeployMode, EvmDeployConfig, Job, SourceKind};
use ic_git_types::proof::{plain, Artifact};
use candid::Principal;
use sha2::Digest as _;

// META keys for the configs (JSON via kv::set_json).
fn config_key(repo: &str) -> String {
    format!("deploy:{repo}")
}
fn evm_config_key(repo: &str) -> String {
    format!("deploy_evm:{repo}")
}

/// Set (or replace) a repo's deploy config, preserving any previously-chosen
/// install mode. `governed` is the authority's word on whether the repo is
/// governed, which holds it to committed `.wasm` (SourceKind::for_repo).
pub fn set_config(repo: &str, target: String, source_path: String, governed: bool) -> Result<(), String> {
    if !store::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    Principal::from_text(&target).map_err(|e| format!("bad target principal: {e}"))?;
    SourceKind::for_repo(governed, &source_path)?;
    let mode = get_config(repo).map(|c| c.mode).unwrap_or_default();
    let cfg = DeployConfig {
        target,
        source_path,
        mode,
    };
    crate::kv::set_json(&config_key(repo), &cfg);
    Ok(())
}

/// Change a repo's install mode (upgrade vs reinstall) without touching the
/// rest of its config.
pub fn set_mode(repo: &str, mode: DeployMode) -> Result<(), String> {
    let mut cfg = get_config(repo).ok_or("no deploy config for repo")?;
    cfg.mode = mode;
    crate::kv::set_json(&config_key(repo), &cfg);
    Ok(())
}

pub fn get_config(repo: &str) -> Option<DeployConfig> {
    crate::kv::get_json(&config_key(repo))
}

/// Set (or replace) a repo's EVM deploy config. `deployable` is the
/// authority's word on whether it could deploy with `gas_limit` at all
/// (`evm::require_deploy_target`), asked after this side's own checks and
/// before anything is stored: a target with no way to reach it is a
/// misconfiguration better rejected now than discovered at push time.
pub fn set_evm_config(
    repo: &str,
    source_path: String,
    gas_limit: u64,
    deployable: impl FnOnce(u64) -> Result<(), String>,
) -> Result<(), String> {
    if !store::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    if !source_path.ends_with(".hex") {
        return Err("source_path must end in .hex (creation bytecode as hex text)".into());
    }
    deployable(gas_limit)?;
    crate::kv::set_json(
        &evm_config_key(repo),
        &EvmDeployConfig {
            source_path,
            gas_limit,
        },
    );
    Ok(())
}

pub fn get_evm_config(repo: &str) -> Option<EvmDeployConfig> {
    crate::kv::get_json(&evm_config_key(repo))
}

/// The git side of a job: snapshot the repo's deploy configs and prove each
/// leg's artifact out of `commit`.
pub fn resolve(repo: &str, commit: &Oid) -> Job {
    let artifact = |path: &str| {
        gitproof::prove(commit, &plain(path))
            .map(|(blob, proof)| Artifact { blob, proof })
            .map_err(|e| format!("resolve {path}: {e}"))
    };
    Job {
        wasm: get_config(repo).map(|c| {
            let a = artifact(&c.source_path);
            (c, a)
        }),
        evm: get_evm_config(repo).map(|c| {
            let a = artifact(&c.source_path);
            (c, a)
        }),
    }
}

/// The creation bytecode of an EVM artifact at `path` within a commit's tree,
/// for the registry publisher's operator path. The deploy leg decodes the
/// proven blob with `bytecode_of` instead; both hash the same bytes.
pub fn evm_artifact_bytecode(commit_oid: &Oid, path: &str) -> Result<Vec<u8>, String> {
    let bytes =
        object::blob_at_path(commit_oid, path).map_err(|e| format!("resolve {path}: {e}"))?;
    bytecode_of(path, bytes)
}

/// sha256 of a commit's decoded EVM artifact -- the bundle hash the registry
/// stores, and the value `evm_deploy_history.bytecode_sha256` must equal.
/// Used by the publish paths that have no deploy in flight to inherit the
/// hash from; see `provenance::publish_commit`.
pub fn evm_artifact_hash(commit_oid: &Oid, path: &str) -> Result<[u8; 32], String> {
    Ok(sha2::Sha256::digest(evm_artifact_bytecode(commit_oid, path)?).into())
}

/// Whether a push to the deploy branch should enqueue a deploy: true when
/// either the wasm-to-canister or the EVM target is configured.
pub fn any_config(repo: &str) -> bool {
    get_config(repo).is_some() || get_evm_config(repo).is_some()
}

/// The branch whose pushes trigger deploys: the repo's HEAD symref target
/// (e.g. refs/heads/main). None if the repo does not exist.
pub fn deploy_branch(repo: &str) -> Option<String> {
    store::head_target(repo)
}

/// The commit that would deploy right now: the deploy-branch tip, or with
/// votes required the approved commit the site serves (`site::served_commit`).
/// The one resolution path for it, shared by the explicit-redeploy escape
/// hatch and the registry publisher, so the two cannot disagree about which
/// commit -- or about how to phrase not finding one.
pub fn release_commit(repo: &str) -> Result<Oid, String> {
    crate::site::served_commit(repo).map_err(str::to_string)
}

