//! The git side of deploying (docs/CANISTER_SPLIT.md, section 3): the job
//! builder, which proves each configured leg's artifact out of a commit.
//! The configs are the authority's (phase 3, step 6); this side reads its
//! mirror of them. The authority (deploy.rs) queues and runs what this
//! builds, refuses a job whose configs are not its own, and reads nothing
//! here while it does.

use crate::gitproof;
use crate::object;
use crate::store::{self, Oid};
use ic_git_types::deploy::{bytecode_of, DeployConfig, EvmDeployConfig, Job};
use ic_git_types::git_side::DeployConfigs;
use ic_git_types::proof::{plain, Artifact};
use sha2::Digest as _;

/// The repo's wasm deploy config, from the mirror of the authority's
/// (phase 3, step 6: the authority owns the configs).
pub fn get_config(repo: &str) -> Option<DeployConfig> {
    crate::mirror::deploy_configs(repo).wasm
}

/// The repo's EVM deploy config, likewise.
pub fn get_evm_config(repo: &str) -> Option<EvmDeployConfig> {
    crate::mirror::deploy_configs(repo).evm
}

/// The git side of a job: the repo's deploy configs, as mirrored, and each
/// leg's artifact proved out of `commit`.
pub fn resolve(repo: &str, commit: &Oid) -> Job {
    resolve_with(&crate::mirror::deploy_configs(repo), commit)
}

/// A job for `commit` under `configs`: for `resolve`, and for the
/// authority's post_upgrade, which rebuilds a legacy job from its own
/// configs before the mirror is filled.
pub fn resolve_with(configs: &DeployConfigs, commit: &Oid) -> Job {
    let artifact = |path: &str| {
        gitproof::prove(commit, &plain(path))
            .map(|(blob, proof)| Artifact { blob, proof })
            .map_err(|e| format!("resolve {path}: {e}"))
    };
    Job {
        wasm: configs.wasm.clone().map(|c| {
            let a = artifact(&c.source_path);
            (c, a)
        }),
        evm: configs.evm.clone().map(|c| {
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

