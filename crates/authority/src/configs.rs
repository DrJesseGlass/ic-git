//! Each repo's deploy configs: the wasm target, source and install mode,
//! and the EVM source and gas limit (docs/CANISTER_SPLIT.md, phase 3 step
//! 6). The authority owns them because a config names where a deploy
//! goes: the queue installs into `target`, and this canister controls
//! every app canister. A job built by the git side carries its configs as
//! the git side saw them; the queue runs it only when they are these
//! (`check_job`), so a job cannot name a canister the repo did not
//! choose, another tenant's app canister included.
//!
//! Every setter goes through here: `set_wasm_deploy`, `set_deploy_mode`,
//! `set_evm_deploy`, and an applied `WasmDeploy` or `DeployMode` policy
//! change. Each one also writes the git side's mirror, which tells it which
//! paths a job proves.

use crate::deploy::{DeployConfig, DeployMode, EvmDeployConfig, Job, SourceKind};
use candid::Principal;
use ic_git_types::git_side::DeployConfigs;

// The META keys these configs have always had, so nothing migrates.
const WASM_PREFIX: &str = "deploy:";
const EVM_PREFIX: &str = "deploy_evm:";

fn wasm_key(repo: &str) -> String {
    format!("{WASM_PREFIX}{repo}")
}

fn evm_key(repo: &str) -> String {
    format!("{EVM_PREFIX}{repo}")
}

pub fn get_wasm(repo: &str) -> Option<DeployConfig> {
    crate::kv::get_json(&wasm_key(repo))
}

pub fn get_evm(repo: &str) -> Option<EvmDeployConfig> {
    crate::kv::get_json(&evm_key(repo))
}

/// Both of a repo's configs.
pub fn get(repo: &str) -> DeployConfigs {
    DeployConfigs {
        wasm: get_wasm(repo),
        evm: get_evm(repo),
    }
}

/// Set (or replace) a repo's wasm deploy config, keeping any install mode
/// chosen before. A governed repo deploys committed `.wasm` only
/// (`SourceKind::for_repo`).
pub fn set_wasm(repo: &str, target: String, source_path: String) -> Result<(), String> {
    if !crate::tenancy::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    Principal::from_text(&target).map_err(|e| format!("bad target principal: {e}"))?;
    SourceKind::for_repo(crate::tenancy::is_governed(repo), &source_path)?;
    let mode = get_wasm(repo).map(|c| c.mode).unwrap_or_default();
    crate::kv::set_json(
        &wasm_key(repo),
        &DeployConfig {
            target,
            source_path,
            mode,
        },
    );
    mirror(repo);
    Ok(())
}

/// Change a repo's install mode (upgrade or reinstall), leaving the rest
/// of its wasm config alone.
pub fn set_mode(repo: &str, mode: DeployMode) -> Result<(), String> {
    let mut cfg = get_wasm(repo).ok_or("no deploy config for repo")?;
    cfg.mode = mode;
    crate::kv::set_json(&wasm_key(repo), &cfg);
    mirror(repo);
    Ok(())
}

/// Set (or replace) a repo's EVM deploy config. Refused when this canister
/// could not deploy with `gas_limit` at all (`evm::require_deploy_target`):
/// a misconfiguration better rejected now than found at push time.
pub fn set_evm(repo: &str, source_path: String, gas_limit: u64) -> Result<(), String> {
    if !crate::tenancy::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    if !source_path.ends_with(".hex") {
        return Err("source_path must end in .hex (creation bytecode as hex text)".into());
    }
    crate::evm::require_deploy_target(gas_limit)?;
    crate::kv::set_json(
        &evm_key(repo),
        &EvmDeployConfig {
            source_path,
            gas_limit,
        },
    );
    mirror(repo);
    Ok(())
}

/// Write the git side's mirror of the repo's configs.
fn mirror(repo: &str) {
    crate::to_git::set_deploy_configs(repo, get(repo));
}

/// Bring every configured repo's mirror up to date. For post_upgrade: a
/// release before the authority owned the configs left the mirrors empty.
/// By key rather than by repo metadata: it runs before `tenancy::adopt_repos`
/// gives a repo created before tenancy its metadata.
pub fn sync_all_mirrors() {
    let mut repos = std::collections::BTreeSet::new();
    for prefix in [WASM_PREFIX, EVM_PREFIX] {
        for key in crate::kv::keys_with_prefix(prefix) {
            repos.insert(key[prefix.len()..].to_string());
        }
    }
    for repo in repos {
        mirror(&repo);
    }
}

/// A job, if its configs are the repo's: the git side built it from its
/// mirror, and a job whose configs differ was either built before a config
/// change or is not one the repo chose. Refused with the reason, which the
/// queue records as the deploy's outcome.
pub fn check_job(repo: &str, job: Job) -> Result<Job, String> {
    let own = get(repo);
    let wasm = job.wasm.as_ref().map(|(c, _)| c);
    let evm = job.evm.as_ref().map(|(c, _)| c);
    if wasm == own.wasm.as_ref() && evm == own.evm.as_ref() {
        return Ok(job);
    }
    Err(format!(
        "refused: the job's deploy config is not the repo's ({}); deploy_now deploys the current one",
        describe_difference(wasm, own.wasm.as_ref(), evm, own.evm.as_ref())
    ))
}

fn describe_difference(
    job_wasm: Option<&DeployConfig>,
    own_wasm: Option<&DeployConfig>,
    job_evm: Option<&EvmDeployConfig>,
    own_evm: Option<&EvmDeployConfig>,
) -> String {
    let mut out = Vec::new();
    match (job_wasm, own_wasm) {
        (Some(j), Some(o)) if j != o => out.push(format!(
            "wasm: the job installs {} into {} ({}), the repo's config {} into {} ({})",
            j.source_path,
            j.target,
            j.mode.as_str(),
            o.source_path,
            o.target,
            o.mode.as_str()
        )),
        (Some(j), None) => out.push(format!("wasm: the job installs into {}, the repo has no wasm config", j.target)),
        (None, Some(_)) => out.push("wasm: the job has no wasm leg, the repo's config does".into()),
        _ => {}
    }
    match (job_evm, own_evm) {
        (Some(j), Some(o)) if j != o => out.push(format!(
            "evm: the job deploys {} with gas {}, the repo's config {} with gas {}",
            j.source_path, j.gas_limit, o.source_path, o.gas_limit
        )),
        (Some(_), None) => out.push("evm: the job has an EVM leg, the repo has no EVM config".into()),
        (None, Some(_)) => out.push("evm: the job has no EVM leg, the repo's config does".into()),
        _ => {}
    }
    out.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{self, ObjectType};
    use ic_git_types::proof::Artifact;

    fn app(n: u8) -> String {
        Principal::from_slice(&[n; 10]).to_text()
    }

    /// The security property of phase 3 step 6: a job naming a target the
    /// repo did not configure -- another repo's app canister -- is refused,
    /// whatever the git side put in it.
    #[test]
    fn a_job_naming_another_repos_app_canister_is_refused() {
        crate::tenancy::test_repo("mine");
        crate::tenancy::test_repo("theirs");
        set_wasm("mine", app(1), "app.wasm".into()).unwrap();
        set_wasm("theirs", app(2), "app.wasm".into()).unwrap();
        let artifact = || Ok(Artifact { blob: b"m".to_vec(), proof: Vec::new() });

        let honest = Job { wasm: Some((get_wasm("mine").unwrap(), artifact())), evm: None };
        assert!(check_job("mine", honest).is_ok());

        let forged = Job { wasm: Some((get_wasm("theirs").unwrap(), artifact())), evm: None };
        let e = check_job("mine", forged).err().unwrap();
        assert!(e.starts_with("refused: the job's deploy config is not the repo's"), "{e}");
        assert!(e.contains(&app(2)) && e.contains(&app(1)), "{e}");

        // A leg the repo has no config for is refused too.
        let extra = Job {
            wasm: Some((get_wasm("mine").unwrap(), artifact())),
            evm: Some((EvmDeployConfig { source_path: "c.hex".into(), gas_limit: 1 }, artifact())),
        };
        assert!(check_job("mine", extra).err().unwrap().contains("the repo has no EVM config"));
    }

    /// Every setter writes the git side's mirror, and a job the git side
    /// builds from it passes; one built before a config change does not.
    #[test]
    fn the_mirror_follows_every_setter() {
        crate::tenancy::test_repo("mirrored");
        let a = store::put_object(ObjectType::Blob, b"wasm");
        let mut tree = b"100644 app.wasm\0".to_vec();
        tree.extend_from_slice(a.as_slice());
        let tree = store::put_object(ObjectType::Tree, &tree);
        let commit = store::put_object(ObjectType::Commit, format!("tree {}\n\nc\n", store::oid_hex(&tree)).as_bytes());

        set_wasm("mirrored", app(3), "app.wasm".into()).unwrap();
        assert_eq!(crate::jobs::get_config("mirrored"), get_wasm("mirrored"));
        let queued = || crate::jobs::resolve("mirrored", &commit);
        assert!(check_job("mirrored", queued()).is_ok());
        let before_the_change = queued();

        set_mode("mirrored", DeployMode::Reinstall).unwrap();
        assert_eq!(crate::jobs::get_config("mirrored").unwrap().mode, DeployMode::Reinstall);
        let e = check_job("mirrored", before_the_change).err().unwrap();
        assert!(e.contains("(upgrade)") && e.contains("(reinstall)"), "{e}");
        assert!(check_job("mirrored", queued()).is_ok());

        // The EVM leg too: a job built before it was configured has none.
        let before_evm = queued();
        crate::evm::set_config("aaaaa-aa".into(), "key".into(), 11155111, Vec::new()).unwrap();
        set_evm("mirrored", "c.hex".into(), 100_000).unwrap();
        assert_eq!(crate::mirror::deploy_configs("mirrored"), get("mirrored"));
        assert!(crate::mirror::deploy_configs("mirrored").evm.is_some());
        let e = check_job("mirrored", before_evm).err().unwrap();
        assert!(e.contains("no EVM leg"), "{e}");

        // The mirror starts empty after an upgrade from a release before
        // this one; post_upgrade fills it by key.
        crate::mirror::set_deploy_configs("mirrored", DeployConfigs::default());
        assert_eq!(crate::jobs::get_config("mirrored"), None);
        sync_all_mirrors();
        assert_eq!(crate::mirror::deploy_configs("mirrored"), get("mirrored"));
        assert_eq!(crate::jobs::get_config("mirrored"), get_wasm("mirrored"));
    }

    #[test]
    fn setters_refuse_what_cannot_deploy() {
        assert!(set_wasm("nowhere", app(4), "app.wasm".into()).unwrap_err().contains("no such repo"));
        crate::tenancy::test_repo("bad");
        assert!(set_wasm("bad", "not a principal".into(), "app.wasm".into()).is_err());
        assert!(set_mode("bad", DeployMode::Reinstall).is_err(), "no config to set the mode of");
        assert!(set_evm("bad", "c.bin".into(), 100_000).unwrap_err().contains(".hex"));
        assert_eq!(get("bad"), DeployConfigs::default());
    }
}
