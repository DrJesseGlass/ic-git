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

/// Hand the authority a commit's deploy job (docs/CANISTER_SPLIT.md,
/// section 4: submit_job), through the outbox. The job is built from this
/// side's state, unless one for the commit still waits in the outbox; the
/// authority drops a job it has queued, or whose commit the app already
/// runs.
pub async fn submit(repo: &str, commit: &Oid) {
    let hex = store::oid_hex(commit);
    if crate::outbox::job_waiting(repo, &hex) {
        return;
    }
    let job = resolve(repo, commit);
    crate::outbox::send(crate::outbox::Outgoing::SubmitJob {
        repo: repo.to_string(),
        commit: hex,
        job,
    })
    .await;
}

/// After anything that can change a votes-gated repo's newest approved
/// commit -- a write of the approved-set mirror (a ballot, the threshold,
/// the voters, the owner) or a push, which moves the tip the walk starts
/// from: record it as what the site serves (`site::advance`) and, when it
/// moved -- or on `retry`, when it did not -- submit its job, so the site
/// and the app follow the same approvals. A ballot retries, so voters can
/// get an app whose deploy failed back in step with the site without first
/// taking the site down; a push does not, or a deploy that keeps failing
/// would be charged again on every push. The authority drops the job when
/// the app already runs the commit or a deploy of it is queued or running
/// (phase 3, step 9); a repo with nothing configured to deploy submits
/// nothing. A repo that requires no votes deploys on push, so this does
/// nothing for it.
pub async fn follow_approvals(repo: &str, retry: bool) {
    let commit = match crate::site::advance(repo) {
        Some(c) => c,
        None if retry && crate::site::gated(repo) => match crate::site::served_commit(repo) {
            Ok(c) => c,
            Err(_) => return,
        },
        None => return,
    };
    let configs = crate::mirror::deploy_configs(repo);
    if configs.wasm.is_none() && configs.evm.is_none() {
        return;
    }
    submit(repo, &commit).await;
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::for_authority::Git;
    use crate::{mirror, site, to_authority};
    use futures::executor::block_on;
    use ic_git_types::authority_side::{AuthoritySide, Event};
    use ic_git_types::git_side::GitSide;
    use ic_git_types::side::{ready, Fut, Reply};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// An authority that records the jobs it is handed.
    #[derive(Default)]
    struct Recorder {
        jobs: RefCell<Vec<String>>,
    }

    impl AuthoritySide for Recorder {
        fn charge_push<'a>(&'a self, _repo: &'a str, _bytes: u64) -> Fut<'a, Reply<Result<(), String>>> {
            ready(Ok(Ok(())))
        }

        fn submit_job<'a>(&'a self, _seq: u64, repo: &'a str, commit_hex: &'a str, _job: Job) -> Fut<'a, Reply<()>> {
            self.jobs.borrow_mut().push(format!("{repo}@{commit_hex}"));
            ready(Ok(()))
        }

        fn notify<'a>(&'a self, _seq: u64, _event: Event) -> Fut<'a, Reply<()>> {
            ready(Ok(()))
        }
    }

    /// A commit holding `app.wasm`, on top of `parent`, as the repo's new
    /// branch tip.
    fn push(repo: &str, wasm: &[u8], parent: Option<Oid>) -> Oid {
        store::commit_file_for_tests(repo, "app.wasm", wasm, parent)
    }

    /// A write of the approved set the git side takes is followed: the
    /// site moves to the newest approved commit and the commit's job goes
    /// to the authority, whichever way it moved; one that moves nothing
    /// submits nothing unless it asks for the retry (a ballot), and then
    /// the served commit's job; a stale write is not taken, so it moves
    /// nothing. What the authority does with a job it already runs is its
    /// own check.
    #[test]
    fn the_approved_sets_write_is_followed() {
        store::create_repo("follow").unwrap();
        let configured = |seq, wasm: bool| {
            let wasm = wasm.then(|| DeployConfig {
                target: "aaaaa-aa".into(),
                source_path: "app.wasm".into(),
                mode: Default::default(),
            });
            assert!(mirror::set_deploy_configs("follow", seq, DeployConfigs { wasm, evm: None }));
        };
        configured(1, true);
        let authority = Rc::new(Recorder::default());
        to_authority::set_test_side(Some(authority.clone()));
        let git = Git { is_operator: |_| false };
        let set = |seq: u64, approved: Option<Vec<&Oid>>, retry: bool| {
            let keys = approved.map(|cs| cs.into_iter().map(|c| mirror::commit_key(c.as_slice())).collect());
            block_on(git.set_approved("follow", seq, keys, retry)).unwrap();
        };
        let taken = || authority.jobs.borrow().clone();
        let job = |c: &Oid| format!("follow@{}", store::oid_hex(c));

        let c1 = push("follow", b"one", None);
        let c2 = push("follow", b"two", Some(c1));
        // Votes required and nothing approved: nothing served, nothing
        // submitted.
        set(1, Some(vec![]), false);
        assert!(taken().is_empty());
        assert!(site::served_commit("follow").is_err());
        // c1 approved below the tip: served, and its job submitted.
        set(2, Some(vec![&c1]), false);
        assert_eq!(site::served_commit("follow").unwrap(), c1);
        assert_eq!(taken(), vec![job(&c1)]);
        // The same set written again (a member added, say): nothing moved,
        // nothing submitted.
        set(3, Some(vec![&c1]), false);
        assert_eq!(taken().len(), 1);
        // A ballot that changes nothing retries the served commit.
        set(4, Some(vec![&c1]), true);
        assert_eq!(taken(), vec![job(&c1), job(&c1)]);
        // A write older than the newest taken: ignored, so not followed.
        set(3, Some(vec![&c1, &c2]), true);
        assert_eq!(taken().len(), 2);
        assert_eq!(site::served_commit("follow").unwrap(), c1);
        // c2 approved: the site moves up to it, and so does the app.
        set(5, Some(vec![&c1, &c2]), false);
        assert_eq!(taken()[2], job(&c2));
        // c2's approval withdrawn: both roll back to c1.
        set(6, Some(vec![&c1]), false);
        assert_eq!(taken()[3], job(&c1));
        // Nothing approved: nothing served, and a ballot's retry has
        // nothing to retry.
        set(7, Some(vec![]), true);
        assert_eq!(taken().len(), 4);
        assert!(site::served_commit("follow").is_err());
        // Votes no longer required: the tip is served and deploys once,
        // since the held pushes never did; a retry then is a no-op.
        set(8, None, false);
        assert_eq!(taken()[4], job(&c2));
        set(9, None, true);
        assert_eq!(taken().len(), 5);
        // Nothing configured to deploy: the move is recorded, and nothing
        // is submitted.
        configured(2, false);
        set(10, Some(vec![&c1]), true);
        assert_eq!(site::served_commit("follow").unwrap(), c1);
        assert_eq!(taken().len(), 5);
        to_authority::set_test_side(None);
    }
}
