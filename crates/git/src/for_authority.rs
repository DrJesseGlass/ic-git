//! The git side's answer to the authority (ic_git_types::git_side): one
//! implementation of the interface, over this crate's store and mirrors.
//! The canister installs it into the authority at init and upgrade. Each
//! call is a plain function behind a future (phase 3, step 8): in one
//! canister nothing is lost, so every reply is `Ok`. One of them,
//! `set_approved`, tells the authority something back on the way (a job,
//! through the outbox), which in one canister is answered at once too.
//!
//! Over messages (phase 3, step 12b) the release job's reply can be
//! larger than a message, so it goes back as a head (`release_head`) and
//! the chunks the head names (`release_chunk`), kept in heap under a
//! handle while the authority fetches them: the newest `STAGED_REPLIES`
//! of them, since an ask that was never finished is asked again.

use crate::{mirror, store};
use candid::Principal;
use ic_git_types::git_side::{Attested, DeployConfigs, GitSide, PushPolicy, RecordKind, Release, Retry};
use ic_git_types::oid::Oid;
use ic_git_types::side::{ready, Fut, Reply};
use ic_git_types::wire::{pieces, ReleaseHead, MAX_CHUNK};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

/// How many release jobs' bodies wait to be fetched.
pub const STAGED_REPLIES: usize = 4;

thread_local! {
    /// Handle -> the whole encoded job, oldest first. The body is kept
    /// once, and each chunk is cut from it as it is asked for.
    static STAGED: RefCell<VecDeque<(u64, Vec<u8>)>> = const { RefCell::new(VecDeque::new()) };
    static NEXT_HANDLE: Cell<u64> = const { Cell::new(1) };
}

/// The release job over messages: its head. A job that fits in one piece
/// is the head alone; a larger one's body waits under the handle.
pub fn release_head(repo: &str) -> Result<ReleaseHead, String> {
    let Release { commit, job } = crate::jobs::release(repo)?;
    let body = candid::encode_one(&job).map_err(|e| format!("the job does not encode: {e}"))?;
    let more = (pieces(&body).len() - 1) as u32;
    if more == 0 {
        return Ok(ReleaseHead { commit, handle: 0, more, head: body });
    }
    let head = body[..MAX_CHUNK].to_vec();
    let handle = NEXT_HANDLE.with(|h| h.replace(h.get() + 1));
    STAGED.with(|s| {
        let mut s = s.borrow_mut();
        while s.len() >= STAGED_REPLIES {
            s.pop_front();
        }
        s.push_back((handle, body));
    });
    Ok(ReleaseHead { commit, handle, more, head })
}

/// Chunk `index` (1 to the head's `more`) of the release job under
/// `handle`. Refused once the body is gone: the authority asks again.
pub fn release_chunk(handle: u64, index: u32) -> Result<Vec<u8>, String> {
    STAGED.with(|s| {
        let s = s.borrow();
        let (_, body) = s
            .iter()
            .find(|(h, _)| *h == handle)
            .ok_or("the release job's chunks are gone; ask again")?;
        if index == 0 {
            return Err("chunk 0 is the head".into());
        }
        let start = index as usize * MAX_CHUNK;
        if start >= body.len() {
            return Err(format!("no chunk {index}; the job has {}", pieces(body).len() - 1));
        }
        Ok(body[start..body.len().min(start + MAX_CHUNK)].to_vec())
    })
}

/// For tests: what an upgrade does to the staged replies.
#[cfg(any(test, feature = "testing"))]
pub fn forget_staged_replies() {
    STAGED.with(|s| s.borrow_mut().clear());
}

/// This crate, as the authority sees it. `is_operator` is this side's own
/// operator rule (operators are not mirrored), which spares an operator's
/// push tokens when a push policy drops them as a writer.
pub struct Git {
    pub is_operator: fn(&Principal) -> bool,
}

impl GitSide for Git {
    fn set_deploy_configs<'a>(&'a self, repo: &'a str, seq: u64, configs: DeployConfigs) -> Fut<'a, Reply<()>> {
        if mirror::set_deploy_configs(repo, seq, configs) {
            // A job built under the old configs would be refused.
            crate::outbox::rebuild_jobs(repo, |commit| {
                let oid = ic_git_types::oid::parse_oid(commit).ok()?;
                Some(crate::jobs::resolve(repo, &oid))
            });
        }
        ready(Ok(()))
    }

    fn set_push_policy<'a>(&'a self, repo: &'a str, seq: u64, policy: PushPolicy) -> Fut<'a, Reply<()>> {
        mirror::set_push_policy(repo, seq, policy, self.is_operator);
        ready(Ok(()))
    }

    /// A write that is taken is followed (jobs::follow_approvals): what
    /// the repo serves is recorded, and its job submitted when that moved
    /// or `retry` says to. A stale write changes nothing, so it moves
    /// nothing either.
    fn set_approved<'a>(&'a self, repo: &'a str, seq: u64, approved: Option<Vec<String>>, retry: Option<Retry>) -> Fut<'a, Reply<()>> {
        Box::pin(async move {
            if mirror::set_approved(repo, seq, approved) {
                crate::jobs::follow_approvals(repo, retry.as_ref()).await;
            }
            Ok(())
        })
    }

    fn check_new_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<String, String>>> {
        ready(Ok(store::check_new_repo(name)))
    }

    /// Idempotent, as the interface requires: the authority holds the name
    /// (tenancy::create_repo reserves it), so a repo of that name is its own
    /// earlier call having landed.
    fn create_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<(), String>>> {
        if store::repo_exists(name) {
            return ready(Ok(Ok(())));
        }
        ready(Ok(store::create_repo(name)))
    }

    fn has_commit<'a>(&'a self, oid: &'a Oid) -> Fut<'a, Reply<bool>> {
        ready(Ok(store::has_object(oid)))
    }

    fn record_artifact<'a>(&'a self, repo: &'a str, kind: RecordKind) -> Fut<'a, Reply<Result<Attested, String>>> {
        ready(Ok(crate::attest::record_artifact(repo, &kind)))
    }

    fn release_job<'a>(&'a self, repo: &'a str) -> Fut<'a, Reply<Result<Release, String>>> {
        ready(Ok(crate::jobs::release(repo)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;
    use ic_git_types::deploy::{DeployConfig, Job};
    use ic_git_types::git_side::DeployConfigs;
    use ic_git_types::wire::MAX_CHUNK;

    /// A release job's chunks are served under its handle until newer
    /// asks push it out; the head is chunk 0 and not served again; a
    /// small job stages nothing.
    #[test]
    fn a_release_job_is_staged_past_its_head() {
        let repo = "stage-release";
        store::create_repo(repo).unwrap();
        let configs = DeployConfigs {
            wasm: Some(DeployConfig {
                target: "aaaaa-aa".into(),
                source_path: "app.wasm".into(),
                mode: Default::default(),
            }),
            evm: None,
        };
        assert!(crate::mirror::set_deploy_configs(repo, 1, configs));
        let tip = store::commit_file_for_tests(repo, "app.wasm", &vec![1u8; MAX_CHUNK + 100], None);
        store::set_ref(repo, &store::head_target(repo).unwrap(), tip).unwrap();

        let head = release_head(repo).unwrap();
        assert_eq!(head.commit, store::oid_hex(&tip));
        assert_eq!(head.more, 1);
        assert_eq!(head.head.len(), MAX_CHUNK);
        assert!(release_chunk(head.handle, 0).is_err());
        assert!(release_chunk(head.handle, 2).is_err());
        let mut body = head.head.clone();
        body.extend(release_chunk(head.handle, 1).unwrap());
        let job: Job = candid::decode_one(&body).unwrap();
        let (_, artifact) = job.wasm.unwrap();
        assert_eq!(artifact.unwrap().blob.len(), MAX_CHUNK + 100);

        // Newer asks push the oldest out.
        let handles: Vec<u64> = (0..STAGED_REPLIES).map(|_| release_head(repo).unwrap().handle).collect();
        assert!(release_chunk(head.handle, 1).is_err(), "pushed out");
        for h in &handles {
            assert!(release_chunk(*h, 1).is_ok());
        }
        forget_staged_replies();
        assert!(release_chunk(handles[0], 1).is_err());

        let small = store::commit_file_for_tests(repo, "app.wasm", b"small", Some(tip));
        store::set_ref(repo, &store::head_target(repo).unwrap(), small).unwrap();
        let head = release_head(repo).unwrap();
        assert_eq!((head.handle, head.more), (0, 0));
        let job: Job = candid::decode_one(&head.head).unwrap();
        assert_eq!(job.wasm.unwrap().1.unwrap().blob, b"small");
    }
}
