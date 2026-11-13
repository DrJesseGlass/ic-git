//! The git side as another canister (docs/CANISTER_SPLIT.md, phase 3 step
//! 12b): its principal (`GIT`), which an operator sets and which alone may
//! call this side's git-facing endpoints; and the `GitSide` that sends it
//! messages (`ic_git_types::wire`), one call each, except the release job
//! and a record's artifact, whose replies come back in chunks. The combined build installs none of
//! this: there the git side is `for_authority::Git`, in the same canister.
//! The two-canister build (step 12c) installs `GIT_CANISTER` at init and
//! upgrade and guards each git-facing endpoint (`charge_push`,
//! `stage_job`, `submit_job`, `notify`) with `GIT.check_caller`.

use candid::Principal;
use ic_git_common::call::Canister;
use ic_git_common::peer::Peer;
use ic_git_types::git_side::{Attested, DeployConfigs, GitSide, PushPolicy, RecordKind, Release, Retry};
use ic_git_types::oid::Oid;
use ic_git_types::side::{Fut, Reply};
use ic_git_types::wire::{self, send, Staged, Transport};
use serde::Deserialize;

/// The git canister, once an operator has named it (`name_git`), which
/// checks first that it is governed as this one is.
pub const GIT: Peer = Peer {
    key: "peer:git_canister",
    name: "git canister",
};

/// What the management canister says of a canister, as far as the rule
/// below reads it: who controls it, and whether it runs code.
#[derive(candid::CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct CanisterInfo {
    pub controllers: Vec<Principal>,
    pub module_hash: Option<Vec<u8>>,
}

/// The rule a git canister must meet before this side names it (phase 3,
/// step 12c): it runs code, one canister alone controls it, and that
/// canister has no controllers -- a governor (docs/GOVERNOR.md), which
/// only installs what its approvers vote for. Anything else could be
/// re-installed out from under the authority by whoever controls it, and
/// what it answered -- proofs, records, which commit a site serves --
/// would be that party's word.
pub fn governed(git: Principal, info: &CanisterInfo, controller_info: impl FnOnce(Principal) -> Result<CanisterInfo, String>) -> Result<(), String> {
    if info.module_hash.is_none() {
        return Err(format!("{git} runs no code"));
    }
    let [governor] = info.controllers[..] else {
        return Err(format!(
            "{git} has {} controllers; a git canister is controlled by a governor alone",
            info.controllers.len()
        ));
    };
    if governor == git {
        return Err(format!("{git} controls itself; a git canister is controlled by a governor alone"));
    }
    let ctl = controller_info(governor)?;
    if !ctl.controllers.is_empty() {
        return Err(format!(
            "{git} is controlled by {governor}, which has {} controllers; a governor has none",
            ctl.controllers.len()
        ));
    }
    Ok(())
}

/// Name the git canister, once: the rule above, read through
/// `canister_info` (the management canister's), then the record. An id
/// already named is kept; the same one again is fine. The record is read
/// again after the calls, since two operators may be naming at once.
pub async fn name_git(git: Principal, canister_info: impl AsyncFn(Principal) -> Result<CanisterInfo, String>) -> Result<(), String> {
    let named = |cur: Principal| {
        if cur == git {
            Ok(())
        } else {
            Err(format!("the git canister is {cur}, named once; this canister's code decides what it talks to"))
        }
    };
    if let Some(cur) = GIT.get() {
        return named(cur);
    }
    let info = canister_info(git).await?;
    let [governor] = info.controllers[..] else {
        return governed(git, &info, |_| unreachable!("checked first"));
    };
    let ctl = if governor == git { None } else { Some(canister_info(governor).await?) };
    governed(git, &info, |_| ctl.ok_or_else(|| "unreachable".to_string()))?;
    if let Some(cur) = GIT.get() {
        return named(cur);
    }
    GIT.set(git);
    Ok(())
}

fn git_canister() -> Option<Principal> {
    GIT.get()
}

/// The git side, reached by messages over `transport`.
pub struct Git<T: Transport> {
    pub transport: T,
}

/// The git canister, by inter-canister calls to whatever `git_canister`
/// says: what the two-canister build installs.
pub static GIT_CANISTER: Git<Canister> = Git {
    transport: Canister { id: git_canister },
};

impl<T: Transport> GitSide for Git<T> {
    fn set_deploy_configs<'a>(&'a self, repo: &'a str, seq: u64, configs: DeployConfigs) -> Fut<'a, Reply<()>> {
        Box::pin(send(&self.transport, wire::SetDeployConfigs { repo: repo.into(), seq, configs }))
    }

    fn set_push_policy<'a>(&'a self, repo: &'a str, seq: u64, policy: PushPolicy) -> Fut<'a, Reply<()>> {
        Box::pin(send(&self.transport, wire::SetPushPolicy { repo: repo.into(), seq, policy }))
    }

    fn set_approved<'a>(&'a self, repo: &'a str, seq: u64, approved: Option<Vec<String>>, retry: Option<Retry>) -> Fut<'a, Reply<()>> {
        Box::pin(send(&self.transport, wire::SetApproved { repo: repo.into(), seq, approved, retry }))
    }

    fn set_site<'a>(&'a self, repo: &'a str, root: String) -> Fut<'a, Reply<Result<(), String>>> {
        Box::pin(send(&self.transport, wire::SetSite { repo: repo.into(), root }))
    }

    fn check_new_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<String, String>>> {
        Box::pin(send(&self.transport, wire::CheckNewRepo { name: name.into() }))
    }

    fn create_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<(), String>>> {
        Box::pin(send(&self.transport, wire::CreateRepo { name: name.into() }))
    }

    fn has_commit<'a>(&'a self, oid: &'a Oid) -> Fut<'a, Reply<bool>> {
        Box::pin(send(&self.transport, wire::HasCommit { oid: oid.as_slice().to_vec() }))
    }

    /// A staged reply: the head, then each further chunk under its
    /// handle, and the artifact is the body they make. A chunk the git
    /// side no longer holds (it keeps a few, in heap) is its refusal, and
    /// the endpoint says to ask again; so is a body that does not decode.
    fn record_artifact<'a>(&'a self, repo: &'a str, kind: RecordKind) -> Fut<'a, Reply<Result<Attested, String>>> {
        Box::pin(async move {
            match send(&self.transport, wire::RecordArtifact { repo: repo.into(), kind }).await? {
                Ok(head) => self.fetch(head).await,
                Err(e) => Ok(Err(e)),
            }
        })
    }

    /// Staged like `record_artifact`'s.
    fn release_job<'a>(&'a self, repo: &'a str) -> Fut<'a, Reply<Result<Release, String>>> {
        Box::pin(async move {
            match send(&self.transport, wire::ReleaseJob { repo: repo.into() }).await? {
                Ok(head) => self.fetch(head).await,
                Err(e) => Ok(Err(e)),
            }
        })
    }
}

impl<T: Transport> Git<T> {
    /// The rest of a staged reply, chunk by chunk, decoded as `R`.
    async fn fetch<R: candid::CandidType + for<'de> Deserialize<'de>>(&self, head: Staged) -> Reply<Result<R, String>> {
        let mut body = head.head;
        for index in 1..=head.more {
            match send(&self.transport, wire::ReplyChunk { handle: head.handle, index }).await? {
                Ok(chunk) => body.extend_from_slice(&chunk),
                Err(e) => return Ok(Err(e)),
            }
        }
        Ok(candid::decode_one::<R>(&body).map_err(|e| format!("the reply does not decode: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::for_git;
    use futures::executor::block_on;
    use ic_git_git::for_authority;
    use ic_git_git::store;
    use ic_git_types::authority_side::{AuthoritySide, Event};
    use ic_git_types::deploy::{DeployConfig, Job};
    use ic_git_types::oid::parse_oid;
    use ic_git_types::side::Failure;
    use ic_git_types::wire::{Message, MAX_CHUNK};
    use std::cell::RefCell;

    fn info(controllers: &[Principal], code: bool) -> CanisterInfo {
        CanisterInfo {
            controllers: controllers.to_vec(),
            module_hash: code.then(|| vec![0u8; 32]),
        }
    }

    /// A git canister is named only if a governor alone controls it: not
    /// one with no code, two controllers, a controller that is itself
    /// controlled, or that controls itself. Named once: another id is
    /// refused, the same one is fine.
    #[test]
    fn a_git_canister_is_named_once_and_only_governed() {
        let git = Principal::from_slice(&[1; 8]);
        let gov = Principal::from_slice(&[2; 8]);
        let person = Principal::from_slice(&[3; 8]);
        let world: std::collections::BTreeMap<Principal, CanisterInfo> = [
            (git, info(&[gov], true)),
            (gov, info(&[], true)),
            (person, info(&[person], true)),
        ]
        .into_iter()
        .collect();
        let ask = |w: &std::collections::BTreeMap<Principal, CanisterInfo>, p: Principal| w.get(&p).cloned().ok_or(format!("no canister {p}"));

        let refused = |i: CanisterInfo| governed(git, &i, |p| ask(&world, p)).unwrap_err();
        assert!(refused(info(&[gov], false)).contains("runs no code"));
        assert!(refused(info(&[gov, person], true)).contains("2 controllers"));
        assert!(refused(info(&[], true)).contains("0 controllers"));
        assert!(refused(info(&[git], true)).contains("controls itself"));
        assert!(refused(info(&[person], true)).contains("which has 1 controllers"));
        assert!(refused(info(&[Principal::from_slice(&[9; 8])], true)).contains("no canister"));
        assert_eq!(governed(git, &info(&[gov], true), |p| ask(&world, p)), Ok(()));

        crate::kv::remove(GIT.key);
        let asks = std::cell::Cell::new(0);
        let w = world.clone();
        let canister_info = async |p: Principal| {
            asks.set(asks.get() + 1);
            ask(&w, p)
        };
        assert!(block_on(name_git(person, canister_info)).unwrap_err().contains("controls itself"));
        assert_eq!(GIT.get(), None);
        assert_eq!(block_on(name_git(git, canister_info)), Ok(()));
        assert_eq!(GIT.get(), Some(git));
        let asked = asks.get();
        assert_eq!(block_on(name_git(git, canister_info)), Ok(()), "the same again");
        assert!(block_on(name_git(gov, canister_info)).unwrap_err().contains("named once"));
        assert_eq!(asks.get(), asked, "nothing asked once named");
        crate::kv::remove(GIT.key);
    }

    /// The transport calls whatever the record names at the time.
    #[test]
    fn the_transport_follows_the_named_git_canister() {
        let git = Principal::from_slice(&[1; 8]);
        assert_eq!((GIT_CANISTER.transport.id)(), None);
        assert_eq!(GIT.check_caller(&git), Err("no git canister is set; only it may call this".into()));
        GIT.set(git);
        assert_eq!((GIT_CANISTER.transport.id)(), Some(git));
        assert_eq!(GIT.check_caller(&git), Ok(()));
        crate::kv::remove(GIT.key);
    }

    fn enc<T: candid::CandidType>(v: T) -> Vec<u8> {
        candid::encode_one(v).expect("a reply encodes")
    }

    fn dec<T: candid::CandidType + for<'de> serde::Deserialize<'de>>(arg: &[u8]) -> T {
        candid::decode_one(arg).expect("the argument is the message")
    }

    /// The git canister's endpoints, as step 12c writes them: each takes
    /// its message and answers the real git side's receiver.
    async fn git_endpoint(method: &str, arg: &[u8]) -> Vec<u8> {
        static GIT: for_authority::Git = for_authority::Git {
            is_operator: crate::tenancy::is_operator,
        };
        match method {
            m if m == wire::SetDeployConfigs::METHOD => {
                let m: wire::SetDeployConfigs = dec(arg);
                enc(GIT.set_deploy_configs(&m.repo, m.seq, m.configs).await.unwrap())
            }
            m if m == wire::SetPushPolicy::METHOD => {
                let m: wire::SetPushPolicy = dec(arg);
                enc(GIT.set_push_policy(&m.repo, m.seq, m.policy).await.unwrap())
            }
            m if m == wire::SetApproved::METHOD => {
                let m: wire::SetApproved = dec(arg);
                enc(GIT.set_approved(&m.repo, m.seq, m.approved, m.retry).await.unwrap())
            }
            m if m == wire::SetSite::METHOD => {
                let m: wire::SetSite = dec(arg);
                enc(GIT.set_site(&m.repo, m.root).await.unwrap())
            }
            m if m == wire::CheckNewRepo::METHOD => {
                let m: wire::CheckNewRepo = dec(arg);
                enc(GIT.check_new_repo(&m.name).await.unwrap())
            }
            m if m == wire::CreateRepo::METHOD => {
                let m: wire::CreateRepo = dec(arg);
                enc(GIT.create_repo(&m.name).await.unwrap())
            }
            m if m == wire::HasCommit::METHOD => {
                let m: wire::HasCommit = dec(arg);
                let oid = Oid::try_from(m.oid.as_slice()).expect("20 bytes");
                enc(GIT.has_commit(&oid).await.unwrap())
            }
            m if m == wire::RecordArtifact::METHOD => {
                let m: wire::RecordArtifact = dec(arg);
                enc(for_authority::staged_record(&m.repo, &m.kind))
            }
            m if m == wire::ReleaseJob::METHOD => {
                let m: wire::ReleaseJob = dec(arg);
                enc(for_authority::staged_release(&m.repo))
            }
            m if m == wire::ReplyChunk::METHOD => {
                let m: wire::ReplyChunk = dec(arg);
                enc(for_authority::reply_chunk(m.handle, m.index))
            }
            other => panic!("the git canister has no method {other}"),
        }
    }

    /// The authority's endpoints, likewise.
    async fn authority_endpoint(method: &str, arg: &[u8]) -> Vec<u8> {
        match method {
            m if m == wire::ChargePush::METHOD => {
                let m: wire::ChargePush = dec(arg);
                enc(for_git::Authority.charge_push(&m.repo, m.bytes).await.unwrap())
            }
            m if m == wire::StageJob::METHOD => {
                let m: wire::StageJob = dec(arg);
                enc(for_git::stage_job(m.seq, &m.repo, &m.commit, m.total, m.index, m.bytes))
            }
            m if m == wire::SubmitJob::METHOD => {
                let m: wire::SubmitJob = dec(arg);
                enc(for_git::submit_staged(m.seq, &m.repo, &m.commit, m.staged, m.tail))
            }
            m if m == wire::Notify::METHOD => {
                let m: wire::Notify = dec(arg);
                enc(for_git::Authority.notify(m.seq, m.event).await.unwrap())
            }
            other => panic!("the authority has no method {other}"),
        }
    }

    /// Messages delivered to one side's endpoints in this process, with
    /// the next call of a chosen method failing as told.
    struct Loopback {
        to_git: bool,
        calls: RefCell<Vec<&'static str>>,
        inject: RefCell<Option<(&'static str, Failure)>>,
    }

    impl Loopback {
        fn new(to_git: bool) -> Self {
            Loopback {
                to_git,
                calls: RefCell::new(Vec::new()),
                inject: RefCell::new(None),
            }
        }

        fn fail_next(&self, method: &'static str, how: Failure) {
            *self.inject.borrow_mut() = Some((method, how));
        }

        fn count(&self, method: &str) -> usize {
            self.calls.borrow().iter().filter(|m| **m == method).count()
        }
    }

    impl Transport for Loopback {
        fn call<'a>(&'a self, method: &'static str, arg: Vec<u8>) -> Fut<'a, Reply<Vec<u8>>> {
            Box::pin(async move {
                self.calls.borrow_mut().push(method);
                let injected = {
                    let mut i = self.inject.borrow_mut();
                    match i.as_ref() {
                        Some((m, _)) if *m == method => i.take().map(|(_, f)| f),
                        _ => None,
                    }
                };
                if let Some(Failure::NotDelivered(e)) = injected {
                    return Err(Failure::NotDelivered(e));
                }
                let reply = if self.to_git {
                    git_endpoint(method, &arg).await
                } else {
                    authority_endpoint(method, &arg).await
                };
                if let Some(Failure::Lost(e)) = injected {
                    return Err(Failure::Lost(e));
                }
                Ok(reply)
            })
        }
    }

    /// A commit holding `app.wasm` as the repo's branch tip.
    fn push(repo: &str, wasm: &[u8]) -> Oid {
        let tip = store::commit_file_for_tests(repo, "app.wasm", wasm, None);
        let branch = store::head_target(repo).unwrap();
        store::set_ref(repo, &branch, tip).unwrap();
        tip
    }

    fn wasm_configs() -> DeployConfigs {
        DeployConfigs {
            wasm: Some(DeployConfig {
                target: "aaaaa-aa".into(),
                source_path: "app.wasm".into(),
                mode: Default::default(),
            }),
            evm: None,
        }
    }

    /// Every call of the authority's interface crosses as a message the
    /// git side's endpoint answers: the mirrors land (a stale one is
    /// ignored), a name is checked and created, a commit is found, and
    /// an artifact comes back with a proof the authority can check.
    #[test]
    fn the_git_side_answers_each_message() {
        let git = Git { transport: Loopback::new(true) };
        let name = "peer-each";
        assert_eq!(block_on(git.check_new_repo(name)), Ok(Ok(name.to_string())));
        assert_eq!(block_on(git.create_repo(name)), Ok(Ok(())));
        assert_eq!(block_on(git.create_repo(name)), Ok(Ok(())), "idempotent");
        assert!(store::repo_exists(name));

        assert_eq!(block_on(git.set_deploy_configs(name, 1, wasm_configs())), Ok(()));
        assert_eq!(ic_git_git::mirror::deploy_configs(name), wasm_configs());
        assert_eq!(block_on(git.set_deploy_configs(name, 0, DeployConfigs::default())), Ok(()));
        assert_eq!(ic_git_git::mirror::deploy_configs(name), wasm_configs(), "a stale write is ignored");

        let writer = Principal::from_slice(&[2; 8]);
        let policy = PushPolicy {
            writers: vec![writer],
            require_signed_push: true,
        };
        assert_eq!(block_on(git.set_push_policy(name, 1, policy)), Ok(()));
        assert!(ic_git_git::mirror::may_write(name, &writer, false).is_ok());
        assert!(ic_git_git::mirror::requires_signed_push(name));

        assert_eq!(block_on(git.set_site(name, "/www/".into())), Ok(Ok(())));
        assert_eq!(ic_git_git::site::get_config(name).map(|c| c.root), Some("www".into()));
        assert!(block_on(git.set_site("peer-none", String::new())).unwrap().is_err(), "a repo the git side does not hold");

        let tip = push(name, b"module");
        assert_eq!(block_on(git.has_commit(&tip)), Ok(true));
        let none = parse_oid("0000000000000000000000000000000000000001").unwrap();
        assert_eq!(block_on(git.has_commit(&none)), Ok(false));

        // The write is followed: the served commit's job goes to the
        // authority through the outbox, here this crate's own.
        ic_git_git::to_authority::set_test_side(Some(std::rc::Rc::new(for_git::Authority)));
        let key = ic_git_git::mirror::commit_key(tip.as_slice());
        assert_eq!(block_on(git.set_approved(name, 1, Some(vec![key]), None)), Ok(()));
        assert_eq!(ic_git_git::site::served_commit(name).unwrap(), tip);
        ic_git_git::to_authority::set_test_side(None);

        let attested = block_on(git.record_artifact(name, RecordKind::Release { path: "app.wasm".into() }))
            .unwrap()
            .expect("the release artifact");
        assert_eq!(attested.commit, store::oid_hex(&tip));
        assert_eq!(attested.path, "app.wasm");
        let commit = ic_git_types::oid::commit20(&tip).unwrap();
        assert_eq!(attested.artifact.verified(&commit, "app.wasm").unwrap(), b"module");

        let refused = block_on(git.record_artifact("peer-none", RecordKind::Site)).unwrap();
        assert!(refused.is_err(), "a repo that does not exist is refused, not answered");
        assert_eq!(git.transport.count(wire::HasCommit::METHOD), 2);
    }

    /// A release job larger than a chunk comes back as a head and the
    /// chunks the head names, and decodes to the job the git side built;
    /// a small one is the head alone. A record's artifact comes back the
    /// same way. The git side's refusal, a chunk it no longer holds, and
    /// a call that fails each reach the caller as what they are.
    #[test]
    fn large_replies_come_back_in_chunks() {
        let git = Git { transport: Loopback::new(true) };
        let name = "peer-release";
        store::create_repo(name).unwrap();
        assert!(ic_git_git::mirror::set_deploy_configs(name, 1, wasm_configs()));
        let refused = block_on(git.release_job(name)).unwrap();
        assert!(refused.is_err_and(|e| e == "deploy branch has no commits"));

        let big = vec![7u8; 2 * MAX_CHUNK + 1000];
        let tip = push(name, &big);
        let release = block_on(git.release_job(name)).unwrap().expect("the release job");
        assert_eq!(release.commit, store::oid_hex(&tip));
        assert_eq!(git.transport.count(wire::ReleaseJob::METHOD), 2);
        assert_eq!(git.transport.count(wire::ReplyChunk::METHOD), 2, "a head and two more chunks");
        let (cfg, artifact) = release.job.wasm.expect("the wasm leg");
        assert_eq!(cfg.source_path, "app.wasm");
        let commit = ic_git_types::oid::commit20(&tip).unwrap();
        assert_eq!(artifact.unwrap().verified(&commit, "app.wasm").unwrap(), big);

        // The record's artifact: the same blob with its proof, in chunks.
        let attested = block_on(git.record_artifact(name, RecordKind::Release { path: "app.wasm".into() }))
            .unwrap()
            .expect("the release artifact");
        assert_eq!(git.transport.count(wire::ReplyChunk::METHOD), 4);
        assert_eq!(attested.commit, store::oid_hex(&tip));
        assert_eq!(attested.artifact.verified(&commit, "app.wasm").unwrap(), big);

        let small = store::commit_file_for_tests(name, "app.wasm", b"small", Some(tip));
        store::set_ref(name, &store::head_target(name).unwrap(), small).unwrap();
        let release = block_on(git.release_job(name)).unwrap().expect("the release job");
        assert_eq!(release.commit, store::oid_hex(&small));
        assert_eq!(git.transport.count(wire::ReplyChunk::METHOD), 4, "no chunk beyond the head");

        // The git side forgot the staged rest (an upgrade, or newer asks):
        // the refusal says to ask again.
        store::set_ref(name, &store::head_target(name).unwrap(), tip).unwrap();
        for_authority::forget_staged_replies();
        git.transport.fail_next(wire::ReplyChunk::METHOD, Failure::Lost("timed out".into()));
        match block_on(git.release_job(name)) {
            Err(Failure::Lost(e)) => assert_eq!(e, "timed out"),
            Err(other) => panic!("{other}"),
            Ok(other) => panic!("answered: {:?}", other.map(|r| r.commit)),
        }
        let head_calls = git.transport.count(wire::ReleaseJob::METHOD);
        let reply = block_on(git.release_job(name)).unwrap();
        assert_eq!(git.transport.count(wire::ReleaseJob::METHOD), head_calls + 1);
        assert!(reply.is_ok(), "{:?}", reply.err());
        git.transport.fail_next(wire::ReleaseJob::METHOD, Failure::NotDelivered("stopped".into()));
        match block_on(git.release_job(name)) {
            Err(f) => assert_eq!(f, Failure::NotDelivered("stopped".into())),
            Ok(_) => panic!("answered"),
        }
    }

    /// A job the git side submits over messages is staged in chunks ahead
    /// of the submit that names them, and the authority queues it once:
    /// again after a lost answer it is answered and not queued; a chunk
    /// whose call failed fails the submit, and nothing is taken until
    /// every chunk is there.
    #[test]
    fn a_submitted_job_is_staged_in_chunks_and_queued_once() {
        let name = "peer-submit";
        crate::tenancy::test_repo(name);
        block_on(crate::configs::set_wasm(name, "aaaaa-aa".into(), "app.wasm".into())).unwrap();
        let big = vec![3u8; MAX_CHUNK + 10];
        let tip = push(name, &big);
        let hex = store::oid_hex(&tip);
        let job = || ic_git_git::jobs::resolve(name, &tip);
        let queued = || crate::deploy::queue_len();
        let before = queued();

        let authority = ic_git_git::peer::Authority { transport: Loopback::new(false) };
        // A chunk's call fails: the submit fails, nothing was staged.
        authority.transport.fail_next(wire::StageJob::METHOD, Failure::NotDelivered("stopped".into()));
        assert_eq!(
            block_on(authority.submit_job(100, name, &hex, job())),
            Err(Failure::NotDelivered("stopped".into()))
        );
        assert_eq!(authority.transport.count(wire::SubmitJob::METHOD), 0, "no submit without its chunks");
        assert_eq!(queued(), before);

        // Then it goes through: one staged chunk, then the submit with the tail.
        assert_eq!(block_on(authority.submit_job(100, name, &hex, job())), Ok(Ok(())));
        assert_eq!(authority.transport.count(wire::StageJob::METHOD), 2);
        assert_eq!(authority.transport.count(wire::SubmitJob::METHOD), 1);
        assert_eq!(queued(), before + 1);
        assert!(for_git::taken(100));

        // The answer was lost: sent again, taken once.
        assert_eq!(block_on(authority.submit_job(100, name, &hex, job())), Ok(Ok(())));
        assert_eq!(queued(), before + 1);

        // A later item whose answer is lost on the submit itself: the
        // authority took it, and the retry is answered and not queued.
        let next = store::commit_file_for_tests(name, "app.wasm", b"v2", Some(tip));
        store::set_ref(name, &store::head_target(name).unwrap(), next).unwrap();
        let next_hex = store::oid_hex(&next);
        authority.transport.fail_next(wire::SubmitJob::METHOD, Failure::Lost("timed out".into()));
        assert_eq!(
            block_on(authority.submit_job(101, name, &next_hex, ic_git_git::jobs::resolve(name, &next))),
            Err(Failure::Lost("timed out".into()))
        );
        assert_eq!(queued(), before + 2);
        assert_eq!(block_on(authority.submit_job(101, name, &next_hex, ic_git_git::jobs::resolve(name, &next))), Ok(Ok(())));
        assert_eq!(queued(), before + 2);

        // A job that does not decode once whole is taken and refused for
        // good, and the commit's status says so.
        let garbage = ic_git_git::peer::Authority { transport: Loopback::new(false) };
        assert_eq!(
            block_on(garbage.submit_job(103, name, &next_hex, Job { wasm: None, evm: None })),
            Ok(Ok(())),
            "an empty job decodes"
        );
        let st = crate::deploy::get_status(name);
        assert!(st.is_none(), "nothing refused yet");

        // The other two calls cross too.
        assert_eq!(block_on(authority.charge_push(name, 10)), Ok(Ok(())), "an ownerless repo pays nothing");
        let event = Event::Pushed {
            repo: name.into(),
            branch: "refs/heads/main".into(),
            tip_before: None,
            tip: next_hex,
        };
        assert_eq!(block_on(authority.notify(102, event)), Ok(()));
        assert!(for_git::taken(102));
    }
}
