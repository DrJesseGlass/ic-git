//! The authority as another canister (docs/CANISTER_SPLIT.md, phase 3
//! step 12b): its principal (`AUTHORITY`), which this side takes at init
//! and which alone may write the mirrors and ask what they govern; and the
//! `AuthoritySide` that sends it messages (`ic_git_types::wire`), one call
//! each, except a job, which goes in chunks. The combined build installs
//! none of this: there the authority is `for_git::Authority`, in the same
//! canister. The two-canister build (step 12c) installs
//! `AUTHORITY_CANISTER` at init and upgrade and guards each
//! authority-facing endpoint (the mirror writes, `check_new_repo`,
//! `create_repo`, `has_commit`, `record_artifact`, `release_job`,
//! `release_chunk`) with `AUTHORITY.check_caller`.

use candid::Principal;
use ic_git_common::call::Canister;
use ic_git_common::peer::Peer;
use ic_git_types::authority_side::{AuthoritySide, Event};
use ic_git_types::deploy::Job;
use ic_git_types::side::{Failure, Fut, Reply};
use ic_git_types::wire::{self, pieces, send, Transport};

/// The authority, once this canister has been told it: the git canister's
/// init argument (step 12c).
pub const AUTHORITY: Peer = Peer {
    key: "peer:authority",
    name: "authority",
};

fn authority() -> Option<Principal> {
    AUTHORITY.get()
}

/// The authority, reached by messages over `transport`.
pub struct Authority<T: Transport> {
    pub transport: T,
}

/// The authority canister, by inter-canister calls to whatever `authority`
/// says: what the two-canister build installs.
pub static AUTHORITY_CANISTER: Authority<Canister> = Authority {
    transport: Canister { id: authority },
};

impl<T: Transport> AuthoritySide for Authority<T> {
    fn charge_push<'a>(&'a self, repo: &'a str, bytes: u64) -> Fut<'a, Reply<Result<(), String>>> {
        Box::pin(send(&self.transport, wire::ChargePush { repo: repo.into(), bytes }))
    }

    /// The encoded job in pieces: each but the last staged under `seq`,
    /// then the submit, which names them and carries the last. A piece
    /// whose call fails fails the whole, and the outbox sends the item
    /// again later; so does a submit the authority refuses, which it does
    /// only when a chunk it was sent is gone (an upgrade between), and
    /// then it took nothing. A piece the authority refuses is the job
    /// refused for good (too large; it recorded why): the answer, and the
    /// outbox drops the item.
    fn submit_job<'a>(&'a self, seq: u64, repo: &'a str, commit_hex: &'a str, job: Job) -> Fut<'a, Reply<Result<(), String>>> {
        Box::pin(async move {
            let body = candid::encode_one(&job).map_err(|e| Failure::NotDelivered(format!("the job does not encode: {e}")))?;
            let total = body.len() as u64;
            let mut chunks = pieces(&body);
            let tail = chunks.pop().expect("at least one piece").to_vec();
            for (index, chunk) in chunks.iter().enumerate() {
                let stage = wire::StageJob {
                    seq,
                    repo: repo.into(),
                    commit: commit_hex.into(),
                    total,
                    index: index as u32,
                    bytes: chunk.to_vec(),
                };
                if let Err(e) = send(&self.transport, stage).await? {
                    return Ok(Err(e));
                }
            }
            let submit = wire::SubmitJob {
                seq,
                repo: repo.into(),
                commit: commit_hex.into(),
                staged: chunks.len() as u32,
                tail,
            };
            match send(&self.transport, submit).await? {
                Ok(()) => Ok(Ok(())),
                Err(e) => Err(Failure::NotDelivered(format!("the authority did not take the job: {e}"))),
            }
        })
    }

    fn notify<'a>(&'a self, seq: u64, event: Event) -> Fut<'a, Reply<()>> {
        Box::pin(send(&self.transport, wire::Notify { seq, event }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ic_git_types::proof::Artifact;
    use ic_git_types::wire::{Message, MAX_CHUNK};
    use std::cell::RefCell;

    /// The transport calls whatever the record names at the time.
    #[test]
    fn the_transport_follows_the_named_authority() {
        let authority = Principal::from_slice(&[1; 8]);
        assert_eq!((AUTHORITY_CANISTER.transport.id)(), None);
        assert_eq!(AUTHORITY.check_caller(&authority), Err("no authority is set; only it may call this".into()));
        AUTHORITY.set(authority);
        assert_eq!((AUTHORITY_CANISTER.transport.id)(), Some(authority));
        assert_eq!(AUTHORITY.check_caller(&authority), Ok(()));
        crate::kv::remove(AUTHORITY.key);
    }

    /// A transport that records each call's method and argument and
    /// answers as told: the authority's refusal of the next submit or the
    /// next piece, or nothing at all for the next call of a method.
    #[derive(Default)]
    struct Recorder {
        calls: RefCell<Vec<(&'static str, Vec<u8>)>>,
        refuse_submit: RefCell<bool>,
        refuse_stage: RefCell<bool>,
        drop_next: RefCell<Option<&'static str>>,
    }

    impl Transport for Recorder {
        fn call<'a>(&'a self, method: &'static str, arg: Vec<u8>) -> Fut<'a, Reply<Vec<u8>>> {
            self.calls.borrow_mut().push((method, arg.clone()));
            let dropped = {
                let mut d = self.drop_next.borrow_mut();
                let hit = *d == Some(method);
                if hit {
                    d.take();
                }
                hit
            };
            if dropped {
                return ic_git_types::side::ready(Err(Failure::NotDelivered("stopped".into())));
            }
            let reply = match method {
                m if m == wire::StageJob::METHOD => {
                    if self.refuse_stage.replace(false) {
                        candid::encode_one(Err::<(), String>("too large".into()))
                    } else {
                        candid::encode_one(Ok::<(), String>(()))
                    }
                }
                m if m == wire::SubmitJob::METHOD => {
                    if self.refuse_submit.replace(false) {
                        candid::encode_one(Err::<(), String>("chunk 0 of item 1 is not staged".into()))
                    } else {
                        candid::encode_one(Ok::<(), String>(()))
                    }
                }
                other => panic!("unexpected {other}"),
            };
            ic_git_types::side::ready(Ok(reply.unwrap()))
        }
    }

    fn job(blob_len: usize) -> Job {
        Job {
            wasm: None,
            evm: Some((
                ic_git_types::deploy::EvmDeployConfig {
                    source_path: "c.hex".into(),
                    gas_limit: 1,
                },
                Ok(Artifact {
                    blob: vec![9u8; blob_len],
                    proof: Vec::new(),
                }),
            )),
        }
    }

    /// A job over a chunk goes as staged pieces of at most a chunk, in
    /// order, each naming the commit and the body's length, then the
    /// submit that names them and carries the rest, and the pieces make
    /// the encoded job again; one under a chunk is the submit alone. The
    /// submit refused (the chunks gone) is not delivered, and so is a
    /// piece whose call failed, after which nothing more is sent; a piece
    /// refused is the job refused for good.
    #[test]
    fn a_job_goes_in_staged_chunks_then_the_submit() {
        let authority = Authority { transport: Recorder::default() };
        let big = job(2 * MAX_CHUNK + 5);
        let encoded = candid::encode_one(&big).unwrap();
        assert_eq!(block_on(authority.submit_job(7, "r", "c", big)), Ok(Ok(())));
        let calls = authority.transport.calls.borrow().clone();
        assert_eq!(calls.len(), 3);
        let mut body = Vec::new();
        for (i, (method, arg)) in calls.iter().enumerate().take(2) {
            assert_eq!(*method, wire::StageJob::METHOD);
            let m: wire::StageJob = candid::decode_one(arg).unwrap();
            assert_eq!((m.seq, m.repo.as_str(), m.commit.as_str(), m.index), (7, "r", "c", i as u32));
            assert_eq!(m.total, encoded.len() as u64);
            assert_eq!(m.bytes.len(), MAX_CHUNK);
            body.extend(m.bytes);
        }
        assert_eq!(calls[2].0, wire::SubmitJob::METHOD);
        let m: wire::SubmitJob = candid::decode_one(&calls[2].1).unwrap();
        assert_eq!((m.seq, m.repo.as_str(), m.commit.as_str(), m.staged), (7, "r", "c", 2));
        assert!(m.tail.len() < MAX_CHUNK);
        body.extend(m.tail);
        assert_eq!(body, encoded);

        authority.transport.calls.borrow_mut().clear();
        assert_eq!(block_on(authority.submit_job(8, "r", "c", job(10))), Ok(Ok(())));
        let calls = authority.transport.calls.borrow().clone();
        assert_eq!(calls.len(), 1);
        let m: wire::SubmitJob = candid::decode_one(&calls[0].1).unwrap();
        assert_eq!(m.staged, 0);

        *authority.transport.refuse_submit.borrow_mut() = true;
        match block_on(authority.submit_job(9, "r", "c", job(10))) {
            Err(Failure::NotDelivered(e)) => assert!(e.contains("did not take the job"), "{e}"),
            other => panic!("{other:?}"),
        }

        authority.transport.calls.borrow_mut().clear();
        *authority.transport.drop_next.borrow_mut() = Some(wire::StageJob::METHOD);
        assert_eq!(
            block_on(authority.submit_job(10, "r", "c", job(MAX_CHUNK + 1))),
            Err(Failure::NotDelivered("stopped".into()))
        );
        assert_eq!(authority.transport.calls.borrow().len(), 1, "nothing after the failed piece");

        authority.transport.calls.borrow_mut().clear();
        *authority.transport.refuse_stage.borrow_mut() = true;
        assert_eq!(
            block_on(authority.submit_job(11, "r", "c", job(MAX_CHUNK + 1))),
            Ok(Err("too large".into()))
        );
        assert_eq!(authority.transport.calls.borrow().len(), 1, "nothing after the refused piece");
    }
}
