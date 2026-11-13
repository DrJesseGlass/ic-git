//! The boundary as messages (docs/CANISTER_SPLIT.md, phase 3 step 12b):
//! one struct per call across it, the method it is sent to and the reply
//! it gets back, and the transport that carries the encoded bytes.
//!
//! Each side's interface (`GitSide`, `AuthoritySide`) stays what the
//! crates program against. Over messages, a call becomes one of these
//! structs, candid-encoded as the one argument of an update method on the
//! other canister, whose reply is `Message::Reply`; the receiving canister's
//! endpoints take the same structs. A reply that will not decode counts as
//! lost (`Failure::Lost`): the call ran, and what it answered is gone.
//!
//! Two calls can carry more than the 2 MiB message limit: a job, with a
//! module and its proof, and the release job `deploy_now` asks for. Their
//! bodies (a candid-encoded `Job`) go in pieces of at most `MAX_CHUNK`
//! bytes: a job is staged on the authority, chunk by chunk, ahead of the
//! `submit_job` that names the chunks and carries the last; a release job
//! comes back as a head with the first chunk and a handle the rest are
//! fetched by.

use crate::authority_side::Event;
use crate::git_side::{Attested, DeployConfigs, PushPolicy, RecordKind, Retry};
use crate::side::{Failure, Fut, Reply};
use candid::CandidType;
use serde::Deserialize;

/// The most bytes one piece of a staged body carries: half the message
/// limit, which leaves the rest of the message and candid's framing room
/// to spare.
pub const MAX_CHUNK: usize = 1 << 20;

/// The most bytes an encoded job may come to, which both sides hold to:
/// what the governor takes for a module, which is the most of a job. The
/// authority refuses a larger one for good, and the git side's outbox
/// drops it.
pub const MAX_JOB_BYTES: usize = 32 << 20;

/// One call across the boundary: its argument, where it goes, what comes
/// back.
pub trait Message: CandidType {
    /// The update method on the other canister.
    const METHOD: &'static str;
    /// What the method answers.
    type Reply: CandidType + for<'de> Deserialize<'de>;
}

/// What carries an encoded message to a method on the other canister and
/// brings its encoded reply back, or says why there is none.
pub trait Transport {
    fn call<'a>(&'a self, method: &'static str, arg: Vec<u8>) -> Fut<'a, Reply<Vec<u8>>>;
}

/// Send `message` over `transport` and decode its reply.
pub async fn send<T: Transport + ?Sized, M: Message>(transport: &T, message: M) -> Reply<M::Reply> {
    let arg = candid::encode_one(&message)
        .map_err(|e| Failure::NotDelivered(format!("{} not encodable: {e}", M::METHOD)))?;
    let reply = transport.call(M::METHOD, arg).await?;
    candid::decode_one::<M::Reply>(&reply).map_err(|e| Failure::Lost(format!("{}'s reply undecodable: {e}", M::METHOD)))
}

/// A body in pieces of at most `MAX_CHUNK` bytes: never none, so the last
/// piece is always there to send with the call that names the others.
pub fn pieces(body: &[u8]) -> Vec<&[u8]> {
    if body.is_empty() {
        return vec![&[]];
    }
    body.chunks(MAX_CHUNK).collect()
}

/// The release job's reply (`release_job`): the release commit, the first
/// chunk of the encoded job, and how many more chunks `release_chunk`
/// serves under `handle`, numbered 1 to `more`. `handle` is 0 when there
/// are none.
#[derive(CandidType, Deserialize)]
pub struct ReleaseHead {
    pub commit: String,
    pub handle: u64,
    pub more: u32,
    pub head: Vec<u8>,
}

macro_rules! messages {
    ($( $(#[$doc:meta])* $name:ident = $method:literal -> $reply:ty { $($field:ident : $ty:ty),* $(,)? } )*) => {$(
        $(#[$doc])*
        #[derive(CandidType, Deserialize)]
        pub struct $name {
            $(pub $field: $ty,)*
        }

        impl Message for $name {
            const METHOD: &'static str = $method;
            type Reply = $reply;
        }
    )*};
}

// What the authority sends the git canister (GitSide).
messages! {
    /// `GitSide::set_deploy_configs`.
    SetDeployConfigs = "set_deploy_configs" -> () { repo: String, seq: u64, configs: DeployConfigs }
    /// `GitSide::set_push_policy`.
    SetPushPolicy = "set_push_policy" -> () { repo: String, seq: u64, policy: PushPolicy }
    /// `GitSide::set_approved`.
    SetApproved = "set_approved" -> () { repo: String, seq: u64, approved: Option<Vec<String>>, retry: Option<Retry> }
    /// `GitSide::check_new_repo`.
    CheckNewRepo = "check_new_repo" -> Result<String, String> { name: String }
    /// `GitSide::create_repo`.
    CreateRepo = "create_repo" -> Result<(), String> { name: String }
    /// `GitSide::has_commit`; `oid` is the 20 bytes.
    HasCommit = "has_commit" -> bool { oid: Vec<u8> }
    /// `GitSide::record_artifact`.
    RecordArtifact = "record_artifact" -> Result<Attested, String> { repo: String, kind: RecordKind }
    /// `GitSide::release_job`, the head of its reply.
    ReleaseJob = "release_job" -> Result<ReleaseHead, String> { repo: String }
    /// The rest of a release job's reply: chunk `index` (1 to `more`) of
    /// the body under `handle`.
    ReleaseChunk = "release_chunk" -> Result<Vec<u8>, String> { handle: u64, index: u32 }
}

// What the git canister sends the authority (AuthoritySide).
messages! {
    /// `AuthoritySide::charge_push`.
    ChargePush = "charge_push" -> Result<(), String> { repo: String, bytes: u64 }
    /// Chunk `index` (from 0) of the job outbox item `seq` submits for
    /// `commit` of `repo`, ahead of the `submit_job` that names it; `total`
    /// is the whole body's length. Staging the same chunk again is fine,
    /// as a retry does. The authority's `Err` is final: a job over
    /// `MAX_JOB_BYTES`, or one whose chunks outrun `total`, is recorded as
    /// the commit's failed deploy, and the git side drops the item.
    StageJob = "stage_job" -> Result<(), String> { seq: u64, repo: String, commit: String, total: u64, index: u32, bytes: Vec<u8> }
    /// `AuthoritySide::submit_job`: the job's body is the `staged` chunks
    /// staged before, in index order, then `tail`. The authority's `Err`
    /// says it does not hold the chunks (an upgrade dropped them) and took
    /// nothing: the git side stages them again, later.
    SubmitJob = "submit_job" -> Result<(), String> { seq: u64, repo: String, commit: String, staged: u32, tail: Vec<u8> }
    /// `AuthoritySide::notify`.
    Notify = "notify" -> () { seq: u64, event: Event }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::side::ready;
    use futures::executor::block_on;
    use std::cell::RefCell;

    #[test]
    fn a_body_goes_in_pieces_of_at_most_a_chunk() {
        assert_eq!(pieces(&[]).len(), 1, "an empty body is one empty piece");
        let one = vec![1u8; MAX_CHUNK];
        assert_eq!(pieces(&one).len(), 1);
        let over = vec![1u8; MAX_CHUNK + 1];
        let p = pieces(&over);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].len(), MAX_CHUNK);
        assert_eq!(p[1].len(), 1);
        assert_eq!(p.concat(), over);
    }

    /// A transport that answers every call with the bytes it was given,
    /// recording the method.
    struct Canned {
        reply: Vec<u8>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl Transport for Canned {
        fn call<'a>(&'a self, method: &'static str, arg: Vec<u8>) -> Fut<'a, Reply<Vec<u8>>> {
            self.calls.borrow_mut().push(method);
            let m: CheckNewRepo = candid::decode_one(&arg).expect("the argument is the message");
            assert_eq!(m.name, "r");
            ready(Ok(self.reply.clone()))
        }
    }

    /// A message goes to its method as one candid argument; its reply
    /// decodes as the message says, and one that does not is lost.
    #[test]
    fn a_message_is_sent_to_its_method_and_its_reply_decoded() {
        let t = Canned {
            reply: candid::encode_one(Ok::<String, String>("label".into())).unwrap(),
            calls: RefCell::new(Vec::new()),
        };
        let reply = block_on(send(&t, CheckNewRepo { name: "r".into() }));
        assert_eq!(reply, Ok(Ok("label".into())));
        assert_eq!(*t.calls.borrow(), vec![CheckNewRepo::METHOD]);

        let t = Canned {
            reply: candid::encode_one(42u64).unwrap(),
            calls: RefCell::new(Vec::new()),
        };
        match block_on(send(&t, CheckNewRepo { name: "r".into() })) {
            Err(Failure::Lost(e)) => assert!(e.contains("undecodable"), "{e}"),
            other => panic!("{other:?}"),
        }
    }
}
