//! The authority's answer to the git side
//! (ic_git_types::authority_side): one implementation of the interface,
//! over tenancy, the deploy queue and the feed. The canister installs it
//! into the git side at init and upgrade. Each call is a plain function
//! behind a ready future (phase 3, step 8): in one canister nothing is
//! lost, so every reply is `Ok`.
//!
//! The outbox items (`submit_job`, `notify`) carry the git side's sequence
//! number and arrive in order, so one high-water mark says which have been
//! taken: one that arrives again, after a lost answer, is answered and not
//! acted on.
//!
//! Over messages (phase 3, step 12b) a job arrives in chunks: `stage_job`
//! keeps each until the `submit_job` that names them (`submit_staged`),
//! which takes the item only once every chunk is there. The chunks wait in
//! heap, one item's at a time and at most `MAX_JOB_BYTES` of it, so a git
//! canister can fill nothing more; an upgrade drops them, and the git
//! side's retry stages them again. A job this side will never run -- over
//! the cap, or unreadable once whole -- is taken and refused for good,
//! and the refusal is the commit's deploy status.
//!
//! The git canister's own record (step 12d) is asked and waited for, by
//! the git canister's `registry_publish_canister`, which its governor
//! calls after an upgrade; `publish_git_record` is the receiver. One
//! canister has no git canister to record: `Authority` refuses the call.

use crate::peer::CanisterInfo;
use candid::Principal;
use ic_git_types::authority_side::{AuthoritySide, Event, Published};
use ic_git_types::deploy::Job;
use ic_git_types::oid::parse_oid;
use ic_git_types::side::{ready, Fut, Reply};
use ic_git_types::wire::MAX_JOB_BYTES;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// This crate, as the git side sees it.
pub struct Authority;

/// `AuthoritySide::publish_git_record` over messages: the git canister's
/// record, `ic-git#git`, from the commit and module hash its governor
/// stated. This side reads the module hash the IC holds for the git
/// canister (`canister_info`, the management canister's) and publishes
/// only a record that names it; a stated value that does not parse is
/// refused before anything is asked, and a canister this side cannot
/// publish to (no registry) is refused before the chain is touched. Paid
/// by this canister, as its own record is: no repo is being served.
pub async fn publish_git_record(
    commit_hex: &str,
    module_sha256_hex: &str,
    canister_info: impl AsyncFn(Principal) -> Result<CanisterInfo, String>,
) -> Result<Published, String> {
    let git = crate::peer::GIT.get().ok_or("no git canister is named")?;
    let record = crate::provenance::git_record(commit_hex, module_sha256_hex)?;
    let info = canister_info(git).await?;
    crate::provenance::running(&record, info.module_hash.as_deref())?;
    crate::evm::require_publish_target()?;
    let out = crate::provenance::publish(&record).await.map_err(|e| e.message)?;
    Ok(Published { tx_hash: out.tx_hash })
}

/// The newest outbox item taken.
const INBOX_KEY: &str = "inbox:last";

/// The chunks of the one item being staged.
struct Staging {
    seq: u64,
    chunks: BTreeMap<u32, Vec<u8>>,
    bytes: usize,
}

thread_local! {
    static STAGING: RefCell<Option<Staging>> = const { RefCell::new(None) };
}

/// Was outbox item `seq` taken?
pub fn taken(seq: u64) -> bool {
    let last: u64 = crate::kv::get_json(INBOX_KEY).unwrap_or(0);
    seq <= last
}

/// Take outbox item `seq`, unless it was taken before.
fn take(seq: u64) -> bool {
    if taken(seq) {
        return false;
    }
    crate::kv::set_json(INBOX_KEY, &seq);
    true
}

/// Queue a submitted job, unless the app already runs the commit or a
/// deploy of it is queued or running (deploy::accept). The git side is
/// not told which: a dropped job is one it had no way to know was moot,
/// and the deploy status says what the app runs.
fn queue(repo: &str, commit_hex: &str, job: Job) {
    if let Ok(commit) = parse_oid(commit_hex) {
        let _queued = crate::deploy::accept(repo, commit, job);
    }
}

/// Take item `seq` as a job this side will never run, and say why in the
/// commit's deploy status.
fn refuse(seq: u64, repo: &str, commit_hex: &str, why: String) -> Result<(), String> {
    STAGING.with(|s| *s.borrow_mut() = None);
    take(seq);
    crate::deploy::refuse_submitted(repo, commit_hex, &why);
    Err(why)
}

/// Keep chunk `index` of the job item `seq` will submit for `commit_hex`
/// of `repo`, a body of `total` bytes. One taken already needs no chunks;
/// a chunk of a newer item than the one staged starts over, since the
/// outbox sends one item at a time. A body over `MAX_JOB_BYTES`, or
/// chunks that outrun `total`, is refused for good: taken, with the
/// refusal as the commit's deploy status.
pub fn stage_job(seq: u64, repo: &str, commit_hex: &str, total: u64, index: u32, bytes: Vec<u8>) -> Result<(), String> {
    if taken(seq) {
        return Ok(());
    }
    if total > MAX_JOB_BYTES as u64 {
        return refuse(seq, repo, commit_hex, format!("the job is {total} bytes; at most {MAX_JOB_BYTES} can be carried across"));
    }
    let outrun = STAGING.with(|s| {
        let mut s = s.borrow_mut();
        if !matches!(s.as_ref(), Some(st) if st.seq == seq) {
            *s = Some(Staging {
                seq,
                chunks: BTreeMap::new(),
                bytes: 0,
            });
        }
        let staging = s.as_mut().expect("staging for this item");
        let replaced = staging.chunks.get(&index).map_or(0, Vec::len);
        let bytes_after = staging.bytes - replaced + bytes.len();
        if bytes_after as u64 > total {
            return true;
        }
        staging.bytes = bytes_after;
        staging.chunks.insert(index, bytes);
        false
    });
    if outrun {
        return refuse(seq, repo, commit_hex, format!("the job's chunks outrun its {total} bytes"));
    }
    Ok(())
}

/// The body item `seq` submits: its `staged` chunks, in order, then
/// `tail`. Refused, with nothing taken and nothing dropped, when a chunk
/// is missing: the git side stages them all again. Otherwise the chunks
/// are moved into the body, each freed as it goes, so the cap bounds the
/// heap and not twice it.
fn assemble(seq: u64, staged: u32, tail: Vec<u8>) -> Result<Vec<u8>, String> {
    STAGING.with(|s| {
        let mut s = s.borrow_mut();
        let staging = match s.as_mut() {
            Some(st) if st.seq == seq => st,
            _ if staged == 0 => return Ok(tail),
            _ => return Err(format!("no chunk of item {seq} is staged")),
        };
        if let Some(missing) = (0..staged).find(|i| !staging.chunks.contains_key(i)) {
            return Err(format!("chunk {missing} of item {seq} is not staged"));
        }
        let mut chunks = std::mem::take(&mut staging.chunks);
        let total = staging.bytes + tail.len();
        *s = None;
        let mut body = chunks.remove(&0).unwrap_or_default();
        body.reserve(total - body.len());
        for index in 1..staged {
            body.append(&mut chunks.remove(&index).expect("checked above"));
        }
        body.extend_from_slice(&tail);
        Ok(body)
    })
}

/// `AuthoritySide::submit_job` over messages: the job is the staged
/// chunks and `tail`. Taken once the body is whole, whether or not it
/// decodes: one that does not is refused for good, with the refusal as
/// the commit's deploy status, since left unanswered it would hold every
/// item behind it.
pub fn submit_staged(seq: u64, repo: &str, commit_hex: &str, staged: u32, tail: Vec<u8>) -> Result<(), String> {
    if taken(seq) {
        return Ok(());
    }
    let body = assemble(seq, staged, tail)?;
    take(seq);
    match candid::decode_one::<Job>(&body) {
        Ok(job) => queue(repo, commit_hex, job),
        Err(e) => crate::deploy::refuse_submitted(repo, commit_hex, &format!("the job does not decode: {e}")),
    }
    Ok(())
}

impl AuthoritySide for Authority {
    fn charge_push<'a>(&'a self, repo: &'a str, bytes: u64) -> Fut<'a, Reply<Result<(), String>>> {
        ready(Ok(crate::tenancy::charge_push(repo, bytes as usize)))
    }

    fn submit_job<'a>(&'a self, seq: u64, repo: &'a str, commit_hex: &'a str, job: Job) -> Fut<'a, Reply<Result<(), String>>> {
        if take(seq) {
            queue(repo, commit_hex, job);
        }
        ready(Ok(Ok(())))
    }

    fn notify<'a>(&'a self, seq: u64, event: Event) -> Fut<'a, Reply<()>> {
        if take(seq) {
            crate::feed::notify(event);
        }
        ready(Ok(()))
    }

    /// One canister is both sides: its record is `ic-git#canister`,
    /// which its controller publishes through `registry_publish_canister`.
    fn publish_git_record<'a>(&'a self, _commit_hex: &'a str, _module_sha256_hex: &'a str) -> Fut<'a, Reply<Result<Published, String>>> {
        ready(Ok(Err("this canister is its own git side; its record is ic-git#canister, which a controller publishes".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An outbox item that arrives again -- its answer was lost -- is taken
    /// once; later ones still are.
    #[test]
    fn an_outbox_item_is_taken_once() {
        assert!(take(1));
        assert!(!take(1), "again, after a lost answer");
        assert!(take(2));
        assert!(!take(1));
        assert!(take(5), "a gap: the outbox dropped an item that no longer decoded");
    }

    /// A submit names chunks it staged: one missing refuses the submit
    /// and takes nothing, a newer item's chunk starts the staging over,
    /// a taken item is answered without chunks, and the body is the
    /// chunks in order then the tail.
    #[test]
    fn a_staged_job_is_taken_once_whole() {
        let job = candid::encode_one(Job { wasm: None, evm: None }).unwrap();
        let (head, tail) = job.split_at(job.len() / 2);
        let repo = "stage";
        let commit = "0000000000000000000000000000000000000001";
        let total = job.len() as u64;
        let stage = |seq, index, bytes: &[u8]| stage_job(seq, repo, commit, total, index, bytes.to_vec());

        assert!(stage(10, 0, head).is_ok());
        let refused = submit_staged(10, repo, commit, 2, tail.to_vec()).unwrap_err();
        assert!(refused.contains("chunk 1"), "{refused}");
        assert!(!taken(10));
        STAGING.with(|s| assert!(s.borrow().is_some(), "kept for the retry"));
        // A later item's chunk replaces the staging.
        assert!(stage(11, 0, head).is_ok());
        let refused = submit_staged(10, repo, commit, 1, tail.to_vec()).unwrap_err();
        assert!(refused.contains("no chunk of item 10"), "{refused}");
        assert!(stage(10, 0, head).is_ok());
        assert!(stage(10, 0, head).is_ok(), "the same chunk again");
        assert_eq!(submit_staged(10, repo, commit, 1, tail.to_vec()), Ok(()));
        assert!(taken(10));
        assert_eq!(crate::deploy::get_status(repo).map(|s| s.ok), None, "a job that decodes is not refused");
        assert_eq!(submit_staged(10, repo, commit, 1, tail.to_vec()), Ok(()), "answered, not acted on");
        assert_eq!(stage(10, 0, head), Ok(()), "a taken item needs no chunks");
        STAGING.with(|s| assert!(s.borrow().is_none()));
        // No staging at all is fine for a job that fits in the tail.
        assert_eq!(submit_staged(12, repo, commit, 0, job.clone()), Ok(()));
        assert!(taken(12));
    }

    /// What this side will never run is refused for good: taken, with
    /// the refusal as the commit's deploy status -- a job over the cap at
    /// its first chunk, chunks that outrun the body's length, and a whole
    /// body that does not decode. A deploy that is running keeps its
    /// status.
    #[test]
    fn a_job_this_side_cannot_run_is_refused_for_good() {
        let repo = "refuse";
        let commit = "0000000000000000000000000000000000000002";
        let status = || crate::deploy::get_status(repo).expect("a status");

        let refused = stage_job(20, repo, commit, MAX_JOB_BYTES as u64 + 1, 0, vec![0u8; 10]).unwrap_err();
        assert!(refused.contains("at most"), "{refused}");
        assert!(taken(20));
        assert!(!status().ok);
        assert!(status().message.contains(&refused));
        assert_eq!(status().commit, commit);
        STAGING.with(|s| assert!(s.borrow().is_none()));

        assert!(stage_job(21, repo, commit, 10, 0, vec![0u8; 8]).is_ok());
        let refused = stage_job(21, repo, commit, 10, 1, vec![0u8; 8]).unwrap_err();
        assert!(refused.contains("outrun"), "{refused}");
        assert!(taken(21));
        assert!(status().message.contains("outrun"));

        assert_eq!(submit_staged(22, repo, commit, 0, b"not candid".to_vec()), Ok(()));
        assert!(taken(22));
        assert!(status().message.contains("does not decode"), "{}", status().message);

        // Taken and refused is final: the same item again is answered.
        assert_eq!(stage_job(21, repo, commit, 10, 1, vec![0u8; 8]), Ok(()));
    }

    /// The git canister's record: nothing is asked of the management
    /// canister for a stated value that does not parse, or before a git
    /// canister is named; a module hash that is not the one the IC holds
    /// is refused; one that is goes on to the publish, which here has no
    /// registry to go to. In one canister the call is refused outright.
    #[test]
    fn the_git_record_is_checked_against_the_running_module() {
        use futures::executor::block_on;
        let commit = "a23ee3157b7837eaa205cdc9f7f5dbadd243b1ce";
        let hash = "30e76748ddb1487e41ca2718c30aa469c2ffa35f21f4c1936e67509771066d6a";
        let git = Principal::from_slice(&[6; 8]);
        let asks = std::cell::Cell::new(0);
        let running = std::cell::RefCell::new(Some(hex::decode(hash).unwrap()));
        let info = async |p: Principal| {
            asks.set(asks.get() + 1);
            assert_eq!(p, git, "the named git canister is asked about");
            Ok(CanisterInfo {
                controllers: vec![],
                module_hash: running.borrow().clone(),
            })
        };
        crate::kv::remove(crate::peer::GIT.key);
        let e = block_on(publish_git_record(commit, hash, info)).unwrap_err();
        assert!(e.contains("no git canister"), "{e}");
        crate::peer::GIT.set(git);
        let e = block_on(publish_git_record("zz", hash, info)).unwrap_err();
        assert!(e.contains("40 hex"), "{e}");
        assert_eq!(asks.get(), 0, "nothing asked for a value that does not parse");

        *running.borrow_mut() = Some(vec![0xcd; 32]);
        let e = block_on(publish_git_record(commit, hash, info)).unwrap_err();
        assert!(e.contains("runs module cdcd"), "{e}");
        *running.borrow_mut() = None;
        let e = block_on(publish_git_record(commit, hash, info)).unwrap_err();
        assert!(e.contains("runs no code"), "{e}");
        assert_eq!(asks.get(), 2);

        *running.borrow_mut() = Some(hex::decode(hash).unwrap());
        crate::kv::remove("evm:config");
        let e = block_on(publish_git_record(commit, hash, info)).unwrap_err();
        assert!(e.contains("evm_set_config") || e.contains("registry"), "past the check, to the publish: {e}");
        assert_eq!(asks.get(), 3);
        crate::kv::remove(crate::peer::GIT.key);

        let one = block_on(Authority.publish_git_record(commit, hash)).unwrap().unwrap_err();
        assert!(one.contains("ic-git#canister"), "{one}");
    }
}
