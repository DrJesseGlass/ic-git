//! Everything the git side tells the authority (docs/CANISTER_SPLIT.md,
//! section 4), as one interface. The authority crate implements it; the git
//! crate holds only this trait. Every call is awaited and answers a `Reply`
//! (side.rs): in one canister a plain function behind a ready future,
//! across the cut a message (phase 3, step 8).
//!
//! The git side sends `submit_job` and `notify` from an outbox it keeps in
//! stable memory, in order and one at a time, and retries each until the
//! authority answers, so each must be safe to receive twice: it carries
//! the outbox's sequence number, and the authority ignores one it has
//! taken. (It dedupes a job by (repo, commit) as well, which covers a job
//! submitted twice by different pushes.) `charge_push` is asked from the
//! push itself, which waits for the answer.
//!
//! `publish_git_record`, the git canister's own module record, comes with
//! the two builds (step 12).

use crate::deploy::Job;
use crate::side::{Fut, Reply};
use candid::CandidType;
use serde::Deserialize;

/// Something that happened on the git side and the authority's feed tells
/// of. Commits are hex object ids.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum Event {
    /// A push moved the deploy branch `branch` from `tip_before` to `tip`.
    Pushed {
        repo: String,
        branch: String,
        tip_before: Option<String>,
        tip: String,
    },
}

pub trait AuthoritySide {
    /// Charge the repo's owner for a push of `bytes`, before the pack is
    /// read. The callee's `Err` refuses the push.
    fn charge_push<'a>(&'a self, repo: &'a str, bytes: u64) -> Fut<'a, Reply<Result<(), String>>>;

    /// Hand the authority a commit's deploy job (outbox item `seq`): the
    /// repo's configs as the git side mirrors them and each leg's proven
    /// artifact. The authority queues it unless it took `seq` already or a
    /// job for the same (repo, commit) is waiting. Its `Err` is a job it
    /// will never take (too large to carry across), which it has recorded
    /// as the commit's failed deploy: the outbox drops the item instead of
    /// sending it again.
    fn submit_job<'a>(&'a self, seq: u64, repo: &'a str, commit_hex: &'a str, job: Job) -> Fut<'a, Reply<Result<(), String>>>;

    /// Tell the authority what happened (outbox item `seq`).
    fn notify<'a>(&'a self, seq: u64, event: Event) -> Fut<'a, Reply<()>>;
}
