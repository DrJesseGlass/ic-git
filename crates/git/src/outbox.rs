//! The git side's outbox (docs/CANISTER_SPLIT.md, phase 3 step 8): what it
//! tells the authority without waiting for an answer -- a commit's deploy
//! job, and what happened on a push -- kept in stable memory until the
//! authority has answered, delivered oldest first, one at a time, and
//! retried on a timer until it does.
//!
//! An item carries its sequence number, so the authority can take it once
//! however often it arrives: a lost answer is settled by sending again.
//! Delivery stops at the first item the authority does not answer, so the
//! authority sees the items in order and one high-water mark is enough
//! there. A job the authority refuses for good (too large to carry across;
//! it records why) is dropped, or it would hold every item behind it. In
//! one canister every item is answered at once and nothing waits.
//!
//! A job is indexed by (repo, commit), so a commit whose job waits is not
//! built again, and a deploy-config change rebuilds the repo's waiting
//! jobs under the new configs (`rebuild_jobs`): what the authority gets is
//! what the configs said when it got it, as before the outbox.

use crate::kv;
use crate::memory::{self, Memory};
use candid::CandidType;
use ic_git_types::authority_side::Event;
use ic_git_types::deploy::Job;
use ic_stable_structures::StableBTreeMap;
use serde::Deserialize;
use std::cell::{Cell, RefCell};

thread_local! {
    /// Sequence number -> candid `Outgoing`.
    static OUTBOX: RefCell<StableBTreeMap<u64, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(memory::get(memory::MEM_OUTBOX)),
    );

    /// True while a drain awaits the authority. A second drain started
    /// meanwhile (a push during a retry, say) would deliver out of order,
    /// so it leaves the items to the one running, which re-reads the outbox
    /// after each answer. Heap state: an upgrade clears it and `resume`
    /// drains again.
    static DRAINING: Cell<bool> = const { Cell::new(false) };

    /// True while a retry timer is armed, so an outage arms one, not one
    /// per push that found the authority away. Heap state likewise.
    static RETRY_ARMED: Cell<bool> = const { Cell::new(false) };
}

/// The next sequence number, in META so it survives the outbox emptying.
const NEXT_KEY: &str = "outbox:next";

/// The index of waiting jobs: "outbox:job:<repo>:<commit>" -> sequence
/// number. Repo names hold no ':' (store::check_new_repo).
const JOB_PREFIX: &str = "outbox:job:";

fn job_key(repo: &str, commit_hex: &str) -> String {
    format!("{JOB_PREFIX}{repo}:{commit_hex}")
}

/// Resets the draining flag when the drain ends, however it ends: a trap
/// in a callback drops the future, and the flag must not outlive it.
struct Draining;

impl Drop for Draining {
    fn drop(&mut self) {
        DRAINING.with(|f| f.set(false));
    }
}

/// How long after an unanswered item the outbox tries again.
pub const RETRY_SECS: u64 = 30;

/// What the git side tells the authority.
#[derive(CandidType, Deserialize)]
pub enum Outgoing {
    /// A commit's deploy job (AuthoritySide::submit_job).
    SubmitJob { repo: String, commit: String, job: Job },
    /// Something the feed tells of (AuthoritySide::notify).
    Notify { event: Event },
}

fn next_seq() -> u64 {
    let n: u64 = kv::get_json(NEXT_KEY).unwrap_or(1);
    kv::set_json(NEXT_KEY, &(n + 1));
    n
}

fn first() -> Option<(u64, Vec<u8>)> {
    OUTBOX.with(|o| o.borrow().iter().next().map(|e| (*e.key(), e.value().clone())))
}

fn remove(seq: u64) {
    OUTBOX.with(|o| o.borrow_mut().remove(&seq));
}

fn holds(seq: u64) -> bool {
    OUTBOX.with(|o| o.borrow().contains_key(&seq))
}

/// The index entry of a waiting job, if its item is still there. An entry
/// whose item is gone (dropped as undecodable) is cleared.
fn indexed(repo: &str, commit_hex: &str) -> Option<u64> {
    let key = job_key(repo, commit_hex);
    let seq: u64 = kv::get_json(&key)?;
    if holds(seq) {
        Some(seq)
    } else {
        kv::remove(&key);
        None
    }
}

fn insert(item: &Outgoing) {
    // Encoding a struct of blobs, strings and integers cannot fail.
    let Ok(bytes) = candid::encode_one(item) else { return };
    let seq = next_seq();
    OUTBOX.with(|o| o.borrow_mut().insert(seq, bytes));
    if let Outgoing::SubmitJob { repo, commit, .. } = item {
        // One job per commit: a newer one replaces what waits.
        if let Some(old) = indexed(repo, commit) {
            remove(old);
        }
        kv::set_json(&job_key(repo, commit), &seq);
    }
}

/// How many items wait for an answer.
pub fn len() -> u64 {
    OUTBOX.with(|o| o.borrow().len())
}

/// Is a job for this commit waiting to be delivered? The authority dedupes
/// a job by (repo, commit) too; this spares building and storing one that
/// would be refused there.
pub fn job_waiting(repo: &str, commit_hex: &str) -> bool {
    indexed(repo, commit_hex).is_some()
}

/// The repo's deploy configs changed: every job of its that waits is built
/// again by `resolve`, under the new configs, and takes a fresh number. A
/// job the authority is answering meanwhile is answered as sent; the
/// rebuilt one follows, and the authority refuses the stale one or dedupes
/// the second.
pub fn rebuild_jobs(repo: &str, resolve: impl Fn(&str) -> Option<Job>) {
    let prefix = format!("{JOB_PREFIX}{repo}:");
    for key in kv::keys_with_prefix(&prefix) {
        let commit = key[prefix.len()..].to_string();
        let Some(old) = indexed(repo, &commit) else { continue };
        remove(old);
        kv::remove(&key);
        if let Some(job) = resolve(&commit) {
            insert(&Outgoing::SubmitJob {
                repo: repo.to_string(),
                commit,
                job,
            });
        }
    }
}

/// Put an item in the outbox, then deliver what waits.
pub async fn send(item: Outgoing) {
    insert(&item);
    drain().await;
}

/// Deliver what waits, oldest first, until the authority fails to answer
/// one; then try again later (`RETRY_SECS`). An item that no longer
/// decodes is dropped: it would never be answered, and would block every
/// item behind it.
pub async fn drain() {
    if DRAINING.with(|f| f.replace(true)) {
        return;
    }
    let _draining = Draining;
    while let Some((seq, bytes)) = first() {
        let Ok(item) = candid::decode_one::<Outgoing>(&bytes) else {
            remove(seq);
            continue;
        };
        let (reply, index) = match item {
            Outgoing::SubmitJob { repo, commit, job } => {
                let key = job_key(&repo, &commit);
                (crate::to_authority::submit_job(seq, &repo, &commit, job).await, Some(key))
            }
            Outgoing::Notify { event } => (crate::to_authority::notify(seq, event).await.map(Ok), None),
        };
        match reply {
            // Answered: taken, or refused for good. Either way it is done.
            Ok(_) => {
                remove(seq);
                // The index names this item unless a rebuild replaced it
                // while the authority answered.
                if let Some(key) = index {
                    if kv::get_json::<u64>(&key) == Some(seq) {
                        kv::remove(&key);
                    }
                }
            }
            Err(_) => {
                arm_retry(std::time::Duration::from_secs(RETRY_SECS));
                break;
            }
        }
    }
}

/// For post_upgrade: timers do not survive an upgrade, so what the outbox
/// still holds is delivered again as soon as the canister is idle.
pub fn resume() {
    if len() > 0 {
        arm_retry(std::time::Duration::ZERO);
    }
}

#[cfg(not(any(test, feature = "testing")))]
fn arm_retry(delay: std::time::Duration) {
    if RETRY_ARMED.with(|a| a.replace(true)) {
        return;
    }
    ic_cdk_timers::set_timer(delay, async {
        RETRY_ARMED.with(|a| a.set(false));
        drain().await;
    });
}

/// Tests drain the outbox themselves; a timer cannot fire outside a
/// canister.
#[cfg(any(test, feature = "testing"))]
fn arm_retry(_delay: std::time::Duration) {
    RETRY_ARMED.with(|a| a.set(true));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_authority::set_test_side;
    use futures::executor::block_on;
    use ic_git_types::authority_side::AuthoritySide;
    use ic_git_types::side::{ready, Failure, Fut, Reply};
    use std::rc::Rc;

    /// An authority that records what it is told, and fails every call
    /// while `fail` is set.
    #[derive(Default)]
    struct Recorder {
        taken: RefCell<Vec<(u64, String)>>,
        fail: Cell<Option<Failure>>,
        /// Refuse the next job for good.
        refuse: Cell<bool>,
    }

    impl AuthoritySide for Recorder {
        fn charge_push<'a>(&'a self, _repo: &'a str, _bytes: u64) -> Fut<'a, Reply<Result<(), String>>> {
            ready(Ok(Ok(())))
        }

        fn submit_job<'a>(&'a self, seq: u64, repo: &'a str, commit_hex: &'a str, _job: Job) -> Fut<'a, Reply<Result<(), String>>> {
            if let Some(f) = self.fail.take() {
                self.fail.set(Some(f.clone()));
                return ready(Err(f));
            }
            if self.refuse.replace(false) {
                return ready(Ok(Err("too large".into())));
            }
            self.taken.borrow_mut().push((seq, format!("job {repo}@{commit_hex}")));
            ready(Ok(Ok(())))
        }

        fn notify<'a>(&'a self, seq: u64, event: Event) -> Fut<'a, Reply<()>> {
            if let Some(f) = self.fail.take() {
                self.fail.set(Some(f.clone()));
                return ready(Err(f));
            }
            let Event::Pushed { repo, tip, .. } = event;
            self.taken.borrow_mut().push((seq, format!("pushed {repo}@{tip}")));
            ready(Ok(()))
        }
    }

    fn pushed(repo: &str, tip: &str) -> Outgoing {
        Outgoing::Notify {
            event: Event::Pushed {
                repo: repo.into(),
                branch: "refs/heads/main".into(),
                tip_before: None,
                tip: tip.into(),
            },
        }
    }

    /// What the authority does not answer stays in the outbox, in order,
    /// behind nothing and ahead of what came later; a later drain delivers
    /// it all in sequence, and nothing is delivered twice.
    #[test]
    fn the_outbox_keeps_what_the_authority_did_not_answer() {
        let authority = Rc::new(Recorder::default());
        set_test_side(Some(authority.clone()));

        block_on(send(pushed("r", "c1")));
        assert_eq!(len(), 0, "answered at once");

        authority.fail.set(Some(Failure::NotDelivered("stopped".into())));
        block_on(send(pushed("r", "c2")));
        block_on(send(Outgoing::SubmitJob {
            repo: "r".into(),
            commit: "c3".into(),
            job: Job { wasm: None, evm: None },
        }));
        assert_eq!(len(), 2);
        assert!(job_waiting("r", "c3"));
        assert!(!job_waiting("r", "c2"));

        // The answer lost rather than the call refused: the item waits too.
        authority.fail.set(Some(Failure::Lost("timeout".into())));
        block_on(drain());
        assert_eq!(len(), 2);

        // The repo's configs change: the waiting job is built again, under
        // a fresh number, and is still the one job for its commit.
        let rebuilt = Cell::new(0);
        rebuild_jobs("r", |commit| {
            rebuilt.set(rebuilt.get() + 1);
            assert_eq!(commit, "c3");
            Some(Job { wasm: None, evm: None })
        });
        assert_eq!(rebuilt.get(), 1);
        assert_eq!(len(), 2);
        assert!(job_waiting("r", "c3"));

        authority.fail.set(None);
        block_on(drain());
        assert_eq!(len(), 0);
        assert!(!job_waiting("r", "c3"));
        let taken = authority.taken.borrow().clone();
        assert_eq!(
            taken,
            vec![(1, "pushed r@c1".into()), (2, "pushed r@c2".into()), (4, "job r@c3".into())],
            "in sequence, each once"
        );

        // A job refused for good is dropped, and what follows it is
        // delivered.
        authority.refuse.set(true);
        block_on(send(Outgoing::SubmitJob {
            repo: "r".into(),
            commit: "c4".into(),
            job: Job { wasm: None, evm: None },
        }));
        block_on(send(pushed("r", "c5")));
        assert_eq!(len(), 0);
        assert!(!job_waiting("r", "c4"));
        assert_eq!(authority.taken.borrow().last().unwrap().1, "pushed r@c5");
        set_test_side(None);
    }
}
