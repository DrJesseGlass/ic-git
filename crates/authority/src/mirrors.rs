//! The authority's side of the git side's mirrors (docs/CANISTER_SPLIT.md,
//! phase 3 step 8): which of a repo's mirrors have changed and not yet been
//! taken by the git side, and the writes that bring them up to date.
//!
//! Whatever changes what a mirror reflects `mark`s it: a repo's metadata
//! (tenancy.rs), a ballot, a deploy config (configs.rs). The flow that made
//! the change then awaits `flush`, which sends each marked mirror's whole
//! current state under a fresh sequence number, one counter per repo, and
//! clears the mark once the git side has answered. A write the git side
//! does not answer leaves its mark, and a timer tries again. The marks are
//! in stable memory, so an upgrade loses none: `resume` picks them up.
//!
//! Full state and a fresh number on every send is what makes a retry safe:
//! a retry carries what the mirror should hold now, and the git side
//! ignores a write older than the newest it holds.
//!
//! The approved set's write carries one more thing (phase 3, step 9): a
//! ballot asks the git side, which follows the approvals once it has the
//! write, to submit the served commit's job even when nothing moved
//! (`mark_ballot`). The ask stays with the mark until the git side has
//! taken a write that carried it.

use ic_git_types::git_side::Retry;
use ic_git_types::side::Reply;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::future::Future;

thread_local! {
    /// True while a retry timer is armed, so an outage arms one, not one
    /// per unanswered write (each retry would otherwise arm more). Heap
    /// state: an upgrade clears it, and `resume` arms again.
    static RETRY_ARMED: Cell<bool> = const { Cell::new(false) };
}

/// The git side's mirrors of this side's decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mirror {
    /// Who may push, and whether pushes must be signed (tenancy).
    PushPolicy,
    /// The commits that reach the vote threshold (tenancy's ballots).
    Approved,
    /// The deploy configs (configs.rs).
    DeployConfigs,
}

const ALL: [Mirror; 3] = [Mirror::PushPolicy, Mirror::Approved, Mirror::DeployConfigs];

/// How long after an unanswered write the marks are flushed again.
pub const RETRY_SECS: u64 = 30;

fn seq_key(repo: &str) -> String {
    format!("mirrors:seq:{repo}")
}

fn pending_key(repo: &str) -> String {
    format!("mirrors:pending:{repo}")
}

const PENDING_PREFIX: &str = "mirrors:pending:";

/// A repo's marks: for each mirror, the sequence number current when it was
/// last marked, so a flush can tell whether the state it sent was the
/// newest.
#[derive(Serialize, Deserialize, Default, Clone, PartialEq)]
struct Pending {
    push: Option<u64>,
    approved: Option<u64>,
    deploy: Option<u64>,
    /// A ballot since the git side last took the approved set: its write
    /// asks for the served commit's deploy to be retried.
    #[serde(default)]
    retry: bool,
}

impl Pending {
    fn slot(&mut self, m: Mirror) -> &mut Option<u64> {
        match m {
            Mirror::PushPolicy => &mut self.push,
            Mirror::Approved => &mut self.approved,
            Mirror::DeployConfigs => &mut self.deploy,
        }
    }

    fn marked(&self, m: Mirror) -> Option<u64> {
        match m {
            Mirror::PushPolicy => self.push,
            Mirror::Approved => self.approved,
            Mirror::DeployConfigs => self.deploy,
        }
    }

    /// The git side took the mirror's write: clear its mark, and with the
    /// approved set's the retry ask that rode on it.
    fn clear(&mut self, m: Mirror) {
        *self.slot(m) = None;
        if m == Mirror::Approved {
            self.retry = false;
        }
    }

    /// No mark: nothing to flush. A retry ask has no write to ride on
    /// without the approved set's mark, so it does not count.
    fn is_empty(&self) -> bool {
        ALL.iter().all(|m| self.marked(*m).is_none())
    }
}

fn load(repo: &str) -> Pending {
    crate::kv::get_json(&pending_key(repo)).unwrap_or_default()
}

fn save(repo: &str, p: &Pending) {
    if p.is_empty() {
        crate::kv::remove(&pending_key(repo));
    } else {
        crate::kv::set_json(&pending_key(repo), p);
    }
}

fn next_seq(repo: &str) -> u64 {
    let n: u64 = crate::kv::get_json(&seq_key(repo)).unwrap_or(0) + 1;
    crate::kv::set_json(&seq_key(repo), &n);
    n
}

/// The sequence number the repo's last write carried.
fn last_seq(repo: &str) -> u64 {
    crate::kv::get_json(&seq_key(repo)).unwrap_or(0)
}

/// Record that a mirror no longer matches this side. The flow that changed
/// it awaits `flush` next; whatever it does, the mark stays until the git
/// side has taken the write.
pub fn mark(repo: &str, m: Mirror) {
    let mut p = load(repo);
    *p.slot(m) = Some(last_seq(repo));
    save(repo, &p);
}

/// A ballot: mark the approved set, and have its write ask the git side
/// to retry the served commit's deploy, so voters can get an app whose
/// deploy failed back in step with the site.
pub fn mark_ballot(repo: &str) {
    let mut p = load(repo);
    *p.slot(Mirror::Approved) = Some(last_seq(repo));
    p.retry = true;
    save(repo, &p);
}

/// Which of a repo's mirrors are marked.
pub fn pending(repo: &str) -> Vec<Mirror> {
    let p = load(repo);
    ALL.into_iter().filter(|m| p.marked(*m).is_some()).collect()
}

/// Every repo with a marked mirror.
pub fn repos_pending() -> Vec<String> {
    crate::kv::keys_with_prefix(PENDING_PREFIX)
        .into_iter()
        .map(|k| k[PENDING_PREFIX.len()..].to_string())
        .collect()
}

/// Send one mirror's current state. A repo this side has no record of has
/// nothing to send, and nothing to mark. A ballot's retry ask rides on the
/// approved set's write with what the app runs as far as this side's
/// deploys say (`deploy::running`); which commit is served only the git
/// side knows, so it decides whether there is anything to retry, and is
/// spared building a job the intake would drop when the app runs it.
async fn send(repo: &str, m: Mirror, seq: u64, retry: bool) -> Reply<()> {
    match m {
        Mirror::PushPolicy => match crate::tenancy::push_policy_of(repo) {
            Some(policy) => crate::to_git::set_push_policy(repo, seq, policy).await,
            None => Ok(()),
        },
        Mirror::Approved => match crate::tenancy::approved_of(repo) {
            Some(approved) => {
                let retry = retry.then(|| Retry {
                    running: crate::deploy::running(repo),
                });
                crate::to_git::set_approved(repo, seq, approved, retry).await
            }
            None => Ok(()),
        },
        Mirror::DeployConfigs => crate::to_git::set_deploy_configs(repo, seq, crate::configs::get(repo)).await,
    }
}

/// Write every marked mirror of the repo and clear the marks the git side
/// answered. A mark made while a write was in flight (by another call of
/// this canister) is newer than what was sent and stays, and so does a
/// ballot's retry ask. An unanswered write leaves its mark and arms the
/// retry.
pub async fn flush(repo: &str) {
    for m in ALL {
        let sent = load(repo);
        let Some(marked) = sent.marked(m) else { continue };
        let seq = next_seq(repo);
        match send(repo, m, seq, sent.retry).await {
            Ok(()) => {
                let mut p = load(repo);
                if p.marked(m) == Some(marked) {
                    p.clear(m);
                    save(repo, &p);
                }
            }
            Err(_) => arm_retry(std::time::Duration::from_secs(RETRY_SECS)),
        }
    }
}

/// Flush every repo with a marked mirror: the retry, and post_upgrade's
/// catch-up.
pub async fn flush_all() {
    for repo in repos_pending() {
        flush(&repo).await;
    }
}

/// For post_upgrade, after everything that marks: the marked mirrors are
/// written before the upgrade's first message, as they were when the
/// mirrors were filled in place, so no push finds them empty. In one
/// canister the writes complete at once; a git side that answers later
/// (step 12) is left to the timer, as timers do not survive an upgrade.
pub fn resume() {
    if repos_pending().is_empty() {
        return;
    }
    let mut flush = Box::pin(flush_all());
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    if flush.as_mut().poll(&mut cx).is_pending() {
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
        flush_all().await;
    });
}

/// Tests flush themselves; a timer cannot fire outside a canister.
#[cfg(any(test, feature = "testing"))]
fn arm_retry(_delay: std::time::Duration) {
    RETRY_ARMED.with(|a| a.set(true));
}
