//! Everything the git side tells the authority (docs/CANISTER_SPLIT.md,
//! section 4), through one interface
//! (ic_git_types::authority_side::AuthoritySide). This crate does not
//! depend on the authority: the canister installs its implementation at
//! init and upgrade, and phase 3 installs one that sends messages instead.
//! The free functions here are what the rest of this crate calls; the
//! outbox (outbox.rs) is the one caller of `submit_job` and `notify`.

use ic_git_types::authority_side::{AuthoritySide, Event, Published};
use ic_git_types::deploy::Job;
use ic_git_types::side::Reply;
use std::sync::OnceLock;

static AUTHORITY: OnceLock<&'static (dyn AuthoritySide + Sync)> = OnceLock::new();

/// Install the authority. The first installation stands: a canister has
/// one authority for its lifetime.
pub fn install(authority: &'static (dyn AuthoritySide + Sync)) {
    let _ = AUTHORITY.set(authority);
}

fn authority() -> &'static dyn AuthoritySide {
    match AUTHORITY.get() {
        Some(a) => *a,
        None => panic!("the authority is not installed (the canister installs it at init and post_upgrade)"),
    }
}

// Tests stand an authority of their own in for the installed one, on this
// thread: one that records what it is told, or fails on a chosen call, so
// each flow's failure rule can be tested.
#[cfg(any(test, feature = "testing"))]
thread_local! {
    static TEST_SIDE: std::cell::RefCell<Option<std::rc::Rc<dyn AuthoritySide>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "testing"))]
pub fn set_test_side(side: Option<std::rc::Rc<dyn AuthoritySide>>) {
    TEST_SIDE.with(|s| *s.borrow_mut() = side);
}

/// The side a call goes to: the test one when a test set it, else the
/// installed one.
macro_rules! via {
    ($call:ident ( $($arg:expr),* )) => {{
        #[cfg(any(test, feature = "testing"))]
        if let Some(side) = TEST_SIDE.with(|s| s.borrow().clone()) {
            return side.$call($($arg),*).await;
        }
        authority().$call($($arg),*).await
    }};
}

/// Charge the repo's owner for a push of `bytes`. The callee's `Err`
/// refuses the push.
pub async fn charge_push(repo: &str, bytes: u64) -> Reply<Result<(), String>> {
    via!(charge_push(repo, bytes))
}

/// Hand the authority a commit's deploy job (outbox item `seq`). Its
/// `Err` is a job it will never take, which it has recorded.
pub async fn submit_job(seq: u64, repo: &str, commit_hex: &str, job: Job) -> Reply<Result<(), String>> {
    via!(submit_job(seq, repo, commit_hex, job))
}

/// Tell the authority what happened (outbox item `seq`).
pub async fn notify(seq: u64, event: Event) -> Reply<()> {
    via!(notify(seq, event))
}

/// Ask the authority to publish this canister's record, from what its
/// controller stated (the canister's `registry_publish_canister`). Waited
/// for: the governor keeps the answer in its log.
pub async fn publish_git_record(commit_hex: &str, module_sha256_hex: &str) -> Reply<Result<Published, String>> {
    via!(publish_git_record(commit_hex, module_sha256_hex))
}
