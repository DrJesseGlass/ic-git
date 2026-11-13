//! Everything the authority asks of the git side (docs/CANISTER_SPLIT.md,
//! section 4), through one interface (ic_git_types::git_side::GitSide).
//! This crate does not depend on the git side: the canister installs its
//! implementation at init and upgrade, and phase 3 installs one that sends
//! messages instead. The free functions here are what the rest of the
//! authority calls; each is awaited and answers a `Reply` (phase 3, step
//! 8). The mirror writes are made only by mirrors.rs, which numbers them.

use ic_git_types::git_side::{Attested, DeployConfigs, GitSide, RecordKind, Release, Retry};
pub use ic_git_types::git_side::PushPolicy;
use ic_git_types::oid::Oid;
use ic_git_types::side::Reply;
use std::sync::OnceLock;

static GIT: OnceLock<&'static (dyn GitSide + Sync)> = OnceLock::new();

/// Install the git side. The first installation stands: a canister has one
/// git side for its lifetime.
pub fn install(git: &'static (dyn GitSide + Sync)) {
    let _ = GIT.set(git);
}

/// Tests, here and in the crates that test against this one, run against
/// the real git side without installing it. Its operator rule is this
/// crate's, as the canister's is.
#[cfg(any(test, feature = "testing"))]
static REAL_GIT: ic_git_git::for_authority::Git = ic_git_git::for_authority::Git {
    is_operator: crate::tenancy::is_operator,
};

fn git() -> &'static dyn GitSide {
    if let Some(g) = GIT.get() {
        return *g;
    }
    #[cfg(any(test, feature = "testing"))]
    {
        &REAL_GIT
    }
    #[cfg(not(any(test, feature = "testing")))]
    {
        panic!("the git side is not installed (the canister installs it at init and post_upgrade)")
    }
}

// Tests stand a git side of their own in for the installed one, on this
// thread: one that fails, or loses its answer, on a chosen call, so each
// flow's failure rule can be tested.
#[cfg(any(test, feature = "testing"))]
thread_local! {
    static TEST_SIDE: std::cell::RefCell<Option<std::rc::Rc<dyn GitSide>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "testing"))]
pub fn set_test_side(side: Option<std::rc::Rc<dyn GitSide>>) {
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
        git().$call($($arg),*).await
    }};
}

/// The deploy-config mirror (configs.rs owns the configs).
pub async fn set_deploy_configs(repo: &str, seq: u64, configs: DeployConfigs) -> Reply<()> {
    via!(set_deploy_configs(repo, seq, configs))
}

/// The push-policy mirror. The git side spares operators' tokens by its
/// own rule when the writers change.
pub async fn set_push_policy(repo: &str, seq: u64, policy: PushPolicy) -> Reply<()> {
    via!(set_push_policy(repo, seq, policy))
}

/// The approved-commits mirror. The git side follows the approvals once it
/// has taken the write, and on a `retry` (a ballot's) submits the served
/// commit's job even when nothing moved, unless the retry says the app
/// runs it.
pub async fn set_approved(repo: &str, seq: u64, approved: Option<Vec<String>>, retry: Option<Retry>) -> Reply<()> {
    via!(set_approved(repo, seq, approved, retry))
}

/// The site config: the repo is served from `root`. The caller has checked
/// the right to set it; the git side keeps it.
pub async fn set_site(repo: &str, root: String) -> Reply<Result<(), String>> {
    via!(set_site(repo, root))
}

/// Would a repo of this name be created? The authority asks before it
/// charges the creation fee.
pub async fn check_new_repo(name: &str) -> Reply<Result<String, String>> {
    via!(check_new_repo(name))
}

/// Create the repo, once the authority has reserved the name. Idempotent on
/// the git side, so a lost answer is settled by asking again.
pub async fn create_repo(name: &str) -> Reply<Result<(), String>> {
    via!(create_repo(name))
}

/// Does the git side hold this commit?
pub async fn has_commit(oid: &Oid) -> Reply<bool> {
    via!(has_commit(oid))
}

/// The artifact behind a registry record, with its proof (provenance.rs
/// checks it).
pub async fn record_artifact(repo: &str, kind: RecordKind) -> Reply<Result<Attested, String>> {
    via!(record_artifact(repo, kind))
}

/// The release commit's job, for deploy_now (the queue checks it).
pub async fn release_job(repo: &str) -> Reply<Result<Release, String>> {
    via!(release_job(repo))
}

/// A git side that fails as told, for the tests of each flow's failure
/// rule: the real one, with the next calls it is told to refuse, not
/// deliver, or run and lose the answer of.
#[cfg(test)]
pub(crate) mod flaky {
    use super::*;
    use ic_git_types::side::{ready, Failure, Fut};
    use std::cell::RefCell;

    /// What the next call of a name does.
    #[derive(Clone, Copy, Debug)]
    pub enum Inject {
        /// The git side answers with a refusal (only `Result`-answering
        /// calls).
        Refuse,
        /// The call never runs.
        NotDelivered,
        /// The call runs, and its answer is lost.
        Lost,
    }

    pub struct Flaky {
        real: ic_git_git::for_authority::Git,
        queue: RefCell<Vec<(&'static str, Inject)>>,
        pub calls: RefCell<Vec<&'static str>>,
        /// The `retry` of each `set_approved`, in order.
        pub retries: RefCell<Vec<Option<Retry>>>,
    }

    impl Flaky {
        pub fn new() -> Self {
            Flaky {
                real: ic_git_git::for_authority::Git {
                    is_operator: crate::tenancy::is_operator,
                },
                queue: RefCell::new(Vec::new()),
                calls: RefCell::new(Vec::new()),
                retries: RefCell::new(Vec::new()),
            }
        }

        /// The next call named `call` does `what`.
        pub fn inject(&self, call: &'static str, what: Inject) {
            self.queue.borrow_mut().push((call, what));
        }

        pub fn count(&self, call: &str) -> usize {
            self.calls.borrow().iter().filter(|c| **c == call).count()
        }

        /// Run `real` under what was injected for `call`, if anything.
        fn go<'a, T: 'a>(&'a self, call: &'static str, real: impl FnOnce() -> Fut<'a, Reply<T>> + 'a, refusal: Option<T>) -> Fut<'a, Reply<T>> {
            self.calls.borrow_mut().push(call);
            let next = {
                let mut q = self.queue.borrow_mut();
                q.iter().position(|(c, _)| *c == call).map(|i| q.remove(i).1)
            };
            match next {
                None => real(),
                Some(Inject::Refuse) => ready(Ok(refusal.expect("a call that can refuse"))),
                Some(Inject::NotDelivered) => ready(Err(Failure::NotDelivered("the git side is stopped".into()))),
                Some(Inject::Lost) => Box::pin(async move {
                    let _ = real().await;
                    Err(Failure::Lost("the answer timed out".into()))
                }),
            }
        }
    }

    impl GitSide for Flaky {
        fn set_deploy_configs<'a>(&'a self, repo: &'a str, seq: u64, configs: DeployConfigs) -> Fut<'a, Reply<()>> {
            self.go("set_deploy_configs", move || self.real.set_deploy_configs(repo, seq, configs), None)
        }

        fn set_push_policy<'a>(&'a self, repo: &'a str, seq: u64, policy: PushPolicy) -> Fut<'a, Reply<()>> {
            self.go("set_push_policy", move || self.real.set_push_policy(repo, seq, policy), None)
        }

        fn set_approved<'a>(&'a self, repo: &'a str, seq: u64, approved: Option<Vec<String>>, retry: Option<Retry>) -> Fut<'a, Reply<()>> {
            self.retries.borrow_mut().push(retry.clone());
            self.go("set_approved", move || self.real.set_approved(repo, seq, approved, retry), None)
        }

        fn set_site<'a>(&'a self, repo: &'a str, root: String) -> Fut<'a, Reply<Result<(), String>>> {
            self.go("set_site", move || self.real.set_site(repo, root), Some(Err("refused by the git side".into())))
        }

        fn check_new_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<String, String>>> {
            self.go("check_new_repo", move || self.real.check_new_repo(name), Some(Err("refused by the git side".into())))
        }

        fn create_repo<'a>(&'a self, name: &'a str) -> Fut<'a, Reply<Result<(), String>>> {
            self.go("create_repo", move || self.real.create_repo(name), Some(Err("refused by the git side".into())))
        }

        fn has_commit<'a>(&'a self, oid: &'a Oid) -> Fut<'a, Reply<bool>> {
            self.go("has_commit", move || self.real.has_commit(oid), None)
        }

        fn record_artifact<'a>(&'a self, repo: &'a str, kind: RecordKind) -> Fut<'a, Reply<Result<Attested, String>>> {
            self.go("record_artifact", move || self.real.record_artifact(repo, kind), Some(Err("refused by the git side".into())))
        }

        fn release_job<'a>(&'a self, repo: &'a str) -> Fut<'a, Reply<Result<Release, String>>> {
            self.go("release_job", move || self.real.release_job(repo), Some(Err("refused by the git side".into())))
        }
    }
}
