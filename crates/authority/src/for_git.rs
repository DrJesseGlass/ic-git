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

use ic_git_types::authority_side::{AuthoritySide, Event};
use ic_git_types::deploy::Job;
use ic_git_types::oid::parse_oid;
use ic_git_types::side::{ready, Fut, Reply};

/// This crate, as the git side sees it.
pub struct Authority;

/// The newest outbox item taken.
const INBOX_KEY: &str = "inbox:last";

/// Take outbox item `seq`, unless it was taken before.
fn take(seq: u64) -> bool {
    let last: u64 = crate::kv::get_json(INBOX_KEY).unwrap_or(0);
    if seq <= last {
        return false;
    }
    crate::kv::set_json(INBOX_KEY, &seq);
    true
}

impl AuthoritySide for Authority {
    fn charge_push<'a>(&'a self, repo: &'a str, bytes: u64) -> Fut<'a, Reply<Result<(), String>>> {
        ready(Ok(crate::tenancy::charge_push(repo, bytes as usize)))
    }

    fn submit_job<'a>(&'a self, seq: u64, repo: &'a str, commit_hex: &'a str, job: Job) -> Fut<'a, Reply<()>> {
        if take(seq) {
            if let Ok(commit) = parse_oid(commit_hex) {
                crate::deploy::enqueue(repo, commit, move || job);
            }
        }
        ready(Ok(()))
    }

    fn notify<'a>(&'a self, seq: u64, event: Event) -> Fut<'a, Reply<()>> {
        if take(seq) {
            crate::feed::notify(event);
        }
        ready(Ok(()))
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
}
