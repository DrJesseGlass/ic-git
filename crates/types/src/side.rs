//! What every call across the boundary has in common (docs/CANISTER_SPLIT.md,
//! phase 3 step 8): it is awaited, and it can fail without an answer.
//!
//! While the two sides share a canister, each call is a plain function
//! behind a future that is ready at once, and never fails this way. Across
//! the cut it is a message, and a message can be refused by the system
//! before it runs (`Failure::NotDelivered`: nothing happened), or run and
//! lose its answer on the way back (`Failure::Lost`: it may have happened).
//! The callee's own answer, a refusal included, is the `Ok` of a `Reply`.

use std::future::Future;
use std::pin::Pin;

/// A call that did not come back with the callee's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The call never ran: the other side was stopped, out of cycles, or the
    /// system refused the message. Nothing happened there.
    NotDelivered(String),
    /// The call may have run; its answer is gone. The caller must not assume
    /// either way.
    Lost(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::NotDelivered(e) => write!(f, "not delivered: {e}"),
            Failure::Lost(e) => write!(f, "answer lost: {e}"),
        }
    }
}

/// The callee's answer, or why there is none.
pub type Reply<T> = Result<T, Failure>;

/// A call in flight. Boxed so the interfaces stay trait objects, which is
/// what lets the canister install one implementation and the tests another.
pub type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// A future that is already done: how the in-canister implementations
/// answer.
pub fn ready<'a, T: 'a>(value: T) -> Fut<'a, T> {
    Box::pin(std::future::ready(value))
}
