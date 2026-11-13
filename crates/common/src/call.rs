//! The other canister as a transport (docs/CANISTER_SPLIT.md, phase 3
//! step 12b): each message is one bounded-wait call to the principal `id`
//! names at the time, with the message as the raw argument. Both sides
//! send the same way; what differs is which canister, so that is a
//! function, read on every call: the authority learns the git canister's
//! id from an operator, the git canister the authority's at init, and
//! until then every call is refused here as not delivered.
//!
//! How a call fails maps onto `Failure`: a bounded-wait call the system
//! gave up waiting on (`SysUnknown`) may have run, so its answer is lost;
//! anything else -- the id unset, the call not performed, the other
//! canister stopped, out of cycles, or trapped (its changes rolled back)
//! -- means nothing happened there.

use candid::Principal;
use ic_cdk::call::{Call, CallFailed, RejectCode};
use ic_git_types::side::{Failure, Fut, Reply};
use ic_git_types::wire::Transport;

pub struct Canister {
    pub id: fn() -> Option<Principal>,
}

impl Transport for Canister {
    fn call<'a>(&'a self, method: &'static str, arg: Vec<u8>) -> Fut<'a, Reply<Vec<u8>>> {
        Box::pin(async move {
            let Some(id) = (self.id)() else {
                return Err(Failure::NotDelivered(format!("{method}: the other canister's id is not set")));
            };
            match Call::bounded_wait(id, method).with_raw_args(&arg).await {
                Ok(reply) => Ok(reply.into_bytes()),
                Err(CallFailed::CallRejected(e)) if e.reject_code() == Ok(RejectCode::SysUnknown) => {
                    Err(Failure::Lost(format!("{method}: {e}")))
                }
                Err(e) => Err(Failure::NotDelivered(format!("{method}: {e}"))),
            }
        })
    }
}
