//! ic-git's git side (docs/CANISTER_SPLIT.md, phase 2 step 4): objects,
//! refs and repos, the smart-HTTP protocol, push tokens and signed pushes,
//! site serving, the deploy configs, and the proofs a deploy job carries.
//!
//! It depends on neither the authority nor the canister. What the authority
//! decides about a repo -- who may push, which commits are approved -- it
//! reads from its mirrors (mirror.rs), which the authority writes; what it
//! tells the authority goes through `to_authority` and, when no answer is
//! waited for, the outbox. That is the boundary phase 3 turns into
//! messages.

pub mod api;
pub mod attest;
pub mod consent;
pub mod for_authority;
pub mod gitproof;
pub mod jobs;
pub mod mirror;
pub mod object;
pub mod outbox;
pub mod pack;
pub mod peer;
pub mod receive;
pub mod signed_push;
pub mod site;
pub mod smart_http;
pub mod store;
pub mod to_authority;
pub mod tokens;
pub mod transfer;

// The shared crate, at the paths every module already names (crate::kv, ...).
use ic_git_common::httpjson::git_response;
use ic_git_common::{clock, httpjson, kv, memory};
