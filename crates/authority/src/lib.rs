//! ic-git's authority (docs/CANISTER_SPLIT.md, phase 2 step 4): tenancy,
//! ballots and governance, accounts and payments, names, the EVM and
//! Solana signers, the deploy queue and provenance publishing.
//!
//! It reaches the git side only through `to_git` (the GitSide interface),
//! so it cannot depend on git state any other way: production builds of
//! this crate do not link the git side at all. What the git side tells it
//! arrives through `for_git` (the AuthoritySide interface).

pub mod api_authority;
pub mod apps;
pub mod configs;
pub mod consent;
pub mod deploy;
pub mod evm;
// The testing feature swaps the governor poll for a stub, which leaves the
// real poll's types unused in those builds only.
#[cfg_attr(all(feature = "testing", not(test)), allow(dead_code))]
pub mod feed;
pub mod fleet;
pub mod for_git;
pub mod icp;
pub mod ledger;
pub mod mirrors;
pub mod names;
pub mod peer;
pub mod provenance;
pub mod records;
pub mod rpc_common;
pub mod sol;
pub mod tenancy;
pub mod to_git;

// The shared crates, at the paths every module already names (crate::kv, ...).
use ic_git_common::httpjson::git_response;
use ic_git_common::{clock, httpjson, kv, memory};
use ic_git_compiler::{compile, lang};

// The git side, for this crate's tests only.
#[cfg(test)]
use ic_git_git::{gitproof, jobs, mirror, store};
