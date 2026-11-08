//! What both sides of ic-git's canister boundary agree on
//! (docs/CANISTER_SPLIT.md, section 4): the proof format and its checker,
//! the wire structs, and the registry record keys. Pure: no canister state,
//! no calls, nothing that reads the object store.

pub mod deploy;
pub mod keys;
pub mod labels;
pub mod oid;
pub mod proof;
