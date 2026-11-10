//! What both sides of ic-git share while they are one canister
//! (docs/CANISTER_SPLIT.md, phase 2 step 4). None of it belongs to either
//! side: the stable-memory layout and the META map both sides key into, the
//! clock, and the JSON helpers both halves of /api answer with. Phase 3
//! gives each canister its own copy.

pub mod clock;
pub mod httpjson;
pub mod kv;
pub mod memory;
