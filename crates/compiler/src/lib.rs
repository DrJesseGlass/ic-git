//! The compiler (docs/CANISTER_SPLIT.md, section 3): builds `.wat` and
//! `.lang` sources for repos that are not governed. A governed repo deploys
//! committed `.wasm` only, so nothing built here reaches a governed backend.
//! Compilation is a pure function of its input: no canister state, no keys.
//! Linked into the ic-git canister until phase 3 cuts it out.

pub mod compile;
pub mod interp;
pub mod lang;
