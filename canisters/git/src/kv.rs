//! The narrow persistence seam for the signing modules.
//!
//! `evm.rs` and `sol.rs` keep a little state of their own -- chain config, the
//! derived-pubkey cache, the registry address, the deploy provenance log. None
//! of it is git data; it just happens to live in the same stable-memory META
//! map today because there has only ever been one canister.
//!
//! Be honest about what this is today: a rename. These functions forward
//! verbatim to `store::meta_*_json`, so `evm.rs` and `sol.rs` still reach the
//! git crate's storage transitively -- the decoupling is a marked seam, not a
//! severed dependency. Its value is that the swap point exists in one place:
//! when the signer becomes its own canister (docs/CANISTER_SPLIT.md phase 3)
//! these two bodies change and no signing logic is touched, which matters
//! because that logic is what K reviewers attest and a diff there costs a
//! re-review. Phase 2 should move the META map itself here and point
//! `deploy`/`site`/`fleet` at it too, so one bucket stops having two names.
//!
//! Deliberately not generic over a backend trait: indirection bought before
//! it is needed.

use crate::store;

/// Read a JSON-encoded value. `None` if absent or undecodable.
pub fn get_json<T: serde::de::DeserializeOwned>(key: &str) -> Option<T> {
    store::meta_get_json(key)
}

/// Write a JSON-encoded value. Silently drops values that fail to encode,
/// matching `store::meta_set_json`'s existing contract.
pub fn set_json<T: serde::Serialize>(key: &str, value: &T) {
    store::meta_set_json(key, value)
}
