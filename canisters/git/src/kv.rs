//! The narrow persistence seam for the signing modules.
//!
//! `evm.rs` and `sol.rs` keep a little state of their own -- chain config, the
//! derived-pubkey cache, the registry address, the deploy provenance log. None
//! of it is git data; it just happens to live in the same stable-memory META
//! map today because there has only ever been one canister.
//!
//! Routing those reads and writes through here rather than calling
//! `store::meta_*_json` directly means the signing half of this canister
//! depends on a two-function interface instead of on the git object store's
//! module. When the signer becomes its own canister (docs/CANISTER_SPLIT.md,
//! phase 3) the backing store changes in exactly one place, and no signing
//! logic is touched -- which matters because that logic is the part K
//! reviewers are attesting, and a diff there costs a re-review.
//!
//! Deliberately not generic over a backend trait: a trait would be indirection
//! bought before it is needed. Two functions and a honest comment are enough
//! to mark the boundary.

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
