//! The META map: small canister-level state under string keys -- configs,
//! logs, caches, the auth snapshot, the object store's schema marker.
//!
//! Its own module, not `store.rs`, so the object store is objects, refs and
//! repos and this bucket has one name (docs/CANISTER_SPLIT.md, phase 2 step
//! 4). Each caller owns its keys, including a namespace prefix, which keeps
//! them out of one another's way. When the authority becomes its own
//! canister (phase 3) the signing modules' state goes with it through this
//! same interface, and no signing logic is touched -- which matters because
//! that logic is what K reviewers attest, and a diff there costs a
//! re-review.
//!
//! Deliberately not generic over a backend trait: indirection bought before
//! it is needed.

use ic_dev_kit_rs::storage;
use ic_stable_structures::{StableBTreeMap, Storable};
use std::cell::RefCell;
use std::ops::Bound;

thread_local! {
    static META: RefCell<StableBTreeMap<String, Vec<u8>, crate::memory::Memory>> =
        RefCell::new(StableBTreeMap::init(crate::memory::get(crate::memory::MEM_META)));
}

/// Read a JSON-encoded value. `None` if absent **or undecodable** -- the two
/// are indistinguishable here. That is safe for a config with a sensible
/// default and unsafe for anything a caller reads, extends, and writes back:
/// use [`try_get_json`] there.
pub fn get_json<T: serde::de::DeserializeOwned>(key: &str) -> Option<T> {
    get_bytes(key).and_then(|b| serde_json::from_slice(&b).ok())
}

/// Read a JSON-encoded value, distinguishing absent (`Ok(None)`) from present
/// but undecodable (`Err`). Required wherever substituting a default would
/// destroy stored data -- see `evm::record`, where a decode failure would
/// otherwise overwrite the entire append-only deploy log with one entry.
pub fn try_get_json<T: serde::de::DeserializeOwned>(key: &str) -> Result<Option<T>, String> {
    match get_bytes(key) {
        None => Ok(None),
        Some(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("stored value at {key} did not decode: {e}")),
    }
}

/// Write a JSON-encoded value. Silently drops values that fail to encode.
pub fn set_json<T: serde::Serialize>(key: &str, value: &T) {
    if let Ok(bytes) = serde_json::to_vec(value) {
        set_bytes(key, bytes);
    }
}

/// Raw bytes under `key`, for the few values that are not JSON (the auth
/// snapshot, the schema marker).
pub fn get_bytes(key: &str) -> Option<Vec<u8>> {
    META.with(|m| storage::load_bytes(m, key))
}

pub fn set_bytes(key: &str, bytes: Vec<u8>) {
    META.with(|m| storage::save_bytes(m, key, bytes));
}

/// Drop `key`, if it is there.
pub fn remove(key: &str) {
    META.with(|m| m.borrow_mut().remove(&key.to_string()));
}

/// Every key that starts with `prefix`, in key order.
pub fn keys_with_prefix(prefix: &str) -> Vec<String> {
    META.with(|m| {
        m.borrow()
            .range(prefix.to_string()..)
            .map(|e| e.key().clone())
            .take_while(|k| k.starts_with(prefix))
            .collect()
    })
}

/// One page of a map, for a walk that visits every entry across several
/// messages (the git side's export, docs/CANISTER_SPLIT.md step 13): the
/// entries from `start`, in key order, while `keep` holds of the key, as
/// many as fit in `budget` bytes of keys and values (by `size`). At least
/// one entry when any remains, so a caller always advances, and never a
/// second that would take the page over the budget, so a page is at most
/// the budget or one entry, whichever is larger; the last key is where
/// the next page starts, excluded.
pub fn page<K, V, M>(
    map: &StableBTreeMap<K, V, M>,
    start: Bound<K>,
    budget: usize,
    keep: impl Fn(&K) -> bool,
    size: impl Fn(&K, &V) -> usize,
) -> Vec<(K, V)>
where
    K: Storable + Ord + Clone,
    V: Storable,
    M: ic_stable_structures::Memory,
{
    let mut out = Vec::new();
    let mut used = 0;
    for e in map.range((start, Bound::Unbounded)) {
        let (k, v) = (e.key().clone(), e.value());
        if !keep(&k) {
            break;
        }
        let n = size(&k, &v);
        if !out.is_empty() && used + n > budget {
            break;
        }
        used += n;
        out.push((k, v));
        if used >= budget {
            break;
        }
    }
    out
}

/// A page (`page`) of the META entries whose key starts with `prefix`,
/// after the key `after` when one is given: the git side's labels and
/// site configs on their way to the git canister.
pub fn export_prefix(prefix: &str, after: Option<&str>, budget: usize) -> Vec<(String, Vec<u8>)> {
    let start = match after {
        Some(a) => Bound::Excluded(a.to_string()),
        None => Bound::Included(prefix.to_string()),
    };
    META.with(|m| page(&m.borrow(), start, budget, |k| k.starts_with(prefix), |k, v| k.len() + v.len()))
}

const AUTH_KEY: &str = "auth";

pub fn save_auth_snapshot(bytes: Vec<u8>) {
    set_bytes(AUTH_KEY, bytes);
}

pub fn load_auth_snapshot() -> Option<Vec<u8>> {
    get_bytes(AUTH_KEY)
}
