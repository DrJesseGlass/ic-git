//! Git object ids as both sides store and name them.

use ic_stable_structures::storable::Blob;

/// 20-byte SHA-1 object id.
pub type Oid = Blob<20>;

pub fn parse_oid(hex: &str) -> Result<Oid, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("bad oid: {e}"))?;
    // Length must be checked here, not left to Blob: `Blob<N>` is a MAXIMUM,
    // so `try_from` accepts anything 20 bytes or shorter and this function's
    // own error message would be a lie. A short Oid reaching the store (via
    // set_ref, say) would then violate the 20-byte invariant that
    // commit20 below and the registry's bytes20 both depend on.
    if bytes.len() != 20 {
        return Err("oid must be 20 bytes".to_string());
    }
    Oid::try_from(bytes.as_slice()).map_err(|_| "oid must be 20 bytes".to_string())
}

pub fn oid_hex(oid: &Oid) -> String {
    hex::encode(oid.as_slice())
}

/// The 20 bytes of an oid, which is what proofs and the registry name a
/// commit by. Fallible because `Blob<20>` is a maximum length, not an exact
/// one.
pub fn commit20(oid: &Oid) -> Result<[u8; 20], String> {
    oid.as_slice().try_into().map_err(|_| "bad oid length".to_string())
}
