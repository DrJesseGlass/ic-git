//! Publishing provenance records: the authority's half of the registry path
//! (docs/CANISTER_SPLIT.md, section 4). It builds records from values the
//! deploy queue or a controller already holds and hands them to
//! `evm::registry_publish_record`, which signs and broadcasts. The records
//! that must be resolved out of a repo -- the served site, the release
//! commit's artifact -- come from the git side (attest.rs).

use crate::evm::{self, TxOutcome};
pub use ic_git_types::keys::{Record, CANISTER_KEY};
use ic_git_types::keys::app_record_key;
use ic_git_types::oid::{commit20, Oid};

/// The single exit point to the signing side. The error says whether the
/// broadcast was attempted, which decides a refund.
pub async fn publish(rec: &Record) -> Result<TxOutcome, evm::SendError> {
    let out = evm::registry_publish_record(&rec.key, &rec.commit, &rec.bundle).await?;
    crate::feed::published(&rec.key, &hex::encode(rec.commit), &out.tx_hash);
    Ok(out)
}

/// The backend record for an install the deploy queue just made: the commit
/// and the installed module's sha256 as the queue computed it from the bytes
/// it sent (`DeployStatus::wasm_sha256`), never re-derived.
pub fn app_record(repo: &str, commit_oid: &Oid, wasm_sha256_hex: &str) -> Result<Record, String> {
    let bytes = hex::decode(wasm_sha256_hex).map_err(|e| format!("bad module hash: {e}"))?;
    let bundle: [u8; 32] = bytes.try_into().map_err(|_| "module hash is not 32 bytes".to_string())?;
    Ok(Record {
        key: app_record_key(repo),
        commit: commit20(commit_oid)?,
        bundle,
    })
}

/// This canister's own record, from the values its controller states: the
/// commit as 40 hex digits and the installed module's sha256 as 64. The
/// canister cannot read its own module hash, so it takes the controller's
/// word; a wrong one only makes the record disagree with the hash the IC
/// certifies, which every reader of the record checks.
pub fn canister_record(commit_hex: &str, module_sha256_hex: &str) -> Result<Record, String> {
    let commit: [u8; 20] = hex::decode(commit_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("commit must be 40 hex digits")?;
    let bundle: [u8; 32] = hex::decode(module_sha256_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("module hash must be 64 hex digits")?;
    Ok(Record {
        key: CANISTER_KEY.to_string(),
        commit,
        bundle,
    })
}

/// Publish a specific commit's deploy-artifact provenance, given its already
/// resolved artifact hash. The deploy queue's auto-publish passes the commit it
/// just deployed rather than the mutable tip, so a push landing mid-deploy
/// cannot make the registry attest a commit whose deploy has not yet run --
/// and passes the hash of the bytes it broadcast, so nothing here re-reads the
/// object store. That takes the auto-publish path off git state entirely,
/// which is what docs/CANISTER_SPLIT.md section 6 needs it to be.
///
/// The record is `Record::artifact`, the same one the git side's
/// `attest::tip_record` builds. `bundle` is the sha256 of the *decoded*
/// bytecode, which keeps it equal to the `bytecode_sha256` already in
/// `evm_deploy_history`; `jobs::evm_artifact_hash` is the one function that
/// derives it. It is a parameter rather than resolved here because the
/// re-derivation would redo the tree walk and open the window for a
/// mid-deploy config edit to redirect the attestation.
pub async fn publish_commit(
    repo: &str,
    commit_oid: &Oid,
    bundle: [u8; 32],
) -> Result<TxOutcome, String> {
    evm::require_publish_target()?;
    Ok(publish(&Record::artifact(repo, commit_oid, bundle)?).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs;
    use crate::store::{self, ObjectType};
    use sha2::Digest;

    /// An app record is namespaced like a site record and carries the
    /// installed module's hash as the queue reported it, so the registry
    /// holds exactly the bytes the IC's certified module hash names.
    #[test]
    fn app_record_is_namespaced_and_carries_the_module_hash() {
        let commit_oid = store::put_object(ObjectType::Commit, b"tree x\n\ncommit\n");
        let hash = "2bfd212775e572b82ff35997309f2753a273cff114035bc015d14d0841ddcec3";
        let rec = app_record("apprepo", &commit_oid, hash).expect("record resolves");
        assert_eq!(rec.key, "apprepo#app");
        assert_eq!(hex::encode(rec.bundle), hash);
        assert_eq!(rec.commit, commit20(&commit_oid).unwrap());
        assert!(app_record("apprepo", &commit_oid, "abcd").is_err(), "a short hash is refused");
        assert!(app_record("apprepo", &commit_oid, "").is_err(), "no hash is refused");
    }

    #[test]
    fn canister_record_takes_full_hex_values() {
        let commit = "a23ee3157b7837eaa205cdc9f7f5dbadd243b1ce";
        let hash = "30e76748ddb1487e41ca2718c30aa469c2ffa35f21f4c1936e67509771066d6a";
        let rec = canister_record(commit, hash).expect("record");
        assert_eq!(rec.key, "ic-git#canister");
        assert_eq!(hex::encode(rec.commit), commit);
        assert_eq!(hex::encode(rec.bundle), hash);
        assert!(canister_record(&commit[..39], hash).is_err(), "a short commit");
        assert!(canister_record(commit, &hash[..62]).is_err(), "a short hash");
        assert!(canister_record("zz", hash).is_err(), "not hex");
    }

    /// A deploy record's key is the bare repo name and its bundle is the
    /// sha256 of the *hex-decoded* bytecode, not of the hex text. This is the
    /// semantic `tools/verify.mjs` check B relies on (it hex-decodes before
    /// hashing) and that `evm_deploy_history.bytecode_sha256` must equal;
    /// hashing the text instead would compile, pass every other test, and
    /// print NOT VERIFIED for correctly deployed contracts on mainnet.
    #[test]
    fn deploy_record_hashes_decoded_bytecode_under_the_bare_repo_key() {
        crate::tenancy::test_repo("hexrepo");
        // Leading 0x and trailing newline both get stripped before decoding.
        let artifact = b"0x6001600155\n";
        let blob = store::put_object(ObjectType::Blob, artifact);
        let mut root = Vec::new();
        root.extend_from_slice(b"100644 contract.hex\0");
        root.extend_from_slice(blob.as_slice());
        let root_tree = store::put_object(ObjectType::Tree, &root);
        let commit = format!("tree {}\n\ncommit\n", store::oid_hex(&root_tree));
        let commit_oid = store::put_object(ObjectType::Commit, commit.as_bytes());

        let bundle = jobs::evm_artifact_hash(&commit_oid, "contract.hex").expect("hash resolves");
        let rec = Record::artifact("hexrepo", &commit_oid, bundle).expect("record resolves");
        assert_eq!(rec.key, "hexrepo");
        assert_eq!(rec.commit, commit20(&commit_oid).unwrap());

        let decoded = [0x60u8, 0x01, 0x60, 0x01, 0x55];
        let expected: [u8; 32] = sha2::Sha256::digest(decoded).into();
        assert_eq!(rec.bundle, expected, "must hash decoded bytecode, not hex");
        let hashed_text: [u8; 32] = sha2::Sha256::digest(artifact).into();
        assert_ne!(rec.bundle, hashed_text);
    }
}
