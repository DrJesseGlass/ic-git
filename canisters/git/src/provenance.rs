//! Resolving repo state into provenance records.
//!
//! The git-side half of the registry publish path: it answers "what commit and
//! what artifact hash does this repo attest to?" by walking refs, trees, and
//! blobs, then hands three plain values to `evm::registry_publish_record`,
//! which signs and broadcasts. The dependency points one way -- git state
//! resolves here, signing happens there -- which is what lets the signing half
//! become its own canister. See docs/CANISTER_SPLIT.md.

use crate::deploy;
use crate::evm::{self, TxOutcome};
use crate::site;
use crate::store::Oid;
use sha2::Digest;

/// Suffix that namespaces a served-site record away from the same repo's
/// deploy-artifact record. The registry stores one slot per key string, and
/// this canister has two writers with incompatible bundleHash semantics
/// (decoded contract bytecode vs. served site bytes), so a repo that both
/// deploys a contract and serves a site would otherwise have one record
/// silently clobber the other on the next push. See docs/ATTESTATION.md,
/// "The two record types". `tools/verify.mjs` hardcodes the same suffix.
const SITE_KEY_SUFFIX: &str = "#site";

/// A resolved provenance record: the registry key, the commit being attested,
/// and the artifact hash bound to it.
struct Record {
    key: String,
    commit: [u8; 20],
    bundle: [u8; 32],
}

impl Record {
    /// The module's single exit point to the signing side.
    async fn publish(&self) -> Result<TxOutcome, String> {
        evm::registry_publish_record(&self.key, &self.commit, &self.bundle).await
    }
}

/// The leading 20 bytes of an oid, which is what the registry stores.
/// Infallible: `Oid` is `Blob<20>`, so the chunk is always present.
fn commit20(oid: &Oid) -> [u8; 20] {
    *oid.as_slice()
        .first_chunk::<20>()
        .expect("Oid is Blob<20>")
}

/// Resolve the deploy-artifact record for a specific commit: the commit itself
/// and the sha256 of the *decoded* bytecode at the repo's EVM deploy source
/// path. Hashing the decoded bytes rather than the hex text is what keeps this
/// equal to the `bytecode_sha256` already in `evm_deploy_history`.
fn deploy_record(repo: &str, commit_oid: &Oid) -> Result<Record, String> {
    let dcfg =
        deploy::get_evm_config(repo).ok_or("repo has no EVM deploy config (nothing to hash)")?;
    let hex_text = deploy::evm_artifact_hex(commit_oid, &dcfg.source_path)?;
    let raw = evm::decode_bytecode_hex(&hex_text)?;
    Ok(Record {
        key: repo.to_string(),
        commit: commit20(commit_oid),
        bundle: sha2::Sha256::digest(&raw).into(),
    })
}

/// Resolve the served-site record: the deploy-branch tip and the sha256 of the
/// served entrypoint blob (site root + index.html fallback -- byte-identical to
/// what `/site/<repo>/` returns). Needs no EVM deploy config, because the
/// artifact is a frontend file hashed as raw bytes, matching how the F2
/// verifier hashes a served non-hex artifact.
fn site_record(repo: &str) -> Result<Record, String> {
    let (tip, _served, body) = site::resolve_entry(repo, "")
        .ok_or("repo serves no site entrypoint (need set_site + a commit with index.html)")?;
    Ok(Record {
        key: format!("{repo}{SITE_KEY_SUFFIX}"),
        commit: commit20(&tip),
        bundle: sha2::Sha256::digest(&body).into(),
    })
}

/// Publish a specific commit's deploy-artifact provenance. The deploy queue's
/// auto-publish passes the commit it just deployed rather than the mutable tip,
/// so a push landing mid-deploy cannot make the registry attest a commit whose
/// deploy has not yet run.
pub async fn publish_commit(repo: &str, commit_oid: &Oid) -> Result<TxOutcome, String> {
    deploy_record(repo, commit_oid)?.publish().await
}

/// Publish the repo's current deploy-branch tip as its deploy-artifact record.
pub async fn publish_tip(repo: &str) -> Result<TxOutcome, String> {
    publish_commit(repo, &deploy::current_tip(repo)?).await
}

/// Publish the repo's served-site record.
pub async fn publish_site(repo: &str) -> Result<TxOutcome, String> {
    site_record(repo)?.publish().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{self, ObjectType};

    /// A site record's key is namespaced and its bundle is the raw served
    /// bytes -- the two properties that keep it from clobbering, or being
    /// clobbered by, the same repo's deploy-artifact record.
    #[test]
    fn site_record_is_namespaced_and_hashes_served_bytes() {
        store::create_repo("provrepo").unwrap();
        let body = b"<h1>hello</h1>";
        let index = store::put_object(ObjectType::Blob, body);
        let mut root = Vec::new();
        root.extend_from_slice(b"100644 index.html\0");
        root.extend_from_slice(index.as_slice());
        let root_tree = store::put_object(ObjectType::Tree, &root);
        let commit = format!("tree {}\n\ncommit\n", store::oid_hex(&root_tree));
        let commit_oid = store::put_object(ObjectType::Commit, commit.as_bytes());
        let branch = store::head_target("provrepo").unwrap();
        store::set_ref("provrepo", &branch, commit_oid).unwrap();
        site::set_config("provrepo", String::new()).unwrap();

        let rec = site_record("provrepo").expect("site record resolves");
        assert_eq!(rec.key, "provrepo#site");
        let expected: [u8; 32] = sha2::Sha256::digest(body).into();
        assert_eq!(rec.bundle, expected);
        assert_eq!(rec.commit, commit20(&commit_oid));
    }

    /// A repo with site config but nothing committed reports that, rather than
    /// publishing a record over an empty or absent artifact. Configured on
    /// purpose, so the failure is the missing entrypoint and not the missing
    /// config.
    #[test]
    fn site_record_requires_an_entrypoint() {
        store::create_repo("emptyrepo").unwrap();
        site::set_config("emptyrepo", String::new()).unwrap();
        assert!(site_record("emptyrepo").is_err());
    }
}
