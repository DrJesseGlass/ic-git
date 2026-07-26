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
///
/// Fallible on purpose. `Oid` is `Blob<20>`, but that is a *maximum* length --
/// `Blob::try_from` only rejects slices longer than N -- so the type alone does
/// not prove 20 bytes are present. `store::parse_oid` now enforces it, and
/// every caller here resolves the object first, which is why this cannot fire
/// today; returning an error rather than panicking keeps a future caller that
/// skips those steps from trapping inside `deploy::run`, which is documented
/// never to trap and whose queue would stop draining if it did.
fn commit20(oid: &Oid) -> Result<[u8; 20], String> {
    oid.as_slice()
        .first_chunk::<20>()
        .copied()
        .ok_or_else(|| "bad oid length".to_string())
}

/// The deploy-artifact record for a commit: the bare repo name as key (no
/// suffix -- that is what distinguishes it from the site record), the commit,
/// and `bundle`, which must be the sha256 of the *decoded* bytecode. Hashing
/// the decoded bytes rather than the hex text is what keeps this equal to the
/// `bytecode_sha256` already in `evm_deploy_history`;
/// `deploy::evm_artifact_hash` is the one function that derives it.
///
/// The hash is a parameter rather than something resolved here because the
/// caller may already hold it -- the deploy queue does, from the bytes it just
/// broadcast -- and re-deriving it would both redo the tree walk and open the
/// window for a mid-deploy config edit to redirect the attestation.
fn deploy_record(repo: &str, commit_oid: &Oid, bundle: [u8; 32]) -> Result<Record, String> {
    Ok(Record {
        key: repo.to_string(),
        commit: commit20(commit_oid)?,
        bundle,
    })
}

/// Resolve the served-site record: the deploy-branch tip and the sha256 of the
/// served entrypoint blob (site root + index.html fallback -- byte-identical to
/// what `/site/<repo>/` returns). Needs no EVM deploy config, because the
/// artifact is a frontend file hashed as raw bytes, matching how the F2
/// verifier hashes a served non-hex artifact.
fn site_record(repo: &str) -> Result<Record, String> {
    let (tip, served, body) = site::resolve_entry(repo, "")
        .ok_or("repo serves no site entrypoint (need set_site + a commit with index.html)")?;
    // Refuse to attest bytes `site::serve` would answer 413 for. Publishing
    // one costs a real registry transaction and produces a record no verifier
    // can ever check -- every fetch of the entrypoint fails before it can be
    // hashed -- and the only repair is to shrink the bundle and republish.
    if body.len() > site::MAX_BODY {
        return Err(format!(
            "site entrypoint is {} bytes, over the {} serving limit: it would be attested but never served",
            body.len(),
            site::MAX_BODY
        ));
    }
    // Same principle, sharper failure: refuse an entrypoint whose hash a
    // verifier could check and still be wrong. This record covers one blob, so
    // an uncovered subresource lets a hostile gateway pair the honest
    // entrypoint with malicious code and still pass the comparison -- the
    // verifier reports verified, which is worse than reporting nothing.
    if let Some(why) = site::unverifiable_subresource(&served, &body) {
        return Err(format!(
            "{served}: {why}. This record attests only the entrypoint, so a \
             referenced file is covered by nothing and a verifier would report \
             verified while it went unchecked. Inline it, or add \
             integrity=\"sha384-...\" so the browser enforces it."
        ));
    }
    Ok(Record {
        key: format!("{repo}{SITE_KEY_SUFFIX}"),
        commit: commit20(&tip)?,
        bundle: sha2::Sha256::digest(&body).into(),
    })
}

/// Publish a specific commit's deploy-artifact provenance, given its already
/// resolved artifact hash. The deploy queue's auto-publish passes the commit it
/// just deployed rather than the mutable tip, so a push landing mid-deploy
/// cannot make the registry attest a commit whose deploy has not yet run --
/// and passes the hash of the bytes it broadcast, so nothing here re-reads the
/// object store. That takes the auto-publish path off git state entirely,
/// which is what docs/CANISTER_SPLIT.md section 6 needs it to be.
pub async fn publish_commit(
    repo: &str,
    commit_oid: &Oid,
    bundle: [u8; 32],
) -> Result<TxOutcome, String> {
    evm::require_publish_target()?;
    deploy_record(repo, commit_oid, bundle)?.publish().await
}

/// Publish the repo's current deploy-branch tip as its deploy-artifact record.
/// The operator entry point, and the only deploy-artifact path that resolves
/// the hash out of the repo: there is no deploy in flight to inherit bytes from.
pub async fn publish_tip(repo: &str) -> Result<TxOutcome, String> {
    evm::require_publish_target()?;
    let cfg =
        deploy::get_evm_config(repo).ok_or("repo has no EVM deploy config (nothing to hash)")?;
    let commit_oid = deploy::current_tip(repo)?;
    let bundle = deploy::evm_artifact_hash(&commit_oid, &cfg.source_path)?;
    publish_commit(repo, &commit_oid, bundle).await
}

/// Publish the repo's served-site record.
pub async fn publish_site(repo: &str) -> Result<TxOutcome, String> {
    evm::require_publish_target()?;
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
        assert_eq!(rec.commit, commit20(&commit_oid).unwrap());
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

    /// A site record is refused when the entrypoint references a file the
    /// record cannot cover, and allowed once the reference is enforceable.
    /// Without this the publish succeeds, the verifier's hash comparison
    /// passes, and the verdict says verified while unattested code runs.
    #[test]
    fn site_record_refuses_an_entrypoint_it_cannot_fully_cover() {
        let commit_index = |repo: &str, html: &[u8]| {
            let index = store::put_object(ObjectType::Blob, html);
            let mut root = Vec::new();
            root.extend_from_slice(b"100644 index.html\0");
            root.extend_from_slice(index.as_slice());
            let root_tree = store::put_object(ObjectType::Tree, &root);
            let commit = format!("tree {}\n\ncommit\n", store::oid_hex(&root_tree));
            let commit_oid = store::put_object(ObjectType::Commit, commit.as_bytes());
            let branch = store::head_target(repo).unwrap();
            store::set_ref(repo, &branch, commit_oid).unwrap();
        };

        store::create_repo("srirepo").unwrap();
        site::set_config("srirepo", String::new()).unwrap();

        commit_index("srirepo", b"<script src=\"app.js\"></script>");
        let err = site_record("srirepo")
            .err()
            .expect("must refuse an uncovered subresource");
        assert!(err.contains("index.html"), "names the entrypoint: {err}");
        assert!(err.contains("integrity"), "says how to fix it: {err}");

        // Same page, reference now enforced by the browser: attestable.
        commit_index(
            "srirepo",
            b"<script src=\"app.js\" integrity=\"sha384-x\"></script>",
        );
        assert!(site_record("srirepo").is_ok());
    }

    /// A deploy record's key is the bare repo name and its bundle is the
    /// sha256 of the *hex-decoded* bytecode, not of the hex text. This is the
    /// semantic `tools/verify.mjs` check B relies on (it hex-decodes before
    /// hashing) and that `evm_deploy_history.bytecode_sha256` must equal;
    /// hashing the text instead would compile, pass every other test, and
    /// print NOT VERIFIED for correctly deployed contracts on mainnet.
    #[test]
    fn deploy_record_hashes_decoded_bytecode_under_the_bare_repo_key() {
        store::create_repo("hexrepo").unwrap();
        // Leading 0x and trailing newline both get stripped before decoding.
        let artifact = b"0x6001600155\n";
        let blob = store::put_object(ObjectType::Blob, artifact);
        let mut root = Vec::new();
        root.extend_from_slice(b"100644 contract.hex\0");
        root.extend_from_slice(blob.as_slice());
        let root_tree = store::put_object(ObjectType::Tree, &root);
        let commit = format!("tree {}\n\ncommit\n", store::oid_hex(&root_tree));
        let commit_oid = store::put_object(ObjectType::Commit, commit.as_bytes());

        let bundle = deploy::evm_artifact_hash(&commit_oid, "contract.hex").expect("hash resolves");
        let rec = deploy_record("hexrepo", &commit_oid, bundle).expect("record resolves");
        assert_eq!(rec.key, "hexrepo");
        assert_eq!(rec.commit, commit20(&commit_oid).unwrap());

        let decoded = [0x60u8, 0x01, 0x60, 0x01, 0x55];
        let expected: [u8; 32] = sha2::Sha256::digest(decoded).into();
        assert_eq!(rec.bundle, expected, "must hash decoded bytecode, not hex");
        let hashed_text: [u8; 32] = sha2::Sha256::digest(artifact).into();
        assert_ne!(rec.bundle, hashed_text);
    }
}
