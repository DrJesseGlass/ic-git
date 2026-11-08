//! The git side of attestation (docs/CANISTER_SPLIT.md, section 4):
//! resolving a repo's state into the records the authority publishes -- the
//! served site's entrypoint, and the release commit's EVM artifact. Reads
//! the object store; publishes nothing.

use crate::{jobs, site};
use ic_git_types::keys::{artifact_record_key, site_record_key, Record};
use ic_git_types::oid::commit20;
use sha2::Digest;

/// Resolve the served-site record: the served commit (the deploy-branch tip,
/// or with votes required the newest approved commit) and the sha256 of the
/// served entrypoint blob (site root + index.html fallback -- byte-identical to
/// what `/site/<repo>/` returns). Needs no EVM deploy config, because the
/// artifact is a frontend file hashed as raw bytes, matching how the F2
/// verifier hashes a served non-hex artifact. The authority checks that it
/// could publish at all (`evm::require_publish_target`) before asking.
pub fn site_record(repo: &str) -> Result<Record, String> {
    let (commit, served, body) = site::resolve_entry(repo, "")
        .ok_or("repo serves no site entrypoint (need set_site + a commit with index.html, approved if the repo requires votes)")?;
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
    // The scan also refuses what the extensions' pinned policy would stop at
    // run time, so the advice covers both: `why` names which it was.
    if let Some(why) = site::unverifiable_subresource(&served, &body) {
        return Err(format!(
            "{served}: {why}. This record attests only the entrypoint, so a \
             referenced file is covered by nothing and a verifier would report \
             verified while it went unchecked: inline it, or give a script \
             integrity=\"sha384-...\" so the browser enforces it -- bundlers \
             do not emit SRI by default, but their plugins do \
             (vite-plugin-sri, webpack-subresource-integrity, rollup-plugin-sri). \
             And what the extensions' pinned policy refuses (docs/EXTENSION.md) \
             would publish and then be stopped: integrity does not admit it."
        ));
    }
    Ok(Record {
        key: site_record_key(repo),
        commit: commit20(&commit)?,
        bundle: sha2::Sha256::digest(&body).into(),
    })
}

/// The repo's release commit (`jobs::release_commit`: the tip, or with
/// votes required the approved commit) as its deploy-artifact record, ready
/// to publish. The operator entry point, and the only deploy-artifact path
/// that resolves the hash out of the repo: there is no deploy in flight to
/// inherit bytes from. Resolved before anything is charged, so every way the
/// publish can fail short of the transaction itself fails for free; the
/// authority checks first that it could publish at all.
pub fn tip_record(repo: &str) -> Result<Record, String> {
    let cfg =
        jobs::get_evm_config(repo).ok_or("repo has no EVM deploy config (nothing to hash)")?;
    let commit_oid = jobs::release_commit(repo)?;
    let bundle = jobs::evm_artifact_hash(&commit_oid, &cfg.source_path)?;
    Ok(Record {
        key: artifact_record_key(repo),
        commit: commit20(&commit_oid)?,
        bundle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{self, ObjectType};

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

    /// config.
    #[test]
    fn site_record_requires_an_entrypoint() {
        store::create_repo("emptyrepo").unwrap();
        site::set_config("emptyrepo", String::new()).unwrap();
        assert!(site_record("emptyrepo").is_err());
    }

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
}
