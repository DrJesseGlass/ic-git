//! The git side of attestation (docs/CANISTER_SPLIT.md, section 4):
//! resolving a repo's state into the artifact behind a registry record --
//! the served site's entrypoint, or the release commit's EVM artifact --
//! with its proof (phase 3, step 10: `record_artifact`). Reads the object
//! store; hashes and publishes nothing. The authority checks the proof,
//! the commit's approval and the hash itself (provenance.rs), so what it
//! signs is what the commit holds, whatever this side says.

use crate::{gitproof, jobs, site, store};
use ic_git_types::git_side::{Attested, RecordKind};
use ic_git_types::proof::{plain, Artifact};

/// The artifact behind a record of `kind`.
pub fn record_artifact(repo: &str, kind: &RecordKind) -> Result<Attested, String> {
    match kind {
        RecordKind::Site => site_artifact(repo),
        RecordKind::Release { path } => release_artifact(repo, path),
    }
}

/// The commit's blob at `path`, proved.
fn attested(commit: &store::Oid, path: &str) -> Result<Attested, String> {
    let path = plain(path);
    let (blob, proof) = gitproof::prove(commit, &path).map_err(|e| format!("resolve {path}: {e}"))?;
    Ok(Attested {
        commit: store::oid_hex(commit),
        path,
        artifact: Artifact { blob, proof },
    })
}

/// The served site's entrypoint: the served commit (the deploy-branch tip,
/// or with votes required the newest approved commit) and the blob at the
/// site root, with the index.html fallback -- byte-identical to what
/// `/site/<repo>/` returns. Needs no EVM deploy config, because the
/// artifact is a frontend file hashed as raw bytes, matching how the F2
/// verifier hashes a served non-hex artifact. The authority checks that it
/// could publish at all (`evm::require_publish_target`) before asking.
fn site_artifact(repo: &str) -> Result<Attested, String> {
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
    attested(&commit, &served)
}

/// The release commit (`jobs::release_commit`: the tip, or with votes
/// required the approved commit) and its blob at `path`, the authority's
/// EVM source path. The operator entry point, and the only deploy-artifact
/// path that resolves its bytes out of the repo: there is no deploy in
/// flight to inherit them from. Resolved before anything is charged, so
/// every way the publish can fail short of the transaction itself fails
/// for free.
fn release_artifact(repo: &str, path: &str) -> Result<Attested, String> {
    let commit = jobs::release_commit(repo)?;
    attested(&commit, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ObjectType;
    use ic_git_types::oid::commit20;

    /// The site's artifact is the served entrypoint's bytes, under the
    /// path the index.html fallback found, with a proof the authority's
    /// checker takes for the served commit and that path.
    #[test]
    fn the_site_artifact_is_the_served_entrypoint_proved() {
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

        let a = record_artifact("provrepo", &RecordKind::Site).expect("site artifact resolves");
        assert_eq!(a.commit, store::oid_hex(&commit_oid));
        assert_eq!(a.path, "index.html");
        assert_eq!(a.artifact.blob, body);
        let blob = a.artifact.verified(&commit20(&commit_oid).unwrap(), "index.html").expect("the proof holds");
        assert_eq!(blob, body);
    }

    /// The release artifact is the tip's blob at the path the authority
    /// names, proved; a path the commit does not hold is refused here.
    #[test]
    fn the_release_artifact_is_the_tips_blob_at_the_authoritys_path() {
        store::create_repo("relrepo").unwrap();
        let tip = store::commit_file_for_tests("relrepo", "contract.hex", b"0x6001", None);
        let path = RecordKind::Release { path: "/contract.hex".into() };
        let a = record_artifact("relrepo", &path).expect("release artifact resolves");
        assert_eq!(a.commit, store::oid_hex(&tip));
        assert_eq!(a.path, "contract.hex", "a plain path");
        assert!(a.artifact.verified(&commit20(&tip).unwrap(), "contract.hex").is_ok());
        let missing = RecordKind::Release { path: "other.hex".into() };
        assert!(record_artifact("relrepo", &missing).is_err());
    }

    /// A repo with site config but nothing committed reports that, rather than
    /// publishing a record over an empty or absent artifact. Configured on
    /// purpose, so the failure is the missing entrypoint and not the missing
    /// config.
    #[test]
    fn the_site_artifact_requires_an_entrypoint() {
        store::create_repo("emptyrepo").unwrap();
        site::set_config("emptyrepo", String::new()).unwrap();
        assert!(record_artifact("emptyrepo", &RecordKind::Site).is_err());
    }

    /// A site record is refused when the entrypoint references a file the
    /// record cannot cover, and allowed once the reference is enforceable.
    /// Without this the publish succeeds, the verifier's hash comparison
    /// passes, and the verdict says verified while unattested code runs.
    #[test]
    fn the_site_artifact_refuses_an_entrypoint_it_cannot_fully_cover() {
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
        let err = record_artifact("srirepo", &RecordKind::Site).err().expect("must refuse an uncovered subresource");
        assert!(err.contains("index.html"), "names the entrypoint: {err}");
        assert!(err.contains("integrity"), "says how to fix it: {err}");

        // Same page, reference now enforced by the browser: attestable.
        commit_index(
            "srirepo",
            b"<script src=\"app.js\" integrity=\"sha384-x\"></script>",
        );
        assert!(record_artifact("srirepo", &RecordKind::Site).is_ok());
    }
}
