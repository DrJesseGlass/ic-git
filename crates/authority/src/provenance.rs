//! Publishing provenance records: the authority's half of the registry path
//! (docs/CANISTER_SPLIT.md, section 4). It builds records from values the
//! deploy queue or a controller already holds and hands them to
//! `evm::registry_publish_record`, which signs and broadcasts. The records
//! that must be resolved out of a repo -- the served site, the release
//! commit's artifact -- start on the git side (attest.rs), which hands over
//! the artifact with its proof (phase 3, step 10: `record_artifact`). This
//! side checks the proof, requires the commit to be approved when the repo
//! requires votes, and hashes the bytes itself, so it signs only what an
//! approved commit holds.

use crate::evm::{self, TxOutcome};
use ic_git_types::deploy::bytecode_of;
use ic_git_types::git_side::{Attested, RecordKind};
pub use ic_git_types::keys::{Record, CANISTER_KEY, GIT_CANISTER_KEY};
use ic_git_types::keys::{app_record_key, site_record_key};
use ic_git_types::oid::{commit20, parse_oid, Oid};
use sha2::Digest as _;

/// The single exit point to the signing side. The error says whether the
/// broadcast was attempted, which decides a refund.
pub async fn publish(rec: &Record) -> Result<TxOutcome, evm::SendError> {
    let out = evm::registry_publish_record(&rec.key, &rec.commit, &rec.bundle).await?;
    crate::feed::published(&rec.key, &hex::encode(rec.commit), &out.tx_hash);
    Ok(out)
}

/// The served site's record: the served commit and the sha256 of its
/// entrypoint, as served. Asked of the git side and checked here.
pub async fn site_record(repo: &str) -> Result<Record, String> {
    resolve(repo, RecordKind::Site).await
}

/// The release commit's deploy-artifact record: the commit and the sha256
/// of its decoded EVM bytecode, at the source path of this side's own EVM
/// config. Asked of the git side and checked here.
pub async fn tip_record(repo: &str) -> Result<Record, String> {
    let cfg = crate::configs::get(repo).evm.ok_or("repo has no EVM deploy config (nothing to hash)")?;
    resolve(repo, RecordKind::Release { path: cfg.source_path }).await
}

async fn resolve(repo: &str, kind: RecordKind) -> Result<Record, String> {
    let attested = crate::to_git::record_artifact(repo, kind.clone())
        .await
        .map_err(|f| format!("the git side did not answer ({f}); nothing was charged, ask again"))??;
    checked(repo, &kind, attested)
}

/// The record for what the git side resolved, once this side has checked
/// it: the proof shows the blob is what the commit holds at the path --
/// for a release, the path of this side's own config, whatever path the
/// git side names -- and with votes required, the commit is approved. The
/// bundle is hashed here, from the checked bytes. Reads nothing of the git
/// side's state, so a forged answer can make a publish fail, never sign
/// what no approved commit holds.
pub fn checked(repo: &str, kind: &RecordKind, a: Attested) -> Result<Record, String> {
    let commit = parse_oid(&a.commit)?;
    let commit20 = commit20(&commit)?;
    let path = match kind {
        RecordKind::Site => a.path,
        RecordKind::Release { path } => path.clone(),
    };
    let blob = a.artifact.verified(&commit20, &path)?;
    if !crate::tenancy::approved(repo, &a.commit) {
        return Err(format!(
            "commit {} is not approved by the repo's voters: nothing to attest (see get_votes)",
            a.commit
        ));
    }
    match kind {
        RecordKind::Site => Ok(Record {
            key: site_record_key(repo),
            commit: commit20,
            bundle: sha2::Sha256::digest(&blob).into(),
        }),
        RecordKind::Release { .. } => {
            Record::artifact(repo, &commit, sha2::Sha256::digest(bytecode_of(&path, blob)?).into())
        }
    }
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
    stated(CANISTER_KEY, commit_hex, module_sha256_hex)
}

/// The git canister's record (phase 3, step 12d), from the values its
/// controller states. The commit is taken on the controller's word, as
/// for this canister's own record; the module hash is checked against
/// what the IC holds for the git canister (`running`) before anything is
/// published.
pub fn git_record(commit_hex: &str, module_sha256_hex: &str) -> Result<Record, String> {
    stated(GIT_CANISTER_KEY, commit_hex, module_sha256_hex)
}

/// Does the git canister run the module `rec` names? `running` is the
/// module hash the management canister's `canister_info` reports for it.
pub fn running(rec: &Record, running: Option<&[u8]>) -> Result<(), String> {
    match running {
        None => Err("the git canister runs no code; nothing to attest".into()),
        Some(h) if h != rec.bundle => Err(format!(
            "the git canister runs module {}, not {}; nothing published",
            hex::encode(h),
            hex::encode(rec.bundle)
        )),
        Some(_) => Ok(()),
    }
}

/// A record from a stated commit (40 hex digits) and module hash (64).
fn stated(key: &str, commit_hex: &str, module_sha256_hex: &str) -> Result<Record, String> {
    let commit: [u8; 20] = hex::decode(commit_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("commit must be 40 hex digits")?;
    let bundle: [u8; 32] = hex::decode(module_sha256_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("module hash must be 64 hex digits")?;
    Ok(Record {
        key: key.to_string(),
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
/// The record is `Record::artifact`, the same one `tip_record` builds.
/// `bundle` is the sha256 of the *decoded* bytecode (`bytecode_of`), which
/// keeps it equal to the `bytecode_sha256` already in
/// `evm_deploy_history`. It is a parameter rather than resolved here
/// because the re-derivation would ask the git side again and open the
/// window for a mid-deploy config edit to redirect the attestation.
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
    use crate::store::{self, ObjectType};
    use futures::executor::block_on;

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

    /// The git canister's record names the module the IC holds for it, or
    /// nothing is published: a canister running no code, or another
    /// module, is refused; the stated values are checked as the
    /// authority's own are.
    #[test]
    fn git_record_must_name_the_running_module() {
        let commit = "a23ee3157b7837eaa205cdc9f7f5dbadd243b1ce";
        let hash = "30e76748ddb1487e41ca2718c30aa469c2ffa35f21f4c1936e67509771066d6a";
        let rec = git_record(commit, hash).expect("record");
        assert_eq!(rec.key, "ic-git#git");
        assert_eq!(hex::encode(rec.commit), commit);
        assert_eq!(hex::encode(rec.bundle), hash);
        assert_eq!(running(&rec, Some(&hex::decode(hash).unwrap())), Ok(()));

        let e = running(&rec, None).unwrap_err();
        assert!(e.contains("runs no code"), "{e}");
        let other = vec![0xabu8; 32];
        let e = running(&rec, Some(&other)).unwrap_err();
        assert!(e.contains(&hex::encode(&other)) && e.contains(hash), "{e}");
        assert!(git_record(&commit[..39], hash).is_err(), "a short commit");
        assert!(git_record(commit, &hash[..62]).is_err(), "a short hash");
    }

    /// A repo with an EVM config at `contract.hex` and `files` committed
    /// at its tip.
    fn evm_repo(repo: &str, files: &[(&str, &[u8])]) -> Oid {
        crate::tenancy::test_repo(repo);
        crate::evm::set_config("aaaaa-aa".into(), "key".into(), 11155111, Vec::new()).unwrap();
        block_on(crate::configs::set_evm(repo, "contract.hex".into(), 100_000)).unwrap();
        let mut root = Vec::new();
        let mut files = files.to_vec();
        files.sort_by_key(|(name, _)| *name);
        for (name, bytes) in files {
            root.extend_from_slice(format!("100644 {name}\0").as_bytes());
            root.extend_from_slice(store::put_object(ObjectType::Blob, bytes).as_slice());
        }
        let tree = store::put_object(ObjectType::Tree, &root);
        let commit = format!("tree {}\n\ncommit\n", store::oid_hex(&tree));
        let oid = store::put_object(ObjectType::Commit, commit.as_bytes());
        let branch = store::head_target(repo).unwrap();
        store::set_ref(repo, &branch, oid).unwrap();
        oid
    }

    /// A deploy record's key is the bare repo name and its bundle is the
    /// sha256 of the *hex-decoded* bytecode, not of the hex text. This is the
    /// semantic `tools/verify.mjs` check B relies on (it hex-decodes before
    /// hashing) and that `evm_deploy_history.bytecode_sha256` must equal;
    /// hashing the text instead would compile, pass every other test, and
    /// print NOT VERIFIED for correctly deployed contracts on mainnet.
    #[test]
    fn deploy_record_hashes_decoded_bytecode_under_the_bare_repo_key() {
        // Leading 0x and trailing newline both get stripped before decoding.
        let artifact = b"0x6001600155\n";
        let commit_oid = evm_repo("hexrepo", &[("contract.hex", artifact)]);
        let rec = block_on(tip_record("hexrepo")).expect("record resolves");
        assert_eq!(rec.key, "hexrepo");
        assert_eq!(rec.commit, commit20(&commit_oid).unwrap());

        let decoded = [0x60u8, 0x01, 0x60, 0x01, 0x55];
        let expected: [u8; 32] = sha2::Sha256::digest(decoded).into();
        assert_eq!(rec.bundle, expected, "must hash decoded bytecode, not hex");
        let hashed_text: [u8; 32] = sha2::Sha256::digest(artifact).into();
        assert_ne!(rec.bundle, hashed_text);
    }

    /// A site record's key is namespaced and its bundle is the raw served
    /// bytes -- the two properties that keep it from clobbering, or being
    /// clobbered by, the same repo's deploy-artifact record.
    #[test]
    fn site_record_is_namespaced_and_hashes_served_bytes() {
        let body = b"<h1>hello</h1>";
        let commit_oid = evm_repo("siterepo", &[("index.html", body)]);
        ic_git_git::site::set_config("siterepo", String::new()).unwrap();
        let rec = block_on(site_record("siterepo")).expect("site record resolves");
        assert_eq!(rec.key, "siterepo#site");
        let expected: [u8; 32] = sha2::Sha256::digest(body).into();
        assert_eq!(rec.bundle, expected);
        assert_eq!(rec.commit, commit20(&commit_oid).unwrap());
    }

    /// What the git side hands over is checked, not believed: another
    /// blob, the proof of another file in the same commit (the release
    /// path is this side's config, not the git side's word), another
    /// commit, a malformed commit id, and a proof cut short are each
    /// refused before anything is hashed.
    #[test]
    fn a_forged_answer_is_refused() {
        let tip = evm_repo("forged", &[("contract.hex", b"0x6001"), ("other.hex", b"0x6002")]);
        let release = RecordKind::Release { path: "contract.hex".into() };
        let honest = || ic_git_git::attest::record_artifact("forged", &release).unwrap();
        let other = || ic_git_git::attest::record_artifact("forged", &RecordKind::Release { path: "other.hex".into() }).unwrap();
        assert!(checked("forged", &release, honest()).is_ok());

        let mut a = honest();
        a.artifact.blob = b"0x6002".to_vec();
        assert!(checked("forged", &release, a).unwrap_err().contains("refused"));

        let e = checked("forged", &release, other()).unwrap_err();
        assert!(e.contains("contract.hex"), "checked against this side's path: {e}");

        let mut a = honest();
        a.commit = store::oid_hex(&store::put_object(ObjectType::Commit, b"tree x\n\nanother\n"));
        assert!(checked("forged", &release, a).is_err());

        let mut a = honest();
        a.commit = "abcd".into();
        assert!(checked("forged", &release, a).is_err());

        let mut a = honest();
        a.artifact.proof.pop();
        assert!(checked("forged", &release, a).is_err());

        // The site's path is the git side's to name, but its proof must
        // still hold for that path.
        let mut a = honest();
        a.path = "other.hex".into();
        assert!(checked("forged", &RecordKind::Site, a).is_err());
        assert_eq!(store::oid_hex(&tip), honest().commit);
    }

    /// With votes required, a record is published only for an approved
    /// commit, whatever commit the git side names as its release.
    #[test]
    fn an_unapproved_commit_is_not_attested() {
        // A ballot reaches the git side, which submits the approved
        // commit's job back to this side.
        ic_git_git::to_authority::set_test_side(Some(std::rc::Rc::new(crate::for_git::Authority)));
        let tip = evm_repo("gatedrec", &[("contract.hex", b"0x6001")]);
        let owner = candid::Principal::from_slice(&[71; 8]);
        crate::tenancy::credit(&owner, 10_000_000_000);
        block_on(crate::tenancy::transfer_repo("gatedrec", &owner, true, owner)).unwrap();
        block_on(crate::tenancy::set_required_votes("gatedrec", &owner, false, 1)).unwrap();
        let release = RecordKind::Release { path: "contract.hex".into() };
        // The git side's tip, forged as its release commit.
        let (blob, proof) = ic_git_git::gitproof::prove(&tip, "contract.hex").unwrap();
        let forged = || Attested {
            commit: store::oid_hex(&tip),
            path: "contract.hex".into(),
            artifact: ic_git_types::proof::Artifact { blob: blob.clone(), proof: proof.clone() },
        };
        let e = checked("gatedrec", &release, forged()).unwrap_err();
        assert!(e.contains("not approved"), "{e}");
        // An honest git side has nothing to offer either.
        assert!(block_on(tip_record("gatedrec")).is_err());

        block_on(crate::tenancy::vote("gatedrec", &owner, &store::oid_hex(&tip), true)).unwrap();
        assert!(checked("gatedrec", &release, forged()).is_ok());
        assert_eq!(block_on(tip_record("gatedrec")).unwrap().commit, commit20(&tip).unwrap());
        ic_git_git::to_authority::set_test_side(None);
    }

    /// A git side that does not answer, or whose answer is lost, fails the
    /// record with a message that says to ask again; a refusal is passed
    /// on as it came.
    #[test]
    fn an_unanswered_ask_fails_the_record() {
        use crate::to_git::flaky::{Flaky, Inject};
        evm_repo("unanswered", &[("contract.hex", b"0x6001")]);
        let git = std::rc::Rc::new(Flaky::new());
        crate::to_git::set_test_side(Some(git.clone()));
        git.inject("record_artifact", Inject::NotDelivered);
        assert!(block_on(tip_record("unanswered")).unwrap_err().contains("ask again"));
        git.inject("record_artifact", Inject::Lost);
        assert!(block_on(tip_record("unanswered")).unwrap_err().contains("ask again"));
        git.inject("record_artifact", Inject::Refuse);
        assert_eq!(block_on(tip_record("unanswered")).unwrap_err(), "refused by the git side");
        assert!(block_on(tip_record("unanswered")).is_ok());
        crate::to_git::set_test_side(None);
    }
}
