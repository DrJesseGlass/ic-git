//! Registry record keys (docs/ATTESTATION.md, "The two record types"). The
//! registry stores one slot per key string, so the key says what the record
//! attests. The one definition the authority, the git side and the tests
//! derive keys from; `tools/verify.mjs` and `core/verifier.js` hardcode the
//! same suffixes, and the tests below read both files to hold them to it.

/// Suffix that namespaces a served-site record away from the same repo's
/// deploy-artifact record. This canister has two writers with incompatible
/// bundleHash semantics (decoded contract bytecode vs. served site bytes),
/// so a repo that both deploys a contract and serves a site would otherwise
/// have one record silently clobber the other on the next push.
pub const SITE_KEY_SUFFIX: &str = "#site";

/// Suffix of a governed repo's backend record: the commit the deploy queue
/// installed into the app canister and the sha256 of the module it
/// installed, which is the module hash the IC certifies for that canister
/// (docs/GOVERNANCE.md, section 3). Published by the queue after every
/// install on a governed repo, so what the chain says the backend runs is
/// an approved commit's build, by a key nobody but ic-git can write.
pub const APP_KEY_SUFFIX: &str = "#app";

/// Key of ic-git's own record: the ic-git commit it was built from and the
/// sha256 of the module installed into it, the hash the IC certifies for
/// it. Published after each upgrade by the controller that made it -- the
/// governor (docs/GOVERNANCE.md, section 5) -- so a verifier can check
/// ic-git itself the way it checks a governed backend.
pub const CANISTER_KEY: &str = "ic-git#canister";

/// A registry record: the key, the commit it attests, and the artifact hash
/// bound to it -- what the authority publishes
/// (`evm::registry_publish_record`), however it was resolved.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub key: String,
    pub commit: [u8; 20],
    pub bundle: [u8; 32],
}

impl Record {
    /// The deploy-artifact record for a commit: the bare repo name as key
    /// (no suffix -- that is what distinguishes it from the site record),
    /// the commit, and `bundle`, which must be the sha256 of the *decoded*
    /// bytecode. The one construction of it, so the release path (the git
    /// side's tip record) and the deploy queue's auto-publish cannot drift
    /// apart on the key or the commit encoding.
    pub fn artifact(repo: &str, commit: &crate::oid::Oid, bundle: [u8; 32]) -> Result<Self, String> {
        Ok(Record {
            key: artifact_record_key(repo),
            commit: crate::oid::commit20(commit)?,
            bundle,
        })
    }
}

/// A repo's deploy-artifact record: its EVM contract's creation bytecode.
pub fn artifact_record_key(repo: &str) -> String {
    repo.to_string()
}

/// A repo's served-site record.
pub fn site_record_key(repo: &str) -> String {
    format!("{repo}{SITE_KEY_SUFFIX}")
}

/// A governed repo's backend record.
pub fn app_record_key(repo: &str) -> String {
    format!("{repo}{APP_KEY_SUFFIX}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_namespaced_by_suffix() {
        assert_eq!(artifact_record_key("app"), "app");
        assert_eq!(site_record_key("app"), "app#site");
        assert_eq!(app_record_key("app"), "app#app");
    }

    /// The verifiers are JavaScript and cannot import these constants, so
    /// hold their copies to them here.
    #[test]
    fn the_verifiers_use_the_same_suffixes() {
        let verify = include_str!("../../../tools/verify.mjs");
        assert!(verify.contains(&format!("const SITE_SUFFIX = \"{SITE_KEY_SUFFIX}\";")));
        let core = include_str!("../../../core/verifier.js");
        assert!(core.contains(&format!("const SITE_SUFFIX = '{SITE_KEY_SUFFIX}';")));
        assert!(core.contains(&format!("const APP_SUFFIX = '{APP_KEY_SUFFIX}';")));
        assert!(core.contains(&format!("const CANISTER_KEY = '{CANISTER_KEY}';")));
    }
}
