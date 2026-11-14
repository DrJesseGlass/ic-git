//! Stable-memory object store, refs, repos and push tokens: the git side.
//! The authority's maps are in records.rs, the layout in memory.rs.
//!
//! Objects are global (content-addressed, shared across repos); refs and repo
//! metadata are namespaced by repo name. Object values are stored as a 1-byte
//! packfile type code followed by zlib(content) - the same zlib stream a pack
//! entry carries, so the milestone-2 pack writer can serve objects without
//! recompressing.

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use ic_stable_structures::StableBTreeMap;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::ops::Bound;

use crate::kv::page;
use crate::memory::Memory;

pub use ic_git_types::oid::{oid_hex, parse_oid, Oid};

/// Git object type; discriminants are the packfile type codes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

impl ObjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "commit" => Ok(ObjectType::Commit),
            "tree" => Ok(ObjectType::Tree),
            "blob" => Ok(ObjectType::Blob),
            "tag" => Ok(ObjectType::Tag),
            _ => Err(format!("invalid object type: {s}")),
        }
    }

    pub fn from_pack_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(ObjectType::Commit),
            2 => Some(ObjectType::Tree),
            3 => Some(ObjectType::Blob),
            4 => Some(ObjectType::Tag),
            _ => None,
        }
    }
}

thread_local! {
    /// oid -> [pack type code][content len u32 LE][zlib(content)]
    /// The length prefix lets the pack writer emit the entry size header
    /// without inflating the object.
    static OBJECTS: RefCell<StableBTreeMap<Oid, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(crate::memory::get(crate::memory::MEM_OBJECTS)),
    );

    /// "<repo>\0<refname>" -> oid
    static REFS: RefCell<StableBTreeMap<String, Oid, Memory>> = RefCell::new(
        StableBTreeMap::init(crate::memory::get(crate::memory::MEM_REFS)),
    );

    /// repo name -> HEAD symref target (e.g. "refs/heads/main")
    static REPOS: RefCell<StableBTreeMap<String, String, Memory>> = RefCell::new(
        StableBTreeMap::init(crate::memory::get(crate::memory::MEM_REPOS)),
    );

    /// hex(sha256(push token)) -> the token's record (tokens.rs owns the
    /// value format; a bare repo name before expiry existed).
    static TOKENS: RefCell<StableBTreeMap<String, String, Memory>> = RefCell::new(
        StableBTreeMap::init(crate::memory::get(crate::memory::MEM_TOKENS)),
    );

    /// Secondary keys over TOKENS, so a repo's tokens and the expired ones
    /// are range reads rather than scans of every token (tokens.rs owns the
    /// key format).
    static TOKEN_INDEX: RefCell<StableBTreeMap<String, (), Memory>> = RefCell::new(
        StableBTreeMap::init(crate::memory::get(crate::memory::MEM_TOKEN_INDEX)),
    );

}

// --- objects ----------------------------------------------------------------

/// Canonical object header: "<type> <len>\0". The oid is the SHA-1 of this
/// header followed by the content.
fn canonical_header(object_type: ObjectType, len: usize) -> String {
    format!("{} {len}\0", object_type.as_str())
}

/// The oid of an object: SHA-1 of its canonical form.
fn compute_oid(object_type: ObjectType, content: &[u8]) -> Oid {
    let mut hasher = Sha1::new();
    hasher.update(canonical_header(object_type, content.len()).as_bytes());
    hasher.update(content);
    let digest: [u8; 20] = hasher.finalize().into();
    Oid::try_from(digest.as_slice()).unwrap()
}

/// Store a git object. Returns the oid (SHA-1 of the canonical form).
pub fn put_object(object_type: ObjectType, content: &[u8]) -> Oid {
    let oid = compute_oid(object_type, content);
    // contains_key is a keys-only probe; on a duplicate it skips the deflate,
    // which dominates the cost of the extra traversal on the miss path.
    if !OBJECTS.with(|o| o.borrow().contains_key(&oid)) {
        let mut value = Vec::with_capacity(5 + content.len() / 2);
        value.push(object_type as u8);
        value.extend_from_slice(&(content.len() as u32).to_le_bytes());
        let mut enc = ZlibEncoder::new(value, Compression::default());
        enc.write_all(content).expect("in-memory write");
        let value = enc.finish().expect("in-memory finish");
        OBJECTS.with(|o| o.borrow_mut().insert(oid, value));
    }
    oid
}

/// Store a git object whose zlib(content) stream is already at hand (a
/// non-delta pack entry): the stream is persisted verbatim, skipping the
/// deflate that dominates put_object. `zlib` must inflate to `content`.
pub fn put_object_zlib(object_type: ObjectType, content: &[u8], zlib: &[u8]) -> Oid {
    let oid = compute_oid(object_type, content);
    if !OBJECTS.with(|o| o.borrow().contains_key(&oid)) {
        let mut value = Vec::with_capacity(5 + zlib.len());
        value.push(object_type as u8);
        value.extend_from_slice(&(content.len() as u32).to_le_bytes());
        value.extend_from_slice(zlib);
        OBJECTS.with(|o| o.borrow_mut().insert(oid, value));
    }
    oid
}

/// A stored object as read from stable memory - type and inflated size are
/// parsed; the zlib(content) stream is borrowed from the value, so serving it
/// (e.g. as a pack entry) copies once and never recompresses.
pub struct StoredObject {
    pub object_type: ObjectType,
    pub size: u32,
    value: Vec<u8>,
}

impl StoredObject {
    /// The raw zlib(content) stream, pack-entry compatible.
    pub fn zlib(&self) -> &[u8] {
        &self.value[5..]
    }

    /// Inflate the content.
    pub fn content(&self) -> Vec<u8> {
        let mut content = Vec::with_capacity(self.size as usize);
        ZlibDecoder::new(self.zlib())
            .read_to_end(&mut content)
            .expect("stored object is valid zlib");
        content
    }
}

pub fn get_object_stored(oid: &Oid) -> Option<StoredObject> {
    let value = OBJECTS.with(|o| o.borrow().get(oid))?;
    Some(StoredObject {
        object_type: ObjectType::from_pack_code(value[0])
            .expect("stored object has valid type code"),
        size: u32::from_le_bytes(value[1..5].try_into().unwrap()),
        value,
    })
}

/// Fetch an object as (type, content).
pub fn get_object_parsed(oid: &Oid) -> Option<(ObjectType, Vec<u8>)> {
    let stored = get_object_stored(oid)?;
    Some((stored.object_type, stored.content()))
}

/// Fetch an object in canonical form: "<type> <len>\0" + content.
pub fn get_object(oid: &Oid) -> Option<Vec<u8>> {
    let (object_type, content) = get_object_parsed(oid)?;
    let header = canonical_header(object_type, content.len());
    let mut canonical = Vec::with_capacity(header.len() + content.len());
    canonical.extend_from_slice(header.as_bytes());
    canonical.extend_from_slice(&content);
    Some(canonical)
}

pub fn has_object(oid: &Oid) -> bool {
    OBJECTS.with(|o| o.borrow().contains_key(oid))
}

// --- repos & refs -----------------------------------------------------------

use ic_git_types::labels::repo_label;

fn label_key(label: &str) -> String {
    format!("label:{label}")
}

/// The repo holding a label, if any. Every repo holds its own, unless an
/// older repo holds it.
pub fn label_holder(label: &str) -> Option<String> {
    crate::kv::get_json(&label_key(label))
}

/// Longest repo name, in bytes. Generous for a git repo name, and well
/// under the 512 bytes ic-name-service accepts for the `repo` text an
/// announce carries, so every repo that can be created can be announced.
pub const MAX_REPO_NAME: usize = 100;

/// Check that `name` could be created now, returning its label: a valid
/// name, not taken, whose label is not held either. `tenancy::create_repo`
/// runs this before charging the creation fee, so a refused name costs
/// nothing.
pub fn check_new_repo(name: &str) -> Result<String, String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name.starts_with('.')
    {
        return Err("repo names: [A-Za-z0-9._-]+, not starting with '.'".into());
    }
    // ASCII only by now, so bytes are characters.
    if name.len() > MAX_REPO_NAME {
        return Err(format!("repo names are at most {MAX_REPO_NAME} characters"));
    }
    if repo_exists(name) {
        return Err(format!("repo '{name}' already exists"));
    }
    let label = repo_label(name)?;
    if let Some(holder) = label_holder(&label) {
        return Err(format!(
            "repo name '{name}' maps to the label '{label}', which repo '{holder}' already holds"
        ));
    }
    Ok(label)
}

/// Create a repo. Its name must be new, and so must its label: once
/// "my-app" exists, "My_App" and "my.app" are refused, so every repo maps
/// to a label no other repo can take.
pub fn create_repo(name: &str) -> Result<(), String> {
    crate::transfer::check_unfrozen()?;
    let label = check_new_repo(name)?;
    REPOS.with(|r| r.borrow_mut().insert(name.to_string(), "refs/heads/main".to_string()));
    crate::kv::set_json(&label_key(&label), &name);
    Ok(())
}

pub fn repo_exists(name: &str) -> bool {
    REPOS.with(|r| r.borrow().contains_key(&name.to_string()))
}

pub fn head_target(repo: &str) -> Option<String> {
    REPOS.with(|r| r.borrow().get(&repo.to_string()))
}

pub fn list_repos() -> Vec<String> {
    REPOS.with(|r| r.borrow().iter().map(|e| e.key().clone()).collect())
}

fn ref_key(repo: &str, refname: &str) -> String {
    format!("{repo}\0{refname}")
}

/// Refused while the git side is frozen for its move (transfer.rs), as
/// `create_repo` and `tokens::mint` are: the backstop behind the
/// endpoints' own refusals, so a write path they do not gate cannot move
/// a store being exported.
pub fn set_ref(repo: &str, refname: &str, oid: Oid) -> Result<(), String> {
    crate::transfer::check_unfrozen()?;
    if !repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    if !refname.starts_with("refs/") {
        return Err("refname must start with refs/".into());
    }
    if !has_object(&oid) {
        return Err("target object not in store".into());
    }
    REFS.with(|r| r.borrow_mut().insert(ref_key(repo, refname), oid));
    Ok(())
}

pub fn get_ref(repo: &str, refname: &str) -> Option<Oid> {
    REFS.with(|r| r.borrow().get(&ref_key(repo, refname)))
}

pub fn delete_ref(repo: &str, refname: &str) {
    REFS.with(|r| r.borrow_mut().remove(&ref_key(repo, refname)));
}

// --- push tokens -------------------------------------------------------------

/// TOKENS key for a plaintext token; tokens are never stored in the clear.
/// Push-token policy (lifetimes, listing, the value format) lives in
/// `tokens.rs`; these are the raw map operations under it.
pub fn token_key(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn token_put(key: &str, value: String) {
    TOKENS.with(|t| t.borrow_mut().insert(key.to_string(), value));
}

pub fn token_get(key: &str) -> Option<String> {
    TOKENS.with(|t| t.borrow().get(&key.to_string()))
}

pub fn token_remove(key: &str) -> bool {
    TOKENS.with(|t| t.borrow_mut().remove(&key.to_string()).is_some())
}

pub fn token_index_put(key: String) {
    TOKEN_INDEX.with(|t| t.borrow_mut().insert(key, ()));
}

pub fn token_index_remove(key: &str) {
    TOKEN_INDEX.with(|t| t.borrow_mut().remove(&key.to_string()));
}

/// At most `limit` index keys in `start..end`, in order.
pub fn token_index_range(start: &str, end: &str, limit: usize) -> Vec<String> {
    TOKEN_INDEX.with(|t| {
        t.borrow()
            .range(start.to_string()..end.to_string())
            .take(limit)
            .map(|e| e.key().clone())
            .collect()
    })
}

/// Every (key, value) whose key starts with `prefix`; "" for all of them.
pub fn token_entries(prefix: &str) -> Vec<(String, String)> {
    TOKENS.with(|t| {
        t.borrow()
            .range(prefix.to_string()..)
            .take_while(|e| e.key().starts_with(prefix))
            .map(|e| (e.key().clone(), e.value()))
            .collect()
    })
}

/// All refs of a repo, sorted by refname (git requires sorted advertisement).
pub fn list_refs(repo: &str) -> Vec<(String, Oid)> {
    let prefix = format!("{repo}\0");
    REFS.with(|r| {
        r.borrow()
            .range(prefix.clone()..)
            .take_while(|e| e.key().starts_with(&prefix))
            .map(|e| (e.key()[prefix.len()..].to_string(), e.value()))
            .collect()
    })
}

// --- the move to the git canister (transfer.rs) -----------------------------
//
// Pages of each map in key order, and the writes that take a page in on
// the other canister. An export carries values as they are stored (an
// object's type code, length and zlib stream), so the copy is byte for
// byte the original and the two digests can agree.

/// After `after`, or from the start.
fn from<K: Clone>(after: Option<&K>) -> Bound<K> {
    after.map_or(Bound::Unbounded, |k| Bound::Excluded(k.clone()))
}

pub fn export_repos(after: Option<&String>, budget: usize) -> Vec<(String, String)> {
    REPOS.with(|r| page(&r.borrow(), from(after), budget, |_| true, |k, v| k.len() + v.len()))
}

pub fn export_refs(after: Option<&String>, budget: usize) -> Vec<(String, Oid)> {
    REFS.with(|r| page(&r.borrow(), from(after), budget, |_| true, |k, _| k.len() + 20))
}

pub fn export_objects(after: Option<&Oid>, budget: usize) -> Vec<(Oid, Vec<u8>)> {
    OBJECTS.with(|o| page(&o.borrow(), from(after), budget, |_| true, |_, v| 20 + v.len()))
}

pub fn export_tokens(after: Option<&String>, budget: usize) -> Vec<(String, String)> {
    TOKENS.with(|t| page(&t.borrow(), from(after), budget, |_| true, |k, v| k.len() + v.len()))
}

/// A repo as another canister held it: its name and HEAD target. Its
/// label comes as its own record.
pub fn import_repo(name: String, head: String) {
    REPOS.with(|r| r.borrow_mut().insert(name, head));
}

/// A ref as another canister held it, by its full key ("<repo>\0<refname>").
pub fn import_ref(key: String, oid: Oid) -> Result<(), String> {
    if !key.contains('\0') {
        return Err(format!("a ref key names a repo and a ref: {key:?}"));
    }
    REFS.with(|r| r.borrow_mut().insert(key, oid));
    Ok(())
}

/// An object as another canister stored it. One already here is the same
/// object (content-addressed); a new one is taken only if its bytes are
/// what they claim: a known type code, a length that matches, and content
/// that hashes to `oid`.
pub fn import_object(oid: Oid, value: Vec<u8>) -> Result<(), String> {
    if has_object(&oid) {
        return Ok(());
    }
    let hex = oid_hex(&oid);
    if oid.as_slice().len() != 20 {
        return Err(format!("object {hex}: an oid is 20 bytes"));
    }
    if value.len() < 5 {
        return Err(format!("object {hex}: too short to be a stored object"));
    }
    let object_type = ObjectType::from_pack_code(value[0]).ok_or_else(|| format!("object {hex}: unknown type code {}", value[0]))?;
    let len = u32::from_le_bytes(value[1..5].try_into().unwrap()) as usize;
    let mut content = Vec::with_capacity(len);
    // One byte past the stated length is enough to know the stream lies;
    // a stream of zeros would otherwise inflate without bound.
    ZlibDecoder::new(&value[5..])
        .take(len as u64 + 1)
        .read_to_end(&mut content)
        .map_err(|e| format!("object {hex}: the stream does not inflate: {e}"))?;
    if content.len() != len {
        return Err(format!("object {hex}: inflates to {} bytes, {len} stated", content.len()));
    }
    if compute_oid(object_type, &content) != oid {
        return Err(format!("object {hex}: the content hashes to something else"));
    }
    OBJECTS.with(|o| o.borrow_mut().insert(oid, value));
    Ok(())
}

/// Every token record and index entry, gone: for an import that starts
/// over, since tokens are the one kind a frozen exporter can still lose
/// (a revoke, or a membership change through the mirrors).
pub fn clear_tokens() {
    TOKENS.with(|t| t.borrow_mut().clear_new());
    TOKEN_INDEX.with(|t| t.borrow_mut().clear_new());
}

// --- schema version ----------------------------------------------------------

/// Encoding version of OBJECTS values ([pack type code][content len u32 LE]
/// [zlib(content)] is schema 1). Bump on any layout change and add a
/// migration in check_schema_version. Pre-release encodings were never
/// deployed anywhere, so schema 1 is the first that can exist in stable
/// memory; the old layouts cannot be sniffed apart anyway (byte 1 of a
/// length-prefix-free value is the zlib magic 0x78, a valid length byte).
const SCHEMA_VERSION: u32 = 1;
const SCHEMA_KEY: &str = "schema";

pub fn init_schema_version() {
    crate::kv::set_bytes(SCHEMA_KEY, SCHEMA_VERSION.to_le_bytes().to_vec());
}

/// Run in post_upgrade: refuse to serve stable data written under a different
/// encoding - trapping here aborts the upgrade and leaves the old code
/// running, instead of misreading objects mid-request later.
pub fn check_schema_version() {
    let stored = crate::kv::get_bytes(SCHEMA_KEY).map(|b| u32::from_le_bytes(b.try_into().expect("schema marker is 4 bytes")));
    match stored {
        Some(v) if v == SCHEMA_VERSION => {}
        Some(v) => ic_cdk::trap(format!(
            "object store schema {v}, code expects {SCHEMA_VERSION}: migrate before upgrading"
        )),
        None if OBJECTS.with(|o| o.borrow().is_empty()) => init_schema_version(),
        None => ic_cdk::trap(
            "object store holds data without a schema marker (pre-release encoding): \
             reinstall and reseed",
        ),
    }
}

/// For tests, here and in the crates that test against this one: a commit
/// whose root tree holds one regular file `path` with `bytes`, on top of
/// `parent`, set as the repo's branch tip. The commit body is minimal (no
/// author): nothing here parses more than `tree` and `parent`.
#[cfg(any(test, feature = "testing"))]
pub fn commit_file_for_tests(repo: &str, path: &str, bytes: &[u8], parent: Option<Oid>) -> Oid {
    let blob = put_object(ObjectType::Blob, bytes);
    let mut root = Vec::new();
    root.extend_from_slice(format!("100644 {path}\0").as_bytes());
    root.extend_from_slice(blob.as_slice());
    let tree = put_object(ObjectType::Tree, &root);
    let parent = parent.map_or(String::new(), |p| format!("parent {}\n", oid_hex(&p)));
    let commit = format!("tree {}\n{parent}\n{}\n", oid_hex(&tree), bytes.len());
    let oid = put_object(ObjectType::Commit, commit.as_bytes());
    let branch = head_target(repo).expect("the repo exists");
    set_ref(repo, &branch, oid).expect("the ref is set");
    oid
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_git_types::labels::MAX_LABEL;

    #[test]
    fn repo_names_map_to_lower_kebab_labels() {
        for (name, label) in [
            ("ic-git", "ic-git"),
            ("My_App", "my-app"),
            ("app.v2", "app-v2"),
            ("a__b..c", "a-b-c"),
            ("_lead-", "lead"),
            ("X", "x"),
        ] {
            assert_eq!(repo_label(name).unwrap(), label, "{name}");
        }
        assert!(repo_label("_").is_err());
        assert!(repo_label("--").is_err());
        assert!(repo_label(&"a".repeat(MAX_LABEL)).is_ok());
        assert!(repo_label(&"a".repeat(MAX_LABEL + 1)).is_err());
    }

    /// A repo name is at most MAX_REPO_NAME characters, and a refused one
    /// leaves no trace.
    #[test]
    fn repo_names_are_bounded() {
        // Both label as "a-b"; only the length differs.
        assert!(check_new_repo(&format!("a{}b", "_".repeat(MAX_REPO_NAME - 2))).is_ok());
        let long = format!("a{}b", "_".repeat(MAX_REPO_NAME - 1));
        assert!(create_repo(&long).unwrap_err().contains("at most"));
        assert!(!repo_exists(&long));
    }

    /// A label is taken by the first repo that maps to it; every other
    /// spelling of it is refused, and a refused name leaves no trace.
    #[test]
    fn a_repo_label_is_unique() {
        create_repo("my-app").unwrap();
        assert_eq!(label_holder("my-app").as_deref(), Some("my-app"));
        for clash in ["My_App", "my.app", "MY-APP", "my__app"] {
            let err = create_repo(clash).unwrap_err();
            assert!(err.contains("'my-app'"), "{clash}: {err}");
            assert!(!repo_exists(clash));
        }
        assert!(create_repo("my-app").unwrap_err().contains("already exists"));
        create_repo("Other.Thing").unwrap();
        assert_eq!(label_holder("other-thing").as_deref(), Some("Other.Thing"));
    }

    #[test]
    fn object_roundtrip_and_oid() {
        let oid = put_object(ObjectType::Blob, b"hello");
        let canonical = get_object(&oid).unwrap();
        assert_eq!(canonical, b"blob 5\0hello");
        // The oid is the SHA-1 of the canonical form we reconstruct.
        let digest: [u8; 20] = Sha1::digest(&canonical).into();
        assert_eq!(digest.as_slice(), oid.as_slice());

        let (object_type, content) = get_object_parsed(&oid).unwrap();
        assert_eq!(object_type, ObjectType::Blob);
        assert_eq!(content, b"hello");
    }
}
