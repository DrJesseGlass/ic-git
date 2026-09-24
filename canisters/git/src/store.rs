//! Stable-memory object store, refs, and repo metadata.
//!
//! Objects are global (content-addressed, shared across repos); refs and repo
//! metadata are namespaced by repo name. Object values are stored as a 1-byte
//! packfile type code followed by zlib(content) - the same zlib stream a pack
//! entry carries, so the milestone-2 pack writer can serve objects without
//! recompressing.

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use ic_dev_kit_rs::storage;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Blob;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::cell::RefCell;
use std::io::{Read, Write};

type Memory = VirtualMemory<DefaultMemoryImpl>;

/// 20-byte SHA-1 object id.
pub type Oid = Blob<20>;

pub fn parse_oid(hex: &str) -> Result<Oid, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("bad oid: {e}"))?;
    // Length must be checked here, not left to Blob: `Blob<N>` is a MAXIMUM,
    // so `try_from` accepts anything 20 bytes or shorter and this function's
    // own error message would be a lie. A short Oid reaching the store (via
    // set_ref, say) would then violate the 20-byte invariant that
    // provenance::commit20 and the registry's bytes20 both depend on.
    if bytes.len() != 20 {
        return Err("oid must be 20 bytes".to_string());
    }
    Oid::try_from(bytes.as_slice()).map_err(|_| "oid must be 20 bytes".to_string())
}

pub fn oid_hex(oid: &Oid) -> String {
    hex::encode(oid.as_slice())
}

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

const MEM_OBJECTS: MemoryId = MemoryId::new(0);
const MEM_REFS: MemoryId = MemoryId::new(1);
const MEM_REPOS: MemoryId = MemoryId::new(2);
const MEM_META: MemoryId = MemoryId::new(3);
const MEM_TOKENS: MemoryId = MemoryId::new(4);
const MEM_ACCOUNTS: MemoryId = MemoryId::new(5);
const MEM_REPO_META: MemoryId = MemoryId::new(6);
const MEM_VOTES: MemoryId = MemoryId::new(7);
const MEM_TOKEN_INDEX: MemoryId = MemoryId::new(8);

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// oid -> [pack type code][content len u32 LE][zlib(content)]
    /// The length prefix lets the pack writer emit the entry size header
    /// without inflating the object.
    static OBJECTS: RefCell<StableBTreeMap<Oid, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_OBJECTS))),
    );

    /// "<repo>\0<refname>" -> oid
    static REFS: RefCell<StableBTreeMap<String, Oid, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_REFS))),
    );

    /// repo name -> HEAD symref target (e.g. "refs/heads/main")
    static REPOS: RefCell<StableBTreeMap<String, String, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_REPOS))),
    );

    /// Small key/value bucket for canister-level state (auth snapshot, ...),
    /// accessed through the dev kit's storage helpers.
    static META: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_META))),
    );

    /// hex(sha256(push token)) -> the token's record (tokens.rs owns the
    /// value format; a bare repo name before expiry existed).
    static TOKENS: RefCell<StableBTreeMap<String, String, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_TOKENS))),
    );

    /// Tenancy (see tenancy.rs): principal text -> JSON account.
    static ACCOUNTS: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_ACCOUNTS))),
    );

    /// Tenancy: repo name -> JSON repo metadata (owner, members, rent state).
    static REPO_META: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_REPO_META))),
    );

    /// Tenancy: "<repo>\0<subject key>" -> JSON list of ic_multisig::Approval
    /// (tenancy.rs owns the key and the record shape).
    static VOTES: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_VOTES))),
    );

    /// Secondary keys over TOKENS, so a repo's tokens and the expired ones
    /// are range reads rather than scans of every token (tokens.rs owns the
    /// key format).
    static TOKEN_INDEX: RefCell<StableBTreeMap<String, (), Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_TOKEN_INDEX))),
    );
}

// --- tenancy maps (JSON values; tenancy.rs owns the schemas) -----------------

pub fn account_get<T: serde::de::DeserializeOwned>(principal: &str) -> Option<T> {
    ACCOUNTS.with(|a| a.borrow().get(&principal.to_string()))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn account_set<T: serde::Serialize>(principal: &str, value: &T) {
    if let Ok(b) = serde_json::to_vec(value) {
        ACCOUNTS.with(|a| a.borrow_mut().insert(principal.to_string(), b));
    }
}

pub fn repo_meta_get<T: serde::de::DeserializeOwned>(repo: &str) -> Option<T> {
    REPO_META.with(|m| m.borrow().get(&repo.to_string()))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn repo_meta_set<T: serde::Serialize>(repo: &str, value: &T) {
    if let Ok(b) = serde_json::to_vec(value) {
        REPO_META.with(|m| m.borrow_mut().insert(repo.to_string(), b));
    }
}

/// Every repo that has tenancy metadata, with it decoded.
pub fn repo_meta_all<T: serde::de::DeserializeOwned>() -> Vec<(String, T)> {
    REPO_META.with(|m| {
        m.borrow()
            .iter()
            .filter_map(|e| serde_json::from_slice(&e.value()).ok().map(|v| (e.key().clone(), v)))
            .collect()
    })
}

fn vote_key(repo: &str, subject_key: &str) -> String {
    format!("{repo}\0{subject_key}")
}

pub fn votes_get<T: serde::de::DeserializeOwned>(repo: &str, subject_key: &str) -> Option<T> {
    VOTES.with(|v| v.borrow().get(&vote_key(repo, subject_key)))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn votes_set<T: serde::Serialize>(repo: &str, subject_key: &str, value: &T) {
    if let Ok(b) = serde_json::to_vec(value) {
        VOTES.with(|v| v.borrow_mut().insert(vote_key(repo, subject_key), b));
    }
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

/// Longest label a repo name may map to: ic-name-service's segment limit,
/// and DNS's.
pub const MAX_LABEL: usize = 63;

/// The lower-kebab label a repo name maps to: lowercased, '.' and '_' made
/// '-', runs of '-' collapsed, and '-' trimmed from both ends. "My_App"
/// and "my-app" map to the same "my-app". Refused when that leaves nothing
/// or more than MAX_LABEL bytes. It is what the repo is announced under in
/// ic-name-service (names.rs), whose names are lower kebab case only.
pub fn repo_label(name: &str) -> Result<String, String> {
    let mut label = String::with_capacity(name.len());
    for c in name.chars() {
        let c = match c {
            '.' | '_' | '-' => '-',
            c => c.to_ascii_lowercase(),
        };
        if !(c == '-' && label.ends_with('-')) {
            label.push(c);
        }
    }
    let label = label.trim_matches('-').to_string();
    if label.is_empty() || label.len() > MAX_LABEL {
        return Err(format!(
            "repo name '{name}' must map to a label of 1 to {MAX_LABEL} of a-z, 0-9 and '-' \
             (lowercased, '.' and '_' as '-')"
        ));
    }
    Ok(label)
}

fn label_key(label: &str) -> String {
    format!("label:{label}")
}

/// The repo holding a label, if any. Every repo created since labels
/// existed holds its own; `index_repo_labels` gives the older ones theirs.
pub fn label_holder(label: &str) -> Option<String> {
    meta_get_json(&label_key(label))
}

/// Create a repo. Its name must be new, and so must its label: once
/// "my-app" exists, "My_App" and "my.app" are refused, so every repo maps
/// to a label no other repo can take.
pub fn create_repo(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name.starts_with('.')
    {
        return Err("repo names: [A-Za-z0-9._-]+, not starting with '.'".into());
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
    REPOS.with(|r| r.borrow_mut().insert(name.to_string(), "refs/heads/main".to_string()));
    meta_set_json(&label_key(&label), &name);
    Ok(())
}

/// For post_upgrade: give every repo created before labels existed its
/// label, first by name order where two would share one (none do on
/// mainnet at the upgrade that introduces this). A repo left without a
/// label is not announced. Runs once, behind a marker.
pub fn index_repo_labels() {
    const MARKER: &str = "labels:indexed";
    if meta_get_json::<bool>(MARKER) == Some(true) {
        return;
    }
    for name in list_repos() {
        if let Ok(label) = repo_label(&name) {
            if label_holder(&label).is_none() {
                meta_set_json(&label_key(&label), &name);
            }
        }
    }
    meta_set_json(MARKER, &true);
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

pub fn set_ref(repo: &str, refname: &str, oid: Oid) -> Result<(), String> {
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

// --- canister-level state ----------------------------------------------------

pub fn save_auth_snapshot(bytes: Vec<u8>) {
    META.with(|m| storage::save_bytes(m, "auth", bytes));
}

pub fn load_auth_snapshot() -> Option<Vec<u8>> {
    META.with(|m| storage::load_bytes(m, "auth"))
}

// JSON-encoded values other modules (deploy, fleet) keep in the META bucket.
// The caller owns the key, including its namespace prefix, which keeps these
// out of the way of the auth/schema markers.

/// Signing-side callers (`evm.rs`, `sol.rs`) go through `crate::kv` instead,
/// which wraps this pair so their persistence has one swap point when the
/// signer splits out. See docs/CANISTER_SPLIT.md.
pub fn meta_set_json<T: serde::Serialize>(key: &str, value: &T) {
    if let Ok(bytes) = serde_json::to_vec(value) {
        META.with(|m| storage::save_bytes(m, key, bytes));
    }
}

pub fn meta_get_json<T: serde::de::DeserializeOwned>(key: &str) -> Option<T> {
    META.with(|m| storage::load_bytes(m, key)).and_then(|b| serde_json::from_slice(&b).ok())
}

/// Like `meta_get_json`, but tells "absent" apart from "present and
/// undecodable". `meta_get_json` collapses both to `None`, which is fine for a
/// config that can fall back to a default and catastrophic for an append-only
/// log: read-None, append, write-back silently replaces the whole history.
/// Callers that would destroy data on a decode failure must use this.
pub fn meta_try_get_json<T: serde::de::DeserializeOwned>(key: &str) -> Result<Option<T>, String> {
    match META.with(|m| storage::load_bytes(m, key)) {
        None => Ok(None),
        Some(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| format!("stored value at {key} did not decode: {e}")),
    }
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
    META.with(|m| storage::save_bytes(m, SCHEMA_KEY, SCHEMA_VERSION.to_le_bytes().to_vec()));
}

/// Run in post_upgrade: refuse to serve stable data written under a different
/// encoding - trapping here aborts the upgrade and leaves the old code
/// running, instead of misreading objects mid-request later.
pub fn check_schema_version() {
    let stored = META
        .with(|m| storage::load_bytes(m, SCHEMA_KEY))
        .map(|b| u32::from_le_bytes(b.try_into().expect("schema marker is 4 bytes")));
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Repos from before labels get theirs on upgrade, first by name order.
    #[test]
    fn upgrade_indexes_labels_of_older_repos() {
        REPOS.with(|r| {
            let mut r = r.borrow_mut();
            for n in ["Foo", "foo", "bar_baz"] {
                r.insert(n.to_string(), "refs/heads/main".to_string());
            }
        });
        index_repo_labels();
        assert_eq!(label_holder("foo").as_deref(), Some("Foo"));
        assert_eq!(label_holder("bar-baz").as_deref(), Some("bar_baz"));
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
