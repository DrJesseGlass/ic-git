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

    /// hex(sha256(push token)) -> repo name the token may push to.
    static TOKENS: RefCell<StableBTreeMap<String, String, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_TOKENS))),
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

pub fn create_repo(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name.starts_with('.')
    {
        return Err("repo names: [A-Za-z0-9._-]+, not starting with '.'".into());
    }
    REPOS.with(|r| {
        let mut repos = r.borrow_mut();
        let key = name.to_string();
        if repos.contains_key(&key) {
            return Err(format!("repo '{name}' already exists"));
        }
        repos.insert(key, "refs/heads/main".to_string());
        Ok(())
    })
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
fn token_key(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn add_push_token(repo: &str, token: &str) {
    TOKENS.with(|t| t.borrow_mut().insert(token_key(token), repo.to_string()));
}

/// The repo a presented token authorizes, if any.
pub fn push_token_repo(token: &str) -> Option<String> {
    TOKENS.with(|t| t.borrow().get(&token_key(token)))
}

pub fn revoke_push_token(token: &str) -> bool {
    TOKENS.with(|t| t.borrow_mut().remove(&token_key(token)).is_some())
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

pub fn meta_set_json<T: serde::Serialize>(key: &str, value: &T) {
    if let Ok(bytes) = serde_json::to_vec(value) {
        META.with(|m| storage::save_bytes(m, key, bytes));
    }
}

pub fn meta_get_json<T: serde::de::DeserializeOwned>(key: &str) -> Option<T> {
    META.with(|m| storage::load_bytes(m, key)).and_then(|b| serde_json::from_slice(&b).ok())
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
        Some(v) => ic_cdk::trap(&format!(
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
