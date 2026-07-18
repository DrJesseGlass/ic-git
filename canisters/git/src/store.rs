//! Stable-memory object store, refs, and repo metadata.
//!
//! Objects are global (content-addressed, shared across repos); refs and repo
//! metadata are namespaced by repo name. Object bodies are stored
//! zlib-deflated in canonical git form: `"<type> <len>\0" + content`.

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Blob;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use sha1::{Digest, Sha1};
use std::cell::RefCell;
use std::io::{Read, Write};

type Memory = VirtualMemory<DefaultMemoryImpl>;

/// 20-byte SHA-1 object id.
pub type Oid = Blob<20>;

const MEM_OBJECTS: MemoryId = MemoryId::new(0);
const MEM_REFS: MemoryId = MemoryId::new(1);
const MEM_REPOS: MemoryId = MemoryId::new(2);
const MEM_META: MemoryId = MemoryId::new(3);

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// oid -> zlib-deflated canonical object bytes
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

    /// Small key/value bucket for canister-level state (auth snapshot, ...).
    static META: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEM_META))),
    );
}

// --- objects ----------------------------------------------------------------

const OBJECT_TYPES: [&str; 4] = ["blob", "tree", "commit", "tag"];

/// Store a git object from its type and content. Returns the oid.
pub fn put_object(object_type: &str, content: &[u8]) -> Result<Oid, String> {
    if !OBJECT_TYPES.contains(&object_type) {
        return Err(format!("invalid object type: {object_type}"));
    }
    let mut canonical = format!("{object_type} {}\0", content.len()).into_bytes();
    canonical.extend_from_slice(content);
    put_canonical_object(&canonical)
}

/// Store canonical object bytes (`"<type> <len>\0" + content`). Returns the oid.
pub fn put_canonical_object(canonical: &[u8]) -> Result<Oid, String> {
    let digest: [u8; 20] = Sha1::digest(canonical).into();
    let oid = Oid::try_from(digest.as_slice()).unwrap();
    if !OBJECTS.with(|o| o.borrow().contains_key(&oid)) {
        OBJECTS.with(|o| o.borrow_mut().insert(oid, deflate(canonical)));
    }
    Ok(oid)
}

/// Fetch an object as canonical (inflated) bytes.
pub fn get_object(oid: &Oid) -> Option<Vec<u8>> {
    let compressed = OBJECTS.with(|o| o.borrow().get(oid))?;
    Some(inflate(&compressed).expect("stored object is valid zlib"))
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
        if repos.contains_key(&name.to_string()) {
            return Err(format!("repo '{name}' already exists"));
        }
        repos.insert(name.to_string(), "refs/heads/main".to_string());
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

// --- canister-level state ---------------------------------------------------

pub fn save_auth_snapshot(bytes: Vec<u8>) {
    META.with(|m| m.borrow_mut().insert("auth".to_string(), bytes));
}

pub fn load_auth_snapshot() -> Option<Vec<u8>> {
    META.with(|m| m.borrow().get(&"auth".to_string()))
}

// --- zlib helpers -----------------------------------------------------------

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).expect("in-memory write");
    enc.finish().expect("in-memory finish")
}

fn inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ZlibDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| format!("zlib: {e}"))?;
    Ok(out)
}
