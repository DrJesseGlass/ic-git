//! Proofs that a blob is what a commit holds at a path
//! (docs/CANISTER_SPLIT.md, section 4): the format and its checker, shared
//! by both sides of the boundary. The git side (`gitproof::prove` in the
//! canister crate) builds a proof from its object store; the authority
//! side runs `check`, a pure function of its arguments. It parses only
//! object headers, a commit's first line and tree entries -- no packs, no
//! deltas, no zlib, nothing beyond one path -- and it uses SHA-1 with
//! collision detection, as git does, so a crafted collision cannot stand in
//! for the object the voters approved.
//!
//! The rules are strict where git is lenient, because the checker decides
//! what reaches a governed backend: a path is plain components (no empty
//! ones, no `.` or `..`), every object's header must match its body
//! exactly, a tree on the path must not name the looked-up entry twice, the
//! entries on the way must be directories, and the last must be a regular
//! file (`100644` or `100755`; not a symlink, a submodule or a tree).

use candid::CandidType;
use serde::Deserialize;

/// The most path components a proof may walk.
pub const MAX_DEPTH: usize = 64;

/// One leg's artifact as a deploy job carries it: the bytes at the leg's
/// source path, and the proof that they are what the job's commit holds
/// there (the raw commit object, then each tree object on the path).
#[derive(CandidType, Deserialize)]
pub struct Artifact {
    pub blob: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
}

impl Artifact {
    /// The authority side: the blob, once its proof shows it is what
    /// `commit` holds at `path`. Reads nothing but its arguments.
    pub fn verified(self, commit: &[u8; 20], path: &str) -> Result<Vec<u8>, String> {
        check(commit, &plain(path), &self.blob, &self.proof)
            .map_err(|e| format!("proof of {path} refused: {e}"))?;
        Ok(self.blob)
    }
}

/// A source path without empty components, which the tree walk always
/// skipped (`/app.wasm` named `app.wasm`) and a proof's path does not allow.
pub fn plain(path: &str) -> String {
    path.split('/').filter(|c| !c.is_empty()).collect::<Vec<_>>().join("/")
}

/// Does `proof` show that `blob` is what commit `commit` holds at `path`?
/// The authority side of the boundary: reads nothing but its arguments.
pub fn check(commit: &[u8; 20], path: &str, blob: &[u8], proof: &[Vec<u8>]) -> Result<(), String> {
    let components = components(path)?;
    if proof.len() != components.len() + 1 {
        return Err(format!(
            "a proof for '{path}' needs {} objects, not {}",
            components.len() + 1,
            proof.len()
        ));
    }
    let body = object(&proof[0], "commit", commit)?;
    let mut expected = tree_of(body)?;
    for (i, name) in components.iter().enumerate() {
        let body = object(&proof[i + 1], "tree", &expected)?;
        let entry = lookup(body, name)?;
        let last = i + 1 == components.len();
        match (last, entry.mode) {
            (false, b"40000") => {}
            (false, _) => {
                return Err(format!("'{}' is not a directory", components[..=i].join("/")))
            }
            (true, b"100644" | b"100755") => {}
            (true, _) => return Err(format!("'{path}' is not a regular file")),
        }
        expected = entry.oid;
    }
    let id = git_id("blob", blob)?;
    if id != expected {
        return Err(format!("the blob is not what the commit holds at '{path}'"));
    }
    Ok(())
}

/// A path's components: plain names, at least one, at most MAX_DEPTH.
pub fn components(path: &str) -> Result<Vec<&str>, String> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_DEPTH {
        return Err(format!("a path may have at most {MAX_DEPTH} components"));
    }
    for p in &parts {
        if p.is_empty() || *p == "." || *p == ".." || p.contains('\0') {
            return Err(format!("'{path}' is not a plain relative path"));
        }
    }
    Ok(parts)
}

/// SHA-1 of `"<kind> <len>\0" + body`, refusing a detected collision.
pub fn git_id(kind: &str, body: &[u8]) -> Result<[u8; 20], String> {
    let mut h = sha1_checked::Sha1::new();
    sha1_checked::Digest::update(&mut h, format!("{kind} {}\0", body.len()).as_bytes());
    sha1_checked::Digest::update(&mut h, body);
    digest(h)
}

fn digest(h: sha1_checked::Sha1) -> Result<[u8; 20], String> {
    let r = h.try_finalize();
    if r.has_collision() {
        return Err("SHA-1 collision attack detected".into());
    }
    Ok((*r.hash()).into())
}

/// A canonical object: check its header against its body and its id
/// against `id`, and return the body.
fn object<'a>(raw: &'a [u8], kind: &str, id: &[u8; 20]) -> Result<&'a [u8], String> {
    let nul = raw.iter().position(|&b| b == 0).ok_or("an object has no header")?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "an object header is not text")?;
    let (ty, len) = header.split_once(' ').ok_or("malformed object header")?;
    if ty != kind {
        return Err(format!("expected a {kind} object, got a {ty}"));
    }
    let body = &raw[nul + 1..];
    if len.is_empty()
        || !len.bytes().all(|b| b.is_ascii_digit())
        || (len.len() > 1 && len.starts_with('0'))
        || len.parse::<usize>().ok() != Some(body.len())
    {
        return Err(format!("a {kind} object's length does not match its header"));
    }
    let mut h = sha1_checked::Sha1::new();
    sha1_checked::Digest::update(&mut h, raw);
    if digest(h)? != *id {
        return Err(format!("a {kind} object is not the one the proof names"));
    }
    Ok(body)
}

/// A commit's tree: its first line, `tree <40 lowercase hex>`, and the
/// only `tree` line in its header. `object::commit_refs`, which browsing and
/// the deploy resolver use, takes the *last* one, so a commit naming two
/// would have two readings; the proof certifies neither.
pub fn tree_of(commit: &[u8]) -> Result<[u8; 20], String> {
    let mut header = commit.split(|&b| b == b'\n').take_while(|l| !l.is_empty());
    let line = header.next().unwrap_or_default();
    if header.any(|l| l.starts_with(b"tree ")) {
        return Err("a commit names more than one tree".into());
    }
    let hex = line.strip_prefix(b"tree ").ok_or("a commit does not start with its tree")?;
    if hex.len() != 40 || !hex.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
        return Err("a commit's tree id is malformed".into());
    }
    let mut id = [0u8; 20];
    hex::decode_to_slice(hex, &mut id).map_err(|e| e.to_string())?;
    Ok(id)
}

#[derive(Debug)]
pub struct Entry<'a> {
    pub mode: &'a [u8],
    pub oid: [u8; 20],
}

/// The one entry named `name` in a tree body. Every entry must parse, and
/// the name must appear exactly once.
pub fn lookup<'a>(tree: &'a [u8], name: &str) -> Result<Entry<'a>, String> {
    let mut found = None;
    let mut i = 0;
    while i < tree.len() {
        let space = tree[i..].iter().position(|&b| b == b' ').ok_or("malformed tree entry")? + i;
        let mode = &tree[i..space];
        if mode.is_empty() || !mode.iter().all(|b| (b'0'..=b'7').contains(b)) {
            return Err("malformed tree entry mode".into());
        }
        let nul = tree[space..].iter().position(|&b| b == 0).ok_or("malformed tree entry")? + space;
        let entry_name = &tree[space + 1..nul];
        let oid: [u8; 20] = tree
            .get(nul + 1..nul + 21)
            .ok_or("truncated tree entry")?
            .try_into()
            .unwrap();
        if entry_name.is_empty() || entry_name.contains(&b'/') {
            return Err("malformed tree entry name".into());
        }
        if entry_name == name.as_bytes() {
            if found.is_some() {
                return Err(format!("a tree names '{name}' twice"));
            }
            found = Some(Entry { mode, oid });
        }
        i = nul + 21;
    }
    found.ok_or_else(|| format!("'{name}' is not in the tree"))
}

/// An object in git's canonical form: `"<kind> <len>\0" + body`.
pub fn canonical(kind: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!("{kind} {}\0", body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SHA-mbles chosen-prefix collision (sha1-checked's own test
    /// vector): its SHA-1 is computed, and the collision is detected.
    #[test]
    fn a_collision_attack_is_detected() {
        let shambles = include_bytes!("../testdata/sha-mbles-1.bin");
        let mut h = sha1_checked::Sha1::new();
        sha1_checked::Digest::update(&mut h, &shambles[..]);
        assert!(digest(h).unwrap_err().contains("collision"));
        // Ordinary data is not flagged.
        assert!(git_id("blob", b"plain").is_ok());
    }

    /// The ids git itself gives the empty blob and the empty tree, so the
    /// checker's hashing is held to git's and not only to this store's.
    #[test]
    fn ids_agree_with_git() {
        assert_eq!(hex::encode(git_id("blob", b"").unwrap()), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        assert_eq!(hex::encode(git_id("tree", b"").unwrap()), "4b825dc642cb6eb9a060e54bf8d69288fbee4904");
    }

    /// The tree walk always skipped empty components, so a configured
    /// `/app.wasm` keeps naming `app.wasm`.
    #[test]
    fn plain_drops_empty_components() {
        assert_eq!(plain("/build//app.wasm"), "build/app.wasm");
        assert_eq!(plain("app.wasm"), "app.wasm");
    }
}
