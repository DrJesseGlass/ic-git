//! Git object-format parsers: commit/tag headers and tree entries.
//!
//! Kept separate from the upload-pack service module because later milestones
//! consume the parsed fields directly: the receive-pack fast-forward check
//! walks commit parents, and the deploy hook walks trees with entry names
//! and modes.

use crate::store::{self, Oid};

/// One tree entry: "<mode> <name>\0" + 20-byte sha on the wire.
pub struct TreeEntry {
    /// Octal mode string as stored, e.g. "100644", "40000" (directory).
    pub mode: String,
    /// Entry name; git allows arbitrary bytes except NUL and '/'.
    pub name: Vec<u8>,
    pub oid: Oid,
}

pub fn tree_entries(content: &[u8]) -> Result<Vec<TreeEntry>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < content.len() {
        let space = content[i..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or("malformed tree mode")?
            + i;
        let nul = content[space..]
            .iter()
            .position(|&b| b == 0)
            .ok_or("malformed tree entry")?
            + space;
        let sha = content.get(nul + 1..nul + 21).ok_or("malformed tree sha")?;
        out.push(TreeEntry {
            mode: std::str::from_utf8(&content[i..space])
                .map_err(|_| "non-ascii tree mode")?
                .to_string(),
            name: content[space + 1..nul].to_vec(),
            oid: Oid::try_from(sha).unwrap(),
        });
        i = nul + 21;
    }
    Ok(out)
}

pub struct CommitRefs {
    pub tree: Oid,
    pub parents: Vec<Oid>,
}

pub fn commit_refs(content: &[u8]) -> Result<CommitRefs, String> {
    let mut tree = None;
    let mut parents = Vec::new();
    for line in header_lines(content) {
        let line = std::str::from_utf8(line).map_err(|_| "non-utf8 commit header")?;
        if let Some(hex) = line.strip_prefix("tree ") {
            tree = Some(store::parse_oid(hex.get(..40).ok_or("short tree line")?)?);
        } else if let Some(hex) = line.strip_prefix("parent ") {
            parents.push(store::parse_oid(hex.get(..40).ok_or("short parent line")?)?);
        }
    }
    Ok(CommitRefs {
        tree: tree.ok_or("commit without tree")?,
        parents,
    })
}

/// The object an annotated tag points at.
pub fn tag_target(content: &[u8]) -> Result<Oid, String> {
    for line in header_lines(content) {
        let line = std::str::from_utf8(line).map_err(|_| "non-utf8 tag header")?;
        if let Some(hex) = line.strip_prefix("object ") {
            return store::parse_oid(hex.get(..40).ok_or("short object line")?);
        }
    }
    Err("tag without object".into())
}

/// Header lines: everything up to the first empty line.
fn header_lines(content: &[u8]) -> impl Iterator<Item = &[u8]> {
    let header_end = content
        .windows(2)
        .position(|w| w == b"\n\n")
        .unwrap_or(content.len());
    content[..header_end].split(|&b| b == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ObjectType;

    #[test]
    fn parses_commit_tree_and_tag() {
        let blob = store::put_object(ObjectType::Blob, b"x");
        let mut tree = Vec::new();
        tree.extend_from_slice(b"100644 a.txt\0");
        tree.extend_from_slice(blob.as_slice());
        let tree_oid = store::put_object(ObjectType::Tree, &tree);

        let entries = tree_entries(&tree).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mode, "100644");
        assert_eq!(entries[0].name, b"a.txt");
        assert_eq!(entries[0].oid, blob);

        let commit = format!(
            "tree {}\nparent {}\nauthor a <a@a> 0 +0000\n\nmsg\n",
            store::oid_hex(&tree_oid),
            store::oid_hex(&blob), // any 40-hex works for parsing
        );
        let refs = commit_refs(commit.as_bytes()).unwrap();
        assert_eq!(refs.tree, tree_oid);
        assert_eq!(refs.parents, vec![blob]);

        let tag = format!("object {}\ntype commit\ntag v1\n\nmsg\n", store::oid_hex(&tree_oid));
        assert_eq!(tag_target(tag.as_bytes()).unwrap(), tree_oid);
    }
}
