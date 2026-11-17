//! What changed between two trees: the files added, deleted, modified and
//! renamed, each with the blobs on either side (api.rs, `/diff`).
//!
//! The comparison is by object id, which is what git's own is: two trees
//! with the same id are the same tree, so a directory nobody touched is
//! never opened, and the walk reads the trees along the changed paths and
//! under what was added or deleted whole. Nothing here reads a blob: the
//! lines that changed inside a file are for whoever holds both blobs to
//! work out (the repo browser fetches them by commit and path).
//!
//! A rename is reported where git reports one without being asked to
//! look inside files: a deleted file and an added one with the same
//! content (the same blob id), and only when that content left one path
//! and arrived at one, so two copies of an empty file are never paired.
//! A file renamed and edited in one commit is a deletion and an addition.

use crate::object::{self, TreeEntry};
use crate::store::{self, ObjectType, Oid};
use std::collections::BTreeMap;

/// How deep a tree may nest and be compared: git's own path limit allows
/// far less, and the walk is a recursion.
const MAX_DEPTH: usize = 128;

/// One side of a change: the entry as the tree holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Side {
    pub mode: String,
    pub oid: Oid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Added,
    Deleted,
    Modified,
    Renamed,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Added => "added",
            Status::Deleted => "deleted",
            Status::Modified => "modified",
            Status::Renamed => "renamed",
        }
    }
}

/// One changed file (or symlink, or submodule: anything a tree holds that
/// is not a directory), by its path from the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub path: Vec<u8>,
    pub status: Status,
    /// Where a renamed file was.
    pub old_path: Option<Vec<u8>>,
    pub old: Option<Side>,
    pub new: Option<Side>,
}

pub struct TreeDiff {
    /// In path order.
    pub changes: Vec<Change>,
    /// There were more than the cap: `changes` is the first of them, and
    /// a rename whose other half lies past the cap shows as that half
    /// alone.
    pub truncated: bool,
}

fn is_dir(mode: &str) -> bool {
    mode == "40000" || mode == "040000"
}

fn entries(tree: Option<&Oid>) -> Result<BTreeMap<Vec<u8>, TreeEntry>, String> {
    let Some(oid) = tree else { return Ok(BTreeMap::new()) };
    let (ty, content) = store::get_object_parsed(oid).ok_or("tree object missing")?;
    if ty != ObjectType::Tree {
        return Err(format!("{} is not a tree", store::oid_hex(oid)));
    }
    Ok(object::tree_entries(&content)?.into_iter().map(|e| (e.name.clone(), e)).collect())
}

fn side(e: &TreeEntry) -> Side {
    Side { mode: e.mode.clone(), oid: e.oid }
}

struct Walk {
    changes: Vec<Change>,
    cap: usize,
    truncated: bool,
}

impl Walk {
    fn push(&mut self, path: Vec<u8>, status: Status, old: Option<&TreeEntry>, new: Option<&TreeEntry>) {
        if self.changes.len() >= self.cap {
            self.truncated = true;
            return;
        }
        self.changes.push(Change { path, status, old_path: None, old: old.map(side), new: new.map(side) });
    }

    /// Compare two directories at `prefix` (either may be absent: the
    /// other is then added or deleted whole).
    fn dir(&mut self, prefix: &[u8], old: Option<&Oid>, new: Option<&Oid>, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("tree nests too deep to compare".into());
        }
        let olds = entries(old)?;
        let news = entries(new)?;
        let names: std::collections::BTreeSet<&Vec<u8>> = olds.keys().chain(news.keys()).collect();
        for name in names {
            if self.truncated {
                return Ok(());
            }
            let mut path = prefix.to_vec();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            let (o, n) = (olds.get(name), news.get(name));
            if let (Some(o), Some(n)) = (o, n) {
                if o.oid == n.oid && o.mode == n.mode {
                    continue;
                }
            }
            let (o_dir, n_dir) = (o.filter(|e| is_dir(&e.mode)), n.filter(|e| is_dir(&e.mode)));
            let (o_file, n_file) = (o.filter(|e| !is_dir(&e.mode)), n.filter(|e| !is_dir(&e.mode)));
            // A file on one side and a directory on the other is the file
            // gone (or come) and the directory's files come (or gone).
            match (o_file, n_file) {
                (Some(o), Some(n)) => self.push(path.clone(), Status::Modified, Some(o), Some(n)),
                (Some(o), None) => self.push(path.clone(), Status::Deleted, Some(o), None),
                (None, Some(n)) => self.push(path.clone(), Status::Added, None, Some(n)),
                (None, None) => {}
            }
            if o_dir.is_some() || n_dir.is_some() {
                self.dir(&path, o_dir.map(|e| &e.oid), n_dir.map(|e| &e.oid), depth + 1)?;
            }
        }
        Ok(())
    }
}

/// The changes from tree `old` (none: the empty tree, as before a root
/// commit) to tree `new`, at most `cap` of them.
pub fn tree_diff(old: Option<&Oid>, new: &Oid, cap: usize) -> Result<TreeDiff, String> {
    let mut walk = Walk { changes: Vec::new(), cap, truncated: false };
    if old != Some(new) {
        walk.dir(b"", old, Some(new), 0)?;
    }
    let mut changes = renames(walk.changes);
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(TreeDiff { changes, truncated: walk.truncated })
}

/// Pair a deletion with an addition of the same blob, where the blob was
/// deleted at one path and added at one.
fn renames(changes: Vec<Change>) -> Vec<Change> {
    let mut deleted: BTreeMap<Oid, Vec<usize>> = BTreeMap::new();
    let mut added: BTreeMap<Oid, Vec<usize>> = BTreeMap::new();
    for (i, c) in changes.iter().enumerate() {
        match (c.status, &c.old, &c.new) {
            (Status::Deleted, Some(s), _) => deleted.entry(s.oid).or_default().push(i),
            (Status::Added, _, Some(s)) => added.entry(s.oid).or_default().push(i),
            _ => {}
        }
    }
    let mut from: BTreeMap<usize, usize> = BTreeMap::new();
    for (oid, dels) in &deleted {
        if let (&[d], Some(&[a])) = (dels.as_slice(), added.get(oid).map(Vec::as_slice)) {
            from.insert(a, d);
        }
    }
    let gone: std::collections::BTreeSet<usize> = from.values().copied().collect();
    let mut out = Vec::with_capacity(changes.len() - gone.len());
    for (i, c) in changes.iter().enumerate() {
        if gone.contains(&i) {
            continue;
        }
        let mut c = c.clone();
        if let Some(&d) = from.get(&i) {
            c.status = Status::Renamed;
            c.old_path = Some(changes[d].path.clone());
            c.old = changes[d].old.clone();
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(content: &[u8]) -> Oid {
        store::put_object(ObjectType::Blob, content)
    }

    fn tree(entries: &[(&str, &str, &Oid)]) -> Oid {
        let mut t = Vec::new();
        for (mode, name, oid) in entries {
            t.extend_from_slice(format!("{mode} {name}\0").as_bytes());
            t.extend_from_slice(oid.as_slice());
        }
        store::put_object(ObjectType::Tree, &t)
    }

    /// (status, path, old path) of each change.
    fn summary(d: &TreeDiff) -> Vec<(&'static str, String, Option<String>)> {
        let s = |p: &Vec<u8>| String::from_utf8_lossy(p).into_owned();
        d.changes.iter().map(|c| (c.status.as_str(), s(&c.path), c.old_path.as_ref().map(s))).collect()
    }

    fn row(status: &'static str, path: &str) -> (&'static str, String, Option<String>) {
        (status, path.to_string(), None)
    }

    #[test]
    fn the_same_tree_has_no_changes_and_a_first_tree_is_all_added() {
        let a = blob(b"a");
        let sub = tree(&[("100644", "b.txt", &a)]);
        let t = tree(&[("100644", "a.txt", &a), ("40000", "sub", &sub)]);
        assert!(tree_diff(Some(&t), &t, 100).unwrap().changes.is_empty());
        let d = tree_diff(None, &t, 100).unwrap();
        assert_eq!(summary(&d), [row("added", "a.txt"), row("added", "sub/b.txt")]);
        assert!(!d.truncated);
        assert_eq!(d.changes[0].old, None);
        assert_eq!(d.changes[0].new, Some(Side { mode: "100644".into(), oid: a }));
    }

    #[test]
    fn changes_are_found_by_id_under_the_directories_that_changed() {
        let (one, two, three) = (blob(b"one"), blob(b"two"), blob(b"three"));
        // `same` is in both trees under the same id; a tree object that is
        // not in the store stands for it, so opening it would fail.
        let same = Oid::try_from([7u8; 20].as_slice()).unwrap();
        let deep_old = tree(&[("100644", "x.txt", &one), ("100644", "y.txt", &two)]);
        let deep_new = tree(&[("100644", "x.txt", &three), ("100644", "z.txt", &three)]);
        let old = tree(&[("40000", "deep", &deep_old), ("100644", "gone.txt", &one), ("40000", "same", &same), ("100644", "stay.txt", &two)]);
        let new = tree(&[("40000", "deep", &deep_new), ("100644", "new.txt", &blob(b"new")), ("40000", "same", &same), ("100644", "stay.txt", &two)]);
        let d = tree_diff(Some(&old), &new, 100).unwrap();
        assert_eq!(
            summary(&d),
            [
                row("modified", "deep/x.txt"),
                row("deleted", "deep/y.txt"),
                row("added", "deep/z.txt"),
                row("deleted", "gone.txt"),
                row("added", "new.txt"),
            ]
        );
        let x = &d.changes[0];
        assert_eq!((x.old.as_ref().unwrap().oid, x.new.as_ref().unwrap().oid), (one, three));
    }

    #[test]
    fn a_mode_change_is_a_modification_and_a_file_become_a_directory_is_both() {
        let (a, b) = (blob(b"a"), blob(b"b"));
        let old = tree(&[("100644", "run.sh", &a), ("100644", "thing", &b)]);
        let inner = tree(&[("100644", "inside.txt", &b)]);
        let new = tree(&[("100755", "run.sh", &a), ("40000", "thing", &inner)]);
        let d = tree_diff(Some(&old), &new, 100).unwrap();
        // The file `thing` is gone and `thing/inside.txt` has come with its
        // content: one path each way, so it reads as the rename it is.
        assert_eq!(summary(&d), [row("modified", "run.sh"), ("renamed", "thing/inside.txt".to_string(), Some("thing".to_string()))]);
        let run = &d.changes[0];
        assert_eq!((run.old.as_ref().unwrap().mode.as_str(), run.new.as_ref().unwrap().mode.as_str()), ("100644", "100755"));
        assert_eq!(run.old.as_ref().unwrap().oid, run.new.as_ref().unwrap().oid);
        // And back: the directory gone, the file come, with other content.
        let back = tree(&[("100755", "run.sh", &a), ("100644", "thing", &a)]);
        let d = tree_diff(Some(&new), &back, 100).unwrap();
        assert_eq!(summary(&d), [row("added", "thing"), row("deleted", "thing/inside.txt")]);
    }

    #[test]
    fn a_rename_is_one_blob_gone_from_one_path_and_come_at_one() {
        let (a, b, empty) = (blob(b"content"), blob(b"other"), blob(b""));
        let old_dir = tree(&[("100644", "a.txt", &a)]);
        let old = tree(&[("40000", "old", &old_dir), ("100644", "e1", &empty), ("100644", "e2", &empty), ("100644", "keep", &b)]);
        let new_dir = tree(&[("100644", "moved.txt", &a)]);
        let new = tree(&[("100644", "f1", &empty), ("100644", "f2", &empty), ("100644", "keep", &b), ("40000", "new", &new_dir)]);
        let d = tree_diff(Some(&old), &new, 100).unwrap();
        // The two empty files went and two came: nothing says which is
        // which, so they stay deletions and additions.
        assert_eq!(
            summary(&d),
            [
                row("deleted", "e1"),
                row("deleted", "e2"),
                row("added", "f1"),
                row("added", "f2"),
                ("renamed", "new/moved.txt".to_string(), Some("old/a.txt".to_string())),
            ]
        );
        let moved = d.changes.last().unwrap();
        assert_eq!(moved.old, moved.new);
    }

    #[test]
    fn past_the_cap_the_first_changes_are_given_and_the_rest_said_to_be_missing() {
        let a = blob(b"a");
        let names: Vec<String> = (0..10).map(|i| format!("f{i}")).collect();
        let all: Vec<(&str, &str, &Oid)> = names.iter().map(|n| ("100644", n.as_str(), &a)).collect();
        let t = tree(&all);
        let d = tree_diff(None, &t, 4).unwrap();
        assert!(d.truncated);
        assert_eq!(d.changes.len(), 4);
        let d = tree_diff(None, &t, 10).unwrap();
        assert!(!d.truncated);
        assert_eq!(d.changes.len(), 10);
    }

    #[test]
    fn a_missing_tree_and_a_tree_too_deep_are_errors() {
        let missing = Oid::try_from([9u8; 20].as_slice()).unwrap();
        assert!(tree_diff(None, &missing, 10).is_err());
        let a = blob(b"a");
        assert!(tree_diff(None, &a, 10).is_err());
        let mut t = tree(&[("100644", "f", &a)]);
        for _ in 0..MAX_DEPTH + 1 {
            t = tree(&[("40000", "d", &t)]);
        }
        assert!(tree_diff(None, &t, 10).is_err());
    }
}
