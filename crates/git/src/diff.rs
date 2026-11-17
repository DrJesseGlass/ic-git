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
//! look inside files: a deleted file and an added one of the same kind
//! with the same content (the same blob id), and only when that content
//! left one path and arrived at one, so two copies of an empty file are
//! never paired. A file renamed and edited in one commit is a deletion
//! and an addition.
//!
//! The changes come in path order (bytes, a directory's files at its
//! name with the slash, which is the order git keeps a tree in), and the
//! walk is bounded twice: by the changes it lists and by the directories
//! it opens, since a pushed tree can name one small directory at many
//! paths and be vast with no file in it. Past either bound the answer is
//! the first of the changes, marked truncated, with no renames paired:
//! the other path of one may lie in what was not walked.

use crate::object::{self, is_tree_mode, TreeEntry};
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
    /// The walk stopped at a bound: `changes` is the first of them, in
    /// path order, and a rename among them shows as its two halves.
    pub truncated: bool,
}

/// The bounds of one walk.
#[derive(Clone, Copy)]
pub struct Limits {
    /// The changes listed.
    pub changes: usize,
    /// The directories opened, on either side.
    pub dirs: usize,
}

/// A directory's entries by the name git orders them by: a directory's
/// with a slash after it. So a file and a directory of one name are two
/// entries, and the order of the walk is the order of the paths.
fn entries(tree: Option<&Oid>) -> Result<BTreeMap<Vec<u8>, TreeEntry>, String> {
    let Some(oid) = tree else { return Ok(BTreeMap::new()) };
    let (ty, content) = store::get_object_parsed(oid).ok_or("tree object missing")?;
    if ty != ObjectType::Tree {
        return Err(format!("{} is not a tree", store::oid_hex(oid)));
    }
    Ok(object::tree_entries(&content)?
        .into_iter()
        .map(|e| {
            let mut key = e.name.clone();
            if is_tree_mode(&e.mode) {
                key.push(b'/');
            }
            (key, e)
        })
        .collect())
}

/// What an entry that is not a directory is: a file (whatever its
/// permission bits), a symlink, a submodule.
fn file_kind(mode: &str) -> &str {
    if mode.starts_with("100") {
        "100"
    } else {
        mode
    }
}

fn side(e: &TreeEntry) -> Side {
    Side { mode: e.mode.clone(), oid: e.oid }
}

struct Walk {
    changes: Vec<Change>,
    limits: Limits,
    dirs: usize,
    truncated: bool,
}

impl Walk {
    fn push(&mut self, path: Vec<u8>, status: Status, old: Option<&TreeEntry>, new: Option<&TreeEntry>) {
        if self.changes.len() >= self.limits.changes {
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
        self.dirs += old.is_some() as usize + new.is_some() as usize;
        if self.dirs > self.limits.dirs {
            self.truncated = true;
            return Ok(());
        }
        let olds = entries(old)?;
        let news = entries(new)?;
        let keys: std::collections::BTreeSet<&Vec<u8>> = olds.keys().chain(news.keys()).collect();
        for key in keys {
            if self.truncated {
                return Ok(());
            }
            let (o, n) = (olds.get(key), news.get(key));
            if let (Some(o), Some(n)) = (o, n) {
                if o.oid == n.oid && o.mode == n.mode {
                    continue;
                }
            }
            let mut path = prefix.to_vec();
            path.extend_from_slice(key);
            if key.last() == Some(&b'/') {
                self.dir(&path, o.map(|e| &e.oid), n.map(|e| &e.oid), depth + 1)?;
                continue;
            }
            let status = match (o, n) {
                (Some(_), Some(_)) => Status::Modified,
                (Some(_), None) => Status::Deleted,
                _ => Status::Added,
            };
            self.push(path, status, o, n);
        }
        Ok(())
    }
}

/// The changes from tree `old` (none: the empty tree, as before a root
/// commit) to tree `new`, within `limits`.
pub fn tree_diff(old: Option<&Oid>, new: &Oid, limits: Limits) -> Result<TreeDiff, String> {
    let mut walk = Walk { changes: Vec::new(), limits, dirs: 0, truncated: false };
    if old != Some(new) {
        walk.dir(b"", old, Some(new), 0)?;
    }
    let changes = if walk.truncated { walk.changes } else { renames(walk.changes) };
    Ok(TreeDiff { changes, truncated: walk.truncated })
}

/// Pair a deletion with an addition of the same blob and kind, where the
/// blob was deleted at one path and added at one. The list is the whole
/// of the changes: with some missing, "at one path" could not be said.
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
    // Addition -> the deletion it is the other half of.
    let mut from: BTreeMap<usize, usize> = BTreeMap::new();
    for (oid, dels) in &deleted {
        if let (&[d], Some(&[a])) = (dels.as_slice(), added.get(oid).map(Vec::as_slice)) {
            let kind = |s: &Option<Side>| s.as_ref().map(|s| file_kind(&s.mode).to_string());
            if kind(&changes[d].old) == kind(&changes[a].new) {
                from.insert(a, d);
            }
        }
    }
    if from.is_empty() {
        return changes;
    }
    let mut slots: Vec<Option<Change>> = changes.into_iter().map(Some).collect();
    let halves: Vec<(usize, Change)> = from.iter().filter_map(|(&a, &d)| slots[d].take().map(|c| (a, c))).collect();
    for (a, gone) in halves {
        if let Some(c) = slots[a].as_mut() {
            c.status = Status::Renamed;
            c.old_path = Some(gone.path);
            c.old = gone.old;
        }
    }
    slots.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDE: Limits = Limits { changes: 100, dirs: 100 };

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
        assert!(tree_diff(Some(&t), &t, WIDE).unwrap().changes.is_empty());
        let d = tree_diff(None, &t, WIDE).unwrap();
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
        let d = tree_diff(Some(&old), &new, WIDE).unwrap();
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
        let d = tree_diff(Some(&old), &new, WIDE).unwrap();
        // The file `thing` is gone and `thing/inside.txt` has come with its
        // content: one path each way, so it reads as the rename it is.
        assert_eq!(summary(&d), [row("modified", "run.sh"), ("renamed", "thing/inside.txt".to_string(), Some("thing".to_string()))]);
        let run = &d.changes[0];
        assert_eq!((run.old.as_ref().unwrap().mode.as_str(), run.new.as_ref().unwrap().mode.as_str()), ("100644", "100755"));
        assert_eq!(run.old.as_ref().unwrap().oid, run.new.as_ref().unwrap().oid);
        // And back: the directory gone, the file come, with other content.
        let back = tree(&[("100755", "run.sh", &a), ("100644", "thing", &a)]);
        let d = tree_diff(Some(&new), &back, WIDE).unwrap();
        assert_eq!(summary(&d), [row("added", "thing"), row("deleted", "thing/inside.txt")]);
    }

    #[test]
    fn a_rename_is_one_blob_gone_from_one_path_and_come_at_one() {
        let (a, b, empty) = (blob(b"content"), blob(b"other"), blob(b""));
        let old_dir = tree(&[("100644", "a.txt", &a)]);
        let old = tree(&[("40000", "old", &old_dir), ("100644", "e1", &empty), ("100644", "e2", &empty), ("100644", "keep", &b)]);
        let new_dir = tree(&[("100644", "moved.txt", &a)]);
        let new = tree(&[("100644", "f1", &empty), ("100644", "f2", &empty), ("100644", "keep", &b), ("40000", "new", &new_dir)]);
        let d = tree_diff(Some(&old), &new, WIDE).unwrap();
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
        let d = tree_diff(None, &t, Limits { changes: 4, dirs: 100 }).unwrap();
        assert!(d.truncated);
        assert_eq!(d.changes.len(), 4);
        let d = tree_diff(None, &t, Limits { changes: 10, dirs: 100 }).unwrap();
        assert!(!d.truncated);
        assert_eq!(d.changes.len(), 10);
    }

    #[test]
    fn the_changes_come_in_path_order_and_a_cut_list_is_the_first_of_them() {
        let a = blob(b"a");
        let dir = tree(&[("100644", "1", &a), ("100644", "2", &a)]);
        // In a tree git keeps `a` the directory after `a-b` and `a.txt`
        // and before `a0`: as the paths under it sort.
        let t = tree(&[("100644", "a-b", &a), ("100644", "a.txt", &a), ("40000", "a", &dir), ("100644", "a0", &a)]);
        let d = tree_diff(None, &t, WIDE).unwrap();
        let paths: Vec<String> = d.changes.iter().map(|c| String::from_utf8_lossy(&c.path).into_owned()).collect();
        assert_eq!(paths, ["a-b", "a.txt", "a/1", "a/2", "a0"]);
        let mut sorted = d.changes.iter().map(|c| c.path.clone()).collect::<Vec<_>>();
        sorted.sort();
        assert_eq!(sorted, d.changes.iter().map(|c| c.path.clone()).collect::<Vec<_>>());
        let cut = tree_diff(None, &t, Limits { changes: 3, dirs: 100 }).unwrap();
        assert!(cut.truncated);
        assert_eq!(cut.changes, d.changes[..3]);
    }

    #[test]
    fn a_cut_list_pairs_no_renames_and_kinds_do_not_pair() {
        // X goes from a/x and comes at b/x and zz/x: no rename. Cut before
        // zz/x, one of each is in view; they are not paired.
        let x = blob(b"x");
        let one = tree(&[("100644", "x", &x)]);
        let old = tree(&[("40000", "a", &one)]);
        let new = tree(&[("40000", "b", &one), ("40000", "zz", &one)]);
        let whole = tree_diff(Some(&old), &new, WIDE).unwrap();
        assert_eq!(summary(&whole), [row("deleted", "a/x"), row("added", "b/x"), row("added", "zz/x")]);
        let cut = tree_diff(Some(&old), &new, Limits { changes: 2, dirs: 100 }).unwrap();
        assert!(cut.truncated);
        assert_eq!(summary(&cut), [row("deleted", "a/x"), row("added", "b/x")]);
        // A symlink gone and a file come with the same bytes: not a rename.
        // A file that moved and became executable: one.
        let old = tree(&[("120000", "link", &x), ("100644", "tool", &blob(b"run"))]);
        let new = tree(&[("100644", "notes", &x), ("100755", "bin", &blob(b"run"))]);
        let d = tree_diff(Some(&old), &new, WIDE).unwrap();
        assert_eq!(summary(&d), [("renamed", "bin".to_string(), Some("tool".to_string())), row("deleted", "link"), row("added", "notes")]);
    }

    #[test]
    fn a_tree_that_is_vast_with_no_file_in_it_stops_at_the_bound_on_directories() {
        // Each level names the one below at two paths: 2^24 directories
        // from 25 objects, and not one file.
        let mut t = tree(&[]);
        for _ in 0..24 {
            t = tree(&[("40000", "a", &t), ("40000", "b", &t)]);
        }
        let d = tree_diff(None, &t, Limits { changes: 100, dirs: 500 }).unwrap();
        assert!(d.truncated);
        assert!(d.changes.is_empty());
        // The same on both sides is no walk at all.
        assert!(!tree_diff(Some(&t), &t, Limits { changes: 100, dirs: 500 }).unwrap().truncated);
    }

    #[test]
    fn a_missing_tree_and_a_tree_too_deep_are_errors() {
        let missing = Oid::try_from([9u8; 20].as_slice()).unwrap();
        assert!(tree_diff(None, &missing, WIDE).is_err());
        let a = blob(b"a");
        assert!(tree_diff(None, &a, WIDE).is_err());
        let mut t = tree(&[("100644", "f", &a)]);
        for _ in 0..MAX_DEPTH + 1 {
            t = tree(&[("40000", "d", &t)]);
        }
        assert!(tree_diff(None, &t, Limits { changes: 100, dirs: 1000 }).is_err());
    }
}
