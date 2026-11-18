//! Where two commits' histories part: their merge base, and the commits
//! each has that the other has not (api.rs, `/compare`).
//!
//! This is what a comparison of a branch with another starts from: what
//! the branch changed is its tree against the merge base's, not against
//! the other branch's tip, which has moved on since; and the commits it
//! would bring are the ones only it reaches.
//!
//! The walk is git's own for a merge base: from both commits at once,
//! newest first by the committer's clock, each commit painted with the
//! sides that reach it, stopping when everything left to visit is behind
//! a common ancestor already found. So two branches that parted a few
//! commits ago cost a few commits, however long the history under them.
//! It is bounded by the commits it loads: past the bound there is no
//! answer rather than a wrong one.
//!
//! Clocks lie: a commit dated before its parent is visited late, after
//! the walk has counted its ancestors for one side alone. A second pass
//! over what was visited carries each side's paint down to them, so the
//! counts are right for every commit the walk saw.

use crate::object;
use crate::store::{self, ObjectType, Oid};
use std::collections::{BTreeMap, BinaryHeap};

const HEAD: u8 = 1;
const BASE: u8 = 2;
const STALE: u8 = 4;
const RESULT: u8 = 8;
const BOTH: u8 = HEAD | BASE;

pub struct Compared {
    /// The newest common ancestor; none for two histories that share
    /// nothing. Where histories crossed and there are several, the one
    /// the walk met first.
    pub merge_base: Option<Oid>,
    /// The commits only `head` reaches, newest first.
    pub ahead: Vec<Oid>,
    /// How many only `base` reaches.
    pub behind: usize,
}

struct Node {
    parents: Vec<Oid>,
    time: u64,
    flags: u8,
}

/// A commit's parents and its committer's time (0 where there is none to
/// read: a hand-made commit).
fn load(oid: &Oid) -> Result<(Vec<Oid>, u64), String> {
    let (ty, content) = store::get_object_parsed(oid).ok_or("commit object missing")?;
    if ty != ObjectType::Commit {
        return Err(format!("{} is not a commit", store::oid_hex(oid)));
    }
    let parents = object::commit_refs(&content)?.parents;
    let time = object::commit_meta(&content)
        .committer
        .and_then(|c| c.rsplit_once('>').and_then(|(_, rest)| rest.split_whitespace().next().and_then(|t| t.parse().ok())))
        .unwrap_or(0);
    Ok((parents, time))
}

/// Compare `head` with `base`, loading at most `cap` commits: `None` past
/// that.
pub fn compare(base: &Oid, head: &Oid, cap: usize) -> Result<Option<Compared>, String> {
    let mut nodes: BTreeMap<Oid, Node> = BTreeMap::new();
    // Newest first; the counter keeps the order of equal times that of
    // their being found.
    let mut queue: BinaryHeap<(u64, std::cmp::Reverse<usize>, Oid)> = BinaryHeap::new();
    let mut seq = 0usize;
    let mut results: Vec<Oid> = Vec::new();
    // Paint `oid` with `flags` and queue it, if that is news to it.
    macro_rules! paint {
        ($oid:expr, $flags:expr) => {{
            let (oid, flags): (Oid, u8) = ($oid, $flags);
            if !nodes.contains_key(&oid) {
                if nodes.len() >= cap {
                    return Ok(None);
                }
                let (parents, time) = load(&oid)?;
                nodes.insert(oid, Node { parents, time, flags: 0 });
            }
            let node = nodes.get_mut(&oid).expect("just inserted");
            if node.flags & flags != flags {
                node.flags |= flags;
                seq += 1;
                queue.push((node.time, std::cmp::Reverse(seq), oid));
            }
        }};
    }
    paint!(*head, HEAD);
    paint!(*base, BASE);
    while queue.iter().any(|(_, _, oid)| nodes[oid].flags & STALE == 0) {
        let Some((_, _, oid)) = queue.pop() else { break };
        let node = &mut nodes.get_mut(&oid).expect("queued commits are loaded");
        let mut down = node.flags & (BOTH | STALE);
        if down & BOTH == BOTH {
            if node.flags & RESULT == 0 {
                node.flags |= RESULT;
                results.push(oid);
            }
            // What lies under a common ancestor is no newer one.
            down |= STALE;
        }
        for parent in node.parents.clone() {
            paint!(parent, down);
        }
    }
    // Each side's paint, down to every commit the walk saw.
    for side in [HEAD, BASE] {
        let mut stack: Vec<Oid> = nodes.iter().filter(|(_, n)| n.flags & side != 0).map(|(oid, _)| *oid).collect();
        while let Some(oid) = stack.pop() {
            for parent in nodes[&oid].parents.clone() {
                if let Some(p) = nodes.get_mut(&parent) {
                    if p.flags & side == 0 {
                        p.flags |= side;
                        stack.push(parent);
                    }
                }
            }
        }
    }
    let merge_base = results.into_iter().find(|oid| nodes[oid].flags & STALE == 0);
    let mut ahead: Vec<(u64, Oid)> = nodes.iter().filter(|(_, n)| n.flags & BOTH == HEAD).map(|(oid, n)| (n.time, *oid)).collect();
    ahead.sort_by(|a, b| b.0.cmp(&a.0));
    let ahead = order(ahead, &nodes);
    let behind = nodes.values().filter(|n| n.flags & BOTH == BASE).count();
    Ok(Some(Compared { merge_base, ahead, behind }))
}

/// Newest first, and never a commit before one that descends from it,
/// whatever the clocks said: a parent listed above its child is moved
/// below it.
fn order(by_time: Vec<(u64, Oid)>, nodes: &BTreeMap<Oid, Node>) -> Vec<Oid> {
    let listed: BTreeMap<Oid, usize> = by_time.iter().enumerate().map(|(i, (_, oid))| (*oid, i)).collect();
    // How many listed children each commit still waits for.
    let mut waits: BTreeMap<Oid, usize> = listed.keys().map(|oid| (*oid, 0)).collect();
    for oid in listed.keys() {
        for p in &nodes[oid].parents {
            if let Some(w) = waits.get_mut(p) {
                *w += 1;
            }
        }
    }
    let mut ready: BinaryHeap<std::cmp::Reverse<(usize, Oid)>> =
        waits.iter().filter(|(_, w)| **w == 0).map(|(oid, _)| std::cmp::Reverse((listed[oid], *oid))).collect();
    let mut out = Vec::with_capacity(by_time.len());
    while let Some(std::cmp::Reverse((_, oid))) = ready.pop() {
        out.push(oid);
        for p in &nodes[&oid].parents {
            if let Some(w) = waits.get_mut(p) {
                *w -= 1;
                if *w == 0 {
                    ready.push(std::cmp::Reverse((listed[p], *p)));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A commit of `parents` at `time`; `tag` tells two apart.
    fn commit(tag: &str, parents: &[&Oid], time: u64) -> Oid {
        let tree = store::put_object(ObjectType::Tree, b"");
        let mut c = format!("tree {}\n", store::oid_hex(&tree));
        for p in parents {
            c.push_str(&format!("parent {}\n", store::oid_hex(p)));
        }
        c.push_str(&format!("author a <a@a> {time} +0000\ncommitter a <a@a> {time} +0000\n\n{tag}\n"));
        store::put_object(ObjectType::Commit, c.as_bytes())
    }

    fn cmp(base: &Oid, head: &Oid) -> Compared {
        compare(base, head, 1000).unwrap().expect("within the bound")
    }

    #[test]
    fn a_branch_off_main_is_compared_from_where_it_left() {
        // a - b - c - d      main
        //      \
        //       x - y        branch
        let a = commit("a", &[], 10);
        let b = commit("b", &[&a], 20);
        let c = commit("c", &[&b], 30);
        let d = commit("d", &[&c], 40);
        let x = commit("x", &[&b], 35);
        let y = commit("y", &[&x], 45);
        let r = cmp(&d, &y);
        assert_eq!(r.merge_base, Some(b));
        assert_eq!(r.ahead, [y, x]);
        assert_eq!(r.behind, 2);
        // The other way round.
        let r = cmp(&y, &d);
        assert_eq!(r.merge_base, Some(b));
        assert_eq!(r.ahead, [d, c]);
        assert_eq!(r.behind, 2);
        // A commit with itself; with its ancestor; with its descendant.
        let r = cmp(&d, &d);
        assert_eq!((r.merge_base, r.ahead.len(), r.behind), (Some(d), 0, 0));
        let r = cmp(&b, &d);
        assert_eq!((r.merge_base, r.ahead.clone(), r.behind), (Some(b), vec![d, c], 0));
        let r = cmp(&d, &b);
        assert_eq!((r.merge_base, r.ahead.len(), r.behind), (Some(b), 0, 2));
    }

    #[test]
    fn two_histories_that_share_nothing_have_no_merge_base() {
        let a = commit("one", &[], 10);
        let b = commit("one-b", &[&a], 20);
        let z = commit("other", &[], 15);
        let r = cmp(&b, &z);
        assert_eq!(r.merge_base, None);
        assert_eq!(r.ahead, [z]);
        assert_eq!(r.behind, 2);
    }

    #[test]
    fn a_branch_that_merged_main_in_is_compared_from_the_merge() {
        // a - b - c ----- e   main
        //      \    \
        //       x --- m - y   branch (m merges c)
        let a = commit("a", &[], 10);
        let b = commit("b", &[&a], 20);
        let c = commit("c", &[&b], 30);
        let e = commit("e", &[&c], 60);
        let x = commit("x", &[&b], 25);
        let m = commit("m", &[&x, &c], 40);
        let y = commit("y", &[&m], 50);
        let r = cmp(&e, &y);
        assert_eq!(r.merge_base, Some(c));
        assert_eq!(r.ahead, [y, m, x]);
        assert_eq!(r.behind, 1);
    }

    #[test]
    fn a_clock_that_ran_backwards_does_not_change_the_answer() {
        // The same shape as the first test, with b dated after everything
        // and x before everything: the walk meets them out of order.
        let a = commit("a", &[], 10);
        let b = commit("b late", &[&a], 900);
        let c = commit("c", &[&b], 30);
        let d = commit("d", &[&c], 40);
        let x = commit("x early", &[&b], 1);
        let y = commit("y", &[&x], 45);
        let r = cmp(&d, &y);
        assert_eq!(r.merge_base, Some(b));
        // Newest first, but never a parent above its child.
        assert_eq!(r.ahead, [y, x]);
        assert_eq!(r.behind, 2);
        // A parent dated after its child, both on the branch.
        let p = commit("p late", &[&b], 800);
        let q = commit("q early", &[&p], 5);
        let r = cmp(&d, &q);
        assert_eq!(r.merge_base, Some(b));
        assert_eq!(r.ahead, [q, p]);
    }

    #[test]
    fn the_walk_stops_near_where_they_part_and_past_its_bound_gives_no_answer() {
        // A long history, and two tips a commit each off its end.
        let mut tip = commit("root", &[], 1);
        for i in 0..200u64 {
            tip = commit(&format!("n{i}"), &[&tip], 10 + i);
        }
        let left = commit("left", &[&tip], 500);
        let right = commit("right", &[&tip], 501);
        // Four commits loaded would do; a bound of eight is plenty, and
        // the 200 under them are never read.
        let r = compare(&left, &right, 8).unwrap().expect("near the tips");
        assert_eq!((r.merge_base, r.ahead, r.behind), (Some(tip), vec![right], 1));
        // The root against a tip is the whole history.
        let root_side = commit("lonely", &[], 2);
        assert!(compare(&root_side, &right, 50).unwrap().is_none());
        // Something that is no commit is an error.
        let blob = store::put_object(ObjectType::Blob, b"x");
        assert!(compare(&blob, &right, 50).is_err());
    }
}
