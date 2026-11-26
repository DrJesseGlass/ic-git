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
//! Clocks lie, and a walk that stops early trusts them: a commit dated
//! before its ancestors is met late, after they were counted for one side
//! alone or taken for the merge base. Two things are done about it, as
//! git does. The walk goes on for `SLOP` commits past the point where it
//! could stop, and a second pass carries each side's paint, and what lies
//! under a common ancestor, down through every commit that was loaded.
//! What is left is a commit dated before an ancestor, or in the same
//! second as it (a rebase stamps a run of commits with one), more than
//! `SLOP` commits further down than the walk went: there the counts can be over
//! and the merge base an older common ancestor than the newest. Git
//! without its commit graph has the same edge.

use crate::object;
use crate::store::{self, ObjectType, Oid};
use ic_git_types::git_side::{Standing, MAX_STANDINGS};
use std::collections::{BTreeMap, BinaryHeap};

const HEAD: u8 = 1;
const BASE: u8 = 2;
const STALE: u8 = 4;
const RESULT: u8 = 8;
const BOTH: u8 = HEAD | BASE;

/// How many commits the walk visits past the point where every one left
/// is under a common ancestor: what a clock that ran backwards by that
/// many commits cannot hide.
const SLOP: usize = 64;

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
    /// How many times it is in the queue.
    queued: usize,
}

/// A commit's parents and its committer's time (0 where there is none to
/// read: a hand-made commit).
fn load(oid: &Oid) -> Result<(Vec<Oid>, u64), String> {
    let (ty, content) = store::get_object_parsed(oid).ok_or("commit object missing")?;
    if ty != ObjectType::Commit {
        return Err(format!("{} is not a commit", store::oid_hex(oid)));
    }
    object::commit_parents_time(&content)
}

/// Compare `head` with `base`, loading at most `cap` commits: `None`
/// where that is not enough to find where they part. The bound counts
/// both sides' commits and the common ones the walk passes on its way;
/// the look past the answer for a lying clock stops at it rather than
/// fails.
pub fn compare(base: &Oid, head: &Oid, cap: usize) -> Result<Option<Compared>, String> {
    let mut nodes: BTreeMap<Oid, Node> = BTreeMap::new();
    // Newest first; the counter keeps the order of equal times that of
    // their being found.
    let mut queue: BinaryHeap<(u64, std::cmp::Reverse<usize>, Oid)> = BinaryHeap::new();
    let mut seq = 0usize;
    let mut results: Vec<Oid> = Vec::new();
    // The entries in the queue whose commit is not behind a common
    // ancestor: the walk has work while there are any.
    let mut live = 0usize;
    // Paint `oid` with `flags` and queue it, if that is news to it.
    macro_rules! paint {
        ($oid:expr, $flags:expr) => {{
            let (oid, flags): (Oid, u8) = ($oid, $flags);
            let full = !nodes.contains_key(&oid) && nodes.len() >= cap;
            // At the bound, a commit under a common ancestor is left
            // unread: it could only have corrected for a clock. Any
            // other is one the answer needs.
            if full && flags & STALE == 0 {
                return Ok(None);
            }
            if !full && !nodes.contains_key(&oid) {
                let (parents, time) = load(&oid)?;
                nodes.insert(oid, Node { parents, time, flags: 0, queued: 0 });
            }
            if let Some(node) = nodes.get_mut(&oid).filter(|n| n.flags & flags != flags) {
                if node.flags & STALE == 0 && flags & STALE != 0 {
                    live -= node.queued;
                }
                node.flags |= flags;
                node.queued += 1;
                if node.flags & STALE == 0 {
                    live += 1;
                }
                seq += 1;
                queue.push((node.time, std::cmp::Reverse(seq), oid));
            }
        }};
    }
    paint!(*head, HEAD);
    paint!(*base, BASE);
    let mut slop = SLOP;
    while let Some((_, _, oid)) = queue.pop() {
        let node = nodes.get_mut(&oid).expect("queued commits are loaded");
        node.queued -= 1;
        if node.flags & STALE == 0 {
            live -= 1;
        }
        let mut down = node.flags & (BOTH | STALE);
        if down & BOTH == BOTH {
            // A candidate, in the order met, unless already known to be
            // under another.
            if node.flags & (RESULT | STALE) == 0 {
                node.flags |= RESULT;
                results.push(oid);
            }
            // What lies under a common ancestor is no newer one.
            down |= STALE;
        }
        for parent in node.parents.clone() {
            paint!(parent, down);
        }
        if live == 0 {
            if slop == 0 {
                break;
            }
            slop -= 1;
        } else {
            slop = SLOP;
        }
    }
    // Each side's paint, and what is under a common ancestor, down to
    // every commit that was loaded.
    for mark in [HEAD, BASE, STALE] {
        let mut stack: Vec<Oid> = nodes
            .iter()
            .filter(|(_, n)| if mark == STALE { n.flags & BOTH == BOTH } else { n.flags & mark != 0 })
            .map(|(oid, _)| *oid)
            .collect();
        while let Some(oid) = stack.pop() {
            for parent in nodes[&oid].parents.clone() {
                if let Some(p) = nodes.get_mut(&parent) {
                    if p.flags & mark == 0 {
                        p.flags |= mark;
                        stack.push(parent);
                    }
                }
            }
        }
    }
    // A common ancestor that no other is above; the newest of several.
    let mut bases: Vec<(u64, Oid)> =
        nodes.iter().filter(|(_, n)| n.flags & BOTH == BOTH && n.flags & STALE == 0).map(|(oid, n)| (n.time, *oid)).collect();
    bases.sort_by(|a, b| b.0.cmp(&a.0));
    let merge_base = results.iter().find(|oid| bases.iter().any(|(_, b)| b == *oid)).copied().or(bases.first().map(|(_, oid)| *oid));
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

/// How many commits `commit_of` loads from a repo's refs before it says
/// no: a ballot is on a commit the repo may come to serve, which is at or
/// near a tip, and a walk of a whole long history is not owed to every
/// caller with a vote. Past it a commit is not found, and the answer is
/// no rather than a guess.
pub const COMMIT_OF_WALK: usize = 20_000;

/// Whether `oid` is a commit of `repo`: a commit object, within reach of
/// one of the repo's refs by parents, among the first `cap` commits met
/// from them (nearest first). The objects are one store for every repo,
/// so holding the object says nothing of whose it is, and a commit no
/// ref of the repo reaches is no commit of it: another repo's, or one a
/// forced push left behind.
pub fn commit_of(repo: &str, oid: &Oid, cap: usize) -> bool {
    if !matches!(store::get_object_stored(oid), Some(o) if o.object_type == ObjectType::Commit) {
        return false;
    }
    let mut queue: std::collections::VecDeque<Oid> = store::list_refs(repo).into_iter().map(|(_, tip)| tip).collect();
    let mut seen: std::collections::BTreeSet<Oid> = std::collections::BTreeSet::new();
    while let Some(at) = queue.pop_front() {
        if at == *oid {
            return true;
        }
        if !seen.insert(at) {
            continue;
        }
        if seen.len() > cap {
            return false;
        }
        // An annotated tag is followed to what it names; anything else
        // that is no commit ends there.
        match store::get_object_parsed(&at) {
            Some((ObjectType::Commit, content)) => {
                if let Ok(refs) = object::commit_refs(&content) {
                    queue.extend(refs.parents);
                }
            }
            Some((ObjectType::Tag, content)) => queue.extend(object::tag_target(&content).ok()),
            _ => {}
        }
    }
    false
}

/// A commit and its first parents, nearest first: the line the deploy
/// branch's own history runs along, which is where the served commit is
/// looked for (site.rs) and what `standings` measures a depth on.
pub fn first_parents(tip: Oid) -> impl Iterator<Item = Oid> {
    std::iter::successors(Some(tip), |c| match store::get_object_parsed(c) {
        Some((ObjectType::Commit, body)) => object::commit_refs(&body).ok().and_then(|r| r.parents.first().copied()),
        _ => None,
    })
}

/// Does `from`'s history hold `to`: is `to` the commit `from` or one of its
/// ancestors? Every parent, nearest first, so a commit a few commits back
/// is met after a few; a non-commit ends its branch of the walk, read off
/// the stored type so it is not inflated to learn that. `None` when `cap`
/// commits were loaded with no answer: past the bound there is no answer
/// rather than a wrong one.
pub fn reaches(from: Oid, to: &Oid, cap: usize) -> Option<bool> {
    let mut queue: std::collections::VecDeque<Oid> = [from].into();
    let mut seen: std::collections::BTreeSet<Oid> = std::collections::BTreeSet::new();
    while let Some(at) = queue.pop_front() {
        if at == *to {
            return Some(true);
        }
        if !seen.insert(at) {
            continue;
        }
        if seen.len() > cap {
            return None;
        }
        if let Some(stored) = store::get_object_stored(&at).filter(|s| s.object_type == ObjectType::Commit) {
            if let Ok(refs) = object::commit_refs(&stored.content()) {
                queue.extend(refs.parents);
            }
        }
    }
    Some(false)
}

/// Where each of `keys` stands in `repo` (`GitSide::standings`), a key
/// being the one a commit's ballots are stored under (`mirror::commit_key`).
/// Two walks, each bounded as the question it answers already is: the
/// deploy branch's first parents for as far as the served commit is looked
/// for (`site::APPROVAL_WALK`), and every ref's history for as far as a
/// ballot's commit is (`COMMIT_OF_WALK`). The first runs along two lines:
/// the tip's, and the served commit's own, which is where the site stands
/// and a withdrawn approval falls back along (`site::advance`), and which
/// a merge can leave off the tip's -- so what the site stands on stays
/// counted whatever line a push draws. Each stops once every key is
/// placed. A key neither walk meets is `Gone`: past `MAX_STANDINGS` in
/// the ask, no commit of the repo, or further back than a ballot is
/// taken on.
pub fn standings(repo: &str, keys: &[String]) -> Vec<Standing> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    let mut out = vec![Standing::Gone; keys.len()];
    let mut wanted: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, k) in keys.iter().enumerate().take(MAX_STANDINGS) {
        wanted.entry(k.as_str()).or_default().push(i);
    }
    let mut left = wanted.len();
    let place = |oid: &Oid, standing: Standing, left: &mut usize, out: &mut Vec<Standing>| {
        if let Some(at) = wanted.get(crate::mirror::commit_key(oid.as_slice()).as_str()) {
            if out[at[0]] == Standing::Gone {
                *left -= 1;
                for i in at {
                    out[*i] = standing;
                }
            }
        }
    };
    let tip = store::head_target(repo).and_then(|branch| store::get_ref(repo, &branch));
    let served = crate::site::gated(repo).then(|| crate::site::served_commit(repo).ok()).flatten();
    for line in [tip, served].into_iter().flatten() {
        for (depth, oid) in first_parents(line).take(crate::site::APPROVAL_WALK).enumerate() {
            if left == 0 {
                return out;
            }
            place(&oid, Standing::Deploy(depth as u32), &mut left, &mut out);
        }
    }
    let mut queue: VecDeque<Oid> = store::list_refs(repo).into_iter().map(|(_, tip)| tip).collect();
    let mut seen: BTreeSet<Oid> = BTreeSet::new();
    while let Some(at) = queue.pop_front() {
        if left == 0 || seen.len() >= COMMIT_OF_WALK {
            break;
        }
        if !seen.insert(at) {
            continue;
        }
        match store::get_object_parsed(&at) {
            Some((ObjectType::Commit, content)) => {
                place(&at, Standing::Held, &mut left, &mut out);
                if let Ok(refs) = object::commit_refs(&content) {
                    queue.extend(refs.parents);
                }
            }
            Some((ObjectType::Tag, content)) => queue.extend(object::tag_target(&content).ok()),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where a commit with ballots stands: on the deploy branch by its
    /// depth along first parents, elsewhere in the repo, or nowhere. A
    /// merge's second parent is off the line, and a key asked twice is
    /// answered twice.
    #[test]
    fn standings_place_a_commit_on_the_deploy_branch_off_it_or_nowhere() {
        store::create_repo("stand").unwrap();
        store::create_repo("stand-other").unwrap();
        let main = store::head_target("stand").unwrap();
        let a = commit("stand-a", &[], 1);
        let side = commit("stand-side", &[&a], 2);
        let merged = commit("stand-merged", &[&a], 2);
        let b = commit("stand-b", &[&a, &merged], 3);
        let c = commit("stand-c", &[&b], 4);
        let gone = commit("stand-gone", &[&a], 5);
        let theirs = commit("stand-theirs", &[], 6);
        store::set_ref("stand", &main, c).unwrap();
        store::set_ref("stand", "refs/heads/side", side).unwrap();
        store::set_ref("stand-other", "refs/heads/main", theirs).unwrap();
        let key = |o: &Oid| crate::mirror::commit_key(o.as_slice());
        let asked = [key(&c), key(&a), key(&side), key(&merged), key(&gone), key(&theirs), key(&a), "commit:nonsense".to_string()];
        assert_eq!(
            standings("stand", &asked),
            [
                Standing::Deploy(0),
                Standing::Deploy(2),
                Standing::Held,
                Standing::Held,
                Standing::Gone,
                Standing::Gone,
                Standing::Deploy(2),
                Standing::Gone
            ]
        );
        // The side branch deleted: its commit is no commit of the repo.
        store::delete_ref("stand", "refs/heads/side");
        assert_eq!(standings("stand", &[key(&side)]), [Standing::Gone]);
        assert!(standings("stand-none", &asked).iter().all(|s| *s == Standing::Gone));
    }

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

    /// Whether a history holds a commit: by any parent, the second of a
    /// merge included; never a descendant; and past the bound, no answer.
    #[test]
    fn reaches_follows_every_parent_and_stops_at_the_bound() {
        let a = commit("reach-a", &[], 1);
        let b = commit("reach-b", &[&a], 2);
        let side = commit("reach-side", &[&a], 2);
        let m = commit("reach-m", &[&b, &side], 3);
        assert_eq!(reaches(m, &m, 0), Some(true), "a commit holds itself, for nothing");
        assert_eq!(reaches(m, &side, 10), Some(true), "through the second parent");
        assert_eq!(reaches(m, &a, 10), Some(true));
        assert_eq!(reaches(a, &m, 10), Some(false), "never forward");
        assert_eq!(reaches(b, &side, 10), Some(false), "nor aside");
        assert_eq!(reaches(m, &a, 1), None, "past the bound");
    }

    fn cmp(base: &Oid, head: &Oid) -> Compared {
        compare(base, head, 1000).unwrap().expect("within the bound")
    }

    /// A commit is a repo's when one of the repo's refs reaches it: not
    /// for being held, which every repo's objects are, and not past the
    /// bound.
    #[test]
    fn a_commit_is_a_repos_by_its_refs() {
        store::create_repo("of-a").unwrap();
        store::create_repo("of-b").unwrap();
        let a1 = commit("of a1", &[], 10);
        let a2 = commit("of a2", &[&a1], 20);
        let side = commit("of side", &[&a1], 25);
        let a3 = commit("of a3", &[&a2, &side], 30);
        let b1 = commit("of b1", &[], 10);
        store::set_ref("of-a", "refs/heads/main", a3).unwrap();
        store::set_ref("of-b", "refs/heads/main", b1).unwrap();
        for c in [&a3, &a2, &side, &a1] {
            assert!(commit_of("of-a", c, 100));
            assert!(!commit_of("of-b", c, 100), "held, and another repo's");
        }
        assert!(commit_of("of-b", &b1, 100) && !commit_of("of-a", &b1, 100));
        assert!(!commit_of("of-none", &a3, 100), "a repo with no refs has no commits");
        // What is no commit is no repo's, though a commit names it.
        let tree = store::put_object(ObjectType::Tree, b"");
        let blob = store::put_object(ObjectType::Blob, b"of a blob");
        assert!(!commit_of("of-a", &tree, 100) && !commit_of("of-a", &blob, 100));
        let absent = store::parse_oid("00000000000000000000000000000000000000aa").unwrap();
        assert!(!commit_of("of-a", &absent, 100));
        // Any ref will do, and an annotated tag is followed to its commit.
        let lone = commit("of lone", &[], 5);
        assert!(!commit_of("of-a", &lone, 100));
        let tag = store::put_object(ObjectType::Tag, format!("object {}\ntype commit\ntag v1\n\nv1\n", store::oid_hex(&lone)).as_bytes());
        store::set_ref("of-a", "refs/tags/v1", tag).unwrap();
        assert!(commit_of("of-a", &lone, 100));
        assert!(!commit_of("of-a", &tag, 100), "the tag itself is no commit");
        // A commit a moved ref left behind is the repo's no longer.
        store::set_ref("of-a", "refs/heads/main", a2).unwrap();
        assert!(commit_of("of-a", &a1, 100) && !commit_of("of-a", &a3, 100) && !commit_of("of-a", &side, 100));
        // The bound: nearest first, and past it no.
        store::set_ref("of-a", "refs/heads/main", a3).unwrap();
        store::delete_ref("of-a", "refs/tags/v1");
        assert!(commit_of("of-a", &a3, 1));
        assert!(commit_of("of-a", &a2, 2) && commit_of("of-a", &side, 2));
        assert!(!commit_of("of-a", &a1, 2));
        assert!(commit_of("of-a", &a1, 3));
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
    fn a_common_ancestor_dated_after_the_merge_base_is_not_taken_for_it() {
        // head and base both merge c2 and c1; c1 is the newer history
        // (c1 -> m -> c2) and is dated long before c2, which the walk
        // therefore meets first.
        let c2 = commit("c2", &[], 50);
        let m = commit("m", &[&c2], 4);
        let c1 = commit("c1", &[&m], 5);
        let h = commit("h", &[&c2, &c1], 100);
        let b = commit("b", &[&c2, &c1], 90);
        let r = cmp(&b, &h);
        assert_eq!(r.merge_base, Some(c1));
        assert_eq!((r.ahead, r.behind), (vec![h], 1));
    }

    #[test]
    fn commits_reached_late_through_older_dated_ones_are_not_counted_ahead() {
        // h merges y and c; base is on c; and c, dated before everything,
        // leads down to y through q and q2: y and z are common, though
        // the walk meets them long before it meets c.
        let z = commit("z", &[], 70);
        let y = commit("y", &[&z], 80);
        let q2 = commit("q2", &[&y], 8);
        let q = commit("q", &[&q2], 9);
        let c = commit("c", &[&q], 10);
        let h = commit("h", &[&y, &c], 100);
        let b = commit("b", &[&c], 95);
        let r = cmp(&b, &h);
        assert_eq!(r.merge_base, Some(c));
        assert_eq!((r.ahead, r.behind), (vec![h], 1));
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
        // Three commits decide it, and the walk looks SLOP further for a
        // clock that ran backwards: the rest of the 200 are never read.
        let r = compare(&left, &right, SLOP + 8).unwrap().expect("near the tips");
        assert_eq!((r.merge_base, r.ahead, r.behind), (Some(tip), vec![right], 1));
        // The root against a tip is the whole history.
        let root_side = commit("lonely", &[], 2);
        assert!(compare(&root_side, &right, 50).unwrap().is_none());
        // A bound reached only while looking past the answer does not
        // take the answer away: three commits decide this one.
        let r = compare(&left, &right, 3).unwrap().expect("decided within the bound");
        assert_eq!((r.merge_base, r.ahead, r.behind), (Some(tip), vec![right], 1));
        assert!(compare(&left, &right, 2).unwrap().is_none());
        // Something that is no commit is an error.
        let blob = store::put_object(ObjectType::Blob, b"x");
        assert!(compare(&blob, &right, 50).is_err());
    }
}
