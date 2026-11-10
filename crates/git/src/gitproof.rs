//! Proofs that a blob is what a commit holds at a path
//! (docs/CANISTER_SPLIT.md, section 4; phase 2, step 1).
//!
//! After the split the authority installs and deploys what the git canister
//! hands it, and must not take the git canister's word for the bytes. So a
//! deploy artifact travels with a proof: the raw commit object and every tree
//! object on the path to the blob. The checker recomputes each object's id
//! and follows the path one entry at a time. A blob that is not exactly what
//! the commit holds at the path is refused.
//!
//! Two halves, kept apart on purpose:
//! - `prove`, here, is the git side: it reads the object store.
//! - `check` is the authority side, in the shared types crate
//!   (`ic_git_types::proof`) with the format, a pure function of its
//!   arguments. The tests below hold the two to each other.

use crate::store::{self, ObjectType, Oid};
use ic_git_types::oid::commit20;
use ic_git_types::proof::{check, components, lookup, tree_of};

/// The proof for `path` in `commit`, and the blob it proves: the commit's
/// raw object, then each tree on the path, each in git's canonical form
/// (`"<type> <len>\0" + body`). The git side of the boundary.
pub fn prove(commit: &Oid, path: &str) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    let components = components(path)?;
    let mut proof = Vec::with_capacity(components.len() + 1);
    let (ty, body) = store::get_object_parsed(commit).ok_or("commit object missing")?;
    if ty != ObjectType::Commit {
        return Err("not a commit".into());
    }
    let mut next = tree_of(&body)?;
    proof.push(canonical(ObjectType::Commit, &body));
    for (i, name) in components.iter().enumerate() {
        let (ty, body) = store::get_object_parsed(&Oid::try_from(next.as_slice()).unwrap())
            .ok_or("tree object missing")?;
        if ty != ObjectType::Tree {
            return Err(match i {
                0 => "the commit's tree is not a tree object".to_string(),
                _ => format!("'{}' is not a directory", components[..i].join("/")),
            });
        }
        let entry = lookup(&body, name)?;
        proof.push(canonical(ObjectType::Tree, &body));
        next = entry.oid;
    }
    let (ty, blob) = store::get_object_parsed(&Oid::try_from(next.as_slice()).unwrap())
        .ok_or("blob object missing")?;
    if ty != ObjectType::Blob {
        return Err(format!("'{path}' is not a file"));
    }
    // The prover holds itself to the checker's rules, so a proof that would
    // be refused is never sent.
    check(&commit20(commit)?, path, &blob, &proof)?;
    Ok((blob, proof))
}

fn canonical(ty: ObjectType, body: &[u8]) -> Vec<u8> {
    ic_git_types::proof::canonical(ty.as_str(), body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_git_types::proof::MAX_DEPTH;

    fn tree(entries: &[(&str, &str, &Oid)]) -> (Oid, Vec<u8>) {
        let mut body = Vec::new();
        for (mode, name, oid) in entries {
            body.extend_from_slice(format!("{mode} {name}\0").as_bytes());
            body.extend_from_slice(oid.as_slice());
        }
        (store::put_object(ObjectType::Tree, &body), body)
    }

    fn commit(tree: &Oid) -> Oid {
        let body = format!("tree {}\nauthor a <a@a> 0 +0000\n\nmsg\n", store::oid_hex(tree));
        store::put_object(ObjectType::Commit, body.as_bytes())
    }

    fn id(oid: &Oid) -> [u8; 20] {
        commit20(oid).unwrap()
    }

    /// app/build/app.wasm plus a sibling, a script and a link.
    fn fixture() -> (Oid, Vec<u8>) {
        let wasm = b"\0asm\x01\0\0\0".to_vec();
        let blob = store::put_object(ObjectType::Blob, &wasm);
        let other = store::put_object(ObjectType::Blob, b"other");
        let (build, _) = tree(&[
            ("100644", "app.wasm", &blob),
            ("100755", "run.sh", &other),
            ("120000", "link", &other),
        ]);
        let (app, _) = tree(&[("40000", "build", &build), ("100644", "README", &other)]);
        let (root, _) = tree(&[("100644", "top.txt", &other), ("40000", "app", &app)]);
        (commit(&root), wasm)
    }

    #[test]
    fn a_proof_round_trips() {
        let (c, wasm) = fixture();
        let (blob, proof) = prove(&c, "app/build/app.wasm").unwrap();
        assert_eq!(blob, wasm);
        // The commit, then the root, app and build trees.
        assert_eq!(proof.len(), 4);
        assert!(proof[0].starts_with(b"commit "));
        check(&id(&c), "app/build/app.wasm", &blob, &proof).unwrap();
        // A file at the root, and an executable one.
        let (top, p) = prove(&c, "top.txt").unwrap();
        check(&id(&c), "top.txt", &top, &p).unwrap();
        let (sh, p) = prove(&c, "app/build/run.sh").unwrap();
        check(&id(&c), "app/build/run.sh", &sh, &p).unwrap();
    }

    #[test]
    fn other_bytes_or_another_commit_are_refused() {
        let (c, _) = fixture();
        let (blob, proof) = prove(&c, "app/build/app.wasm").unwrap();
        let mut wrong = blob.clone();
        wrong.push(0);
        assert!(check(&id(&c), "app/build/app.wasm", &wrong, &proof).unwrap_err().contains("not what the commit holds"));
        let (other, _) = tree(&[]);
        let c2 = commit(&other);
        assert!(check(&id(&c2), "app/build/app.wasm", &blob, &proof).unwrap_err().contains("not the one the proof names"));
        // The same proof does not prove a different path.
        assert!(check(&id(&c), "app/build/run.sh", &blob, &proof).is_err());
    }

    #[test]
    fn a_tampered_or_swapped_object_is_refused() {
        let (c, _) = fixture();
        let (blob, proof) = prove(&c, "app/build/app.wasm").unwrap();
        // A tree from elsewhere in its place.
        let mut swapped = proof.clone();
        swapped[2] = swapped[1].clone();
        assert!(check(&id(&c), "app/build/app.wasm", &blob, &swapped).is_err());
        // One flipped byte anywhere in any object.
        for k in 0..proof.len() {
            let mut bad = proof.clone();
            let last = bad[k].len() - 1;
            bad[k][last] ^= 1;
            assert!(check(&id(&c), "app/build/app.wasm", &blob, &bad).is_err(), "object {k}");
        }
        // Too few or too many objects.
        assert!(check(&id(&c), "app/build/app.wasm", &blob, &proof[..2]).is_err());
        let mut extra = proof.clone();
        extra.push(proof[2].clone());
        assert!(check(&id(&c), "app/build/app.wasm", &blob, &extra).is_err());
    }

    #[test]
    fn only_regular_files_through_directories() {
        let (c, _) = fixture();
        // A symlink, a directory, and a path through a file.
        assert!(prove(&c, "app/build/link").unwrap_err().contains("not a regular file"));
        assert!(prove(&c, "app/build").unwrap_err().contains("not a file"));
        assert!(prove(&c, "top.txt/x").is_err());
        // A submodule entry, forged by hand: the checker refuses it.
        let target = store::put_object(ObjectType::Blob, b"sub");
        let (root, root_body) = tree(&[("160000", "sub", &target)]);
        let c2 = commit(&root);
        let (_, commit_body) = store::get_object_parsed(&c2).unwrap();
        let proof = vec![canonical(ObjectType::Commit, &commit_body), canonical(ObjectType::Tree, &root_body)];
        assert!(check(&id(&c2), "sub", b"sub", &proof).unwrap_err().contains("not a regular file"));
        // A directory whose entry says file mode is not walked through.
        let leaf = store::put_object(ObjectType::Blob, b"leaf");
        let (inner, inner_body) = tree(&[("100644", "f", &leaf)]);
        let (root, root_body) = tree(&[("100644", "d", &inner)]);
        let c3 = commit(&root);
        let (_, commit_body) = store::get_object_parsed(&c3).unwrap();
        let proof = vec![
            canonical(ObjectType::Commit, &commit_body),
            canonical(ObjectType::Tree, &root_body),
            canonical(ObjectType::Tree, &inner_body),
        ];
        assert!(check(&id(&c3), "d/f", b"leaf", &proof).unwrap_err().contains("not a directory"));
    }

    #[test]
    fn a_name_listed_twice_is_refused() {
        let a = store::put_object(ObjectType::Blob, b"a");
        let b = store::put_object(ObjectType::Blob, b"b");
        let (root, root_body) = tree(&[("100644", "x", &a), ("100644", "x", &b)]);
        let c = commit(&root);
        let (_, commit_body) = store::get_object_parsed(&c).unwrap();
        let proof = vec![canonical(ObjectType::Commit, &commit_body), canonical(ObjectType::Tree, &root_body)];
        for blob in [&b"a"[..], &b"b"[..]] {
            assert!(check(&id(&c), "x", blob, &proof).unwrap_err().contains("twice"));
        }
    }

    #[test]
    fn only_plain_paths() {
        let (c, wasm) = fixture();
        let (_, proof) = prove(&c, "app/build/app.wasm").unwrap();
        for bad in ["", "/app/build/app.wasm", "app//build/app.wasm", "app/./build/app.wasm", "app/../app/build/app.wasm", "app/build/app.wasm/"] {
            assert!(check(&id(&c), bad, &wasm, &proof).unwrap_err().contains("plain relative path"), "{bad:?}");
        }
        let deep = vec!["d"; MAX_DEPTH + 1].join("/");
        assert!(check(&id(&c), &deep, &wasm, &proof).unwrap_err().contains("at most"));
    }

    #[test]
    fn headers_must_match_their_bodies() {
        let (c, _) = fixture();
        let (blob, proof) = prove(&c, "top.txt").unwrap();
        let body = &proof[0][proof[0].iter().position(|&b| b == 0).unwrap() + 1..];
        for header in [
            format!("tree {}\0", body.len()),      // wrong type
            format!("commit {}\0", body.len() + 1), // wrong length
            format!("commit 0{}\0", body.len()),    // leading zero
            format!("commit  {}\0", body.len()),    // not a plain number
        ] {
            let mut raw = header.into_bytes();
            raw.extend_from_slice(body);
            let mut bad = proof.clone();
            bad[0] = raw;
            assert!(check(&id(&c), "top.txt", &blob, &bad).is_err());
        }
    }

    #[test]
    fn a_commit_must_open_with_a_well_formed_tree() {
        assert!(tree_of(b"tree 0123456789abcdef0123456789abcdef01234567\n").is_ok());
        assert!(tree_of(b"tree 0123456789ABCDEF0123456789abcdef01234567\n").is_err());
        assert!(tree_of(b"parent 0123456789abcdef0123456789abcdef01234567\n").is_err());
        assert!(tree_of(b"tree 0123\n").is_err());
        assert!(tree_of(b"").is_err());
        // A second tree line anywhere in the header is refused; the same
        // words in the message are not a header.
        let a = "0123456789abcdef0123456789abcdef01234567";
        let b = "89abcdef0123456789abcdef0123456789abcdef";
        let two = format!("tree {a}\nparent {b}\ntree {b}\nauthor a <a@a> 0 +0000\n\nmsg\n");
        assert!(tree_of(two.as_bytes()).unwrap_err().contains("more than one tree"));
        let in_message = format!("tree {a}\nauthor a <a@a> 0 +0000\n\ntree {b}\n");
        assert!(tree_of(in_message.as_bytes()).is_ok());
    }

    /// The commit Codex described on #89: a header naming tree A, then tree
    /// B. object::commit_refs reads B; the proof must not certify A.
    #[test]
    fn a_commit_with_two_trees_cannot_be_proved() {
        let a_blob = store::put_object(ObjectType::Blob, b"from A");
        let b_blob = store::put_object(ObjectType::Blob, b"from B");
        let (a, _) = tree(&[("100644", "f", &a_blob)]);
        let (b, _) = tree(&[("100644", "f", &b_blob)]);
        let body = format!(
            "tree {}\ntree {}\nauthor a <a@a> 0 +0000\n\nmsg\n",
            store::oid_hex(&a),
            store::oid_hex(&b)
        );
        let c = store::put_object(ObjectType::Commit, body.as_bytes());
        assert_eq!(crate::object::commit_refs(body.as_bytes()).unwrap().tree, b);
        assert!(prove(&c, "f").unwrap_err().contains("more than one tree"));
        let (_, a_body) = store::get_object_parsed(&a).unwrap();
        let proof = vec![canonical(ObjectType::Commit, body.as_bytes()), canonical(ObjectType::Tree, &a_body)];
        assert!(check(&id(&c), "f", b"from A", &proof).unwrap_err().contains("more than one tree"));
    }

    #[test]
    fn a_truncated_tree_is_refused() {
        let blob = store::put_object(ObjectType::Blob, b"t");
        let (_, body) = tree(&[("100644", "t", &blob)]);
        assert!(lookup(&body[..body.len() - 1], "t").unwrap_err().contains("truncated"));
        assert!(lookup(b"100644 t", "t").is_err());
        assert!(lookup(b"10x644 t\0aaaaaaaaaaaaaaaaaaaa", "t").unwrap_err().contains("mode"));
    }

    /// Mutation fuzz: from a valid proof, flip, drop or insert bytes at
    /// random in any object or in the blob. Every input that differs from
    /// the original must be refused, and nothing may panic. Deterministic
    /// (xorshift from a fixed seed), so a failure reproduces.
    #[test]
    fn mutated_proofs_are_always_refused() {
        let (c, _) = fixture();
        let path = "app/build/app.wasm";
        let (blob, proof) = prove(&c, path).unwrap();
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..20_000 {
            let mut b = blob.clone();
            let mut p = proof.clone();
            for _ in 0..1 + next() % 3 {
                let k = (next() % (p.len() as u64 + 1)) as usize;
                let target = if k == p.len() { &mut b } else { &mut p[k] };
                let at = (next() % (target.len() as u64 + 1)) as usize;
                match next() % 3 {
                    0 if at < target.len() => target[at] ^= 1 << (next() % 8),
                    1 if at < target.len() => {
                        target.remove(at);
                    }
                    _ => target.insert(at, next() as u8),
                }
            }
            if b == blob && p == proof {
                continue;
            }
            assert!(check(&id(&c), path, &b, &p).is_err(), "round {round} was accepted");
        }
    }
}
