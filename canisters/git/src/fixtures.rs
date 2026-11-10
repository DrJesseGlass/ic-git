//! Test fixtures for the canister crate's tests, which run both sides
//! together: a seeded repo, and /api as the canister answers it.

use crate::store::{self, ObjectType, Oid};
use ic_dev_kit_rs::http::HttpResponse;

/// All of /api, as the canister answers it.
pub fn get(url: &str) -> HttpResponse {
    crate::api_route(url)
}

pub fn body_json(res: &HttpResponse) -> serde_json::Value {
    serde_json::from_slice(&res.body).unwrap()
}

/// Two commits: c1 (a.txt) -> c2 (a.txt, "sub dir"/b.txt), a tag ref on c1.
/// The repo is ownerless, as one created before tenancy.
pub fn seed(repo: &str) -> (Oid, Oid) {
    crate::tenancy::test_repo(repo);
    let a = store::put_object(ObjectType::Blob, b"alpha\n");
    let b = store::put_object(ObjectType::Blob, b"bravo\n");
    let mut t1 = Vec::new();
    t1.extend_from_slice(b"100644 a.txt\0");
    t1.extend_from_slice(a.as_slice());
    let t1 = store::put_object(ObjectType::Tree, &t1);
    let c1 = store::put_object(
        ObjectType::Commit,
        format!(
            "tree {}\nauthor Ann <ann@x> 1700000000 +0100\ncommitter Bob <bob@x> 1700000001 +0000\n\nfirst\n\nbody line\n",
            store::oid_hex(&t1)
        )
        .as_bytes(),
    );
    let mut sub = Vec::new();
    sub.extend_from_slice(b"100644 b.txt\0");
    sub.extend_from_slice(b.as_slice());
    let sub = store::put_object(ObjectType::Tree, &sub);
    let mut t2 = Vec::new();
    t2.extend_from_slice(b"40000 sub dir\0");
    t2.extend_from_slice(sub.as_slice());
    t2.extend_from_slice(b"100644 a.txt\0");
    t2.extend_from_slice(a.as_slice());
    let t2 = store::put_object(ObjectType::Tree, &t2);
    let c2 = store::put_object(
        ObjectType::Commit,
        format!(
            "tree {}\nparent {}\nauthor Ann <ann@x> 1700000002 +0100\ncommitter Ann <ann@x> 1700000002 +0100\n\nsecond\n",
            store::oid_hex(&t2),
            store::oid_hex(&c1)
        )
        .as_bytes(),
    );
    let branch = store::head_target(repo).unwrap();
    store::set_ref(repo, &branch, c2).unwrap();
    store::set_ref(repo, "refs/tags/v1", c1).unwrap();
    (c1, c2)
}
