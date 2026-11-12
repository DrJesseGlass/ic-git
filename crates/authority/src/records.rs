//! The authority's stable maps (docs/CANISTER_SPLIT.md, section 3):
//! accounts, repo metadata, ballots, and queued deploy jobs' payloads. Out
//! of store.rs, which is the git side's objects, refs, repos and tokens.

use crate::memory::Memory;
use ic_stable_structures::StableBTreeMap;
use std::cell::RefCell;

thread_local! {
    /// Tenancy (see tenancy.rs): principal text -> JSON account.
    static ACCOUNTS: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(crate::memory::get(crate::memory::MEM_ACCOUNTS)),
    );

    /// Tenancy: repo name -> JSON repo metadata (owner, members, rent state).
    static REPO_META: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(crate::memory::get(crate::memory::MEM_REPO_META)),
    );

    /// Tenancy: "<repo>\0<subject key>" -> JSON list of ic_multisig::Approval
    /// (tenancy.rs owns the key and the record shape).
    static VOTES: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(crate::memory::get(crate::memory::MEM_VOTES)),
    );

    /// A queued deploy job's payload: the bytes it deploys and their proofs
    /// (deploy.rs owns the key and the encoding). Not in META, because a
    /// payload can hold a whole module.
    static DEPLOY_JOBS: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(
        StableBTreeMap::init(crate::memory::get(crate::memory::MEM_DEPLOY_JOBS)),
    );
}

// --- tenancy maps (JSON values; tenancy.rs owns the schemas) -------------------

pub fn account_get<T: serde::de::DeserializeOwned>(principal: &str) -> Option<T> {
    ACCOUNTS.with(|a| a.borrow().get(&principal.to_string()))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn account_set<T: serde::Serialize>(principal: &str, value: &T) {
    if let Ok(b) = serde_json::to_vec(value) {
        ACCOUNTS.with(|a| a.borrow_mut().insert(principal.to_string(), b));
    }
}

pub fn repo_meta_get<T: serde::de::DeserializeOwned>(repo: &str) -> Option<T> {
    REPO_META.with(|m| m.borrow().get(&repo.to_string()))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn repo_meta_set<T: serde::Serialize>(repo: &str, value: &T) {
    if let Ok(b) = serde_json::to_vec(value) {
        REPO_META.with(|m| m.borrow_mut().insert(repo.to_string(), b));
    }
}

/// Every repo that has tenancy metadata, with it decoded.
pub fn repo_meta_all<T: serde::de::DeserializeOwned>() -> Vec<(String, T)> {
    REPO_META.with(|m| {
        m.borrow()
            .iter()
            .filter_map(|e| serde_json::from_slice(&e.value()).ok().map(|v| (e.key().clone(), v)))
            .collect()
    })
}

fn vote_key(repo: &str, subject_key: &str) -> String {
    format!("{repo}\0{subject_key}")
}

pub fn votes_get<T: serde::de::DeserializeOwned>(repo: &str, subject_key: &str) -> Option<T> {
    VOTES.with(|v| v.borrow().get(&vote_key(repo, subject_key)))
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// The subject keys of a repo's stored ballots that start with `prefix`
/// (`"commit:"`, say).
pub fn vote_subject_keys(repo: &str, prefix: &str) -> Vec<String> {
    let start = vote_key(repo, prefix);
    let skip = vote_key(repo, "").len();
    VOTES.with(|v| {
        v.borrow()
            .range(start.clone()..)
            .take_while(|e| e.key().starts_with(&start))
            .map(|e| e.key()[skip..].to_string())
            .collect()
    })
}

pub fn votes_set<T: serde::Serialize>(repo: &str, subject_key: &str, value: &T) {
    if let Ok(b) = serde_json::to_vec(value) {
        VOTES.with(|v| v.borrow_mut().insert(vote_key(repo, subject_key), b));
    }
}

// --- deploy job payloads -----------------------------------------------------

pub fn deploy_job_put(key: &str, payload: Vec<u8>) {
    DEPLOY_JOBS.with(|j| j.borrow_mut().insert(key.to_string(), payload));
}

/// Remove a job's payload and return it.
pub fn deploy_job_take(key: &str) -> Option<Vec<u8>> {
    DEPLOY_JOBS.with(|j| j.borrow_mut().remove(&key.to_string()))
}

pub fn deploy_job_keys() -> Vec<String> {
    DEPLOY_JOBS.with(|j| j.borrow().keys().collect())
}

