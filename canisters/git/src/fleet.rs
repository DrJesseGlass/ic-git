//! R4 (see ROADMAP.md): distribute compilation across a fleet of worker
//! canisters.
//!
//! The coordinator (this canister) fans `compile_module` out to registered
//! workers -- concurrently, round-robin -- then links the returned objects into
//! one wasm binary. Because the git wasm already exposes `compile_module`, any
//! git-canister instance is a valid worker; the pool is just a list of their
//! principals.
//!
//! This is the payoff of R3's seam: separate compilation made each module an
//! independent, portable unit of work, so the only thing R4 adds is a scheduler
//! and a fan-out. Compilation is now embarrassingly parallel across canisters,
//! with linking as the single join point.

use crate::lang::link::{self, ModuleObject};
use crate::store;
use candid::Principal;
use futures::future::join_all;
use ic_dev_kit_rs::intercanister;

/// META key for the pool, stored as principal text (stable across candid
/// versions and readable in a raw dump).
const WORKERS_KEY: &str = "compiler_workers";

/// Register the worker pool (principals of canisters exposing `compile_module`).
pub fn set_workers(workers: &[Principal]) {
    let texts: Vec<String> = workers.iter().map(|p| p.to_text()).collect();
    store::meta_set_json(WORKERS_KEY, &texts);
}

/// The registered worker pool.
pub fn get_workers() -> Vec<Principal> {
    store::meta_get_json::<Vec<String>>(WORKERS_KEY)
        .unwrap_or_default()
        .iter()
        .filter_map(|t| Principal::from_text(t).ok())
        .collect()
}

/// Compile each source on one of `workers` (round-robin, all calls in flight
/// at once), then link the collected objects into one validated wasm binary.
/// Takes the pool as an argument so callers that also report on it load it
/// from stable memory only once.
pub async fn compile_distributed(
    workers: &[Principal],
    sources: Vec<String>,
) -> Result<Vec<u8>, String> {
    if workers.is_empty() {
        return Err("no compiler workers registered; call set_compiler_workers".into());
    }

    // Dispatch every module's compile as a concurrent inter-canister call.
    let calls = sources.into_iter().enumerate().map(|(i, src)| {
        let worker = workers[i % workers.len()];
        async move {
            intercanister::call::<(String,), Result<Vec<u8>, String>>(
                worker,
                "compile_module",
                (src,),
            )
            .await
            // Flatten transport error and the worker's own compile error.
            .and_then(|compiled| compiled)
            .map_err(|e| format!("module {i} on worker {worker}: {e}"))
        }
    });
    let results = join_all(calls).await;

    // Collect objects in module order, then link (the single join point).
    let mut objects: Vec<ModuleObject> = Vec::with_capacity(results.len());
    for r in results {
        let bytes = r?;
        let obj = serde_json::from_slice(&bytes).map_err(|e| format!("object decode: {e}"))?;
        objects.push(obj);
    }
    link::link(&objects)
}
