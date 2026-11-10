//! The canister's stable-memory layout: one memory manager, and the id of
//! every map in it. Both sides of the split keep their maps here while they
//! share a canister (docs/CANISTER_SPLIT.md, phase 2 step 4): the git side's
//! in store.rs, the authority's in records.rs, META in kv.rs. An id is never
//! reused or renumbered, since a map is found by its id across upgrades.

use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::DefaultMemoryImpl;
use std::cell::RefCell;

pub type Memory = VirtualMemory<DefaultMemoryImpl>;

pub const MEM_OBJECTS: MemoryId = MemoryId::new(0);
pub const MEM_REFS: MemoryId = MemoryId::new(1);
pub const MEM_REPOS: MemoryId = MemoryId::new(2);
pub const MEM_META: MemoryId = MemoryId::new(3);
pub const MEM_TOKENS: MemoryId = MemoryId::new(4);
pub const MEM_ACCOUNTS: MemoryId = MemoryId::new(5);
pub const MEM_REPO_META: MemoryId = MemoryId::new(6);
pub const MEM_VOTES: MemoryId = MemoryId::new(7);
pub const MEM_TOKEN_INDEX: MemoryId = MemoryId::new(8);
pub const MEM_DEPLOY_JOBS: MemoryId = MemoryId::new(9);
/// The git side's outbox (outbox.rs): what it has told the authority and
/// the authority has not yet answered.
pub const MEM_OUTBOX: MemoryId = MemoryId::new(10);

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

/// The memory with this id. Each id is opened by exactly one map.
pub fn get(id: MemoryId) -> Memory {
    MEMORY_MANAGER.with(|m| m.borrow().get(id))
}
