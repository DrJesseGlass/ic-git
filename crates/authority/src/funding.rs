//! The git canister's cycles (docs/CANISTER_SPLIT.md, phase 3 step 12d).
//!
//! Tenants pay the authority for what their repos cost: rent on the bytes
//! they store and a fee on each push. After the cut those bytes live in
//! the git canister, which burns cycles holding and serving them, so what
//! tenants pay for git-side work is kept apart here as the **pool**, and
//! the authority sends it across on the rent timer: when the git canister
//! is under the **floor** (`Pricing::git_canister_floor`, which
//! `/api/pricing` reports), it gets the floor's worth, as far as the pool
//! goes and never so much that this canister's liquid balance (what it
//! holds above its freezing threshold) is left under the floor itself.
//! The pool is revenue, not tenants' balances: a deposit is a liability
//! until a charge spends it, and only charges feed the pool, so the git
//! canister can never be funded with cycles a tenant could still spend.
//! One tick runs at a time; a tick that could not send is on record
//! (`Funding::last_failure`), with the pool kept.
//!
//! An operator can send more from this canister's own cycles
//! (`top_up_git_canister`), as an operator's repos pay nothing and cost
//! the git canister all the same. One canister has no git canister to
//! fund: the pool still fills, and funds the git canister from the cut.

use crate::clock::now_ns;
use candid::{CandidType, Principal};
use ic_git_types::side::Reply;
use serde::{Deserialize, Serialize};

/// Cycles charged for git-side work and not yet sent across.
const POOL_KEY: &str = "funding:pool";
/// What has been sent, and the last time.
const SENT_KEY: &str = "funding:sent";

/// The git canister's funding, as `get_git_funding` reports it.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Funding {
    pub git_canister: Option<Principal>,
    /// Charged for git-side work (rent, pushes), not yet sent across.
    pub pool: u64,
    /// Below this the timer tops the git canister up (`Pricing`).
    pub floor: u64,
    /// Sent across so far, by the timer and by operators.
    pub sent: u64,
    /// The last top-up.
    pub last: Option<TopUp>,
    /// The last tick that could not send: the git canister did not say
    /// what it holds, or the deposit failed. The pool kept what it had.
    pub last_failure: Option<TopUpFailure>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TopUpFailure {
    pub at_ns: u64,
    pub error: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TopUp {
    pub at_ns: u64,
    pub cycles: u64,
    /// What the git canister held before, as it reported it; none for an
    /// operator's top-up, which does not ask.
    pub balance_before: Option<u64>,
}

#[derive(Serialize, Deserialize, Default)]
struct Sent {
    total: u64,
    last: Option<TopUp>,
    #[serde(default)]
    failed: Option<TopUpFailure>,
}

thread_local! {
    /// A tick is between its asks: the next one waits for the next
    /// timer. Heap: an upgrade clears it with the tick it belonged to.
    static IN_FLIGHT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Holds `IN_FLIGHT` for a tick, however it ends.
struct Tick;

impl Tick {
    fn begin() -> Option<Tick> {
        IN_FLIGHT.with(|f| (!f.replace(true)).then_some(Tick))
    }
}

impl Drop for Tick {
    fn drop(&mut self) {
        IN_FLIGHT.with(|f| f.set(false));
    }
}

pub fn pool() -> u64 {
    crate::kv::get_json(POOL_KEY).unwrap_or(0)
}

fn set_pool(cycles: u64) {
    crate::kv::set_json(POOL_KEY, &cycles);
}

/// Cycles charged for git-side work: into the pool.
pub fn earn(cycles: u64) {
    if cycles > 0 {
        set_pool(pool().saturating_add(cycles));
    }
}

fn sent() -> Sent {
    crate::kv::get_json(SENT_KEY).unwrap_or_default()
}

fn record_sent(cycles: u64, balance_before: Option<u64>) {
    let mut s = sent();
    s.total = s.total.saturating_add(cycles);
    s.last = Some(TopUp {
        at_ns: now_ns(),
        cycles,
        balance_before,
    });
    crate::kv::set_json(SENT_KEY, &s);
}

fn record_failure(error: String) -> String {
    let mut s = sent();
    s.failed = Some(TopUpFailure {
        at_ns: now_ns(),
        error: error.clone(),
    });
    crate::kv::set_json(SENT_KEY, &s);
    error
}

pub fn funding() -> Funding {
    let s = sent();
    Funding {
        git_canister: crate::peer::GIT.get(),
        pool: pool(),
        floor: crate::tenancy::git_canister_floor(),
        sent: s.total,
        last: s.last,
        last_failure: s.failed,
    }
}

/// What the timer sends: nothing while the git canister holds the floor;
/// otherwise the floor's worth, as far as the pool goes, and never more
/// than would leave this canister's liquid balance (`own`) under the
/// floor itself.
pub fn due(git_balance: u64, floor: u64, pool: u64, own: u64) -> u64 {
    if git_balance >= floor {
        return 0;
    }
    floor.min(pool).min(own.saturating_sub(floor))
}

/// The timer's top-up: ask the git canister what it holds, send what is
/// due from the pool. One at a time: a tick that finds another between
/// its asks sends nothing, so two cannot both judge the same balance.
/// Nothing is asked when there is nothing to send (no git canister, an
/// empty pool, or `own`, this canister's liquid balance, not above the
/// floor). The pool is debited before the deposit and credited back if
/// the deposit fails; a tick that could not send is on record. Answers
/// what was sent.
pub async fn top_up(
    balance_of: impl AsyncFn() -> Reply<u64>,
    own: u64,
    deposit: impl AsyncFn(u64) -> Result<(), String>,
) -> Result<u64, String> {
    if crate::peer::GIT.get().is_none() {
        return Ok(0);
    }
    let floor = crate::tenancy::git_canister_floor();
    if pool() == 0 || own <= floor {
        return Ok(0);
    }
    let Some(_tick) = Tick::begin() else {
        return Ok(0);
    };
    let balance = match balance_of().await {
        Ok(b) => b,
        Err(f) => return Err(record_failure(format!("the git canister did not say what it holds ({f})"))),
    };
    let cycles = due(balance, floor, pool(), own);
    if cycles == 0 {
        return Ok(0);
    }
    set_pool(pool().saturating_sub(cycles));
    if let Err(e) = deposit(cycles).await {
        earn(cycles);
        return Err(record_failure(format!("deposit_cycles: {e}")));
    }
    record_sent(cycles, Some(balance));
    Ok(cycles)
}

/// An operator's top-up, from this canister's own cycles: not the pool.
pub async fn top_up_by_operator(cycles: u64, deposit: impl AsyncFn(u64) -> Result<(), String>) -> Result<(), String> {
    if crate::peer::GIT.get().is_none() {
        return Err("no git canister is named".into());
    }
    if cycles == 0 {
        return Err("nothing to send".into());
    }
    deposit(cycles).await.map_err(|e| format!("deposit_cycles: {e}"))?;
    record_sent(cycles, None);
    Ok(())
}

/// `deposit_cycles` on the management canister, with `cycles` attached,
/// to the named git canister.
pub async fn deposit(cycles: u64) -> Result<(), String> {
    let git = crate::peer::GIT.get().ok_or("no git canister is named")?;
    ic_dev_kit_rs::intercanister::call_with_payment(
        Principal::management_canister(),
        "deposit_cycles",
        (crate::apps::CanisterIdArg { canister_id: git },),
        cycles as u128,
    )
    .await
}

/// The timer's top-up with the canister's own calls: the git canister
/// asked over messages, this canister's liquid balance (what it may
/// attach to a call: its balance less its freezing threshold), the
/// deposit above.
pub async fn top_up_git() -> Result<u64, String> {
    let own = u64::try_from(ic_cdk::api::canister_liquid_cycle_balance()).unwrap_or(u64::MAX);
    top_up(async || crate::peer::GIT_CANISTER.cycle_balance().await, own, deposit).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use ic_git_types::side::Failure;
    use std::cell::{Cell, RefCell};

    const T: u64 = 1_000_000_000_000;

    /// Nothing while the git canister holds the floor; under it, the
    /// floor's worth, bounded by the pool and by what leaves this
    /// canister the floor.
    #[test]
    fn what_is_due() {
        assert_eq!(due(T, T, 10 * T, 10 * T), 0, "at the floor");
        assert_eq!(due(2 * T, T, 10 * T, 10 * T), 0, "above it");
        assert_eq!(due(T - 1, T, 10 * T, 10 * T), T, "under it: the floor's worth");
        assert_eq!(due(0, T, T / 2, 10 * T), T / 2, "as far as the pool goes");
        assert_eq!(due(0, T, 10 * T, T + 5), 5, "leaving this canister the floor");
        assert_eq!(due(0, T, 10 * T, T / 2), 0, "and nothing when it has less");
        assert_eq!(due(0, 0, 10 * T, 10 * T), 0, "a floor of 0 is no floor");
    }

    /// The pool is what charges put in, less what the timer sent.
    #[test]
    fn the_pool_is_charges_less_top_ups() {
        crate::kv::remove(POOL_KEY);
        crate::kv::remove(SENT_KEY);
        crate::kv::remove(crate::peer::GIT.key);
        earn(0);
        assert_eq!(pool(), 0);
        earn(3);
        earn(4);
        assert_eq!(pool(), 7);
        assert_eq!(funding().pool, 7);
        assert_eq!(funding().git_canister, None);
        assert_eq!(funding().floor, crate::tenancy::DEFAULT_GIT_CANISTER_FLOOR);
        crate::kv::remove(POOL_KEY);
    }

    /// The timer sends only with a git canister named, only from a pool
    /// that holds something, only when the git canister is under the
    /// floor; the pool is debited before the deposit and refunded when it
    /// fails; a git canister that does not answer sends nothing.
    #[test]
    fn the_timer_tops_up_from_the_pool() {
        crate::kv::remove(POOL_KEY);
        crate::kv::remove(SENT_KEY);
        crate::kv::remove(crate::peer::GIT.key);
        let mut pricing = crate::tenancy::Pricing::default();
        pricing.git_canister_floor = Some(T);
        crate::tenancy::set_pricing(pricing);
        let balance: RefCell<Reply<u64>> = RefCell::new(Ok(0));
        let asked = Cell::new(0);
        let balance_of = async || {
            asked.set(asked.get() + 1);
            balance.borrow().clone()
        };
        let deposited: RefCell<Vec<u64>> = RefCell::new(Vec::new());
        let refuse = Cell::new(false);
        let deposit = async |c: u64| {
            if refuse.get() {
                return Err("stopped".to_string());
            }
            deposited.borrow_mut().push(c);
            Ok(())
        };

        earn(T / 4);
        assert_eq!(block_on(top_up(balance_of, 10 * T, deposit)), Ok(0), "no git canister named");
        assert_eq!(asked.get(), 0);
        crate::peer::GIT.set(Principal::from_slice(&[7; 8]));
        set_pool(0);
        assert_eq!(block_on(top_up(balance_of, 10 * T, deposit)), Ok(0), "an empty pool");
        assert_eq!(asked.get(), 0, "not even asked");

        earn(T / 4);
        *balance.borrow_mut() = Ok(T);
        assert_eq!(block_on(top_up(balance_of, 10 * T, deposit)), Ok(0), "at the floor");
        assert_eq!(asked.get(), 1);
        assert_eq!(pool(), T / 4);

        *balance.borrow_mut() = Ok(T / 2);
        assert_eq!(block_on(top_up(balance_of, T, deposit)), Ok(0), "this canister has no more than the floor");
        assert_eq!(asked.get(), 1, "not asked");
        refuse.set(true);
        let e = block_on(top_up(balance_of, 10 * T, deposit)).unwrap_err();
        assert!(e.contains("stopped"), "{e}");
        assert_eq!(pool(), T / 4, "refunded");
        assert_eq!(funding().sent, 0);
        assert_eq!(funding().last_failure.map(|f| f.error), Some(e), "on record");
        assert!(!IN_FLIGHT.with(|f| f.get()), "the tick is over");

        refuse.set(false);
        assert_eq!(block_on(top_up(balance_of, 10 * T, deposit)), Ok(T / 4));
        assert_eq!(*deposited.borrow(), vec![T / 4]);
        assert_eq!(pool(), 0);
        let f = funding();
        assert_eq!(f.sent, T / 4);
        assert_eq!(f.last.as_ref().map(|l| (l.cycles, l.balance_before)), Some((T / 4, Some(T / 2))));

        earn(T);
        *balance.borrow_mut() = Err(Failure::NotDelivered("stopped".into()));
        let e = block_on(top_up(balance_of, 10 * T, deposit)).unwrap_err();
        assert!(e.contains("did not say"), "{e}");
        assert_eq!(pool(), T, "nothing moved");
        assert!(funding().last_failure.is_some_and(|f| f.error.contains("did not say")));

        // Two ticks at once: the second finds the first between its asks
        // and sends nothing, so both cannot both judge the same balance.
        *balance.borrow_mut() = Ok(0);
        let first = Tick::begin().expect("no tick in flight");
        assert_eq!(block_on(top_up(balance_of, 10 * T, deposit)), Ok(0));
        assert_eq!(pool(), T, "the pool is the first tick's to spend");
        drop(first);
        assert_eq!(block_on(top_up(balance_of, 10 * T, deposit)), Ok(T), "the floor's worth, once the first is over");

        assert_eq!(pool(), 0);

        // An operator's top-up is not the pool's.
        earn(T);
        assert_eq!(block_on(top_up_by_operator(5, deposit)), Ok(()));
        assert_eq!(pool(), T);
        assert_eq!(*deposited.borrow(), vec![T / 4, T, 5]);
        assert_eq!(funding().sent, T / 4 + T + 5);
        assert!(block_on(top_up_by_operator(0, deposit)).is_err());
        crate::kv::remove(crate::peer::GIT.key);
        assert!(block_on(top_up_by_operator(5, deposit)).unwrap_err().contains("no git canister"));

        crate::kv::remove(POOL_KEY);
        crate::kv::remove(SENT_KEY);
        crate::tenancy::set_pricing(crate::tenancy::Pricing::default());
    }
}
