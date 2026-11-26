//! Gas balances (docs/EVM_GAS.md, section 3): what a tenant holds of the
//! EVM chain's asset on the IC side -- ckETH for Ethereum, ckSepoliaETH
//! for Sepolia -- to pay for the gas of the transactions ic-git sends for
//! them. This module holds the balance, moves the asset in and out, and
//! charges each transaction against it (section 4):
//!
//! - **Reserve before signing.** `reserve` takes `gas_limit * max_fee`,
//!   with the markup on it, from what is available into what is reserved,
//!   and refuses when it is short. The hold is stored at once, before any
//!   await, so an upgrade between the reserve and the broadcast leaves it
//!   on record rather than reserved and forgotten.
//! - **Settle on the receipt.** `settle_tx` charges the receipt's
//!   `gas_used * effective_gas_price` plus the markup, never more than the
//!   hold, and makes the rest available again. A reverted transaction used
//!   gas and is charged for it.
//! - **Release what never went out.** A send refused before any provider
//!   could hold it releases its hold whole; one whose outcome is unknown
//!   keeps it until a receipt settles it, or the operators release it
//!   (`release_hold`) for a transaction that never landed.
//!
//! - **One ledger at a time.** The asset is the ledger the operators set
//!   (`set_gas_ledger`), or else the ck ledger of the chain the EVM config
//!   names. Balances are kept per ledger, so a change of ledger leaves
//!   what was held on the old one where it is, and never relabels it.
//! - **Amounts are the ledger's base units.** ckETH has 18 decimals, so a
//!   unit is one wei of the chain's own token: the same number a receipt
//!   gives as `gas_used * effective_gas_price`.
//! - **A deposit** is the tenant's `icrc2_approve` of this canister for the
//!   amount plus one ledger fee, then `deposit_gas(amount)`, which pulls the
//!   amount with `icrc2_transfer_from` into this canister's own account and
//!   credits it whole: the ledger takes its fee from the tenant on top.
//! - **A withdrawal** debits the amount first and sends it, less one
//!   ledger fee, to the caller's own account with `icrc1_transfer`. The fee
//!   is read from the ledger and named in the transfer, so a fee that has
//!   changed in between is refused by the ledger rather than paid.
//!
//! Every transfer is recorded as pending before anything moves, under an
//! id that is also its `created_at_time`, as icp.rs does it: the ledger
//! answers a replay within its dedup window with the first transfer's
//! block (`Duplicate`), so an outcome that is unknown is replayed safely
//! by `finish_gas_transfer(id)`. A refusal drops the entry (and, for a
//! withdrawal, gives the amount back), but only while no attempt has had
//! an unknown outcome: after one, the first transfer may have happened,
//! and a refused replay (the ledger unavailable, say) does not show it
//! did not, so the entry stays pending until a replay finds its block.
//! Where icp.rs drops a deposit on any refusal, this does not, because a
//! withdrawal given back after it was paid would pay a tenant twice. An
//! attempt cut off between its call and its reply (an upgrade drops the
//! reply, since the governor does not stop the canister to install) leaves
//! a stable `in_flight` mark, and the next attempt treats that like an
//! unknown outcome. A
//! replay past the window moves it to `failed_gas_transfers` for the
//! operators. One attempt at a time takes a transfer forward, for the
//! reason icp.rs gives (#186).

use crate::ledger::{Account, TransferFromArgs, TransferFromError};
use candid::{CandidType, Nat, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

/// The ckETH ledger on mainnet (fee 2,000,000,000,000 wei).
pub const CKETH_LEDGER: &str = "ss2fx-dyaaa-aaaar-qacoq-cai";
/// The ckSepoliaETH ledger on mainnet (fee 10,000,000,000 wei).
pub const CKSEPOLIAETH_LEDGER: &str = "apia6-jaaaa-aaaar-qabma-cai";
/// The smallest deposit, in ledger fees: a deposit worth less than a few
/// fees costs the tenant more in fees than it holds.
pub const MIN_DEPOSIT_FEES: u128 = 10;

const LEDGER_KEY: &str = "gas:ledger";
const PENDING_KEY: &str = "gas:pending";
const FAILED_KEY: &str = "gas:failed";
const SETTLED_KEY: &str = "gas:settled";
const LAST_ID_KEY: &str = "gas:last_id";
/// How many settled transfers are remembered, to answer a late finish.
const SETTLED_KEEP: usize = 200;

// --- the ledger ------------------------------------------------------------------

/// The ck ledger of an EVM chain, by its chain id.
pub fn default_ledger(chain_id: u64) -> Option<Principal> {
    match chain_id {
        1 => Principal::from_text(CKETH_LEDGER).ok(),
        11_155_111 => Principal::from_text(CKSEPOLIAETH_LEDGER).ok(),
        _ => None,
    }
}

/// The ledger gas is held on: the operators' choice, or the ck ledger of
/// the configured chain.
pub fn ledger() -> Result<Principal, String> {
    if let Some(p) = set_ledger_now() {
        return Ok(p);
    }
    let cfg = crate::evm::get_config().ok_or("no EVM config, so no chain whose gas to hold; call evm_set_config first")?;
    ledger_of(None, cfg.chain_id)
}

fn set_ledger_now() -> Option<Principal> {
    crate::kv::get_json::<String>(LEDGER_KEY).and_then(|t| Principal::from_text(t).ok())
}

/// The ledger that holds the gas of a transaction on `chain_id`: the one
/// the operators set, or the chain's own ck asset. A send reads it with
/// the chain config it signs with, before any await, so a config changed
/// while the send waits cannot charge one chain's gas in another's asset.
pub fn ledger_for_chain(chain_id: u64) -> Result<Principal, String> {
    ledger_of(set_ledger_now(), chain_id)
}

fn ledger_of(set: Option<Principal>, chain_id: u64) -> Result<Principal, String> {
    set.or_else(|| default_ledger(chain_id))
        .ok_or_else(|| format!("chain {chain_id} has no ck asset to hold its gas in; set one with set_gas_ledger"))
}

/// Set the ledger, or with `None` go back to the configured chain's own.
pub fn set_ledger(p: Option<Principal>) {
    crate::kv::set_json(LEDGER_KEY, &p.map(|p| p.to_text()));
}

/// What a person reads an amount on `ledger` as: in ETH for the known ck
/// ledgers, which have 18 decimals, else in the ledger's base units.
pub fn amount_text(ledger: &Principal, amount: u128) -> String {
    let symbol = match ledger.to_text().as_str() {
        CKETH_LEDGER => "ckETH",
        CKSEPOLIAETH_LEDGER => "ckSepoliaETH",
        _ => return format!("{amount} units of the gas ledger {ledger}"),
    };
    const ONE: u128 = 1_000_000_000_000_000_000;
    let frac = format!("{:018}", amount % ONE);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        format!("{} {symbol}", amount / ONE)
    } else {
        format!("{}.{frac} {symbol}", amount / ONE)
    }
}

// --- balances ----------------------------------------------------------------------

/// One principal's gas balance on one ledger.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GasAccount {
    /// The ledger this balance is held on.
    #[serde(default = "anonymous")]
    pub ledger: Principal,
    /// What may be spent or withdrawn, in the ledger's base units.
    pub available: u128,
    /// Lifetime totals, for the console.
    pub deposited: u128,
    pub withdrawn: u128,
    pub created_ns: u64,
    /// Held for transactions sent and not yet settled.
    #[serde(default)]
    pub reserved: u128,
    /// What settled transactions cost on the chain, and the markup on it.
    #[serde(default)]
    pub spent: u128,
    #[serde(default)]
    pub markup: u128,
    /// What has come back to it out of the markup's surplus.
    #[serde(default)]
    pub credited: u128,
}

impl Default for GasAccount {
    fn default() -> Self {
        GasAccount { ledger: anonymous(), available: 0, deposited: 0, withdrawn: 0, created_ns: 0, reserved: 0, spent: 0, markup: 0, credited: 0 }
    }
}

fn anonymous() -> Principal {
    Principal::anonymous()
}

fn account_key(ledger: &Principal, who: &Principal) -> String {
    format!("gas:account:{}:{}", ledger.to_text(), who.to_text())
}

/// `who`'s balance on `ledger`; an empty one if they never held any.
pub fn account_on(ledger: &Principal, who: &Principal) -> GasAccount {
    let mut a: GasAccount = crate::kv::get_json(&account_key(ledger, who)).unwrap_or_default();
    a.ledger = *ledger;
    a
}

/// `who`'s balance on the ledger in force, or why there is none.
pub fn account(who: &Principal) -> Result<GasAccount, String> {
    Ok(account_on(&ledger()?, who))
}

fn save(ledger: &Principal, who: &Principal, a: &GasAccount) {
    crate::kv::set_json(&account_key(ledger, who), a);
}

pub(crate) fn credit(ledger: &Principal, who: &Principal, amount: u128) -> GasAccount {
    let mut a = account_on(ledger, who);
    if a.created_ns == 0 {
        a.created_ns = crate::clock::now_ns();
    }
    a.available = a.available.saturating_add(amount);
    a.deposited = a.deposited.saturating_add(amount);
    save(ledger, who, &a);
    a
}

/// Does `who`'s balance on `ledger` cover `amount`? The refusal if not.
pub fn covers(ledger: &Principal, who: &Principal, amount: u128) -> Result<(), String> {
    let available = account_on(ledger, who).available;
    if available < amount {
        return Err(format!(
            "the gas balance holds {}, less than the {} asked for",
            amount_text(ledger, available),
            amount_text(ledger, amount)
        ));
    }
    Ok(())
}

/// Take `amount` out for a withdrawal, before anything is sent.
fn debit_for_withdrawal(ledger: &Principal, who: &Principal, amount: u128) -> Result<(), String> {
    covers(ledger, who, amount)?;
    let mut a = account_on(ledger, who);
    a.available -= amount;
    a.withdrawn = a.withdrawn.saturating_add(amount);
    save(ledger, who, &a);
    Ok(())
}

/// Give back a withdrawal the ledger refused: nothing left.
fn undo_withdrawal(ledger: &Principal, who: &Principal, amount: u128) {
    let mut a = account_on(ledger, who);
    a.available = a.available.saturating_add(amount);
    a.withdrawn = a.withdrawn.saturating_sub(amount);
    save(ledger, who, &a);
}

// --- reserving and settling transactions -----------------------------------------------

const HOLDS_KEY: &str = "gas:holds";
const LAST_HOLD_KEY: &str = "gas:last_hold";
const TOTALS_PREFIX: &str = "gas:totals:";
/// How many settled charges an account keeps, for the console.
const CHARGES_KEEP: usize = 50;

/// What a transaction holds of its payer's balance until it is settled.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GasHold {
    pub id: u64,
    pub who: Principal,
    pub ledger: Principal,
    /// `gas_limit * max_fee`, with the markup on it.
    pub amount: u128,
    /// The markup in force when it was reserved, which its settlement uses.
    pub markup_bps: u32,
    /// Set once the transaction is signed, before it is broadcast.
    pub tx_hash: Option<String>,
    pub at_ns: u64,
    /// What it was signed as; set with `tx_hash`.
    #[serde(default)]
    pub signed: Option<SignedTx>,
}

/// What a hold's transaction was signed as. Whether it can still be mined
/// is a question about this chain, this address and this nonce
/// (evm.rs, `recheck_stale_holds`), which the nonce store cannot answer:
/// it lags what was signed after `evm_reset_nonce`, or an upgrade that
/// dropped a broadcast's reply.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SignedTx {
    pub chain_id: u64,
    pub from: String,
    pub nonce: u64,
}

/// One settled transaction, as its payer's account keeps it.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GasCharge {
    pub tx_hash: String,
    pub gas_used: u128,
    pub effective_gas_price: u128,
    /// `gas_used * effective_gas_price`, and the markup on it: their sum is
    /// what the balance paid.
    pub cost: u128,
    pub markup: u128,
    pub at_ns: u64,
}

/// What every payer's settled transactions on one ledger came to: what
/// the EOA spent for them, and what the markup collected toward refills.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GasTotals {
    pub spent: u128,
    pub markup: u128,
    /// What refilling the EOA has cost: ledger fees, the minter's gas, and
    /// any part of a failed refill not given back (refill.rs). The markup
    /// is there to pay for it.
    #[serde(default)]
    pub refill_costs: u128,
    /// What has been credited back to balances out of the markup's surplus.
    #[serde(default)]
    pub credited: u128,
}

impl GasTotals {
    /// What the markup collected and neither refills cost nor was credited.
    pub fn surplus(&self) -> u128 {
        self.markup.saturating_sub(self.refill_costs).saturating_sub(self.credited)
    }
}

pub(crate) fn save_totals(ledger: &Principal, t: &GasTotals) {
    crate::kv::set_json(&format!("{TOTALS_PREFIX}{}", ledger.to_text()), t);
}

/// The markup on `cost` at `bps` basis points, rounded up: it errs high,
/// as an overcharge is the cheap one to put right.
pub fn markup_of(cost: u128, bps: u32) -> u128 {
    let m = cost.saturating_mul(bps as u128);
    m / 10_000 + u128::from(!m.is_multiple_of(10_000))
}

pub fn holds() -> Vec<GasHold> {
    crate::kv::get_json(HOLDS_KEY).unwrap_or_default()
}

fn save_holds(all: &[GasHold]) {
    crate::kv::set_json(HOLDS_KEY, &all);
}

fn take_hold(pred: impl Fn(&GasHold) -> bool) -> Option<GasHold> {
    let mut all = holds();
    let i = all.iter().position(pred)?;
    let h = all.remove(i);
    save_holds(&all);
    Some(h)
}

/// Reserve what a transaction of `gas_limit` gas at `max_fee` wei a unit
/// may cost `who` on `ledger`, with the markup on it. The ledger is the
/// caller's, read with the chain config the transaction is signed with
/// (`ledger_for_chain`), not the one in force now. Stored before it
/// returns.
pub fn reserve(who: &Principal, ledger: Principal, gas_limit: u64, max_fee: u128) -> Result<GasHold, String> {
    let bps = crate::tenancy::gas_markup_bps();
    let amount = hold_amount(gas_limit, max_fee);
    let mut a = account_on(&ledger, who);
    if a.available < amount {
        return Err(format!(
            "the gas balance holds {}, less than the {} this transaction may cost ({gas_limit} gas \
             at {max_fee} wei, with a {bps} basis point markup); deposit with deposit_gas",
            amount_text(&ledger, a.available),
            amount_text(&ledger, amount)
        ));
    }
    a.available -= amount;
    a.reserved = a.reserved.saturating_add(amount);
    save(&ledger, who, &a);
    let id = crate::clock::now_ns().max(crate::kv::get_json::<u64>(LAST_HOLD_KEY).unwrap_or(0).saturating_add(1));
    crate::kv::set_json(LAST_HOLD_KEY, &id);
    let hold = GasHold { id, who: *who, ledger, amount, markup_bps: bps, tx_hash: None, at_ns: crate::clock::now_ns(), signed: None };
    let mut all = holds();
    all.push(hold.clone());
    save_holds(&all);
    Ok(hold)
}

/// What `reserve` holds for a transaction of `gas_limit` gas at `max_fee`
/// wei a unit: the most it may cost, with the markup in force on it.
pub fn hold_amount(gas_limit: u64, max_fee: u128) -> u128 {
    let cost = (gas_limit as u128).saturating_mul(max_fee);
    cost.saturating_add(markup_of(cost, crate::tenancy::gas_markup_bps()))
}

/// The holds on `ledger` whose transaction is signed and named, made
/// before `before_ns`: past their receipt polls (evm.rs). `who`'s come
/// first, then the oldest.
pub fn stale_holds(ledger: &Principal, who: &Principal, before_ns: u64) -> Vec<GasHold> {
    let mut out: Vec<GasHold> = holds()
        .into_iter()
        .filter(|h| h.ledger == *ledger && h.tx_hash.is_some() && h.signed.is_some() && h.at_ns < before_ns)
        .collect();
    out.sort_by_key(|h| (h.who != *who, h.at_ns));
    out
}

/// Name the signed transaction a hold is for, and what it was signed as,
/// before it is broadcast, so its receipt can find the hold.
pub fn attach(hold_id: u64, tx_hash: &str, signed: SignedTx) {
    let mut all = holds();
    if let Some(h) = all.iter_mut().find(|h| h.id == hold_id) {
        h.tx_hash = Some(tx_hash.to_ascii_lowercase());
        h.signed = Some(signed);
        save_holds(&all);
    }
}

fn give_back(h: &GasHold) {
    let mut a = account_on(&h.ledger, &h.who);
    a.reserved = a.reserved.saturating_sub(h.amount);
    a.available = a.available.saturating_add(h.amount);
    save(&h.ledger, &h.who, &a);
}

/// A send no provider can hold: its hold goes back whole.
pub fn release(hold_id: u64) {
    if let Some(h) = take_hold(|h| h.id == hold_id) {
        give_back(&h);
    }
}

/// The operators' release of a hold whose transaction never landed (it
/// was dropped from every mempool), by the hold's id.
pub fn release_hold(hold_id: u64) -> Result<GasHold, String> {
    let h = take_hold(|h| h.id == hold_id).ok_or_else(|| format!("no gas hold {hold_id}"))?;
    give_back(&h);
    Ok(h)
}

pub fn totals(ledger: &Principal) -> GasTotals {
    crate::kv::get_json(&format!("{TOTALS_PREFIX}{}", ledger.to_text())).unwrap_or_default()
}

fn charges_key(ledger: &Principal, who: &Principal) -> String {
    format!("gas:charges:{}:{}", ledger.to_text(), who.to_text())
}

/// `who`'s most recent settled charges on the ledger in force, newest last.
pub fn charges(who: &Principal) -> Result<Vec<GasCharge>, String> {
    Ok(charges_on(&ledger()?, who))
}

pub fn charges_on(ledger: &Principal, who: &Principal) -> Vec<GasCharge> {
    crate::kv::get_json(&charges_key(ledger, who)).unwrap_or_default()
}

/// Settle the transaction `tx_hash` on its receipt, if it holds any
/// balance: charge what it cost and the markup, never more than its hold,
/// and give the rest back. Once: a second receipt finds no hold.
pub fn settle_tx(tx_hash: &str, gas_used: u128, effective_gas_price: u128) -> Option<GasCharge> {
    let tx = tx_hash.to_ascii_lowercase();
    let h = take_hold(|h| h.tx_hash.as_deref() == Some(tx.as_str()))?;
    let cost = gas_used.saturating_mul(effective_gas_price).min(h.amount);
    let markup = markup_of(cost, h.markup_bps).min(h.amount - cost);
    let mut a = account_on(&h.ledger, &h.who);
    a.reserved = a.reserved.saturating_sub(h.amount);
    a.available = a.available.saturating_add(h.amount - cost - markup);
    a.spent = a.spent.saturating_add(cost);
    a.markup = a.markup.saturating_add(markup);
    save(&h.ledger, &h.who, &a);
    let mut t = totals(&h.ledger);
    t.spent = t.spent.saturating_add(cost);
    t.markup = t.markup.saturating_add(markup);
    save_totals(&h.ledger, &t);
    let charge = GasCharge { tx_hash: tx, gas_used, effective_gas_price, cost, markup, at_ns: crate::clock::now_ns() };
    let key = charges_key(&h.ledger, &h.who);
    let mut list: Vec<GasCharge> = crate::kv::get_json(&key).unwrap_or_default();
    list.push(charge.clone());
    if list.len() > CHARGES_KEEP {
        let drop = list.len() - CHARGES_KEEP;
        list.drain(0..drop);
    }
    crate::kv::set_json(&key, &list);
    Some(charge)
}

// --- what ic-git owes, and the surplus ---------------------------------------------------

/// Every balance held on `ledger`, by principal.
pub fn accounts_on(ledger: &Principal) -> Vec<(Principal, GasAccount)> {
    let prefix = format!("gas:account:{}:", ledger.to_text());
    crate::kv::keys_with_prefix(&prefix)
        .into_iter()
        .filter_map(|k| Principal::from_text(&k[prefix.len()..]).ok())
        .map(|who| (who, account_on(ledger, &who)))
        .collect()
}

/// What of ic-git's balance on `ledger` is the tenants': every balance,
/// available or held; every withdrawal debited and not yet known to be
/// sent; and every deposit that may have been pulled and is not yet
/// credited. It errs high, so that a refill never spends a tenant's.
pub fn owed_on(ledger: &Principal) -> u128 {
    let held = accounts_on(ledger)
        .iter()
        .fold(0u128, |s, (_, a)| s.saturating_add(a.available).saturating_add(a.reserved));
    let pending = pending()
        .iter()
        .filter(|p| p.ledger == *ledger && (p.direction == GasDirection::Withdrawal || p.uncertain || p.in_flight))
        .fold(0u128, |s, p| s.saturating_add(p.amount));
    let failed = failed().iter().filter(|f| f.ledger == *ledger).fold(0u128, |s, f| s.saturating_add(f.amount));
    held.saturating_add(pending).saturating_add(failed)
}

/// `a * b / c`, exactly, rounded down; `c` is not 0.
fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    let n = Nat::from(a) * Nat::from(b) / Nat::from(c);
    u128::try_from(n.0).unwrap_or(u128::MAX)
}

/// Shares of `amount` in proportion to `weights`, rounded down, so they
/// never sum to more than `amount`.
fn pro_rata(amount: u128, weights: &[u128]) -> Vec<u128> {
    let total = weights.iter().fold(0u128, |s, w| s.saturating_add(*w));
    if total == 0 {
        return vec![0; weights.len()];
    }
    weights.iter().map(|w| mul_div(amount, *w, total)).collect()
}

/// Credit the markup's surplus on the ledger in force back to the balances
/// it came from, in proportion to the markup each has paid (section 4).
/// An entry in this canister's books: no ledger transfer, no fee. Returns
/// what was credited.
pub fn credit_surplus() -> Result<u128, String> {
    let ledger = ledger()?;
    // A refill under way has costs not booked yet: the surplus would be
    // counted high, and credited from what those costs will take.
    if let Some(why) = crate::refill::busy(&ledger) {
        return Err(format!("{why}, so what refilling costs is not known yet; credit the surplus once it is"));
    }
    let mut t = totals(&ledger);
    let surplus = t.surplus();
    let accounts = accounts_on(&ledger);
    let shares = pro_rata(surplus, &accounts.iter().map(|(_, a)| a.markup).collect::<Vec<_>>());
    let mut given = 0u128;
    for ((who, _), share) in accounts.iter().zip(shares) {
        if share > 0 {
            credit_markup_back(&ledger, who, share);
            given = given.saturating_add(share);
        }
    }
    t.credited = t.credited.saturating_add(given);
    save_totals(&ledger, &t);
    Ok(given)
}

fn credit_markup_back(ledger: &Principal, who: &Principal, amount: u128) {
    let mut a = account_on(ledger, who);
    a.available = a.available.saturating_add(amount);
    a.credited = a.credited.saturating_add(amount);
    save(ledger, who, &a);
}

// --- the float ---------------------------------------------------------------------

/// How many receipts the cost per transaction is the mean of.
const COSTS_KEEP: usize = 50;
/// The gas of a transaction for the cost per transaction, until a chain
/// has receipts to measure it by: about what a registry write uses.
pub const FALLBACK_TX_GAS: u128 = 100_000;

fn costs_key(chain_id: u64) -> String {
    format!("gas:costs:{chain_id}")
}

/// One receipt the cost per transaction is the mean of.
#[derive(Serialize, Deserialize)]
struct CostSample {
    tx: String,
    /// Where it was mined: the block number, then the index in the block.
    mined_at: (u128, u128),
    cost: u128,
}

/// Note what one of the EOA's transactions on `chain_id` cost, from its
/// receipt, ic-git's own sends and tenants' alike, once per transaction.
/// The EOA's transactions are mined in nonce order, so a receipt counts
/// only if it was mined after the newest one counted: one read again after
/// it has left the window cannot come back into it, and one read out of
/// order is passed over, which only loses a sample. The hash is checked as
/// well, for a reorg that mines a counted transaction again later.
pub fn observe_cost(chain_id: u64, tx_hash: &str, mined_at: (u128, u128), cost: u128) {
    let tx = tx_hash.to_ascii_lowercase();
    let key = costs_key(chain_id);
    let mut list: Vec<CostSample> = crate::kv::get_json(&key).unwrap_or_default();
    if list.last().is_some_and(|s| s.mined_at >= mined_at) || list.iter().any(|s| s.tx == tx) {
        return;
    }
    list.push(CostSample { tx, mined_at, cost });
    if list.len() > COSTS_KEEP {
        let drop = list.len() - COSTS_KEEP;
        list.drain(0..drop);
    }
    crate::kv::set_json(&key, &list);
}

/// The mean cost of the chain's recent transactions, if it has any.
pub fn measured_cost(chain_id: u64) -> Option<u128> {
    let list: Vec<CostSample> = crate::kv::get_json(&costs_key(chain_id)).unwrap_or_default();
    mean(list.iter().map(|s| s.cost))
}

fn mean(costs: impl Iterator<Item = u128>) -> Option<u128> {
    let (sum, n) = costs.fold((0u128, 0u128), |(s, n), c| (s.saturating_add(c), n + 1));
    (n > 0).then(|| sum / n)
}

/// The cost per transaction the float is sized by: the measured mean, or
/// `FALLBACK_TX_GAS` at `max_fee` before there is one.
pub fn unit_cost(chain_id: u64, max_fee: u128) -> u128 {
    measured_cost(chain_id).unwrap_or_else(|| FALLBACK_TX_GAS.saturating_mul(max_fee))
}

/// What all open holds on `ledger` come to.
pub fn held_on(ledger: &Principal) -> u128 {
    holds().iter().filter(|h| h.ledger == *ledger).fold(0u128, |s, h| s.saturating_add(h.amount))
}

/// Section 5's invariant: after a tenant's send is reserved, the EOA still
/// holds every open hold and the margin. `held` includes the new hold.
pub fn float_covers(balance: u128, held: u128, margin: u128) -> Result<(), String> {
    let need = held.saturating_add(margin);
    if balance >= need {
        return Ok(());
    }
    Err(format!(
        "ic-git's EOA holds {balance} wei, under the {need} wei its open gas holds and margin need; \
         the operators refill it, and the send can be retried then"
    ))
}

const FLOAT_KEY: &str = "gas:float";

/// The EOA's balance as last read, for `get_gas_float` to answer without an
/// outcall of its own.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BalanceRead {
    pub chain_id: u64,
    pub address: String,
    pub wei: u128,
    /// The fee cap read with it, for the cost per transaction before any
    /// receipt has measured it.
    pub max_fee: u128,
    pub at_ns: u64,
}

pub fn note_balance(read: &BalanceRead) {
    crate::kv::set_json(FLOAT_KEY, read);
}

pub fn last_balance() -> Option<BalanceRead> {
    crate::kv::get_json(FLOAT_KEY)
}

/// ic-git's float, in wei: what the EOA held when last read, against the
/// target, the floor and the margin, each a count of transactions at the
/// cost per transaction (docs/EVM_GAS.md, section 5).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GasFloat {
    pub balance: Option<BalanceRead>,
    /// The mean of the chain's recent receipts; `None` before it has any,
    /// when the sizes below use `FALLBACK_TX_GAS` at the fee cap.
    pub measured_cost: Option<u128>,
    /// 0, and every size below with it, until a receipt has measured the
    /// cost or a balance read has given a fee cap: `balance` is `None`
    /// then, and `gas_float_refresh` reads both.
    pub unit_cost: u128,
    pub target: u128,
    pub floor: u128,
    pub margin: u128,
    /// The sum of open holds on the gas ledger.
    pub held: u128,
}

pub fn float_view(chain_id: u64, max_fee: u128) -> Result<GasFloat, String> {
    let unit = unit_cost(chain_id, max_fee);
    let p = crate::tenancy::pricing();
    let times = |n: Option<u32>| unit.saturating_mul(n.unwrap_or(0) as u128);
    Ok(GasFloat {
        balance: last_balance().filter(|b| b.chain_id == chain_id),
        measured_cost: measured_cost(chain_id),
        unit_cost: unit,
        target: times(p.float_target_txs),
        floor: times(p.float_floor_txs),
        margin: times(p.float_margin_txs),
        held: held_on(&ledger_for_chain(chain_id)?),
    })
}

// --- transfers in flight -------------------------------------------------------------

#[derive(CandidType, Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum GasDirection {
    Deposit,
    Withdrawal,
}

/// A transfer that has not been settled yet.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PendingGasTransfer {
    /// Also the transfer's `created_at_time`, which makes a replay of it
    /// idempotent on the ledger.
    pub id: u64,
    pub direction: GasDirection,
    pub who: Principal,
    /// What the balance gains (a deposit) or loses (a withdrawal).
    pub amount: u128,
    /// The fee a withdrawal names, and takes out of the amount; 0 for a
    /// deposit, whose fee the ledger takes from the tenant on top.
    pub fee: u128,
    /// The ledger it is on: every replay uses this one, not the ledger in
    /// force, since a replay must repeat the first transfer exactly.
    pub ledger: Principal,
    pub at_ns: u64,
    pub last_error: Option<String>,
    /// An attempt's outcome was unknown, so the transfer may have
    /// happened. From then on a refusal is no proof that nothing moved:
    /// a replay refused while the ledger is unavailable, say, does not
    /// show the first attempt did not land. Only a block (the first
    /// transfer's, as `Duplicate`) settles it, or, past the ledger's
    /// dedup window, the operators.
    #[serde(default)]
    pub uncertain: bool,
    /// An attempt has sent the ledger call and not yet handled its reply.
    /// Stable, unlike the claim: an upgrade drops the reply of a call that
    /// is out (the governor installs without stopping the canister), and a
    /// trap after the reply rolls back what handling it wrote. The next
    /// attempt that finds this set knows an earlier one may have moved the
    /// asset, and marks the transfer `uncertain` before it asks again.
    #[serde(default)]
    pub in_flight: bool,
}

/// A transfer no replay can settle, kept for the operators.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FailedGasTransfer {
    pub id: u64,
    pub direction: GasDirection,
    pub who: Principal,
    pub amount: u128,
    pub ledger: Principal,
    pub error: String,
    pub at_ns: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Settled {
    id: u64,
    who: Principal,
    ledger: Principal,
}

pub fn pending() -> Vec<PendingGasTransfer> {
    crate::kv::get_json(PENDING_KEY).unwrap_or_default()
}

pub fn failed() -> Vec<FailedGasTransfer> {
    crate::kv::get_json(FAILED_KEY).unwrap_or_default()
}

thread_local! {
    /// What the withdrawals settled on each ledger since this canister
    /// started took, all told, so a reader of ic-git's balance on one can
    /// leave out what those that settled while it waited took (refill.rs).
    /// A settled withdrawal is the one change to the transfers in progress
    /// that takes from what is owed (`owed_on`) an amount the ledger may
    /// still have shown when the balance was read: a deposit is owed from
    /// before its call (`in_flight`), and a refused or lost withdrawal
    /// stays owed. Only a balance can raise it, by what it takes: a call
    /// refused at once changes nothing. On the heap: an upgrade drops the
    /// reply such a reader waits on, so no read spans one.
    static WITHDRAWN: RefCell<BTreeMap<Principal, u128>> = const { RefCell::new(BTreeMap::new()) };
    /// Set while the refill reads ic-git's ledger balance (`Reading`).
    static READING: Cell<bool> = const { Cell::new(false) };
}

/// What withdrawals settled on `ledger` have taken since this canister
/// started (`WITHDRAWN`). It wraps: readers take the difference of two.
pub fn withdrawn(ledger: &Principal) -> u128 {
    WITHDRAWN.with(|w| w.borrow().get(ledger).copied().unwrap_or(0))
}

fn count_withdrawn(ledger: &Principal, amount: u128) {
    WITHDRAWN.with(|w| {
        let mut w = w.borrow_mut();
        let total = w.entry(*ledger).or_insert(0);
        *total = total.wrapping_add(amount);
    });
}

/// Held while the refill reads ic-git's ledger balance: no withdrawal
/// sends its ledger call meanwhile (`not_while_reading`), so the only
/// ones that can settle during the read are those already out when it
/// began. A refused one costs its caller nothing but a retry.
pub struct Reading(());

impl Reading {
    pub fn start() -> Reading {
        READING.with(|r| r.set(true));
        Reading(())
    }
}

impl Drop for Reading {
    fn drop(&mut self) {
        READING.with(|r| r.set(false));
    }
}

/// Refuse a withdrawal's ledger call while the refill reads the balance.
/// Asked with no await between it and the call, so a withdrawal is either
/// out before the read begins or refused.
fn not_while_reading() -> Result<(), String> {
    if READING.with(|r| r.get()) {
        return Err("ic-git is reading its gas ledger balance to refill its EOA, which takes a few seconds; withdraw again then".into());
    }
    Ok(())
}

fn save_pending(all: &[PendingGasTransfer]) {
    crate::kv::set_json(PENDING_KEY, &all);
}

/// A fresh id: now in ns, bumped past the last one, so two transfers never
/// share a `created_at_time` (the ledger would take the second for a
/// replay of the first).
fn next_id() -> u64 {
    let last = crate::kv::get_json::<u64>(LAST_ID_KEY).unwrap_or(0);
    let id = crate::clock::now_ns().max(last.saturating_add(1));
    crate::kv::set_json(LAST_ID_KEY, &id);
    id
}

fn add_pending(p: PendingGasTransfer) {
    let mut all = pending();
    all.retain(|x| x.id != p.id);
    all.push(p);
    save_pending(&all);
}

fn get_pending(id: u64) -> Option<PendingGasTransfer> {
    pending().into_iter().find(|p| p.id == id)
}

/// Record a reply that leaves transfer `id` pending: its error, whether it
/// leaves the outcome unknown, and that no attempt is out any more.
fn note_error(id: u64, e: &str, uncertain: bool) {
    let mut all = pending();
    if let Some(p) = all.iter_mut().find(|p| p.id == id) {
        p.last_error = Some(e.to_string());
        p.uncertain |= uncertain;
        p.in_flight = false;
        save_pending(&all);
    }
}

/// Start an attempt on transfer `id`: if an earlier one sent its call and
/// never handled the reply, the transfer may have happened, so it is
/// uncertain from here on; then mark this attempt out, before its call.
fn begin_attempt(id: u64) -> Result<PendingGasTransfer, String> {
    let mut all = pending();
    let p = all.iter_mut().find(|p| p.id == id).ok_or_else(|| format!("no pending gas transfer {id}"))?;
    if p.in_flight {
        p.uncertain = true;
        p.last_error = Some("an earlier attempt's reply was never handled (an upgrade or a trap came between)".into());
    }
    p.in_flight = true;
    let out = p.clone();
    save_pending(&all);
    Ok(out)
}

/// Remove and return pending transfer `id`: the one step that hands a
/// transfer to exactly one settlement.
fn take_pending(id: u64) -> Option<PendingGasTransfer> {
    let mut all = pending();
    let i = all.iter().position(|p| p.id == id)?;
    let p = all.remove(i);
    save_pending(&all);
    Some(p)
}

fn record_settled(id: u64, who: Principal, ledger: Principal) {
    let mut all: Vec<Settled> = crate::kv::get_json(SETTLED_KEY).unwrap_or_default();
    all.push(Settled { id, who, ledger });
    if all.len() > SETTLED_KEEP {
        let drop = all.len() - SETTLED_KEEP;
        all.drain(0..drop);
    }
    crate::kv::set_json(SETTLED_KEY, &all);
}

fn settled(id: u64) -> Option<Settled> {
    crate::kv::get_json::<Vec<Settled>>(SETTLED_KEY).unwrap_or_default().into_iter().find(|s| s.id == id)
}

fn fail(id: u64, error: &str) {
    if let Some(p) = take_pending(id) {
        let mut all = failed();
        all.push(FailedGasTransfer {
            id,
            direction: p.direction,
            who: p.who,
            amount: p.amount,
            ledger: p.ledger,
            error: error.to_string(),
            at_ns: crate::clock::now_ns(),
        });
        crate::kv::set_json(FAILED_KEY, &all);
    }
}

/// Settle failed transfer `id` (operators), once its ledger shows whether
/// it happened: a transfer from or to its principal whose
/// `created_at_time` is `id`. A deposit that happened is credited, and a
/// withdrawal that did not is given back; a deposit that did not, or a
/// withdrawal that did, only leaves the list, its balance already right.
/// Either way it is settled from then on, so `finish_gas_transfer(id)`
/// reports the balance. Returns the account it is for.
pub fn resolve_failed(id: u64, happened: bool) -> Result<GasAccount, String> {
    let mut all = failed();
    let i = all.iter().position(|f| f.id == id).ok_or_else(|| format!("no failed gas transfer {id}"))?;
    let f = all.remove(i);
    crate::kv::set_json(FAILED_KEY, &all);
    match (f.direction, happened) {
        (GasDirection::Deposit, true) => {
            credit(&f.ledger, &f.who, f.amount);
        }
        (GasDirection::Withdrawal, false) => undo_withdrawal(&f.ledger, &f.who, f.amount),
        _ => {}
    }
    record_settled(f.id, f.who, f.ledger);
    Ok(account_on(&f.ledger, &f.who))
}

// --- outcomes -------------------------------------------------------------------------

/// What a transfer on the ledger came to.
#[derive(Debug, PartialEq)]
enum Moved {
    /// It happened (now or, for a replay, before) at this block.
    Block,
    /// Definitely refused: nothing moved.
    Refused(String),
    /// The reply was lost or undecodable: replay it.
    Unknown(String),
    /// A replay past the ledger's dedup window: whether the first attempt
    /// happened can no longer be told from here.
    Lost(String),
}

/// The errors `icrc1_transfer` and `icrc2_transfer_from` share, and the
/// one only the second has.
fn classify<E: std::fmt::Debug>(reply: Result<Result<Nat, E>, String>, what: &str, is_duplicate: impl Fn(&E) -> bool, is_too_old: impl Fn(&E) -> bool) -> Moved {
    match reply {
        Ok(Ok(_)) => Moved::Block,
        Ok(Err(e)) if is_duplicate(&e) => Moved::Block,
        Ok(Err(e)) if is_too_old(&e) => Moved::Lost(format!("the {what} is too old to replay on the ledger")),
        Ok(Err(e)) => Moved::Refused(format!("ledger {what}: {e:?}")),
        Err(e) => Moved::Unknown(format!("ledger {what} call: {e}")),
    }
}

fn classify_pull(reply: Result<Result<Nat, TransferFromError>, String>) -> Moved {
    classify(reply, "transfer_from", |e| matches!(e, TransferFromError::Duplicate { .. }), |e| matches!(e, TransferFromError::TooOld))
}

#[derive(CandidType)]
struct TransferArgs {
    from_subaccount: Option<Vec<u8>>,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
enum TransferError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    TemporarilyUnavailable,
    Duplicate { duplicate_of: Nat },
    GenericError { error_code: Nat, message: String },
}

fn classify_send(reply: Result<Result<Nat, TransferError>, String>) -> Moved {
    classify(reply, "transfer", |e| matches!(e, TransferError::Duplicate { .. }), |e| matches!(e, TransferError::TooOld))
}

/// Settle transfer `id` on its outcome; returns the balance it leaves.
fn settle(id: u64, moved: Moved) -> Result<u128, String> {
    match moved {
        Moved::Block => match take_pending(id) {
            Some(p) => {
                record_settled(p.id, p.who, p.ledger);
                Ok(match p.direction {
                    GasDirection::Deposit => credit(&p.ledger, &p.who, p.amount).available,
                    GasDirection::Withdrawal => {
                        count_withdrawn(&p.ledger, p.amount);
                        account_on(&p.ledger, &p.who).available
                    }
                })
            }
            None => settled(id).map(|s| account_on(&s.ledger, &s.who).available).ok_or_else(|| format!("no pending gas transfer {id}")),
        },
        Moved::Refused(e) if get_pending(id).is_some_and(|p| p.uncertain) => {
            note_error(id, &e, false);
            Err(format!(
                "{e}; an earlier attempt's outcome is unknown, so this refusal does not show that \
                 nothing moved. It stays pending: finish_gas_transfer({id}) again, and past the \
                 ledger's dedup window it goes to the operators"
            ))
        }
        Moved::Refused(e) => {
            if let Some(p) = take_pending(id) {
                if p.direction == GasDirection::Withdrawal {
                    undo_withdrawal(&p.ledger, &p.who, p.amount);
                }
            }
            Err(e)
        }
        Moved::Unknown(e) => {
            note_error(id, &e, true);
            Err(format!("{e}; the transfer's outcome is unknown, finish_gas_transfer({id}) replays it safely"))
        }
        Moved::Lost(e) => {
            fail(id, &e);
            Err(format!("{e}; recorded in failed_gas_transfers for the operators"))
        }
    }
}

// --- the calls -------------------------------------------------------------------------

pub(crate) async fn fee_of(ledger: Principal) -> Result<u128, String> {
    let fee: Nat = intercanister::call(ledger, "icrc1_fee", ()).await?;
    u128::try_from(fee.0).map_err(|_| "the gas ledger's fee is out of range".to_string())
}

async fn pull(p: &PendingGasTransfer) -> Moved {
    let reply: Result<Result<Nat, TransferFromError>, String> = intercanister::call(
        p.ledger,
        "icrc2_transfer_from",
        (TransferFromArgs {
            spender_subaccount: None,
            from: Account { owner: p.who, subaccount: None },
            to: Account { owner: ic_cdk::api::canister_self(), subaccount: None },
            amount: Nat::from(p.amount),
            fee: None,
            memo: None,
            // Identical on every replay: what makes a replay idempotent.
            created_at_time: Some(p.id),
        },),
    )
    .await;
    classify_pull(reply)
}

async fn send(p: &PendingGasTransfer) -> Moved {
    let reply: Result<Result<Nat, TransferError>, String> = intercanister::call(
        p.ledger,
        "icrc1_transfer",
        (TransferArgs {
            from_subaccount: None,
            to: Account { owner: p.who, subaccount: None },
            amount: Nat::from(p.amount - p.fee),
            fee: Some(Nat::from(p.fee)),
            memo: None,
            created_at_time: Some(p.id),
        },),
    )
    .await;
    classify_send(reply)
}

thread_local! {
    /// The transfers an attempt is taking forward now (`claim`).
    static ADVANCING: std::cell::RefCell<std::collections::BTreeSet<u64>> = const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
}

#[derive(Debug)]
struct Claim(u64);

impl Drop for Claim {
    fn drop(&mut self) {
        ADVANCING.with(|a| a.borrow_mut().remove(&self.0));
    }
}

fn claim(id: u64) -> Result<Claim, String> {
    if ADVANCING.with(|a| a.borrow_mut().insert(id)) {
        Ok(Claim(id))
    } else {
        Err(format!("gas transfer {id} is being finished by an earlier call; ask again when it has answered (finish_gas_transfer({id}))"))
    }
}

async fn advance(id: u64) -> Result<u128, String> {
    let _claim = claim(id)?;
    let p = begin_attempt(id)?;
    let moved = match p.direction {
        GasDirection::Deposit => pull(&p).await,
        GasDirection::Withdrawal => send(&p).await,
    };
    settle(id, moved)
}

fn signed_in(who: &Principal) -> Result<(), String> {
    if *who == Principal::anonymous() {
        return Err("sign in first: the anonymous principal cannot hold a balance".into());
    }
    Ok(())
}

/// Pull `amount` the caller approved on the gas ledger (plus one fee) into
/// their gas balance. Returns the balance available after it.
pub async fn deposit(who: Principal, amount: u128) -> Result<u128, String> {
    signed_in(&who)?;
    let ledger = ledger()?;
    let fee = fee_of(ledger).await?;
    let least = MIN_DEPOSIT_FEES.saturating_mul(fee);
    if amount < least {
        return Err(format!("deposit at least {} ({MIN_DEPOSIT_FEES} ledger fees)", amount_text(&ledger, least)));
    }
    let id = next_id();
    add_pending(PendingGasTransfer {
        id,
        direction: GasDirection::Deposit,
        who,
        amount,
        fee: 0,
        ledger,
        at_ns: crate::clock::now_ns(),
        last_error: None,
        uncertain: false,
        in_flight: false,
    });
    advance(id).await
}

/// Send `amount` of the caller's gas balance, less one ledger fee, to their
/// own account on the gas ledger. Returns the balance available after it.
pub async fn withdraw(who: Principal, amount: u128) -> Result<u128, String> {
    signed_in(&who)?;
    let ledger = ledger()?;
    // Asked before the fee, so a call no balance covers costs nothing more.
    covers(&ledger, &who, amount)?;
    let fee = fee_of(ledger).await?;
    if amount <= fee {
        return Err(format!("withdraw more than the ledger's fee of {}", amount_text(&ledger, fee)));
    }
    // After the last await before the ledger call, so the call is out
    // before a balance read begins or not sent during one.
    not_while_reading()?;
    // Debited before anything moves: the balance cannot be spent twice
    // while the transfer is out.
    debit_for_withdrawal(&ledger, &who, amount)?;
    let id = next_id();
    add_pending(PendingGasTransfer {
        id,
        direction: GasDirection::Withdrawal,
        who,
        amount,
        fee,
        ledger,
        at_ns: crate::clock::now_ns(),
        last_error: None,
        uncertain: false,
        in_flight: false,
    });
    advance(id).await
}

/// Replay pending transfer `id` whose outcome was unknown. For the one it
/// is for, or an operator. Returns that principal's balance available.
pub async fn finish(caller: Principal, operator: bool, id: u64) -> Result<u128, String> {
    match get_pending(id) {
        Some(p) if p.who == caller || operator => {
            if p.direction == GasDirection::Withdrawal {
                not_while_reading()?;
            }
            advance(id).await
        }
        Some(_) => Err("only the one this gas transfer is for, or an operator, may finish it".into()),
        None => match settled(id) {
            Some(s) if s.who == caller || operator => Ok(account_on(&s.ledger, &s.who).available),
            _ => Err(format!("no pending gas transfer {id}")),
        },
    }
}

/// Is transfer `id` one for `who`, pending or settled? What
/// `finish_gas_transfer` asks of a caller who is no operator.
pub fn is_party(id: u64, who: &Principal) -> bool {
    get_pending(id).is_some_and(|p| p.who == *who) || settled(id).is_some_and(|s| s.who == *who)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 8])
    }

    fn ck() -> Principal {
        Principal::from_text(CKSEPOLIAETH_LEDGER).unwrap()
    }

    fn signed_as(nonce: u64) -> SignedTx {
        SignedTx { chain_id: 11_155_111, from: "0xE0A".into(), nonce }
    }

    fn pend(id: u64, direction: GasDirection, who: Principal, amount: u128) {
        add_pending(PendingGasTransfer { id, direction, who, amount, fee: 7, ledger: ck(), at_ns: 0, last_error: None, uncertain: false, in_flight: false });
    }

    /// Pinned by what the ledgers answer on mainnet (icrc1_symbol).
    #[test]
    fn the_known_chains_have_their_ck_ledgers() {
        assert_eq!(default_ledger(1), Principal::from_text("ss2fx-dyaaa-aaaar-qacoq-cai").ok());
        assert_eq!(default_ledger(11_155_111), Principal::from_text("apia6-jaaaa-aaaar-qabma-cai").ok());
        assert_eq!(default_ledger(100), None, "Gnosis has no ck asset");
    }

    #[test]
    fn the_operators_ledger_comes_first_and_can_be_taken_back() {
        set_ledger(Some(p(90)));
        assert_eq!(ledger(), Ok(p(90)));
        set_ledger(None);
        // No EVM config in this test: no chain, so no ledger.
        if crate::evm::get_config().is_none() {
            assert!(ledger().unwrap_err().contains("no EVM config"));
        }
    }

    #[test]
    fn amounts_read_in_eth_on_the_ck_ledgers() {
        let eth = Principal::from_text(CKETH_LEDGER).unwrap();
        assert_eq!(amount_text(&eth, 1_000_000_000_000_000_000), "1 ckETH");
        assert_eq!(amount_text(&eth, 1_500_000_000_000_000), "0.0015 ckETH");
        assert_eq!(amount_text(&ck(), 10_000_000_000), "0.00000001 ckSepoliaETH");
        assert_eq!(amount_text(&p(1), 42), format!("42 units of the gas ledger {}", p(1)));
    }

    /// Balances are kept per ledger, and wider than u64: 18.4 ETH is
    /// u64::MAX wei.
    #[test]
    fn a_balance_is_per_ledger_and_holds_more_than_u64() {
        let who = p(11);
        let big = u64::MAX as u128 * 3;
        credit(&ck(), &who, big);
        assert_eq!(account_on(&ck(), &who).available, big);
        assert_eq!(account_on(&p(91), &who).available, 0);
        assert_eq!(account_on(&p(91), &who).ledger, p(91));
    }

    #[test]
    fn a_deposit_credits_once_and_a_late_finish_sees_it() {
        let who = p(12);
        pend(100, GasDirection::Deposit, who, 5_000);
        assert_eq!(settle(100, Moved::Block), Ok(5_000));
        assert_eq!(settle(100, Moved::Block), Ok(5_000), "a second settlement credits nothing");
        assert_eq!(account_on(&ck(), &who).deposited, 5_000);
        assert!(is_party(100, &who));
        assert!(!is_party(100, &p(13)));
        assert!(futures::executor::block_on(finish(p(13), false, 100)).is_err());
        assert_eq!(futures::executor::block_on(finish(who, false, 100)), Ok(5_000));
    }

    #[test]
    fn a_refused_withdrawal_gives_the_amount_back_and_a_sent_one_keeps_it_out() {
        let who = p(14);
        credit(&ck(), &who, 1_000);
        debit_for_withdrawal(&ck(), &who, 600).unwrap();
        pend(200, GasDirection::Withdrawal, who, 600);
        assert!(settle(200, Moved::Refused("BadFee".into())).is_err());
        let a = account_on(&ck(), &who);
        assert_eq!((a.available, a.withdrawn), (1_000, 0));
        debit_for_withdrawal(&ck(), &who, 600).unwrap();
        pend(201, GasDirection::Withdrawal, who, 600);
        assert_eq!(settle(201, Moved::Block), Ok(400));
        let a = account_on(&ck(), &who);
        assert_eq!((a.available, a.withdrawn), (400, 600));
        assert!(debit_for_withdrawal(&ck(), &who, 401).unwrap_err().contains("less than"));
    }

    #[test]
    fn an_unknown_outcome_stays_pending_and_a_lost_one_goes_to_the_operators() {
        let who = p(15);
        pend(300, GasDirection::Deposit, who, 9);
        assert!(settle(300, Moved::Unknown("timeout".into())).unwrap_err().contains("finish_gas_transfer(300)"));
        assert_eq!(get_pending(300).unwrap().last_error.as_deref(), Some("timeout"));
        assert!(settle(300, Moved::Lost("too old".into())).unwrap_err().contains("failed_gas_transfers"));
        assert!(get_pending(300).is_none());
        assert!(failed().iter().any(|f| f.id == 300 && f.who == who));
        assert_eq!(account_on(&ck(), &who).available, 0);
    }

    /// After an unknown outcome, a refused replay gives nothing back: the
    /// first attempt may have paid out. Only a block settles it.
    #[test]
    fn a_refusal_after_an_unknown_outcome_settles_nothing() {
        let who = p(17);
        credit(&ck(), &who, 1_000);
        debit_for_withdrawal(&ck(), &who, 600).unwrap();
        pend(500, GasDirection::Withdrawal, who, 600);
        settle(500, Moved::Unknown("reply lost".into())).unwrap_err();
        let e = settle(500, Moved::Refused("TemporarilyUnavailable".into())).unwrap_err();
        assert!(e.contains("does not show that nothing moved"), "{e}");
        let still = get_pending(500).unwrap();
        assert!(still.uncertain);
        assert_eq!(still.last_error.as_deref(), Some("TemporarilyUnavailable"));
        assert_eq!(account_on(&ck(), &who).available, 400, "nothing given back");
        // The replay that finds the first transfer settles it.
        assert_eq!(settle(500, Moved::Block), Ok(400));
        assert!(get_pending(500).is_none());
        // A deposit likewise: a refusal after an unknown credits nothing and drops nothing.
        pend(501, GasDirection::Deposit, who, 50);
        settle(501, Moved::Unknown("reply lost".into())).unwrap_err();
        settle(501, Moved::Refused("TemporarilyUnavailable".into())).unwrap_err();
        assert!(get_pending(501).is_some());
        assert_eq!(settle(501, Moved::Block), Ok(450));
    }

    /// Only a settled withdrawal counts toward what the refill leaves out
    /// of a balance read, by what it took and on its own ledger: a call
    /// refused at once, a deposit, or a withdrawal still owed changes
    /// nothing, so no caller can move it without spending a balance.
    #[test]
    fn only_a_settled_withdrawal_counts_by_its_amount_on_its_ledger() {
        let who = p(44);
        credit(&ck(), &who, 1_000);
        let w = withdrawn(&ck());
        // A deposit with no allowance: added, attempted, refused.
        pend(610, GasDirection::Deposit, who, 100);
        begin_attempt(610).unwrap();
        settle(610, Moved::Refused("InsufficientAllowance".into())).unwrap_err();
        assert!(get_pending(610).is_none());
        // A deposit that lands.
        pend(611, GasDirection::Deposit, who, 100);
        begin_attempt(611).unwrap();
        settle(611, Moved::Block).unwrap();
        assert_eq!(withdrawn(&ck()), w, "deposits are owed from before their call");
        // A withdrawal refused, one whose outcome is unknown, one lost.
        for (id, moved) in [
            (612, Moved::Refused("TemporarilyUnavailable".into())),
            (613, Moved::Unknown("reply lost".into())),
            (614, Moved::Lost("too old".into())),
        ] {
            debit_for_withdrawal(&ck(), &who, 100).unwrap();
            pend(id, GasDirection::Withdrawal, who, 100);
            begin_attempt(id).unwrap();
            settle(id, moved).unwrap_err();
        }
        assert_eq!(withdrawn(&ck()), w, "a withdrawal refused, unknown or lost is still owed");
        // The unknown one settles: what it took counts.
        settle(613, Moved::Block).unwrap();
        assert_eq!(withdrawn(&ck()), w + 100);
        // A replay that finds it settled already counts nothing more.
        settle(613, Moved::Block).unwrap();
        assert_eq!(withdrawn(&ck()), w + 100);
        // One on another ledger counts there, not here.
        let other = p(90);
        credit(&other, &who, 500);
        debit_for_withdrawal(&other, &who, 500).unwrap();
        add_pending(PendingGasTransfer { id: 615, direction: GasDirection::Withdrawal, who, amount: 500, fee: 7, ledger: other, at_ns: 0, last_error: None, uncertain: false, in_flight: false });
        settle(615, Moved::Block).unwrap();
        assert_eq!((withdrawn(&ck()), withdrawn(&other)), (w + 100, 500));
    }

    /// While the refill reads the balance, no withdrawal sends its ledger
    /// call, a replay included; a deposit may, since it errs only low.
    #[test]
    fn no_withdrawal_goes_out_while_the_balance_is_read() {
        let who = p(46);
        credit(&ck(), &who, 1_000);
        debit_for_withdrawal(&ck(), &who, 100).unwrap();
        pend(620, GasDirection::Withdrawal, who, 100);
        let reading = Reading::start();
        let e = futures::executor::block_on(finish(who, false, 620)).unwrap_err();
        assert!(e.contains("reading its gas ledger balance"), "{e}");
        let still = get_pending(620).unwrap();
        assert!(!still.in_flight && !still.uncertain, "no attempt was made");
        assert!(not_while_reading().is_err());
        drop(reading);
        assert_eq!(not_while_reading(), Ok(()));
    }

    /// An attempt whose reply was never handled (an upgrade dropped it)
    /// leaves the transfer uncertain for the next one, so the next one's
    /// refusal gives nothing back; a first attempt's own refusal still does.
    #[test]
    fn an_attempt_cut_off_before_its_reply_leaves_the_transfer_uncertain() {
        let who = p(18);
        credit(&ck(), &who, 1_000);
        debit_for_withdrawal(&ck(), &who, 600).unwrap();
        pend(600, GasDirection::Withdrawal, who, 600);
        let first = begin_attempt(600).unwrap();
        assert!(first.in_flight && !first.uncertain);
        // The upgrade: the reply is never handled. The next attempt sees it.
        let next = begin_attempt(600).unwrap();
        assert!(next.uncertain, "{next:?}");
        let e = settle(600, Moved::Refused("BadFee".into())).unwrap_err();
        assert!(e.contains("does not show that nothing moved"), "{e}");
        assert_eq!(account_on(&ck(), &who).available, 400, "the withdrawal is not given back");
        assert!(!get_pending(600).unwrap().in_flight, "its reply was handled");
        // A first attempt refused outright is given back, as before.
        debit_for_withdrawal(&ck(), &who, 100).unwrap();
        pend(601, GasDirection::Withdrawal, who, 100);
        begin_attempt(601).unwrap();
        settle(601, Moved::Refused("BadFee".into())).unwrap_err();
        assert!(get_pending(601).is_none());
        assert_eq!(account_on(&ck(), &who).available, 400);
    }

    /// The ledger a send holds gas in is the one for the chain it signs
    /// for, whatever chain the config says by the time it reserves; the
    /// operators' choice of ledger wins over both.
    #[test]
    fn a_send_holds_gas_in_its_own_chains_asset() {
        assert_eq!(ledger_of(None, 1).unwrap().to_text(), CKETH_LEDGER);
        assert_eq!(ledger_of(None, 11155111).unwrap().to_text(), CKSEPOLIAETH_LEDGER);
        assert!(ledger_of(None, 31337).unwrap_err().contains("no ck asset"));
        assert_eq!(ledger_of(Some(p(40)), 11155111).unwrap(), p(40));
    }

    #[test]
    fn the_cost_per_transaction_is_the_mean_of_recent_receipts() {
        let chain = 990_001;
        assert_eq!(measured_cost(chain), None);
        assert_eq!(unit_cost(chain, 7), FALLBACK_TX_GAS * 7, "before any receipt");
        observe_cost(chain, "0xA", (10, 0), 100);
        observe_cost(chain, "0xa", (10, 0), 999_999);
        assert_eq!(measured_cost(chain), Some(100), "a receipt read twice counts once");
        observe_cost(chain, "0xb", (10, 3), 300);
        assert_eq!(unit_cost(chain, 7), 200);
        observe_cost(chain, "0xc", (10, 1), 5_000);
        assert_eq!(measured_cost(chain), Some(200), "one read out of order is passed over");
        observe_cost(chain, "0xb", (12, 0), 300);
        assert_eq!(measured_cost(chain), Some(200), "nor does a reorg count one twice");
        for i in 0..COSTS_KEEP {
            observe_cost(chain, &format!("0x{i:x}f"), (20 + i as u128, 0), 1_000);
        }
        assert_eq!(measured_cost(chain), Some(1_000), "only the last {COSTS_KEEP}");
        observe_cost(chain, "0xA", (10, 0), 100);
        assert_eq!(measured_cost(chain), Some(1_000), "nor one read again after it left the window");
        assert_eq!(mean(std::iter::empty()), None);
        assert_eq!(mean([u128::MAX, u128::MAX].into_iter()), Some(u128::MAX / 2), "saturates, never wraps");
    }

    #[test]
    fn the_float_must_cover_every_hold_and_the_margin() {
        assert!(float_covers(1_000, 900, 100).is_ok());
        let e = float_covers(999, 900, 100).unwrap_err();
        assert!(e.contains("999 wei") && e.contains("1000 wei"), "{e}");
        assert!(float_covers(u128::MAX, u128::MAX, 1).is_ok(), "saturates, never wraps");
    }

    #[test]
    fn a_surplus_is_shared_by_the_markup_paid_and_never_over() {
        assert_eq!(pro_rata(100, &[1, 1, 2]), vec![25, 25, 50]);
        assert_eq!(pro_rata(10, &[1, 1, 1]), vec![3, 3, 3], "rounded down, the rest kept");
        assert_eq!(pro_rata(10, &[0, 0]), vec![0, 0]);
        let big = u128::MAX / 2;
        let s = pro_rata(big, &[big, big]);
        assert_eq!(s, vec![big / 2, big / 2], "no overflow in the product");
        let t = GasTotals { spent: 0, markup: 100, refill_costs: 30, credited: 20 };
        assert_eq!(t.surplus(), 50);
        assert_eq!(GasTotals { markup: 10, refill_costs: 30, ..t }.surplus(), 0, "a loss is no surplus");
    }

    /// The tenants' share of ic-git's ledger balance: every balance, held
    /// or not, and every transfer that may yet be theirs.
    #[test]
    fn what_is_owed_counts_every_balance_and_every_doubtful_transfer() {
        let l = p(140);
        credit(&l, &p(41), 1_000);
        credit(&l, &p(42), 500);
        let h = reserve(&p(42), l, 100, 1).unwrap();
        assert_eq!(owed_on(&l), 1_500, "a hold is still owed");
        let mk = |id, direction, uncertain| PendingGasTransfer { id, direction, who: p(43), amount: 70, fee: 1, ledger: l, at_ns: 0, last_error: None, uncertain, in_flight: false };
        add_pending(mk(9_140_001, GasDirection::Withdrawal, false));
        add_pending(mk(9_140_002, GasDirection::Deposit, false));
        add_pending(mk(9_140_003, GasDirection::Deposit, true));
        assert_eq!(owed_on(&l), 1_500 + 70 + 70, "a deposit not yet pulled is not");
        for id in [9_140_001, 9_140_002, 9_140_003] {
            take_pending(id);
        }
        release(h.id);
    }

    #[test]
    fn the_markup_rounds_up() {
        assert_eq!(markup_of(10_000, 100), 100);
        assert_eq!(markup_of(10_001, 100), 101, "a part of a unit is a unit");
        assert_eq!(markup_of(0, 100), 0);
        assert_eq!(markup_of(123, 0), 0);
        assert_eq!(markup_of(u128::MAX, 10_000), u128::MAX / 10_000 + 1, "saturates, never wraps");
    }

    /// A reservation of the whole limit at the max fee, with the markup;
    /// the receipt charges what was used at the price paid, with the
    /// markup, and the rest comes back.
    #[test]
    fn a_transaction_reserves_its_most_and_is_charged_what_it_used() {
        let l = p(130);
        let who = p(30);
        credit(&l, &who, 10_000_000);
        let h = reserve(&who, l, 100_000, 50).unwrap();
        // The rate the hold took, as the pricing table may change under a
        // test running beside this one.
        let bps = h.markup_bps;
        let most = 5_000_000 + markup_of(5_000_000, bps);
        assert_eq!(h.amount, most);
        let a = account_on(&l, &who);
        assert_eq!((a.available, a.reserved), (10_000_000 - most, most));
        attach(h.id, "0xABCD", signed_as(1));
        let c = settle_tx("0xabcd", 60_000, 40).unwrap();
        assert_eq!((c.cost, c.markup), (2_400_000, markup_of(2_400_000, bps)));
        let a = account_on(&l, &who);
        assert_eq!(a.reserved, 0);
        assert_eq!(a.available, 10_000_000 - c.cost - c.markup);
        assert_eq!((a.spent, a.markup), (c.cost, c.markup));
        assert!(settle_tx("0xabcd", 60_000, 40).is_none(), "settled once");
        assert_eq!(charges_on(&l, &who), vec![c.clone()]);
        assert_eq!(totals(&l).spent, c.cost);
    }

    #[test]
    fn a_short_balance_reserves_nothing_and_a_release_gives_it_all_back() {
        let l = p(131);
        let who = p(31);
        credit(&l, &who, 1_000);
        let e = reserve(&who, l, 21_000, 1).unwrap_err();
        assert!(e.contains("deposit with deposit_gas"), "{e}");
        assert_eq!(account_on(&l, &who).reserved, 0);
        assert!(holds().iter().all(|h| h.who != who));
        credit(&l, &who, 100_000);
        let h = reserve(&who, l, 21_000, 1).unwrap();
        release(h.id);
        let a = account_on(&l, &who);
        assert_eq!((a.available, a.reserved), (101_000, 0));
        // The operators' release, for a transaction that never landed.
        let h = reserve(&who, l, 21_000, 1).unwrap();
        attach(h.id, "0x01", signed_as(1));
        assert_eq!(release_hold(h.id).unwrap().id, h.id);
        assert!(release_hold(h.id).is_err());
        assert!(settle_tx("0x01", 1, 1).is_none(), "nothing left to settle");
        assert_eq!(account_on(&l, &who).available, 101_000);
    }

    /// A hold is looked at again past its receipt polls only: one that
    /// names its transaction and was made before the cut, on the ledger
    /// asked about; the payer's own first, then the oldest, at most as
    /// many as asked.
    #[test]
    fn the_stale_holds_are_the_payers_first_then_the_oldest() {
        let l = p(135);
        let (me, other) = (p(35), p(36));
        credit(&l, &me, 1_000_000);
        credit(&l, &other, 1_000_000);
        let held = |who: &Principal, ns: u64, tx: Option<&str>| {
            crate::clock::set_test_now(ns);
            let h = reserve(who, l, 1_000, 1).unwrap();
            if let Some(tx) = tx {
                attach(h.id, tx, signed_as(ns));
            }
            h.id
        };
        let o1 = held(&other, 1_000, Some("0x01"));
        let m1 = held(&me, 2_000, Some("0x02"));
        held(&me, 3_000, None);
        let o2 = held(&other, 3_000, Some("0x03"));
        held(&me, 9_000, Some("0x04"));
        let ids = |v: Vec<GasHold>| v.into_iter().map(|h| h.id).collect::<Vec<_>>();
        assert_eq!(ids(stale_holds(&l, &me, 5_000)), vec![m1, o1, o2], "unsigned and fresh ones left out");
        assert_eq!(ids(stale_holds(&l, &other, 5_000)), vec![o1, o2, m1]);
        assert!(stale_holds(&p(136), &me, 5_000).is_empty(), "another ledger's");
        let h = holds().into_iter().find(|h| h.id == m1).unwrap();
        assert_eq!(h.signed, Some(signed_as(2_000)), "what it was signed as, kept with its hash");
    }

    /// A failed transfer is the operators' to settle once its ledger shows
    /// whether it happened: a deposit that did is credited, a withdrawal
    /// that did not is given back, and the other two only leave the list.
    /// Then it is settled: finish reports it, and it is not settled twice.
    #[test]
    fn the_operators_settle_a_failed_transfer_by_what_the_ledger_shows() {
        let who = p(37);
        credit(&ck(), &who, 1_000);
        let lose = |id: u64, direction: GasDirection, amount: u128| {
            if direction == GasDirection::Withdrawal {
                debit_for_withdrawal(&ck(), &who, amount).unwrap();
            }
            pend(id, direction, who, amount);
            settle(id, Moved::Lost("too old".into())).unwrap_err();
        };
        lose(701, GasDirection::Deposit, 100);
        lose(702, GasDirection::Deposit, 200);
        lose(703, GasDirection::Withdrawal, 300);
        lose(704, GasDirection::Withdrawal, 400);
        assert_eq!(failed().len(), 4);
        assert_eq!(account_on(&ck(), &who).available, 300);
        let owed = owed_on(&ck());
        assert_eq!(resolve_failed(701, true).unwrap().available, 400, "a deposit that happened is credited");
        assert_eq!(resolve_failed(702, false).unwrap().available, 400, "one that did not credits nothing");
        assert_eq!(resolve_failed(703, false).unwrap().available, 700, "a withdrawal that did not is given back");
        assert_eq!(resolve_failed(704, true).unwrap().available, 700, "one that did stays out");
        assert!(failed().is_empty());
        assert_eq!(owed_on(&ck()), owed - 200 - 400, "owed no more: what never came in, and what went out");
        assert!(resolve_failed(701, true).unwrap_err().contains("no failed gas transfer 701"), "once");
        assert_eq!(futures::executor::block_on(finish(who, false, 703)), Ok(700));
    }

    /// A receipt that says more than was reserved (the price above the cap
    /// cannot happen on chain, but the arithmetic must not wrap) charges
    /// the hold and no more.
    #[test]
    fn no_settlement_charges_more_than_its_hold() {
        let l = p(132);
        let who = p(32);
        credit(&l, &who, 1_000_000);
        let h = reserve(&who, l, 21_000, 10).unwrap();
        attach(h.id, "0x02", signed_as(2));
        let c = settle_tx("0x02", 21_000, u128::MAX).unwrap();
        assert_eq!(c.cost + c.markup, h.amount);
        let a = account_on(&l, &who);
        assert_eq!((a.available, a.reserved), (1_000_000 - h.amount, 0));
    }

    #[test]
    fn ledger_replies_are_told_apart() {
        let n = |x: u64| Nat::from(x);
        assert_eq!(classify_pull(Ok(Ok(n(1)))), Moved::Block);
        assert_eq!(classify_pull(Ok(Err(TransferFromError::Duplicate { duplicate_of: n(1) }))), Moved::Block);
        assert!(matches!(classify_pull(Ok(Err(TransferFromError::InsufficientAllowance { allowance: n(0) }))), Moved::Refused(_)));
        assert!(matches!(classify_pull(Ok(Err(TransferFromError::TooOld))), Moved::Lost(_)));
        assert!(matches!(classify_pull(Err("lost".into())), Moved::Unknown(_)));
        assert_eq!(classify_send(Ok(Err(TransferError::Duplicate { duplicate_of: n(2) }))), Moved::Block);
        assert!(matches!(classify_send(Ok(Err(TransferError::BadFee { expected_fee: n(3) }))), Moved::Refused(_)));
        assert!(matches!(classify_send(Ok(Err(TransferError::TooOld))), Moved::Lost(_)));
    }

    #[test]
    fn one_attempt_at_a_time_takes_a_transfer_forward() {
        let held = claim(400).unwrap();
        assert!(claim(400).unwrap_err().contains("earlier call"));
        drop(held);
        drop(claim(400).unwrap());
    }

    #[test]
    fn a_balance_round_trips_through_storage() {
        let a = GasAccount { ledger: ck(), available: u128::MAX, deposited: 1, withdrawn: 2, created_ns: 3, reserved: 4, spent: 5, markup: 6, credited: 7 };
        save(&ck(), &p(16), &a);
        assert_eq!(account_on(&ck(), &p(16)), a);
        let bytes = candid::encode_one(&a).unwrap();
        assert_eq!(candid::decode_one::<GasAccount>(&bytes).unwrap(), a);
    }
}
