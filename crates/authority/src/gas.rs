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
}

impl Default for GasAccount {
    fn default() -> Self {
        GasAccount { ledger: anonymous(), available: 0, deposited: 0, withdrawn: 0, created_ns: 0, reserved: 0, spent: 0, markup: 0 }
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
    let cost = (gas_limit as u128).saturating_mul(max_fee);
    let amount = cost.saturating_add(markup_of(cost, bps));
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
    let hold = GasHold { id, who: *who, ledger, amount, markup_bps: bps, tx_hash: None, at_ns: crate::clock::now_ns() };
    let mut all = holds();
    all.push(hold.clone());
    save_holds(&all);
    Ok(hold)
}

/// Name the signed transaction a hold is for, before it is broadcast, so
/// its receipt can find the hold.
pub fn attach(hold_id: u64, tx_hash: &str) {
    let mut all = holds();
    if let Some(h) = all.iter_mut().find(|h| h.id == hold_id) {
        h.tx_hash = Some(tx_hash.to_ascii_lowercase());
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
    crate::kv::set_json(&format!("{TOTALS_PREFIX}{}", h.ledger.to_text()), &t);
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

fn record_settled(p: &PendingGasTransfer) {
    let mut all: Vec<Settled> = crate::kv::get_json(SETTLED_KEY).unwrap_or_default();
    all.push(Settled { id: p.id, who: p.who, ledger: p.ledger });
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
                record_settled(&p);
                Ok(match p.direction {
                    GasDirection::Deposit => credit(&p.ledger, &p.who, p.amount).available,
                    GasDirection::Withdrawal => account_on(&p.ledger, &p.who).available,
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

async fn fee_of(ledger: Principal) -> Result<u128, String> {
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
        Some(p) if p.who == caller || operator => advance(id).await,
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
        attach(h.id, "0xABCD");
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
        attach(h.id, "0x01");
        assert_eq!(release_hold(h.id).unwrap().id, h.id);
        assert!(release_hold(h.id).is_err());
        assert!(settle_tx("0x01", 1, 1).is_none(), "nothing left to settle");
        assert_eq!(account_on(&l, &who).available, 101_000);
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
        attach(h.id, "0x02");
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
        let a = GasAccount { ledger: ck(), available: u128::MAX, deposited: 1, withdrawn: 2, created_ns: 3, reserved: 4, spent: 5, markup: 6 };
        save(&ck(), &p(16), &a);
        assert_eq!(account_on(&ck(), &p(16)), a);
        let bytes = candid::encode_one(&a).unwrap();
        assert_eq!(candid::decode_one::<GasAccount>(&bytes).unwrap(), a);
    }
}
