//! The refill of ic-git's EOA from what tenants have paid (docs/EVM_GAS.md,
//! section 5; leg 3b).
//!
//! Tenants pay their gas in the chain's ck asset into ic-git's ledger
//! account; the EOA paid it on the chain in ETH. When the EOA falls under
//! its floor, the authority burns some of that ckETH at the ckETH minter
//! (`withdraw_eth`), which sends ETH to the EOA.
//!
//! - **What may be refilled from** is read from the ledger, not kept in a
//!   counter: ic-git's ckETH balance, less all it owes tenants
//!   (`gas::owed_on`, erring high) and the markup's surplus not yet
//!   credited back. What is left is gas tenants have paid for and the EOA
//!   has not yet been given back. A refill never spends a tenant's
//!   balance, held or not. The balance and what is owed are taken as of
//!   one moment: no withdrawal goes out while the balance is read, a
//!   read one settled during is made again, and the last is taken with
//!   what they took left out, which can only err low.
//! - **The minter is the record of every refill.** Each tick first reads
//!   the withdrawals of ic-git's account from the minter
//!   (`withdrawal_status`), which finds a refill whose reply was lost to
//!   an upgrade, and books what each finished one cost.
//! - **One at a time.** A refill the minter has not finished blocks the
//!   next, since the EOA's balance does not show it yet. So does a mark
//!   left by a call whose reply was lost, until the minter shows it or an
//!   hour passes.
//! - **What a refill costs** is booked against the markup
//!   (`GasTotals::refill_costs`): the ledger fee of the approval, the
//!   minter's gas, which comes out of the amount, and any part of a failed
//!   refill the minter does not give back.
//!
//! Every amount is an integer in wei.

use crate::ledger::Account;
use candid::{CandidType, Nat, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};
use std::cell::Cell;

pub const CKETH_MINTER: &str = "sv3dd-oaaaa-aaaar-qacoa-cai";
pub const CKSEPOLIAETH_MINTER: &str = "jzenf-aiaaa-aaaar-qaa7q-cai";

const IN_FLIGHT_KEY: &str = "gas:refill:in_flight";
const LAST_KEY: &str = "gas:refill:last";
/// How long a mark left by a lost reply blocks the next refill: past it,
/// a withdrawal that was made shows on the minter.
const LOST_REPLY_NS: u64 = 3_600 * 1_000_000_000;

/// The ckETH minter of a chain, if it has one.
pub fn default_minter(chain_id: u64) -> Option<Principal> {
    match chain_id {
        1 => Principal::from_text(CKETH_MINTER).ok(),
        11_155_111 => Principal::from_text(CKSEPOLIAETH_MINTER).ok(),
        _ => None,
    }
}

// --- the record ----------------------------------------------------------------

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum RefillState {
    /// The minter holds it and has not sent it yet.
    Pending,
    Sent { tx_hash: String },
    /// Landed: the EOA got `amount - fee`.
    Done { tx_hash: String, fee: u128 },
    /// Failed on the chain; the minter will give back part of it.
    PendingReimbursement { tx_hash: String },
    /// Failed on the chain; `reimbursed` of it came back as ckETH.
    Reimbursed { tx_hash: String, reimbursed: u128 },
}

impl RefillState {
    pub fn is_final(&self) -> bool {
        matches!(self, RefillState::Done { .. } | RefillState::Reimbursed { .. })
    }

    /// What a finished refill cost: the minter's gas, or what of a failed
    /// one did not come back.
    fn cost(&self, amount: u128) -> u128 {
        match self {
            RefillState::Done { fee, .. } => *fee,
            RefillState::Reimbursed { reimbursed, .. } => amount.saturating_sub(*reimbursed),
            _ => 0,
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Refill {
    /// The minter's id for it: the burn's index on the ledger.
    pub withdrawal_id: u64,
    pub ledger: Principal,
    /// ckETH burned; the EOA gets it less the minter's gas.
    pub amount: u128,
    pub recipient: String,
    pub state: RefillState,
    /// Set once its cost is booked, so it is booked once.
    pub booked: bool,
    pub at_ns: u64,
}

fn refills_key(ledger: &Principal) -> String {
    format!("gas:refills:{}", ledger.to_text())
}

pub fn refills(ledger: &Principal) -> Vec<Refill> {
    crate::kv::get_json(&refills_key(ledger)).unwrap_or_default()
}

/// Every refill is kept. The minter lists every withdrawal ever made from
/// ic-git's account, so one dropped here would be adopted again on the
/// next tick and its cost booked twice. A refill is at most hourly and in
/// practice a few a month, so the list stays small.
fn save_refills(ledger: &Principal, all: &[Refill]) {
    crate::kv::set_json(&refills_key(ledger), &all);
}

/// Fold what the minter says of a withdrawal into the record, and book
/// the cost of one newly finished. Returns whether anything changed.
pub fn absorb(ledger: &Principal, seen: Seen) -> bool {
    let mut all = refills(ledger);
    let i = match all.iter().position(|r| r.withdrawal_id == seen.withdrawal_id) {
        Some(i) => i,
        None => {
            all.push(Refill {
                withdrawal_id: seen.withdrawal_id,
                ledger: *ledger,
                amount: seen.amount,
                recipient: seen.recipient.clone(),
                state: RefillState::Pending,
                booked: false,
                at_ns: crate::clock::now_ns(),
            });
            all.len() - 1
        }
    };
    let r = &mut all[i];
    let changed = r.state != seen.state;
    r.state = seen.state;
    if r.state.is_final() && !r.booked {
        r.booked = true;
        let mut t = crate::gas::totals(ledger);
        t.refill_costs = t.refill_costs.saturating_add(r.state.cost(r.amount));
        crate::gas::save_totals(ledger, &t);
    }
    save_refills(ledger, &all);
    changed
}

/// A withdrawal as the minter reports it.
#[derive(Clone, Debug, PartialEq)]
pub struct Seen {
    pub withdrawal_id: u64,
    pub amount: u128,
    pub recipient: String,
    pub state: RefillState,
}

fn book_fee(ledger: &Principal, fee: u128) {
    let mut t = crate::gas::totals(ledger);
    t.refill_costs = t.refill_costs.saturating_add(fee);
    crate::gas::save_totals(ledger, &t);
}

/// Whether a refill on `ledger` is not finished: its cost is not booked
/// yet, so the markup's surplus is not known.
pub fn unfinished(ledger: &Principal) -> Option<u64> {
    refills(ledger).iter().find(|r| !r.state.is_final()).map(|r| r.withdrawal_id)
}

/// Why a refill may have costs on `ledger` not booked yet, if one may:
/// from a tick's first read until the minter has finished what it asked
/// for, a lost reply included. The surplus is not credited meanwhile.
pub fn busy(ledger: &Principal) -> Option<String> {
    if RUNNING.with(|r| r.get()) {
        return Some("a refill tick is running".into());
    }
    if crate::kv::get_json::<u64>(IN_FLIGHT_KEY).is_some() {
        return Some("a refill's reply was lost, and a tick has not read it from the minter yet".into());
    }
    unfinished(ledger).map(|id| format!("refill {id} is not finished"))
}

/// How many times a tick reads the balance for a read no withdrawal
/// settled during.
const POOL_READS: u32 = 3;

/// What may be refilled from, with the balance and what is owed of it as
/// of one moment. What is owed is read when the balance comes back, so a
/// tenant's withdrawal the ledger made after the balance was read, and
/// that settled before the reply, would be in the one and gone from the
/// other: a tenant's ckETH counted as paid for gas.
///
/// So no withdrawal goes out while the balance is read (`gas::Reading`),
/// and only those already out when the reads began can settle during
/// one, each once. A read one settled during is made again, up to
/// `POOL_READS` times, and the first none settled during is taken. If
/// each was touched, the last is taken with what those withdrawals took
/// left out as well (`gas::withdrawn`), which errs low when the balance
/// already showed them. Either way the read never counts a tenant's
/// balance as paid, and never fails for anything a caller does.
async fn read_pool(ledger: Principal) -> Result<u128, String> {
    let _reading = crate::gas::Reading::start();
    let mut read = 0;
    for _ in 0..POOL_READS {
        let before = crate::gas::withdrawn(&ledger);
        let balance = balance_of(ledger).await?;
        let during = crate::gas::withdrawn(&ledger).wrapping_sub(before);
        read = pool(balance, crate::gas::owed_on(&ledger), crate::gas::totals(&ledger).surplus(), during);
        if during == 0 {
            break;
        }
    }
    Ok(read)
}

/// What may be refilled from: the ledger balance, less what is owed, the
/// surplus kept to credit back, and what withdrawals that settled while
/// the balance was read took.
pub fn pool(balance: u128, owed: u128, surplus: u128, withdrawn_during: u128) -> u128 {
    balance.saturating_sub(owed).saturating_sub(surplus).saturating_sub(withdrawn_during)
}

/// The ledger fees a refill keeps aside: the approval's, and the burn's,
/// in case the ledger takes one for it. Both are booked as its cost, which
/// errs high if the burn is free.
pub fn refill_fees(fee: u128) -> u128 {
    fee.saturating_mul(2)
}

/// How much to refill: back to the target, from what the pool holds once
/// the fees are kept aside, and never under the minter's minimum.
pub fn refill_amount(eoa: u128, floor: u128, target: u128, pool: u128, fees: u128, minimum: u128) -> Result<Option<u128>, String> {
    if eoa >= floor {
        return Ok(None);
    }
    let amount = target.saturating_sub(eoa).min(pool.saturating_sub(fees));
    if amount < minimum {
        return Err(format!(
            "the EOA holds {eoa} wei, under its floor of {floor}; a refill to its target of {target} \
             from what tenants have paid ({pool} wei, less {fees} wei of fees) comes to {amount}, \
             under the minter's minimum of {minimum}; the operators fund the EOA meanwhile"
        ));
    }
    Ok(Some(amount))
}

// --- one tick ------------------------------------------------------------------

/// What one tick did, kept for `get_gas_refills`.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RefillReport {
    pub at_ns: u64,
    /// Withdrawals whose state the minter changed.
    pub updated: u32,
    /// The refill this tick asked for, if any.
    pub started: Option<Refill>,
    pub note: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RefillStatus {
    pub minter: Option<Principal>,
    pub last: Option<RefillReport>,
    pub refills: Vec<Refill>,
}

pub fn status() -> Result<RefillStatus, String> {
    let cfg = crate::evm::get_config().ok_or("no EVM config, so no chain to refill on")?;
    let ledger = crate::gas::ledger_for_chain(cfg.chain_id)?;
    Ok(RefillStatus { minter: default_minter(cfg.chain_id), last: crate::kv::get_json(LAST_KEY), refills: refills(&ledger) })
}

thread_local! {
    static RUNNING: Cell<bool> = const { Cell::new(false) };
}

struct Running;
impl Running {
    fn start() -> Result<Self, String> {
        if RUNNING.with(|r| r.replace(true)) {
            return Err("a refill tick is already running".into());
        }
        Ok(Running)
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        RUNNING.with(|r| r.set(false));
    }
}

/// Reconcile with the minter, then refill if the EOA is under its floor.
pub async fn tick() -> Result<RefillReport, String> {
    let _running = Running::start()?;
    let cfg = crate::evm::get_config().ok_or("no EVM config, so no chain to refill on")?;
    let minter = default_minter(cfg.chain_id).ok_or_else(|| format!("chain {} has no ckETH minter to refill through", cfg.chain_id))?;
    let ledger = crate::gas::ledger_for_chain(cfg.chain_id)?;
    // The minter burns its own ledger's asset: with another gas ledger set
    // by the operators, an approval there would only pay a fee each hour.
    if Some(ledger) != crate::gas::default_ledger(cfg.chain_id) {
        return Err(format!(
            "the gas ledger {ledger} is not the one the chain's minter burns; refilling is the operators' while it is set"
        ));
    }
    let mut report = RefillReport { at_ns: crate::clock::now_ns(), updated: 0, started: None, note: String::new() };
    let out = run(&cfg, minter, ledger, &mut report).await;
    report.note = match out {
        Ok(note) => note,
        Err(e) => e,
    };
    crate::kv::set_json(LAST_KEY, &report);
    Ok(report)
}

async fn run(cfg: &crate::evm::EvmConfig, minter: Principal, ledger: Principal, report: &mut RefillReport) -> Result<String, String> {
    for seen in withdrawals(minter).await? {
        if absorb(&ledger, seen) {
            report.updated += 1;
        }
    }
    if let Some(at) = crate::kv::get_json::<u64>(IN_FLIGHT_KEY) {
        if crate::clock::now_ns().saturating_sub(at) < LOST_REPLY_NS {
            return Err("a refill's reply was lost; the next waits until the minter shows it, or an hour".into());
        }
        crate::kv::remove(IN_FLIGHT_KEY);
    }
    if let Some(id) = unfinished(&ledger) {
        return Ok(format!("refill {id} is not finished; the next waits for it"));
    }
    // The ledger and the minter first: calls between canisters, no
    // outcalls. Only a pool that could make a refill pays for the chain read.
    let (pool, fee, minimum) = futures::future::join3(read_pool(ledger), crate::gas::fee_of(ledger), minimum_of(minter)).await;
    let (pool, fee, minimum) = (pool?, fee?, minimum?);
    let fees = refill_fees(fee);
    if pool.saturating_sub(fees) < minimum {
        return Ok(format!("what tenants have paid toward refills ({pool} wei) is under the minter's minimum of {minimum}"));
    }
    let read = crate::evm::read_float(cfg).await?;
    let view = crate::gas::float_view(cfg.chain_id, read.max_fee)?;
    let Some(amount) = refill_amount(read.wei, view.floor, view.target, pool, fees, minimum)? else {
        return Ok(format!("the EOA holds {} wei, at or over its floor of {}", read.wei, view.floor));
    };

    // Marked before the first call: an upgrade that drops a reply leaves
    // it, and the next tick waits for the minter to show the withdrawal.
    crate::kv::set_json(IN_FLIGHT_KEY, &crate::clock::now_ns());
    match approve(ledger, minter, amount.saturating_add(fee), fee).await {
        Approved::Yes => book_fee(&ledger, fees),
        Approved::Unknown(e) => {
            book_fee(&ledger, fee);
            crate::kv::remove(IN_FLIGHT_KEY);
            return Err(format!("the approval's outcome is unknown ({e}); no withdrawal was asked for"));
        }
        Approved::No(e) => {
            crate::kv::remove(IN_FLIGHT_KEY);
            return Err(format!("the ledger refused the approval: {e}"));
        }
    }
    let reply: Result<Result<RetrieveEthRequest, WithdrawalError>, String> = intercanister::call(
        minter,
        "withdraw_eth",
        (WithdrawalArg { recipient: read.address.clone(), amount: Nat::from(amount), from_subaccount: None },),
    )
    .await;
    match reply {
        Ok(Ok(req)) => {
            // The mark goes only once the refill is on record, which then
            // blocks the next refill and the surplus credit in its place.
            let withdrawal_id = u64::try_from(req.block_index.0)
                .map_err(|_| "a withdrawal id past u64; the next tick reads the refill from the minter".to_string())?;
            absorb(&ledger, Seen { withdrawal_id, amount, recipient: read.address.clone(), state: RefillState::Pending });
            crate::kv::remove(IN_FLIGHT_KEY);
            report.started = refills(&ledger).into_iter().find(|r| r.withdrawal_id == withdrawal_id);
            Ok(format!("asked the minter for {amount} wei to {}", read.address))
        }
        Ok(Err(e)) => {
            // Refused before any burn: nothing moved but the approval's fee.
            crate::kv::remove(IN_FLIGHT_KEY);
            Err(format!("the minter refused the refill: {e:?}"))
        }
        // Unknown: the mark stays, and the minter's list settles it.
        Err(e) => Err(format!("the withdrawal's outcome is unknown ({e}); the next tick reads it from the minter")),
    }
}

/// Every hour; init and post_upgrade arm it, timers not surviving upgrades.
#[cfg(not(any(test, feature = "testing")))]
pub fn arm_timer() {
    ic_cdk_timers::set_timer_interval(std::time::Duration::from_secs(3_600), || async {
        let _ = tick().await;
    });
}

#[cfg(any(test, feature = "testing"))]
pub fn arm_timer() {}

// --- the calls -------------------------------------------------------------------

async fn balance_of(ledger: Principal) -> Result<u128, String> {
    let n: Nat = intercanister::call(ledger, "icrc1_balance_of", (Account { owner: ic_cdk::api::canister_self(), subaccount: None },)).await?;
    u128::try_from(n.0).map_err(|_| "a ledger balance past u128".to_string())
}

#[derive(CandidType, Deserialize)]
struct MinterInfo {
    minimum_withdrawal_amount: Option<Nat>,
}

async fn minimum_of(minter: Principal) -> Result<u128, String> {
    let info: MinterInfo = intercanister::call(minter, "get_minter_info", ()).await?;
    let n = info.minimum_withdrawal_amount.ok_or("the minter names no minimum withdrawal")?;
    u128::try_from(n.0).map_err(|_| "a minimum past u128".to_string())
}

#[derive(CandidType)]
struct ApproveArgs {
    from_subaccount: Option<Vec<u8>>,
    spender: Account,
    amount: Nat,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
enum ApproveError {
    BadFee { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    AllowanceChanged { current_allowance: Nat },
    Expired { ledger_time: u64 },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

enum Approved {
    Yes,
    No(String),
    Unknown(String),
}

/// Allow the minter `amount`: the burn, and its fee if the ledger takes
/// one. An allowance is not a transfer: one left over moves nothing, and
/// the next approval replaces it.
async fn approve(ledger: Principal, minter: Principal, amount: u128, fee: u128) -> Approved {
    let reply: Result<Result<Nat, ApproveError>, String> = intercanister::call(
        ledger,
        "icrc2_approve",
        (ApproveArgs {
            from_subaccount: None,
            spender: Account { owner: minter, subaccount: None },
            amount: Nat::from(amount),
            expected_allowance: None,
            expires_at: None,
            fee: Some(Nat::from(fee)),
            memo: None,
            created_at_time: None,
        },),
    )
    .await;
    match reply {
        Ok(Ok(_)) | Ok(Err(ApproveError::Duplicate { .. })) => Approved::Yes,
        Ok(Err(e)) => Approved::No(format!("{e:?}")),
        Err(e) => Approved::Unknown(e),
    }
}

#[derive(CandidType)]
struct WithdrawalArg {
    recipient: String,
    amount: Nat,
    from_subaccount: Option<Vec<u8>>,
}

#[derive(CandidType, Deserialize, Debug)]
struct RetrieveEthRequest {
    block_index: Nat,
}

#[derive(CandidType, Deserialize, Debug)]
enum WithdrawalError {
    AmountTooLow { min_withdrawal_amount: Nat },
    InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    RecipientAddressBlocked { address: String },
    TemporarilyUnavailable(String),
}

/// The minter's names, which the candid encoding carries.
#[derive(CandidType)]
#[allow(clippy::enum_variant_names)]
enum WithdrawalSearchParameter {
    #[allow(dead_code)]
    ByRecipient(String),
    BySenderAccount(Account),
    #[allow(dead_code)]
    ByWithdrawalId(u64),
}

#[derive(CandidType, Deserialize, Debug)]
struct EthTransaction {
    transaction_hash: String,
}

#[derive(CandidType, Deserialize, Debug)]
enum TxFinalizedStatus {
    Success { transaction_hash: String, effective_transaction_fee: Option<Nat> },
    Reimbursed { transaction_hash: String, reimbursed_amount: Nat, reimbursed_in_block: Nat },
    PendingReimbursement(EthTransaction),
}

#[derive(CandidType, Deserialize, Debug)]
enum WithdrawalStatus {
    Pending,
    TxCreated,
    TxSent(EthTransaction),
    TxFinalized(TxFinalizedStatus),
}

#[derive(CandidType, Deserialize, Debug)]
struct WithdrawalDetail {
    withdrawal_id: u64,
    withdrawal_amount: Nat,
    recipient_address: String,
    status: WithdrawalStatus,
}

fn wei(n: Nat) -> u128 {
    u128::try_from(n.0).unwrap_or(u128::MAX)
}

fn seen_of(d: WithdrawalDetail) -> Seen {
    let state = match d.status {
        WithdrawalStatus::Pending | WithdrawalStatus::TxCreated => RefillState::Pending,
        WithdrawalStatus::TxSent(t) => RefillState::Sent { tx_hash: t.transaction_hash },
        WithdrawalStatus::TxFinalized(TxFinalizedStatus::Success { transaction_hash, effective_transaction_fee }) => {
            // A finished withdrawal without its fee is booked at none; the
            // minter has named it on every one seen.
            RefillState::Done { tx_hash: transaction_hash, fee: effective_transaction_fee.map_or(0, wei) }
        }
        WithdrawalStatus::TxFinalized(TxFinalizedStatus::Reimbursed { transaction_hash, reimbursed_amount, .. }) => {
            RefillState::Reimbursed { tx_hash: transaction_hash, reimbursed: wei(reimbursed_amount) }
        }
        WithdrawalStatus::TxFinalized(TxFinalizedStatus::PendingReimbursement(t)) => {
            RefillState::PendingReimbursement { tx_hash: t.transaction_hash }
        }
    };
    Seen { withdrawal_id: d.withdrawal_id, amount: wei(d.withdrawal_amount), recipient: d.recipient_address, state }
}

/// Every withdrawal from ic-git's own account, as the minter knows them.
async fn withdrawals(minter: Principal) -> Result<Vec<Seen>, String> {
    let list: Vec<WithdrawalDetail> = intercanister::call(
        minter,
        "withdrawal_status",
        (WithdrawalSearchParameter::BySenderAccount(Account { owner: ic_cdk::api::canister_self(), subaccount: None }),),
    )
    .await?;
    Ok(list.into_iter().map(seen_of).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(n: u8) -> Principal {
        Principal::from_slice(&[n; 29])
    }

    #[test]
    fn the_known_chains_have_their_minters() {
        assert_eq!(default_minter(1).unwrap().to_text(), CKETH_MINTER);
        assert_eq!(default_minter(11_155_111).unwrap().to_text(), CKSEPOLIAETH_MINTER);
        assert_eq!(default_minter(100), None);
    }

    /// The pool is what tenants have paid toward the EOA, never what they
    /// hold or the surplus kept to credit back.
    #[test]
    fn the_pool_leaves_what_is_owed_and_the_surplus() {
        assert_eq!(pool(1_000, 600, 100, 0), 300);
        assert_eq!(pool(500, 600, 100, 0), 0, "owing more than is held refills nothing");
    }

    /// A tenant's withdrawal that the ledger made after it answered the
    /// balance, and that settled before the reply, is in the balance and
    /// gone from what is owed. Left out as well, it is not counted as paid
    /// for gas; one the balance did not show any more only errs low.
    #[test]
    fn a_withdrawal_settled_during_the_read_is_not_counted_as_paid() {
        // 300 paid for gas; a tenant holds 600 and withdraws 200 of it.
        let (paid, held, out) = (300u128, 600u128, 200u128);
        // Moved after the balance was read: in it, and gone from what is owed.
        assert_eq!(pool(paid + held, held - out, 0, out), paid);
        // Moved before: gone from both, so leaving it out errs low.
        assert_eq!(pool(paid + held - out, held - out, 0, out), paid - out);
        assert_eq!(pool(100, 0, 0, 500), 0);
    }

    #[test]
    fn a_refill_brings_the_eoa_back_to_its_target_from_the_pool() {
        // Over the floor: nothing.
        assert_eq!(refill_amount(600, 500, 1_000, 10_000, 1, 10), Ok(None));
        // Under it: back to the target.
        assert_eq!(refill_amount(400, 500, 1_000, 10_000, 1, 10), Ok(Some(600)));
        // The pool, less the fees, caps it.
        assert_eq!(refill_amount(400, 500, 1_000, 302, refill_fees(1), 10), Ok(Some(300)));
        // Under the minter's minimum: a refusal that says why.
        let e = refill_amount(400, 500, 1_000, 5, 2, 10).unwrap_err();
        assert!(e.contains("comes to 3") && e.contains("minter's minimum of 10"), "{e}");
    }

    /// The minter's word on each withdrawal is folded in, the cost of a
    /// finished one booked once, and one first seen there adopted.
    #[test]
    fn the_minter_is_the_record_and_each_cost_is_booked_once() {
        let ledger = l(150);
        let seen = |state| Seen { withdrawal_id: 7, amount: 1_000, recipient: "0xE".into(), state };
        assert!(!absorb(&ledger, seen(RefillState::Pending)), "adopted as pending");
        assert_eq!(refills(&ledger).len(), 1);
        assert!(absorb(&ledger, seen(RefillState::Sent { tx_hash: "0x1".into() })));
        assert_eq!(crate::gas::totals(&ledger).refill_costs, 0);
        absorb(&ledger, seen(RefillState::Done { tx_hash: "0x1".into(), fee: 30 }));
        absorb(&ledger, seen(RefillState::Done { tx_hash: "0x1".into(), fee: 30 }));
        assert_eq!(crate::gas::totals(&ledger).refill_costs, 30, "booked once");

        let failed = |state| Seen { withdrawal_id: 8, amount: 1_000, recipient: "0xE".into(), state };
        absorb(&ledger, failed(RefillState::PendingReimbursement { tx_hash: "0x2".into() }));
        assert_eq!(crate::gas::totals(&ledger).refill_costs, 30);
        absorb(&ledger, failed(RefillState::Reimbursed { tx_hash: "0x2".into(), reimbursed: 990 }));
        assert_eq!(crate::gas::totals(&ledger).refill_costs, 40, "what did not come back");
        assert!(refills(&ledger).iter().all(|r| r.booked));
        assert_eq!(unfinished(&ledger), None);
        absorb(&ledger, Seen { withdrawal_id: 9, amount: 1, recipient: "0xE".into(), state: RefillState::Pending });
        assert_eq!(unfinished(&ledger), Some(9));

        // The minter lists every withdrawal on every tick: reading the
        // finished ones again books nothing more.
        let before = crate::gas::totals(&ledger).refill_costs;
        for _ in 0..3 {
            absorb(&ledger, seen(RefillState::Done { tx_hash: "0x1".into(), fee: 30 }));
            absorb(&ledger, failed(RefillState::Reimbursed { tx_hash: "0x2".into(), reimbursed: 990 }));
        }
        assert_eq!(crate::gas::totals(&ledger).refill_costs, before);
    }

    /// The surplus waits while a refill may have costs not booked yet:
    /// during a tick, while a lost reply's mark stands, and until the
    /// minter has finished the refill.
    #[test]
    fn a_refill_under_way_holds_back_the_surplus_credit() {
        let ledger = l(151);
        assert_eq!(busy(&ledger), None);
        {
            let _running = Running::start().unwrap();
            assert!(busy(&ledger).unwrap().contains("tick is running"));
        }
        assert_eq!(busy(&ledger), None);
        crate::kv::set_json(IN_FLIGHT_KEY, &1u64);
        assert!(busy(&ledger).unwrap().contains("reply was lost"));
        crate::kv::remove(IN_FLIGHT_KEY);
        let seen = |state| Seen { withdrawal_id: 4, amount: 1_000, recipient: "0xE".into(), state };
        absorb(&ledger, seen(RefillState::Pending));
        assert!(busy(&ledger).unwrap().contains("refill 4 is not finished"));
        absorb(&ledger, seen(RefillState::Done { tx_hash: "0x4".into(), fee: 30 }));
        assert_eq!(busy(&ledger), None);
    }

    #[test]
    fn the_minters_statuses_are_read() {
        let d = |status| WithdrawalDetail { withdrawal_id: 3, withdrawal_amount: Nat::from(500u64), recipient_address: "0xE".into(), status };
        assert_eq!(seen_of(d(WithdrawalStatus::TxCreated)).state, RefillState::Pending);
        assert_eq!(
            seen_of(d(WithdrawalStatus::TxFinalized(TxFinalizedStatus::Success { transaction_hash: "0xa".into(), effective_transaction_fee: Some(Nat::from(21u64)) }))).state,
            RefillState::Done { tx_hash: "0xa".into(), fee: 21 }
        );
        let r = seen_of(d(WithdrawalStatus::TxFinalized(TxFinalizedStatus::Reimbursed {
            transaction_hash: "0xb".into(),
            reimbursed_amount: Nat::from(480u64),
            reimbursed_in_block: Nat::from(9u64),
        })));
        assert_eq!(r.state, RefillState::Reimbursed { tx_hash: "0xb".into(), reimbursed: 480 });
        assert_eq!((r.withdrawal_id, r.amount), (3, 500));
    }
}
