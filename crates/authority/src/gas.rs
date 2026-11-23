//! Gas balances (docs/EVM_GAS.md, section 3): what a tenant holds of the
//! EVM chain's asset on the IC side -- ckETH for Ethereum, ckSepoliaETH
//! for Sepolia -- to pay for the gas of the transactions ic-git sends for
//! them. This module holds the balance and moves the asset in and out;
//! charging a transaction against it is a later leg.
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
//! withdrawal given back after it was paid would pay a tenant twice. A
//! replay past the window moves it to `failed_gas_transfers` for the
//! operators. One attempt at a
//! time takes a transfer forward, for the reason icp.rs gives (#186).

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
    if let Some(p) = crate::kv::get_json::<String>(LEDGER_KEY).and_then(|t| Principal::from_text(t).ok()) {
        return Ok(p);
    }
    let cfg = crate::evm::get_config().ok_or("no EVM config, so no chain whose gas to hold; call evm_set_config first")?;
    default_ledger(cfg.chain_id)
        .ok_or_else(|| format!("chain {} has no ck asset to hold its gas in; set one with set_gas_ledger", cfg.chain_id))
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
}

impl Default for GasAccount {
    fn default() -> Self {
        GasAccount { ledger: anonymous(), available: 0, deposited: 0, withdrawn: 0, created_ns: 0 }
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

fn credit(ledger: &Principal, who: &Principal, amount: u128) -> GasAccount {
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

fn note_error(id: u64, e: &str, uncertain: bool) {
    let mut all = pending();
    if let Some(p) = all.iter_mut().find(|p| p.id == id) {
        p.last_error = Some(e.to_string());
        p.uncertain |= uncertain;
        save_pending(&all);
    }
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
    let p = get_pending(id).ok_or_else(|| format!("no pending gas transfer {id}"))?;
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
        add_pending(PendingGasTransfer { id, direction, who, amount, fee: 7, ledger: ck(), at_ns: 0, last_error: None, uncertain: false });
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
        let a = GasAccount { ledger: ck(), available: u128::MAX, deposited: 1, withdrawn: 2, created_ns: 3 };
        save(&ck(), &p(16), &a);
        assert_eq!(account_on(&ck(), &p(16)), a);
        let bytes = candid::encode_one(&a).unwrap();
        assert_eq!(candid::decode_one::<GasAccount>(&bytes).unwrap(), a);
    }
}
