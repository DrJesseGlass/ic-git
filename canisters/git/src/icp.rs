//! ICP deposits (docs/TENANCY.md, "Money"): fund an ic-git balance from ICP,
//! the route OISY users actually hold.
//!
//! The tenant approves this canister on the ICP ledger (`icrc2_approve`, for
//! the amount plus one ledger fee) and calls `deposit_from_icp`. Then:
//!
//! 1. `icrc2_transfer_from` moves the ICP from the tenant straight to the
//!    cycles minting canister (CMC), into the account the CMC reads as "top
//!    up this canister": owner CMC, subaccount derived from this canister's
//!    principal, memo `TPUP`.
//! 2. `notify_top_up` asks the CMC to turn that block into cycles, which it
//!    deposits into this canister and reports back.
//! 3. The tenant is credited with exactly the cycles the CMC reported.
//!
//! Every deposit is recorded as pending before anything moves, under an id
//! that is also the transfer's `created_at_time`, and stays pending until
//! its cycles are credited or it is settled otherwise:
//!
//! - The ICP ledger deduplicates a transfer with the same arguments and
//!   `created_at_time` for 24 hours, answering `Duplicate { duplicate_of }`.
//!   So a transfer whose outcome is unknown (its reply lost or undecodable)
//!   is replayed safely: if it happened, the replay returns its block; if
//!   not, the replay makes it. Only a definite refusal (insufficient
//!   allowance, and the like: nothing moved) drops the entry.
//! - Once the block is known the ICP is the CMC's. A failed notify stays
//!   pending; `Processing` and transient errors are retried by
//!   `finish_icp_deposit(id)`. A refund drops the entry (the CMC returns the
//!   ICP, less a fee, to the tenant). Errors that no retry can fix --
//!   `TransactionTooOld`, `InvalidTransaction`, a replay past the ledger's
//!   dedup window -- move it to `failed_icp_deposits` for the operator.
//! - `finish_icp_deposit(id)` is for the depositor or an operator, and
//!   credits the depositor. The CMC answers a repeated notify with the same
//!   result, and the entry is taken off the list after the reply and before
//!   the credit, so concurrent finishes credit once; the one that finds it
//!   already credited reports the depositor's balance, not an error.
//!
//! The candid below is hand-mirrored from the ICP ledger and the CMC, the
//! same way ledger.rs mirrors the cycles ledger.

use crate::ledger::{Account, TransferFromArgs, TransferFromError};
use crate::{store, tenancy};
use candid::{CandidType, Nat, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};

/// Mainnet ICP ledger and cycles minting canister (the same ids an NNS
/// install gives a local replica). Overridable through META.
pub const ICP_LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
pub const CMC: &str = "rkp4c-7iaaa-aaaaa-aaaap-cai";
/// The ICP ledger's transfer fee, in e8s.
pub const ICP_FEE: u64 = 10_000;
/// Smallest deposit, in e8s (0.01 ICP): far above the fee, which the CMC
/// takes again if it has to refund.
pub const MIN_DEPOSIT: u64 = 1_000_000;
/// The memo the CMC requires on a top-up transfer: "TPUP", as the ICP
/// ledger's u64 memo in little-endian bytes (what an ICRC-1/2 transfer
/// carries in its memo field).
pub const TOP_UP_MEMO: u64 = 0x5055_5054;

const IDS_KEY: &str = "tenancy:icp_ids";
const PENDING_KEY: &str = "tenancy:icp_pending";

#[derive(Serialize, Deserialize)]
struct Ids {
    ledger: String,
    cmc: String,
}

/// (ICP ledger, CMC).
pub fn ids() -> (Principal, Principal) {
    let parse = |t: &str| Principal::from_text(t).ok();
    store::meta_get_json::<Ids>(IDS_KEY)
        .and_then(|i| Some((parse(&i.ledger)?, parse(&i.cmc)?)))
        .unwrap_or_else(|| (Principal::from_text(ICP_LEDGER).unwrap(), Principal::from_text(CMC).unwrap()))
}

pub fn set_ids(ledger: Principal, cmc: Principal) {
    store::meta_set_json(
        IDS_KEY,
        &Ids {
            ledger: ledger.to_text(),
            cmc: cmc.to_text(),
        },
    );
}

/// The CMC subaccount for topping up `canister`: the principal's length,
/// then its bytes, zero-padded to 32 (the CMC's principal_to_subaccount).
pub fn top_up_subaccount(canister: &Principal) -> Vec<u8> {
    let bytes = canister.as_slice();
    let mut sub = vec![0u8; 32];
    sub[0] = bytes.len() as u8;
    sub[1..=bytes.len()].copy_from_slice(bytes);
    sub
}

// --- CMC ---------------------------------------------------------------------

#[derive(CandidType)]
struct NotifyTopUpArg {
    block_index: u64,
    canister_id: Principal,
}

#[derive(CandidType, Deserialize, Debug)]
enum NotifyError {
    Refunded { reason: String, block_index: Option<u64> },
    Processing,
    TransactionTooOld(u64),
    InvalidTransaction(String),
    Other { error_code: u64, error_message: String },
}

// --- deposits in flight -------------------------------------------------------

/// A deposit that has not been credited or settled yet.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PendingIcpDeposit {
    /// Also the transfer's `created_at_time`, which makes a replay of it
    /// idempotent on the ICP ledger.
    pub id: u64,
    /// The ledger block of the transfer to the CMC, once known.
    pub block_index: Option<u64>,
    pub who: Principal,
    pub e8s: u64,
    pub at_ns: u64,
    /// The last failure, if a step failed.
    pub last_error: Option<String>,
}

/// A deposit no retry can finish, kept for the operator.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FailedIcpDeposit {
    pub id: u64,
    pub block_index: Option<u64>,
    pub who: Principal,
    pub e8s: u64,
    pub error: String,
    pub at_ns: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Credited {
    id: u64,
    who: Principal,
}

const FAILED_KEY: &str = "tenancy:icp_failed";
const CREDITED_KEY: &str = "tenancy:icp_credited";
const LAST_ID_KEY: &str = "tenancy:icp_last_id";
/// How many credited deposits are remembered, to answer a late finish.
const CREDITED_KEEP: usize = 200;

pub fn pending() -> Vec<PendingIcpDeposit> {
    store::meta_get_json(PENDING_KEY).unwrap_or_default()
}

pub fn failed() -> Vec<FailedIcpDeposit> {
    store::meta_get_json(FAILED_KEY).unwrap_or_default()
}

fn save_pending(all: &[PendingIcpDeposit]) {
    store::meta_set_json(PENDING_KEY, &all);
}

/// A fresh id: the current time in ns, bumped past the last one issued, so
/// two deposits never share a `created_at_time` (the ledger would take the
/// second for a replay of the first). The bump is nanoseconds, well inside
/// the ledger's allowance for a time slightly in the future.
fn next_id() -> u64 {
    let last = store::meta_get_json::<u64>(LAST_ID_KEY).unwrap_or(0);
    let id = tenancy::now_ns().max(last.saturating_add(1));
    store::meta_set_json(LAST_ID_KEY, &id);
    id
}

fn add_pending(p: PendingIcpDeposit) {
    let mut all = pending();
    all.retain(|x| x.id != p.id);
    all.push(p);
    save_pending(&all);
}

fn get_pending(id: u64) -> Option<PendingIcpDeposit> {
    pending().into_iter().find(|p| p.id == id)
}

fn update_pending(id: u64, f: impl FnOnce(&mut PendingIcpDeposit)) {
    let mut all = pending();
    if let Some(p) = all.iter_mut().find(|p| p.id == id) {
        f(p);
        save_pending(&all);
    }
}

/// Remove and return the pending deposit `id`: the one step that hands a
/// deposit to exactly one settlement.
fn take_pending(id: u64) -> Option<PendingIcpDeposit> {
    let mut all = pending();
    let i = all.iter().position(|p| p.id == id)?;
    let p = all.remove(i);
    save_pending(&all);
    Some(p)
}

fn record_credit(id: u64, who: Principal) {
    let mut all: Vec<Credited> = store::meta_get_json(CREDITED_KEY).unwrap_or_default();
    all.push(Credited { id, who });
    if all.len() > CREDITED_KEEP {
        let drop = all.len() - CREDITED_KEEP;
        all.drain(0..drop);
    }
    store::meta_set_json(CREDITED_KEY, &all);
}

fn credited_to(id: u64) -> Option<Principal> {
    store::meta_get_json::<Vec<Credited>>(CREDITED_KEY)
        .unwrap_or_default()
        .into_iter()
        .find(|c| c.id == id)
        .map(|c| c.who)
}

/// Move a pending deposit to the failed list.
fn fail(id: u64, error: &str) {
    if let Some(p) = take_pending(id) {
        let mut all = failed();
        all.push(FailedIcpDeposit {
            id,
            block_index: p.block_index,
            who: p.who,
            e8s: p.e8s,
            error: error.to_string(),
            at_ns: tenancy::now_ns(),
        });
        store::meta_set_json(FAILED_KEY, &all);
    }
}

// --- outcomes ------------------------------------------------------------------

/// What an `icrc2_transfer_from` to the CMC came to.
#[derive(Debug, PartialEq)]
enum Transfer {
    /// It happened (now or, for a replay, before) at this block.
    Block(u64),
    /// Definitely refused: nothing moved.
    Refused(String),
    /// The reply was lost or undecodable: replay it.
    Unknown(String),
    /// A replay past the ledger's dedup window: whether the first attempt
    /// happened can no longer be told from here.
    Lost(String),
}

fn classify_transfer(reply: Result<Result<Nat, TransferFromError>, String>) -> Transfer {
    let block = |n: Nat| match u64::try_from(n.0) {
        Ok(b) => Transfer::Block(b),
        Err(_) => Transfer::Unknown("ledger block index out of range".into()),
    };
    match reply {
        Ok(Ok(n)) => block(n),
        Ok(Err(TransferFromError::Duplicate { duplicate_of })) => block(duplicate_of),
        Ok(Err(TransferFromError::TooOld)) => Transfer::Lost("the transfer is too old to replay on the ICP ledger".into()),
        Ok(Err(e)) => Transfer::Refused(format!("ICP ledger transfer_from: {e:?}")),
        Err(e) => Transfer::Unknown(format!("ICP ledger transfer_from call: {e}")),
    }
}

/// What a `notify_top_up` came to.
#[derive(Debug, PartialEq)]
enum Notified {
    Cycles(u64),
    Refunded(String),
    /// Worth retrying: Processing, a transient or unknown error.
    Retry(String),
    /// No retry can succeed.
    Permanent(String),
}

fn classify_notify(reply: Result<Result<Nat, NotifyError>, String>) -> Notified {
    match reply {
        Ok(Ok(n)) => match u64::try_from(n.0) {
            Ok(c) => Notified::Cycles(c),
            Err(_) => Notified::Retry("notify_top_up: cycles amount out of range".into()),
        },
        Ok(Err(NotifyError::Refunded { reason, .. })) => Notified::Refunded(reason),
        Ok(Err(e @ (NotifyError::TransactionTooOld(_) | NotifyError::InvalidTransaction(_)))) => {
            Notified::Permanent(format!("notify_top_up: {e:?}"))
        }
        Ok(Err(e)) => Notified::Retry(format!("notify_top_up: {e:?}")),
        Err(e) => Notified::Retry(format!("notify_top_up call: {e}")),
    }
}

/// Settle deposit `id` on its notify outcome. Returns the depositor's new
/// balance when credited -- now, or already by a concurrent finish.
fn settle(id: u64, outcome: Notified) -> Result<u64, String> {
    match outcome {
        Notified::Cycles(cycles) => match take_pending(id) {
            Some(p) => {
                record_credit(id, p.who);
                Ok(tenancy::credit(&p.who, cycles).balance)
            }
            None => credited_to(id)
                .map(|who| tenancy::get_account(&who).balance)
                .ok_or_else(|| format!("no pending ICP deposit {id}")),
        },
        Notified::Refunded(reason) => {
            take_pending(id);
            Err(format!("the cycles minting canister refunded the ICP (less a fee): {reason}"))
        }
        Notified::Retry(e) => {
            update_pending(id, |p| p.last_error = Some(e.clone()));
            Err(format!(
                "{e}; the ICP is with the cycles minting canister, finish with finish_icp_deposit({id})"
            ))
        }
        Notified::Permanent(e) => {
            fail(id, &e);
            Err(format!("{e}; recorded in failed_icp_deposits for the operator"))
        }
    }
}

// --- the calls -------------------------------------------------------------------

async fn transfer(p: &PendingIcpDeposit) -> Transfer {
    let (ledger, cmc) = ids();
    let me = ic_cdk::api::canister_self();
    let reply: Result<Result<Nat, TransferFromError>, String> = intercanister::call(
        ledger,
        "icrc2_transfer_from",
        (TransferFromArgs {
            spender_subaccount: None,
            from: Account {
                owner: p.who,
                subaccount: None,
            },
            to: Account {
                owner: cmc,
                subaccount: Some(top_up_subaccount(&me)),
            },
            amount: Nat::from(p.e8s),
            fee: None,
            memo: Some(TOP_UP_MEMO.to_le_bytes().to_vec()),
            // Identical on every replay: what makes a replay idempotent.
            created_at_time: Some(p.id),
        },),
    )
    .await;
    classify_transfer(reply)
}

async fn notify(block: u64) -> Notified {
    let (_, cmc) = ids();
    let reply: Result<Result<Nat, NotifyError>, String> = intercanister::call(
        cmc,
        "notify_top_up",
        (NotifyTopUpArg {
            block_index: block,
            canister_id: ic_cdk::api::canister_self(),
        },),
    )
    .await;
    classify_notify(reply)
}

/// Take pending deposit `id` as far as it will go: the transfer if its
/// block is not known yet, then the notify and the credit.
async fn advance(id: u64) -> Result<u64, String> {
    let p = get_pending(id).ok_or_else(|| format!("no pending ICP deposit {id}"))?;
    let block = match p.block_index {
        Some(b) => b,
        None => match transfer(&p).await {
            Transfer::Block(b) => {
                update_pending(id, |p| {
                    p.block_index = Some(b);
                    p.last_error = None;
                });
                b
            }
            Transfer::Refused(e) => {
                take_pending(id);
                return Err(e);
            }
            Transfer::Unknown(e) => {
                update_pending(id, |p| p.last_error = Some(e.clone()));
                return Err(format!(
                    "{e}; the transfer's outcome is unknown, finish_icp_deposit({id}) replays it safely"
                ));
            }
            Transfer::Lost(e) => {
                fail(id, &e);
                return Err(format!("{e}; recorded in failed_icp_deposits for the operator"));
            }
        },
    };
    settle(id, notify(block).await)
}

/// Pull `e8s` ICP the caller approved on the ICP ledger, convert it to
/// cycles through the CMC, and credit them. Returns the new balance.
pub async fn deposit_from_icp(who: Principal, e8s: u64) -> Result<u64, String> {
    if who == Principal::anonymous() {
        return Err("sign in first: the anonymous principal cannot hold a balance".into());
    }
    if e8s < MIN_DEPOSIT {
        return Err(format!("deposit at least {MIN_DEPOSIT} e8s (0.01 ICP)"));
    }
    let id = next_id();
    // Recorded before anything moves, so no outcome goes unrecorded.
    add_pending(PendingIcpDeposit {
        id,
        block_index: None,
        who,
        e8s,
        at_ns: tenancy::now_ns(),
        last_error: None,
    });
    advance(id).await
}

/// Retry pending deposit `id`: replay its transfer if the outcome was
/// unknown, then notify and credit. For the depositor or an operator, so no
/// one else can spend this canister's cycles on retries. Credits the
/// depositor; returns their balance.
pub async fn finish_icp_deposit(caller: Principal, operator: bool, id: u64) -> Result<u64, String> {
    match get_pending(id) {
        Some(p) if p.who == caller || operator => advance(id).await,
        Some(_) => Err("only the depositor or an operator may finish this ICP deposit".into()),
        None => match credited_to(id) {
            Some(who) if who == caller || operator => Ok(tenancy::get_account(&who).balance),
            _ => Err(format!("no pending ICP deposit {id}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 8])
    }

    fn pend(id: u64, block: Option<u64>, who: Principal) {
        add_pending(PendingIcpDeposit { id, block_index: block, who, e8s: MIN_DEPOSIT, at_ns: 0, last_error: None });
    }

    #[test]
    fn the_top_up_subaccount_and_memo_match_the_cmc() {
        // umobs-yiaaa-aaaab-agyrq-cai: 10 bytes, length first, zero padded.
        let c = Principal::from_text("umobs-yiaaa-aaaab-agyrq-cai").unwrap();
        let sub = top_up_subaccount(&c);
        assert_eq!(sub.len(), 32);
        assert_eq!(sub[0] as usize, c.as_slice().len());
        assert_eq!(&sub[1..=c.as_slice().len()], c.as_slice());
        assert!(sub[1 + c.as_slice().len()..].iter().all(|b| *b == 0));
        // "TPUP" as the ledger's u64 memo, 1347768404.
        assert_eq!(TOP_UP_MEMO, 1_347_768_404);
        assert_eq!(&TOP_UP_MEMO.to_le_bytes()[..4], b"TPUP");
    }

    #[test]
    fn ids_are_unique_even_within_one_instant() {
        tenancy::set_test_now(1_000);
        let (a, b) = (next_id(), next_id());
        assert_eq!((a, b), (1_000, 1_001));
        tenancy::set_test_now(5_000);
        assert_eq!(next_id(), 5_000);
    }

    #[test]
    fn transfer_outcomes_are_told_apart() {
        let n = |x: u64| Nat::from(x);
        assert_eq!(classify_transfer(Ok(Ok(n(5)))), Transfer::Block(5));
        // A replay of a transfer that happened returns its block.
        assert_eq!(classify_transfer(Ok(Err(TransferFromError::Duplicate { duplicate_of: n(5) }))), Transfer::Block(5));
        assert!(matches!(classify_transfer(Ok(Err(TransferFromError::InsufficientAllowance { allowance: n(0) }))), Transfer::Refused(_)));
        assert!(matches!(classify_transfer(Ok(Err(TransferFromError::TemporarilyUnavailable))), Transfer::Refused(_)));
        assert!(matches!(classify_transfer(Ok(Err(TransferFromError::TooOld))), Transfer::Lost(_)));
        assert!(matches!(classify_transfer(Err("decode failed".into())), Transfer::Unknown(_)));
    }

    #[test]
    fn notify_outcomes_are_told_apart() {
        assert_eq!(classify_notify(Ok(Ok(Nat::from(9u64)))), Notified::Cycles(9));
        assert!(matches!(classify_notify(Ok(Err(NotifyError::Processing))), Notified::Retry(_)));
        assert!(matches!(
            classify_notify(Ok(Err(NotifyError::Other { error_code: 1, error_message: "x".into() }))),
            Notified::Retry(_)
        ));
        assert!(matches!(classify_notify(Ok(Err(NotifyError::TransactionTooOld(3)))), Notified::Permanent(_)));
        assert!(matches!(classify_notify(Ok(Err(NotifyError::InvalidTransaction("bad".into())))), Notified::Permanent(_)));
        assert!(matches!(
            classify_notify(Ok(Err(NotifyError::Refunded { reason: "r".into(), block_index: None }))),
            Notified::Refunded(_)
        ));
        assert!(matches!(classify_notify(Err("call failed".into())), Notified::Retry(_)));
    }

    #[test]
    fn a_notified_deposit_credits_once_and_a_late_finish_sees_the_credit() {
        let who = p(61);
        pend(7, Some(70), who);
        let before = tenancy::get_account(&who).balance;
        assert_eq!(settle(7, Notified::Cycles(3_000)).unwrap(), before + 3_000);
        // A concurrent finish settling the same deposit credits nothing more,
        // and reports the balance rather than an error.
        assert_eq!(settle(7, Notified::Cycles(3_000)).unwrap(), before + 3_000);
        assert_eq!(tenancy::get_account(&who).balance, before + 3_000);
        assert!(pending().is_empty());
        assert!(settle(99, Notified::Cycles(1)).is_err());
    }

    #[test]
    fn retry_stays_pending_refund_drops_permanent_moves_to_failed() {
        let who = p(62);
        pend(8, Some(80), who);
        let err = settle(8, Notified::Retry("Processing".into())).unwrap_err();
        assert!(err.contains("finish_icp_deposit(8)"), "{err}");
        assert_eq!(get_pending(8).unwrap().last_error.as_deref(), Some("Processing"));
        pend(9, Some(90), who);
        assert!(settle(9, Notified::Refunded("too small".into())).unwrap_err().contains("refunded"));
        pend(10, Some(100), who);
        assert!(settle(10, Notified::Permanent("too old".into())).unwrap_err().contains("failed_icp_deposits"));
        assert_eq!(pending().iter().map(|p| p.id).collect::<Vec<_>>(), vec![8]);
        let f = failed();
        assert_eq!((f.len(), f[0].id, f[0].block_index, f[0].error.as_str()), (1, 10, Some(100), "too old"));
        assert_eq!(tenancy::get_account(&who).balance, 0);
    }
}
