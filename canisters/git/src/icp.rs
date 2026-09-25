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
//! Between 1 and 3 the ICP is already the CMC's, so the deposit is recorded
//! as pending before the notify and removed only once the reply is in hand,
//! just before crediting. `finish_icp_deposit(block)` retries a pending one
//! (anyone may call it; it credits the original depositor). The CMC answers
//! a repeated notify with the same result, and the removal happens after the
//! await, so two concurrent retries credit once. If the CMC refunds instead
//! (it returns the ICP, less a fee, to the tenant), nothing is credited.
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

// --- pending deposits ----------------------------------------------------------

/// A deposit whose ICP reached the CMC and whose cycles have not been
/// credited yet.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PendingIcpDeposit {
    pub block_index: u64,
    pub who: Principal,
    pub e8s: u64,
    pub at_ns: u64,
    /// The last notify's failure, if one was tried.
    pub last_error: Option<String>,
}

pub fn pending() -> Vec<PendingIcpDeposit> {
    store::meta_get_json(PENDING_KEY).unwrap_or_default()
}

fn save_pending(all: &[PendingIcpDeposit]) {
    store::meta_set_json(PENDING_KEY, &all);
}

fn add_pending(p: PendingIcpDeposit) {
    let mut all = pending();
    all.retain(|x| x.block_index != p.block_index);
    all.push(p);
    save_pending(&all);
}

/// Remove and return the pending deposit for `block`: the one step that
/// hands a deposit to exactly one credit.
fn take_pending(block: u64) -> Option<PendingIcpDeposit> {
    let mut all = pending();
    let i = all.iter().position(|p| p.block_index == block)?;
    let p = all.remove(i);
    save_pending(&all);
    Some(p)
}

fn note_error(block: u64, error: &str) {
    let mut all = pending();
    if let Some(p) = all.iter_mut().find(|p| p.block_index == block) {
        p.last_error = Some(error.to_string());
        save_pending(&all);
    }
}

/// Settle a notify outcome for `block`. `Ok(cycles)` credits the depositor
/// if the deposit is still pending (a concurrent settle may have taken it);
/// a refund drops it without credit; anything else leaves it pending with
/// the error, for `finish_icp_deposit`. Returns the depositor's new balance.
fn settle(block: u64, outcome: Result<u64, String>, refunded: bool) -> Result<u64, String> {
    match outcome {
        Ok(cycles) => {
            let p = take_pending(block).ok_or_else(|| format!("ICP deposit {block} was already credited"))?;
            Ok(tenancy::credit(&p.who, cycles).balance)
        }
        Err(e) if refunded => {
            take_pending(block);
            Err(format!("the cycles minting canister refunded the ICP (less a fee): {e}"))
        }
        Err(e) => {
            note_error(block, &e);
            Err(format!("{e}; the ICP is with the cycles minting canister, finish with finish_icp_deposit({block})"))
        }
    }
}

async fn notify(block: u64) -> Result<u64, String> {
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
    match reply {
        Ok(Ok(cycles)) => {
            // Out of range stays pending (with the error) rather than
            // being taken and dropped uncredited.
            let cycles = u64::try_from(cycles.0).map_err(|_| "notify_top_up: cycles amount out of range".to_string());
            settle(block, cycles, false)
        }
        Ok(Err(NotifyError::Refunded { reason, .. })) => settle(block, Err(reason), true),
        Ok(Err(e)) => settle(block, Err(format!("notify_top_up: {e:?}")), false),
        Err(e) => settle(block, Err(format!("notify_top_up call: {e}")), false),
    }
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
    let (ledger, cmc) = ids();
    let me = ic_cdk::api::canister_self();
    let moved: Result<Nat, TransferFromError> = intercanister::call(
        ledger,
        "icrc2_transfer_from",
        (TransferFromArgs {
            spender_subaccount: None,
            from: Account {
                owner: who,
                subaccount: None,
            },
            to: Account {
                owner: cmc,
                subaccount: Some(top_up_subaccount(&me)),
            },
            amount: Nat::from(e8s),
            fee: None,
            memo: Some(TOP_UP_MEMO.to_le_bytes().to_vec()),
            created_at_time: None,
        },),
    )
    .await?;
    let block = moved.map_err(|e| format!("ICP ledger transfer_from: {e:?}"))?;
    let block = u64::try_from(block.0).map_err(|_| "ledger block index out of range".to_string())?;
    // From here the ICP is the CMC's: record it before asking for cycles.
    add_pending(PendingIcpDeposit {
        block_index: block,
        who,
        e8s,
        at_ns: tenancy::now_ns(),
        last_error: None,
    });
    notify(block).await
}

/// Retry the notify for a pending deposit. Credits its depositor, whoever
/// calls. Returns the depositor's new balance.
pub async fn finish_icp_deposit(block: u64) -> Result<u64, String> {
    if !pending().iter().any(|p| p.block_index == block) {
        return Err(format!("no pending ICP deposit at block {block}"));
    }
    notify(block).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 8])
    }

    fn pend(block: u64, who: Principal) {
        add_pending(PendingIcpDeposit { block_index: block, who, e8s: MIN_DEPOSIT, at_ns: 0, last_error: None });
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
    fn a_notified_deposit_credits_its_depositor_once() {
        let who = p(61);
        pend(7, who);
        let before = tenancy::get_account(&who).balance;
        assert_eq!(settle(7, Ok(3_000_000_000_000), false).unwrap(), before + 3_000_000_000_000);
        // A second settle for the same block (a concurrent retry) credits nothing.
        assert!(settle(7, Ok(3_000_000_000_000), false).unwrap_err().contains("already credited"));
        assert_eq!(tenancy::get_account(&who).balance, before + 3_000_000_000_000);
        assert!(pending().is_empty());
    }

    #[test]
    fn a_failed_notify_stays_pending_and_a_refund_drops_it() {
        let who = p(62);
        pend(8, who);
        let err = settle(8, Err("Processing".into()), false).unwrap_err();
        assert!(err.contains("finish_icp_deposit(8)"), "{err}");
        assert_eq!(pending()[0].last_error.as_deref(), Some("Processing"));
        pend(9, who);
        assert!(settle(9, Err("too small".into()), true).unwrap_err().contains("refunded"));
        assert_eq!(pending().iter().map(|p| p.block_index).collect::<Vec<_>>(), vec![8]);
        assert_eq!(tenancy::get_account(&who).balance, 0);
    }
}
