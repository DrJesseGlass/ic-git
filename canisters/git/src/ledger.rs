//! Cycles-ledger deposits (docs/TENANCY.md).
//!
//! A tenant funds their account by approving this canister on the cycles
//! ledger (`icrc2_approve`) and calling `deposit_from_cycles_ledger`. Two
//! calls follow: `icrc2_transfer_from` moves the cycles to this canister's
//! ledger account, then `withdraw` turns that ledger balance into real
//! canister cycles. The account is credited with the amount net of the
//! ledger's withdraw fee.
//!
//! Failure between the two calls leaves cycles sitting in this canister's
//! ledger account. The tenant is credited anyway -- the cycles are ours, just
//! in the wrong place -- and the event is logged for the operator to sweep
//! (`stranded_deposits`). The candid below is hand-mirrored from the cycles
//! ledger's interface, the same way evm.rs mirrors the EVM RPC canister.

use crate::{store, tenancy};
use candid::{CandidType, Nat, Principal};
use ic_dev_kit_rs::intercanister;
use serde::{Deserialize, Serialize};

/// Mainnet cycles ledger. Overridable through META for local testing.
pub const CYCLES_LEDGER: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";
/// The ledger's transfer/withdraw fee.
pub const LEDGER_FEE: u64 = 100_000_000;
const LEDGER_KEY: &str = "tenancy:cycles_ledger";
const STRANDED_KEY: &str = "tenancy:stranded";

pub fn ledger_id() -> Principal {
    store::meta_get_json::<String>(LEDGER_KEY)
        .and_then(|t| Principal::from_text(t).ok())
        .unwrap_or_else(|| Principal::from_text(CYCLES_LEDGER).unwrap())
}

pub fn set_ledger_id(p: Principal) {
    store::meta_set_json(LEDGER_KEY, &p.to_text());
}

#[derive(CandidType, Deserialize, Clone)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Vec<u8>>,
}

#[derive(CandidType)]
struct TransferFromArgs {
    spender_subaccount: Option<Vec<u8>>,
    from: Account,
    to: Account,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
enum TransferFromError {
    BadFee { expected_fee: Nat },
    BadBurn { min_burn_amount: Nat },
    InsufficientFunds { balance: Nat },
    InsufficientAllowance { allowance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    Duplicate { duplicate_of: Nat },
    TemporarilyUnavailable,
    GenericError { error_code: Nat, message: String },
}

#[derive(CandidType)]
struct WithdrawArgs {
    amount: Nat,
    from_subaccount: Option<Vec<u8>>,
    to: Principal,
    created_at_time: Option<u64>,
}

#[derive(CandidType, Deserialize, Debug)]
enum LedgerRejectionCode {
    NoError,
    SysFatal,
    SysTransient,
    DestinationInvalid,
    CanisterReject,
    CanisterError,
    Unknown,
}

#[derive(CandidType, Deserialize, Debug)]
enum WithdrawError {
    BadFee { expected_fee: Nat },
    InsufficientFunds { balance: Nat },
    TooOld,
    CreatedInFuture { ledger_time: u64 },
    TemporarilyUnavailable,
    Duplicate { duplicate_of: Nat },
    FailedToWithdraw {
        fee_block: Option<Nat>,
        rejection_code: LedgerRejectionCode,
        rejection_reason: String,
    },
    GenericError { error_code: Nat, message: String },
    InvalidReceiver { receiver: Principal },
}

/// A deposit whose cycles reached this canister's ledger account but could
/// not be withdrawn into the canister. The tenant was credited regardless.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Stranded {
    pub who: Principal,
    pub amount: u64,
    pub error: String,
    pub at_ns: u64,
}

pub fn stranded() -> Vec<Stranded> {
    store::meta_get_json(STRANDED_KEY).unwrap_or_default()
}

fn record_stranded(s: Stranded) {
    let mut all = stranded();
    all.push(s);
    store::meta_set_json(STRANDED_KEY, &all);
}

/// Pull `amount` cycles the caller approved on the cycles ledger into their
/// account here. Returns the new balance.
pub async fn deposit_from_cycles_ledger(who: Principal, amount: u64) -> Result<u64, String> {
    if who == Principal::anonymous() {
        return Err("sign in first: the anonymous principal cannot hold a balance".into());
    }
    if amount <= 2 * LEDGER_FEE {
        return Err(format!("deposit at least {} cycles (two ledger fees)", 2 * LEDGER_FEE + 1));
    }
    let ledger = ledger_id();
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
                owner: me,
                subaccount: None,
            },
            amount: Nat::from(amount),
            fee: None,
            memo: None,
            created_at_time: None,
        },),
    )
    .await?;
    moved.map_err(|e| format!("cycles ledger transfer_from: {e:?}"))?;

    // The cycles are in our ledger account. Withdrawing costs one more fee.
    let net = amount - LEDGER_FEE;
    let pulled: Result<Result<Nat, WithdrawError>, String> = intercanister::call(
        ledger,
        "withdraw",
        (WithdrawArgs {
            amount: Nat::from(net),
            from_subaccount: None,
            to: me,
            created_at_time: None,
        },),
    )
    .await;
    match pulled {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => record_stranded(Stranded {
            who,
            amount: net,
            error: format!("withdraw: {e:?}"),
            at_ns: tenancy::now_ns(),
        }),
        Err(e) => record_stranded(Stranded {
            who,
            amount: net,
            error: format!("withdraw call: {e}"),
            at_ns: tenancy::now_ns(),
        }),
    }
    Ok(tenancy::credit(&who, net).balance)
}
