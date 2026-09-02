//! Per-user app canisters (docs/TENANCY.md, phase 3).
//!
//! An app deployed to the IC should run in a canister its owner controls, so
//! the cycles it burns are the owner's in the ordinary way -- topped up from a
//! wallet, visible in the NNS dapp -- and never metered by ic-git. This module
//! creates that canister from the owner's prepaid balance, with the owner and
//! this canister as controllers (this canister must stay one to install
//! code from the deploy queue), and records it on the repo so
//! `set_wasm_deploy(repo, "app", path)` can target it by name.
//!
//! The balance is debited before the management-canister call and refunded
//! if the call fails, so a tenant is never charged for a canister that does
//! not exist.

use crate::tenancy;
use candid::{CandidType, Principal};
use ic_dev_kit_rs::intercanister;
use serde::Deserialize;

/// Below this the creation fee would eat most of the deposit.
pub const MIN_CREATE_CYCLES: u64 = 1_000_000_000_000;

#[derive(CandidType)]
struct CanisterSettings {
    controllers: Option<Vec<Principal>>,
}

#[derive(CandidType)]
struct CreateCanisterArgs {
    settings: Option<CanisterSettings>,
    sender_canister_version: Option<u64>,
}

#[derive(CandidType, Deserialize)]
struct CreateCanisterReply {
    canister_id: Principal,
}

#[derive(CandidType)]
struct CanisterIdArg {
    canister_id: Principal,
}

/// Create the repo's app canister with `cycles` from the owner's balance.
/// Controllers: the owner and this canister.
pub async fn create_app_canister(
    repo: &str,
    who: &Principal,
    operator: bool,
    cycles: u64,
) -> Result<Principal, String> {
    let m = tenancy::can_admin(repo, who, operator)?;
    if let Some(existing) = m.app_canister {
        return Err(format!("repo {repo} already has an app canister: {existing}"));
    }
    if cycles < MIN_CREATE_CYCLES {
        return Err(format!("attach at least {MIN_CREATE_CYCLES} cycles"));
    }
    let owner = m.owner.unwrap_or(*who);
    let payer = pay(repo, &owner, cycles, "create app canister")?;
    let me = ic_cdk::api::canister_self();
    let reply: Result<CreateCanisterReply, String> = intercanister::call_with_payment(
        Principal::management_canister(),
        "create_canister",
        (CreateCanisterArgs {
            settings: Some(CanisterSettings {
                controllers: Some(vec![owner, me]),
            }),
            sender_canister_version: None,
        },),
        cycles as u128,
    )
    .await;
    match reply {
        Ok(r) => {
            tenancy::set_app_canister(repo, r.canister_id)?;
            Ok(r.canister_id)
        }
        Err(e) => {
            refund(payer, cycles);
            Err(format!("create_canister: {e}"))
        }
    }
}

/// Move `cycles` from the owner's balance into the repo's app canister.
pub async fn top_up_app_canister(
    repo: &str,
    who: &Principal,
    operator: bool,
    cycles: u64,
) -> Result<(), String> {
    let m = tenancy::can_admin(repo, who, operator)?;
    let target = m
        .app_canister
        .ok_or_else(|| format!("repo {repo} has no app canister; call create_app_canister"))?;
    let owner = m.owner.unwrap_or(*who);
    let payer = pay(repo, &owner, cycles, "top up app canister")?;
    let sent: Result<(), String> = intercanister::call_with_payment(
        Principal::management_canister(),
        "deposit_cycles",
        (CanisterIdArg {
            canister_id: target,
        },),
        cycles as u128,
    )
    .await;
    if let Err(e) = sent {
        refund(payer, cycles);
        return Err(format!("deposit_cycles: {e}"));
    }
    Ok(())
}

/// Debit the owner unless the repo is exempt (operator repos spend this
/// canister's own cycles, by the operator's choice). Returns who to refund.
fn pay(repo: &str, owner: &Principal, cycles: u64, what: &str) -> Result<Option<Principal>, String> {
    if tenancy::is_exempt(repo) {
        return Ok(None);
    }
    tenancy::debit(owner, cycles, what)?;
    Ok(Some(*owner))
}

fn refund(payer: Option<Principal>, cycles: u64) {
    if let Some(p) = payer {
        tenancy::refund(&p, cycles);
    }
}
