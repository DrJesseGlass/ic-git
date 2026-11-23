//! The authority's methods as ingress messages (ic_git_common::ingress):
//! who may send each. A method without a line here is refused, and the
//! canister's tests hold the list to its `.did`.

use candid::Principal;
use ic_git_common::ingress::Rule::{self, *};

/// The git canister is a canister: its messages never come signed by a key.
const GIT: Rule = NotIngress("only the git canister may call this");

/// Cycles ride on a canister's call. A signed message carries none, so
/// one of these would credit nothing.
const WITH_CYCLES: Rule = NotIngress("a signed message carries no cycles to deposit; call it from a cycles wallet or another canister");

pub const RULES: &[(&str, Rule)] = &[
    // The git canister's messages.
    ("charge_push", GIT),
    ("stage_job", GIT),
    ("submit_job", GIT),
    ("notify", GIT),
    ("publish_git_record", GIT),
    // Deposits of attached cycles.
    ("deposit", WITH_CYCLES),
    ("deposit_for", WITH_CYCLES),
    // Operators. A controller is one, so the record a controller alone
    // publishes is here.
    ("registry_publish_canister", Operator),
    ("set_git_canister", Operator),
    ("top_up_git_canister", Operator),
    ("authorize", Operator),
    ("deauthorize", Operator),
    ("set_pricing", Operator),
    ("charge_rent_now", Operator),
    ("set_cycles_ledger", Operator),
    ("set_icp_ledgers", Operator),
    ("set_gas_ledger", Operator),
    ("gas_release_hold", Operator),
    ("compile_wat", Operator),
    ("compile_wat_info", Operator),
    ("compile_lang", Operator),
    ("compile_lang_info", Operator),
    ("compile_lang_metered", Operator),
    ("measure_compile", Operator),
    ("compile_job_start", Operator),
    ("compile_job_step", Operator),
    ("compile_job_take", Operator),
    ("compile_module", Operator),
    ("link_module_objects", Operator),
    ("compile_and_link_info", Operator),
    ("set_compiler_workers", Operator),
    ("compile_distributed", Operator),
    ("compile_distributed_info", Operator),
    ("evm_set_config", Operator),
    ("evm_set_fee_fallback", Operator),
    ("evm_address", Operator),
    ("evm_send", Operator),
    ("evm_deploy", Operator),
    ("evm_receipt", Operator),
    ("evm_reset_nonce", Operator),
    ("evm_set_registry", Operator),
    ("names_set_config", Operator),
    ("names_clear_config", Operator),
    ("feed_set_governor", Operator),
    ("feed_poll_governor", Operator),
    ("sol_set_config", Operator),
    ("sol_address", Operator),
    ("sol_balance", Operator),
    ("sol_send", Operator),
    ("sol_signature_status", Operator),
    ("run_wasm", Operator),
    ("run_wat", Operator),
    // Tenants, each taken only from a caller it could be for (`standing`).
    // On a repo, named first: its owner, a member, or the one it is
    // offered to. The rest by the method: an account that covers the new
    // repo, a deposit of the caller's to finish, and a first deposit,
    // which is anyone's and one number.
    ("create_repo", SignedIn),
    ("set_require_signed_push", Member),
    ("deposit_from_cycles_ledger", SignedIn),
    ("deposit_from_icp", SignedIn),
    ("finish_icp_deposit", SignedIn),
    ("deposit_gas", SignedIn),
    ("withdraw_gas", SignedIn),
    ("finish_gas_transfer", SignedIn),
    ("add_member", Member),
    ("remove_member", Member),
    ("transfer_repo", Member),
    ("accept_transfer", Member),
    ("cancel_transfer", Member),
    ("set_required_votes", Member),
    ("cast_ballot", Member),
    ("vote", Member),
    ("propose_policy_change", Member),
    ("create_app_canister", Member),
    ("top_up_app_canister", Member),
    ("govern_app_canister", Member),
    ("set_wasm_deploy", Member),
    ("set_deploy_mode", Member),
    ("deploy_now", Member),
    ("set_evm_deploy", Member),
    ("set_site", Member),
    ("set_site_domains", Member),
    ("evm_registry_publish", Member),
    ("evm_registry_publish_site", Member),
    // What a wallet asks before it signs.
    ("icrc21_canister_call_consent_message", Consent),
    // The queries.
    ("http_request", Anyone),
    ("get_git_canister", Anyone),
    ("get_mirrors_pending", Anyone),
    ("get_git_funding", Anyone),
    ("cycle_balance", Anyone),
    ("list_authorized", Anyone),
    ("pending_icp_deposits", Anyone),
    ("failed_icp_deposits", Anyone),
    ("get_gas_ledger", Anyone),
    ("get_gas_account", Anyone),
    ("get_gas_charges", Anyone),
    ("gas_holds", Anyone),
    ("get_gas_totals", Anyone),
    ("pending_gas_transfers", Anyone),
    ("failed_gas_transfers", Anyone),
    ("stranded_deposits", Anyone),
    ("get_account", Anyone),
    ("my_repos", Anyone),
    ("get_repo_info", Anyone),
    ("get_votes", Anyone),
    ("get_policy_proposals", Anyone),
    ("get_pricing", Anyone),
    ("get_compiler_workers", Anyone),
    ("get_deploy_config", Anyone),
    ("get_deploy_status", Anyone),
    ("get_deploy_history", Anyone),
    ("deploy_queue_len", Anyone),
    ("get_evm_deploy_config", Anyone),
    ("get_evm_deploy_status", Anyone),
    ("evm_get_config", Anyone),
    ("evm_deploy_history", Anyone),
    ("evm_next_nonce", Anyone),
    ("evm_get_registry", Anyone),
    ("names_get_config", Anyone),
    ("feed_governor", Anyone),
    ("sol_get_config", Anyone),
    ("icrc10_supported_standards", Anyone),
];

pub fn rule(method: &str) -> Option<Rule> {
    ic_git_common::ingress::find(RULES, method)
}

/// Could this call be for `who`, who is signed in and no operator? Asked
/// of the `SignedIn` and `Member` methods once the message is otherwise
/// taken (ic_git_common::ingress::asks_standing). Each answer is the
/// method's own first refusal, or wider: what is refused here the method
/// would refuse.
pub fn standing(method: &str, rule: Rule, who: &Principal, arg: &[u8]) -> Result<(), String> {
    use ic_git_common::ingress::{first_text, MAX_DEPOSIT_ARG};
    let unread = || format!("{method}: the argument is not this call's");
    match (rule, method) {
        (Member, _) => {
            let repo = first_text(arg).ok_or_else(unread)?;
            if crate::tenancy::has_part(&repo, who) {
                Ok(())
            } else {
                Err(format!("{method}: {who} has no part in a repo named {repo}"))
            }
        }
        (SignedIn, "create_repo") => {
            let name = first_text(arg).ok_or_else(unread)?;
            if crate::tenancy::could_create(&name, who) {
                Ok(())
            } else {
                Err(format!("create_repo: the balance of {who} does not cover the creation fee; deposit first"))
            }
        }
        (SignedIn, "deposit_from_cycles_ledger" | "deposit_from_icp" | "deposit_gas") => {
            if arg.len() <= MAX_DEPOSIT_ARG {
                Ok(())
            } else {
                Err(format!("{method}: the argument is {} bytes, and a call of it carries at most {MAX_DEPOSIT_ARG}", arg.len()))
            }
        }
        (SignedIn, "finish_icp_deposit") => {
            let (id,) = candid::decode_args::<(u64,)>(arg).map_err(|_| unread())?;
            if crate::icp::is_depositor(id, who) {
                Ok(())
            } else {
                Err(format!("finish_icp_deposit: {who} made no ICP deposit {id}"))
            }
        }
        (SignedIn, "withdraw_gas") => {
            let (amount,) = candid::decode_args::<(candid::Nat,)>(arg).map_err(|_| unread())?;
            let amount = u128::try_from(amount.0).map_err(|_| "withdraw_gas: the amount is more than any balance holds".to_string())?;
            crate::gas::ledger().and_then(|ledger| crate::gas::covers(&ledger, who, amount)).map_err(|e| format!("withdraw_gas: {e}"))
        }
        (SignedIn, "finish_gas_transfer") => {
            let (id,) = candid::decode_args::<(u64,)>(arg).map_err(|_| unread())?;
            if crate::gas::is_party(id, who) {
                Ok(())
            } else {
                Err(format!("finish_gas_transfer: {who} has no gas transfer {id}"))
            }
        }
        // A tenant's method with no answer here is taken from no one: the
        // tests hold every one to a line above.
        (SignedIn, _) => Err(format!("{method}: no one has standing for this call")),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenancy;
    use candid::encode_args;

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n; 8])
    }

    /// Every tenant method has its answer, and it is no to a stranger:
    /// one who owns nothing, belongs to nothing and holds nothing.
    #[test]
    fn a_stranger_has_standing_for_a_first_deposit_alone() {
        let stranger = p(201);
        let mut pricing = tenancy::pricing();
        pricing.create_repo = 1;
        tenancy::set_pricing(pricing);
        for (method, rule) in RULES.iter().filter(|(_, r)| matches!(r, SignedIn | Member)) {
            let deposit = matches!(*method, "deposit_from_cycles_ledger" | "deposit_from_icp" | "deposit_gas");
            let arg = match *method {
                _ if deposit => encode_args((1u64,)).unwrap(),
                "finish_icp_deposit" | "finish_gas_transfer" => encode_args((1u64,)).unwrap(),
                "withdraw_gas" => encode_args((candid::Nat::from(1u64),)).unwrap(),
                _ => encode_args(("no-such-repo",)).unwrap(),
            };
            assert_eq!(standing(method, *rule, &stranger, &arg).is_ok(), deposit, "{method}");
            // An argument that is not the call's is nobody's.
            assert!(deposit || standing(method, *rule, &stranger, b"junk").is_err(), "{method}");
        }
        let long = encode_args((1u64, vec![0u8; 100])).unwrap();
        assert!(standing("deposit_from_icp", SignedIn, &stranger, &long).is_err());
        // The others are not asked.
        assert_eq!(standing("get_pricing", Anyone, &stranger, b""), Ok(()));
    }

    #[test]
    fn a_repos_own_people_have_standing_on_it() {
        let (owner, voter, next, other) = (p(202), p(203), p(204), p(205));
        use futures::executor::block_on;
        tenancy::credit(&owner, 10_000_000_000);
        block_on(tenancy::create_repo("ingress-part", &owner, false)).unwrap();
        block_on(tenancy::add_member("ingress-part", &owner, false, voter, tenancy::Role::Voter)).unwrap();
        block_on(tenancy::transfer_repo("ingress-part", &owner, false, next)).unwrap();
        let arg = encode_args(("ingress-part", "x")).unwrap();
        for who in [owner, voter, next] {
            assert_eq!(standing("cast_ballot", Member, &who, &arg), Ok(()), "{who}");
        }
        let e = standing("cast_ballot", Member, &other, &arg).unwrap_err();
        assert!(e.contains("has no part in a repo named ingress-part"), "{e}");
    }

    #[test]
    fn a_repo_is_created_by_an_account_that_covers_it() {
        let (rich, poor) = (p(206), p(207));
        let mut pricing = tenancy::pricing();
        pricing.create_repo = 1_000;
        tenancy::set_pricing(pricing);
        tenancy::credit(&rich, 1_000);
        tenancy::credit(&poor, 999);
        let arg = encode_args(("ingress-new",)).unwrap();
        assert_eq!(standing("create_repo", SignedIn, &rich, &arg), Ok(()));
        let e = standing("create_repo", SignedIn, &poor, &arg).unwrap_err();
        assert!(e.contains("does not cover the creation fee"), "{e}");
    }
}
