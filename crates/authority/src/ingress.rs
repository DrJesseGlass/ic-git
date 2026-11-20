//! The authority's methods as ingress messages (ic_git_common::ingress):
//! who may send each. A method without a line here is refused, and the
//! canister's tests hold the list to its `.did`.

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
    // Tenants: each asks for an owner, a member, or an account's holder,
    // and the anonymous principal is none of them.
    ("create_repo", SignedIn),
    ("set_require_signed_push", SignedIn),
    ("deposit_from_cycles_ledger", SignedIn),
    ("deposit_from_icp", SignedIn),
    ("finish_icp_deposit", SignedIn),
    ("add_member", SignedIn),
    ("remove_member", SignedIn),
    ("transfer_repo", SignedIn),
    ("accept_transfer", SignedIn),
    ("cancel_transfer", SignedIn),
    ("set_required_votes", SignedIn),
    ("cast_ballot", SignedIn),
    ("vote", SignedIn),
    ("propose_policy_change", SignedIn),
    ("create_app_canister", SignedIn),
    ("top_up_app_canister", SignedIn),
    ("govern_app_canister", SignedIn),
    ("set_wasm_deploy", SignedIn),
    ("set_deploy_mode", SignedIn),
    ("deploy_now", SignedIn),
    ("set_evm_deploy", SignedIn),
    ("set_site", SignedIn),
    ("set_site_domains", SignedIn),
    ("evm_registry_publish", SignedIn),
    ("evm_registry_publish_site", SignedIn),
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
