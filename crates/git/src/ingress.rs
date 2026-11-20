//! The git canister's methods as ingress messages
//! (ic_git_common::ingress): who may send each. A method without a line
//! here is refused, and the canister's tests hold the list to its `.did`.

use ic_git_common::ingress::Rule::{self, *};

/// The authority is a canister: its messages never come signed by a key.
const AUTHORITY: Rule = NotIngress("only the authority may call this");

pub const RULES: &[(&str, Rule)] = &[
    // The authority's messages.
    ("set_deploy_configs", AUTHORITY),
    ("set_push_policy", AUTHORITY),
    ("set_approved", AUTHORITY),
    ("set_site", AUTHORITY),
    ("set_site_domains", AUTHORITY),
    ("check_new_repo", AUTHORITY),
    ("create_repo", AUTHORITY),
    ("has_commit", AUTHORITY),
    ("standings", AUTHORITY),
    ("record_artifact", AUTHORITY),
    ("release_job", AUTHORITY),
    ("reply_chunk", AUTHORITY),
    // A push, through the gateway: taken with a push token only.
    ("http_request_update", Push),
    // Operators. A controller is one, so the record a controller alone
    // publishes is here; so is the export, which the importer, a
    // canister, reads besides them.
    ("registry_publish_canister", Operator),
    ("put_object", Operator),
    ("set_ref", Operator),
    ("freeze", Operator),
    ("unfreeze", Operator),
    ("set_importer", Operator),
    ("export_page", Operator),
    ("digest_step", Operator),
    ("import_start", Operator),
    ("import_reset", Operator),
    ("authorize", Operator),
    ("deauthorize", Operator),
    ("dead_push_tokens", Operator),
    ("purge_dead_push_token", Operator),
    // A repo's writers.
    ("create_push_token", SignedIn),
    ("revoke_push_token", SignedIn),
    ("revoke_push_token_id", SignedIn),
    // What a wallet asks before it signs.
    ("icrc21_canister_call_consent_message", Consent),
    // The queries.
    ("http_request", Anyone),
    ("http_request_streaming_callback", Anyone),
    ("get_authority", Anyone),
    ("cycle_balance", Anyone),
    ("sites_to_certify", Anyone),
    ("get_object", Anyone),
    ("frozen", Anyone),
    ("get_importer", Anyone),
    ("get_digest", Anyone),
    ("import_status", Anyone),
    ("list_authorized", Anyone),
    ("list_push_tokens", Anyone),
    ("list_refs", Anyone),
    ("list_repos", Anyone),
    ("get_site", Anyone),
    ("icrc10_supported_standards", Anyone),
];

pub fn rule(method: &str) -> Option<Rule> {
    ic_git_common::ingress::find(RULES, method)
}
