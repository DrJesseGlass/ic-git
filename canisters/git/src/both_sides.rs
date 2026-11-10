//! Tests that run both sides of the cut together: an authority decision,
//! carried across by the canister's glue, and its effect on the git side.
//! Each side's own behavior is tested in its crate.

use crate::clock::set_test_now;
use crate::fixtures::{body_json, get, run, seed, sides};
use crate::{deploy, store};
use crate::{mirror, tokens};
use candid::Principal;
use tenancy::Role;

/// The authority's flows that await the git side, driven to completion
/// (`fixtures::run`); the rest of the module as it is.
mod tenancy {
    pub use crate::tenancy::*;
    use crate::fixtures::run;
    use candid::Principal;

    pub fn create_repo(name: &str, who: &Principal, operator: bool) -> Result<(), String> {
        run(crate::tenancy::create_repo(name, who, operator))
    }

    pub fn add_member(repo: &str, who: &Principal, operator: bool, target: Principal, role: Role) -> Result<Vec<Member>, String> {
        run(crate::tenancy::add_member(repo, who, operator, target, role))
    }

    pub fn remove_member(repo: &str, who: &Principal, operator: bool, target: Principal) -> Result<Vec<Member>, String> {
        run(crate::tenancy::remove_member(repo, who, operator, target))
    }

    pub fn transfer_repo(repo: &str, who: &Principal, operator: bool, new_owner: Principal) -> Result<(), String> {
        run(crate::tenancy::transfer_repo(repo, who, operator, new_owner))
    }

    pub fn set_required_votes(repo: &str, who: &Principal, operator: bool, k: u32) -> Result<(), String> {
        run(crate::tenancy::set_required_votes(repo, who, operator, k))
    }

    pub fn cast_ballot(repo: &str, who: &Principal, commit_hex: &str, decision: Vote, reason: Option<String>) -> Result<Tally, String> {
        run(crate::tenancy::cast_ballot(repo, who, commit_hex, decision, reason)).map(|c| c.tally)
    }

    pub fn propose_policy_change(repo: &str, who: &Principal, change: PolicyChange, decision: Vote, reason: Option<String>) -> Result<(Tally, Option<PolicyChange>), String> {
        run(crate::tenancy::propose_policy_change(repo, who, change, decision, reason))
    }
}

/// Likewise the config setters.
mod configs {
    pub use crate::configs::*;
    use crate::fixtures::run;

    pub fn set_wasm(repo: &str, target: String, source_path: String) -> Result<(), String> {
        run(crate::configs::set_wasm(repo, target, source_path))
    }
}

const T0: u64 = 1_000 * 86_400 * 1_000_000_000;

/// Against the real write rule: removing a writer, demoting one to
/// voter, and transferring the repo each revoke the tokens of whoever
/// lost write access, and only theirs -- as the change is saved, through
/// the push-policy mirror (mirror::set_push_policy), with no sweep.
#[test]
fn losing_write_access_revokes_your_tokens() {
    sides();
    set_test_now(T0);
    let (owner, w1, w2, next) = (Principal::from_slice(&[9; 8]), Principal::from_slice(&[10; 8]), Principal::from_slice(&[11; 8]), Principal::from_slice(&[12; 8]));
    tenancy::credit(&owner, 10_000_000_000);
    tenancy::create_repo("acl", &owner, false).unwrap();
    tenancy::add_member("acl", &owner, false, w1, Role::Writer).unwrap();
    tenancy::add_member("acl", &owner, false, w2, Role::Writer).unwrap();
    tokens::mint("acl", "tok-owner", owner, None, None).unwrap();
    tokens::mint("acl", "tok-w1", w1, None, None).unwrap();
    tokens::mint("acl", "tok-w2", w2, None, None).unwrap();
    let sweep = || tokens::revoke_unless("acl", |p| mirror::may_write("acl", p, false).is_ok());

    tenancy::remove_member("acl", &owner, false, w1).unwrap();
    assert_eq!(tokens::authorize("tok-w1"), None);
    assert_eq!(tokens::authorize("tok-w2").as_deref(), Some("acl"));

    tenancy::add_member("acl", &owner, false, w2, Role::Voter).unwrap();
    assert_eq!(tokens::authorize("tok-w2"), None);

    assert_eq!(tokens::authorize("tok-owner").as_deref(), Some("acl"));
    tenancy::transfer_repo("acl", &owner, false, next).unwrap();
    assert_eq!(tokens::authorize("tok-owner"), None);
    assert_eq!(sweep(), 0, "nothing was left for a sweep");
}

// The authority's /api views (api_authority.rs), over repos seeded through
// the git side and asked through the canister's /api dispatcher.

#[test]
fn tenancy_views() {
    let (_, c2) = seed("api-ten");
    let owner = Principal::from_slice(&[7; 8]);
    let voter = Principal::from_slice(&[8; 8]);
    tenancy::credit(&owner, 10_000_000_000);
    tenancy::create_repo("api-ten-owned", &owner, false).unwrap();
    tenancy::add_member("api-ten-owned", &owner, false, voter, tenancy::Role::Voter).unwrap();

    let legacy = body_json(&get("/api/api-ten/info"));
    assert_eq!(legacy["exempt"], true);
    assert!(legacy["owner"].is_null());
    let owned = body_json(&get("/api/api-ten-owned/info"));
    assert_eq!(owned["owner"], owner.to_text());
    assert_eq!(owned["members"][0]["role"], "voter");
    assert_eq!(owned["exempt"], false);
    assert_eq!(owned["governed"], false);
    assert_eq!(body_json(&get("/api/api-ten-owned/proposals")).as_array().unwrap().len(), 0);

    let acct = body_json(&get(&format!("/api/account/{}", owner.to_text())));
    assert_eq!(acct["balance"], 10_000_000_000u64 - tenancy::pricing().create_repo);
    assert_eq!(acct["repos"][0], "api-ten-owned");
    assert_eq!(get("/api/account/not-a-principal").status_code, 400);

    assert_eq!(body_json(&get("/api/pricing"))["push_base"], tenancy::pricing().push_base);
    // Votes on the seeded repo's tip (an object that exists): none yet,
    // and the legacy repo requires none.
    let v = body_json(&get(&format!("/api/api-ten/votes/{}", store::oid_hex(&c2))));
    assert_eq!(v["ballots"].as_array().unwrap().len(), 0);
    assert_eq!((v["required"].as_u64(), v["reached"].as_bool()), (Some(0), Some(true)));
    assert_eq!(get("/api/api-ten-owned/votes/not-an-oid").status_code, 400);

    // On the owned repo: an approval and an objection with its reason,
    // and the count they leave: 1 - 1 against a threshold of 1. Objects
    // are shared across repos, so the seeded commit stands in.
    let hex = store::oid_hex(&c2);
    tenancy::set_required_votes("api-ten-owned", &owner, false, 1).unwrap();
    tenancy::cast_ballot("api-ten-owned", &owner, &hex, tenancy::Vote::Approve, None).unwrap();
    tenancy::cast_ballot("api-ten-owned", &voter, &hex, tenancy::Vote::Object, Some("needs a test".into())).unwrap();
    let v = body_json(&get(&format!("/api/api-ten-owned/votes/{hex}")));
    assert_eq!(
        (v["approvals"].as_u64(), v["objections"].as_u64(), v["required"].as_u64(), v["reached"].as_bool()),
        (Some(1), Some(1), Some(1), Some(false))
    );
    let ballots = v["ballots"].as_array().unwrap();
    let obj = ballots.iter().find(|b| b["principal"] == voter.to_text()).unwrap();
    assert_eq!((obj["decision"].as_str(), obj["approve"].as_bool()), (Some("object"), Some(false)));
    assert_eq!(obj["reason"], "needs a test");
    let yes = ballots.iter().find(|b| b["principal"] == owner.to_text()).unwrap();
    assert_eq!((yes["decision"].as_str(), yes["approve"].as_bool()), (Some("approve"), Some(true)));
    assert!(yes["reason"].is_null());

    assert_eq!((obj["counts"].as_bool(), yes["counts"].as_bool()), (Some(true), Some(true)));

    // The objector leaves the policy: the ballot stays on record, marked
    // as no longer counting, and the count goes on without it.
    tenancy::remove_member("api-ten-owned", &owner, false, voter).unwrap();
    let v = body_json(&get(&format!("/api/api-ten-owned/votes/{hex}")));
    assert_eq!(
        (v["approvals"].as_u64(), v["objections"].as_u64(), v["reached"].as_bool()),
        (Some(1), Some(0), Some(true))
    );
    let ballots = v["ballots"].as_array().unwrap();
    let obj = ballots.iter().find(|b| b["principal"] == voter.to_text()).unwrap();
    assert_eq!((obj["decision"].as_str(), obj["counts"].as_bool()), (Some("object"), Some(false)));
    let yes = ballots.iter().find(|b| b["principal"] == owner.to_text()).unwrap();
    assert_eq!(yes["counts"], true);

    // Governed: info says so, and a pending policy change is listed with
    // its ballots and the candid variant as JSON.
    tenancy::set_app_canister("api-ten-owned", Principal::from_slice(&[6; 8])).unwrap();
    tenancy::mark_governed("api-ten-owned", &owner).unwrap();
    assert_eq!(body_json(&get("/api/api-ten-owned/info"))["governed"], true);
    // The owner is the one approver and K = 1: each approval applies at
    // once, nothing pending.
    tenancy::propose_policy_change("api-ten-owned", &owner, tenancy::PolicyChange::AddVoter { principal: voter }, tenancy::Vote::Approve, None).unwrap();
    tenancy::propose_policy_change("api-ten-owned", &owner, tenancy::PolicyChange::RequiredVotes { k: 2 }, tenancy::Vote::Approve, None).unwrap();
    assert_eq!(body_json(&get("/api/api-ten-owned/proposals")).as_array().unwrap().len(), 0);
    // With K = 2 a proposal waits, and is listed.
    let third = Principal::from_slice(&[5; 8]);
    tenancy::propose_policy_change("api-ten-owned", &voter, tenancy::PolicyChange::AddVoter { principal: third }, tenancy::Vote::Approve, Some("two eyes".into())).unwrap();
    let props = body_json(&get("/api/api-ten-owned/proposals"));
    let props = props.as_array().unwrap();
    assert_eq!(props.len(), 1);
    assert_eq!(props[0]["change"]["AddVoter"]["principal"], third.to_text());
    assert_eq!((props[0]["approvals"].as_u64(), props[0]["required"].as_u64(), props[0]["reached"].as_bool()), (Some(1), Some(2), Some(false)));
    assert_eq!(props[0]["ballots"][0]["reason"], "two eyes");
}

#[test]
fn deploys_report_what_was_installed_not_the_tip() {
    let (c1, c2) = seed("api-dep");
    let empty = body_json(&get("/api/api-dep/deploys"));
    assert!(empty["config"].is_null());
    assert!(empty["status"].is_null());
    assert_eq!(empty["history"].as_array().unwrap().len(), 0);

    let target = Principal::from_slice(&[9; 8]).to_text();
    configs::set_wasm("api-dep", target.clone(), "app.wasm".into()).unwrap();
    let cfg = configs::get_wasm("api-dep").unwrap();
    // c1 was installed; c2 (the tip) was pushed later and failed.
    deploy::record_for_tests("api-dep", &cfg, &deploy::DeployStatus {
        commit: store::oid_hex(&c1),
        ok: true,
        message: format!("install to {target}"),
        wasm_len: 7,
        wasm_sha256: "ab".repeat(32),
    });
    deploy::record_for_tests("api-dep", &cfg, &deploy::DeployStatus {
        commit: store::oid_hex(&c2),
        ok: false,
        message: "install_code: rejected".into(),
        wasm_len: 0,
        wasm_sha256: String::new(),
    });

    let v = body_json(&get("/api/api-dep/deploys"));
    assert_eq!(v["config"]["target"], target);
    assert_eq!(v["config"]["source_path"], "app.wasm");
    assert_eq!(v["config"]["mode"], "upgrade");
    let h = v["history"].as_array().unwrap();
    assert_eq!(h.len(), 2);
    assert_eq!(h[0]["commit"], store::oid_hex(&c1));
    assert_eq!(h[0]["target"], target);
    assert_eq!(h[0]["ok"], true);
    assert_eq!(h[0]["wasm_sha256"], "ab".repeat(32));
    assert_eq!(h[1]["commit"], store::oid_hex(&c2));
    assert_eq!(h[1]["ok"], false);
    assert_eq!(get("/api/nope/deploys").status_code, 404);
}

// The push path's failure rule (phase 3, step 8), against an authority
// that does not answer the charge, or whose answer arrives after the
// writers changed.

mod push {
    use super::*;
    use crate::{for_git, smart_http, to_authority};
    use base64::Engine;
    use ic_dev_kit_rs::http::{HttpRequest, HttpResponse};
    use ic_git_types::authority_side::{AuthoritySide, Event};
    use ic_git_types::deploy::Job;
    use ic_git_types::side::{ready, Failure, Fut, Reply};
    use std::cell::Cell;
    use std::rc::Rc;

    /// The real authority, with the next charge failing as told, or landing
    /// after the repo's writers changed.
    #[derive(Default)]
    pub struct Flaky {
        pub fail: Cell<Option<Failure>>,
        pub drop_writers: Cell<bool>,
    }

    impl AuthoritySide for Flaky {
        fn charge_push<'a>(&'a self, repo: &'a str, bytes: u64) -> Fut<'a, Reply<Result<(), String>>> {
            if let Some(f) = self.fail.take() {
                return ready(Err(f));
            }
            let reply = for_git::Authority.charge_push(repo, bytes);
            if self.drop_writers.take() {
                // While the charge was in flight the writers changed, and
                // the authority's mirror write landed before the answer.
                mirror::set_push_policy(repo, u64::MAX, mirror::PushPolicy::default(), |_| false);
            }
            reply
        }

        fn submit_job<'a>(&'a self, seq: u64, repo: &'a str, commit_hex: &'a str, job: Job) -> Fut<'a, Reply<()>> {
            for_git::Authority.submit_job(seq, repo, commit_hex, job)
        }

        fn notify<'a>(&'a self, seq: u64, event: Event) -> Fut<'a, Reply<()>> {
            for_git::Authority.notify(seq, event)
        }
    }

    /// A push creating `refname` at `oid`, with no pack (the object is
    /// there already), through the canister's receive-pack endpoint.
    fn push(repo: &str, token: &str, refname: &str, oid: &store::Oid) -> HttpResponse {
        let mut body = smart_http::pkt_line(
            format!("{} {} {refname}\0 report-status\n", smart_http::ZERO_OID, store::oid_hex(oid)).as_bytes(),
        );
        body.extend_from_slice(smart_http::FLUSH_PKT);
        let auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("ic:{token}")));
        run(crate::http_request_update(HttpRequest {
            method: "POST".into(),
            url: format!("/{repo}.git/git-receive-pack"),
            headers: vec![("authorization".into(), auth)],
            body,
        }))
    }

    #[test]
    fn a_push_waits_for_the_charge_and_checks_its_writer_again() {
        sides();
        set_test_now(T0);
        let owner = Principal::from_slice(&[21; 8]);
        tenancy::credit(&owner, 10_000_000_000);
        tenancy::create_repo("push-ack", &owner, false).unwrap();
        tokens::mint("push-ack", "tok-push", owner, None, None).unwrap();
        let blob = store::put_object(store::ObjectType::Blob, b"pushed");
        let authority = Rc::new(Flaky::default());
        to_authority::set_test_side(Some(authority.clone()));
        let before = tenancy::balance(&owner);

        // The charge is not answered: the push is refused with nothing
        // ingested, and the pusher is told to push again.
        authority.fail.set(Some(Failure::NotDelivered("stopped".into())));
        let report = String::from_utf8(push("push-ack", "tok-push", "refs/tags/one", &blob).body).unwrap();
        assert!(report.contains("could not be charged") && report.contains("push again"), "{report}");
        assert!(store::get_ref("push-ack", "refs/tags/one").is_none());
        assert_eq!(tenancy::balance(&owner), before, "a charge that never ran");

        // Answered: charged, and applied.
        let report = String::from_utf8(push("push-ack", "tok-push", "refs/tags/one", &blob).body).unwrap();
        assert!(report.contains("ok refs/tags/one"), "{report}");
        assert!(store::get_ref("push-ack", "refs/tags/one").is_some());
        let charged = before - tenancy::balance(&owner);
        assert!(charged > 0);

        // The writers changed while the charge was in flight: the token is
        // checked again after it, and the push is refused -- charged, as a
        // refused pack is.
        authority.drop_writers.set(true);
        let report = String::from_utf8(push("push-ack", "tok-push", "refs/tags/two", &blob).body).unwrap();
        assert!(report.contains("no longer authorizes"), "{report}");
        assert!(store::get_ref("push-ack", "refs/tags/two").is_none());
        assert_eq!(tenancy::balance(&owner), before - 2 * charged);
        to_authority::set_test_side(None);
    }
}
