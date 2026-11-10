//! Tests that run both sides of the cut together: an authority decision,
//! carried across by the canister's glue, and its effect on the git side.
//! Each side's own behavior is tested in its crate.

use crate::clock::set_test_now;
use crate::fixtures::{body_json, get, seed};
use crate::{configs, deploy, store};
use crate::tenancy::{self, Role};
use crate::{mirror, tokens};
use candid::Principal;

const T0: u64 = 1_000 * 86_400 * 1_000_000_000;

/// Against the real write rule: removing a writer, demoting one to
/// voter, and transferring the repo each revoke the tokens of whoever
/// lost write access, and only theirs -- as the change is saved, through
/// the push-policy mirror (mirror::set_push_policy), with no sweep.
#[test]
fn losing_write_access_revokes_your_tokens() {
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
