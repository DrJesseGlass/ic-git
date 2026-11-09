//! The authority's half of the read-only JSON API (api.rs has the git
//! side's):
//!
//!   GET /api/<repo>/info                        tenancy: owner, members, rent state
//!   GET /api/<repo>/votes/<commit>              ballots on a commit, and their count
//!   GET /api/<repo>/proposals                   pending policy changes, with their ballots
//!   GET /api/<repo>/deploys                     wasm deploy config, last status, provenance log
//!   GET /api/account/<principal>                balance and repos of a principal
//!   GET /api/pricing                            the fee table

use crate::deploy;
use crate::httpjson::{decode, error, json, ApiPath};
use crate::tenancy;
use candid::Principal;
use ic_dev_kit_rs::http::HttpResponse;
use ic_git_types::deploy::DeployConfig;
use ic_git_types::oid::parse_oid;
use serde::Serialize;

#[derive(Serialize)]
struct AccountInfo {
    principal: String,
    balance: u64,
    deposited: u64,
    spent: u64,
    repos: Vec<String>,
}

#[derive(Serialize)]
struct MemberInfo {
    principal: String,
    role: &'static str,
}

#[derive(Serialize)]
struct RepoTenancy {
    owner: Option<String>,
    members: Vec<MemberInfo>,
    storage_bytes: u64,
    delinquent: bool,
    required_votes: u32,
    app_canister: Option<String>,
    exempt: bool,
    require_signed_push: bool,
    governed: bool,
}

/// What a deployed app can show about itself: the config that names its
/// target, the most recent attempt, and the log binding each commit to the
/// wasm that was installed from it. The log is the record of what actually
/// ran; the branch tip is not, since a push can be queued, held for votes,
/// or fail after the ref has moved.
#[derive(Serialize)]
struct DeployView {
    config: Option<DeployConfig>,
    status: Option<deploy::DeployStatus>,
    history: Vec<deploy::DeployRecord>,
}

#[derive(Serialize)]
struct BallotInfo {
    principal: String,
    /// "approve", "reject" or "object". `approve` says the same as a bool,
    /// for the clients that read it before objections existed.
    decision: &'static str,
    approve: bool,
    reason: Option<String>,
    at_ns: u64,
    /// False for a ballot whose caster has left the policy: it is listed,
    /// and the count below leaves it out.
    counts: bool,
}

/// The ballots on a commit and where they leave it: a commit passes when
/// `approvals - objections >= required`, over the ballots that count.
/// `required` is 0 and `reached` true for a repo that needs no votes.
#[derive(Serialize)]
struct VotesView {
    ballots: Vec<BallotInfo>,
    approvals: u32,
    objections: u32,
    required: u32,
    reached: bool,
}

fn ballot_info(b: tenancy::Ballot) -> BallotInfo {
    BallotInfo {
        principal: b.principal.to_text(),
        decision: match b.decision {
            tenancy::Vote::Approve => "approve",
            tenancy::Vote::Reject => "reject",
            tenancy::Vote::Object => "object",
        },
        approve: b.approve,
        reason: b.reason,
        at_ns: b.at_ns,
        counts: b.counts,
    }
}

/// A pending policy change (docs/GOVERNANCE.md) and where its ballots
/// stand; `change` is the candid variant as JSON, e.g.
/// {"RequiredVotes":{"k":2}} or {"AddVoter":{"principal":"..."}}.
#[derive(Serialize)]
struct ProposalView {
    change: tenancy::PolicyChange,
    ballots: Vec<BallotInfo>,
    approvals: u32,
    objections: u32,
    required: u32,
    reached: bool,
}

/// Which of the authority's per-repo views a request names.
enum View<'a> {
    Info,
    Votes(&'a str),
    Proposals,
    Deploys,
}

/// Answer a GET under `/api/` if it is one of the authority's routes;
/// `None` hands it to the git side's (`api::handle`).
pub fn handle(req: &ApiPath) -> Option<HttpResponse> {
    let rest = req.rest;
    if rest == "pricing" {
        return Some(json(200, &tenancy::pricing(), None));
    }
    if let Some(p) = rest.strip_prefix("account/") {
        return Some(match decode(p).and_then(|t| Principal::from_text(t).map_err(|e| e.to_string())) {
            Ok(principal) => {
                let a = tenancy::get_account(&principal);
                json(
                    200,
                    &AccountInfo {
                        principal: principal.to_text(),
                        balance: a.balance,
                        deposited: a.deposited,
                        spent: a.spent,
                        repos: tenancy::repos_of(&principal),
                    },
                    None,
                )
            }
            Err(e) => error(400, &format!("bad principal: {e}")),
        });
    }
    let (repo, what, arg, more) = req.repo_route()?;
    let view = match (what, arg, more) {
        ("info", None, None) => View::Info,
        ("votes", Some(commit), None) => View::Votes(commit),
        ("proposals", None, None) => View::Proposals,
        ("deploys", None, None) => View::Deploys,
        _ => return None,
    };
    let repo = match decode(repo) {
        Ok(r) => r,
        Err(e) => return Some(error(400, &e)),
    };
    if !crate::to_git::repo_exists(&repo) {
        return Some(error(404, "no such repo"));
    }
    Some(match view {
        View::Info => match tenancy::repo_info(&repo) {
            Some(i) => json(
                200,
                &RepoTenancy {
                    owner: i.owner.map(|p| p.to_text()),
                    members: i
                        .members
                        .iter()
                        .map(|m| MemberInfo {
                            principal: m.principal.to_text(),
                            role: match m.role {
                                tenancy::Role::Writer => "writer",
                                tenancy::Role::Voter => "voter",
                            },
                        })
                        .collect(),
                    storage_bytes: i.storage_bytes,
                    delinquent: i.delinquent,
                    required_votes: i.required_votes,
                    app_canister: i.app_canister.map(|p| p.to_text()),
                    exempt: i.exempt,
                    require_signed_push: i.require_signed_push,
                    governed: i.governed,
                },
                None,
            ),
            None => error(404, "no such repo"),
        },
        View::Votes(commit) => {
            // A commit id that does not parse has no count: say so rather
            // than report it as a commit that requires nothing.
            if let Err(e) = parse_oid(commit) {
                return Some(error(400, &e));
            }
            let ballots: Vec<BallotInfo> = tenancy::votes(&repo, commit).into_iter().map(ballot_info).collect();
            // A repo without tenancy metadata (legacy, operator-owned) has
            // no policy: it requires nothing, so every commit is reached.
            let t = tenancy::tally(&repo, commit);
            let view = VotesView {
                ballots,
                approvals: t.as_ref().map_or(0, |t| t.approvals),
                objections: t.as_ref().map_or(0, |t| t.objections),
                required: t.as_ref().map_or(0, |t| t.required),
                reached: t.as_ref().is_none_or(|t| t.reached),
            };
            json(200, &view, None)
        }
        View::Proposals => {
            let view: Vec<ProposalView> = tenancy::proposals(&repo)
                .into_iter()
                .map(|p| ProposalView {
                    change: p.change,
                    ballots: p.ballots.into_iter().map(ballot_info).collect(),
                    approvals: p.approvals,
                    objections: p.objections,
                    required: p.required,
                    reached: p.reached,
                })
                .collect();
            json(200, &view, None)
        }
        View::Deploys => json(
            200,
            &DeployView {
                config: crate::to_git::deploy_config(&repo),
                status: deploy::get_status(&repo),
                history: deploy::get_history(&repo),
            },
            None,
        ),
    })
}

#[cfg(test)]
mod tests {
    //! These seed repos through the git side (`api::tests::seed`) and ask
    //! the whole of /api, as the canister does.
    use crate::api::tests::{body_json, get, seed};
    use crate::{deploy, jobs, store, tenancy};
    use candid::Principal;

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
        jobs::set_config("api-dep", target.clone(), "app.wasm".into(), false).unwrap();
        let cfg = jobs::get_config("api-dep").unwrap();
        // c1 was installed; c2 (the tip) was pushed later and failed.
        deploy::record("api-dep", &cfg, &deploy::DeployStatus {
            commit: store::oid_hex(&c1),
            ok: true,
            message: format!("install to {target}"),
            wasm_len: 7,
            wasm_sha256: "ab".repeat(32),
        });
        deploy::record("api-dep", &cfg, &deploy::DeployStatus {
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
}
