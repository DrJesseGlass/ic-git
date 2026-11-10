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
