//! The authority's consent messages (ic_git_common::consent): every call
//! the console makes that the authority decides -- deposits, repos and
//! their members, ballots, deploy and site configs, publishes. A method
//! absent here is not the authority's; the canister asks its other side,
//! if it has one, and refuses otherwise.

use crate::tenancy::{PolicyChange, Vote};
use candid::Principal;
use ic_git_common::consent::{args, prefix, unavailable, Icrc21Error};

/// The text for `method` called with the candid-encoded `arg`, or `None`
/// for a method that is not the authority's.
pub fn describe(method: &str, arg: &[u8]) -> Option<Result<String, Icrc21Error>> {
    let m = method;
    Some(match method {
        "deposit" => Ok("Deposit the cycles attached to this call into your ic-git balance.".to_string()),
        "deposit_from_cycles_ledger" => args::<(u64,)>(arg, m).map(|(amount,)| {
            format!(
                "Deposit {} into your ic-git balance, taken from the allowance you approved \
                 on the cycles ledger. The ledger's fee comes out of this amount.",
                cycles(amount)
            )
        }),
        "deposit_from_icp" => args::<(u64,)>(arg, m).map(|(e8s,)| {
            format!(
                "Deposit {} into your ic-git balance, taken from the allowance you approved on \
                 the ICP ledger (plus its {} fee). The ICP goes to the cycles minting canister, \
                 and you are credited the cycles it converts it to at the current rate.",
                icp(e8s),
                icp(crate::icp::ICP_FEE)
            )
        }),
        "finish_icp_deposit" => args::<(u64,)>(arg, m).map(|(id,)| {
            format!(
                "Finish pending ICP deposit {id}: complete its transfer to the cycles minting \
                 canister if that did not go through, then convert it to cycles and credit \
                 them to the depositor."
            )
        }),
        "create_repo" => args::<(String,)>(arg, m).map(|(repo,)| {
            format!(
                "Create the repository \"{repo}\" on ic-git. You become its owner, and the \
                 creation fee is charged to your ic-git balance."
            )
        }),
        "create_app_canister" => args::<(String, u64)>(arg, m).map(|(repo, amount)| {
            format!(
                "Create an app canister for \"{repo}\" with {} from your ic-git balance. \
                 You and ic-git will both control it; ic-git installs what the repository \
                 deploys into it.",
                cycles(amount)
            )
        }),
        "top_up_app_canister" => args::<(String, u64)>(arg, m)
            .map(|(repo, amount)| format!("Send {} from your ic-git balance to the app canister of \"{repo}\".", cycles(amount))),
        "govern_app_canister" => args::<(String,)>(arg, m).map(|(repo,)| {
            format!(
                "GOVERN the app canister of \"{repo}\": ic-git becomes its ONLY controller and you \
                 are removed, so its code changes only by a commit the voters approve. The required \
                 votes, the voters, the owner and the deploy config become votes too, and required \
                 votes can no longer be 0. THIS CANNOT BE UNDONE."
            )
        }),
        "propose_policy_change" => args::<(String, PolicyChange, Vote, Option<String>)>(arg, m).map(|(repo, change, decision, reason)| {
            let what = match &change {
                PolicyChange::RequiredVotes { k } => format!("require {k} approval{} per commit", if *k == 1 { "" } else { "s" }),
                PolicyChange::AddVoter { principal } => format!("add {} as a voter", prefix(&principal.to_text(), 11)),
                PolicyChange::RemoveVoter { principal } => format!("remove voter {}", prefix(&principal.to_text(), 11)),
                PolicyChange::Transfer { new_owner } => format!("transfer the repository to {}", prefix(&new_owner.to_text(), 11)),
                PolicyChange::WasmDeploy { target, source_path } => format!("deploy \"{source_path}\" to canister {target}"),
                PolicyChange::DeployMode { mode } => match mode.as_str() {
                    "reinstall" => "set the install mode to REINSTALL, which WIPES ALL STATE of the target on every deploy".to_string(),
                    other => format!("set the install mode to \"{other}\""),
                },
            };
            let because = match reason.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
                Some(r) => format!(" Reason: {r}"),
                None => String::new(),
            };
            match decision {
                Vote::Approve => format!(
                    "Approve a policy change on \"{repo}\": {what}. It applies once approvals minus \
                     objections reach the required votes.{because}"
                ),
                Vote::Reject => format!("Reject the policy change on \"{repo}\": {what}.{because}"),
                Vote::Object => format!(
                    "Object to the policy change on \"{repo}\": {what}. It then needs one more approval \
                     than usual, and the other voters see why.{because}"
                ),
            }
        }),
        "add_member" => args::<(String, Principal, String)>(arg, m).map(|(repo, who, role)| {
            let power = match role.as_str() {
                "writer" => "push, mint push tokens, and configure what the repository deploys and serves",
                "voter" => "approve, reject or object to commits before the repository deploys them",
                _ => "hold that role",
            };
            format!("Add {who} to \"{repo}\" as a {role}: they will be able to {power}.")
        }),
        "remove_member" => args::<(String, Principal)>(arg, m)
            .map(|(repo, who)| format!("Remove {who} from \"{repo}\". They lose every role they held there.")),
        "set_require_signed_push" => args::<(String, bool)>(arg, m).map(|(repo, on)| {
            if on {
                format!(
                    "Require every push to \"{repo}\" to be signed: a push with a push token \
                     that is not bound to an SSH key will be refused."
                )
            } else {
                format!("Stop requiring signed pushes to \"{repo}\": any valid push token can push.")
            }
        }),
        "set_required_votes" => args::<(String, u32)>(arg, m).map(|(repo, k)| {
            if k == 0 {
                format!("Let pushes to \"{repo}\" deploy without any approvals.")
            } else {
                format!(
                    "Require {k} approval{} from the voters of \"{repo}\" before a pushed \
                     commit is deployed or served as its site. A site served today goes \
                     down until a commit is approved.",
                    if k == 1 { "" } else { "s" }
                )
            }
        }),
        "vote" => args::<(String, String, bool)>(arg, m).map(|(repo, commit, approve)| {
            let commit = prefix(&commit, 12);
            if approve {
                format!("Approve commit {commit} in \"{repo}\" for deployment and for serving as its site.")
            } else {
                rejection(&commit, &repo)
            }
        }),
        "cast_ballot" => (|| {
            let (repo, commit, decision, reason): (String, String, Vote, Option<String>) = args(arg, m)?;
            let commit = prefix(&commit, 12);
            // Describe only a ballot the call would accept: an objection
            // has a reason, and no reason is longer than the call allows.
            let reason = crate::tenancy::ballot_reason(decision, reason).map_err(|e| unavailable(m, e))?;
            // The reason is the signer's own words, shown back verbatim: it
            // is what the other voters will read.
            let because = match reason {
                Some(r) => format!(" Reason: {r}"),
                None => String::new(),
            };
            Ok(match decision {
                Vote::Approve => format!(
                    "Approve commit {commit} in \"{repo}\" for deployment and for serving as its site.{because}"
                ),
                Vote::Reject => format!("{}{because}", rejection(&commit, &repo)),
                Vote::Object => format!(
                    "Object to commit {commit} in \"{repo}\": it needs one more approval than \
                     usual to deploy or to be served as the site, and the other voters see why.{because}"
                ),
            })
        })(),
        "set_wasm_deploy" => args::<(String, String, String)>(arg, m).map(|(repo, target, path)| {
            let into = if target == "app" {
                "its app canister".to_string()
            } else {
                format!("canister {target}")
            };
            format!("On every push to \"{repo}\", build or install {path} from the pushed commit into {into}.")
        }),
        "set_deploy_mode" => args::<(String, String)>(arg, m).map(|(repo, mode)| match mode.as_str() {
            "reinstall" => format!(
                "Set deploys of \"{repo}\" to REINSTALL. Every deploy will WIPE ALL STATE in \
                 the target canister before installing. This stays in force until set back \
                 to upgrade."
            ),
            "upgrade" => format!(
                "Set deploys of \"{repo}\" to upgrade: the target canister keeps its state \
                 across deploys."
            ),
            other => format!("Set the deploy mode of \"{repo}\" to \"{other}\"."),
        }),
        "deploy_now" => args::<(String,)>(arg, m).map(|(repo,)| {
            format!(
                "Deploy \"{repo}\" now, without a push: its newest approved commit, or its \
                 deploy-branch tip if it needs no votes. Each configured leg runs and is charged \
                 to your ic-git balance; an EVM leg deploys a NEW contract even if one is \
                 already on chain."
            )
        }),
        "set_site" => args::<(String, String)>(arg, m).map(|(repo, root)| {
            let from = if root.is_empty() {
                "the repository root".to_string()
            } else {
                format!("its directory {root}/")
            };
            format!(
                "Serve \"{repo}\" as a website at /site/{repo}/, from {from} in the newest \
                 commit on its deploy branch that has the approvals the repo requires (the \
                 tip, when none are required)."
            )
        }),
        "evm_registry_publish_site" => args::<(String,)>(arg, m).map(|(repo,)| {
            format!(
                "Publish a provenance record for the site of \"{repo}\" to the EVM registry: \
                 the commit and the hash of the page it serves. The EVM action fee is charged \
                 to your ic-git balance."
            )
        }),
        _ => return None,
    })
}

/// e8s as ICP, to 8 places with trailing zeros dropped: "1.5 ICP".
fn icp(e8s: u64) -> String {
    let frac = format!("{:08}", e8s % 100_000_000);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        format!("{} ICP", e8s / 100_000_000)
    } else {
        format!("{}.{frac} ICP", e8s / 100_000_000)
    }
}

/// Cycles for a person: T with three decimals from 10 B up, B with one
/// decimal from 1 B, M below. Integer arithmetic only, so 2 T is "2.000 T".
fn cycles(n: u64) -> String {
    const T: u64 = 1_000_000_000_000;
    const B: u64 = 1_000_000_000;
    const M: u64 = 1_000_000;
    if n >= 10 * B {
        format!("{}.{:03} T cycles", n / T, (n % T) / B)
    } else if n >= B {
        format!("{}.{} B cycles", n / B, (n % B) / (B / 10))
    } else {
        format!("{} M cycles", n / M)
    }
}

/// What a rejection does, for both calls that cast one. A ballot replaces
/// the caller's earlier one, so a rejection from someone who had objected
/// takes the objection's -1 away, and the commit can pass on the spot. The
/// message is built from the arguments alone and cannot know which ballot
/// is on record, so every rejection says it.
fn rejection(commit: &str, repo: &str) -> String {
    format!(
        "Reject commit {commit} in \"{repo}\": do not count you as approving it. This \
         replaces any earlier ballot of yours. If you had objected, the objection is \
         withdrawn, and the commit may then be deployed and served as the site."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::encode_args;
    use ic_git_common::consent::ErrorInfo;

    fn text(method: &str, arg: Vec<u8>) -> Result<String, Icrc21Error> {
        describe(method, &arg).unwrap_or_else(|| panic!("{method} is the authority's"))
    }

    #[test]
    fn every_console_method_has_a_message_with_its_arguments_in_it() {
        let p = Principal::from_text("3kq6u-eptpm-egjdi-5qvjv-twk23-m4ymt-qqrcs-tdkvy-ob7zx-x6qq3-wqe").unwrap();
        let cases: Vec<(&str, Vec<u8>, &[&str])> = vec![
            ("deposit_from_cycles_ledger", encode_args((2_100_000_000_000u64,)).unwrap(), &["2.100 T cycles", "allowance"]),
            ("deposit_from_icp", encode_args((150_000_000u64,)).unwrap(), &["Deposit 1.5 ICP", "0.0001 ICP fee", "cycles minting canister"]),
            ("deposit_from_icp", encode_args((2_000_000u64,)).unwrap(), &["Deposit 0.02 ICP"]),
            ("finish_icp_deposit", encode_args((42u64,)).unwrap(), &["pending ICP deposit 42", "credit them to the depositor"]),
            ("create_repo", encode_args(("ic-vote",)).unwrap(), &["\"ic-vote\"", "owner"]),
            ("create_app_canister", encode_args(("ic-vote", 1_000_000_000_000u64)).unwrap(), &["1.000 T cycles", "both control"]),
            ("top_up_app_canister", encode_args(("ic-vote", 500_000_000_000u64)).unwrap(), &["0.500 T cycles", "app canister"]),
            ("set_require_signed_push", encode_args(("ic-vote", true)).unwrap(), &["Require every push", "refused"]),
            ("set_require_signed_push", encode_args(("ic-vote", false)).unwrap(), &["Stop requiring"]),
            ("add_member", encode_args(("ic-vote", p, "voter")).unwrap(), &["3kq6u-eptpm", "voter", "approve, reject or object"]),
            ("remove_member", encode_args(("ic-vote", p)).unwrap(), &["Remove 3kq6u-eptpm", "every role"]),
            ("set_required_votes", encode_args(("ic-vote", 2u32)).unwrap(), &["Require 2 approvals"]),
            ("set_required_votes", encode_args(("ic-vote", 0u32)).unwrap(), &["without any approvals"]),
            ("vote", encode_args(("ic-vote", "0123456789abcdef0123456789abcdef01234567", true)).unwrap(), &["Approve commit 0123456789ab..."]),
            ("vote", encode_args(("ic-vote", "0123456789abcdef0123456789abcdef01234567", false)).unwrap(), &["Reject commit 0123456789ab...", "not count you", "objection is withdrawn", "may then be deployed"]),
            ("cast_ballot", encode_args(("ic-vote", "0123456789abcdef0123456789abcdef01234567", Vote::Approve, None::<String>)).unwrap(), &["Approve commit 0123456789ab..."]),
            ("cast_ballot", encode_args(("ic-vote", "0123456789abcdef0123456789abcdef01234567", Vote::Reject, None::<String>)).unwrap(), &["Reject commit 0123456789ab...", "not count you", "objection is withdrawn", "may then be deployed"]),
            ("cast_ballot", encode_args(("ic-vote", "0123456789abcdef0123456789abcdef01234567", Vote::Object, Some("skips the schema migration"))).unwrap(), &["Object to commit 0123456789ab...", "one more approval", "Reason: skips the schema migration"]),
            ("govern_app_canister", encode_args(("ic-vote",)).unwrap(), &["GOVERN", "ONLY controller", "CANNOT BE UNDONE"]),
            ("propose_policy_change", encode_args(("ic-vote", PolicyChange::RequiredVotes { k: 2 }, Vote::Approve, None::<String>)).unwrap(), &["Approve a policy change", "require 2 approvals", "applies once"]),
            ("propose_policy_change", encode_args(("ic-vote", PolicyChange::AddVoter { principal: p }, Vote::Object, Some("not reviewed yet"))).unwrap(), &["Object to the policy change", "add 3kq6u-eptpm... as a voter", "Reason: not reviewed yet"]),
            ("propose_policy_change", encode_args(("ic-vote", PolicyChange::DeployMode { mode: "reinstall".into() }, Vote::Approve, None::<String>)).unwrap(), &["REINSTALL", "WIPES ALL STATE"]),
            ("propose_policy_change", encode_args(("ic-vote", PolicyChange::Transfer { new_owner: p }, Vote::Reject, None::<String>)).unwrap(), &["Reject the policy change", "transfer the repository to 3kq6u-eptpm..."]),
            ("set_wasm_deploy", encode_args(("ic-vote", "app", "app.wasm")).unwrap(), &["app.wasm", "its app canister"]),
            ("set_deploy_mode", encode_args(("ic-vote", "reinstall")).unwrap(), &["REINSTALL", "WIPE ALL STATE"]),
            ("set_deploy_mode", encode_args(("ic-vote", "upgrade")).unwrap(), &["keeps its state"]),
            ("deploy_now", encode_args(("ic-vote",)).unwrap(), &["now, without a push", "newest approved commit", "NEW contract", "charged to your ic-git balance"]),
            ("set_site", encode_args(("ic-vote", "site")).unwrap(), &["site/", "/site/ic-vote/"]),
            ("set_site", encode_args(("ic-vote", "")).unwrap(), &["repository root"]),
            ("evm_registry_publish_site", encode_args(("ic-vote",)).unwrap(), &["provenance record", "EVM action fee"]),
            ("deposit", encode_args(()).unwrap(), &["attached to this call"]),
        ];
        for (method, arg, expect) in cases {
            let text = text(method, arg).unwrap_or_else(|e| panic!("{method}: {e:?}"));
            for needle in expect {
                assert!(text.contains(needle), "{method}: expected {needle:?} in {text:?}");
            }
        }
        assert!(describe("create_push_token", &encode_args(("r",)).unwrap()).is_none(), "the git side's");
        assert!(describe("charge_rent_now", &encode_args(()).unwrap()).is_none(), "not for a wallet");
    }

    #[test]
    fn arguments_that_do_not_decode_are_an_error_not_a_guess() {
        // The wrong shape for create_repo: a number where the name goes.
        let err = text("create_repo", encode_args((7u64,)).unwrap()).unwrap_err();
        assert!(matches!(err, Icrc21Error::ConsentMessageUnavailable(ErrorInfo { ref description }) if description.contains("create_repo")));
    }

    #[test]
    fn a_ballot_the_call_would_refuse_is_not_described() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        for reason in [None, Some("  ".to_string()), Some("x".repeat(1025))] {
            let err = text("cast_ballot", encode_args(("ic-vote", commit, Vote::Object, reason)).unwrap()).unwrap_err();
            assert!(matches!(err, Icrc21Error::ConsentMessageUnavailable(ErrorInfo { ref description }) if description.contains("reason")));
        }
        // A reason is trimmed the way the call stores it.
        let text = text("cast_ballot", encode_args(("ic-vote", commit, Vote::Approve, Some(" reviewed \n"))).unwrap()).unwrap();
        assert!(text.ends_with("Reason: reviewed"), "{text:?}");
    }

    #[test]
    fn cycles_read_the_way_the_console_prints_them() {
        assert_eq!(cycles(2_000_000_000_000), "2.000 T cycles");
        assert_eq!(cycles(2_100_000_000_000), "2.100 T cycles");
        assert_eq!(cycles(10_000_000_000), "0.010 T cycles");
        assert_eq!(cycles(1_500_000_000), "1.5 B cycles");
        assert_eq!(cycles(100_000_000), "100 M cycles");
    }
}
