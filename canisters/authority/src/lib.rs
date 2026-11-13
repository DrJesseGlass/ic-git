//! ic-git's authority canister (docs/CANISTER_SPLIT.md, phase 3 step
//! 12c): the build for umobs after the cut. Tenancy, ballots and
//! governance, accounts and payments, the signers, the deploy queue,
//! provenance, names, the feed, and the compile endpoints until the
//! compiler canister. The git side is another canister, reached by
//! messages (ic_git_authority::peer), which an operator names once
//! (`set_git_canister`); what it tells this one arrives at the
//! git-facing endpoints below, from its principal alone.
//!
//! Every endpoint here is the combined canister's, body for body
//! (canisters/combined), less the git side's; the two agree until the cut.

// The compiler crate's modules, under the names this crate has always used.
use ic_git_compiler::{compile, interp, lang};
// The shared crate.
use ic_git_common::httpjson::git_response;
use ic_git_common::{httpjson, kv};
// The authority (crates/authority).
use ic_git_authority::{api_authority, apps, configs, deploy, evm, feed, fleet, for_git, icp, ledger, mirrors, names, peer, provenance, sol, tenancy, to_git};
use ic_git_types::authority_side::AuthoritySide;
use ic_git_types::side::Reply;
use ic_git_types::wire;

use ic_dev_kit_rs::auth;
use ic_dev_kit_rs::http::{self, HttpRequest, HttpResponse};

// --- lifecycle --------------------------------------------------------------

/// The git side is the git canister, by messages to whatever principal
/// `peer::GIT` names. Done first in init and post_upgrade, before anything
/// can ask.
fn install_sides() {
    to_git::install(&peer::GIT_CANISTER);
}

#[ic_cdk::init]
fn init() {
    install_sides();
    auth::init_with_caller();
    tenancy::arm_rent_timer();
    feed::arm_governor_timer();
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    kv::save_auth_snapshot(auth::save_to_bytes());
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    install_sides();
    auth::init_from_saved(kv::load_auth_snapshot());
    // Timers do not survive upgrades; re-arm the drain timer if the queue
    // (which does survive, in stable memory) still holds pending deploys.
    deploy::resume_pending();
    tenancy::arm_rent_timer();
    feed::arm_governor_timer();
    // What this side has not yet told the git canister: the mirrors marked
    // before the upgrade. They survive in stable memory; their timer does
    // not.
    mirrors::resume();
}

// --- the git canister -------------------------------------------------------

/// Name the git canister (operators). Checked first, through the
/// management canister: it runs code, one canister alone controls it, and
/// that one has no controllers -- a governor, as this canister's is -- so
/// nothing but its approvers' votes can change what answers this side.
/// Named once: a second id is refused, the same one again is fine.
#[ic_cdk::update(guard = "is_admin")]
async fn set_git_canister(git: candid::Principal) -> Result<(), String> {
    peer::name_git(git, canister_info).await
}

#[ic_cdk::query]
fn get_git_canister() -> Option<candid::Principal> {
    peer::GIT.get()
}

#[derive(candid::CandidType)]
struct CanisterInfoArgs {
    canister_id: candid::Principal,
    num_requested_changes: Option<u64>,
}

/// The management canister's `canister_info`, as far as the rule reads
/// it (ic_git_authority::peer::CanisterInfo).
async fn canister_info(id: candid::Principal) -> Result<peer::CanisterInfo, String> {
    ic_dev_kit_rs::intercanister::call(
        candid::Principal::management_canister(),
        "canister_info",
        (CanisterInfoArgs {
            canister_id: id,
            num_requested_changes: None,
        },),
    )
    .await
    .map_err(|e| format!("canister_info of {id}: {e}"))
}

/// Guard: the caller is the git canister (peer::GIT).
fn from_git() -> Result<(), String> {
    peer::GIT.check_caller(&caller())
}

/// What this side answers in this canister it answers at once; the
/// `Reply` is the interface's, for the build where it may not.
fn answered<T>(reply: Reply<T>) -> T {
    match reply {
        Ok(v) => v,
        Err(f) => ic_cdk::trap(format!("the authority did not answer itself: {f}")),
    }
}

// The git canister's messages (ic_git_types::wire), each from its
// principal alone: the receivers of for_git.rs.

/// `AuthoritySide::charge_push`: the push's owner pays before the pack is
/// read. `Err` refuses the push.
#[ic_cdk::update(guard = "from_git")]
async fn charge_push(m: wire::ChargePush) -> Result<(), String> {
    answered(for_git::Authority.charge_push(&m.repo, m.bytes).await)
}

/// A chunk of a job ahead of the `submit_job` that names it; `Err` is the
/// job refused for good (for_git::stage_job).
#[ic_cdk::update(guard = "from_git")]
fn stage_job(m: wire::StageJob) -> Result<(), String> {
    for_git::stage_job(m.seq, &m.repo, &m.commit, m.total, m.index, m.bytes)
}

/// `AuthoritySide::submit_job`: the staged chunks and the tail make the
/// job; `Err` says the chunks are gone and nothing was taken.
#[ic_cdk::update(guard = "from_git")]
fn submit_job(m: wire::SubmitJob) -> Result<(), String> {
    for_git::submit_staged(m.seq, &m.repo, &m.commit, m.staged, m.tail)
}

/// `AuthoritySide::notify`: what happened on the git side, for the feed.
#[ic_cdk::update(guard = "from_git")]
async fn notify(m: wire::Notify) {
    answered(for_git::Authority.notify(m.seq, m.event).await)
}

// --- HTTP: the authority's half of /api, and the feeds -----------------------

#[ic_cdk::query]
fn http_request(req: HttpRequest) -> HttpResponse {
    let path = http::extract_path(&req.url);
    if path == "/" {
        return git_response(
            200,
            "text/plain",
            b"ic-git authority\n\nfeeds (Atom): /feed/<repo>, and /feed for ic-git itself\n".to_vec(),
        );
    }
    if path.starts_with("/api/") {
        if req.method != "GET" {
            return git_response(404, "text/plain", b"not found\n".to_vec());
        }
        return api_route(&req.url);
    }
    if path == "/feed" || path.starts_with("/feed/") {
        if req.method != "GET" {
            return git_response(404, "text/plain", b"not found\n".to_vec());
        }
        let repo = path["/feed".len()..].trim_matches('/');
        let host = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str());
        return feed::serve((!repo.is_empty()).then_some(repo), host);
    }
    git_response(404, "text/plain", b"not found\n".to_vec())
}

/// The authority's routes of /api, answered from this canister's own
/// state; the git canister answers the rest (step 14 points clients at
/// each).
fn api_route(url: &str) -> HttpResponse {
    let path = http::extract_path(url);
    match httpjson::ApiPath::parse(path) {
        Some(req) => api_authority::handle(&req).unwrap_or_else(|| httpjson::error(404, "not found")),
        None => httpjson::error(404, "not found"),
    }
}

// --- repos ------------------------------------------------------------------

/// Anyone signed in with a funded account may create a repo and becomes its
/// owner; operators pay nothing. See tenancy.rs.
#[ic_cdk::update]
async fn create_repo(name: String) -> Result<(), String> {
    tenancy::create_repo(&name, &caller(), operator()).await
}

// --- admin allowlist management ---------------------------------------------
//
// The allowlist that guards the admin API is seeded with the principal that
// ran the first install and survives upgrades via the stable snapshot. Until
// these endpoints existed nothing could change it, so the canister's operator
// was permanently whoever deployed it -- a controller cutover could hand over
// the upgrade key but not the admin API. Controllers can already reinstall the
// canister, so they are trusted at least as much as an allowlisted principal;
// letting them manage the list makes the cutover a settings change.

/// The one operator rule, `tenancy::is_operator`: controllers and the admin
/// allowlist, never this canister. `operator()` and the `is_admin` guard
/// apply it to the caller; the push-token checks apply it to a token's
/// minter; tenancy applies it to a repo's owner to decide who pays.
fn is_operator(p: &candid::Principal) -> bool {
    tenancy::is_operator(p)
}

/// Guard: the caller is an operator (`is_operator`).
fn is_admin() -> Result<(), String> {
    let c = caller();
    if is_operator(&c) {
        Ok(())
    } else {
        Err(format!("{c} is not an operator (a controller or on the admin allowlist)"))
    }
}

fn caller() -> candid::Principal {
    ic_cdk::api::msg_caller()
}

/// Operators (`is_operator`) may act on any repo and pay nothing; everyone
/// else is a tenant.
fn operator() -> bool {
    is_operator(&caller())
}

#[ic_cdk::update(guard = "is_admin")]
fn authorize(principal: candid::Principal) -> Result<(), String> {
    if principal == candid::Principal::anonymous() {
        return Err("refusing to authorize the anonymous principal".to_string());
    }
    auth::add_principal(principal)
}

/// Refuses to empty the list: an allowlist with no members would leave the
/// admin API reachable only by controllers, which is a state nobody chose.
#[ic_cdk::update(guard = "is_admin")]
fn deauthorize(principal: candid::Principal) -> Result<(), String> {
    let current = auth::list_principals()?;
    if !current.contains(&principal) {
        return Err(format!("{principal} is not authorized"));
    }
    if current.len() == 1 {
        return Err("refusing to remove the last authorized principal".to_string());
    }
    auth::remove_principal(principal).map(|_| ())
}

/// Public, like the controller list is: who may operate this canister is part
/// of what a verifier should be able to see.
#[ic_cdk::query]
fn list_authorized() -> Vec<candid::Principal> {
    auth::list_principals().unwrap_or_default()
}

/// Require every push to the repo to be signed: a push with a token that
/// is not bound to an SSH key is refused (signed_push.rs). Owner or
/// operator.
#[ic_cdk::update]
async fn set_require_signed_push(repo: String, on: bool) -> Result<(), String> {
    tenancy::set_require_signed_push(&repo, &caller(), operator(), on).await
}

// --- tenancy: accounts, ownership, membership, votes (docs/TENANCY.md) --------

/// Fund the caller's account with the cycles attached to this call.
#[ic_cdk::update]
fn deposit() -> Result<tenancy::Account, String> {
    let who = caller();
    if who == candid::Principal::anonymous() {
        return Err("sign in first: the anonymous principal cannot hold a balance".into());
    }
    let available = ic_cdk::api::msg_cycles_available();
    let accepted = ic_cdk::api::msg_cycles_accept(available);
    Ok(tenancy::credit(&who, accepted.min(u64::MAX as u128) as u64))
}

/// Fund `beneficiary`'s account with the cycles attached to this call. For
/// deposits that arrive through a proxy -- a cycles wallet canister, another
/// canister paying on a user's behalf -- where the caller is not the tenant.
#[ic_cdk::update]
fn deposit_for(beneficiary: candid::Principal) -> Result<tenancy::Account, String> {
    if beneficiary == candid::Principal::anonymous() {
        return Err("the anonymous principal cannot hold a balance".into());
    }
    let available = ic_cdk::api::msg_cycles_available();
    let accepted = ic_cdk::api::msg_cycles_accept(available);
    Ok(tenancy::credit(&beneficiary, accepted.min(u64::MAX as u128) as u64))
}

/// Fund the caller's account from cycles they approved to this canister on
/// the cycles ledger (icrc2_approve). Returns the new balance.
#[ic_cdk::update]
async fn deposit_from_cycles_ledger(amount: u64) -> Result<u64, String> {
    ledger::deposit_from_cycles_ledger(caller(), amount).await
}

/// Fund your balance with ICP: approve this canister on the ICP ledger for
/// `e8s` plus one fee, then call this. The ICP goes to the cycles minting
/// canister, which turns it into cycles for this canister; you are credited
/// exactly those cycles. Returns your new balance. See icp.rs.
#[ic_cdk::update]
async fn deposit_from_icp(e8s: u64) -> Result<u64, String> {
    icp::deposit_from_icp(caller(), e8s).await
}

/// Finish pending ICP deposit `id` (see pending_icp_deposits): replay its
/// transfer if the outcome was unknown, then have the cycles minting
/// canister convert it and credit the cycles. For the depositor or an
/// operator; credits the depositor and returns their new balance.
#[ic_cdk::update]
async fn finish_icp_deposit(id: u64) -> Result<u64, String> {
    icp::finish_icp_deposit(caller(), operator(), id).await
}

/// ICP deposits not yet credited or settled.
#[ic_cdk::query]
fn pending_icp_deposits() -> Vec<icp::PendingIcpDeposit> {
    icp::pending()
}

/// ICP deposits no retry can finish, for the operator to resolve by hand.
#[ic_cdk::query]
fn failed_icp_deposits() -> Vec<icp::FailedIcpDeposit> {
    icp::failed()
}

#[ic_cdk::query]
fn get_account(principal: candid::Principal) -> tenancy::Account {
    tenancy::get_account(&principal)
}

/// Repos a principal owns or is a member of.
#[ic_cdk::query]
fn my_repos(principal: candid::Principal) -> Vec<String> {
    tenancy::repos_of(&principal)
}

#[ic_cdk::query]
fn get_repo_info(repo: String) -> Option<tenancy::RepoInfo> {
    tenancy::repo_info(&repo)
}

// Whatever changes which commits of a repo are approved -- its voters, its
// owner, its threshold, a ballot -- reaches the git side as a write of the
// approved-set mirror, and the git side follows it (jobs::follow_approvals):
// the site moves to the newest approved commit and its deploy is queued
// (phase 3, step 9). Nothing here has to ask.

/// Grant a principal a role on a repo: "writer" (push, tokens, config) or
/// "voter" (approve commits for deploy). Owner or operator only.
#[ic_cdk::update]
async fn add_member(repo: String, principal: candid::Principal, role: String) -> Result<Vec<tenancy::Member>, String> {
    // A voter added back brings their earlier ballots back into the count.
    // Re-adding a writer as a voter is a demotion, which revokes their push
    // tokens (mirror::set_push_policy).
    tenancy::add_member(&repo, &caller(), operator(), principal, tenancy::Role::parse(&role)?).await
}

#[ic_cdk::update]
async fn remove_member(repo: String, principal: candid::Principal) -> Result<Vec<tenancy::Member>, String> {
    tenancy::remove_member(&repo, &caller(), operator(), principal).await
}

/// Hand a repo to a new owner, who pays for it from then on.
#[ic_cdk::update]
async fn transfer_repo(repo: String, new_owner: candid::Principal) -> Result<(), String> {
    // The owner is an approver, so a new owner changes whose ballots count.
    // The previous owner's push tokens go with the repo, unless they can
    // still write as an operator (mirror::set_push_policy).
    tenancy::transfer_repo(&repo, &caller(), operator(), new_owner).await
}

/// Approvals a commit needs from voters before the deploy queue runs it, and
/// before a site serves it (see `site::served_commit`): raising it from 0 on
/// a live site takes the site down until a commit is approved.
#[ic_cdk::update]
async fn set_required_votes(repo: String, k: u32) -> Result<(), String> {
    tenancy::set_required_votes(&repo, &caller(), operator(), k).await
}

/// What a ballot did to its commit's count.
#[derive(candid::CandidType)]
struct BallotTally {
    approvals: u32,
    objections: u32,
    required: u32,
    reached: bool,
}

/// Cast (or change) a ballot on a commit: approve, reject (a "no", or an
/// approval withdrawn) or object with a reason. An objection counts -1: the
/// commit passes when approvals minus objections reach the threshold.
/// When the ballot changes which commit is the newest approved one -- tip
/// or not, approving, withdrawing or objecting -- the site moves to it and
/// its deploy is queued. Any ballot also retries the approved commit's
/// deploy if the app is not running it (an earlier attempt failed), so
/// voters can get the app back in step with the site without first taking
/// the site down.
#[ic_cdk::update]
async fn cast_ballot(
    repo: String,
    commit: String,
    decision: tenancy::Vote,
    reason: Option<String>,
) -> Result<BallotTally, String> {
    let cast = tenancy::cast_ballot(&repo, &caller(), &commit, decision, reason.clone()).await?;
    let t = cast.tally;
    feed::ballot(&repo, &caller(), &commit, decision, reason.as_deref(), &t, cast.was_reached);
    Ok(BallotTally {
        approvals: t.approvals,
        objections: t.objections,
        required: t.required,
        reached: t.reached,
    })
}

/// The two-way form of `cast_ballot`, kept for clients that predate
/// objections. Returns (approvals, required).
#[ic_cdk::update]
async fn vote(repo: String, commit: String, approve: bool) -> Result<(u32, u32), String> {
    let cast = tenancy::vote(&repo, &caller(), &commit, approve).await?;
    let t = cast.tally;
    let decision = if approve { tenancy::Vote::Approve } else { tenancy::Vote::Reject };
    feed::ballot(&repo, &caller(), &commit, decision, None, &t, cast.was_reached);
    Ok((t.approvals, t.required))
}

#[ic_cdk::query]
fn get_votes(repo: String, commit: String) -> Vec<tenancy::Ballot> {
    tenancy::votes(&repo, &commit)
}

#[ic_cdk::query]
fn get_pricing() -> tenancy::Pricing {
    tenancy::pricing()
}

#[ic_cdk::update(guard = "is_admin")]
fn set_pricing(p: tenancy::Pricing) -> Result<(), String> {
    tenancy::set_pricing(p);
    Ok(())
}

/// Operator only: settle rent now instead of waiting for the hourly timer.
/// Returns (repos charged, cycles collected).
#[ic_cdk::update(guard = "is_admin")]
fn charge_rent_now() -> (u32, u64) {
    tenancy::charge_rent_all()
}

#[ic_cdk::update(guard = "is_admin")]
fn set_cycles_ledger(principal: candid::Principal) -> Result<(), String> {
    ledger::set_ledger_id(principal);
    Ok(())
}

/// Point ICP deposits at another ICP ledger and cycles minting canister
/// (local testing; mainnet ids are the defaults).
#[ic_cdk::update(guard = "is_admin")]
fn set_icp_ledgers(ledger: candid::Principal, cmc: candid::Principal) -> Result<(), String> {
    icp::set_ids(ledger, cmc);
    Ok(())
}

/// Create the repo's app canister from the owner's balance, with the owner
/// and this canister as controllers. Then `set_wasm_deploy(repo, "app", ...)`.
#[ic_cdk::update]
async fn create_app_canister(repo: String, cycles: u64) -> Result<candid::Principal, String> {
    apps::create_app_canister(&repo, &caller(), operator(), cycles).await
}

/// Move cycles from the owner's balance into the repo's app canister.
#[ic_cdk::update]
async fn top_up_app_canister(repo: String, cycles: u64) -> Result<(), String> {
    apps::top_up_app_canister(&repo, &caller(), operator(), cycles).await
}

/// Govern the repo's app canister (docs/GOVERNANCE.md): this canister
/// becomes its only controller and the owner is removed, so its code
/// changes only by an approved commit's deploy; the repo's required votes,
/// voters, owner and deploy config become votes too (propose_policy_change),
/// and required votes can no longer be 0. One-way. Owner only, with votes
/// required and an app canister. Returns the governed canister.
#[ic_cdk::update]
async fn govern_app_canister(repo: String) -> Result<candid::Principal, String> {
    apps::govern_app_canister(&repo, &caller()).await
}

/// Cast a ballot on a change to the repo's policy or deploy config, under
/// the same rule as a commit: approve, reject or object with a reason, and
/// the change applies the moment approvals minus objections reach the
/// required votes. Any voter may. On a governed repo this is the only way
/// to make such a change; on another, the owner could also make it directly.
#[ic_cdk::update]
async fn propose_policy_change(
    repo: String,
    change: tenancy::PolicyChange,
    decision: tenancy::Vote,
    reason: Option<String>,
) -> Result<BallotTally, String> {
    let described = change.describe();
    let (t, apply) = tenancy::propose_policy_change(&repo, &caller(), change, decision, reason.clone()).await?;
    feed::policy_ballot(&repo, &caller(), &described, decision, reason.as_deref(), &t);
    // The deploy configs live in configs.rs; tenancy decided, this applies.
    // A changed threshold or voter set reaches the git side as the
    // approved-set mirror's write, which it follows; a writer re-added as a
    // voter, or a transferred-away owner, loses their push tokens as the
    // change is saved (mirror::set_push_policy).
    match apply {
        Some(tenancy::PolicyChange::WasmDeploy { target, source_path }) => configs::set_wasm(&repo, target, source_path).await?,
        Some(tenancy::PolicyChange::DeployMode { mode }) => configs::set_mode(&repo, deploy::DeployMode::parse(&mode)?).await?,
        _ => {}
    }
    Ok(BallotTally {
        approvals: t.approvals,
        objections: t.objections,
        required: t.required,
        reached: t.reached,
    })
}

/// Policy changes proposed on the repo and not yet applied, with their
/// ballots and count.
#[ic_cdk::query]
fn get_policy_proposals(repo: String) -> Vec<tenancy::Proposal> {
    tenancy::proposals(&repo)
}

/// Deposits whose cycles reached this canister's ledger account but could
/// not be withdrawn into it; the tenant was credited, the operator sweeps.
#[ic_cdk::query]
fn stranded_deposits() -> Vec<ledger::Stranded> {
    ledger::stranded()
}

// --- on-chain build spike (Track B rung R0; see ROADMAP.md) -----------------

/// Compile WebAssembly text (WAT) to a wasm binary, in-canister. The smallest
/// real compiler that proves the source -> artifact pipeline on-chain.
#[ic_cdk::query]
fn compile_wat(text: String) -> Result<Vec<u8>, String> {
    compile::compile_wat(&text)
}

/// Same compile, but returns size + sha256 instead of the bytes -- convenient
/// to inspect over `dfx canister call`.
#[ic_cdk::query]
fn compile_wat_info(text: String) -> Result<compile::CompileInfo, String> {
    compile::compile_wat_info(&text)
}

// --- on-chain build: R1 minimal language (see ROADMAP.md) -------------------

/// Compile R1 language source to a wasm binary, in-canister. Unlike compile_wat
/// (an assembler), this is a real compiler: lexer + parser + wasm codegen.
#[ic_cdk::query]
fn compile_lang(text: String) -> Result<Vec<u8>, String> {
    lang::compile_checked(&text)
}

/// Compile R1 source, returning size + sha256 instead of the bytes.
#[ic_cdk::query]
fn compile_lang_info(text: String) -> Result<compile::CompileInfo, String> {
    let wasm = lang::compile_checked(&text)?;
    Ok(compile::info_of(&wasm))
}

// --- R2: instruction metering, ceiling measurement, resumable compile -------

/// Run `f` and report the wasm instructions it consumed alongside its result.
fn metered<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let start = ic_cdk::api::instruction_counter();
    let result = f();
    (result, ic_cdk::api::instruction_counter() - start)
}

#[derive(candid::CandidType)]
struct MeteredCompile {
    wasm_len: u64,
    sha256_hex: String,
    instructions: u64,
}

#[derive(candid::CandidType)]
struct MeasureResult {
    funcs: u32,
    wasm_len: u64,
    instructions: u64,
}

#[derive(candid::CandidType)]
struct JobProgress {
    done: bool,
    done_funcs: u32,
    total_funcs: u32,
    instructions: u64,
}

/// Compile R1 source and report how many wasm instructions the compile itself
/// cost. An update call so the measurement gets the full ~40B budget.
#[ic_cdk::update]
fn compile_lang_metered(text: String) -> Result<MeteredCompile, String> {
    let (wasm, instructions) = metered(|| lang::compile_checked(&text));
    let info = compile::info_of(&wasm?);
    Ok(MeteredCompile {
        wasm_len: info.wasm_len,
        sha256_hex: info.sha256_hex,
        instructions,
    })
}

/// Compile a generated `funcs`-function program in one call and report the
/// instruction cost -- used to chart the single-message compile ceiling.
#[ic_cdk::update]
fn measure_compile(funcs: u32) -> Result<MeasureResult, String> {
    if funcs == 0 {
        return Err("funcs must be >= 1".into());
    }
    let src = lang::synthetic_program(funcs);
    let (wasm, instructions) = metered(|| lang::compile_checked(&src));
    Ok(MeasureResult {
        funcs,
        wasm_len: wasm?.len() as u64,
        instructions,
    })
}

/// Start a resumable compile; returns a job id. Codegen happens in later steps.
#[ic_cdk::update]
fn compile_job_start(text: String) -> Result<u64, String> {
    lang::job::start(&text)
}

/// Codegen up to `batch` more functions of a job, reporting progress + cost.
#[ic_cdk::update]
fn compile_job_step(id: u64, batch: u32) -> Result<JobProgress, String> {
    let (progress, instructions) = metered(|| lang::job::step(id, batch as usize));
    let (done, done_funcs, total_funcs) = progress?;
    Ok(JobProgress {
        done,
        done_funcs: done_funcs as u32,
        total_funcs: total_funcs as u32,
        instructions,
    })
}

/// Finish a fully-stepped job: assemble, validate, and return the wasm bytes.
#[ic_cdk::update]
fn compile_job_take(id: u64) -> Result<Vec<u8>, String> {
    lang::job::take(id)
}

// --- R3: separate compilation across modules --------------------------------

/// Compile one module in isolation to a portable object (serde-encoded). The
/// object records the module's exports and the imports it expects, with call
/// sites left as unresolved relocations. This is the unit R4 will distribute:
/// one module per canister.
#[ic_cdk::query]
fn compile_module(source: String) -> Result<Vec<u8>, String> {
    let obj = lang::link::compile_module(&source)?;
    serde_json::to_vec(&obj).map_err(|e| e.to_string())
}

/// Link separately-compiled module objects (as returned by compile_module) into
/// one validated wasm binary, resolving cross-module calls.
#[ic_cdk::query]
fn link_module_objects(objects: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    let objs: Result<Vec<_>, String> = objects
        .iter()
        .map(|b| serde_json::from_slice(b).map_err(|e| e.to_string()))
        .collect();
    lang::link::link(&objs?)
}

/// Convenience: separately compile each source, then link -- the whole R3
/// pipeline in one call. Returns size + sha256 of the linked wasm.
#[ic_cdk::query]
fn compile_and_link_info(sources: Vec<String>) -> Result<compile::CompileInfo, String> {
    let objs: Result<Vec<_>, String> = sources
        .iter()
        .map(|s| lang::link::compile_module(s))
        .collect();
    let wasm = lang::link::link(&objs?)?;
    Ok(compile::info_of(&wasm))
}

// --- R4: distribute compilation across a worker fleet -----------------------

#[derive(candid::CandidType)]
struct DistributeReport {
    wasm_len: u64,
    sha256_hex: String,
    module_count: u32,
    worker_count: u32,
}

/// Register the compiler worker pool (canisters exposing `compile_module`).
#[ic_cdk::update(guard = "is_admin")]
fn set_compiler_workers(workers: Vec<candid::Principal>) -> Result<(), String> {
    fleet::set_workers(&workers);
    Ok(())
}

#[ic_cdk::query]
fn get_compiler_workers() -> Vec<candid::Principal> {
    fleet::get_workers()
}

/// Distribute each module's compile across the worker fleet (concurrently),
/// then link the results into one wasm binary.
#[ic_cdk::update]
async fn compile_distributed(sources: Vec<String>) -> Result<Vec<u8>, String> {
    fleet::compile_distributed(&fleet::get_workers(), sources).await
}

/// Same as compile_distributed, reporting size/sha256 plus how many modules
/// were fanned out across how many workers.
#[ic_cdk::update]
async fn compile_distributed_info(sources: Vec<String>) -> Result<DistributeReport, String> {
    let module_count = sources.len() as u32;
    let workers = fleet::get_workers();
    let worker_count = workers.len() as u32;
    let wasm = fleet::compile_distributed(&workers, sources).await?;
    let info = compile::info_of(&wasm);
    Ok(DistributeReport {
        wasm_len: info.wasm_len,
        sha256_hex: info.sha256_hex,
        module_count,
        worker_count,
    })
}

// --- deploy-on-push (first slice of m4; see ARCHITECTURE.md / ROADMAP.md) ----

/// Configure compile-and-deploy for a repo: on push to the deploy branch, the
/// source at `source_path` (.wat or .lang, compiled here, or a committed
/// .wasm, validated) is installed into `target`. A governed repo deploys
/// .wasm only. The git canister must be a controller of `target`. Install mode
/// defaults to upgrade; change it with set_deploy_mode.
#[ic_cdk::update]
async fn set_wasm_deploy(repo: String, target: String, source_path: String) -> Result<(), String> {
    let m = tenancy::can_admin(&repo, &caller(), operator())?;
    // Governed: what the queue installs is the voters' decision.
    tenancy::locked(&m, "the deploy config", Some("WasmDeploy"))?;
    // "app" names the repo's own app canister (create_app_canister).
    let target = if target == "app" {
        m.app_canister
            .ok_or_else(|| format!("repo {repo} has no app canister; call create_app_canister"))?
            .to_text()
    } else {
        target
    };
    configs::set_wasm(&repo, target, source_path).await
}

/// Set a repo's install mode: "upgrade" (default; preserves target state) or
/// "reinstall" (wipes target state).
#[ic_cdk::update]
async fn set_deploy_mode(repo: String, mode: String) -> Result<(), String> {
    let m = tenancy::can_admin(&repo, &caller(), operator())?;
    tenancy::locked(&m, "the install mode", Some("DeployMode"))?;
    configs::set_mode(&repo, deploy::DeployMode::parse(&mode)?).await
}

/// Run the configured deploy now against the repo's release commit -- the
/// deploy-branch tip, or with votes required the approved commit the site
/// serves -- without waiting for a push. Returns the outcome. Redeploys even
/// when the commit is already in the EVM provenance log (the push path
/// dedupes).
#[ic_cdk::update]
async fn deploy_now(repo: String) -> Result<deploy::DeployStatus, String> {
    tenancy::can_admin(&repo, &caller(), operator())?;
    let (commit, job) = deploy::release_job(&repo).await?;
    // Asked again after the wait: the caller may have lost the repo.
    tenancy::can_admin(&repo, &caller(), operator())?;
    Ok(deploy::run_now(&repo, commit, job).await)
}

#[ic_cdk::query]
fn get_deploy_config(repo: String) -> Option<deploy::DeployConfig> {
    configs::get_wasm(&repo)
}

#[ic_cdk::query]
fn get_deploy_status(repo: String) -> Option<deploy::DeployStatus> {
    deploy::get_status(&repo)
}

/// Append-only provenance log for a repo: each deploy's binding of on-chain
/// commit to deployed wasm hash. Immutable record, independently re-verifiable
/// by reproducibly rebuilding the commit.
#[ic_cdk::query]
fn get_deploy_history(repo: String) -> Vec<deploy::DeployRecord> {
    deploy::get_history(&repo)
}

/// Number of deploy jobs waiting in the timer-driven queue.
#[ic_cdk::query]
fn deploy_queue_len() -> u64 {
    deploy::queue_len() as u64
}

/// E2: configure push-to-EVM for a repo. On push to the deploy branch, the
/// committed hex artifact at `source_path` (.hex, creation bytecode) is
/// deployed as a CREATE transaction on the chain in the global EVM config,
/// with the commit oid recorded in the provenance log. Coexists with
/// set_wasm_deploy: a repo can deploy to a canister and an EVM chain from the
/// same push.
#[ic_cdk::update]
async fn set_evm_deploy(repo: String, source_path: String, gas_limit: u64) -> Result<(), String> {
    tenancy::can_admin(&repo, &caller(), operator())?;
    // One definition of "could this canister deploy at all", shared with the
    // deploy leg and with the evm_deploy endpoint, so a config accepted here
    // cannot be rejected at drain time for a reason this check missed.
    configs::set_evm(&repo, source_path, gas_limit).await
}

#[ic_cdk::query]
fn get_evm_deploy_config(repo: String) -> Option<deploy::EvmDeployConfig> {
    configs::get_evm(&repo)
}

#[ic_cdk::query]
fn get_evm_deploy_status(repo: String) -> Option<deploy::EvmDeployStatus> {
    deploy::get_evm_status(&repo)
}

/// Turn on bundle serving for a repo: GET /site/<repo>/<path> serves blobs
/// from `root` (a directory in the repo tree; "" = repo root) at the served
/// commit (the deploy-branch tip, or with votes required the newest approved
/// commit), each response bound to its commit via X-Ic-Git-Commit. The
/// authority decides; the git side keeps the config (phase 3, step 12c).
#[ic_cdk::update]
async fn set_site(repo: String, root: String) -> Result<(), String> {
    tenancy::can_admin(&repo, &caller(), operator())?;
    match to_git::set_site(&repo, root).await {
        Ok(r) => r,
        Err(f) => Err(format!("the site config could not be set ({f}); try again")),
    }
}

// --- Track A: EVM deployment (phases E0/E1; see ROADMAP.md) ------------------

/// Configure EVM signing and broadcast: the EVM RPC canister principal, the
/// threshold ECDSA key name (dfx_test_key locally, test_key_1/key_1 on ICP),
/// the target chain id, and optional custom JSON-RPC URLs (required for chains
/// without an EVM RPC preset, e.g. a local anvil or Base Sepolia).
#[ic_cdk::update(guard = "is_admin")]
fn evm_set_config(
    evm_rpc: String,
    key_name: String,
    chain_id: u64,
    rpc_urls: Vec<String>,
) -> Result<(), String> {
    evm::set_config(evm_rpc, key_name, chain_id, rpc_urls)
}

#[ic_cdk::query]
fn evm_get_config() -> Option<evm::EvmConfig> {
    evm::get_config()
}

// --- ic-name-service hook (names.rs) -----------------------------------------

/// Turn on the announce hook: after each successful install, tell the
/// name service canister `canister` about it under `<handle>/<label>`.
/// Operators: controllers or the admin allowlist, like set_pricing.
#[ic_cdk::update(guard = "is_admin")]
fn names_set_config(canister: String, handle: String) -> Result<(), String> {
    names::set_config(canister, handle)
}

#[ic_cdk::update(guard = "is_admin")]
fn names_clear_config() {
    names::clear_config()
}

#[ic_cdk::query]
fn names_get_config() -> Option<names::NamesConfig> {
    names::get_config()
}

// --- Activity feeds (docs/GOVERNANCE.md, section 6; feed.rs) ------------------

/// Mirror the governor's proposals, ballots and outcomes into this
/// canister's own feed (`GET /feed`), polled every few minutes. The
/// governor must control this canister: the feed says who governs ic-git,
/// so it cannot be pointed at a canister that does not. `None` stops it.
#[ic_cdk::update(guard = "is_admin")]
fn feed_set_governor(governor: Option<candid::Principal>) -> Result<(), String> {
    if let Some(p) = &governor {
        if !ic_cdk::api::is_controller(p) {
            return Err(format!("{p} does not control this canister, so it is not its governor"));
        }
    }
    feed::set_governor(governor);
    Ok(())
}

#[ic_cdk::query]
fn feed_governor() -> Option<candid::Principal> {
    feed::governor()
}

/// Ask the governor what changed now rather than at the next poll. Returns
/// how many events that added to the feed.
#[ic_cdk::update(guard = "is_admin")]
async fn feed_poll_governor() -> Result<u64, String> {
    feed::poll_governor().await
}

/// The canister's own EOA (EIP-55). Derived from the threshold ECDSA public
/// key on first call, cached after. Fund this address with native gas on the
/// target chain; the canister pays for its own deploys.
#[ic_cdk::update(guard = "is_admin")]
async fn evm_address() -> Result<String, String> {
    evm::address().await
}

/// E0 signing spine: send a plain value transfer from the canister EOA.
/// `value_wei` is a decimal string. Returns the tx hash.
#[ic_cdk::update(guard = "is_admin")]
async fn evm_send(to: String, value_wei: String) -> Result<evm::TxOutcome, String> {
    evm::send_value(to, value_wei).await
}

/// E1: deploy init bytecode as a CREATE transaction from the canister EOA.
/// Returns the deterministic contract address immediately (no receipt wait);
/// confirm with evm_receipt. Appends to the EVM provenance log.
#[ic_cdk::update(guard = "is_admin")]
async fn evm_deploy(bytecode_hex: String, gas_limit: u64) -> Result<evm::TxOutcome, String> {
    // Hex in, bytes out: the signing side takes decoded bytecode, so this
    // endpoint decodes on the way in. The candid signature is unchanged.
    let bytecode = ic_git_types::deploy::decode_bytecode_hex(&bytecode_hex)?;
    Ok(evm::deploy_bytecode(String::new(), bytecode, gas_limit, String::new()).await?)
}

/// Poll a transaction receipt. None while still pending. A found receipt is
/// folded into any matching deploy record's receipt_status, same as the
/// automatic post-broadcast poll.
#[ic_cdk::update(guard = "is_admin")]
async fn evm_receipt(tx_hash: String) -> Result<Option<evm::ReceiptSummary>, String> {
    evm::receipt(tx_hash).await
}

/// Append-only EVM provenance log: (repo, commit, chain, address, tx,
/// bytecode hash, ok) per deploy attempt. Repo and commit are empty for
/// direct-hex deploys. An ok record means the broadcast was accepted;
/// receipt_status carries the mined outcome once the automatic receipt
/// poll (or an evm_receipt call) has seen it.
#[ic_cdk::query]
fn evm_deploy_history() -> Vec<evm::EvmDeployRecord> {
    evm::get_history()
}

/// The stored next EVM nonce: the nonce after the last broadcast a provider
/// accepted. Sends use the higher of this and the confirmed count.
#[ic_cdk::query]
fn evm_next_nonce() -> Option<u64> {
    evm::next_nonce()
}

/// Forget the stored next nonce. Only for a transaction that was accepted
/// and then dropped from every mempool, which leaves a gap every later send
/// waits behind; on a merely slow one, the next send would replace it.
#[ic_cdk::update(guard = "is_admin")]
fn evm_reset_nonce() {
    evm::reset_next_nonce()
}

/// Point the canister at its deployed ProvenanceRegistry contract.
#[ic_cdk::update(guard = "is_admin")]
fn evm_set_registry(address: String) -> Result<(), String> {
    evm::set_registry(address)
}

#[ic_cdk::query]
fn evm_get_registry() -> Option<String> {
    evm::get_registry()
}

/// Write a repo's provenance to the on-chain registry: set(repo, tip commit,
/// sha256 of its EVM artifact). The canister's EOA is the registry's owner, so
/// this transaction is the canister's own attestation.
#[ic_cdk::update]
async fn evm_registry_publish(repo: String) -> Result<evm::TxOutcome, String> {
    tenancy::can_admin(&repo, &caller(), operator())?;
    // Resolve the record before charging: a publish that cannot happen costs
    // nothing.
    evm::require_publish_target()?;
    let record = provenance::tip_record(&repo).await?;
    publish_checked(&repo, &record).await
}

/// Write a *site* repo's provenance to the registry under the key
/// `<repo>#site` -- NOT the bare repo name, which belongs to the repo's
/// deploy-artifact record: set("<repo>#site", served commit, sha256 of the served
/// entrypoint blob). Read it back with `get("<repo>#site")`; `get("<repo>")`
/// returns the deploy record, or an all-zero struct if there is none.
/// No EVM deploy config needed -- the attested artifact is the frontend file
/// itself, so a client can verify a served page against the canister's own
/// on-chain attestation.
#[ic_cdk::update]
async fn evm_registry_publish_site(repo: String) -> Result<evm::TxOutcome, String> {
    tenancy::can_admin(&repo, &caller(), operator())?;
    evm::require_publish_target()?;
    let record = provenance::site_record(&repo).await?;
    publish_checked(&repo, &record).await
}

/// Publish `ic-git#canister`: the commit this canister was built from and
/// the sha256 of its installed module. A controller only -- the governor
/// calls it right after it installs an upgrade (docs/GOVERNANCE.md,
/// section 5). Paid by the canister, as no repo is being served.
#[ic_cdk::update]
async fn registry_publish_canister(
    commit: String,
    module_sha256: String,
) -> Result<evm::TxOutcome, String> {
    if !ic_cdk::api::is_controller(&caller()) {
        return Err("only a controller of this canister can publish its record".to_string());
    }
    let record = provenance::canister_record(&commit, &module_sha256)?;
    provenance::publish(&record).await.map_err(|e| e.message)
}

/// Publish a record asked of the git side, once the checks made before the
/// ask hold again: the caller may have lost the repo, or the registry been
/// unset, while it waited.
async fn publish_checked(repo: &str, record: &provenance::Record) -> Result<evm::TxOutcome, String> {
    tenancy::can_admin(repo, &caller(), operator())?;
    evm::require_publish_target()?;
    publish_charged(repo, record).await
}

/// Charge the repo for a registry publish, and give back what a failed one
/// did not use: all of it when it failed before any outcall, the price less
/// the outcalls it made when no provider can hold the transaction (a read,
/// the signature, or a definite refusal failed). When a provider may hold it,
/// the gas may be spent and the full charge stays.
async fn publish_charged(
    repo: &str,
    record: &provenance::Record,
) -> Result<evm::TxOutcome, String> {
    let cost = tenancy::pricing().evm_action;
    let payer = tenancy::charge_action(repo, cost, "registry publish")?;
    provenance::publish(record).await.map_err(|e| {
        tenancy::refund_action(payer, e.refundable(cost));
        e.message
    })
}

// --- Track S: Solana signing spine (phase S0; see VISION.md section 4) -------

/// Configure Solana signing and broadcast: the SOL RPC canister principal
/// (mainnet: tghme-zyaaa-aaaar-qarca-cai), the threshold Schnorr key name
/// (dfx_test_key locally, test_key_1/key_1 on ICP), the target cluster
/// ("mainnet" / "devnet" / "testnet"), and optional custom JSON-RPC URLs.
#[ic_cdk::update(guard = "is_admin")]
fn sol_set_config(
    sol_rpc: String,
    key_name: String,
    cluster: String,
    rpc_urls: Vec<String>,
) -> Result<(), String> {
    sol::set_config(sol_rpc, key_name, cluster, rpc_urls)
}

#[ic_cdk::query]
fn sol_get_config() -> Option<sol::SolConfig> {
    sol::get_config()
}

/// The canister's own Solana address (base58 of its threshold Ed25519 public
/// key). Derived on first call, cached after. Fund it (devnet: airdrop) and
/// the canister pays its own fees.
#[ic_cdk::update(guard = "is_admin")]
async fn sol_address() -> Result<String, String> {
    sol::address().await
}

/// Lamport balance of the canister's own address (finalized commitment).
#[ic_cdk::update(guard = "is_admin")]
async fn sol_balance() -> Result<u64, String> {
    sol::balance().await
}

/// S0 signing spine: send a system transfer from the canister's address.
/// Returns the transaction signature; confirm with sol_signature_status.
#[ic_cdk::update(guard = "is_admin")]
async fn sol_send(to: String, lamports: u64) -> Result<sol::SolTxOutcome, String> {
    sol::send_lamports(to, lamports).await
}

/// Confirmation status of a transaction signature: null while the cluster
/// does not know it, otherwise the confirmation level, slot, and whether the
/// transaction succeeded on-chain. The sol analog of evm_receipt.
#[ic_cdk::update(guard = "is_admin")]
async fn sol_signature_status(signature: String) -> Result<Option<sol::SolSigStatus>, String> {
    sol::signature_status(signature).await
}

// --- R6 spike: interpret a wasm32-wasip1 module in-canister ------------------

#[derive(candid::CandidType)]
struct RunReport {
    output: String,
    output_len: u64,
    exit_code: i32,
    instructions: u64,
}

fn run_and_measure(wasm: &[u8]) -> Result<RunReport, String> {
    let (r, instructions) = metered(|| interp::run_wasip1(wasm));
    let r = r?;
    Ok(RunReport {
        output: String::from_utf8_lossy(&r.output).into_owned(),
        output_len: r.output.len() as u64,
        exit_code: r.exit_code,
        instructions,
    })
}

/// Interpret a wasm32-wasip1 module (as bytes) with wasmi + a minimal WASI host,
/// returning captured stdout/stderr, exit code, and the instruction cost of the
/// interpretation. This is the harness rustc.wasm will eventually run in.
#[ic_cdk::update]
fn run_wasm(module: Vec<u8>) -> Result<RunReport, String> {
    run_and_measure(&module)
}

/// Self-contained demo: compile WAT (R0) to a wasip1 module in-canister, then
/// interpret it (R6) -- source -> wasm -> interpreted-run, all on-chain, with
/// the interpretation cost measured.
#[ic_cdk::update]
fn run_wat(text: String) -> Result<RunReport, String> {
    let wasm = compile::compile_wat_checked(&text)?;
    run_and_measure(&wasm)
}

// --- wallet standards: ICRC-10 and ICRC-21 -----------------------------------
//
// A wallet signing for a user asks the target canister for a readable
// description of the call first, and refuses to sign without one. See
// ic_git_common::consent for the answer and this side's consent.rs for the
// messages; a method absent there is refused, not signed blind.

#[ic_cdk::query]
fn icrc10_supported_standards() -> Vec<ic_git_common::consent::Standard> {
    ic_git_common::consent::supported_standards()
}

#[ic_cdk::update]
fn icrc21_canister_call_consent_message(req: ic_git_common::consent::ConsentMessageRequest) -> ic_git_common::consent::ConsentMessageResponse {
    ic_git_common::consent::consent_message(req, &[ic_git_authority::consent::describe])
}

ic_cdk::export_candid!();
