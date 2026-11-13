//! ic-git's git canister (docs/CANISTER_SPLIT.md, phase 3 step 12c): the
//! build for the new canister. Objects, refs and repos, both git services
//! over smart HTTP, `/site/`, the git half of `/api`, push tokens and
//! signed pushes. The authority is another canister, named at init,
//! reached by messages (ic_git_git::peer); what it decides about a repo
//! arrives at the authority-facing endpoints below, from its principal
//! alone, and nothing else may write there.
//!
//! Every endpoint here is the combined canister's, body for body
//! (canisters/combined), less the authority's; the two agree until the cut.

// The shared crate.
use ic_git_common::httpjson::git_response;
use ic_git_common::{clock, httpjson, kv};
// The git side (crates/git).
use ic_git_git::{api, for_authority, jobs, mirror, outbox, pack, peer, receive, signed_push, site, smart_http, store, to_authority, tokens};
use ic_git_types::authority_side::Event;
use ic_git_types::git_side::GitSide;
use ic_git_types::oid::Oid;
use ic_git_types::side::Reply;
use ic_git_types::wire::{self, Staged};

use base64::Engine;
use ic_dev_kit_rs::auth;
use ic_dev_kit_rs::http::{
    self, HttpRequest, HttpResponse, StreamingCallback, StreamingCallbackHttpResponse,
    StreamingCallbackToken, StreamingStrategy,
};
use smart_http::Service;
use store::ObjectType;

// --- lifecycle --------------------------------------------------------------

/// What the canister is told once, at install: the authority it answers
/// to, whose principal alone may write the mirrors and ask what they
/// govern.
#[derive(candid::CandidType, serde::Deserialize)]
struct InitArg {
    authority: candid::Principal,
}

/// The authority is the authority canister, by messages to whatever
/// principal `peer::AUTHORITY` names. Done first in init and post_upgrade,
/// before anything can ask. This canister's operator rule is
/// `is_operator`, which the push-policy mirror spares tokens by.
fn install_sides() {
    to_authority::install(&peer::AUTHORITY_CANISTER);
}

/// This canister as the authority sees it (for_authority::Git).
static GIT: for_authority::Git = for_authority::Git { is_operator };

#[ic_cdk::init]
fn init(arg: InitArg) {
    peer::AUTHORITY.set(arg.authority);
    install_sides();
    auth::init_with_caller();
    store::init_schema_version();
    arm_push_cert_seed();
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    kv::save_auth_snapshot(auth::save_to_bytes());
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    install_sides();
    store::check_schema_version();
    auth::init_from_saved(kv::load_auth_snapshot());
    arm_push_cert_seed();
    // What this side has not yet told the authority: the outbox. It
    // survives in stable memory; its timer does not.
    outbox::resume();
}

#[ic_cdk::query]
fn get_authority() -> Option<candid::Principal> {
    peer::AUTHORITY.get()
}

// --- the authority's messages -----------------------------------------------

/// Guard: the caller is the authority (peer::AUTHORITY).
fn from_authority() -> Result<(), String> {
    peer::AUTHORITY.check_caller(&caller())
}

/// What this side answers in this canister it answers at once; the
/// `Reply` is the interface's, for the build where it may not.
fn answered<T>(reply: Reply<T>) -> T {
    match reply {
        Ok(v) => v,
        Err(f) => ic_cdk::trap(format!("the git side did not answer itself: {f}")),
    }
}

// The authority's messages (ic_git_types::wire), each from its principal
// alone: the mirrors, the asks of steps 7 and 10, and the site config.

/// `GitSide::set_deploy_configs`: the deploy-config mirror.
#[ic_cdk::update(guard = "from_authority")]
async fn set_deploy_configs(m: wire::SetDeployConfigs) {
    answered(GIT.set_deploy_configs(&m.repo, m.seq, m.configs).await)
}

/// `GitSide::set_push_policy`: the push-policy mirror.
#[ic_cdk::update(guard = "from_authority")]
async fn set_push_policy(m: wire::SetPushPolicy) {
    answered(GIT.set_push_policy(&m.repo, m.seq, m.policy).await)
}

/// `GitSide::set_approved`: the approved-commits mirror, followed once
/// taken (jobs::follow_approvals).
#[ic_cdk::update(guard = "from_authority")]
async fn set_approved(m: wire::SetApproved) {
    answered(GIT.set_approved(&m.repo, m.seq, m.approved, m.retry).await)
}

/// `GitSide::set_site`: serve the repo from `root`; the authority decided
/// who may.
#[ic_cdk::update(guard = "from_authority")]
async fn set_site(m: wire::SetSite) -> Result<(), String> {
    answered(GIT.set_site(&m.repo, m.root).await)
}

/// `GitSide::check_new_repo`: would the repo be created? Its label.
#[ic_cdk::update(guard = "from_authority")]
async fn check_new_repo(m: wire::CheckNewRepo) -> Result<String, String> {
    answered(GIT.check_new_repo(&m.name).await)
}

/// `GitSide::create_repo`: idempotent, as the authority holds the name.
#[ic_cdk::update(guard = "from_authority")]
async fn create_repo(m: wire::CreateRepo) -> Result<(), String> {
    answered(GIT.create_repo(&m.name).await)
}

/// `GitSide::has_commit`.
#[ic_cdk::update(guard = "from_authority")]
async fn has_commit(m: wire::HasCommit) -> bool {
    match Oid::try_from(m.oid.as_slice()) {
        Ok(oid) => answered(GIT.has_commit(&oid).await),
        Err(_) => false,
    }
}

/// `GitSide::record_artifact`, staged: the head of the encoded `Attested`
/// (for_authority::staged_record).
#[ic_cdk::update(guard = "from_authority")]
fn record_artifact(m: wire::RecordArtifact) -> Result<Staged, String> {
    for_authority::staged_record(&m.repo, &m.kind)
}

/// `GitSide::release_job`, staged: the head of the encoded `Release`
/// (for_authority::staged_release).
#[ic_cdk::update(guard = "from_authority")]
fn release_job(m: wire::ReleaseJob) -> Result<Staged, String> {
    for_authority::staged_release(&m.repo)
}

/// The rest of a staged reply, chunk by chunk.
#[ic_cdk::update(guard = "from_authority")]
fn reply_chunk(m: wire::ReplyChunk) -> Result<Vec<u8>, String> {
    for_authority::reply_chunk(m.handle, m.index)
}

// --- HTTP: git smart-HTTP endpoints -----------------------------------------

enum Route {
    /// GET /<repo>.git/info/refs?service=<service>
    InfoRefs { repo: String, service: Service },
    /// POST /<repo>.git/<service> (upload-pack is a query; receive-pack
    /// mutates and upgrades to http_request_update)
    Rpc { repo: String, service: Service },
    /// GET /site/<repo>/<path>: a committed static bundle (see site.rs).
    Site { repo: String, path: String },
    /// GET /api/...: the git side's read-only JSON for the repo browser
    /// (see api.rs); the authority canister answers its own routes.
    Api { url: String },
    Index,
    NotFound,
}

fn route(req: &HttpRequest) -> Route {
    let path = http::extract_path(&req.url);
    if path == "/" {
        return Route::Index;
    }
    if path.starts_with("/api/") {
        return if req.method == "GET" {
            Route::Api { url: req.url.clone() }
        } else {
            Route::NotFound
        };
    }
    if let Some(rest) = path.strip_prefix("/site/") {
        if req.method != "GET" {
            return Route::NotFound;
        }
        let (repo, sub) = rest.split_once('/').unwrap_or((rest, ""));
        if repo.is_empty() {
            return Route::NotFound;
        }
        return Route::Site {
            repo: repo.to_string(),
            path: sub.to_string(),
        };
    }
    let Some((repo, rest)) = path
        .strip_prefix('/')
        .and_then(|p| p.split_once(".git/"))
    else {
        return Route::NotFound;
    };
    let repo = repo.to_string();
    match (req.method.as_str(), rest) {
        ("GET", "info/refs") => {
            let service = http::extract_query_params(&req.url)
                .get("service")
                .and_then(|s| Service::from_name(s));
            match service {
                Some(service) => Route::InfoRefs { repo, service },
                None => Route::NotFound, // dumb-protocol clients: unsupported
            }
        }
        ("POST", rpc) => match Service::from_name(rpc) {
            Some(service) => Route::Rpc { repo, service },
            None => Route::NotFound,
        },
        _ => Route::NotFound,
    }
}

/// What a Basic-auth push token grants, if the header carries one, the
/// token has not expired, and its minter may still write to the repo: the
/// repo, and the SSH key a push must be signed with if the token is bound.
fn push_grant(headers: &[(String, String)]) -> Option<tokens::Grant> {
    let value = http::get_header(headers, "authorization")?;
    let b64 = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    // Username is ignored; the password slot carries the token.
    let token = creds.split_once(':').map(|(_, p)| p).unwrap_or(&creds);
    tokens::authorize_if(token, |repo, minter| mirror::may_write(repo, minter, is_operator(minter)).is_ok())
}

fn push_authorized(repo: &str, headers: &[(String, String)]) -> Option<tokens::Grant> {
    push_grant(headers).filter(|g| g.repo == repo)
}

/// 401 challenge that makes git retry with credentials.
fn unauthorized() -> HttpResponse {
    HttpResponse {
        status_code: 401,
        headers: vec![
            (
                "WWW-Authenticate".to_string(),
                "Basic realm=\"ic-git\"".to_string(),
            ),
            ("Content-Type".to_string(), "text/plain".to_string()),
        ],
        body: b"push token required\n".to_vec(),
        upgrade: None,
        streaming_strategy: None,
    }
}

#[ic_cdk::query]
fn http_request(req: HttpRequest) -> HttpResponse {
    match route(&req) {
        // head_target doubles as the repo-existence probe: one REPOS read.
        Route::InfoRefs { repo, service } => match store::head_target(&repo) {
            None => git_response(404, "text/plain", b"no such repo\n".to_vec()),
            Some(_) if service == Service::ReceivePack && push_authorized(&repo, &req.headers).is_none() => {
                unauthorized()
            }
            Some(head) => git_response(
                200,
                &format!("application/x-{}-advertisement", service.name()),
                smart_http::advertisement(&repo, service, &head),
            ),
        },
        // Mutating: hand off to http_request_update via the gateway.
        Route::Rpc {
            service: Service::ReceivePack,
            ..
        } => http::upgrade_response(),
        Route::Rpc { repo, .. } => upload_pack(&repo, &req.body),
        Route::Site { repo, path } => site::serve(&repo, &path),
        Route::Api { url } => api_route(&url),
        Route::Index => {
            let repos = store::list_repos().join("\n");
            git_response(
                200,
                "text/plain",
                format!("ic-git\n\nrepos:\n{repos}\n").into_bytes(),
            )
        }
        Route::NotFound => git_response(404, "text/plain", b"not found\n".to_vec()),
    }
}

/// POST /<repo>.git/git-upload-pack: maps pack.rs's semantic reply onto the
/// HTTP envelope (status, content-type, streaming).
fn upload_pack(repo: &str, body: &[u8]) -> HttpResponse {
    const RESULT_CT: &str = "application/x-git-upload-pack-result";
    if !store::repo_exists(repo) {
        return git_response(404, "text/plain", b"no such repo\n".to_vec());
    }
    let req = match pack::parse_request(body) {
        Ok(req) => req,
        Err(e) => return git_response(400, "text/plain", format!("error: {e}\n").into_bytes()),
    };
    match pack::respond(&req) {
        Err(e) => git_response(500, "text/plain", format!("error: {e}\n").into_bytes()),
        Ok(pack::UploadPackReply::Negotiating(body)) => git_response(200, RESULT_CT, body),
        Ok(pack::UploadPackReply::Pack(body)) if body.len() <= pack::STREAM_CHUNK => {
            git_response(200, RESULT_CT, body)
        }
        Ok(pack::UploadPackReply::Pack(mut body)) => {
            body.truncate(pack::STREAM_CHUNK);
            git_response(200, RESULT_CT, body).with_streaming_strategy(
                StreamingStrategy::Callback {
                    callback: StreamingCallback::new(
                        ic_cdk::api::canister_self(),
                        "http_request_streaming_callback".to_string(),
                    ),
                    token: pack::stream_token(&req, 1),
                },
            )
        }
    }
}

#[ic_cdk::query]
fn http_request_streaming_callback(token: StreamingCallbackToken) -> StreamingCallbackHttpResponse {
    match pack::next_chunk(&token) {
        Ok(chunk) => chunk,
        Err(e) => ic_cdk::trap(format!("streaming callback: {e}")),
    }
}

#[ic_cdk::update]
async fn http_request_update(req: HttpRequest) -> HttpResponse {
    match route(&req) {
        Route::Rpc {
            service: Service::ReceivePack,
            repo,
        } => {
            if !store::repo_exists(&repo) {
                return git_response(404, "text/plain", b"no such repo\n".to_vec());
            }
            let Some(grant) = push_authorized(&repo, &req.headers) else {
                return unauthorized();
            };
            // Refusals are a 200 report-status naming each ref
            // (receive::refuse): git drops the body of a non-200 reply and
            // shows only the status code.
            const RESULT: &str = "application/x-git-receive-pack-result";
            // Key-bound tokens and repos that require them (signed_push.rs):
            // the certificate is checked before the push is charged or its
            // pack is read.
            let request = receive::parse_request(&req.body);
            // An unparseable request is refused as it is, uncharged: judging
            // it as "unsigned" would tell a bound token's pusher to sign a
            // push that may already be signed.
            let parsed = match &request {
                Ok(r) => r,
                Err(e) => return git_response(200, RESULT, receive::refuse(&request, e)),
            };
            // The clock the advertisement's nonce was issued by.
            let now_s = crate::clock::now_ns() / 1_000_000_000;
            let required = mirror::requires_signed_push(&repo);
            if let Err(e) = signed_push::check(&repo, grant.key.as_deref(), parsed.cert.as_ref(), required, now_s) {
                return git_response(200, RESULT, receive::refuse(&request, &e));
            }
            // Tenancy: the owner pays for the push before anything is
            // ingested. The authority is asked and waited for. A charge it
            // did not answer refuses the push, and the pusher tries again:
            // the charge is kept on a refused pack, so a lost answer may
            // have charged this one (section 4).
            match to_authority::charge_push(&repo, req.body.len() as u64).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return git_response(200, RESULT, receive::refuse(&request, &e)),
                Err(f) => {
                    let e = format!("the push could not be charged ({f}); push again");
                    return git_response(200, RESULT, receive::refuse(&request, &e));
                }
            }
            // The writers, and whether pushes must be signed, may have
            // changed while the authority answered: both are read again.
            let Some(grant) = push_authorized(&repo, &req.headers) else {
                let e = "the token no longer authorizes pushes to this repo";
                return git_response(200, RESULT, receive::refuse(&request, e));
            };
            let required = mirror::requires_signed_push(&repo);
            if let Err(e) = signed_push::check(&repo, grant.key.as_deref(), parsed.cert.as_ref(), required, now_s) {
                return git_response(200, RESULT, receive::refuse(&request, &e));
            }
            let tip_before = store::head_target(&repo).and_then(|b| store::get_ref(&repo, &b));
            let outcome = receive::handle(&repo, request, &req.body);
            // A votes-gated repo's feed tells of a tip nobody approved: the
            // authority hears of the push through the outbox. Only a gated
            // repo's (the approved-set mirror says which), since the feed
            // has nothing to say of the others.
            if let Some(branch) = store::head_target(&repo) {
                if let Some(tip) = store::get_ref(&repo, &branch) {
                    if tip_before.as_ref() != Some(&tip) && mirror::approved(&repo).is_some() {
                        let event = Event::Pushed {
                            repo: repo.clone(),
                            branch,
                            tip_before: tip_before.as_ref().map(store::oid_hex),
                            tip: store::oid_hex(&tip),
                        };
                        outbox::send(outbox::Outgoing::Notify { event }).await;
                    }
                }
            }
            // m4: if the push moved the deploy branch and a deploy is
            // configured, hand the authority a job and return. The compile +
            // validate + install_code runs from a timer, off the push path
            // (see deploy::accept). Outcome is readable via get_deploy_status.
            if let Some(commit) = outcome.deploy_commit {
                jobs::submit(&repo, &commit).await;
            }
            // A push never approves anything, but it moves the tip the
            // approval walk starts from (a force push can drop the served
            // commit off the branch).
            jobs::follow_approvals(&repo, None).await;
            git_response(200, RESULT, outcome.report)
        }
        _ => git_response(404, "text/plain", b"not found\n".to_vec()),
    }
}

/// The git side's routes of /api (api.rs); the authority canister
/// answers its own.
fn api_route(url: &str) -> HttpResponse {
    let path = http::extract_path(url);
    match httpjson::ApiPath::parse(path) {
        Some(req) => api::handle(&req, url),
        None => httpjson::error(404, "not found"),
    }
}

// --- candid admin API (guard = is_admin, see is_operator) --------------------

/// Store an object from (type, content); returns the hex oid.
#[ic_cdk::update(guard = "is_admin")]
fn put_object(object_type: String, content: Vec<u8>) -> Result<String, String> {
    let object_type = ObjectType::parse(&object_type)?;
    Ok(store::oid_hex(&store::put_object(object_type, &content)))
}

/// Canonical (inflated) object bytes: "<type> <len>\0" + content.
#[ic_cdk::query]
fn get_object(oid_hex: String) -> Option<Vec<u8>> {
    store::get_object(&store::parse_oid(&oid_hex).ok()?)
}

#[ic_cdk::update(guard = "is_admin")]
fn set_ref(repo: String, refname: String, oid_hex: String) -> Result<(), String> {
    store::set_ref(&repo, &refname, store::parse_oid(&oid_hex)?)
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

/// The one operator rule, this canister's own (operators are not
/// mirrored; the authority keeps its own): controllers and the admin
/// allowlist, never this canister. `operator()` and the `is_admin` guard
/// apply it to the caller; the push-token checks apply it to a token's
/// minter; the push-policy mirror spares an operator's tokens by it.
fn is_operator(p: &candid::Principal) -> bool {
    *p != ic_cdk::api::canister_self() && (ic_cdk::api::is_controller(p) || auth::is_principal_authorized(*p).unwrap_or(false))
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

/// Mint a push token for a repo, valid for `days` (default 30, at most
/// 365; see tokens.rs). Returned once, in the clear; only its sha256 is
/// stored. Use as the password in the remote URL:
/// https://ic:<token>@<canister>.raw.icp0.io/<repo>.git
/// `days` is a trailing opt, so a caller passing only the repo still works.
#[ic_cdk::update]
async fn create_push_token(repo: String, days: Option<u32>, key: Option<String>) -> Result<String, String> {
    mirror::may_write(&repo, &caller(), operator())?;
    // Refuse a bad lifetime, a key that cannot be bound, or a repo at its
    // token cap, before paying for randomness; mint checks the cap again
    // after the await.
    tokens::lifetime(days)?;
    tokens::bindable_key(key.as_deref())?;
    tokens::check_room(&repo)?;
    let bytes: Vec<u8> = ic_dev_kit_rs::intercanister::call_no_args(
        candid::Principal::management_canister(),
        "raw_rand",
    )
    .await?;
    // Membership may have changed while raw_rand was in flight.
    mirror::may_write(&repo, &caller(), operator())?;
    let token = hex::encode(&bytes[..16]);
    tokens::mint(&repo, &token, caller(), days, key.as_deref())?;
    Ok(token)
}

/// Create the secret seed push-certificate nonces are keyed with, once. From
/// init and post_upgrade on a timer, since raw_rand is a call; until it
/// lands the advertisement offers no push-cert, and a bound token's push is
/// refused as unsigned. A failed raw_rand is retried a minute later rather
/// than leaving bound tokens unusable until the next upgrade.
fn arm_push_cert_seed() {
    arm_push_cert_seed_after(std::time::Duration::ZERO);
}

fn arm_push_cert_seed_after(delay: std::time::Duration) {
    if signed_push::has_seed() {
        return;
    }
    ic_cdk_timers::set_timer(delay, async {
        let bytes: Result<Vec<u8>, String> = ic_dev_kit_rs::intercanister::call_no_args(
            candid::Principal::management_canister(),
            "raw_rand",
        )
        .await;
        match bytes {
            Ok(b) => signed_push::set_seed_once(&b),
            Err(_) => arm_push_cert_seed_after(std::time::Duration::from_secs(60)),
        }
    });
}

/// The live push tokens of a repo, by id, soonest to expire first. Public:
/// an id is a prefix of the token's hash, not the token, and says nothing a
/// holder could push with.
#[ic_cdk::query]
fn list_push_tokens(repo: String) -> Vec<tokens::PushTokenInfo> {
    tokens::list(&repo)
}

/// Revoke a token you could have minted: writers of its repo, or operators.
#[ic_cdk::update]
fn revoke_push_token(token: String) -> bool {
    match tokens::repo_of(&token) {
        Some(repo) if mirror::may_write(&repo, &caller(), operator()).is_ok() => tokens::revoke(&token),
        _ => false,
    }
}

/// Ids of dead push-token records (operators): ones that can never
/// authorize again and that no listing shows or revoke can remove -- a
/// record that does not decode, or an old-format bare repo name. Only a
/// bug or a rollback leaves one; see tokens.rs.
#[ic_cdk::query(guard = "is_admin")]
fn dead_push_tokens() -> Vec<String> {
    tokens::dead_ids()
}

/// Remove a dead push-token record by id (operators). A live one is
/// refused: revoke_push_token_id removes those.
#[ic_cdk::update(guard = "is_admin")]
fn purge_dead_push_token(id: String) -> Result<(), String> {
    tokens::purge_dead(&id)
}

/// Revoke a token by the id `list_push_tokens` shows, without holding the
/// token. Same permission as `revoke_push_token`.
#[ic_cdk::update]
fn revoke_push_token_id(id: String) -> Result<(), String> {
    let (key, repo) = tokens::find_id(&id)?;
    mirror::may_write(&repo, &caller(), operator())?;
    tokens::revoke_key(&key);
    Ok(())
}

#[ic_cdk::query]
fn list_refs(repo: String) -> Vec<(String, String)> {
    store::list_refs(&repo)
        .into_iter()
        .map(|(name, oid)| (name, store::oid_hex(&oid)))
        .collect()
}

#[ic_cdk::query]
fn list_repos() -> Vec<String> {
    store::list_repos()
}

#[ic_cdk::query]
fn get_site(repo: String) -> Option<site::SiteConfig> {
    site::get_config(&repo)
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
    ic_git_common::consent::consent_message(req, &[ic_git_git::consent::describe])
}

ic_cdk::export_candid!();
