//! ic-git: a git smart-HTTP remote on an Internet Computer canister.
//!
//! See ../../ARCHITECTURE.md. Current state: milestone 1 (object store +
//! refs + admin API) plus the info/refs advertisement, so `git ls-remote`
//! works against seeded repos. upload-pack / receive-pack are stubs.

mod compile;
mod deploy;
mod lang;
mod object;
mod pack;
mod receive;
mod smart_http;
mod store;

use base64::Engine;
use ic_dev_kit_rs::auth;
use ic_dev_kit_rs::http::{
    self, HttpRequest, HttpResponse, StreamingCallback, StreamingCallbackHttpResponse,
    StreamingCallbackToken, StreamingStrategy,
};
use smart_http::Service;
use store::ObjectType;

// --- lifecycle --------------------------------------------------------------

#[ic_cdk::init]
fn init() {
    auth::init_with_caller();
    store::init_schema_version();
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    store::save_auth_snapshot(auth::save_to_bytes());
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    store::check_schema_version();
    auth::init_from_saved(store::load_auth_snapshot());
    // Timers do not survive upgrades; re-arm the drain timer if the queue
    // (which does survive, in stable memory) still holds pending deploys.
    deploy::resume_pending();
}

// --- HTTP: git smart-HTTP endpoints -----------------------------------------

enum Route {
    /// GET /<repo>.git/info/refs?service=<service>
    InfoRefs { repo: String, service: Service },
    /// POST /<repo>.git/<service> (upload-pack is a query; receive-pack
    /// mutates and upgrades to http_request_update)
    Rpc { repo: String, service: Service },
    Index,
    NotFound,
}

fn route(req: &HttpRequest) -> Route {
    let path = http::extract_path(&req.url);
    if path == "/" {
        return Route::Index;
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

fn git_response(status_code: u16, content_type: &str, body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status_code,
        headers: vec![
            ("Content-Type".to_string(), content_type.to_string()),
            ("Cache-Control".to_string(), "no-cache".to_string()),
        ],
        body,
        upgrade: None,
        streaming_strategy: None,
    }
}

/// The repo a Basic-auth push token authorizes, if the header carries one.
fn push_token_repo(headers: &[(String, String)]) -> Option<String> {
    let value = http::get_header(headers, "authorization")?;
    let b64 = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    // Username is ignored; the password slot carries the token.
    let token = creds.split_once(':').map(|(_, p)| p).unwrap_or(&creds);
    store::push_token_repo(token)
}

fn push_authorized(repo: &str, headers: &[(String, String)]) -> bool {
    push_token_repo(headers).as_deref() == Some(repo)
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
            Some(_) if service == Service::ReceivePack && !push_authorized(&repo, &req.headers) => {
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
        Err(e) => ic_cdk::trap(&format!("streaming callback: {e}")),
    }
}

#[ic_cdk::update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    match route(&req) {
        Route::Rpc {
            service: Service::ReceivePack,
            repo,
        } => {
            if !store::repo_exists(&repo) {
                return git_response(404, "text/plain", b"no such repo\n".to_vec());
            }
            if !push_authorized(&repo, &req.headers) {
                return unauthorized();
            }
            let outcome = receive::handle(&repo, &req.body);
            // m4: if the push moved the deploy branch and a deploy is
            // configured, enqueue a job and return immediately. The compile +
            // validate + install_code runs from a timer, off the push path
            // (see deploy::enqueue). Outcome is readable via get_deploy_status.
            if let Some(commit) = outcome.deploy_commit {
                deploy::enqueue(&repo, commit);
            }
            git_response(
                200,
                "application/x-git-receive-pack-result",
                outcome.report,
            )
        }
        _ => git_response(404, "text/plain", b"not found\n".to_vec()),
    }
}

// --- candid admin API (milestone 1; auth = dev-kit principal allowlist) -----

#[ic_cdk::update(guard = "auth::is_authorized")]
fn create_repo(name: String) -> Result<(), String> {
    store::create_repo(&name)
}

/// Store an object from (type, content); returns the hex oid.
#[ic_cdk::update(guard = "auth::is_authorized")]
fn put_object(object_type: String, content: Vec<u8>) -> Result<String, String> {
    let object_type = ObjectType::parse(&object_type)?;
    Ok(store::oid_hex(&store::put_object(object_type, &content)))
}

/// Canonical (inflated) object bytes: "<type> <len>\0" + content.
#[ic_cdk::query]
fn get_object(oid_hex: String) -> Option<Vec<u8>> {
    store::get_object(&store::parse_oid(&oid_hex).ok()?)
}

#[ic_cdk::update(guard = "auth::is_authorized")]
fn set_ref(repo: String, refname: String, oid_hex: String) -> Result<(), String> {
    store::set_ref(&repo, &refname, store::parse_oid(&oid_hex)?)
}

/// Mint a push token for a repo. Returned once, in the clear; only its
/// sha256 is stored. Use as the password in the remote URL:
/// https://ic:<token>@<canister>.raw.icp0.io/<repo>.git
#[ic_cdk::update(guard = "auth::is_authorized")]
async fn create_push_token(repo: String) -> Result<String, String> {
    if !store::repo_exists(&repo) {
        return Err(format!("no such repo: {repo}"));
    }
    let bytes: Vec<u8> = ic_dev_kit_rs::intercanister::call_no_args(
        candid::Principal::management_canister(),
        "raw_rand",
    )
    .await?;
    let token = hex::encode(&bytes[..16]);
    store::add_push_token(&repo, &token);
    Ok(token)
}

#[ic_cdk::update(guard = "auth::is_authorized")]
fn revoke_push_token(token: String) -> bool {
    store::revoke_push_token(&token)
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
    let start = ic_cdk::api::instruction_counter();
    let wasm = lang::compile_checked(&text)?;
    let instructions = ic_cdk::api::instruction_counter() - start;
    let info = compile::info_of(&wasm);
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
    let start = ic_cdk::api::instruction_counter();
    let wasm = lang::compile_checked(&src)?;
    let instructions = ic_cdk::api::instruction_counter() - start;
    Ok(MeasureResult {
        funcs,
        wasm_len: wasm.len() as u64,
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
    let start = ic_cdk::api::instruction_counter();
    let (done, done_funcs, total_funcs) = lang::job::step(id, batch as usize)?;
    let instructions = ic_cdk::api::instruction_counter() - start;
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

// --- deploy-on-push (first slice of m4; see ARCHITECTURE.md / ROADMAP.md) ----

/// Configure compile-and-deploy for a repo: on push to the deploy branch, the
/// source at `source_path` (.wat or .lang) is compiled and installed into
/// `target`. The git canister must be a controller of `target`. Install mode
/// defaults to upgrade; change it with set_deploy_mode.
#[ic_cdk::update(guard = "auth::is_authorized")]
fn set_wasm_deploy(repo: String, target: String, source_path: String) -> Result<(), String> {
    if !store::repo_exists(&repo) {
        return Err(format!("no such repo: {repo}"));
    }
    deploy::set_config(&repo, target, source_path)
}

/// Set a repo's install mode: "upgrade" (default; preserves target state) or
/// "reinstall" (wipes target state).
#[ic_cdk::update(guard = "auth::is_authorized")]
fn set_deploy_mode(repo: String, mode: String) -> Result<(), String> {
    deploy::set_mode(&repo, deploy::DeployMode::parse(&mode)?)
}

/// Run the configured deploy now against the repo's current deploy-branch tip,
/// without waiting for a push. Returns the outcome.
#[ic_cdk::update(guard = "auth::is_authorized")]
async fn deploy_now(repo: String) -> Result<deploy::DeployStatus, String> {
    let branch = store::head_target(&repo).ok_or(format!("no such repo: {repo}"))?;
    let tip = store::get_ref(&repo, &branch).ok_or("deploy branch has no commits")?;
    Ok(deploy::run(&repo, tip).await)
}

#[ic_cdk::query]
fn get_deploy_config(repo: String) -> Option<deploy::DeployConfig> {
    deploy::get_config(&repo)
}

#[ic_cdk::query]
fn get_deploy_status(repo: String) -> Option<deploy::DeployStatus> {
    deploy::get_status(&repo)
}

/// Number of deploy jobs waiting in the timer-driven queue.
#[ic_cdk::query]
fn deploy_queue_len() -> u64 {
    deploy::queue_len() as u64
}

ic_cdk::export_candid!();
