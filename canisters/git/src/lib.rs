//! ic-git: a git smart-HTTP remote on an Internet Computer canister.
//!
//! See ../../ARCHITECTURE.md. Current state: milestone 1 (object store +
//! refs + admin API) plus the info/refs advertisement, so `git ls-remote`
//! works against seeded repos. upload-pack / receive-pack are stubs.

mod compile;
mod deploy;
mod evm;
mod fleet;
mod interp;
mod lang;
mod object;
mod pack;
mod receive;
mod site;
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
    /// GET /site/<repo>/<path>: a committed static bundle (see site.rs).
    Site { repo: String, path: String },
    Index,
    NotFound,
}

fn route(req: &HttpRequest) -> Route {
    let path = http::extract_path(&req.url);
    if path == "/" {
        return Route::Index;
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
        Route::Site { repo, path } => site::serve(&repo, &path),
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
#[ic_cdk::update(guard = "auth::is_authorized")]
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
/// source at `source_path` (.wat or .lang) is compiled and installed into
/// `target`. The git canister must be a controller of `target`. Install mode
/// defaults to upgrade; change it with set_deploy_mode.
#[ic_cdk::update(guard = "auth::is_authorized")]
fn set_wasm_deploy(repo: String, target: String, source_path: String) -> Result<(), String> {
    deploy::set_config(&repo, target, source_path)
}

/// Set a repo's install mode: "upgrade" (default; preserves target state) or
/// "reinstall" (wipes target state).
#[ic_cdk::update(guard = "auth::is_authorized")]
fn set_deploy_mode(repo: String, mode: String) -> Result<(), String> {
    deploy::set_mode(&repo, deploy::DeployMode::parse(&mode)?)
}

/// Run the configured deploy now against the repo's current deploy-branch tip,
/// without waiting for a push. Returns the outcome. Redeploys even when the
/// tip commit is already in the EVM provenance log (the push path dedupes).
#[ic_cdk::update(guard = "auth::is_authorized")]
async fn deploy_now(repo: String) -> Result<deploy::DeployStatus, String> {
    deploy::run_current(&repo).await
}

#[ic_cdk::query]
fn get_deploy_config(repo: String) -> Option<deploy::DeployConfig> {
    deploy::get_config(&repo)
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
#[ic_cdk::update(guard = "auth::is_authorized")]
fn set_evm_deploy(repo: String, source_path: String, gas_limit: u64) -> Result<(), String> {
    deploy::set_evm_config(&repo, source_path, gas_limit)
}

#[ic_cdk::query]
fn get_evm_deploy_config(repo: String) -> Option<deploy::EvmDeployConfig> {
    deploy::get_evm_config(&repo)
}

#[ic_cdk::query]
fn get_evm_deploy_status(repo: String) -> Option<deploy::EvmDeployStatus> {
    deploy::get_evm_status(&repo)
}

// --- F0: verifiable frontend serving (see VISION.md section 2) ---------------

/// Turn on bundle serving for a repo: GET /site/<repo>/<path> serves blobs
/// from `root` (a directory in the repo tree; "" = repo root) at the
/// deploy-branch tip, each response bound to its commit via X-Ic-Git-Commit.
#[ic_cdk::update(guard = "auth::is_authorized")]
fn set_site(repo: String, root: String) -> Result<(), String> {
    site::set_config(&repo, root)
}

#[ic_cdk::query]
fn get_site(repo: String) -> Option<site::SiteConfig> {
    site::get_config(&repo)
}

// --- Track A: EVM deployment (phases E0/E1; see ROADMAP.md) ------------------

/// Configure EVM signing and broadcast: the EVM RPC canister principal, the
/// threshold ECDSA key name (dfx_test_key locally, test_key_1/key_1 on ICP),
/// the target chain id, and optional custom JSON-RPC URLs (required for chains
/// without an EVM RPC preset, e.g. a local anvil or Base Sepolia).
#[ic_cdk::update(guard = "auth::is_authorized")]
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

/// The canister's own EOA (EIP-55). Derived from the threshold ECDSA public
/// key on first call, cached after. Fund this address with native gas on the
/// target chain; the canister pays for its own deploys.
#[ic_cdk::update(guard = "auth::is_authorized")]
async fn evm_address() -> Result<String, String> {
    evm::address().await
}

/// E0 signing spine: send a plain value transfer from the canister EOA.
/// `value_wei` is a decimal string. Returns the tx hash.
#[ic_cdk::update(guard = "auth::is_authorized")]
async fn evm_send(to: String, value_wei: String) -> Result<evm::TxOutcome, String> {
    evm::send_value(to, value_wei).await
}

/// E1: deploy init bytecode as a CREATE transaction from the canister EOA.
/// Returns the deterministic contract address immediately (no receipt wait);
/// confirm with evm_receipt. Appends to the EVM provenance log.
#[ic_cdk::update(guard = "auth::is_authorized")]
async fn evm_deploy(bytecode_hex: String, gas_limit: u64) -> Result<evm::TxOutcome, String> {
    evm::deploy_bytecode(String::new(), bytecode_hex, gas_limit, String::new()).await
}

/// Poll a transaction receipt. None while still pending. A found receipt is
/// folded into any matching deploy record's receipt_status, same as the
/// automatic post-broadcast poll.
#[ic_cdk::update(guard = "auth::is_authorized")]
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

/// Point the canister at its deployed ProvenanceRegistry contract.
#[ic_cdk::update(guard = "auth::is_authorized")]
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
#[ic_cdk::update(guard = "auth::is_authorized")]
async fn evm_registry_publish(repo: String) -> Result<evm::TxOutcome, String> {
    evm::registry_publish(&repo).await
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

ic_cdk::export_candid!();
