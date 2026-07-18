//! ic-git: a git smart-HTTP remote on an Internet Computer canister.
//!
//! See ../../ARCHITECTURE.md. Current state: milestone 1 (object store +
//! refs + admin API) plus the info/refs advertisement, so `git ls-remote`
//! works against seeded repos. upload-pack / receive-pack are stubs.

mod smart_http;
mod store;

use ic_dev_kit_rs::auth;
use ic_dev_kit_rs::http::{self, HttpRequest, HttpResponse};
use store::Oid;

// --- lifecycle --------------------------------------------------------------

#[ic_cdk::init]
fn init() {
    auth::init_with_caller();
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    store::save_auth_snapshot(auth::save_to_bytes());
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    auth::init_from_saved(store::load_auth_snapshot());
}

// --- HTTP: git smart-HTTP endpoints -----------------------------------------

enum Route {
    /// GET /<repo>.git/info/refs?service=<service>
    InfoRefs { repo: String, service: String },
    /// POST /<repo>.git/git-upload-pack (query: read-only)
    UploadPack { repo: String },
    /// POST /<repo>.git/git-receive-pack (update: mutates)
    ReceivePack { repo: String },
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
    match (req.method.as_str(), rest) {
        ("GET", "info/refs") => {
            let service = ["git-upload-pack", "git-receive-pack"]
                .into_iter()
                .find(|s| req.url.contains(&format!("service={s}")));
            match service {
                Some(s) => Route::InfoRefs {
                    repo: repo.to_string(),
                    service: s.to_string(),
                },
                None => Route::NotFound, // dumb-protocol clients: unsupported
            }
        }
        ("POST", "git-upload-pack") => Route::UploadPack {
            repo: repo.to_string(),
        },
        ("POST", "git-receive-pack") => Route::ReceivePack {
            repo: repo.to_string(),
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
    }
}

#[ic_cdk::query]
fn http_request(req: HttpRequest) -> HttpResponse {
    match route(&req) {
        Route::InfoRefs { repo, service } => {
            if !store::repo_exists(&repo) {
                return git_response(404, "text/plain", b"no such repo\n".to_vec());
            }
            git_response(
                200,
                &format!("application/x-{service}-advertisement"),
                smart_http::advertisement(&repo, &service),
            )
        }
        Route::UploadPack { .. } => git_response(
            501,
            "text/plain",
            b"ic-git: upload-pack not implemented yet (milestone 2)\n".to_vec(),
        ),
        // Mutating: hand off to http_request_update via the gateway.
        Route::ReceivePack { .. } => http::upgrade_response(),
        Route::Index => {
            let repos = store::list_repos().join("\n");
            git_response(200, "text/plain", format!("ic-git\n\nrepos:\n{repos}\n").into_bytes())
        }
        Route::NotFound => git_response(404, "text/plain", b"not found\n".to_vec()),
    }
}

#[ic_cdk::update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    match route(&req) {
        Route::ReceivePack { .. } => git_response(
            501,
            "text/plain",
            b"ic-git: receive-pack not implemented yet (milestone 3)\n".to_vec(),
        ),
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
    store::put_object(&object_type, &content).map(|oid| hex::encode(oid.as_slice()))
}

/// Canonical (inflated) object bytes: "<type> <len>\0" + content.
#[ic_cdk::query]
fn get_object(oid_hex: String) -> Option<Vec<u8>> {
    store::get_object(&parse_oid(&oid_hex).ok()?)
}

#[ic_cdk::update(guard = "auth::is_authorized")]
fn set_ref(repo: String, refname: String, oid_hex: String) -> Result<(), String> {
    store::set_ref(&repo, &refname, parse_oid(&oid_hex)?)
}

#[ic_cdk::query]
fn list_refs(repo: String) -> Vec<(String, String)> {
    store::list_refs(&repo)
        .into_iter()
        .map(|(name, oid)| (name, hex::encode(oid.as_slice())))
        .collect()
}

#[ic_cdk::query]
fn list_repos() -> Vec<String> {
    store::list_repos()
}

fn parse_oid(oid_hex: &str) -> Result<Oid, String> {
    let bytes = hex::decode(oid_hex).map_err(|e| format!("bad oid: {e}"))?;
    Oid::try_from(bytes.as_slice()).map_err(|_| "oid must be 20 bytes".to_string())
}

ic_cdk::export_candid!();
