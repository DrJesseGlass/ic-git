//! The demo app: a canister whose only job is to prove how it got here.
//!
//! Its source and its compiled `app.wasm` live in a git repo hosted by the
//! ic-git canister. A `git push` to that remote enqueues a deploy; the queue
//! reads `app.wasm` out of the pushed commit's tree and installs it here with
//! `install_code`. Nothing in that chain leaves the Internet Computer, so the
//! page below can name the commit it came from and let a reader check it
//! against the same canister that served the push.
//!
//! Build: demo/hello/build.sh (wasm32-unknown-unknown, release), which
//! also fixes the deployment coordinates below.

use candid::{CandidType, Deserialize};

// Where this build is going, fixed at compile time by build.sh so the page
// can only describe the deployment it is part of: the ic-git canister that
// hosts the repo and runs the deploy, the origin its HTTP routes answer on
// (raw.icp0.io on mainnet, raw.localhost on a replica), and the repo name.
// A bare `cargo build` without them fails here rather than silently
// describing some other canister.
const IC_GIT: &str = env!("HELLO_IC_GIT", "set by demo/hello/build.sh: the ic-git canister id");
const GIT_ORIGIN: &str = env!("HELLO_GIT_ORIGIN", "set by demo/hello/build.sh: the ic-git HTTP origin");
const REPO: &str = env!("HELLO_REPO", "set by demo/hello/build.sh: the repo this canister deploys from");

#[derive(CandidType, Deserialize, Clone)]
struct HeaderField(String, String);

#[derive(CandidType, Deserialize)]
struct HttpRequest {
    method: String,
    url: String,
    headers: Vec<HeaderField>,
    body: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
struct HttpResponse {
    status_code: u16,
    headers: Vec<HeaderField>,
    body: Vec<u8>,
}

#[ic_cdk::query]
fn http_request(req: HttpRequest) -> HttpResponse {
    // One page, served for every path: a demo with a 404 would only invite
    // questions about routing that have nothing to do with what it shows.
    let _ = req;
    HttpResponse {
        status_code: 200,
        headers: vec![
            HeaderField("content-type".into(), "text/html; charset=utf-8".into()),
            HeaderField("cache-control".into(), "no-cache".into()),
        ],
        body: page().into_bytes(),
    }
}

/// Who I am, for anyone who wants to check this page against the IC's own
/// state rather than take its word.
#[ic_cdk::query]
fn whoami() -> String {
    ic_cdk::api::canister_self().to_text()
}

fn page() -> String {
    let me = ic_cdk::api::canister_self().to_text();
    HTML.replace("{{CANISTER}}", &me)
        .replace("{{IC_GIT}}", IC_GIT)
        .replace("{{GIT_ORIGIN}}", GIT_ORIGIN)
        .replace("{{REPO}}", REPO)
}

const HTML: &str = include_str!("index.html");
