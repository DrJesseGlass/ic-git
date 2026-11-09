//! JSON responses for the /api routes, shared by both sides' handlers
//! (api.rs, api_authority.rs).

use ic_dev_kit_rs::http::HttpResponse;
use ic_git_types::oid::{oid_hex, Oid};
use serde::Serialize;

/// Minimal percent-decoding; the result must be UTF-8.
pub fn decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3).ok_or("truncated percent-escape")?;
            let v = u8::from_str_radix(std::str::from_utf8(hex).map_err(|_| "bad escape")?, 16)
                .map_err(|_| "bad percent-escape")?;
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "path is not UTF-8".to_string())
}

pub fn json<T: Serialize>(status: u16, value: &T, commit: Option<&Oid>) -> HttpResponse {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    let mut res = crate::git_response(status, "application/json", body);
    res.headers
        .push(("X-Content-Type-Options".to_string(), "nosniff".to_string()));
    if let Some(c) = commit {
        res.headers
            .push(("X-Ic-Git-Commit".to_string(), oid_hex(c)));
    }
    res
}

pub fn error(status: u16, msg: &str) -> HttpResponse {
    #[derive(Serialize)]
    struct Err<'a> {
        error: &'a str,
    }
    json(status, &Err { error: msg }, None)
}
