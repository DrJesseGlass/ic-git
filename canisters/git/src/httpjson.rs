//! The /api request path and JSON responses, shared by both sides'
//! handlers (api.rs, api_authority.rs).

use ic_dev_kit_rs::http::HttpResponse;
use ic_git_types::oid::{oid_hex, Oid};
use serde::Serialize;

/// A GET under `/api/`, parsed once by the dispatcher and handed to each
/// side's handler: the rest of the path without trailing slashes, and its
/// first four segments (`<repo>/<what>/<arg>/<more>`; the last keeps any
/// further slashes).
pub struct ApiPath<'a> {
    pub rest: &'a str,
    segs: Vec<&'a str>,
}

impl<'a> ApiPath<'a> {
    pub fn parse(path: &'a str) -> Option<Self> {
        let rest = path.strip_prefix("/api/")?.trim_end_matches('/');
        Some(ApiPath {
            rest,
            segs: rest.splitn(4, '/').collect(),
        })
    }

    /// `(repo, what, arg, more)` for a per-repo route, still percent-encoded.
    pub fn repo_route(&self) -> Option<(&'a str, &'a str, Option<&'a str>, Option<&'a str>)> {
        Some((
            *self.segs.first()?,
            *self.segs.get(1)?,
            self.segs.get(2).copied(),
            self.segs.get(3).copied(),
        ))
    }
}

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
