//! F0 (VISION.md section 2): serve a committed static bundle over
//! http_request.
//!
//! GET /site/<repo>/<path> resolves <path> within the repo's deploy-branch
//! tip tree (under the configured root directory) and serves the blob. The
//! serving code and the source of truth are the same audited canister: what
//! is served IS what is committed, and every response names the commit it
//! came from (X-Ic-Git-Commit) -- the binding a client-side verifier (F2)
//! checks against the ProvenanceRegistry.
//!
//! Rung one deliberately: no IC response certification yet (reach it via the
//! .raw gateway, or verify by hash -- which is the F2 story anyway), and
//! blobs above the single-response cap are rejected rather than streamed.

use crate::object;
use crate::store::{self, ObjectType};
use candid::CandidType;
use ic_dev_kit_rs::http::HttpResponse;
use serde::{Deserialize, Serialize};

/// Per-repo site config (META key `site:{repo}`). Existence turns serving on.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SiteConfig {
    /// Directory within the repo tree the bundle is served from; "" = root.
    pub root: String,
}

fn site_key(repo: &str) -> String {
    format!("site:{repo}")
}

pub fn set_config(repo: &str, root: String) -> Result<(), String> {
    if !store::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    let root = root.trim_matches('/').to_string();
    store::meta_set_json(&site_key(repo), &SiteConfig { root });
    Ok(())
}

pub fn get_config(repo: &str) -> Option<SiteConfig> {
    store::meta_get_json(&site_key(repo))
}

/// Stay under the ~2 MiB ingress reply limit with headroom for headers.
/// Bigger assets need the streaming rung. Public because the registry
/// publisher must refuse to attest a body `serve` would answer 413 for --
/// an attestation nobody can ever verify is worse than no attestation.
pub const MAX_BODY: usize = 1_900_000;

/// Byte offset of `needle` in `hay` at or after `from`.
fn find_from(hay: &str, needle: &str, from: usize) -> Option<usize> {
    hay.get(from..).and_then(|s| s.find(needle)).map(|p| p + from)
}

/// End of a tag's attribute region: the `>` that closes it, skipping any `>`
/// inside a quoted attribute value. `None` if the tag never closes.
fn tag_end(hay: &str, from: usize) -> Option<usize> {
    let b = hay.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &c) in b.iter().enumerate().skip(from) {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None => match c {
                b'"' | b'\'' => quote = Some(c),
                b'>' => return Some(i),
                _ => {}
            },
        }
    }
    None
}

/// Start offset of attribute `name` in an attribute region: the name must sit
/// on a word boundary and be followed by `=`. Rules out `data-integrity=` and a
/// bare `integrity` with no value, both of which a substring test would accept.
fn attr_at(region: &str, name: &str) -> Option<usize> {
    let b = region.as_bytes();
    let mut i = 0;
    while let Some(pos) = find_from(region, name, i) {
        i = pos + 1;
        if pos > 0 && !b[pos - 1].is_ascii_whitespace() {
            continue;
        }
        let mut j = pos + name.len();
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < b.len() && b[j] == b'=' {
            return Some(j + 1);
        }
    }
    None
}

fn has_attr(region: &str, name: &str) -> bool {
    attr_at(region, name).is_some()
}

/// Value of attribute `name`, quoted or bare.
fn attr_value<'a>(region: &'a str, name: &str) -> Option<&'a str> {
    let b = region.as_bytes();
    let mut j = attr_at(region, name)?;
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    if j >= b.len() {
        return None;
    }
    let (quote, start) = match b[j] {
        q @ (b'"' | b'\'') => (Some(q), j + 1),
        _ => (None, j),
    };
    let mut k = start;
    while k < b.len() {
        let stop = match quote {
            Some(q) => b[k] == q,
            None => b[k].is_ascii_whitespace(),
        };
        if stop {
            break;
        }
        k += 1;
    }
    region.get(start..k)
}

/// Why a served entrypoint's own bytes are not enough to verify the page, or
/// `None` if they are.
///
/// The registry attests exactly ONE blob -- the entrypoint, since
/// `provenance::site_record` resolves path "" -- so every file the entrypoint
/// *names* is fetched in a separate request that no attestation covers. Without
/// this check a hostile gateway serves the honest, correctly-hashing index.html
/// next to a malicious app.js, and a verifier comparing only the entrypoint
/// hash reports "verified" while attacker code runs. That is a false GREEN, the
/// one direction docs/ATTESTATION.md's doctrine forbids.
///
/// Two entrypoint shapes are honest, and this accepts exactly those: reference
/// nothing (inline it, so the attested bytes cover it), or declare `integrity`
/// on every reference, which the *browser* then enforces -- SRI covers the
/// subresources and the registry covers the document that names them, so the
/// pair is complete where either alone is not.
///
/// Deliberately conservative, and biased toward refusing:
/// - `<script src>` and `<link rel=stylesheet|modulepreload>` need `integrity`.
/// - `<iframe>`, `<object>`, `<embed>` have no SRI mechanism at all, so they can
///   never be made verifiable and are refused outright.
/// - A tag that never closes, or a body that is not UTF-8, is refused rather
///   than skipped.
/// A false refusal costs the operator one inline-or-add-integrity edit; a false
/// accept costs a user their funds. That asymmetry is the whole design, and it
/// is why no attempt is made to track HTML comments: a commented-out
/// `<script src=...>` is refused, which is the safe direction to be wrong in.
///
/// NOT covered, stated rather than implied: images, fonts, and media. SRI has
/// no mechanism for them, so refusing them would reject every real site. They
/// cannot execute; a swapped image can mislead the eye but not the machine.
pub fn unverifiable_subresource(served_path: &str, body: &[u8]) -> Option<String> {
    if !matches!(
        served_path.rsplit('.').next().unwrap_or(""),
        "html" | "htm"
    ) {
        return None;
    }
    let Ok(text) = core::str::from_utf8(body) else {
        return Some("entrypoint is not valid UTF-8, so its references cannot be read".to_string());
    };
    // ASCII-only lowercasing, so offsets stay aligned with the original.
    let hay = text.to_ascii_lowercase();
    let b = hay.as_bytes();
    let mut i = 0;
    while let Some(lt) = find_from(&hay, "<", i) {
        let name_start = lt + 1;
        let mut name_end = name_start;
        while name_end < b.len() && b[name_end].is_ascii_alphanumeric() {
            name_end += 1;
        }
        i = name_end.max(lt + 1);
        let tag = &hay[name_start..name_end];
        if !matches!(tag, "script" | "link" | "iframe" | "object" | "embed") {
            continue;
        }
        let Some(end) = tag_end(&hay, name_end) else {
            return Some(format!("<{tag}> tag is never closed"));
        };
        let region = &hay[name_end..end];
        i = end + 1;
        match tag {
            // No SRI mechanism exists for these; integrity= on them is ignored
            // by the browser, so accepting one would be accepting a promise
            // nothing enforces.
            "iframe" | "object" | "embed" => {
                if has_attr(region, "src") || has_attr(region, "data") {
                    return Some(format!(
                        "<{tag}> loads a subresource SRI cannot cover; inline the content instead"
                    ));
                }
            }
            "script" => {
                if has_attr(region, "src") && !has_attr(region, "integrity") {
                    return Some("<script src=...> has no integrity=".to_string());
                }
            }
            "link" => {
                let rel = attr_value(region, "rel").unwrap_or("");
                let enforced = rel
                    .split_ascii_whitespace()
                    .any(|r| matches!(r, "stylesheet" | "modulepreload"));
                if enforced && has_attr(region, "href") && !has_attr(region, "integrity") {
                    return Some(format!("<link rel=\"{rel}\"> has no integrity="));
                }
            }
            _ => {}
        }
    }
    None
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "txt" | "md" => "text/plain; charset=utf-8",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "application/octet-stream",
    }
}

fn plain(status_code: u16, msg: &str) -> HttpResponse {
    crate::git_response(status_code, "text/plain", msg.as_bytes().to_vec())
}

/// The blob `serve` would return for `path`, given an already-resolved tip and
/// config: its tree location (site root prefix and index.html fallback
/// applied) and bytes. One walk from the root -- a blob serves directly; a
/// directory (including "" for the bundle root) serves the index.html inside.
fn resolve_blob(tip: &store::Oid, cfg: &SiteConfig, path: &str) -> Option<(String, Vec<u8>)> {
    let rel = path.trim_matches('/');
    let full = match (cfg.root.is_empty(), rel.is_empty()) {
        (true, _) => rel.to_string(),
        (false, true) => cfg.root.clone(),
        (false, false) => format!("{}/{rel}", cfg.root),
    };
    match object::node_at_path(tip, &full) {
        Ok((ObjectType::Blob, body)) => Some((full, body)),
        Ok((ObjectType::Tree, tree)) => object::tree_entries(&tree)
            .ok()
            .and_then(|es| es.into_iter().find(|e| e.name == b"index.html"))
            .and_then(|e| store::get_object_parsed(&e.oid))
            .and_then(|(ty, body)| {
                let name = if full.is_empty() {
                    "index.html".to_string()
                } else {
                    format!("{full}/index.html")
                };
                (ty == ObjectType::Blob).then_some((name, body))
            }),
        _ => None,
    }
}

/// What a verifier attests for `path` (site root when `path` is ""): the tip
/// commit, the served blob's tree location, and its raw bytes -- exactly what
/// `serve` would return as the body. `None` mirrors the cases `serve` turns
/// into a 404. Used by the registry publisher so the attested bytes are byte-
/// identical to what the network serves.
pub fn resolve_entry(repo: &str, path: &str) -> Option<(store::Oid, String, Vec<u8>)> {
    let cfg = get_config(repo)?;
    let branch = store::head_target(repo)?;
    let tip = store::get_ref(repo, &branch)?;
    let (served, body) = resolve_blob(&tip, &cfg, path)?;
    Some((tip, served, body))
}

/// GET /site/<repo>/<path>. `path` may be "", carry a trailing slash
/// (directory request), or name a blob.
pub fn serve(repo: &str, path: &str) -> HttpResponse {
    let Some(cfg) = get_config(repo) else {
        return plain(404, "no site configured for repo\n");
    };
    let Some(branch) = store::head_target(repo) else {
        return plain(404, "no such repo\n");
    };
    let Some(tip) = store::get_ref(repo, &branch) else {
        return plain(404, "site branch has no commits\n");
    };

    let Some((served, body)) = resolve_blob(&tip, &cfg, path) else {
        return plain(404, "not found in site bundle\n");
    };
    if body.len() > MAX_BODY {
        return plain(413, "file exceeds the single-response limit\n");
    }
    let mut res = crate::git_response(200, content_type(&served), body);
    // The provenance binding a verifier checks against the registry. Path is
    // the actual location in the commit tree (site root and index.html
    // fallback applied), so `git show <commit>:<path>` reproduces the body.
    res.headers
        .push(("X-Ic-Git-Repo".to_string(), repo.to_string()));
    res.headers
        .push(("X-Ic-Git-Commit".to_string(), store::oid_hex(&tip)));
    res.headers.push(("X-Ic-Git-Path".to_string(), served));
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ObjectType;

    /// Commit index.html + app/main.js into a fresh repo and serve them.
    #[test]
    fn serves_committed_bundle_with_provenance_headers() {
        store::create_repo("web").unwrap();
        let index = store::put_object(ObjectType::Blob, b"<h1>hi</h1>");
        let js = store::put_object(ObjectType::Blob, b"console.log(1)");

        let mut app = Vec::new();
        app.extend_from_slice(b"100644 main.js\0");
        app.extend_from_slice(js.as_slice());
        let app_tree = store::put_object(ObjectType::Tree, &app);

        let mut root = Vec::new();
        root.extend_from_slice(b"40000 app\0");
        root.extend_from_slice(app_tree.as_slice());
        root.extend_from_slice(b"100644 index.html\0");
        root.extend_from_slice(index.as_slice());
        let root_tree = store::put_object(ObjectType::Tree, &root);

        let commit = format!(
            "tree {}\nauthor a <a@a> 0 +0000\ncommitter a <a@a> 0 +0000\n\nmsg\n",
            store::oid_hex(&root_tree)
        );
        let commit_oid = store::put_object(ObjectType::Commit, commit.as_bytes());
        let branch = store::head_target("web").unwrap();
        store::set_ref("web", &branch, commit_oid).unwrap();

        // Not configured yet: 404.
        assert_eq!(serve("web", "").status_code, 404);
        set_config("web", String::new()).unwrap();

        // "" and "/" resolve to index.html; nested blob resolves; the commit
        // header binds every response to the tip.
        let res = serve("web", "");
        assert_eq!(res.status_code, 200);
        assert_eq!(res.body, b"<h1>hi</h1>");
        assert!(res
            .headers
            .iter()
            .any(|(k, v)| k == "X-Ic-Git-Commit" && *v == store::oid_hex(&commit_oid)));
        // The tree-path header names the actual blob, index fallback applied,
        // so `git show <commit>:<path>` reproduces the body.
        assert!(res
            .headers
            .iter()
            .any(|(k, v)| k == "X-Ic-Git-Path" && v == "index.html"));
        assert_eq!(serve("web", "app/main.js").body, b"console.log(1)");
        assert_eq!(serve("web", "missing.js").status_code, 404);

        // A root directory scopes the bundle: index.html no longer at "".
        set_config("web", "app".into()).unwrap();
        assert_eq!(serve("web", "main.js").status_code, 200);
        assert_eq!(serve("web", "").status_code, 404);
    }

    /// The two entrypoint shapes whose attested hash actually proves something:
    /// self-contained, or SRI-complete so the browser enforces the rest.
    #[test]
    fn accepts_self_contained_and_sri_complete_entrypoints() {
        for ok in [
            // Inline script and style are inside the attested bytes already.
            "<html><script>go()</script><style>b{}</style></html>",
            "<script src=\"app.js\" integrity=\"sha384-x\"></script>",
            // Bare and single-quoted attributes, uppercase tags, attribute
            // order, and a multi-token rel all still parse.
            "<SCRIPT SRC=app.js INTEGRITY=sha384-x></SCRIPT>",
            "<link integrity='sha384-x' rel='preload stylesheet' href='a.css'>",
            // rel values SRI does not enforce are not subresource execution
            // surfaces, so they need no integrity.
            "<link rel=\"icon\" href=\"favicon.ico\">",
            "<link rel=\"canonical\" href=\"https://example.com/\">",
            // Images and fonts are documented as out of scope.
            "<img src=\"logo.png\"><p>text</p>",
        ] {
            assert_eq!(
                unverifiable_subresource("index.html", ok.as_bytes()),
                None,
                "should accept: {ok}"
            );
        }
    }

    /// Every shape where the entrypoint hash would verify while unattested
    /// bytes went unchecked -- the false GREEN this guard exists to stop.
    #[test]
    fn refuses_entrypoints_whose_hash_would_not_prove_the_page() {
        for bad in [
            // The core case: honest index.html, unattested app.js.
            "<script src=\"app.js\"></script>",
            "<script src=\"https://cdn.example.com/a.js\"></script>",
            "<link rel=\"stylesheet\" href=\"app.css\">",
            "<link rel=\"modulepreload\" href=\"m.js\">",
            // SRI does not apply to these at all, so integrity= on them is a
            // promise nothing enforces -- refused even when it is present.
            "<iframe src=\"child.html\"></iframe>",
            "<object data=\"x.swf\"></object>",
            "<embed src=\"x.svg\">",
            "<iframe src=\"child.html\" integrity=\"sha384-x\"></iframe>",
            // A substring test would have accepted both of these.
            "<script src=\"app.js\" data-integrity=\"sha384-x\"></script>",
            "<script src=\"app.js\" integrity></script>",
            // Unparseable beats optimistic: never closed, so never checked.
            "<script src=\"app.js\"",
        ] {
            assert!(
                unverifiable_subresource("index.html", bad.as_bytes()).is_some(),
                "should refuse: {bad}"
            );
        }
        // Not UTF-8: the references cannot be read, so they cannot be cleared.
        assert!(unverifiable_subresource("index.html", &[0xff, 0xfe]).is_some());
    }

    /// The scan is HTML-only. A non-HTML entrypoint names no subresources, and
    /// a `<script` byte sequence inside one is data, not markup -- gating on it
    /// would refuse to attest artifacts that are perfectly verifiable.
    #[test]
    fn scan_applies_only_to_html_entrypoints() {
        let looks_like_markup = b"{\"a\":\"<script src=x>\"}";
        assert_eq!(
            unverifiable_subresource("data.json", looks_like_markup),
            None
        );
        assert_eq!(unverifiable_subresource("contract.hex", b"0x6001"), None);
        assert!(unverifiable_subresource("index.htm", looks_like_markup).is_some());
    }

    /// resolve_entry (what the registry publisher attests) returns the same
    /// tip, tree path, and bytes that serve returns as the response body.
    #[test]
    fn resolve_entry_matches_served_bytes() {
        store::create_repo("site2").unwrap();
        let index = store::put_object(ObjectType::Blob, b"<h1>site2</h1>");
        let mut root = Vec::new();
        root.extend_from_slice(b"100644 index.html\0");
        root.extend_from_slice(index.as_slice());
        let root_tree = store::put_object(ObjectType::Tree, &root);
        let commit = format!(
            "tree {}\nauthor a <a@a> 0 +0000\ncommitter a <a@a> 0 +0000\n\nmsg\n",
            store::oid_hex(&root_tree)
        );
        let commit_oid = store::put_object(ObjectType::Commit, commit.as_bytes());
        let branch = store::head_target("site2").unwrap();
        store::set_ref("site2", &branch, commit_oid).unwrap();

        // No site config: nothing to attest.
        assert!(resolve_entry("site2", "").is_none());
        set_config("site2", String::new()).unwrap();

        let (tip, served, body) = resolve_entry("site2", "").unwrap();
        assert_eq!(tip, commit_oid);
        assert_eq!(served, "index.html");
        assert_eq!(body, b"<h1>site2</h1>");
        // The attested bytes are exactly what the network serves.
        assert_eq!(serve("site2", "").body, body);
    }

    #[test]
    fn content_types_by_extension() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("a/b.wasm"), "application/wasm");
        assert_eq!(content_type("noext"), "application/octet-stream");
    }
}
