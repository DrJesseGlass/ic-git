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

/// One tag's attributes, tokenized the way the browser's tokenizer does it,
/// because every divergence from that tokenizer fails open: a new attribute
/// may begin after whitespace, a `/`, or a closing quote (so `<script/src=a>`
/// and `<script data-x="y"src=a>` both carry `src`); quotes delimit a value
/// only immediately after `=` and are literal bytes anywhere else (so
/// `alt=it's` opens nothing); an unquoted value ends at whitespace or `>`.
/// Attribute lookups take the FIRST occurrence of a name, which is also the
/// one the browser keeps. Returns the attributes and the offset of the
/// closing `>`, or `None` if the tag never closes.
///
/// "Whitespace" throughout is `u8::is_ascii_whitespace`, which is exactly the
/// HTML tokenizer's set -- TAB, LF, FF, CR, SPACE, and NOT vertical tab
/// (0x0B). The match matters: a VT inside an unquoted value stays inside the
/// value for the browser, so `src=x\x0Bintegrity=y` carries no integrity
/// attribute and must not be read as one (there is a test pinning this, and
/// the verify.mjs port's isWs must keep the same five characters).
fn parse_tag(hay: &str, from: usize) -> Option<(Vec<(&str, &str)>, usize)> {
    let b = hay.as_bytes();
    let mut attrs = Vec::new();
    let mut i = from;
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        if b[i] == b'>' {
            return Some((attrs, i));
        }
        let name_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'/' | b'=' | b'>') {
            i += 1;
        }
        let name = &hay[name_start..i];
        let mut j = i;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < b.len() && b[j] == b'=' {
            j += 1;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j >= b.len() {
                return None;
            }
            let value = match b[j] {
                q @ (b'"' | b'\'') => {
                    let vs = j + 1;
                    let ve = find_from(hay, if q == b'"' { "\"" } else { "'" }, vs)?;
                    j = ve + 1;
                    &hay[vs..ve]
                }
                _ => {
                    let vs = j;
                    while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'>' {
                        j += 1;
                    }
                    &hay[vs..j]
                }
            };
            attrs.push((name, value));
            i = j;
        } else {
            attrs.push((name, ""));
        }
    }
}

/// First (the browser's winner) value of attribute `name`.
fn attr<'a>(attrs: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    attrs.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// True when an `integrity` value holds at least one token the SRI spec
/// recognizes: `sha256-`/`sha384-`/`sha512-` plus base64, options after `?`.
/// Presence of the attribute proves nothing -- the spec makes the browser
/// IGNORE metadata that parses to an empty set, so `integrity=""` or a
/// malformed value loads the resource with no check at all.
///
/// A token counts only if the browser's grammar would KEEP it. The CSP
/// base64-value grammar is `1*(ALPHA/DIGIT/"+"/"/"/"-"/"_") *2("=")` --
/// padding is trailing only, two at most, never the whole value -- so
/// `sha384-====` fails it, the browser discards the metadata, and the
/// resource loads unchecked. This check is a strict SUBSET of that grammar
/// (the base64url chars `-`/`_` are refused too): a token we keep and the
/// browser discards is a false accept, while a token we discard and the
/// browser keeps merely fails closed at digest time -- the browser blocks
/// the load -- so tightness costs nothing.
fn integrity_enforceable(value: &str) -> bool {
    value.split_ascii_whitespace().any(|tok| {
        ["sha256-", "sha384-", "sha512-"]
            .iter()
            .find_map(|p| tok.strip_prefix(p))
            .and_then(|rest| rest.split('?').next())
            .is_some_and(|h| {
                let body = h.trim_end_matches('=');
                !body.is_empty()
                    && h.len() - body.len() <= 2
                    && body
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/'))
            })
    })
}

/// Guard for values compared against keywords: the browser decodes character
/// references in attribute values and this scanner does not, so to the
/// browser `rel="style&#115;heet"` IS a stylesheet. A `&` in a value a
/// decision keys on is refused rather than compared wrong; no keyword value
/// (`rel`, `type`, `http-equiv`) legitimately contains one.
fn char_ref_free<'a>(tag: &str, name: &str, value: &'a str) -> Result<&'a str, String> {
    if value.contains('&') {
        Err(format!(
            "<{tag} {name}=...> value holds a character reference this scanner does not decode"
        ))
    } else {
        Ok(value)
    }
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
/// - `<script src>` and `<link rel=stylesheet|modulepreload>` need an
///   `integrity` value the SRI spec actually parses -- presence alone leaves
///   the browser loading the file unchecked.
/// - `<iframe>`, `<object>`, `<embed>` have no SRI mechanism for anything they
///   load (src, data, srcdoc), so they can never be made verifiable and are
///   refused outright, whatever their attributes.
/// - `<base href>` and `<meta http-equiv=refresh>` relocate the page or its
///   relative URLs to bytes no record attests, and are refused for the same
///   reason.
/// - SVG-form `<script href>` / `xlink:href` executes with no SRI coverage;
///   an inline `<script type=module>` imports files no integrity can pin.
/// - A tag that never closes, a keyword value hiding behind a character
///   reference, or a body that is not UTF-8, is refused rather than skipped.
/// A false refusal costs the operator one inline-or-add-integrity edit; a false
/// accept costs a user their funds. That asymmetry is the whole design.
/// Comments get no full tracking: `<!` constructs are skipped only to their
/// first `>` (never past anything the browser would execute), so trailing
/// comment text can be rescanned as markup and over-refuse -- the safe
/// direction to be wrong in.
///
/// NOT covered, stated rather than implied:
/// - Images, fonts, and media. SRI has no mechanism for them, so refusing them
///   would reject every real site. They cannot execute; a swapped image can
///   mislead the eye but not the machine.
/// - What attested or SRI-pinned JavaScript does at runtime. A markup scan
///   cannot follow `fetch()`, dynamic `import()`, or the import chain of an
///   integrity-pinned external module (import specifiers take no integrity);
///   those loads are issued by code the record or SRI already covers, and
///   auditing that code is the operator's job, not this scanner's.
pub fn unverifiable_subresource(served_path: &str, body: &[u8]) -> Option<String> {
    // Gate on the entrypoint's file NAME, case-insensitively -- `index.HTML`
    // renders exactly like `index.html`. `set_site` can also point the root
    // at a blob directly; when that name has no extension at all there is no
    // evidence it is not a page, so scan rather than skip. Known non-markup
    // extensions stay exempt: a JSON or hex artifact holding "<script" as
    // data is verifiable as-is (see tests).
    let name = served_path.rsplit('/').next().unwrap_or(served_path);
    let markup = match name.rsplit_once('.') {
        Some((_, ext)) => ["html", "htm", "xhtml", "svg"]
            .iter()
            .any(|e| ext.eq_ignore_ascii_case(e)),
        None => true,
    };
    if !markup {
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
        let Some(&c) = b.get(lt + 1) else { break };
        if !c.is_ascii_alphabetic() {
            // `</`, `<!`, `<?`: closing tag, comment, doctype, or bogus
            // comment. Nothing inside one executes before its first `>` (a
            // real comment runs at least to the `>` of `-->`), so skipping
            // there never hides executable markup; what follows may be
            // rescanned and over-refuse. Any other byte is a stray `<`.
            i = if matches!(c, b'/' | b'!' | b'?') {
                match find_from(&hay, ">", lt + 1) {
                    Some(gt) => gt + 1,
                    None => break,
                }
            } else {
                lt + 1
            };
            continue;
        }
        let name_start = lt + 1;
        let mut name_end = name_start;
        while name_end < b.len() && b[name_end].is_ascii_alphanumeric() {
            name_end += 1;
        }
        let tag = &hay[name_start..name_end];
        // Every element is tokenized to its real end, quoted values and all,
        // so an unchecked tag's attribute text is never rescanned as markup:
        // `<div title="<script src=x>">` is inert to the browser and must not
        // block attestation.
        let Some((attrs, end)) = parse_tag(&hay, name_end) else {
            return Some(format!("<{tag}> tag is never closed"));
        };
        i = end + 1;
        let get = |n: &str| attr(&attrs, n);
        match tag {
            // No SRI mechanism exists for anything these load -- src, data,
            // or a whole srcdoc document -- so integrity= on them is a
            // promise nothing enforces. Refused outright.
            "iframe" | "object" | "embed" => {
                return Some(format!(
                    "<{tag}> loads content SRI cannot cover; inline the content instead"
                ));
            }
            // Re-roots every relative URL on the page, so each subresource
            // resolves to bytes no record attests.
            "base" => {
                if get("href").is_some() {
                    return Some(
                        "<base href=...> relocates every relative URL on the page".to_string(),
                    );
                }
            }
            "meta" => {
                if let Some(v) = get("http-equiv") {
                    let v = match char_ref_free(tag, "http-equiv", v) {
                        Ok(v) => v,
                        Err(why) => return Some(why),
                    };
                    if v.trim() == "refresh" {
                        return Some(
                            "<meta http-equiv=refresh> navigates away from the attested page"
                                .to_string(),
                        );
                    }
                }
            }
            "script" => {
                // The SVG form loads and executes via href/xlink:href, which
                // SRI does not cover at all.
                if get("href").is_some() || get("xlink:href").is_some() {
                    return Some(
                        "<script href=...> (SVG form) loads a subresource SRI cannot cover"
                            .to_string(),
                    );
                }
                if get("src").is_some() {
                    if !get("integrity").is_some_and(integrity_enforceable) {
                        return Some(
                            "<script src=...> has no enforceable integrity= \
                             (missing, empty, or not sha256/384/512-base64)"
                                .to_string(),
                        );
                    }
                } else if let Some(t) = get("type") {
                    let t = match char_ref_free(tag, "type", t) {
                        Ok(t) => t,
                        Err(why) => return Some(why),
                    };
                    // An inline module's import statements fetch files SRI
                    // cannot pin, from inside the attested bytes.
                    if t.trim() == "module" {
                        return Some(
                            "inline <script type=module> imports files SRI cannot cover; \
                             use a classic inline script or src= with integrity="
                                .to_string(),
                        );
                    }
                }
            }
            "link" => {
                let rel = match char_ref_free(tag, "rel", get("rel").unwrap_or("")) {
                    Ok(rel) => rel,
                    Err(why) => return Some(why),
                };
                let enforced = rel
                    .split_ascii_whitespace()
                    .any(|r| matches!(r, "stylesheet" | "modulepreload"));
                if enforced
                    && get("href").is_some()
                    && !get("integrity").is_some_and(integrity_enforceable)
                {
                    return Some(format!("<link rel=\"{rel}\"> has no enforceable integrity="));
                }
            }
            _ => {}
        }
    }
    None
}

fn content_type(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
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

    /// The repo browser is the first page ic-git serves about itself; it
    /// must pass the same gate every attested entrypoint passes. Test-only
    /// include: the page is not part of the wasm.
    #[test]
    fn repo_browser_page_is_verifiable() {
        let page = include_bytes!("../../../browser/index.html");
        assert_eq!(unverifiable_subresource("index.html", page), None);
    }

    /// The two entrypoint shapes whose attested hash actually proves something:
    /// self-contained, or SRI-complete so the browser enforces the rest.
    #[test]
    fn accepts_self_contained_and_sri_complete_entrypoints() {
        for ok in [
            // Inline script and style are inside the attested bytes already.
            "<html><script>go()</script><style>b{}</style></html>",
            "<script src=\"app.js\" integrity=\"sha384-x\"></script>",
            // Trailing base64 padding is part of the grammar the browser keeps.
            "<script src=\"app.js\" integrity=\"sha384-abc==\"></script>",
            // Bare and single-quoted attributes, uppercase tags, attribute
            // order, and a multi-token rel all still parse.
            "<SCRIPT SRC=app.js INTEGRITY=sha384-x></SCRIPT>",
            "<link integrity='sha384-x' rel='preload stylesheet' href='a.css'>",
            // An SRI-pinned external module is enforced at the top; its import
            // chain is documented as out of the scanner's reach.
            "<script type=\"module\" src=\"m.js\" integrity=\"sha384-abc\"></script>",
            // rel values SRI does not enforce are not subresource execution
            // surfaces, so they need no integrity.
            "<link rel=\"icon\" href=\"favicon.ico\">",
            "<link rel=\"canonical\" href=\"https://example.com/\">",
            // Images and fonts are documented as out of scope.
            "<img src=\"logo.png\"><p>text</p>",
            // Markup sitting inside an unchecked tag's quoted value is inert
            // to the browser and must not block attestation.
            "<div title=\"<script src=x>\">inert</div>",
            // An apostrophe in an unquoted value is a literal byte, not an
            // open quote; the tags after it must still be seen (and this page
            // has nothing to refuse).
            "<img alt=it's src=logo.png><p>fine</p>",
            // meta/base are only refused in their page-relocating forms.
            "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"w\">",
            "<base target=\"_blank\">",
            // Comment content the browser never executes is not refused.
            "<!-- <script src=x> --><p>ok</p>",
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
            // The browser starts a new attribute after `/` and after a
            // closing quote -- both of these DO carry src.
            "<script/src=app.js></script>",
            "<script data-x=\"y\"src=app.js></script>",
            // integrity= inside another attribute's value is not an attribute.
            "<script data-x=\"y integrity=sha384-q\" src=app.js></script>",
            // An unquoted apostrophe must not swallow the tags after it.
            "<img alt=it's><script src=app.js></script>",
            // SRI does not apply to these at all, so integrity= on them is a
            // promise nothing enforces -- refused even when it is present,
            // and srcdoc (a whole inline document) is refused with them.
            "<iframe src=\"child.html\"></iframe>",
            "<object data=\"x.swf\"></object>",
            "<embed src=\"x.svg\">",
            "<iframe src=\"child.html\" integrity=\"sha384-x\"></iframe>",
            "<iframe srcdoc=\"<p>hi</p>\"></iframe>",
            // Page-relocating tags: same reason iframe is refused.
            "<base href=\"https://evil.example/\">",
            "<meta http-equiv=\"refresh\" content=\"0;url=https://x/\">",
            // The SVG script form has no SRI coverage at all.
            "<svg><script href=\"x.js\"></script></svg>",
            "<svg><script xlink:href=\"x.js\"/></svg>",
            // An inline module imports files nothing can pin.
            "<script type=\"module\">import './app.js'</script>",
            // A substring test would have accepted both of these.
            "<script src=\"app.js\" data-integrity=\"sha384-x\"></script>",
            "<script src=\"app.js\" integrity></script>",
            // Present but unenforceable: the SRI spec makes the browser load
            // these with no check at all.
            "<script src=\"app.js\" integrity=\"\"></script>",
            "<script src=\"app.js\" integrity=\"sha384-\"></script>",
            "<script src=\"app.js\" integrity=\"lol\"></script>",
            "<link rel=\"stylesheet\" href=\"a.css\" integrity=\"md5-x\">",
            // Grammar-invalid base64: padding must be trailing, two at most,
            // never the whole value -- the browser discards each of these.
            "<script src=\"app.js\" integrity=\"sha384-====\"></script>",
            "<script src=\"app.js\" integrity=\"sha384-ab=c\"></script>",
            "<script src=\"app.js\" integrity=\"sha384-abc===\"></script>",
            // Vertical tab is NOT whitespace to the HTML tokenizer: the VT
            // stays inside the unquoted src value, so this tag carries no
            // integrity attribute at all.
            "<script src=x\u{0B}integrity=sha384-x></script>",
            // The browser decodes character references in values; we do not,
            // so a keyword hiding behind one is refused, not compared wrong.
            "<link rel=\"style&#115;heet\" href=\"a.css\">",
            // Unparseable beats optimistic: never closed, so never checked.
            "<script src=\"app.js\"",
            "<div class=\"x",
        ] {
            assert!(
                unverifiable_subresource("index.html", bad.as_bytes()).is_some(),
                "should refuse: {bad}"
            );
        }
        // Not UTF-8: the references cannot be read, so they cannot be cleared.
        assert!(unverifiable_subresource("index.html", &[0xff, 0xfe]).is_some());
    }

    /// The scan gates on the served file's NAME: markup extensions in any
    /// case, and extensionless blobs (set_site can point the root straight at
    /// one, and nothing proves those are not pages). A known non-markup
    /// extension is exempt -- a `<script` byte sequence inside JSON or hex is
    /// data, not markup, and gating on it would refuse artifacts that are
    /// perfectly verifiable.
    #[test]
    fn scan_gates_on_served_name_not_exact_extension() {
        let looks_like_markup = b"{\"a\":\"<script src=x>\"}";
        assert_eq!(
            unverifiable_subresource("data.json", looks_like_markup),
            None
        );
        assert_eq!(unverifiable_subresource("contract.hex", b"0x6001"), None);
        assert!(unverifiable_subresource("index.htm", looks_like_markup).is_some());
        // Case must not open a hole: app.HTML renders exactly like app.html.
        assert!(unverifiable_subresource("app.HTML", looks_like_markup).is_some());
        // Extensionless entrypoint: no evidence it is not a page, so scanned.
        assert!(unverifiable_subresource("entry", looks_like_markup).is_some());
        // The dot in a directory name is not an extension.
        assert!(unverifiable_subresource("v1.2/entry", looks_like_markup).is_some());
        // SVG documents execute scripts too.
        assert!(unverifiable_subresource("logo.svg", b"<script href=x></script>").is_some());
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
