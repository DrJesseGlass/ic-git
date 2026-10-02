//! F0 (VISION.md section 2): serve a committed static bundle over
//! http_request.
//!
//! GET /site/<repo>/<path> resolves <path> within the tree of the repo's
//! served commit (under the configured root directory) and serves the blob.
//! The served commit is the deploy-branch tip when the repo requires no
//! votes, and otherwise the newest approved commit on that branch, which
//! `advance` records whenever the approvals change and the deploy queue is
//! sent the same commit: the site and the app follow the same approvals. The
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
        // A leading `=` is part of the name to the tokenizer, not a value
        // separator: `<a ='>...` is attribute `='` and the tag ends at `>`.
        if b[i] == b'=' {
            i += 1;
        }
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

/// Where a tag name starting at `from` ends as the tokenizer reads it: at
/// whitespace, `/` or `>`, so `<a"b='>` is one tag named `a"b='` and
/// `<script-x>` is not a script.
fn tag_name_end(b: &[u8], from: usize) -> usize {
    let mut e = from;
    while e < b.len() && !b[e].is_ascii_whitespace() && !matches!(b[e], b'/' | b'>') {
        e += 1;
    }
    e
}

/// Where a comment opened at `lt` ends (the offset just past it), as the
/// browser's tokenizer ends it: `<!-->` and `<!--->` close at once; any
/// other comment at the first `-->` or `--!>` after its `<!--`, whichever
/// comes first. `None`: it runs to the end of the document, so nothing after
/// it is markup.
fn comment_end(hay: &str, lt: usize) -> Option<usize> {
    let rest = &hay[lt..];
    if rest.starts_with("<!-->") {
        return Some(lt + 5);
    }
    if rest.starts_with("<!--->") {
        return Some(lt + 6);
    }
    [("-->", 3), ("--!>", 4)]
        .iter()
        .filter_map(|(m, n)| find_from(hay, m, lt + 4).map(|p| p + n))
        .min()
}

/// Offset of the end tag that closes raw-text element `tag` opened before
/// `from`: the first `</tag` followed by whitespace, `/` or `>` (the
/// tokenizer's "appropriate end tag"). `None` when there is none, and the
/// element would swallow the rest of the document.
fn raw_text_end(hay: &str, from: usize, tag: &str) -> Option<usize> {
    let close = format!("</{tag}");
    let b = hay.as_bytes();
    let mut at = from;
    loop {
        let p = find_from(hay, &close, at)?;
        match b.get(p + close.len()) {
            Some(c) if c.is_ascii_whitespace() || matches!(c, b'/' | b'>') => return Some(p),
            Some(_) => at = p + close.len(),
            None => return None,
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
/// Whether URL attribute `name` on `tag` runs script when followed: a
/// `javascript:` URL, which the pinned policy refuses (a hash matches no
/// URL). The browser decodes character references and drops every tab and
/// newline, and leading spaces and controls, before it reads the scheme; a
/// reference before the first `/`, `?` or `#` could spell one, so it is
/// refused rather than decoded -- query strings keep their `&`.
fn script_url(tag: &str, name: &str, value: &str) -> Option<String> {
    let head = value.find(['/', '?', '#']).unwrap_or(value.len());
    if value[..head].contains('&') {
        return Some(format!(
            "<{tag} {name}=...> holds a character reference where a URL scheme could be"
        ));
    }
    let cleaned: String = value.chars().filter(|c| !matches!(c, '\t' | '\n' | '\r')).collect();
    if cleaned.trim_start_matches(|c: char| c <= ' ').starts_with("javascript:") {
        return Some(format!(
            "<{tag} {name}=\"javascript:...\"> runs script from a URL, which the pinned policy refuses"
        ));
    }
    None
}

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
/// - What the extensions' pinned policy would refuse at run time
///   (docs/EXTENSION.md): it admits a page's own scripts and styles by hash
///   and nothing else, so a page holding these would publish and then be
///   stopped. Inline event handlers (`on...=`), `style=` attributes,
///   `javascript:` URLs, every external stylesheet (pinned or not: inline
///   it), `@import` in an inline `<style>`, and a `<script>` or `<style>`
///   inside `<svg>` or `<math>`, whose text is markup there and cannot be
///   hashed as the browser will read it.
///
/// A false refusal costs the operator one inline-or-add-integrity edit; a false
/// accept costs a user their funds. That asymmetry is the whole design.
/// Text the browser never parses as markup is not scanned, so an honest
/// page is not refused over strings in its own code: a comment is skipped to
/// where the tokenizer ends it, and the body of `<script>`, `<style>`,
/// `<textarea>`, `<title>`, `<xmp>`, `<noembed>`, `<noframes>` and
/// `<noscript>` is skipped to its end tag (a `<noscript>` body is also
/// scanned as a page of its own, which is how a browser with scripting off
/// reads it). Every skip ends no later than the browser's -- a script can end
/// later than its first `</script>` (a `<!--<script>` inside it defers the
/// end), never earlier -- so the scan covers at least what the browser
/// parses as markup, and a divergence can only over-refuse. That holds only
/// while the scan is in step with the tokenizer, so these skips are made
/// only in plain HTML content: in a page served as HTML (`.html`, `.htm`;
/// never SVG or XHTML, which are XML, where a script's `<` does open a tag
/// and CDATA, processing instructions and doctype subsets can hide a
/// `<!--`), before the first `<svg` or `<math` (foreign content: `<script>`
/// is ordinary markup there, `<script/>` closes itself, CDATA is text) and
/// before the first `<select` (whose legacy parser ignores `<style>` and
/// `<title>`, leaving their bodies markup); only on an exact tag name
/// (`<script-x>` is not a script); and with end tags tokenized attributes
/// and all, as the browser does. Elsewhere, and for other `<!` and `<?`
/// constructs, a skip runs only to the first `>` (never past anything the
/// browser would execute), so what follows may be rescanned and
/// over-refuse -- the safe direction to be wrong in.
///
/// NOT covered, stated rather than implied (the pinned policy refuses the
/// first two at run time, where the extensions' stop page names them):
/// - Workers (`new Worker(...)`) and an external module's import chain:
///   both are started by code, not markup.
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
    let ext = name.rsplit_once('.').map(|(_, ext)| ext);
    let ext_in = |set: &[&str]| ext.is_some_and(|x| set.iter().any(|e| x.eq_ignore_ascii_case(e)));
    if ext.is_some() && !ext_in(&["html", "htm", "xhtml", "svg"]) {
        return None;
    }
    // Plain HTML content, where the long skips are sound (see above): only a
    // page served as HTML (see content_type), until foreign content or a
    // select begins.
    let mut plain = ext_in(&["html", "htm"]);
    // Inside <svg> or <math>: a <script> or <style> there cannot be pinned.
    let mut foreign = false;
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
            // `</`, `<!`, `<?`: end tag, comment, doctype, or bogus comment.
            // An end tag's attributes are tokenized like a start tag's, so
            // `</p title="> <!--">` ends after its closing quote, not at the
            // first `>`. A comment in plain HTML ends where the tokenizer
            // ends it. Anything else executes nothing before its first `>`,
            // so skipping there never hides executable markup; what follows
            // may be rescanned and over-refuse. Any other byte is a stray `<`.
            i = if c == b'/' && b.get(lt + 2).is_some_and(u8::is_ascii_alphabetic) {
                match parse_tag(&hay, tag_name_end(b, lt + 2)) {
                    Some((_, gt)) => gt + 1,
                    None => break,
                }
            } else if plain && hay[lt..].starts_with("<!--") {
                match comment_end(&hay, lt) {
                    Some(end) => end,
                    None => break,
                }
            } else if matches!(c, b'/' | b'!' | b'?') {
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
        // `tag` is the alphanumeric prefix, so a check keyed on it also
        // catches `<script-x ...>` (over-refusing); a skip keys on `exact`.
        let tag = &hay[name_start..name_end];
        let full_end = tag_name_end(b, name_start);
        let exact = full_end == name_end;
        // Every element is tokenized to its real end, quoted values and all,
        // so an unchecked tag's attribute text is never rescanned as markup:
        // `<div title="<script src=x>">` is inert to the browser and must not
        // block attestation.
        let Some((attrs, end)) = parse_tag(&hay, full_end) else {
            return Some(format!("<{tag}> tag is never closed"));
        };
        i = end + 1;
        let get = |n: &str| attr(&attrs, n);
        // What the pinned policy refuses, on any element.
        for (n, _) in &attrs {
            if n.len() > 2 && n.starts_with("on") {
                return Some(format!(
                    "<{tag} {n}=...> is an inline event handler, which the pinned policy refuses; \
                     attach it from a script"
                ));
            }
        }
        if get("style").is_some() {
            return Some(format!(
                "<{tag} style=...> is an inline style attribute, which the pinned policy refuses; \
                 move it into a <style>"
            ));
        }
        for name in ["href", "xlink:href", "action", "formaction"] {
            if let Some(why) = get(name).and_then(|v| script_url(tag, name, v)) {
                return Some(why);
            }
        }
        if foreign && matches!(tag, "script" | "style") {
            return Some(format!(
                "<{tag}> inside <svg> or <math> cannot be pinned: its text is markup there"
            ));
        }
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
                let rels = || rel.split_ascii_whitespace();
                // The pinned policy pins styles by the hash of their text, and
                // Chrome takes no hash for an external stylesheet; a URL would
                // pin nothing once the markup can be altered.
                if get("href").is_some() && rels().any(|r| r == "stylesheet") {
                    return Some(format!(
                        "<link rel=\"{rel}\"> is an external stylesheet, which the pinned policy \
                         refuses; inline it as a <style>"
                    ));
                }
                if rels().any(|r| r == "modulepreload")
                    && get("href").is_some()
                    && !get("integrity").is_some_and(integrity_enforceable)
                {
                    return Some(format!("<link rel=\"{rel}\"> has no enforceable integrity="));
                }
            }
            "svg" | "math" => {
                plain = false;
                foreign = true;
            }
            "select" => plain = false,
            _ => {}
        }
        // Raw text: the browser reads everything to the end tag as text.
        if plain
            && exact
            && matches!(
                tag,
                "script" | "style" | "textarea" | "title" | "xmp" | "noembed" | "noframes"
                    | "noscript"
            )
        {
            let Some(end) = raw_text_end(&hay, i, tag) else {
                return Some(format!("<{tag}> is never closed"));
            };
            // An @import in a pinned inline style loads a stylesheet no hash
            // admits.
            if tag == "style" && hay[i..end].contains("@import") {
                return Some(
                    "<style> holds an @import, which the pinned policy refuses; inline what it imports"
                        .to_string(),
                );
            }
            if tag == "noscript" {
                // With scripting off the body is markup: scan it as a page of
                // its own. A comment there that is still open at the end tag
                // would run on past it, where this scan does not follow.
                let inner = &hay[i..end];
                if let Some(why) = unverifiable_subresource("noscript.html", inner.as_bytes()) {
                    return Some(why);
                }
                if inner.rfind("<!--").is_some_and(|p| comment_end(inner, p).is_none()) {
                    return Some("<noscript> holds a comment that runs past its end".to_string());
                }
                if ["<svg", "<math", "<select"].iter().any(|t| inner.contains(t)) {
                    plain = false;
                }
            }
            i = end;
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

/// The blob `serve` would return for `path`, given an already-resolved commit and
/// config: its tree location (site root prefix and index.html fallback
/// applied) and bytes. One walk from the root -- a blob serves directly; a
/// directory (including "" for the bundle root) serves the index.html inside.
fn resolve_blob(commit: &store::Oid, cfg: &SiteConfig, path: &str) -> Option<(String, Vec<u8>)> {
    let rel = path.trim_matches('/');
    let full = match (cfg.root.is_empty(), rel.is_empty()) {
        (true, _) => rel.to_string(),
        (false, true) => cfg.root.clone(),
        (false, false) => format!("{}/{rel}", cfg.root),
    };
    match object::node_at_path(commit, &full) {
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

/// How far back from the tip `advance` looks for the newest approved commit.
/// It runs in update calls (a vote, a push, a policy change), never in a
/// site request, so it can afford a long walk. Only commits the walk
/// reaches can be served, so this bound is also what an approved site
/// withstands: a writer would have to push this many unapproved commits on
/// top of it, each charged as a push, to take it down.
pub const APPROVAL_WALK: usize = 10_000;

/// What a votes-gated repo serves and deploys (META key `served:{repo}`).
/// Absent while the repo requires no votes. `commit` is `None` when no
/// commit is approved.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
struct Served {
    commit: Option<String>,
}

fn served_key(repo: &str) -> String {
    format!("served:{repo}")
}

fn required_votes(repo: &str) -> u32 {
    crate::tenancy::meta(repo).map_or(0, |m| m.required_votes)
}

/// Does the repo require votes, so that what it serves and deploys is the
/// recorded approved commit rather than the tip?
pub fn gated(repo: &str) -> bool {
    required_votes(repo) > 0
}

fn tip_of(repo: &str) -> Result<store::Oid, &'static str> {
    let branch = store::head_target(repo).ok_or("no such repo")?;
    store::get_ref(repo, &branch).ok_or("deploy branch has no commits")
}

/// Recompute what a repo serves after anything that can change it: a
/// ballot, the threshold, the voter set, the owner, or a push. Returns the
/// commit the app should now be deployed at, when that moved, so the caller
/// queues its deploy and the app follows the site.
///
/// With votes required: the newest commit within `APPROVAL_WALK` first
/// parents of the tip that has reached the threshold, and otherwise
/// nothing. Only a commit on the branch now qualifies: deleting the branch,
/// or replacing it with history the voters never approved, takes the site
/// down rather than leaving an off-branch commit live. First parents only:
/// approvals on history a merge brought in through its second parent are
/// not seen.
///
/// With no votes required the tip is served and deploys on push. Leaving
/// the gated regime returns the tip once, since pushes held for approval
/// never deployed it.
pub fn advance(repo: &str) -> Option<store::Oid> {
    let key = served_key(repo);
    let prev: Option<Served> = store::meta_get_json(&key);
    if required_votes(repo) == 0 {
        let prev = prev?;
        store::meta_set_json(&key, &Option::<Served>::None);
        let tip = tip_of(repo).ok()?;
        return (prev.commit != Some(store::oid_hex(&tip))).then_some(tip);
    }
    let prev = prev.unwrap_or_default();
    let next = tip_of(repo)
        .ok()
        .and_then(|tip| {
            let first_parents = std::iter::successors(Some(tip), |c| match store::get_object_parsed(c) {
                Some((ObjectType::Commit, body)) => object::commit_refs(&body)
                    .ok()
                    .and_then(|r| r.parents.first().copied()),
                _ => None,
            })
            .take(APPROVAL_WALK);
            crate::tenancy::first_approved(repo, first_parents)
        });
    let now = Served {
        commit: next.as_ref().map(store::oid_hex),
    };
    let moved = now.commit != prev.commit;
    store::meta_set_json(&key, &Some(now));
    next.filter(|_| moved)
}

fn recorded_if_approved(repo: &str, served: &Served) -> Option<store::Oid> {
    let oid = store::parse_oid(served.commit.as_deref()?).ok()?;
    crate::tenancy::first_approved(repo, std::iter::once(oid))
}

/// Record what every votes-gated repo serves. For post_upgrade: a repo that
/// set its threshold before `advance` existed has nothing recorded, and would
/// serve nothing until its next vote. Queues no deploys; the apps are left
/// where they are.
pub fn record_gated_repos() {
    for (repo, m) in store::repo_meta_all::<crate::tenancy::RepoMeta>() {
        if m.required_votes > 0 && store::meta_get_json::<Served>(&served_key(&repo)).is_none() {
            advance(&repo);
        }
    }
}

/// The commit a site serves. With no votes required (the default, and every
/// legacy repo) that is the deploy-branch tip. With votes required it is the
/// commit `advance` last recorded, re-checked against the current ballots on
/// every request so a withdrawn approval can never be served; an unapproved
/// push is not served, and the last approved commit stays up.
pub fn served_commit(repo: &str) -> Result<store::Oid, &'static str> {
    if required_votes(repo) == 0 {
        return tip_of(repo);
    }
    store::meta_get_json::<Served>(&served_key(repo))
        .and_then(|s| recorded_if_approved(repo, &s))
        .ok_or("no approved commit on the site branch")
}

/// What a verifier attests for `path` (site root when `path` is ""): the
/// served commit (`served_commit`), the served blob's tree location, and its
/// raw bytes -- exactly what `serve` would return as the body. `None` mirrors
/// the cases `serve` turns into a 404. Used by the registry publisher so the attested bytes are byte-
/// identical to what the network serves.
pub fn resolve_entry(repo: &str, path: &str) -> Option<(store::Oid, String, Vec<u8>)> {
    let cfg = get_config(repo)?;
    let commit = served_commit(repo).ok()?;
    let (served, body) = resolve_blob(&commit, &cfg, path)?;
    Some((commit, served, body))
}

/// GET /site/<repo>/<path>. `path` may be "", carry a trailing slash
/// (directory request), or name a blob.
pub fn serve(repo: &str, path: &str) -> HttpResponse {
    let Some(cfg) = get_config(repo) else {
        return plain(404, "no site configured for repo\n");
    };
    let commit = match served_commit(repo) {
        Ok(c) => c,
        Err(why) => return plain(404, &format!("{why}\n")),
    };

    let Some((served, body)) = resolve_blob(&commit, &cfg, path) else {
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
        .push(("X-Ic-Git-Commit".to_string(), store::oid_hex(&commit)));
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

    /// A fresh repo with an index.html commit per push, owned by `owner`.
    fn gated_repo(repo: &str, owner: u8) -> (candid::Principal, impl Fn(&[u8], Option<store::Oid>) -> store::Oid + '_) {
        use crate::tenancy;
        let owner = candid::Principal::from_slice(&[owner; 8]);
        tenancy::credit(&owner, 10_000_000_000);
        tenancy::create_repo(repo, &owner, false).unwrap();
        set_config(repo, String::new()).unwrap();
        let push = move |html: &[u8], parent: Option<store::Oid>| {
            let index = store::put_object(ObjectType::Blob, html);
            let mut root = Vec::new();
            root.extend_from_slice(b"100644 index.html\0");
            root.extend_from_slice(index.as_slice());
            let tree = store::put_object(ObjectType::Tree, &root);
            let parent = parent.map_or(String::new(), |p| format!("parent {}\n", store::oid_hex(&p)));
            let commit = format!("tree {}\n{parent}\n{}\n", store::oid_hex(&tree), html.len());
            let oid = store::put_object(ObjectType::Commit, commit.as_bytes());
            let branch = store::head_target(repo).unwrap();
            store::set_ref(repo, &branch, oid).unwrap();
            oid
        };
        (owner, push)
    }

    /// With votes required, a push is not served until it is approved; the
    /// site stays on the last approved commit, and `advance` hands the deploy
    /// queue each commit the site moves to, so the app follows the site.
    #[test]
    fn serves_and_deploys_the_newest_approved_commit() {
        use crate::tenancy;
        let (owner, push) = gated_repo("gated", 77);
        let vote = |c: &store::Oid, yes: bool| {
            tenancy::vote("gated", &owner, &store::oid_hex(c), yes).unwrap();
            advance("gated")
        };
        let served_by = |res: &HttpResponse| {
            res.headers
                .iter()
                .find(|(k, _)| k == "X-Ic-Git-Commit")
                .map(|(_, v)| v.clone())
        };

        // No votes required: the tip serves as soon as it is pushed, and
        // advance leaves deploys to the push path.
        let c1 = push(b"one", None);
        assert_eq!(serve("gated", "").body, b"one");
        assert_eq!(advance("gated"), None);

        // Votes required and nothing approved: nothing is served.
        tenancy::set_required_votes("gated", &owner, false, 1).unwrap();
        assert_eq!(advance("gated"), None);
        let res = serve("gated", "");
        assert_eq!(res.status_code, 404);
        assert!(String::from_utf8_lossy(&res.body).contains("no approved commit"));
        assert!(resolve_entry("gated", "").is_none());

        // Approving c1 serves it and deploys it.
        assert_eq!(vote(&c1, true), Some(c1));
        // c2 and c3 pushed on top: c1 stays up, nothing new deploys.
        let c2 = push(b"two", Some(c1));
        let c3 = push(b"three", Some(c2));
        assert_eq!(advance("gated"), None);
        let res = serve("gated", "");
        assert_eq!(res.body, b"one");
        assert_eq!(served_by(&res), Some(store::oid_hex(&c1)));
        assert_eq!(resolve_entry("gated", "").unwrap().0, c1);

        // Approving c2, below the tip, moves the site and the app to c2.
        assert_eq!(vote(&c2, true), Some(c2));
        assert_eq!(serve("gated", "").body, b"two");
        // Approving an older commit again moves nothing.
        assert_eq!(vote(&c1, true), None);

        // Approving the tip serves and deploys the tip.
        assert_eq!(vote(&c3, true), Some(c3));
        assert_eq!(serve("gated", "").body, b"three");
        assert_eq!(resolve_entry("gated", "").unwrap().0, c3);

        // A withdrawn approval rolls the site and the app back together.
        assert_eq!(vote(&c3, false), Some(c2));
        assert_eq!(serve("gated", "").body, b"two");

        // Dropping the threshold serves the tip and deploys it, once.
        tenancy::set_required_votes("gated", &owner, false, 0).unwrap();
        assert_eq!(advance("gated"), Some(c3));
        assert_eq!(serve("gated", "").body, b"three");
        assert_eq!(advance("gated"), None);
    }

    /// A served commit re-checks its approval on every request: a ballot
    /// withdrawn without an `advance` (which every canister entry point
    /// runs) still takes the commit down rather than serving it.
    #[test]
    fn a_recorded_commit_is_served_only_while_approved() {
        use crate::tenancy;
        let (owner, push) = gated_repo("recheck", 79);
        let c1 = push(b"one", None);
        tenancy::set_required_votes("recheck", &owner, false, 1).unwrap();
        tenancy::vote("recheck", &owner, &store::oid_hex(&c1), true).unwrap();
        advance("recheck");
        assert_eq!(serve("recheck", "").status_code, 200);
        tenancy::vote("recheck", &owner, &store::oid_hex(&c1), false).unwrap();
        assert_eq!(serve("recheck", "").status_code, 404);
    }

    /// Unapproved pushes on top of an approved commit keep it served for as
    /// long as the walk still reaches it: APPROVAL_WALK - 1 of them, and one
    /// more takes the site down.
    #[test]
    fn unapproved_pushes_bury_the_served_commit_only_past_the_walk() {
        use crate::tenancy;
        let (owner, push) = gated_repo("deep", 78);
        let c1 = push(b"approved", None);
        tenancy::set_required_votes("deep", &owner, false, 1).unwrap();
        tenancy::vote("deep", &owner, &store::oid_hex(&c1), true).unwrap();
        assert_eq!(advance("deep"), Some(c1));
        let mut tip = c1;
        for i in 0..APPROVAL_WALK - 1 {
            tip = push(format!("unapproved {i}").as_bytes(), Some(tip));
        }
        assert_eq!(advance("deep"), None);
        assert_eq!(served_commit("deep").unwrap(), c1);
        assert_eq!(serve("deep", "").body, b"approved");
        push(b"one too many", Some(tip));
        assert_eq!(advance("deep"), None);
        assert_eq!(serve("deep", "").status_code, 404);
    }

    /// The recorded commit must still be on the branch. Deleting the branch,
    /// or replacing it with history nobody approved, takes the site down; it
    /// does not leave the old approved commit live off the branch.
    #[test]
    fn an_approved_commit_off_the_branch_is_not_served() {
        use crate::tenancy;
        let (owner, push) = gated_repo("rewrite", 81);
        let c1 = push(b"approved", None);
        tenancy::set_required_votes("rewrite", &owner, false, 1).unwrap();
        tenancy::vote("rewrite", &owner, &store::oid_hex(&c1), true).unwrap();
        assert_eq!(advance("rewrite"), Some(c1));

        // Deleted branch.
        let branch = store::head_target("rewrite").unwrap();
        store::delete_ref("rewrite", &branch);
        assert_eq!(advance("rewrite"), None);
        assert_eq!(serve("rewrite", "").status_code, 404);

        // Recreated with unrelated, unapproved history.
        push(b"unrelated", None);
        assert_eq!(advance("rewrite"), None);
        assert_eq!(serve("rewrite", "").status_code, 404);

        // The approved commit back on the branch serves again.
        push(b"on top", Some(c1));
        assert_eq!(advance("rewrite"), Some(c1));
        assert_eq!(serve("rewrite", "").body, b"approved");
    }

    /// A repo gated before `advance` existed has nothing recorded; the
    /// upgrade hook records it so the site keeps serving.
    #[test]
    fn upgrade_records_repos_gated_before_advance() {
        use crate::tenancy;
        let (owner, push) = gated_repo("legacy-gated", 80);
        let c1 = push(b"one", None);
        tenancy::set_required_votes("legacy-gated", &owner, false, 1).unwrap();
        tenancy::vote("legacy-gated", &owner, &store::oid_hex(&c1), true).unwrap();
        assert_eq!(serve("legacy-gated", "").status_code, 404);
        record_gated_repos();
        assert_eq!(served_commit("legacy-gated").unwrap(), c1);
    }

    /// The repo browser is the first page ic-git serves about itself; it
    /// must pass the same gate every attested entrypoint passes. Test-only
    /// include: the page is not part of the wasm.
    #[test]
    fn repo_browser_page_is_verifiable() {
        let page = include_bytes!("../../../browser/index.html");
        assert_eq!(unverifiable_subresource("index.html", page), None);
    }

    /// The loader is published as a site record too (docs/LOADER.md), and its
    /// own JavaScript holds "<base href=" and "<script src=" as strings.
    #[test]
    fn loader_page_is_verifiable() {
        let page = include_bytes!("../../../loader/index.html");
        assert_eq!(unverifiable_subresource("index.html", page), None);
    }

    /// What the browser reads as text is not scanned as markup, in a page
    /// served as HTML.
    #[test]
    fn text_the_browser_never_parses_as_markup_is_not_scanned() {
        let ok = |page: &str| {
            assert_eq!(
                unverifiable_subresource("index.html", page.as_bytes()),
                None,
                "{page}"
            )
        };
        ok("<script>const s = '<base href=x>' + '<script src=y>';</script>");
        ok("<script src=a.js integrity=sha384-AAAA></script><script>'<iframe>'</script>");
        ok("<style>/* <link rel=stylesheet href=x> */</style>");
        ok("<title><base href=x></title>");
        ok("<textarea><meta http-equiv=refresh content=0></textarea>");
        ok("<SCRIPT>'<base href=x>'</Script >");
        // Only an appropriate end tag ends the body: `</scripts` is text.
        ok("<script>'</scripts><base href=x>'</script>");
        ok("<!-- a > <base href=x> -->");
        ok("<!-- <script src=x> --><p>after</p>");
        ok("<noscript>enable JavaScript</noscript><script>'<base href=x>'</script>");
        ok("<xmp><base href=x></xmp>");
    }

    /// Every skip ends no later than the browser's, and bodies are not
    /// skipped where the browser parses them as markup.
    #[test]
    fn skips_never_hide_what_the_browser_parses() {
        let refused = |path: &str, page: &str| {
            assert!(
                unverifiable_subresource(path, page.as_bytes()).is_some(),
                "{path}: {page}"
            )
        };
        // Comments end where the tokenizer ends them.
        refused("index.html", "<!-- x --!><base href=y>");
        refused("index.html", "<!--><base href=y>");
        refused("index.html", "<!---><base href=y>");
        refused("index.html", "<!-- a --> <base href=y> -->");
        // A script body ends at its first end tag; one the browser ends
        // later (double-escaped) is over-scanned, never under.
        refused("index.html", "<script>a</script><base href=y>");
        refused(
            "index.html",
            "<script><!--<script>x</script><base href=y></script>-->",
        );
        // A body with no end tag swallows the page: refused, not skipped.
        refused("index.html", "<script>'<base href=y>'");
        // Foreign content: <script> there is markup, <script/> self-closes.
        refused("index.html", "<svg><script/><base href=y></svg>");
        refused("index.html", "<svg></svg><script>'<base href=y>'</script>");
        refused("index.html", "<math><style><base href=y></style></math>");
        // XML documents parse a script's `<` as a tag.
        refused("page.svg", "<svg><script>'<base href=y>'</script></svg>");
        refused("page.xhtml", "<script>'<base href=y>'</script>");
        refused("page", "<script>'<base href=y>'</script>");
        // An end tag's quoted attribute holds its `>`: a `<!--` in it is not
        // a comment.
        refused("index.html", "<p></p title=\"> <!--\"><base href=y><!-- -->");
        // Every HTML raw-text element: a `<!--` in its body is text.
        refused("index.html", "<xmp><!--</xmp><base href=y>-->");
        refused("index.html", "<noembed><!--</noembed><base href=y>-->");
        refused("index.html", "<noframes><!--</noframes><base href=y>-->");
        refused("index.html", "<noscript><!--</noscript><base href=y>-->");
        refused("index.html", "<xmp><a title=\"</xmp><base href=y>\">");
        // With scripting off a noscript body is markup.
        refused("index.html", "<noscript><base href=y></noscript>");
        refused("index.html", "<noscript><!-- </noscript><a title=\" --><base href=y>\">");
        // Only the exact tag name is a raw-text element.
        refused("index.html", "<script-x><base href=y></script>");
        refused("index.html", "<title:x><base href=y></title>");
        // A legacy select parser ignores <style>, leaving its body markup.
        refused("index.html", "<select><style><base href=y></style></select>");
        // CDATA (foreign content) and processing instructions (XML) are not
        // comments, and may hold a `<!--` and a `>`.
        refused("index.html", "<svg><![CDATA[ a > <!-- ]]><base href=y> -->");
        refused("page.svg", "<?pi > <!-- ?><script href=\"y\"/><!-- -->");
        // The tokenizer's tag name runs to whitespace, `/` or `>`, and a
        // leading `=` starts an attribute name: neither opens a quote.
        refused("index.html", "<a\"b='><base href=y>'>");
        refused("index.html", "<a ='><base href=y>'>");
    }

    /// What the extensions' pinned policy refuses at run time is refused at
    /// publish too, so a page that publishes is a page they run -- and the
    /// look-alikes that are honest still pass.
    #[test]
    fn refuses_what_the_pinned_policy_refuses() {
        for bad in [
            "<button onclick=\"go()\">go</button>",
            "<svg><circle ONLOAD=\"x()\"/></svg>",
            "<body onload=go()>",
            "<p style=\"color: red\">x</p>",
            "<a href=\"javascript:go()\">x</a>",
            "<a href=\"  JavaScript:go()\">x</a>",
            "<a href=\"java\tscript:go()\">x</a>",
            "<a href=\"&#106;avascript:go()\">x</a>",
            "<form action=\"javascript:go()\"></form>",
            "<button formaction=\"javascript:go()\">x</button>",
            "<svg><a xlink:href=\"javascript:go()\"><text>x</text></a></svg>",
            "<link rel=\"stylesheet\" href=\"a.css\" integrity=\"sha384-abc\">",
            "<link rel=\"alternate stylesheet\" href=\"b.css\" integrity=\"sha384-abc\">",
            "<svg><script>x()</script></svg>",
            "<math><style>a{}</style></math>",
            "<style>@import url(a.css); b{}</style>",
            // Over-refused on purpose: any attribute named on... counts as a
            // handler, since browsers keep adding event names and a list
            // would fall behind; an honest one is a rename away.
            "<div one=\"y\">x</div>",
        ] {
            assert!(
                unverifiable_subresource("index.html", bad.as_bytes()).is_some(),
                "should refuse: {bad}"
            );
        }
        for ok in [
            "<details open><summary>x</summary></details>",
            "<div data-on=\"x\">x</div>",
            "<a href=\"/search?a=1&amp;b=2\">x</a>",
            "<a href=\"https://example.com/javascript:not-a-scheme\">x</a>",
            "<form action=\"/go\"><button formaction=\"/other\">x</button></form>",
            "<style>b { color: red }</style>",
            "<svg><path d=\"M0 0\"/></svg><p>after</p>",
        ] {
            assert_eq!(
                unverifiable_subresource("index.html", ok.as_bytes()),
                None,
                "should accept: {ok}"
            );
        }
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
            "<link integrity='sha384-x' rel='preload modulepreload' href='m.js'>",
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
