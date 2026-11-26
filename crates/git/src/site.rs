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
//! Every answer here is certified (certify.rs): the IC's gateway at a
//! non-raw host passes it with the subnet's certificate over its bytes,
//! and the raw host passes it as before, where the clients verify by hash
//! (the F2 story). One URL, one answer: `served` takes a bare blob path or
//! a directory with or without its trailing slash, and anything else is
//! the site's one miss, so the certified set is exactly the bundle. Blobs
//! above the single-response cap are rejected rather than streamed.

use crate::object;
use crate::store::{self, ObjectType};
use candid::CandidType;
use core::ops::Range;
use ic_dev_kit_rs::http::HttpResponse;
use serde::{Deserialize, Serialize};

/// Per-repo site config (META key `site:{repo}`). Existence turns serving on.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SiteConfig {
    /// Directory within the repo tree the bundle is served from; "" = root.
    pub root: String,
    /// The site's own domains (docs/TENANCY.md, "Custom domains"): a
    /// request whose Host is one of them is the site, from its root. Each
    /// is held by one repo; `check_domain` says what one may be. A config
    /// stored before the field has none.
    #[serde(default)]
    pub domains: Vec<String>,
}

fn site_key(repo: &str) -> String {
    format!("site:{repo}")
}

const SITE_PREFIX: &str = "site:";

/// Turn serving on from `root`. The domains, if any, stay as they are.
pub fn set_config(repo: &str, root: String) -> Result<(), String> {
    if !store::repo_exists(repo) {
        return Err(format!("no such repo: {repo}"));
    }
    ic_git_types::deploy::check_config_path("a site's root", &root)?;
    let root = root.trim_matches('/').to_string();
    let domains = get_config(repo).map(|c| c.domains).unwrap_or_default();
    crate::kv::set_json(&site_key(repo), &SiteConfig { root, domains });
    crate::certify::site_changed(repo);
    Ok(())
}

#[cfg(test)]
pub(crate) fn clear_config_for_tests(repo: &str) {
    crate::kv::remove(&site_key(repo));
}

pub fn get_config(repo: &str) -> Option<SiteConfig> {
    crate::kv::get_json(&site_key(repo))
}

/// How many domains one site may have.
pub const MAX_DOMAINS: usize = ic_git_types::git_side::MAX_SITE_DOMAINS;

/// The IC's own domains, under which a host names a canister by its id,
/// and the local one. No site's domain is under them. The list is what
/// the gateways answered at when it was written, and they add to it
/// (`icp.net` came after the first six), so `check_domain` also refuses
/// any name with a canister id for a label, whatever it is under.
const RESERVED: [&str; 8] = ["icp0.io", "ic0.app", "icp-api.io", "icp1.io", "icp2.io", "icp.net", "internetcomputer.org", "localhost"];

/// A domain a site may be served at: a DNS name as it would be looked up
/// (lowercase, no trailing dot), of at least two labels, that is no IP
/// address, is under none of `RESERVED`, and has no label that is a
/// principal as text, alone or after a `--` (a gateway drops what is
/// before the last one, so `x--<id>` names the canister as `<id>` does):
/// a host with one is how a gateway names a canister, this one included,
/// and a site that held it would be served in the canister's place there.
pub fn check_domain(d: &str) -> Result<(), String> {
    if d.len() > 253 {
        return Err("a domain is at most 253 characters".to_string());
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return Err(format!("{d:?} is not a domain: it has one label"));
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 {
            return Err(format!("{d:?} is not a domain: a label is empty or longer than 63 characters"));
        }
        if !l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return Err(format!("{d:?} is not a domain as looked up: lowercase letters, digits and hyphens only"));
        }
        if l.starts_with('-') || l.ends_with('-') {
            return Err(format!("{d:?} is not a domain: a label starts or ends with a hyphen"));
        }
    }
    if labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return Err(format!("{d:?} is an IP address, not a domain"));
    }
    if RESERVED.iter().any(|r| d == *r || d.strip_suffix(r).is_some_and(|rest| rest.ends_with('.'))) {
        return Err(format!("{d:?} is under one of the IC's own domains, where a host names a canister by its id"));
    }
    let ids = labels.iter().filter_map(|l| l.rsplit("--").next());
    if let Some(id) = ids.into_iter().find(|id| candid::Principal::from_text(id).is_ok()) {
        return Err(format!("{d:?} has a canister id for a label ({id}): such a host names a canister, and is no site's domain"));
    }
    Ok(())
}

/// Name the site's domains, replacing what it had: the whole list, so a
/// lost answer is settled by asking again, and an empty one takes the site
/// off every domain. A domain another repo holds is refused until that
/// repo gives it up (an operator may, on any repo). The site must be
/// configured already: naming a domain does not turn serving on.
///
/// The work is bounded by the limit and not by the list: a list longer
/// than `MAX_DOMAINS` is refused before anything is read (a repeat
/// counts), the names are checked before any other site's config is
/// read, the configs are walked once for all of them, and a list that is
/// what the site has already changes and certifies nothing. Until
/// 2026-11 the limit was checked last, after a walk of every site config
/// for each element of a list of any length.
pub fn set_domains(repo: &str, domains: Vec<String>) -> Result<(), String> {
    let Some(mut cfg) = get_config(repo) else {
        return Err(if store::repo_exists(repo) {
            format!("no site configured for {repo}: set_site first")
        } else {
            format!("no such repo: {repo}")
        });
    };
    if domains.len() > MAX_DOMAINS {
        return Err(format!("a site has at most {MAX_DOMAINS} domains"));
    }
    let mut names: Vec<String> = Vec::new();
    for d in domains {
        let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
        check_domain(&d)?;
        if !names.contains(&d) {
            names.push(d);
        }
    }
    if names == cfg.domains {
        return Ok(());
    }
    if !names.is_empty() {
        for (holder, other) in all_configs() {
            if holder == repo {
                continue;
            }
            if let Some(d) = names.iter().find(|d| other.domains.contains(d)) {
                return Err(format!("{d:?} is held by {holder}; it must be given up there first"));
            }
        }
    }
    cfg.domains = names;
    crate::kv::set_json(&site_key(repo), &cfg);
    // The domains file, and the site's entries at its domains.
    crate::certify::domains_changed();
    crate::certify::site_changed(repo);
    Ok(())
}

/// Every site config, by repo.
pub(crate) fn all_configs() -> Vec<(String, SiteConfig)> {
    crate::kv::keys_with_prefix(SITE_PREFIX)
        .into_iter()
        .filter_map(|k| crate::kv::get_json(&k).map(|c| (k[SITE_PREFIX.len()..].to_string(), c)))
        .collect()
}

/// The repo whose site holds this domain (a name as `check_domain` takes
/// it). A walk of the site configs: there are few, and only a request on
/// a domain makes it.
pub fn repo_for_domain(domain: &str) -> Option<String> {
    all_configs()
        .into_iter()
        .find(|(_, c)| c.domains.iter().any(|d| d == domain))
        .map(|(repo, _)| repo)
}

/// A Host header as a domain: lowercase, without a port or a trailing dot.
/// An IPv6 literal is kept whole, brackets and all, and is no domain.
pub(crate) fn host_name(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    if host.starts_with('[') {
        return host;
    }
    let name = match host.rsplit_once(':') {
        Some((n, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => n,
        _ => host.as_str(),
    };
    name.trim_end_matches('.').to_string()
}

/// The repo whose site a request is for, by its Host: one of the site's
/// domains. A host that could not be a domain (`check_domain`: a gateway
/// host naming a canister by its id, the local one, an IP) is nobody's,
/// without a walk.
pub fn repo_for_host(host: Option<&str>) -> Option<String> {
    let name = host_name(host?);
    check_domain(&name).ok()?;
    repo_for_domain(&name)
}

/// `/.well-known/ic-domains`: every domain any site here is served at, one
/// per line, sorted. The IC's boundary nodes read it when a domain is
/// registered for this canister, and refuse one it does not list.
pub fn domains_file() -> String {
    let mut all: Vec<String> = all_configs().into_iter().flat_map(|(_, c)| c.domains).collect();
    all.sort();
    all.dedup();
    all.into_iter().map(|d| d + "\n").collect()
}

/// GET /.well-known/ic-domains, as certified (certify.rs).
pub fn domains_response() -> HttpResponse {
    expressed(crate::git_response(200, "text/plain", domains_file().into_bytes()))
}

/// GET /, the canister's index: its name and its repos, one per line.
/// Certified beside a domain's root when a site has a domain
/// (certify.rs, the shadows), so it is one function's answer.
pub fn index_response() -> HttpResponse {
    let repos = store::list_repos().join("\n");
    expressed(crate::git_response(200, "text/plain", format!("ic-git\n\nrepos:\n{repos}\n").into_bytes()))
}

/// The canister's 404 for a path that is nothing of it. Certified beside
/// a domain's pages (certify.rs, the shadows), so it is one function's
/// answer.
pub fn not_found() -> HttpResponse {
    expressed(crate::git_response(404, "text/plain", b"not found\n".to_vec()))
}

/// With the header that names what its certificate covers (certify.rs):
/// on every answer of `serve` and on the pages beside it, before any is
/// hashed.
fn expressed(mut res: HttpResponse) -> HttpResponse {
    res.headers.push(crate::certify::expression_header());
    res
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

/// One tag, as the browser's tokenizer reads it.
struct Tag<'a> {
    /// Each attribute's name, and where its value lies in the page, so the
    /// value can be read lowercased or as written.
    attrs: Vec<(&'a str, Range<usize>)>,
    /// Offset of the closing `>`.
    end: usize,
    /// A `/` right before the `>`, outside an unquoted value.
    self_closing: bool,
}

impl Tag<'_> {
    /// Where the value of attribute `name` lies: its FIRST occurrence, which
    /// is also the one the browser keeps.
    fn value(&self, name: &str) -> Option<Range<usize>> {
        self.attrs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone())
    }
}

/// One tag's attributes, tokenized the way the browser's tokenizer does it,
/// because every divergence from that tokenizer fails open: a new attribute
/// may begin after whitespace, a `/`, or a closing quote (so `<script/src=a>`
/// and `<script data-x="y"src=a>` both carry `src`); quotes delimit a value
/// only immediately after `=` and are literal bytes anywhere else (so
/// `alt=it's` opens nothing); an unquoted value ends at whitespace or `>`.
/// `None` if the tag never closes.
///
/// "Whitespace" throughout is `u8::is_ascii_whitespace`, which is exactly the
/// HTML tokenizer's set -- TAB, LF, FF, CR, SPACE, and NOT vertical tab
/// (0x0B). The match matters: a VT inside an unquoted value stays inside the
/// value for the browser, so `src=x\x0Bintegrity=y` carries no integrity
/// attribute and must not be read as one (there is a test pinning this, and
/// the JS port's isWs must keep the same five characters).
fn parse_tag(hay: &str, from: usize) -> Option<Tag<'_>> {
    let b = hay.as_bytes();
    let mut attrs = Vec::new();
    let mut i = from;
    loop {
        let mut self_closing = false;
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            self_closing = b[i] == b'/';
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        if b[i] == b'>' {
            return Some(Tag { attrs, end: i, self_closing });
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
                    vs..ve
                }
                _ => {
                    let vs = j;
                    while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'>' {
                        j += 1;
                    }
                    vs..j
                }
            };
            attrs.push((name, value));
            i = j;
        } else {
            attrs.push((name, i..i));
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
/// browser keeps merely fails closed at digest time -- the browser blocks the
/// load -- so tightness costs nothing.
///
/// `value` is the attribute as the page wrote it, never lowercased: Chrome
/// and Firefox both discard an algorithm in any other case, so
/// `integrity="SHA384-..."` loads unchecked (measured, docs/EXTENSION.md).
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

/// Why inline style text `css` (lowercased) cannot be pinned, or `None`: an
/// `@import` loads a stylesheet no hash admits. CSS decodes an escape inside
/// an at-rule's name (`@\69mport`) and this scanner does not, so a name
/// holding one is refused rather than compared wrong; an `@` that is itself
/// escaped (`.\@md` in a selector) starts no at-rule.
fn style_import(css: &str) -> Option<String> {
    if css.contains("@import") {
        return Some(
            "<style> holds an @import, which the pinned policy refuses; inline what it imports"
                .to_string(),
        );
    }
    let b = css.as_bytes();
    let escaped = css.match_indices('@').any(|(p, _)| {
        (p == 0 || b[p - 1] != b'\\')
            && css[p + 1..]
                .trim_start_matches(|c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                .starts_with('\\')
    });
    escaped.then(|| {
        "<style> holds an at-rule whose name is escaped, where an @import could be; write it plainly"
            .to_string()
    })
}

/// Start tags that end an `<svg>` or `<math>` (the HTML parser's list; `font`
/// only with some attributes there, always here).
const BREAKOUT: &[&str] = &[
    "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div", "dl", "dt", "em",
    "embed", "font", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li",
    "listing", "menu", "meta", "nobr", "ol", "p", "pre", "ruby", "s", "small", "span", "strong",
    "strike", "sub", "sup", "table", "tt", "u", "ul", "var",
];

/// Elements inside an `<svg>` or `<math>` whose content is parsed as HTML.
const INTEGRATION: &[&str] = &[
    "foreignobject", "desc", "title", "mi", "mo", "mn", "ms", "mtext", "annotation-xml",
];

/// The MIME types a `<script type=...>` runs as JavaScript.
const JS_TYPES: &[&str] = &[
    "application/ecmascript",
    "application/javascript",
    "application/x-ecmascript",
    "application/x-javascript",
    "text/ecmascript",
    "text/javascript",
    "text/javascript1.0",
    "text/javascript1.1",
    "text/javascript1.2",
    "text/javascript1.3",
    "text/javascript1.4",
    "text/javascript1.5",
    "text/jscript",
    "text/livescript",
    "text/x-ecmascript",
    "text/x-javascript",
];

/// What the browser makes of a `<script>` with these attributes ("prepare the
/// script element"): `"classic"`, `"module"`, `"importmap"` or
/// `"speculationrules"`, or `None` for one it does nothing with -- a data
/// block, a `nomodule` script, a handler for another event. `get` returns an
/// attribute's lowercased value.
fn script_kind<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Option<&'static str> {
    let strip = |s: &'a str| s.trim_matches(|c: char| c.is_ascii_whitespace());
    let kind = match (get("type"), get("language")) {
        (Some(""), _) | (None, None | Some("")) => "text/javascript".to_string(),
        (Some(t), _) => strip(t).to_string(),
        (None, Some(l)) => format!("text/{l}"),
    };
    match kind.as_str() {
        "module" => return Some("module"),
        "importmap" => return Some("importmap"),
        "speculationrules" => return Some("speculationrules"),
        k if !JS_TYPES.contains(&k) => return None,
        _ => {}
    }
    if get("nomodule").is_some() {
        return None;
    }
    if let (Some(f), Some(e)) = (get("for"), get("event")) {
        if strip(f) != "window" || !matches!(strip(e), "onload" | "onload()") {
            return None;
        }
    }
    Some("classic")
}

/// The refusal for a point past which the parse is not one `read_page`
/// follows.
fn lost(place: &str) -> String {
    format!("cannot follow the page after {place}: how the browser parses from there is ambiguous")
}

/// Reads a page as the browser's HTML parser will, tag by tag. `Err(why)`:
/// why its hash would not prove the page, or why the extensions' pinned
/// policy could not run it (the rules are listed on
/// `unverifiable_subresource`). `Ok(open)`: nothing to refuse, `open` saying
/// the page ends inside an `<svg>`, `<math>` or `<select>`.
///
/// Text the browser never parses as markup is not read as markup, so an
/// honest page is not refused over strings in its own code: a comment is
/// skipped to where the tokenizer ends it, a CDATA section inside `<svg>` or
/// `<math>` to its `]]>`, and the body of `<script>`, `<style>`,
/// `<textarea>`, `<title>`, `<xmp>`, `<noembed>`, `<noframes>` and
/// `<noscript>` to its end tag (a `<noscript>` body is also read as a page
/// of its own, which is how a browser with scripting off reads it).
///
/// Each skip is right only while this is in step with the parser, and wrong
/// either way fails open: a skip the parser does not make hides markup the
/// browser runs, and text read as markup can open a quote that swallows the
/// real tags after it. So this follows the parser where it can, and where it
/// cannot say what the parser will do it refuses rather than guess:
/// - Inside `<svg>` or `<math>` a `<script>`'s `<` opens a tag and
///   `<script/>` closes itself, so the elements open there are tracked to the
///   end tag that closes them, and plain HTML is taken up again after it. A
///   script or style inside is refused (its text is markup there and cannot
///   be hashed as the browser reads it), and so is what leaves the simple
///   case: a tag that breaks out of foreign content, markup in an integration
///   point such as `<foreignObject>` or an SVG `<title>`, an end tag that
///   matches nothing open.
/// - Inside `<select>` the old and the new select parsers agree only on
///   options, so anything else in one is refused.
/// - A `<frameset>`'s parser ignores the tags whose bodies this would skip;
///   it is refused with the frames it exists to hold.
/// - A script holding `<!--` and then a script start tag can end later than
///   its first end tag (the double-escaped state), and is refused.
/// - A script that runs inside a `<template>`: its content is inert unless
///   the template declares a shadow root, and which end tag closes one is
///   not followed.
/// - A `<col>` inside a `<template>`: as the first element there it leaves
///   the template's parser ignoring every tag, the ones this would skip a
///   body for among them.
///
/// The JS port (`readPage` in core/verifier.js) is this walk, and also
/// collects what the extensions' policy pins, so a page accepted here is a
/// page they can pin. The two must refuse the same pages, and both must
/// stay in step with the browsers' parsers: tools/walk-fuzz.mjs checks each
/// on random pages. The port turns CRLF and CR into LF first, as the parser
/// does before a hash is taken; here they are left, since nothing below
/// tells a CR from an LF.
fn read_page(text: &str) -> Result<bool, String> {
    // ASCII-only lowercasing, so offsets stay aligned with the original.
    let hay = text.to_ascii_lowercase();
    let b = hay.as_bytes();
    // The elements open inside an <svg> or <math>, outermost first; empty
    // outside one.
    let mut foreign: Vec<&str> = Vec::new();
    let mut select = false;
    // How many <template>s are open.
    let mut templates = 0u32;
    let mut i = 0;
    while let Some(lt) = find_from(&hay, "<", i) {
        if hay[lt..].starts_with("<!--") {
            match comment_end(&hay, lt) {
                Some(end) => i = end,
                None => break,
            }
            continue;
        }
        if !foreign.is_empty() && text[lt..].starts_with("<![CDATA[") {
            match find_from(&hay, "]]>", lt) {
                Some(end) => i = end + 3,
                None => break,
            }
            continue;
        }
        let c = b.get(lt + 1).copied().unwrap_or(0);
        if !c.is_ascii_alphabetic() {
            if c == b'/' && b.get(lt + 2).is_some_and(u8::is_ascii_alphabetic) {
                // An end tag, its attributes tokenized like a start tag's, so
                // `</p title="> <!--">` ends after its closing quote.
                let name_end = tag_name_end(b, lt + 2);
                let name = &hay[lt + 2..name_end];
                let Some(tag) = parse_tag(&hay, name_end) else { break };
                i = tag.end + 1;
                if !foreign.is_empty() {
                    // It closes the nearest open element of its name; one
                    // that matches none is handled by the HTML around the
                    // <svg>.
                    match foreign.iter().rposition(|open| *open == name) {
                        Some(open) => foreign.truncate(open),
                        None => return Err(lost(&format!("</{name}> inside <svg> or <math>"))),
                    }
                } else if select {
                    match name {
                        "select" => select = false,
                        "option" | "optgroup" => {}
                        _ => return Err(lost(&format!("</{name}> inside <select>"))),
                    }
                } else if name == "template" {
                    templates = templates.saturating_sub(1);
                }
            } else if matches!(c, b'/' | b'!' | b'?') {
                // A doctype or bogus comment: it ends at its first `>`.
                match find_from(&hay, ">", lt + 1) {
                    Some(gt) => i = gt + 1,
                    None => break,
                }
            } else {
                // A stray `<` is text.
                i = lt + 1;
            }
            continue;
        }
        let name_end = tag_name_end(b, lt + 1);
        let name = &hay[lt + 1..name_end];
        // Every tag is tokenized to its real end, quoted values and all, so
        // its attribute text is never read as markup: `<div title="<script
        // src=x>">` is inert to the browser and must not block attestation.
        let Some(tag) = parse_tag(&hay, name_end) else {
            return Err(format!("<{name}> tag is never closed"));
        };
        i = tag.end + 1;
        // An attribute's value: lowercased, or as the page wrote it.
        let get = |n: &str| tag.value(n).map(|v| &hay[v]);
        let written = |n: &str| tag.value(n).map(|v| &text[v]);

        // What the pinned policy refuses, on any element.
        for (n, _) in &tag.attrs {
            if n.len() > 2 && n.starts_with("on") {
                return Err(format!(
                    "<{name} {n}=...> is an inline event handler, which the pinned policy refuses; \
                     attach it from a script"
                ));
            }
        }
        if get("style").is_some() {
            return Err(format!(
                "<{name} style=...> is an inline style attribute, which the pinned policy refuses; \
                 move it into a <style>"
            ));
        }
        for attr in ["href", "xlink:href", "action", "formaction"] {
            if let Some(why) = get(attr).and_then(|v| script_url(name, attr, v)) {
                return Err(why);
            }
        }
        match name {
            // No SRI mechanism exists for anything these load -- src, data,
            // or a whole srcdoc document -- so integrity= on them is a
            // promise nothing enforces. Refused outright.
            "iframe" | "frame" | "frameset" | "object" | "embed" => {
                return Err(format!(
                    "<{name}> loads content SRI cannot cover; inline the content instead"
                ));
            }
            // Re-roots every relative URL on the page, so each subresource
            // resolves to bytes no record attests.
            "base" if get("href").is_some() => {
                return Err("<base href=...> relocates every relative URL on the page".to_string());
            }
            "meta" => {
                if let Some(v) = get("http-equiv") {
                    if char_ref_free(name, "http-equiv", v)?.trim() == "refresh" {
                        return Err(
                            "<meta http-equiv=refresh> navigates away from the attested page"
                                .to_string(),
                        );
                    }
                }
            }
            "link" => {
                let rel = char_ref_free(name, "rel", get("rel").unwrap_or(""))?;
                let rels = || rel.split_ascii_whitespace();
                // The pinned policy pins styles by the hash of their text, and
                // Chrome takes no hash for an external stylesheet; a URL would
                // pin nothing once the markup can be altered.
                if get("href").is_some() && rels().any(|r| r == "stylesheet") {
                    return Err("<link rel=stylesheet> is an external stylesheet, which the \
                                pinned policy refuses; inline it as a <style>"
                        .to_string());
                }
                if get("href").is_some()
                    && rels().any(|r| r == "modulepreload")
                    && !written("integrity").is_some_and(integrity_enforceable)
                {
                    return Err("<link rel=modulepreload> has no enforceable integrity=".to_string());
                }
            }
            _ => {}
        }

        if !foreign.is_empty() {
            if matches!(name, "script" | "style") {
                return Err(format!(
                    "<{name}> inside <svg> or <math> cannot be pinned: its text is markup there"
                ));
            }
            if BREAKOUT.contains(&name) {
                return Err(lost(&format!("<{name}> inside <svg> or <math>")));
            }
            if tag.self_closing {
                continue;
            }
            if INTEGRATION.contains(&name) {
                // Its content is parsed as HTML; followed only while that is
                // text, so the next tag must be its own end tag.
                let Some(next) = find_from(&hay, "<", i) else { break };
                let own_end = hay[next..].strip_prefix("</").is_some_and(|r| r.starts_with(name))
                    && tag_name_end(b, next + 2) == next + 2 + name.len();
                if !own_end {
                    return Err(lost(&format!("markup in <{name}> inside <svg> or <math>")));
                }
            }
            foreign.push(name);
            continue;
        }
        if select {
            if !matches!(name, "option" | "optgroup" | "hr") {
                return Err(lost(&format!("<{name}> inside <select>")));
            }
            continue;
        }
        match name {
            "svg" | "math" => {
                if !tag.self_closing {
                    foreign.push(name);
                }
                continue;
            }
            "select" => {
                select = true;
                continue;
            }
            // The rest of the page is text.
            "plaintext" => break,
            "template" => {
                templates += 1;
                continue;
            }
            "col" if templates > 0 => return Err(lost("<col> inside <template>")),
            "script" | "style" | "textarea" | "title" | "xmp" | "noembed" | "noframes"
            | "noscript" => {}
            _ => continue,
        }

        // Raw text: the browser reads everything to the end tag as text.
        let Some(end) = raw_text_end(&hay, i, name) else {
            return Err(format!("<{name}> is never closed"));
        };
        let body = &hay[i..end];
        match name {
            "script" => {
                for attr in ["type", "language", "for", "event"] {
                    char_ref_free(name, attr, get(attr).unwrap_or(""))?;
                }
                let kind = script_kind(get);
                if get("src").is_some() {
                    // Asked of a data block too: a type misread as one would
                    // otherwise load unchecked.
                    if !written("integrity").is_some_and(integrity_enforceable) {
                        return Err("<script src=...> has no enforceable integrity= \
                                    (missing, empty, or not sha256/384/512-base64)"
                            .to_string());
                    }
                } else if kind == Some("module") {
                    // An inline module's import statements fetch files SRI
                    // cannot pin, from inside the attested bytes.
                    return Err("inline <script type=module> imports files SRI cannot cover; \
                                use a classic inline script or src= with integrity="
                        .to_string());
                }
                // Chrome loads the pages such rules name and runs their
                // scripts, on this origin and unasked (a prerender).
                if kind == Some("speculationrules") {
                    return Err("<script type=speculationrules> has the browser load pages \
                                no record covers"
                        .to_string());
                }
                // After a comment opener, a nested script start tag makes the
                // parser read past the first end tag (the double-escaped
                // state).
                let nested = |esc: usize| {
                    body[esc..].match_indices("<script").any(|(p, _)| {
                        body.as_bytes()
                            .get(esc + p + "<script".len())
                            .is_some_and(|c| c.is_ascii_whitespace() || matches!(c, b'/' | b'>'))
                    })
                };
                if body.find("<!--").is_some_and(nested) {
                    return Err("<script> holds a comment opener and then a script start tag: \
                                where it ends is ambiguous"
                        .to_string());
                }
                if kind.is_some() && templates > 0 {
                    return Err("<script> inside <template> cannot be pinned: \
                                whether it runs is ambiguous"
                        .to_string());
                }
            }
            "style" => {
                if let Some(why) = style_import(body) {
                    return Err(why);
                }
            }
            "noscript" => {
                // With scripting off the body is markup: read it as a page of
                // its own. One that ends inside an element this follows, or
                // in a comment, would run on past the end tag, where this
                // does not follow.
                if read_page(&text[i..end])? {
                    return Err("<noscript> ends inside an <svg>, <math> or <select>".to_string());
                }
                if body.rfind("<!--").is_some_and(|p| comment_end(body, p).is_none()) {
                    return Err("<noscript> holds a comment that runs past its end".to_string());
                }
            }
            _ => {}
        }
        i = end;
    }
    Ok(!foreign.is_empty() || select)
}

/// Why a served entrypoint's own bytes are not enough to verify the page, or
/// `None` if they are.
///
/// The registry attests exactly ONE blob -- the entrypoint, since
/// `attest::record_artifact` resolves path "" for the site -- so every file the entrypoint
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
/// - `<script src>` and `<link rel=modulepreload>` need an `integrity` value
///   the SRI spec actually parses -- presence alone leaves the browser
///   loading the file unchecked.
/// - `<iframe>`, `<frame>`, `<frameset>`, `<object>`, `<embed>` have no SRI
///   mechanism for anything they load (src, data, srcdoc), so they can never
///   be made verifiable and are refused outright, whatever their attributes.
/// - `<base href>` and `<meta http-equiv=refresh>` relocate the page or its
///   relative URLs to bytes no record attests, and are refused for the same
///   reason.
/// - An inline `<script type=module>` imports files no integrity can pin,
///   and a `<script type=speculationrules>` has Chrome load other pages of
///   the origin and run their scripts, unasked.
/// - A tag that never closes, a keyword value hiding behind a character
///   reference, or a body that is not UTF-8, is refused rather than skipped.
/// - What the extensions' pinned policy would refuse at run time, or could
///   not pin (docs/EXTENSION.md): it admits a page's own scripts and styles
///   by hash and nothing else, so a page holding these would publish and
///   then be stopped. Inline event handlers (`on...=`), `style=` attributes,
///   `javascript:` URLs, every external stylesheet (pinned or not: inline
///   it), `@import` in an inline `<style>`, and a script or style where
///   `read_page` cannot say what the browser will hash or run.
/// - An entrypoint that is XML (`.svg`, `.xhtml`). The page is read as HTML,
///   and XML has ways to load code that reading never sees: an
///   `<?xml-stylesheet?>` instruction (CSS, or an XSLT that rewrites the
///   whole document), an element or attribute under a namespace prefix
///   (`<h:script src>`, `x:href`), an entity or a default attribute from the
///   doctype. A page is `.html`; an `<svg>` can be inline in it.
///
/// A false refusal costs the operator one edit; a false accept costs a user
/// their funds. That asymmetry is the whole design.
///
/// NOT covered, stated rather than implied:
/// - Images, fonts, and media. SRI has no mechanism for them, so refusing them
///   would reject every real site. They cannot execute; a swapped image can
///   mislead the eye but not the machine.
/// - What attested or SRI-pinned JavaScript does at runtime. A markup scan
///   cannot follow `fetch()`, a worker, dynamic `import()`, or the import
///   chain of an integrity-pinned external module (import specifiers take no
///   integrity); those are issued by code the record or SRI already covers,
///   and auditing that code is the operator's job, not this scanner's. Under
///   the extensions the pinned policy still applies to that code, and
///   refuses some of it at run time (docs/EXTENSION.md lists what).
pub fn unverifiable_subresource(served_path: &str, body: &[u8]) -> Option<String> {
    // Gate on the entrypoint's file NAME, case-insensitively -- `index.HTML`
    // renders exactly like `index.html`. `set_site` can also point the root
    // at a blob directly; when that name has no extension at all there is no
    // evidence it is not a page, so it is read as one rather than skipped.
    // Known non-markup extensions stay exempt: a JSON or hex artifact holding
    // "<script" as data is verifiable as-is (see tests).
    let name = served_path.rsplit('/').next().unwrap_or(served_path);
    let ext = name.rsplit_once('.').map(|(_, ext)| ext.to_ascii_lowercase());
    match ext.as_deref() {
        Some(ext @ ("svg" | "xhtml")) => {
            return Some(format!(
                "a .{ext} entrypoint is XML, where a stylesheet instruction, a prefixed element \
                 or an entity can load code this scan (an HTML one) does not see; publish an \
                 .html page -- an <svg> can be inline in it"
            ));
        }
        Some("html" | "htm") | None => {}
        Some(_) => return None,
    }
    let Ok(text) = core::str::from_utf8(body) else {
        return Some("entrypoint is not valid UTF-8, so its references cannot be read".to_string());
    };
    read_page(text).err()
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

/// The 404 for a repo with no site, as certified for every such repo at
/// once (certify.rs).
pub(crate) fn no_site() -> HttpResponse {
    expressed(plain(404, "no site configured for repo\n"))
}

fn not_in_bundle() -> HttpResponse {
    plain(404, "not found in site bundle\n")
}

/// The 404 `serve` gives for a path the site does not answer: the one
/// response certified for every such path of the site (certify.rs).
pub(crate) fn miss(repo: &str) -> HttpResponse {
    expressed(match site_state(repo) {
        Ok(_) => not_in_bundle(),
        Err(res) => res,
    })
}

/// What a site is serving from, or the 404 that says why not.
fn site_state(repo: &str) -> Result<(SiteConfig, store::Oid), HttpResponse> {
    let Some(cfg) = get_config(repo) else {
        return Err(plain(404, "no site configured for repo\n"));
    };
    match served_commit(repo) {
        Ok(c) => Ok((cfg, c)),
        Err(why) => Err(plain(404, &format!("{why}\n"))),
    }
}

/// The blob `serve` answers with.
struct Resolved {
    /// Its tree location (site root prefix and index.html fallback applied).
    path: String,
    body: Vec<u8>,
    oid: store::Oid,
    /// The request named a directory, and this is its index.html.
    index: bool,
}

/// The blob `serve` would return for `path`, given an already-resolved commit and
/// config. One walk from the root -- a blob serves directly; a
/// directory (including "" for the bundle root) serves the index.html inside.
fn resolve_blob(commit: &store::Oid, cfg: &SiteConfig, path: &str) -> Option<Resolved> {
    let rel = path.trim_matches('/');
    let full = match (cfg.root.is_empty(), rel.is_empty()) {
        (true, _) => rel.to_string(),
        (false, true) => cfg.root.clone(),
        (false, false) => format!("{}/{rel}", cfg.root),
    };
    match object::node_at_path_oid(commit, &full) {
        Ok((oid, ObjectType::Blob, body)) => Some(Resolved { path: full, body, oid, index: false }),
        Ok((_, ObjectType::Tree, tree)) => object::tree_entries(&tree)
            .ok()
            .and_then(|es| es.into_iter().find(|e| e.name == b"index.html"))
            .filter(|e| !object::is_gitlink_mode(&e.mode))
            .and_then(|e| store::get_object_parsed(&e.oid).map(|(ty, body)| (e.oid, ty, body)))
            .and_then(|(oid, ty, body)| {
                let path = if full.is_empty() {
                    "index.html".to_string()
                } else {
                    format!("{full}/index.html")
                };
                (ty == ObjectType::Blob).then_some(Resolved { path, body, oid, index: true })
            }),
        _ => None,
    }
}

/// One URL of a site's bundle: the sub-path `serve` takes for it, and
/// the blob that answers there.
pub(crate) struct Page {
    pub sub: String,
    /// The blob's location in the commit's tree, as the walk of the
    /// bundle met it.
    path: String,
    oid: store::Oid,
}

/// What a site answers at: the commit it serves and every URL of the
/// bundle, from one walk of its trees.
pub(crate) struct Bundle {
    /// `None` when the site serves nothing.
    commit: Option<store::Oid>,
    pub pages: Vec<Page>,
}

impl Bundle {
    /// What `serve` answers at a page, and the blob it answers with:
    /// `served`, without its walk from the commit down to the file, which
    /// the walk of the bundle has made already for every page at once.
    /// One blob read where `served` reads the commit and each tree on the
    /// way again; a directory of 2,000 files was read 2,000 times. Where
    /// the entry is no blob (a tree no git writes), `served` is asked, as
    /// it was for every page.
    pub fn answer(&self, repo: &str, page: &Page) -> (HttpResponse, Option<store::Oid>) {
        if let Some(commit) = &self.commit {
            if let Some((ObjectType::Blob, body)) = store::get_object_parsed(&page.oid) {
                return answer(repo, commit, page.path.clone(), body, page.oid);
            }
        }
        served(repo, &page.sub)
    }
}

/// The URLs a site answers at, as `serve` takes them: "" for the root,
/// each blob of the bundle, and each directory holding an index.html
/// with and without its trailing slash; in tree order, so the count is
/// the same every time. None when the site serves nothing (no config, no
/// commit: every path is the one miss). `Err` past `cap` of them.
pub(crate) fn bundle(repo: &str, cap: usize) -> Result<Bundle, ()> {
    let Ok((cfg, commit)) = site_state(repo) else {
        return Ok(Bundle { commit: None, pages: Vec::new() });
    };
    let mut pages = Vec::new();
    match object::node_at_path_oid(&commit, &cfg.root) {
        Ok((oid, ObjectType::Blob, _)) => pages.push(Page { sub: String::new(), path: cfg.root.clone(), oid }),
        Ok((oid, ObjectType::Tree, _)) => walk_bundle(&oid, &cfg.root, "", &mut pages, cap)?,
        _ => {}
    }
    Ok(Bundle { commit: Some(commit), pages })
}

/// `root` is the site's root in the commit's tree, `prefix` the
/// directory under it: a page's sub-path is from the one, its tree
/// location from both.
fn walk_bundle(tree: &store::Oid, root: &str, prefix: &str, out: &mut Vec<Page>, cap: usize) -> Result<(), ()> {
    let Some((ObjectType::Tree, content)) = store::get_object_parsed(tree) else {
        return Ok(());
    };
    let Ok(entries) = object::tree_entries(&content) else {
        return Ok(());
    };
    let located = |rel: &str| match (root.is_empty(), rel.is_empty()) {
        (true, _) => rel.to_string(),
        (false, true) => root.to_string(),
        (false, false) => format!("{root}/{rel}"),
    };
    let index = entries.iter().any(|e| e.name == b"index.html" && e.mode != "40000");
    // The entry `serve` takes for the directory: the first of the name,
    // whatever it is, but a submodule's, which is no object of this repo.
    if let Some(e) = entries.iter().find(|e| e.name == b"index.html").filter(|e| index && !object::is_gitlink_mode(&e.mode)) {
        let dir = located(prefix);
        let path = if dir.is_empty() { "index.html".to_string() } else { format!("{dir}/index.html") };
        if !prefix.is_empty() {
            out.push(Page { sub: prefix.to_string(), path: path.clone(), oid: e.oid });
            out.push(Page { sub: format!("{prefix}/"), path, oid: e.oid });
        } else {
            out.push(Page { sub: String::new(), path, oid: e.oid });
        }
    }
    // A path finds an entry by its name, and the first of the name: an
    // entry a path cannot spell (an empty name, a slash in it) or cannot
    // reach (a name a second time) is in no tree git writes, and is not
    // what `serve` answers with at its URL. It is no page, and such a
    // directory is not walked.
    let mut seen = std::collections::BTreeSet::new();
    for e in &entries {
        let Ok(name) = std::str::from_utf8(&e.name) else { continue };
        let found = seen.insert(name) && !name.is_empty() && !name.contains('/');
        let rel = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        match e.mode.as_str() {
            _ if !found => {}
            "40000" => walk_bundle(&e.oid, root, &rel, out, cap)?,
            m if object::is_gitlink_mode(m) => {}
            _ => out.push(Page { path: located(&rel), oid: e.oid, sub: rel }),
        }
        if out.len() > cap {
            return Err(());
        }
    }
    Ok(())
}

/// How far back from the tip `advance` looks for the newest approved commit,
/// and how many commits each of its ancestry checks may load. It runs in
/// update calls (a vote, a push, a policy change), never in a site
/// request, so it can afford a long walk. Past it, what is served stays:
/// unapproved pushes on top of an approved commit do not take it down,
/// however many.
pub const APPROVAL_WALK: usize = 10_000;

/// What a votes-gated repo serves and deploys (META key `served:{repo}`).
/// Absent while the repo requires no votes. `commit` is `None` when no
/// commit is approved.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
struct Served {
    commit: Option<String>,
}

/// Why a repo whose approvals the authority never wrote serves nothing.
pub const AWAITING_AUTHORITY: &str = "the authority has not yet said which commits of this repo may be served";

fn served_key(repo: &str) -> String {
    format!("served:{repo}")
}

/// Does the repo require votes, so that what it serves and deploys is the
/// recorded approved commit rather than the tip? Read from the approvals
/// mirror (mirror.rs), as everything here that depends on votes is.
pub fn gated(repo: &str) -> bool {
    crate::mirror::approved(repo).is_some()
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
/// parents of the tip that has reached the threshold -- but only forward
/// (`forward_only`): a push never takes the site back to an older approved
/// commit. Only a commit on the branch qualifies: deleting the branch, or
/// replacing it with history the voters never approved, takes the site
/// down rather than leaving an off-branch commit live. First parents only:
/// approvals on history a merge brought in through its second parent are
/// not seen.
///
/// With no votes required the tip is served and deploys on push. Leaving
/// the gated regime returns the tip once, since pushes held for approval
/// never deployed it.
pub fn advance(repo: &str) -> Option<store::Oid> {
    let moved = advance_served(repo);
    // Whatever moved, or did not, what the site answers is recomputed
    // from the state of now: a push changes an open site's every page
    // without moving anything here.
    crate::certify::site_changed(repo);
    moved
}

fn advance_served(repo: &str) -> Option<store::Oid> {
    if !crate::mirror::approvals_written(repo) {
        return None;
    }
    let key = served_key(repo);
    let prev: Option<Served> = crate::kv::get_json(&key);
    let Some(approved) = crate::mirror::approved(repo) else {
        let prev = prev?;
        crate::kv::set_json(&key, &Option::<Served>::None);
        let tip = tip_of(repo).ok()?;
        return (prev.commit != Some(store::oid_hex(&tip))).then_some(tip);
    };
    let prev = prev.unwrap_or_default();
    let tip = tip_of(repo).ok();
    let found = tip.and_then(|tip| newest_approved(tip, &approved));
    let next = match prev.commit.as_deref().and_then(|h| store::parse_oid(h).ok()) {
        Some(was) => forward_only(was, found, tip, &approved),
        None => found,
    };
    let now = Served {
        commit: next.as_ref().map(store::oid_hex),
    };
    let moved = now.commit != prev.commit;
    crate::kv::set_json(&key, &Some(now));
    next.filter(|_| moved)
}

/// The newest approved commit among `from` and its first parents, within
/// the walk.
fn newest_approved(from: store::Oid, approved: &crate::mirror::Approved) -> Option<store::Oid> {
    crate::graph::first_parents(from).take(APPROVAL_WALK).find(|c| approved.contains(c))
}

/// What a votes-gated repo serves next, when it served `was` and the tip's
/// first parents lead to `found`. Forward only: `found` when it is `was` or
/// descends from it. The tip's first parents are the pusher's to choose --
/// a merge whose first parent is an old approved commit and whose second
/// is the tip is a fast-forward any writer may push -- so a `found` behind
/// `was`, or beside it, is no step the voters took. The site stays on its
/// own line instead: `was` while it is approved, and when its approval is
/// withdrawn (or the threshold or the voters change), the newest approved
/// commit among `was`'s own first parents -- the line the voters approved
/// along, whatever line the tip now draws. Only once the branch no longer
/// holds `was` at all (history replaced other than by a push, which only
/// fast-forwards it) does what the tip's walk found decide, as it does for
/// a repo that served nothing. An ancestry check that runs out of walk
/// counts as no move: the site stays where it is.
fn forward_only(
    was: store::Oid,
    found: Option<store::Oid>,
    tip: Option<store::Oid>,
    approved: &crate::mirror::Approved,
) -> Option<store::Oid> {
    if let Some(c) = found {
        // Behind `was` is checked first: it is the short walk when the tip
        // leads back, and the long one (all of `c`'s past) is skipped.
        let behind = c != was && crate::graph::reaches(was, &c, APPROVAL_WALK) == Some(true);
        if c == was || (!behind && crate::graph::reaches(c, &was, APPROVAL_WALK) == Some(true)) {
            return found;
        }
    }
    if tip.is_none_or(|t| crate::graph::reaches(t, &was, APPROVAL_WALK) == Some(false)) {
        return found;
    }
    newest_approved(was, approved)
}

fn recorded_if_approved(served: &Served, approved: &crate::mirror::Approved) -> Option<store::Oid> {
    let oid = store::parse_oid(served.commit.as_deref()?).ok()?;
    approved.contains(&oid).then_some(oid)
}

/// The commit a site serves. With no votes required (the default, and every
/// legacy repo) that is the deploy-branch tip. With votes required it is the
/// commit `advance` last recorded, re-checked on every request against the
/// approvals mirror, which the authority updates with each ballot, so a
/// withdrawn approval can never be served; an unapproved push is not
/// served, and the last approved commit stays up.
///
/// A repo whose approved set the authority never wrote serves nothing:
/// whether it requires votes is the authority's to say, and until it has,
/// the tip may be a commit the voters never approved (step 16.4).
pub fn served_commit(repo: &str) -> Result<store::Oid, &'static str> {
    if !crate::mirror::approvals_written(repo) {
        return Err(AWAITING_AUTHORITY);
    }
    let Some(approved) = crate::mirror::approved(repo) else {
        return tip_of(repo);
    };
    crate::kv::get_json::<Served>(&served_key(repo))
        .and_then(|s| recorded_if_approved(&s, &approved))
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
    let r = resolve_blob(&commit, &cfg, path)?;
    Some((commit, r.path, r.body))
}

/// The repo and sub-path a URL path under `/site` names, as `serve` takes
/// them: `/site` and `/site/` name the empty repo, `/site/<repo>` its
/// root, `/site/<repo>/<sub>` the rest. `None` off `/site`. One parse for
/// the routers and for the certifier's shadows (certify.rs), so what is
/// certified at such a path is what is served there. One slash is taken
/// after `/site`, as the certification tree splits a path: `/site//<repo>`
/// names the empty repo too, which has no site, and not `<repo>`, whose
/// entries the gateway would not take for that path.
pub fn site_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/site").filter(|r| r.is_empty() || r.starts_with('/'))?;
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    Some(rest.split_once('/').unwrap_or((rest, "")))
}

/// The sub-path a URL path names at a site's own domain, as `serve` takes
/// it: one leading slash off, so `//x` keeps its empty component and is
/// the miss the certifier holds for it, as `/site/<repo>//x` is.
pub fn domain_path(path: &str) -> &str {
    path.strip_prefix('/').unwrap_or(path)
}

/// GET /site/<repo>/<path>. `path` is "" for the root, a blob's path, or
/// a directory's with or without its trailing slash.
pub fn serve(repo: &str, path: &str) -> HttpResponse {
    served(repo, path).0
}

/// `serve`, and the blob it answered with, for the certifier's body
/// hashes (certify.rs).
pub(crate) fn served(repo: &str, path: &str) -> (HttpResponse, Option<store::Oid>) {
    let (cfg, commit) = match site_state(repo) {
        Ok(s) => s,
        Err(res) => return (expressed(res), None),
    };
    // One URL, one answer: an empty component, or a slash after a file,
    // is a miss, so that the certified set is exactly the bundle's files
    // and directories.
    if path.starts_with('/') || path.contains("//") {
        return (expressed(not_in_bundle()), None);
    }
    let dir = path.ends_with('/');
    let Some(r) = resolve_blob(&commit, &cfg, path).filter(|r| r.index || !dir) else {
        return (expressed(not_in_bundle()), None);
    };
    answer(repo, &commit, r.path, r.body, r.oid)
}

/// The answer with a blob of the bundle: `served`'s, and the certifier's
/// for a page of the bundle it walked (`Bundle::answer`), so that what is
/// certified at a URL is what is served there.
fn answer(repo: &str, commit: &store::Oid, path: String, body: Vec<u8>, oid: store::Oid) -> (HttpResponse, Option<store::Oid>) {
    if body.len() > MAX_BODY {
        return (expressed(plain(413, "file exceeds the single-response limit\n")), None);
    }
    let mut res = crate::git_response(200, content_type(&path), body);
    // The provenance binding a verifier checks against the registry. Path is
    // the actual location in the commit tree (site root and index.html
    // fallback applied), so `git show <commit>:<path>` reproduces the body.
    res.headers
        .push(("X-Ic-Git-Repo".to_string(), repo.to_string()));
    res.headers
        .push(("X-Ic-Git-Commit".to_string(), store::oid_hex(commit)));
    res.headers.push(("X-Ic-Git-Path".to_string(), path));
    (expressed(res), Some(oid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ObjectType;

    /// Commit index.html + app/main.js into a fresh repo and serve them.
    #[test]
    fn serves_committed_bundle_with_provenance_headers() {
        store::create_repo("web").unwrap();
        crate::mirror::ungated_for_tests("web");
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

    /// The certifier's walk of a bundle answers at every page as `serve`
    /// does there (`Bundle::answer`), with the site at the root and under
    /// a directory, and in trees git does not write: an empty name, a
    /// slash in one, a name twice (a file over a directory and the other
    /// way), an index.html that is a directory, a file's mode on a tree.
    #[test]
    fn the_walk_of_a_bundle_answers_as_serve_does() {
        fn tree(entries: &[(&str, &str, store::Oid)]) -> store::Oid {
            let mut t = Vec::new();
            for (mode, name, oid) in entries {
                t.extend_from_slice(format!("{mode} {name}\0").as_bytes());
                t.extend_from_slice(oid.as_slice());
            }
            store::put_object(ObjectType::Tree, &t)
        }
        let blob = |b: &[u8]| store::put_object(ObjectType::Blob, b);
        store::create_repo("walked").unwrap();
        crate::mirror::ungated_for_tests("walked");
        let docs = tree(&[("100644", "a.txt", blob(b"a")), ("100644", "index.html", blob(b"docs"))]);
        let deep = tree(&[("40000", "docs", docs), ("100644", "x.js", blob(b"x"))]);
        let hidden = tree(&[("100644", "x.js", blob(b"hidden")), ("100644", "only.txt", blob(b"only"))]);
        let no_index = tree(&[("40000", "index.html", docs), ("100644", "index.html", blob(b"late"))]);
        let root = tree(&[
            ("100644", "", blob(b"nameless")),
            ("40000", "", hidden),
            ("100644", "app/x.js", blob(b"slashed")),
            ("40000", "app", deep),
            ("100644", "app", blob(b"a file after its directory")),
            ("100644", "twice", blob(b"first")),
            ("40000", "twice", hidden),
            ("100644", "twice", blob(b"second")),
            ("100644", "tree.txt", docs),
            ("40000", "odd", no_index),
            ("100644", "index.html", blob(b"<h1>root</h1>")),
            ("100644", "big.bin", blob(&vec![0u8; MAX_BODY + 1])),
            ("160000", "sub", store::parse_oid(&"07".repeat(20)).unwrap()),
            // Submodule entries forged to name blobs the store holds:
            // no pages, at their own path or as a directory's index.
            ("160000", "linked", blob(b"linked")),
            ("40000", "gl", tree(&[("160000", "index.html", blob(b"gl")), ("100644", "index.html", blob(b"second"))])),
        ]);
        let commit = format!("tree {}\nauthor a <a@a> 0 +0000\ncommitter a <a@a> 0 +0000\n\nmsg\n", store::oid_hex(&root));
        let commit = store::put_object(ObjectType::Commit, commit.as_bytes());
        store::set_ref("walked", &store::head_target("walked").unwrap(), commit).unwrap();
        for (site_root, pages, a_page) in [("", 16, "app/docs/a.txt"), ("app", 5, "docs/"), ("app/docs/a.txt", 1, ""), ("nowhere", 0, "")] {
            set_config("walked", site_root.to_string()).unwrap();
            let bundle = bundle("walked", 100).unwrap();
            let subs: Vec<&str> = bundle.pages.iter().map(|p| p.sub.as_str()).collect();
            assert_eq!(subs.len(), pages, "{site_root:?}: {subs:?}");
            assert!(pages == 0 || subs.contains(&a_page), "{site_root:?}: {subs:?}");
            // Each URL once.
            assert_eq!(subs.iter().collect::<std::collections::BTreeSet<_>>().len(), pages, "{site_root:?}: {subs:?}");
            for page in &bundle.pages {
                let (walked, blob) = bundle.answer("walked", page);
                let (asked, asked_blob) = served("walked", &page.sub);
                let at = (site_root, &page.sub);
                assert_eq!((walked.status_code, &walked.headers, &walked.body), (asked.status_code, &asked.headers, &asked.body), "{at:?}");
                assert_eq!(blob, asked_blob, "{at:?}");
            }
        }
        for sub in ["linked", "gl", "gl/", "gl/index.html", "sub"] {
            assert_eq!(served("walked", sub).0.status_code, 404, "{sub}");
            assert!(!bundle("walked", 100).unwrap().pages.iter().any(|p| p.sub == sub), "{sub}");
        }
        // And what it answers with is the bundle's own: a page, the 413,
        // the miss where no path leads.
        set_config("walked", String::new()).unwrap();
        let bundle = bundle("walked", 100).unwrap();
        let status = |sub: &str| {
            let page = bundle.pages.iter().find(|p| p.sub == sub).unwrap_or_else(|| panic!("no page {sub:?}"));
            let (res, _) = bundle.answer("walked", page);
            (res.status_code, res.body)
        };
        assert_eq!(status("app/docs"), (200, b"docs".to_vec()));
        assert_eq!(status("app/x.js"), (200, b"x".to_vec()));
        assert_eq!(status("twice"), (200, b"first".to_vec()));
        assert_eq!(status("big.bin").0, 413);
        assert_eq!(status("tree.txt"), (200, b"docs".to_vec()));
        assert!(!bundle.pages.iter().any(|p| p.sub.contains("only.txt")));
        // Past the cap: no bundle.
        assert!(super::bundle("walked", 15).is_err());
        assert!(super::bundle("walked", 16).is_ok());
    }

    /// A site's own domains: named as looked up, held by one repo at a
    /// time, under none of the IC's domains; a Host that is one of them
    /// is the site, and the well-known file lists them all.
    #[test]
    fn custom_domains() {
        store::create_repo("dom-a").unwrap();
        store::create_repo("dom-b").unwrap();
        store::create_repo("dom-nosite").unwrap();
        assert!(set_domains("dom-none", vec!["a.example".into()]).unwrap_err().contains("no such repo"));
        assert!(set_domains("dom-nosite", vec!["a.example".into()]).unwrap_err().contains("set_site first"));

        set_config("dom-a", String::new()).unwrap();
        set_config("dom-b", "www".into()).unwrap();
        // A root is a path in the tree, and no longer than a config's may be.
        let long = "d/".repeat(ic_git_types::deploy::MAX_CONFIG_PATH);
        assert!(set_config("dom-b", long).unwrap_err().contains("at most 512 bytes"));
        assert_eq!(get_config("dom-b").unwrap().root, "www");
        set_config("dom-b", "w".repeat(ic_git_types::deploy::MAX_CONFIG_PATH)).unwrap();
        set_config("dom-b", "www".into()).unwrap();
        // Named as looked up: case and a trailing dot fall away, a repeat
        // is one domain.
        set_domains("dom-a", vec!["App.Example.".into(), " app.example".into(), "www.app.example".into()]).unwrap();
        assert_eq!(get_config("dom-a").unwrap().domains, ["app.example", "www.app.example"]);
        // The root can change without touching the domains.
        set_config("dom-a", "site".into()).unwrap();
        let cfg = get_config("dom-a").unwrap();
        assert_eq!((cfg.root.as_str(), cfg.domains.len()), ("site", 2));

        // One holder at a time, until it gives the domain up.
        let held = set_domains("dom-b", vec!["app.example".into()]).unwrap_err();
        assert!(held.contains("held by dom-a"), "{held}");
        assert!(get_config("dom-b").unwrap().domains.is_empty(), "nothing of a refused list is kept");
        set_domains("dom-a", vec!["www.app.example".into()]).unwrap();
        set_domains("dom-b", vec!["app.example".into()]).unwrap();
        assert_eq!(repo_for_domain("app.example").as_deref(), Some("dom-b"));
        assert_eq!(repo_for_domain("www.app.example").as_deref(), Some("dom-a"));
        assert_eq!(repo_for_domain("other.example"), None);

        // What is no site's domain.
        for bad in [
            "localhost",
            "example",
            "x.icp0.io",
            "icp0.io",
            "a.b.ic0.app",
            "x.raw.icp0.io",
            "icp-api.io",
            "icp.net",
            "x.icp.net",
            "34koz-jyaaa-aaaab-ahejq-cai.icp.net",
            "34koz-jyaaa-aaaab-ahejq-cai.raw.icp.net",
            // A canister id under a domain the list does not know.
            "34koz-jyaaa-aaaab-ahejq-cai.gateway.example",
            "raw.umobs-yiaaa-aaaab-agyrq-cai.example",
            // ...and behind a prefix, which a gateway drops.
            "x--34koz-jyaaa-aaaab-ahejq-cai.gateway.example",
            "a--b--34koz-jyaaa-aaaab-ahejq-cai.raw.gateway.example",
            "1.2.3.4",
            "-a.example",
            "a-.example",
            "a_b.example",
            "a..example",
            ".example",
            "a.example.",
            "A.example",
            "xn--.example",
            &format!("{}.example", "a".repeat(64)),
            &format!("{}.example", ["abcdefghij"; 26].join(".")),
        ] {
            assert!(check_domain(bad).is_err(), "{bad}");
        }
        // Not refused for being long or odd-looking.
        assert_eq!(check_domain("xn--bcher-kva.example"), Ok(()));
        assert_eq!(check_domain("a.b.c.d.e.f.example"), Ok(()));
        assert_eq!(check_domain("notlocalhost.example"), Ok(()), "only the reserved names themselves and what is under them");
        assert_eq!(check_domain("icp0.io.example"), Ok(()));
        assert_eq!(check_domain("icp.net.example"), Ok(()));
        assert_eq!(check_domain("hello-world-app.example"), Ok(()), "shaped like an id, and not one: the checksum says");
        assert_eq!(check_domain("34koz-jyaaa-aaaab-ahejq-caj.example"), Ok(()));
        assert_eq!(check_domain("xn--bcher-kva.example"), Ok(()), "a prefix alone is no id");
        assert_eq!(check_domain("34koz-jyaaa-aaaab-ahejq-cai--x.example"), Ok(()), "the id is what is after the last one");
        let many: Vec<String> = (0..=MAX_DOMAINS).map(|i| format!("d{i}.example")).collect();
        assert!(set_domains("dom-b", many).unwrap_err().contains("at most"));
        assert_eq!(get_config("dom-b").unwrap().domains, ["app.example"], "the list before stays");
        // The limit is on the list as sent, and comes before its names
        // are looked at: a long list of what is no domain, or of one
        // domain over and over, is refused for its length.
        let junk = vec!["not a domain".to_string(); MAX_DOMAINS + 1];
        assert!(set_domains("dom-b", junk).unwrap_err().contains("at most"));
        let repeats = vec!["app.example".to_string(); MAX_DOMAINS + 1];
        assert!(set_domains("dom-b", repeats).unwrap_err().contains("at most"));
        let full: Vec<String> = (0..MAX_DOMAINS).map(|i| format!("d{i}.example")).collect();
        set_domains("dom-b", full.clone()).unwrap();
        assert_eq!(get_config("dom-b").unwrap().domains, full);
        // A held domain anywhere in the list refuses the whole of it.
        let held = set_domains("dom-a", vec!["new.example".into(), "d3.example".into()]).unwrap_err();
        assert!(held.contains("\"d3.example\" is held by dom-b"), "{held}");
        assert_eq!(get_config("dom-a").unwrap().domains, ["www.app.example"]);
        // The list the site has, named again, is taken and changes nothing.
        set_domains("dom-b", full.iter().map(|d| d.to_uppercase() + ".").collect()).unwrap();
        assert_eq!(get_config("dom-b").unwrap().domains, full);
        set_domains("dom-b", vec!["app.example".into()]).unwrap();

        // A request's Host: the domain with its port, case and trailing dot
        // gone; a gateway host, the local one, an IP are nobody's.
        assert_eq!(repo_for_host(Some("App.Example:443")).as_deref(), Some("dom-b"));
        assert_eq!(repo_for_host(Some("www.app.example.")).as_deref(), Some("dom-a"));
        for none in [
            "umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io",
            "umobs-yiaaa-aaaab-agyrq-cai.icp0.io",
            "34koz-jyaaa-aaaab-ahejq-cai.icp.net",
            "34koz-jyaaa-aaaab-ahejq-cai.raw.icp.net",
            "x--34koz-jyaaa-aaaab-ahejq-cai.gateway.example",
            "umobs-yiaaa-aaaab-agyrq-cai.raw.localhost:4950",
            "localhost:4950",
            "127.0.0.1:4950",
            "[::1]:4950",
            "other.example",
            "app.example:x",
            "",
        ] {
            assert_eq!(repo_for_host(Some(none)), None, "{none}");
        }
        assert_eq!(repo_for_host(None), None);

        // The well-known file: every site's domains, sorted.
        let file = domains_file();
        assert!(file.contains("app.example\nwww.app.example\n"), "{file:?}");
        assert!(file.lines().all(|l| check_domain(l).is_ok()));
        set_domains("dom-a", vec![]).unwrap();
        set_domains("dom-b", vec![]).unwrap();
        assert!(!domains_file().contains("app.example"));
    }

    /// What the authority's votes do to a repo, as the git side sees it:
    /// the approved mirror. With no votes required it is `None`; with one
    /// required, a commit is in it while its one voter approves.
    mod votes {
        use crate::{mirror, store};
        use std::cell::RefCell;
        use std::collections::BTreeMap;

        thread_local! {
            static REPOS: RefCell<BTreeMap<String, (u32, Vec<String>)>> = const { RefCell::new(BTreeMap::new()) };
        }

        thread_local! {
            static SEQ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        }

        fn sync(repo: &str) {
            let approved = REPOS.with(|r| r.borrow().get(repo).cloned().unwrap_or_default());
            let seq = SEQ.with(|s| s.replace(s.get() + 1) + 1);
            mirror::set_approved(repo, seq, (approved.0 > 0).then_some(approved.1));
        }

        pub fn require(repo: &str, k: u32) {
            REPOS.with(|r| r.borrow_mut().entry(repo.into()).or_default().0 = k);
            sync(repo);
        }

        pub fn vote(repo: &str, c: &store::Oid, yes: bool) {
            let key = mirror::commit_key(c.as_slice());
            REPOS.with(|r| {
                let mut r = r.borrow_mut();
                let keys = &mut r.entry(repo.into()).or_default().1;
                keys.retain(|k| *k != key);
                if yes {
                    keys.push(key);
                }
            });
            sync(repo);
        }
    }

    /// A repo whose approved set the authority never wrote -- what a git
    /// canister holds after the import, before the cut rewrites the
    /// mirrors -- serves nothing and records nothing, not its tip; the
    /// first write of the set decides, whichever way it goes.
    #[test]
    fn a_repo_the_authority_has_not_written_serves_nothing() {
        store::create_repo("unwritten").unwrap();
        set_config("unwritten", String::new()).unwrap();
        let tip = store::commit_file_for_tests("unwritten", "index.html", b"tip", None);
        let res = serve("unwritten", "");
        assert_eq!(res.status_code, 404);
        assert!(String::from_utf8_lossy(&res.body).contains(AWAITING_AUTHORITY));
        assert!(resolve_entry("unwritten", "").is_none());
        assert_eq!(served_commit("unwritten"), Err(AWAITING_AUTHORITY));
        assert_eq!(advance("unwritten"), None);
        assert!(crate::kv::get_bytes(&served_key("unwritten")).is_none(), "advance records nothing");

        // Gated, nothing approved: still nothing, now for that reason.
        assert!(crate::mirror::set_approved("unwritten", 1, Some(Vec::new())));
        assert_eq!(served_commit("unwritten"), Err("no approved commit on the site branch"));
        // Ungated: the tip.
        assert!(crate::mirror::set_approved("unwritten", 2, None));
        assert_eq!(served_commit("unwritten"), Ok(tip));
        assert_eq!(serve("unwritten", "").body, b"tip");
    }

    /// A fresh repo with an index.html commit per push.
    fn gated_repo(repo: &str) -> impl Fn(&[u8], Option<store::Oid>) -> store::Oid + '_ {
        store::create_repo(repo).unwrap();
        crate::mirror::ungated_for_tests(repo);
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
        push
    }

    /// With votes required, a push is not served until it is approved; the
    /// site stays on the last approved commit, and `advance` hands the deploy
    /// queue each commit the site moves to, so the app follows the site.
    #[test]
    fn serves_and_deploys_the_newest_approved_commit() {
        let push = gated_repo("gated");
        let vote = |c: &store::Oid, yes: bool| {
            votes::vote("gated", c, yes);
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
        votes::require("gated", 1);
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
        votes::require("gated", 0);
        assert_eq!(advance("gated"), Some(c3));
        assert_eq!(serve("gated", "").body, b"three");
        assert_eq!(advance("gated"), None);
    }

    /// A served commit re-checks its approval on every request: a ballot
    /// withdrawn without an `advance` (which every canister entry point
    /// runs) still takes the commit down rather than serving it.
    #[test]
    fn a_recorded_commit_is_served_only_while_approved() {
        let push = gated_repo("recheck");
        let c1 = push(b"one", None);
        votes::require("recheck", 1);
        votes::vote("recheck", &c1, true);
        advance("recheck");
        assert_eq!(serve("recheck", "").status_code, 200);
        votes::vote("recheck", &c1, false);
        assert_eq!(serve("recheck", "").status_code, 404);
    }

    /// Unapproved pushes on top of an approved commit never take it down:
    /// the walk finds it under APPROVAL_WALK - 1 of them, and past the walk
    /// the site stays where it is. (Until 2026-11 one more took it down.)
    #[test]
    fn unapproved_pushes_never_bury_the_served_commit() {
        let push = gated_repo("deep");
        let c1 = push(b"approved", None);
        votes::require("deep", 1);
        votes::vote("deep", &c1, true);
        assert_eq!(advance("deep"), Some(c1));
        let mut tip = c1;
        for i in 0..APPROVAL_WALK - 1 {
            tip = push(format!("unapproved {i}").as_bytes(), Some(tip));
        }
        assert_eq!(advance("deep"), None);
        assert_eq!(served_commit("deep").unwrap(), c1);
        assert_eq!(serve("deep", "").body, b"approved");
        push(b"past the walk", Some(tip));
        assert_eq!(advance("deep"), None);
        assert_eq!(served_commit("deep").unwrap(), c1);
        assert_eq!(serve("deep", "").body, b"approved");
    }

    /// A push never takes the site back. A merge whose first parent is an
    /// old approved commit and whose second is the tip (`git merge -s ours`
    /// from the old commit) is a fast-forward, which any writer may push,
    /// and the tip's first parents then lead to the old commit: the site
    /// stays, and nothing deploys. A withdrawn approval still falls back,
    /// along the served commit's own line and not the one the merge drew;
    /// and a commit on top that the voters approve moves the site forward.
    #[test]
    fn a_push_never_takes_the_served_commit_back() {
        let push = gated_repo("rollback");
        let c1 = push(b"one", None);
        let c2 = push(b"two", Some(c1));
        let c3 = push(b"three", Some(c2));
        votes::require("rollback", 1);
        for c in [&c1, &c2, &c3] {
            votes::vote("rollback", c, true);
        }
        assert_eq!(advance("rollback"), Some(c3));

        // The merge, pushed as a writer pushes it: taken as a fast-forward.
        let index = store::put_object(ObjectType::Blob, b"one");
        let mut root = b"100644 index.html\0".to_vec();
        root.extend_from_slice(index.as_slice());
        let tree = store::put_object(ObjectType::Tree, &root);
        let text = format!("tree {}\nparent {}\nparent {}\n\nmerge -s ours\n", store::oid_hex(&tree), store::oid_hex(&c1), store::oid_hex(&c3));
        let merge = store::put_object(ObjectType::Commit, text.as_bytes());
        let branch = store::head_target("rollback").unwrap();
        let line = format!("{} {} {branch}\0 report-status\n", store::oid_hex(&c3), store::oid_hex(&merge));
        let mut body = crate::smart_http::pkt_line(line.as_bytes());
        body.extend_from_slice(crate::smart_http::FLUSH_PKT);
        let out = crate::receive::handle("rollback", crate::receive::parse_request(&body).unwrap(), None);
        assert!(String::from_utf8_lossy(&out.report).contains(&format!("ok {branch}")));
        assert_eq!(crate::graph::first_parents(merge).nth(1), Some(c1), "the tip's first parents lead to c1");

        assert_eq!(advance("rollback"), None, "nothing moves, nothing deploys");
        assert_eq!(serve("rollback", "").body, b"three");
        // The authority keeps counting the served line's approvals as on
        // the branch, though the tip's first parents leave it.
        use ic_git_types::git_side::Standing;
        let key = |c: &store::Oid| crate::mirror::commit_key(c.as_slice());
        assert_eq!(
            crate::graph::standings("rollback", &[key(&c3), key(&c2), key(&c1)]),
            [Standing::Deploy(0), Standing::Deploy(1), Standing::Deploy(1)]
        );

        // c3's approval withdrawn: back along c3's line to c2, not to c1.
        votes::vote("rollback", &c3, false);
        assert_eq!(advance("rollback"), Some(c2));
        assert_eq!(serve("rollback", "").body, b"two");

        // On top of the merge: unapproved, nothing moves; approved, it
        // descends from c2 (through the merge's second parent) and serves.
        let c4 = push(b"four", Some(merge));
        assert_eq!(advance("rollback"), None);
        assert_eq!(serve("rollback", "").body, b"two");
        votes::vote("rollback", &c4, true);
        assert_eq!(advance("rollback"), Some(c4));
        assert_eq!(serve("rollback", "").body, b"four");
    }

    /// The recorded commit must still be on the branch. Deleting the branch,
    /// or replacing it with history nobody approved, takes the site down; it
    /// does not leave the old approved commit live off the branch.
    #[test]
    fn an_approved_commit_off_the_branch_is_not_served() {
        let push = gated_repo("rewrite");
        let c1 = push(b"approved", None);
        votes::require("rewrite", 1);
        votes::vote("rewrite", &c1, true);
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

    /// What the browser reads as text is not read as markup.
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
        // After a closed <svg> or <select> the page is plain HTML again.
        ok("<svg></svg><script>'<base href=y>'</script>");
        ok("<select><option>a</option></select><textarea><iframe src=x></textarea>");
        // CDATA inside <svg> is text, and so is everything after <plaintext>.
        ok("<svg><![CDATA[ <base href=y> ]]></svg>");
        ok("<plaintext><script src=x></script>");
    }

    /// Every skip ends where the browser's does, and bodies are not skipped
    /// where the browser parses them as markup.
    #[test]
    fn skips_never_hide_what_the_browser_parses() {
        let refused = |page: &str| {
            assert!(
                unverifiable_subresource("index.html", page.as_bytes()).is_some(),
                "{page}"
            )
        };
        // Comments end where the tokenizer ends them.
        refused("<!-- x --!><base href=y>");
        refused("<!--><base href=y>");
        refused("<!---><base href=y>");
        refused("<!-- a --> <base href=y> -->");
        // A script body ends at its first end tag; one the browser may end
        // later (double-escaped) is refused.
        refused("<script>a</script><base href=y>");
        refused("<script><!--<script>x</script><base href=y></script>-->");
        // A body with no end tag swallows the page: refused, not skipped.
        refused("<script>'<base href=y>'");
        // Foreign content: <script> there is markup, <script/> self-closes.
        refused("<svg><script/><base href=y></svg>");
        refused("<math><style><base href=y></style></math>");
        // An end tag's quoted attribute holds its `>`: a `<!--` in it is not
        // a comment.
        refused("<p></p title=\"> <!--\"><base href=y><!-- -->");
        // Every HTML raw-text element: a `<!--` in its body is text.
        refused("<xmp><!--</xmp><base href=y>-->");
        refused("<noembed><!--</noembed><base href=y>-->");
        refused("<noframes><!--</noframes><base href=y>-->");
        refused("<noscript><!--</noscript><base href=y>-->");
        refused("<xmp><a title=\"</xmp><base href=y>\">");
        // With scripting off a noscript body is markup.
        refused("<noscript><base href=y></noscript>");
        refused("<noscript><!-- </noscript><a title=\" --><base href=y>\">");
        // Only the exact tag name is a raw-text element.
        refused("<script-x><base href=y></script>");
        refused("<title:x><base href=y></title>");
        // A legacy select parser ignores <style>, leaving its body markup.
        refused("<select><style><base href=y></style></select>");
        // CDATA is not a comment, and may hold a `<!--` and a `>`.
        refused("<svg><![CDATA[ a > <!-- ]]><base href=y> -->");
        // The tokenizer's tag name runs to whitespace, `/` or `>`, and a
        // leading `=` starts an attribute name: neither opens a quote.
        refused("<a\"b='><base href=y>'>");
        refused("<a ='><base href=y>'>");
        // Text is never read as markup, where a quote in it would swallow
        // the real tags after it: a comment or a raw-text body after a
        // closed <svg> or <select> is still one.
        refused("<svg></svg><!-- > <a title=\" --><iframe src=x></iframe><!-- \"> -->");
        refused("<svg></svg><textarea><a title=\"</textarea><iframe src=x></iframe>\"></textarea>");
        refused("<select></select><title><a title=\"</title><base href=y>\"></title>");
        refused("<svg></svg><textarea>never closed");
        // A frameset's parser ignores <textarea>, leaving its body markup,
        // and so does a template's after a <col>.
        refused("<frameset><textarea><frame src=x></textarea></frameset>");
        refused("<template><col><textarea></template><iframe src=x></textarea>");
    }

    /// Where the parse is not one `read_page` follows, the page is refused
    /// rather than guessed at -- and the simple cases around it are followed.
    #[test]
    fn refuses_where_it_cannot_follow_the_parser() {
        for bad in [
            // A tag that breaks out of foreign content.
            "<svg><p></svg>",
            // Markup in an integration point, whose content is HTML.
            "<svg><foreignObject><p>a</p></foreignObject></svg>",
            "<svg><title><b>x</b></title></svg>",
            // An end tag the <svg> does not own.
            "<div><svg></div>",
            "<svg></math><link rel=icon href=x>",
            // Anything but options in a select.
            "<select><button>a</button></select>",
            "<select><option>a</option></div></select>",
            // A script the parser may end past its first end tag.
            "<script><!-- <script> </script> --></script>",
            // A noscript body that, read as a page, ends inside an element.
            "<noscript><svg></noscript>",
            "<noscript><select></noscript>",
        ] {
            assert!(
                unverifiable_subresource("index.html", bad.as_bytes()).is_some(),
                "should refuse: {bad}"
            );
        }
        for ok in [
            "<svg viewBox=\"0 0 1 1\"><title>Icon</title><g><path d=\"M0 0\"/></g></svg><script>x()</script>",
            "<svg/><script>x()</script>",
            "<svg><svg></svg></svg><script>x()</script>",
            "<svg><![CDATA[ </svg> ]]></svg><script>x()</script>",
            "<math><mi>x</mi><mo>+</mo></math><script>x()</script>",
            "<select><optgroup><option>a</select><script>x()</script>",
            "<select><option>a</option><hr><option>b</option></select><style>b{}</style>",
            "<noscript><svg><path d=\"M0 0\"/></svg></noscript>",
        ] {
            assert_eq!(
                unverifiable_subresource("index.html", ok.as_bytes()),
                None,
                "should accept: {ok}"
            );
        }
    }

    /// What the extensions' pinned policy refuses at run time, or could not
    /// pin, is refused at publish too, so a page that publishes is a page
    /// they run -- and the look-alikes that are honest still pass.
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
            // A style after a closed select is read for an @import like any.
            "<select><option>a</option></select><style>@import url(a.css);</style>",
            // CSS decodes an escape in an at-rule's name; this does not.
            "<style>@\\69mport url(a.css);</style>",
            "<style>@im\\70 ort url(a.css);</style>",
            // Still inside the <svg>: the outer one, one a stray end tag did
            // not close, one whose end tag is in a comment, and one whose
            // unquoted value ends in `/`, which does not self-close.
            "<svg><svg></svg><script>x()</script></svg>",
            "<svg></math><script>x()</script></svg>",
            "<svg><!-- > </svg> --><script>x()</script></svg>",
            "<svg a=b/><script>x()</script>",
            // A script that runs, inside a template.
            "<template><script>x()</script></template>",
            // Whether a script runs turns on these values, and the browser
            // decodes a character reference in them; this does not.
            "<script language=\"&#106;avascript\">x()</script>",
            "<script for=\"&#119;indow\" event=onload>x()</script>",
            "<script src=a.js integrity=sha384-abc type=\"text/&#106;avascript\"></script>",
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
            // After its end tag an <svg> or <math> is closed, and what
            // follows is the page's own script and style again.
            "<svg><path d=\"M0 0\"/></svg><script>x()</script>",
            "<svg><g><path d=\"M0 0\"/></g></svg><math><mi>x</mi></math><style>b{}</style>",
            // An escaped @ in a selector starts no at-rule.
            "<style>.\\@md\\:flex { display: flex } @media print { b{} }</style>",
            // A data block does not run, in a template or out of one.
            "<template><script type=\"application/json\">{}</script><p></template><script>x()</script>",
            "<script type=\"text/plain\" src=\"a.txt\" integrity=\"sha384-abc\"></script>",
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
            // Not a script: the tag name runs to whitespace, `/` or `>`.
            "<script-x src=\"a.js\"></script-x>",
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
            "<frameset><frame src=\"child.html\"></frameset>",
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
            // A src needs integrity even on what reads as a data block: a
            // type misread as one would otherwise load unchecked.
            "<script type=\"text/plain\" src=\"a.txt\"></script>",
            // An inline module imports files nothing can pin.
            "<script type=\"module\">import './app.js'</script>",
            // Speculation rules have Chrome prerender the pages they name.
            "<script type=\"speculationrules\">{\"prerender\":[{\"urls\":[\"/other.html\"]}]}</script>",
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
            // An algorithm not in lower case: browsers discard that too.
            "<script src=\"app.js\" integrity=\"SHA384-abc\"></script>",
            "<link rel=\"modulepreload\" href=\"m.js\" integrity=\"Sha384-abc\">",
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
        // Extensionless entrypoint: no evidence it is not a page, so it is
        // read as one -- an HTML one, like any other.
        assert!(unverifiable_subresource("entry", looks_like_markup).is_some());
        assert_eq!(
            unverifiable_subresource("entry", b"<script>'<base href=y>'</script>"),
            None
        );
        // The dot in a directory name is not an extension.
        assert!(unverifiable_subresource("v1.2/entry", looks_like_markup).is_some());
    }

    /// An XML entrypoint is refused whatever it holds: the page is read as
    /// HTML, and XML loads code in ways that reading never sees.
    #[test]
    fn refuses_xml_entrypoints() {
        const SVG: &str = "xmlns=\"http://www.w3.org/2000/svg\"";
        for (path, page) in [
            ("logo.svg", format!("<svg {SVG}><path d=\"M0 0\"/></svg>")),
            ("logo.SVG", format!("<svg {SVG}/>")),
            ("page.xhtml", "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body>x</body></html>".to_string()),
            // A stylesheet instruction: CSS, or an XSLT that rewrites the
            // whole document.
            ("logo.svg", format!("<?xml-stylesheet type=\"text/xsl\" href=\"a.xsl\"?><svg {SVG}/>")),
            // An HTML script, and a javascript: URL, under a prefix.
            (
                "logo.svg",
                format!("<svg {SVG}><h:script xmlns:h=\"http://www.w3.org/1999/xhtml\" src=\"a.js\"/></svg>"),
            ),
            (
                "logo.svg",
                format!("<svg {SVG}><a x:href=\"javascript:go()\" xmlns:x=\"http://www.w3.org/1999/xlink\"/></svg>"),
            ),
            // A script out of an entity.
            (
                "logo.svg",
                format!("<!DOCTYPE svg [<!ENTITY s \"<script href='a.js'/>\">]><svg {SVG}>&s;</svg>"),
            ),
        ] {
            assert!(
                unverifiable_subresource(path, page.as_bytes()).is_some_and(|why| why.contains("is XML")),
                "should refuse {path}: {page}"
            );
        }
    }

    /// resolve_entry (what the registry publisher attests) returns the same
    /// tip, tree path, and bytes that serve returns as the response body.
    #[test]
    fn resolve_entry_matches_served_bytes() {
        store::create_repo("site2").unwrap();
        crate::mirror::ungated_for_tests("site2");
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

    /// The JS port (`readPage` in core/verifier.js) refuses the same pages,
    /// for the same reason: `node tools/walk-fuzz.mjs --rust` writes random
    /// pages with the port's verdicts, as `<hex page> <hex reason>` lines,
    /// names the file in WALK_FUZZ and runs this.
    #[test]
    #[ignore = "run by tools/walk-fuzz.mjs --rust"]
    fn agrees_with_the_js_port_on_random_pages() {
        let path = std::env::var("WALK_FUZZ").expect("WALK_FUZZ names the file walk-fuzz.mjs wrote");
        let unhex = |h: &str| -> Vec<u8> {
            (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
        };
        for line in std::fs::read_to_string(path).unwrap().lines() {
            let (page, js) = line.split_once(' ').unwrap();
            let (page, js) = (unhex(page), String::from_utf8(unhex(js)).unwrap());
            let rs = unverifiable_subresource("index.html", &page).unwrap_or_default();
            assert_eq!(rs, js, "on {:?}", String::from_utf8_lossy(&page));
        }
    }
}
