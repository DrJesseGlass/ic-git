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
use core::ops::Range;
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
