#!/usr/bin/env node
// F2 rung one (VISION.md section 2): the client-side verifier, as a CLI.
//
// Checks that what the ic-git canister serves is what the on-chain
// ProvenanceRegistry attests, from the user's own trust domain:
//
//   A. served /site/<repo>/<path> carries X-Ic-Git-Commit equal to the
//      registry entry's commit (the canister's on-chain attestation);
//   B. sha256 of the artifact equals the registry entry's bundleHash;
//   C. (--contract) the deployed runtime bytecode is a trailing slice of
//      the attested creation bytecode (advisory: constructors that write
//      immutables legitimately transform it);
//   D. (if git is installed) an independent `git clone` of the repo from
//      the canister contains that commit, and the blob at <commit>:<path>
//      is byte-identical to what was served.
//   E. (site records) the served entrypoint's own markup references are
//      enforceable -- a port of the canister's site::unverifiable_subresource.
//      A matching hash on a page that pulls un-integrity'd code is a FAILED
//      verification, never a passed one (docs/ATTESTATION.md, step 1): this
//      record attests ONE blob, so a subresource without SRI is covered by
//      nothing and a hostile gateway can swap it while A-D all pass. Checked
//      here independently because the publish-time guard is not retroactive:
//      records written before it shipped may cover pages that fail it.
//
// Zero dependencies (node >= 18: fetch + crypto). The one piece of
// precomputation is the registry getter's 4-byte selector, because node has
// no keccak256: get(string) -> 0x693ec85e. Recompute it yourself with any
// keccak tool; the registry source is itself cloneable from the canister
// (repo "registry") and attested in the same registry it serves.
//
// The registry stores one entry per key STRING, and the canister writes two
// kinds of record with incompatible bundleHash semantics: a deploy-artifact
// record under "<repo>" (sha256 of decoded contract bytecode) and a served-site
// record under "<repo>#site" (sha256 of the served bytes). --record picks one;
// the default resolves it (see resolveRecord below) so a repo that has only one
// of them just works, and a repo that has both is never checked against the
// wrong one.
//
// Usage:
//   node tools/verify.mjs <repo> <path> [--contract 0x...]
//     [--record auto|site|deploy]
//     [--canister umobs-yiaaa-aaaab-agyrq-cai]
//     [--registry 0xa1362DAda583c56a395D305a8C7A458E0B62A209]
//     [--rpc https://ethereum-sepolia-rpc.publicnode.com]

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const GET_SELECTOR = "693ec85e"; // keccak256("get(string)")[..4]
const SITE_SUFFIX = "#site"; // must match provenance.rs::SITE_KEY_SUFFIX

const args = process.argv.slice(2);
const positional = [];
const opts = {
  canister: "umobs-yiaaa-aaaab-agyrq-cai",
  registry: "0xa1362DAda583c56a395D305a8C7A458E0B62A209",
  rpc: "https://ethereum-sepolia-rpc.publicnode.com",
  contract: null,
  record: "auto",
};
for (let i = 0; i < args.length; i++) {
  if (args[i].startsWith("--")) {
    opts[args[i].slice(2)] = args[++i];
  } else {
    positional.push(args[i]);
  }
}
const [repo, path] = positional;
if (!repo || !path) {
  console.error("usage: verify.mjs <repo> <path> [--contract 0x...] [--record auto|site|deploy] [--canister id] [--registry 0x...] [--rpc url]");
  process.exit(2);
}
if (!["auto", "site", "deploy"].includes(opts.record)) {
  console.error(`--record must be auto, site, or deploy (got "${opts.record}")`);
  process.exit(2);
}
const gateway = `https://${opts.canister}.raw.icp0.io`;

let failures = 0;
const report = (ok, label, detail) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` -- ${detail}` : ""}`);
  if (!ok) failures++;
};
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

// --- entrypoint reference scan (check E) -------------------------------------
// Port of canisters/git/src/site.rs::unverifiable_subresource; the two must
// track each other. Returns a reason string when the entrypoint names a
// subresource the browser will not enforce, else null. Same bias as the
// canister: every ambiguity refuses, because a false refusal costs one edit
// and a false accept reports "verified" over swappable code.

// === shared: unverifiableSubresource ===
// loader/index.html carries a byte-identical copy of this block
// (tools/loader-test.mjs checks it); edit both or neither.
const isWs = (c) => " \t\n\r\f".includes(c); // Rust is_ascii_whitespace

// Where a tag name starting at `from` ends as the tokenizer reads it: at
// whitespace, `/` or `>` (`<a"b='>` is one tag; `<script-x>` is no script).
function tagNameEnd(hay, from) {
  let e = from;
  while (e < hay.length && !isWs(hay[e]) && hay[e] !== "/" && hay[e] !== ">") e++;
  return e;
}

// Where a comment opened at `lt` ends (the offset just past it), as the
// browser's tokenizer ends it: an empty comment (the opener followed by `>`
// or `->`) at once, else the first `-->` or `--!>`. -1: it runs to the end,
// and nothing after is markup.
//
// The comment opener is written "\x3c!--" throughout this block, never
// literally: the block also runs inside the loader's <script>, where a
// literal one puts the HTML parser in the script-escaped state, and a later
// "<script" in this code then keeps the element's real end tag from ending
// it -- the page fails to parse (tools/loader-test.mjs checks this).
function commentEnd(hay, lt) {
  if (hay.startsWith("\x3c!-->", lt)) return lt + 5;
  if (hay.startsWith("\x3c!--->", lt)) return lt + 6;
  const ends = [["-->", 3], ["--!>", 4]]
    .map(([m, n]) => { const p = hay.indexOf(m, lt + 4); return p === -1 ? -1 : p + n; })
    .filter((e) => e !== -1);
  return ends.length ? Math.min(...ends) : -1;
}

// Offset of the end tag closing raw-text element `tag`: the first `</tag`
// followed by whitespace, `/` or `>`. -1 when there is none.
function rawTextEnd(hay, from, tag) {
  const close = "</" + tag;
  for (let at = from; ; ) {
    const p = hay.indexOf(close, at);
    if (p === -1) return -1;
    const c = hay[p + close.length];
    if (c === undefined) return -1;
    if (isWs(c) || c === "/" || c === ">") return p;
    at = p + close.length;
  }
}

// The tokens of an integrity value the browser will enforce, as the CSP
// sources that pin them: sha256/384/512 + base64, options after `?` dropped.
// The SRI spec makes the browser IGNORE metadata that parses to an empty
// set -- the resource then loads with no check at all -- so presence alone
// proves nothing, and a token counts only if the browser's grammar would
// KEEP it: padding is trailing only, two at most, never the whole value
// (`sha384-====` is discarded). Like the canister's integrity_enforceable,
// a strict subset of that grammar -- a token discarded here that the browser
// keeps costs one edit -- and `value` is the attribute as the page wrote
// it, never lowercased: Chrome and Firefox both discard an algorithm in any
// other case, so `SHA384-...` loads unchecked.
const integritySources = (value) =>
  value.split(/[ \t\n\r\f]+/).flatMap((tok) => {
    const m = /^(sha(?:256|384|512)-[a-zA-Z0-9+/]+={0,2})(?:\?.*)?$/.exec(tok);
    return m ? ["'" + m[1] + "'"] : [];
  });

// Whether URL attribute `name` runs script when followed: a `javascript:`
// URL, which the pinned policy refuses. The browser decodes character
// references and drops tabs, newlines, and leading spaces and controls
// before reading the scheme; a reference before the first `/`, `?` or `#`
// could spell one, so it is refused rather than decoded. Port of the
// canister's script_url.
function scriptUrl(tag, name, value) {
  const m = /[/?#]/.exec(value);
  const head = m ? m.index : value.length;
  if (value.slice(0, head).includes("&")) {
    return `<${tag} ${name}=...> holds a character reference where a URL scheme could be`;
  }
  const cleaned = value.replace(/[\t\n\r]/g, "").replace(/^[\x00-\x20]+/, "");
  if (cleaned.startsWith("javascript:")) {
    return `<${tag} ${name}="javascript:..."> runs script from a URL, which the pinned policy refuses`;
  }
  return null;
}

// Why inline style text `css` (lowercased) cannot be pinned, or null: an
// `@import` loads a stylesheet no hash admits. CSS decodes an escape inside
// an at-rule's name and this scanner does not, so a name holding one is
// refused rather than compared wrong; an `@` that is itself escaped (as in
// a selector) starts no at-rule. Port of the canister's style_import.
function styleImport(css) {
  if (css.includes("@import")) {
    return "<style> holds an @import, which the pinned policy refuses; inline what it imports";
  }
  if (/(?:^|[^\\])@[a-z0-9_-]*\\/.test(css)) {
    return "<style> holds an at-rule whose name is escaped, where an @import could be; write it plainly";
  }
  return null;
}

// Start tags that end an <svg> or <math> (the HTML parser's list; `font`
// only with some attributes there, always here), and the elements inside
// one whose content is parsed as HTML.
const BREAKOUT = ("b big blockquote body br center code dd div dl dt em embed font h1 h2 h3 h4 h5 h6 head hr i img li listing "
  + "menu meta nobr ol p pre ruby s small span strong strike sub sup table tt u ul var").split(" ");
const INTEGRATION = ["foreignobject", "desc", "title", "mi", "mo", "mn", "ms", "mtext", "annotation-xml"];
// Elements whose body the parser reads as text, to their end tag.
const RAW_TEXT = ["script", "style", "textarea", "title", "xmp", "noembed", "noframes", "noscript"];
const JS_TYPES = ("application/ecmascript application/javascript application/x-ecmascript application/x-javascript "
  + "text/ecmascript text/javascript text/javascript1.0 text/javascript1.1 text/javascript1.2 text/javascript1.3 "
  + "text/javascript1.4 text/javascript1.5 text/jscript text/livescript text/x-ecmascript text/x-javascript").split(" ");

// What the browser makes of a <script> with these attributes ("prepare the
// script element"): "classic", "module", "importmap" or "speculationrules",
// or null for one it does nothing with -- a data block, a nomodule script,
// a handler for another event. `get` returns an attribute's lowercased
// value. Port of the canister's script_kind.
function scriptKind(get) {
  const strip = (s) => s.replace(/^[ \t\n\f\r]+|[ \t\n\f\r]+$/g, "");
  const type = get("type") !== undefined ? (get("type") === "" ? "text/javascript" : strip(get("type")))
    : get("language") ? "text/" + get("language")
    : "text/javascript";
  if (["module", "importmap", "speculationrules"].includes(type)) return type;
  if (!JS_TYPES.includes(type) || get("nomodule") !== undefined) return null;
  if (get("for") !== undefined && get("event") !== undefined
    && !(strip(get("for")) === "window" && ["onload", "onload()"].includes(strip(get("event"))))) return null;
  return "classic";
}

// Reads a page as the browser's HTML parser will, tag by tag. Returns
// { why }: why its hash would not prove the page, or why the extensions'
// pinned policy could not run it. Else { why: null, scripts, styles, open }:
// what that policy pins -- each a CSP source, or { text } to pin by hash --
// and whether the page ends inside an <svg>, <math> or <select>. One walk
// decides both, so a page check E accepts is a page derivePolicy pins.
// Port of the canister's read_page, which has the reasoning; the two must
// refuse the same pages.
function readPage(page) {
  // The parser turns CRLF and CR into LF before a script's text exists,
  // and the text is what a hash pins.
  const text = page.replace(/\r\n?/g, "\n");
  // ASCII-only lowercasing, mirroring the canister's to_ascii_lowercase.
  const hay = text.replace(/[A-Z]/g, (c) => c.toLowerCase());
  const scripts = [], styles = [];
  const lost = (where) => ({ why: `cannot follow the page after ${where}: how the browser parses from there is ambiguous` });

  // Tokenize one tag's attributes the way the browser does: a new attribute
  // may begin after whitespace, `/`, or a closing quote; quotes delimit a
  // value only immediately after `=`; an unquoted value ends at whitespace
  // or `>`. First occurrence of a name wins, and a value is kept as where
  // it lies. Self-closing as the tokenizer has it: a `/` right before the
  // `>`, outside an unquoted value. Returns {attrs, end, selfClosing}, or
  // null when the tag never closes.
  const parseTag = (from) => {
    const attrs = new Map();
    for (let i = from; ; ) {
      let slash = false;
      while (i < hay.length && (isWs(hay[i]) || hay[i] === "/")) slash = hay[i++] === "/";
      if (i >= hay.length) return null;
      if (hay[i] === ">") return { attrs, end: i, selfClosing: slash };
      const nameStart = i;
      if (hay[i] === "=") i++; // a leading `=` is part of the name
      while (i < hay.length && !isWs(hay[i]) && !"/=>".includes(hay[i])) i++;
      const attrName = hay.slice(nameStart, i);
      let j = i, value = [i, i];
      while (j < hay.length && isWs(hay[j])) j++;
      if (hay[j] === "=") {
        j++;
        while (j < hay.length && isWs(hay[j])) j++;
        if (j >= hay.length) return null;
        if (hay[j] === '"' || hay[j] === "'") {
          const ve = hay.indexOf(hay[j], j + 1);
          if (ve === -1) return null;
          value = [j + 1, ve];
          j = ve + 1;
        } else {
          const vs = j;
          while (j < hay.length && !isWs(hay[j]) && hay[j] !== ">") j++;
          value = [vs, j];
        }
        i = j;
      }
      if (!attrs.has(attrName)) attrs.set(attrName, value);
    }
  };

  // `foreign`: the elements open inside an <svg> or <math>, outermost
  // first, or null outside one. `select`: inside a <select>. `templates`:
  // how many <template>s are open.
  let foreign = null, select = false, templates = 0;
  for (let i = 0; ; ) {
    const lt = hay.indexOf("<", i);
    if (lt === -1) break;
    if (hay.startsWith("\x3c!--", lt)) {
      const end = commentEnd(hay, lt);
      if (end === -1) break;
      i = end;
      continue;
    }
    if (foreign && text.startsWith("<![CDATA[", lt)) {
      const end = hay.indexOf("]]>", lt);
      if (end === -1) break;
      i = end + 3;
      continue;
    }
    const c = hay[lt + 1] ?? "";
    if (!/[a-z]/.test(c)) {
      if (c === "/" && /[a-z]/.test(hay[lt + 2] ?? "")) {
        // An end tag, its attributes tokenized like a start tag's.
        const nameEnd = tagNameEnd(hay, lt + 2);
        const name = hay.slice(lt + 2, nameEnd);
        const t = parseTag(nameEnd);
        if (t === null) break;
        i = t.end + 1;
        if (foreign) {
          // It closes the nearest open element of its name; one that
          // matches none is handled by the HTML around the <svg>.
          const open = foreign.lastIndexOf(name);
          if (open === -1) return lost(`</${name}> inside <svg> or <math>`);
          foreign.length = open;
          if (!open) foreign = null;
        } else if (select) {
          if (name === "select") select = false;
          else if (name !== "option" && name !== "optgroup") return lost(`</${name}> inside <select>`);
        } else if (name === "template" && templates) {
          templates--;
        }
      } else if (c === "/" || c === "!" || c === "?") {
        // A doctype or bogus comment: it ends at its first `>`.
        const gt = hay.indexOf(">", lt + 1);
        if (gt === -1) break;
        i = gt + 1;
      } else {
        i = lt + 1; // a stray `<` is text
      }
      continue;
    }
    const nameEnd = tagNameEnd(hay, lt + 1);
    const name = hay.slice(lt + 1, nameEnd);
    const t = parseTag(nameEnd);
    if (t === null) return { why: `<${name}> tag is never closed` };
    i = t.end + 1;
    // An attribute's value: lowercased, or as the page wrote it.
    const get = (n) => { const r = t.attrs.get(n); return r && hay.slice(r[0], r[1]); };
    const written = (n) => { const r = t.attrs.get(n); return r ? text.slice(r[0], r[1]) : ""; };
    // The browser decodes character references in values; this scanner does
    // not, so a keyword value hiding one is refused, not compared wrong.
    const charRef = (an) =>
      (get(an) ?? "").includes("&")
        ? `<${name} ${an}=...> value holds a character reference this scanner does not decode`
        : null;

    // What the pinned policy refuses, on any element.
    for (const n of t.attrs.keys()) {
      if (n.length > 2 && n.startsWith("on")) {
        return { why: `<${name} ${n}=...> is an inline event handler, which the pinned policy refuses; attach it from a script` };
      }
    }
    if (get("style") !== undefined) {
      return { why: `<${name} style=...> is an inline style attribute, which the pinned policy refuses; move it into a <style>` };
    }
    for (const an of ["href", "xlink:href", "action", "formaction"]) {
      const why = get(an) === undefined ? null : scriptUrl(name, an, get(an));
      if (why) return { why };
    }
    if (["iframe", "frame", "frameset", "object", "embed"].includes(name)) {
      return { why: `<${name}> loads content SRI cannot cover; inline the content instead` };
    }
    if (name === "base" && get("href") !== undefined) {
      return { why: "<base href=...> relocates every relative URL on the page" };
    }
    if (name === "meta" && get("http-equiv") !== undefined) {
      if (charRef("http-equiv")) return { why: charRef("http-equiv") };
      if (get("http-equiv").trim() === "refresh") {
        return { why: "<meta http-equiv=refresh> navigates away from the attested page" };
      }
    }
    if (name === "link") {
      if (charRef("rel")) return { why: charRef("rel") };
      const rels = (get("rel") ?? "").split(/[ \t\n\r\f]+/);
      // The pinned policy pins styles by the hash of their text, and Chrome
      // takes no hash for an external stylesheet.
      if (get("href") !== undefined && rels.includes("stylesheet")) {
        return { why: "<link rel=stylesheet> is an external stylesheet, which the pinned policy refuses; inline it as a <style>" };
      }
      if (get("href") !== undefined && rels.includes("modulepreload")) {
        const pins = integritySources(written("integrity"));
        if (!pins.length) return { why: "<link rel=modulepreload> has no enforceable integrity=" };
        if (!foreign) scripts.push(...pins);
      }
    }

    if (foreign) {
      if (name === "script" || name === "style") {
        return { why: `<${name}> inside <svg> or <math> cannot be pinned: its text is markup there` };
      }
      if (BREAKOUT.includes(name)) return lost(`<${name}> inside <svg> or <math>`);
      if (t.selfClosing) continue;
      if (INTEGRATION.includes(name)) {
        // Its content is parsed as HTML; followed only while that is text.
        const next = hay.indexOf("<", i);
        if (next === -1) break;
        if (!hay.startsWith("</" + name, next) || tagNameEnd(hay, next + 2) !== next + 2 + name.length) {
          return lost(`markup in <${name}> inside <svg> or <math>`);
        }
      }
      foreign.push(name);
      continue;
    }
    if (select) {
      // Browsers agree on a select that holds only options; on anything
      // else in one, the old and the new select parsers differ.
      if (!["option", "optgroup", "hr"].includes(name)) return lost(`<${name}> inside <select>`);
      continue;
    }
    if (name === "svg" || name === "math") { if (!t.selfClosing) foreign = [name]; continue; }
    if (name === "select") { select = true; continue; }
    if (name === "plaintext") break; // the rest of the page is text
    if (name === "template") { templates++; continue; }
    // As the first element in a template, a <col> leaves its parser
    // ignoring every tag, the ones this would skip a body for among them.
    if (name === "col" && templates) return lost("<col> inside <template>");
    if (!RAW_TEXT.includes(name)) continue;

    // Raw text: the browser reads everything to the end tag as text.
    const end = rawTextEnd(hay, i, name);
    if (end === -1) return { why: `<${name}> is never closed` };
    const body = hay.slice(i, end);
    if (name === "script") {
      for (const an of ["type", "language", "for", "event"]) {
        if (charRef(an)) return { why: charRef(an) };
      }
      const kind = scriptKind(get);
      const pins = integritySources(written("integrity"));
      if (get("src") !== undefined) {
        // Asked of a data block too: a type misread as one would otherwise
        // load unchecked.
        if (!pins.length) {
          return { why: "<script src=...> has no enforceable integrity= (missing, empty, or not sha256/384/512-base64)" };
        }
      } else if (kind === "module") {
        return { why: "inline <script type=module> imports files SRI cannot cover; use a classic inline script or src= with integrity=" };
      }
      // Chrome loads the pages such rules name and runs their scripts, on
      // this origin and unasked (a prerender).
      if (kind === "speculationrules") {
        return { why: "<script type=speculationrules> has the browser load pages no record covers" };
      }
      // After a comment opener, a nested script start tag makes the parser
      // read past the first end tag (the double-escaped state).
      const esc = body.indexOf("\x3c!--");
      if (esc !== -1 && /<script[ \t\n\r\f\/>]/.test(body.slice(esc))) {
        return { why: "<script> holds a comment opener and then a script start tag: where it ends is ambiguous" };
      }
      if (kind !== null) {
        // A template's content is inert, unless the template declares a
        // shadow root; and which end tag closes one is not followed.
        if (templates) return { why: "<script> inside <template> cannot be pinned: whether it runs is ambiguous" };
        scripts.push(...(get("src") !== undefined ? pins : [{ text: text.slice(i, end) }]));
      }
    }
    if (name === "style") {
      const why = styleImport(body);
      if (why) return { why };
      styles.push({ text: text.slice(i, end) });
    }
    if (name === "noscript") {
      // With scripting off the body is markup: read it as a page of its
      // own. One that ends inside an element this follows, or in a comment,
      // would run on past the end tag, where this does not follow.
      const inner = readPage(text.slice(i, end));
      if (inner.why) return inner;
      if (inner.open) return { why: "<noscript> ends inside an <svg>, <math> or <select>" };
      const p = body.lastIndexOf("\x3c!--");
      if (p !== -1 && commentEnd(body, p) === -1) return { why: "<noscript> holds a comment that runs past its end" };
    }
    i = end;
  }
  return { why: null, scripts, styles, open: foreign !== null || select };
}

function unverifiableSubresource(servedPath, body) {
  // Gate on the served file's NAME, case-insensitively; an extensionless
  // blob could be a page, so it is read rather than skipped.
  const name = servedPath.split("/").pop();
  const dot = name.lastIndexOf(".");
  const ext = dot === -1 ? null : name.slice(dot + 1).toLowerCase();
  if (ext === "svg" || ext === "xhtml") {
    return `a .${ext} entrypoint is XML, where a stylesheet instruction, a prefixed element or an entity can load code this scan (an HTML one) does not see; publish an .html page -- an <svg> can be inline in it`;
  }
  if (ext !== null && ext !== "html" && ext !== "htm") return null;
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    return "entrypoint is not valid UTF-8, so its references cannot be read";
  }
  return readPage(text).why;
}

// === end shared ===

// ABI-encode get(string repo): selector, offset word, length word, padded data.
function encodeGet(repo) {
  const utf8 = Buffer.from(repo, "utf8");
  const pad = Buffer.alloc((32 - (utf8.length % 32)) % 32);
  const word = (n) => Buffer.from(n.toString(16).padStart(64, "0"), "hex");
  return (
    "0x" +
    GET_SELECTOR +
    Buffer.concat([word(0x20), word(utf8.length), utf8, pad]).toString("hex")
  );
}

async function rpc(method, params) {
  const res = await fetch(opts.rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

// Decode get(string) -> (bytes20 commit, bytes32 bundleHash, uint64 updatedAt).
// An unwritten key returns three zero words rather than reverting, so an
// all-zero commit is the "no such record" signal.
function decodeGet(callRet) {
  const ret = callRet.slice(2);
  return {
    commit: ret.slice(0, 40), // bytes20, left-aligned in word 0
    bundleHash: ret.slice(64, 128), // bytes32, word 1
    updatedAt: parseInt(ret.slice(128, 192), 16), // uint64, word 2
    present: !/^0*$/.test(ret.slice(0, 40)),
  };
}

// --- gather ------------------------------------------------------------------

// The two record keys, named once: the key that is read and the key that is
// reported must not be able to drift apart.
const keys = { site: repo + SITE_SUFFIX, deploy: repo };

// Both registry records and the served artifact are independent reads; fetch
// them concurrently. Reading both keys costs one extra eth_call and no extra
// wall clock, and is what lets --record auto tell a site-only repo from a
// deploy-only one.
const [siteRet, deployRet, servedRes] = await Promise.all([
  rpc("eth_call", [{ to: opts.registry, data: encodeGet(keys.site) }, "latest"]),
  rpc("eth_call", [{ to: opts.registry, data: encodeGet(keys.deploy) }, "latest"]),
  fetch(`${gateway}/site/${repo}/${path}`),
]);
const records = { site: decodeGet(siteRet), deploy: decodeGet(deployRet) };

// What the canister actually served.
if (!servedRes.ok) {
  console.error(`fetch ${gateway}/site/${repo}/${path}: HTTP ${servedRes.status}`);
  process.exit(1);
}
const served = Buffer.from(await servedRes.arrayBuffer());

// A deploy record attests sha256 of the DECODED contract bytecode, so check B
// needs the hex form for that kind. This is a property of the record, never of
// the artifact: a site page whose entire content happens to be an even number
// of hex characters is still hashed raw by the publisher.
const servedText = served.toString("utf8").trim();
const hexBody = servedText.startsWith("0x") ? servedText.slice(2) : servedText;
const isHexText = /^[0-9a-fA-F]+$/.test(hexBody) && hexBody.length % 2 === 0;

function resolveRecord() {
  if (opts.record !== "auto") return opts.record;
  if (records.site.present && !records.deploy.present) return "site";
  if (records.deploy.present && !records.site.present) return "deploy";
  if (records.site.present && records.deploy.present) {
    // Both exist (a repo that deploys a contract AND serves a site). Guessing
    // from the artifact's shape gets a hex-looking site page wrong, and picking
    // whichever record happens to match would turn check B into "matches
    // something". Ask instead: only the caller knows which one they meant.
    console.error(`"${repo}" has both a site and a deploy record; pass --record site or --record deploy`);
    process.exit(2);
  }
  // Neither present. Pick by artifact form purely so the error below names the
  // key the caller most likely meant.
  return isHexText ? "deploy" : "site";
}
const kind = resolveRecord();
const recordKey = keys[kind];
const record = records[kind];
if (!record.present) {
  console.error(`no registry entry for key "${recordKey}" at ${opts.registry}`);
  const other = kind === "site" ? "deploy" : "site";
  if (records[other].present) {
    console.error(`(a ${other} record exists for this repo; try --record ${other})`);
  }
  process.exit(1);
}
const { commit: registryCommit, bundleHash: registryBundleHash, updatedAt } = record;
console.log(`registry: key "${recordKey}" (${kind} record)`);
console.log(`registry: commit ${registryCommit}`);
console.log(`registry: bundleHash ${registryBundleHash}`);
console.log(`registry: updatedAt ${new Date(updatedAt * 1000).toISOString()}`);

const servedCommit = servedRes.headers.get("x-ic-git-commit") ?? "";
// Where the served bytes live in the commit tree (site root + index.html
// fallback applied by the canister); the git-clone check must use this, not
// the URL path. Fallback for canisters predating the header.
const servedPath = servedRes.headers.get("x-ic-git-path") ?? path;
console.log(`served: ${served.length} bytes, X-Ic-Git-Commit ${servedCommit}, tree path ${servedPath}`);

// --- checks ------------------------------------------------------------------

// A. The served response claims exactly the attested commit.
const commitOk = servedCommit === registryCommit;
report(commitOk, "A: served commit == registry commit", commitOk ? "" : `served ${servedCommit || "(none)"}`);

// B. The artifact hashes to the attested bundleHash, hashed the way THIS
// record's publisher hashed it: provenance::deploy_record hashes the decoded
// contract bytecode, provenance::site_record hashes the served bytes exactly
// as delivered (both then write through evm::registry_publish_record).
// Choosing by the artifact's shape instead would mis-hash a site
// page that is all hex characters and report a correctly served page as
// unverified.
const wantsHex = kind === "deploy";
const hashed = wantsHex && isHexText ? Buffer.from(hexBody, "hex") : served;
const artifactHash = sha256(hashed);
const hashOk = artifactHash === registryBundleHash;
report(
  hashOk,
  `B: sha256(${wantsHex ? "hex-decoded" : "raw"} artifact) == registry bundleHash`,
  hashOk
    ? ""
    : wantsHex && !isHexText
      ? "a deploy record attests hex-decoded bytecode, but the served artifact is not hex text"
      : `artifact ${artifactHash}`
);

// C. Advisory: on-chain runtime code should be a trailing slice of the
// attested creation bytecode. Only a deploy record attests creation bytecode;
// against a site record `hashed` is page content, so comparing it would be
// meaningless rather than merely failing.
if (opts.contract && !wantsHex) {
  report(false, "C: --contract needs a deploy record", `resolved the ${kind} record; pass --record deploy`);
} else if (opts.contract) {
  const code = (await rpc("eth_getCode", [opts.contract, "latest"])).slice(2).toLowerCase();
  const creation = hashed.toString("hex").toLowerCase();
  report(
    code.length > 0 && creation.endsWith(code),
    "C: eth_getCode(contract) is a trailing slice of the creation bytecode",
    code.length === 0 ? "no code at address" : ""
  );
}

// D. Independent re-derivation: clone the repo from the canister and compare
// the blob at <commit>:<path> with what was served.
try {
  execFileSync("git", ["--version"], { stdio: "ignore" });
  const dir = mkdtempSync(join(tmpdir(), "icgit-verify-"));
  try {
    execFileSync(
      "git",
      ["clone", "--quiet", "--no-checkout", `${gateway}/${repo}.git`, dir],
      { stdio: ["ignore", "ignore", "pipe"] }
    );
    const blob = execFileSync(
      "git",
      ["-C", dir, "show", `${servedCommit}:${servedPath}`],
      { maxBuffer: 64 * 1024 * 1024 }
    );
    report(
      Buffer.compare(blob, served) === 0,
      "D: git clone reproduces the served bytes at the attested commit"
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
} catch (e) {
  report(false, "D: git clone reproduces the served bytes", e.message.split("\n")[0]);
}

// E. A matching hash proves the entrypoint, not the page. Only meaningful for
// a site record -- a deploy record's artifact is bytecode, not a page.
if (kind === "site") {
  const reason = unverifiableSubresource(servedPath, served);
  report(
    reason === null,
    "E: entrypoint references are enforceable (self-contained or SRI-pinned)",
    reason ?? ""
  );
}

console.log(failures === 0 ? "\nVERIFIED" : `\nNOT VERIFIED (${failures} failing check${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
