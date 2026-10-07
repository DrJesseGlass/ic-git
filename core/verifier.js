// === core ===
// Verification with no DOM: Verifier.verify(options) -> result,
// Verifier.derivePolicy(bytes, url) -> the CSP that pins a verified page's
// scripts and styles (docs/EXTENSION.md), and
// Verifier.readCanisterState(canisterId, options) -> a canister's module
// hash and controllers out of a certificate the IC signed (docs/CERTIFIED.md),
// and Verifier.checkBackends(repo, options) -> which canisters a verified
// page may call, judged from those reads (docs/GOVERNANCE.md, section 4).
// The last two need core/bls12-381.js loaded first (a vendored verifier,
// tools/vendor-bls.mjs); without it a certificate is reported unverified,
// never trusted.
//
// The source of truth is core/verifier.js. loader/index.html carries it
// inline, byte-identical, because the loader must stay one file (its hash
// is its record); `node tools/sync-core.mjs` copies it in, and
// tools/loader-test.mjs fails when the two differ. It is a classic script,
// not a module, so the loader can inline it, an extension's background
// worker can importScripts it, and node can evaluate it. It also runs
// inside the loader's <script>, so its text must never hold the comment
// opener or a script end tag (see the scanner block below).
const Verifier = (() => {
  'use strict';
  const te = new TextEncoder(), td = new TextDecoder();
  // The IC's DER wrapping of a 96-byte BLS12-381 G2 public key: a fixed
  // 37-byte prefix, the algorithm identifier, then the key.
  const DER_PREFIX = '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100';
  const DEFAULTS = {
    canister: 'umobs-yiaaa-aaaab-agyrq-cai',
    registry: '0xa1362DAda583c56a395D305a8C7A458E0B62A209',
    chainId: 11155111, // Sepolia
    rpc: 'https://ethereum-sepolia-rpc.publicnode.com',
    icApi: 'https://icp-api.io',
    provider: null, // an EIP-1193 provider (window.ethereum), preferred for the registry read
    providerName: 'wallet', // how a read through it is reported
    providerOnly: false, // true: a provider that fails or is on another chain fails the read
    // The NNS root public key (DER, 133 bytes), the one key every mainnet
    // certificate chains to. Pinned: a reader that fetched it from the
    // network it is checking would prove nothing. /api/v2/status reports
    // the same bytes; tools/certified-test.mjs compares them.
    rootKey: DER_PREFIX
      + '814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc534'
      + '1583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae',
    // How old a certificate may be before readCanisterState reports it
    // stale. Stale is a warning, not a failure: the certificate is still
    // the IC's word, only about an earlier moment.
    freshMs: 5 * 60_000,
    now: null, // Date.now() unless a test says otherwise
  };
  const GET_SELECTOR = '693ec85e'; // keccak256("get(string)")[..4], as in tools/verify.mjs
  const SITE_SUFFIX = '#site'; // provenance.rs::SITE_KEY_SUFFIX
  const APP_SUFFIX = '#app'; // provenance.rs::APP_KEY_SUFFIX: (commit, sha256 of the installed module)
  // The NNS root canister: the one controller of the system canisters a page
  // may call (the ledgers, the cycles minting canister).
  const NNS_ROOT = 'r7inp-6aaaa-aaaaa-aaabq-cai';
  const SYSTEM = {
    'ryjl3-tyaaa-aaaaa-aaaba-cai': 'the ICP ledger',
    'um5iw-rqaaa-aaaaq-qaaba-cai': 'the cycles ledger',
    'rkp4c-7iaaa-aaaaa-aaaca-cai': 'the cycles minting canister',
  };
  const TIMEOUT_MS = 15_000;

  const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
  const digest = async (alg, b) => hex(new Uint8Array(await crypto.subtle.digest(alg, b)));
  const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

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

  // --- registry: get(string) -> (bytes20 commit, bytes32 bundleHash, uint64 updatedAt)
  function encodeGet(key) {
    const u = te.encode(key), word = n => n.toString(16).padStart(64, '0');
    return '0x' + GET_SELECTOR + word(32) + word(u.length) + hex(u).padEnd(Math.ceil(u.length / 32) * 64, '0');
  }
  // An unwritten key returns zero words rather than reverting.
  function decodeGet(ret) {
    const r = (ret || '').replace(/^0x/, '');
    if (r.length < 192) return { present: false };
    return {
      present: !/^0+$/.test(r.slice(0, 40)),
      commit: r.slice(0, 40),
      bundleHash: r.slice(64, 128),
      updatedAt: parseInt(r.slice(128, 192), 16),
    };
  }
  async function rpc(o, method, params) {
    const r = await o.fetch(o.rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(TIMEOUT_MS) });
    const body = await r.json();
    if (body.error) throw new Error(method + ': ' + (body.error.message || JSON.stringify(body.error)));
    return body.result;
  }
  // The wallet's provider first: then the record is read through the node
  // the user chose. It needs no account access, only eth_call.
  async function readRecord(o, key) {
    const params = [{ to: o.registry, data: encodeGet(key) }, 'latest'];
    let note = o.provider ? '' : 'no wallet on this page';
    if (o.provider) {
      try {
        const chain = parseInt(await o.provider.request({ method: 'eth_chainId' }), 16);
        if (chain === o.chainId) return { ret: await o.provider.request({ method: 'eth_call', params }), via: o.providerName };
        note = o.providerName + ' is on chain ' + chain + ', not ' + o.chainId;
      } catch (e) {
        note = o.providerName + ' read failed: ' + (e.message || e);
      }
      // The extension reads through two endpoints that must agree; falling
      // back to one would quietly drop that requirement.
      if (o.providerOnly) throw new Error(note);
    }
    return { ret: await rpc(o, 'eth_call', params), via: new URL(o.rpc).host, note };
  }

  // --- IC: anonymous queries. Replies are one replica's unsigned word, which
  // is enough here: every object read is checked against its own hash.
  const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
  const CRC = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc32 = b => { let c = 0xffffffff; for (const x of b) c = CRC[(c ^ x) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  function principalBytes(text) {
    let bits = 0, val = 0; const out = [];
    for (const ch of text.toLowerCase().replace(/-/g, '')) {
      const i = B32.indexOf(ch); if (i < 0) throw new Error('bad canister id: ' + text);
      val = (val << 5) | i; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    const b = Uint8Array.from(out.slice(4));
    if (out.length <= 4 || ((out[0] << 24) | (out[1] << 16) | (out[2] << 8) | out[3]) >>> 0 !== crc32(b)) throw new Error('bad canister id checksum: ' + text);
    return b;
  }
  function principalText(bytes) {
    const c = crc32(bytes), all = Uint8Array.of(c >>> 24, (c >>> 16) & 255, (c >>> 8) & 255, c & 255, ...bytes);
    let bits = 0, val = 0, s = '';
    for (const b of all) { val = ((val << 8) | b) >>> 0; bits += 8; while (bits >= 5) { s += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
    if (bits) s += B32[(val << (5 - bits)) & 31];
    return s.match(/.{1,5}/g).join('-');
  }
  const uleb = n => { const o = []; do { let b = n & 0x7f; n = Math.floor(n / 128); if (n) b |= 0x80; o.push(b); } while (n); return o; };
  const textArg = s => { const u = te.encode(s); return Uint8Array.from([...te.encode('DIDL'), 0, 1, 0x71, ...uleb(u.length), ...u]); };
  // Candid replies: opt, vec, record over text and nat8 -- all get_object
  // and get_site return. A record decodes to its field values in id order.
  function candid(b) {
    if (td.decode(b.subarray(0, 4)) !== 'DIDL') throw new Error('reply is not candid');
    let p = 4;
    const leb = signed => { let r = 0, s = 0, x; do { x = b[p++]; r += (x & 0x7f) * 2 ** s; s += 7; } while (x & 0x80); return signed && x & 0x40 ? r - 2 ** s : r; };
    const table = [];
    for (let n = leb(); n--;) {
      const op = leb(true);
      if (op === -18 || op === -19) table.push({ op, of: leb(true) });
      else if (op === -20) { const f = []; for (let m = leb(); m--;) f.push([leb(), leb(true)]); table.push({ op, f }); }
      else throw new Error('candid: unsupported type ' + op);
    }
    const types = []; for (let n = leb(); n--;) types.push(leb(true));
    const val = t => {
      if (t === -15) { const l = leb(), s = td.decode(b.subarray(p, p + l)); p += l; return s; }
      if (t === -5) return b[p++];
      const e = table[t];
      if (e && e.op === -18) return b[p++] ? val(e.of) : null;
      if (e && e.op === -19) { const l = leb(); if (e.of === -5) { const r = b.slice(p, p + l); p += l; return r; } return Array.from({ length: l }, () => val(e.of)); }
      if (e && e.op === -20) return e.f.map(([, ft]) => val(ft));
      throw new Error('candid: cannot read type ' + t);
    };
    return types.map(val);
  }
  function cborEnc(v) {
    const out = [0xd9, 0xd9, 0xf7];
    const head = (mt, n) => { n = BigInt(n); if (n < 24n) out.push((mt << 5) | Number(n)); else { const w = n < 256n ? 1 : n < 65536n ? 2 : n < 4294967296n ? 4 : 8; out.push((mt << 5) | { 1: 24, 2: 25, 4: 26, 8: 27 }[w]); for (let i = w - 1; i >= 0; i--) out.push(Number((n >> BigInt(8 * i)) & 255n)); } };
    const item = v => {
      if (typeof v === 'bigint' || typeof v === 'number') head(0, v);
      else if (typeof v === 'string') { const u = te.encode(v); head(3, u.length); out.push(...u); }
      else if (v instanceof Uint8Array) { head(2, v.length); out.push(...v); }
      else if (Array.isArray(v)) { head(4, v.length); for (const x of v) item(x); }
      else { const k = Object.keys(v); head(5, k.length); for (const x of k) { item(x); item(v[x]); } }
    };
    item(v);
    return Uint8Array.from(out);
  }
  function cbor(b) {
    let p = 0;
    const item = () => {
      const ib = b[p++], mt = ib >> 5, ai = ib & 31;
      let n = ai;
      if (ai >= 24 && ai <= 27) { n = 0; for (let i = 0; i < 2 ** (ai - 24); i++) n = n * 256 + b[p++]; }
      else if (ai === 31 && (mt === 4 || mt === 5)) n = Infinity; // indefinite: runs to the 0xff break
      else if (ai > 27) throw new Error('cbor: unsupported length');
      const more = i => n === Infinity ? (b[p] === 0xff ? (p++, false) : true) : i < n;
      if (mt === 0) return n;
      if (mt === 1) return -1 - n;
      if (mt === 2) { const r = b.slice(p, p + n); p += n; return r; }
      if (mt === 3) { const s = td.decode(b.subarray(p, p + n)); p += n; return s; }
      if (mt === 4) { const a = []; for (let i = 0; more(i); i++) a.push(item()); return a; }
      if (mt === 5) { const o = {}; for (let i = 0; more(i); i++) { const k = item(); o[k] = item(); } return o; }
      if (mt === 6) return item();
      if (mt === 7) return ai === 21 ? true : ai === 20 ? false : null;
    };
    return item();
  }
  async function query(o, method, arg) {
    const content = { request_type: 'query', sender: Uint8Array.of(4), canister_id: principalBytes(o.canister), method_name: method, arg: textArg(arg), ingress_expiry: BigInt(Date.now() + 240_000) * 1_000_000n };
    const r = await o.fetch(o.icApi + '/api/v2/canister/' + o.canister + '/query', { method: 'POST', headers: { 'content-type': 'application/cbor' }, body: cborEnc({ content }), signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!r.ok) throw new Error(method + ': HTTP ' + r.status);
    const res = cbor(new Uint8Array(await r.arrayBuffer()));
    if (res.status !== 'replied') throw new Error(method + ': ' + (res.reject_message || res.status));
    return candid(res.reply.arg);
  }

  // --- certified reads: a canister's module hash and controllers, out of a
  // state certificate (docs/CERTIFIED.md). Unlike the queries above, whose
  // replies are checked against hashes the caller already holds, these values
  // are the IC's own word and nothing else vouches for them, so the
  // certificate's signature chain is what is checked: the subnet's key signs
  // the state root, and the NNS root key (pinned) signs the subnet's key.
  const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
  const sha256 = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
  const sep = s => concat(Uint8Array.of(s.length), te.encode(s));
  const unhex = h => Uint8Array.from(h.match(/../g), x => parseInt(x, 16));
  const unleb = b => { let r = 0n, s = 0n; for (const x of b) { r |= BigInt(x & 0x7f) << s; s += 7n; if (!(x & 0x80)) break; } return r; };
  // A hash tree as CBOR gives it: [0] empty, [1,l,r] fork, [2,label,sub]
  // labeled, [3,leaf], [4,hash] pruned. Its root hash is what is signed.
  async function treeHash(t) {
    switch (t[0]) {
      case 0: return sha256(sep('ic-hashtree-empty'));
      case 1: return sha256(concat(sep('ic-hashtree-fork'), await treeHash(t[1]), await treeHash(t[2])));
      case 2: return sha256(concat(sep('ic-hashtree-labeled'), t[1], await treeHash(t[2])));
      case 3: return sha256(concat(sep('ic-hashtree-leaf'), t[1]));
      case 4: return t[1];
      default: throw new Error('certificate: malformed hash tree');
    }
  }
  const cmpBytes = (a, b) => { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };
  // Lookup as the interface spec defines it: `found` with the leaf, `absent`
  // when the labels at some level show the path is not in the state, or
  // `unknown` when a pruned subtree hides whether it is. The three are not
  // the same answer: a missing module hash means no module is installed
  // only when the tree says so, not when it says nothing. Labels at a level
  // are sorted, and a reply prunes the siblings it was not asked for, so
  // absence is proved by the neighbours: the label falls before the first
  // labeled node, after the last, or between two adjacent ones. Anywhere
  // else a pruned node could be hiding it.
  function lookup(tree, path) {
    const flat = t => t[0] === 0 ? [] : t[0] === 1 ? [...flat(t[1]), ...flat(t[2])] : [t];
    const labeled = n => n !== undefined && n[0] === 2;
    let node = tree;
    for (const seg of path) {
      const label = typeof seg === 'string' ? te.encode(seg) : seg;
      const here = flat(node);
      const hit = here.find(n => labeled(n) && cmpBytes(n[1], label) === 0);
      if (hit) { node = hit[2]; continue; }
      const last = here[here.length - 1];
      let absent = here.length === 0
        || (labeled(here[0]) && cmpBytes(label, here[0][1]) < 0)
        || (labeled(last) && cmpBytes(last[1], label) < 0);
      for (let i = 0; !absent && i + 1 < here.length; i++) {
        absent = labeled(here[i]) && labeled(here[i + 1]) && cmpBytes(here[i][1], label) < 0 && cmpBytes(label, here[i + 1][1]) < 0;
      }
      return { status: absent ? 'absent' : 'unknown' };
    }
    // The path ends on a leaf, or it ends on something the tree does not
    // vouch for as a value: a pruned node, or a subtree. Neither is an
    // absence.
    return node[0] === 3 ? { status: 'found', value: node[1] } : { status: 'unknown' };
  }
  // The 96-byte G2 public key inside the IC's DER wrapping (DER_PREFIX).
  function blsKey(der) {
    if (der.length !== 133 || hex(der.subarray(0, 37)) !== DER_PREFIX) throw new Error('public key is not a DER-wrapped BLS12-381 G2 key');
    return der.subarray(37);
  }
  // Does `sig` (G1, 48 bytes) sign the state root under `key`? The message
  // is the domain-separated root. A signature that does not decode (not a
  // curve point) is a failed verification, not an error.
  async function signedRoot(tree, sig, key) {
    if (typeof NobleBls === 'undefined') throw new Error('BLS verifier not loaded (core/bls12-381.js)');
    const msg = concat(sep('ic-state-root'), await treeHash(tree));
    try { return NobleBls.shortSignatures.verify(sig, NobleBls.shortSignatures.hash(msg), key); } catch { return false; }
  }

  async function readCanisterState(canisterId, options) {
    const o = { ...DEFAULTS, ...options };
    o.fetch = o.fetch || globalThis.fetch.bind(globalThis);
    const now = o.now ?? Date.now();
    const checks = [];
    const check = (id, ok, label, detail) => { checks.push({ id, ok, label, detail: detail || '' }); return ok; };
    const out = { canister: canisterId, checks, certified: false, moduleHash: null, controllers: null, time: null, stale: false, subnet: null };
    const fail = (id, label, detail) => { check(id, false, label, detail); return out; };

    let cid;
    try { cid = principalBytes(canisterId); } catch (e) { return fail('C1', 'read the canister\'s certified state', e.message); }
    const paths = [['canister', cid, 'module_hash'], ['canister', cid, 'controllers']].map(p => p.map(x => typeof x === 'string' ? te.encode(x) : x));
    let cert;
    try {
      const content = { request_type: 'read_state', sender: Uint8Array.of(4), paths, ingress_expiry: BigInt(now + 240_000) * 1_000_000n };
      const r = await o.fetch(o.icApi + '/api/v2/canister/' + canisterId + '/read_state', { method: 'POST', headers: { 'content-type': 'application/cbor' }, body: cborEnc({ content }), signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const res = cbor(new Uint8Array(await r.arrayBuffer()));
      if (!(res.certificate instanceof Uint8Array)) throw new Error('reply holds no certificate');
      cert = cbor(res.certificate);
      if (!Array.isArray(cert.tree) || !(cert.signature instanceof Uint8Array)) throw new Error('certificate is malformed');
    } catch (e) {
      return fail('C1', 'read the canister\'s certified state', e.message);
    }
    check('C1', true, 'read the canister\'s certified state', 'read_state at ' + new URL(o.icApi).host);

    // The key that must have signed this certificate. A canister on an
    // application subnet comes with a delegation: a certificate signed by
    // the root key that names the subnet's key and the canister ranges it
    // speaks for. One without (an NNS canister) is signed by the root key
    // itself. Either way the chain ends at the pinned key and nowhere else.
    let key;
    try {
      key = blsKey(unhex(o.rootKey));
      if (cert.delegation) {
        const d = cert.delegation;
        if (!(d.subnet_id instanceof Uint8Array) || !(d.certificate instanceof Uint8Array)) throw new Error('delegation is malformed');
        const dc = cbor(d.certificate);
        if (dc.delegation) throw new Error('delegation certificate carries a delegation of its own, which the spec forbids');
        if (!await signedRoot(dc.tree, dc.signature, key)) throw new Error('delegation certificate is not signed by the NNS root key');
        const pk = lookup(dc.tree, ['subnet', d.subnet_id, 'public_key']);
        if (pk.status !== 'found') throw new Error('delegation certificate shows no public key for the subnet');
        const ranges = lookup(dc.tree, ['subnet', d.subnet_id, 'canister_ranges']);
        if (ranges.status !== 'found') throw new Error('delegation certificate shows no canister ranges for the subnet');
        const inRange = cbor(ranges.value).some(([lo, hi]) => cmpBytes(lo, cid) <= 0 && cmpBytes(cid, hi) <= 0);
        if (!inRange) throw new Error('the canister is outside the ranges the subnet is delegated');
        key = blsKey(pk.value);
        out.subnet = principalText(d.subnet_id);
      }
    } catch (e) {
      return fail('C2', 'the signing key is delegated by the NNS root key', e.message);
    }
    check('C2', true, 'the signing key is delegated by the NNS root key', out.subnet ? 'subnet ' + out.subnet : 'signed by the root key directly (no delegation)');

    let signed;
    try { signed = await signedRoot(cert.tree, cert.signature, key); } catch (e) { return fail('C3', 'the certificate is signed by that key', e.message); }
    if (!check('C3', signed, 'the certificate is signed by that key', signed ? 'BLS12-381 over the state root' : 'signature does not verify')) return out;

    // From here the tree is the IC's word. Time first: a certificate is a
    // statement about one moment, and an old one, however genuine, can show
    // a module since replaced.
    const t = lookup(cert.tree, ['time']);
    if (t.status !== 'found') return fail('C4', 'the certificate is dated', 'no /time in the certificate');
    out.time = Number(unleb(t.value) / 1_000_000n);
    out.stale = Math.abs(now - out.time) > o.freshMs;
    check('C4', true, 'the certificate is dated', (out.stale ? 'STALE: ' : '') + 'certified at ' + new Date(out.time).toISOString() + ', ' + Math.round((now - out.time) / 1000) + 's ago');

    const SHOWS = 'the certificate shows the canister\'s module hash and controllers';
    const mh = lookup(cert.tree, ['canister', cid, 'module_hash']);
    if (mh.status === 'unknown') return fail('C5', SHOWS, 'the module hash path is pruned from the certificate');
    out.moduleHash = mh.status === 'found' ? hex(mh.value) : null;
    const ctl = lookup(cert.tree, ['canister', cid, 'controllers']);
    if (ctl.status !== 'found') return fail('C5', SHOWS, ctl.status === 'unknown' ? 'the controllers path is pruned from the certificate' : 'no controllers in the certificate');
    try {
      const list = cbor(ctl.value);
      if (!Array.isArray(list)) throw new Error('controllers are not a list');
      out.controllers = list.map(principalText).sort();
    } catch (e) {
      return fail('C5', SHOWS, e.message);
    }
    check('C5', true, SHOWS, (out.moduleHash ? 'module ' + out.moduleHash.slice(0, 16) + '...' : 'no module installed') + ', ' + out.controllers.length + ' controller' + (out.controllers.length === 1 ? '' : 's'));
    out.certified = checks.every(c => c.ok);
    return out;
  }

  // --- backends: which canisters a verified page may call (docs/GOVERNANCE.md,
  // section 4). A page's code is verified; what it talks to is not, unless
  // that is judged too. Every judgment below rests on a certified read, so
  // nothing here takes ic-git's word for what a canister runs or who holds
  // it: ic-git's own API only names which canister is the site's backend,
  // and the registry record only says which module hash is approved.
  //
  // Kinds, in the order they are tried:
  //   system      controllers are exactly the NNS root: a ledger, the CMC.
  //   approved    controllers are exactly ic-git, and the certified module
  //               hash is the repo's <repo>#app record: a governed backend
  //               running an approved commit's build.
  //   blocked     controllers are exactly ic-git but no record approves the
  //               module it runs -- the one case a verified page must not
  //               reach, since governance promised otherwise.
  //   immutable   nobody holds it: its code can never change. Allowed.
  //   ungoverned  anyone else holds it (an owner, ic-git among others, ic-git
  //               itself today): its code is not tampered, but its holder
  //               can change it without a vote. Allowed, and said.
  //   unreadable  no certified answer: the certificate failed, or the record
  //               could not be read. Not allowed: a backend nobody can vouch
  //               for is treated as the worst it could be.
  async function judge(o, repo, canisterId) {
    const st = await readCanisterState(canisterId, o);
    const b = { canister: canisterId, kind: 'unreadable', ok: false, warn: false, detail: '', moduleHash: st.moduleHash, controllers: st.controllers, stale: st.stale };
    if (!st.certified) {
      const bad = st.checks.find(c => !c.ok);
      b.detail = 'its state could not be certified: ' + (bad ? bad.detail || bad.label : 'unknown');
      return b;
    }
    const ctl = st.controllers;
    if (ctl.length === 1 && ctl[0] === NNS_ROOT) {
      Object.assign(b, { kind: 'system', ok: true, detail: (SYSTEM[canisterId] || 'a canister') + ', controlled by the NNS root' });
    } else if (ctl.length === 1 && ctl[0] === o.canister) {
      // Governed by ic-git: approved only if the chain says this is what
      // the repo's voters approved. The record names the repo it is for, so
      // a canister ic-git holds for another repo is not this site's backend.
      let rec;
      try { rec = decodeGet((await readRecord(o, repo + APP_SUFFIX)).ret); } catch (e) { b.detail = 'controlled by ic-git, but its record could not be read: ' + e.message; return b; }
      if (!rec.present) {
        Object.assign(b, { kind: 'blocked', detail: 'controlled by ic-git alone, but the registry holds no "' + repo + APP_SUFFIX + '" record: no approved build is on record for it' });
      } else if (st.moduleHash === rec.bundleHash) {
        Object.assign(b, { kind: 'approved', ok: true, detail: 'governed by ic-git; runs the approved build of commit ' + rec.commit.slice(0, 12) });
      } else {
        Object.assign(b, { kind: 'blocked', detail: 'governed by ic-git, but runs module ' + (st.moduleHash || 'none').slice(0, 16) + '... where the record approves ' + rec.bundleHash.slice(0, 16) + '... (commit ' + rec.commit.slice(0, 12) + ')' });
      }
    } else if (ctl.length === 0) {
      Object.assign(b, { kind: 'immutable', ok: true, detail: 'controlled by nobody: its code can never change' });
    } else {
      const who = ctl.map(c => c === o.canister ? 'ic-git' : c.slice(0, 5) + '...').join(', ');
      Object.assign(b, { kind: 'ungoverned', ok: true, warn: true, detail: 'not governed: controlled by ' + who + ', who can change its code without a vote' });
    }
    if (b.ok && st.stale) { b.warn = true; b.detail += '; the certificate is stale (' + Math.round(((o.now ?? Date.now()) - st.time) / 60_000) + ' min old)'; }
    return b;
  }

  // The canisters a verified page of `repo` may call, judged one by one:
  // ic-git itself (every page reads it), the system canisters the console
  // and wallets use, and the repo's app canister if it has one (asked of
  // ic-git's API, which may lie about the id -- the judgment of that id is
  // certified, so the worst a lie buys is a different canister allowed on
  // its own merits). `ok` is false if any is blocked or unreadable; `warn`
  // is true if any is ungoverned or stale, and `warning` says which. Set
  // `canisters` to judge a list of your own instead. `check` is the row
  // the callers add to a site's checks (G), built once here so the loader
  // and both extensions describe it alike.
  async function checkBackends(repo, options) {
    const o = { ...DEFAULTS, ...options };
    o.fetch = o.fetch || globalThis.fetch.bind(globalThis);
    let ids = o.canisters;
    let note = '';
    if (!ids) {
      ids = [o.canister, ...Object.keys(SYSTEM)];
      try {
        const r = await o.fetch('https://' + o.canister + '.raw.icp0.io/api/' + encodeURIComponent(repo) + '/info', { cache: 'no-store', signal: AbortSignal.timeout(TIMEOUT_MS) });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const info = await r.json();
        if (info.app_canister) ids.push(info.app_canister);
        else note = 'the site has no app canister';
      } catch (e) {
        note = 'could not read the site\'s info (' + (e.message || e) + '); only ic-git and the system canisters were judged';
      }
    }
    ids = [...new Set(ids)];
    const backends = await Promise.all(ids.map(id => judge(o, repo, id).catch(e => ({ canister: id, kind: 'unreadable', ok: false, warn: false, detail: e.message || String(e) }))));
    const ok = backends.every(b => b.ok);
    const ungoverned = backends.filter(b => b.kind === 'ungoverned');
    const warning = ungoverned.length ? 'its backend is not governed: the site owner can change it without approval (' + ungoverned.map(b => b.canister.slice(0, 5)).join(', ') + ')'
      : backends.some(b => b.warn) ? 'a backend\'s certificate is stale' : '';
    return {
      repo, backends, note, ok, warning,
      warn: warning !== '',
      allowed: backends.filter(b => b.ok).map(b => b.canister),
      check: { id: 'G', ok, warn: warning !== '', label: 'the canisters the page may call are approved or system canisters',
        detail: backends.map(b => b.canister.slice(0, 5) + ': ' + b.detail).concat(note ? [note] : []).join('; ') },
    };
  }

  // --- git objects, each checked against its id before it is believed.
  async function object(o, oid) {
    const [raw] = await query(o, 'get_object', oid);
    if (!raw) throw new Error('object ' + oid + ' is missing');
    const got = await digest('SHA-1', raw);
    if (got !== oid) throw new Error('object ' + oid + ' hashes to ' + got);
    const nul = raw.indexOf(0);
    return { type: td.decode(raw.subarray(0, nul)).split(' ')[0], body: raw.subarray(nul + 1) };
  }
  function entry(tree, name) {
    for (let i = 0; i < tree.length;) {
      const sp = tree.indexOf(0x20, i), nul = sp < 0 ? -1 : tree.indexOf(0, sp);
      if (nul < 0) return null; // malformed: stop rather than loop
      if (td.decode(tree.subarray(sp + 1, nul)) === name) return hex(tree.subarray(nul + 1, nul + 21));
      i = nul + 21;
    }
    return null;
  }
  // The blob site::resolve_entry(repo, "") serves: the site root, and its
  // index.html when the root is a directory.
  async function entrypoint(o, commit, root) {
    const c = await object(o, commit);
    const t = c.type === 'commit' && /^tree ([0-9a-f]{40})\n/.exec(td.decode(c.body));
    if (!t) throw new Error(commit + ' is not a commit');
    let node = await object(o, t[1]);
    const parts = root.split('/').filter(Boolean);
    for (const name of parts) {
      const oid = node.type === 'tree' && entry(node.body, name);
      if (!oid) throw new Error('site root "' + root + '" is not in the attested commit');
      node = await object(o, oid);
    }
    let path = parts.join('/');
    if (node.type === 'tree') {
      const oid = entry(node.body, 'index.html');
      if (!oid) throw new Error('no index.html under the site root at the attested commit');
      node = await object(o, oid);
      path = path ? path + '/index.html' : 'index.html';
    }
    if (node.type !== 'blob') throw new Error(path + ' is not a file');
    return { path, bytes: node.body };
  }

  // --- the pinned policy (docs/EXTENSION.md) ---------------------------
  // The Content-Security-Policy that admits exactly the scripts and styles a
  // verified page loads and nothing else: each inline <script> and <style>
  // by the sha256 of its text, each external script (and modulepreload) by
  // its integrity hashes; no frames, objects or <base>. A <script> the
  // browser does not run (a data block, a nomodule script) gets no pin. An
  // external stylesheet cannot be pinned: Chrome takes no hash source for
  // one, and a URL source admits whatever is served there to markup that
  // drops the integrity attribute.
  //
  // It must pin exactly what the browser runs: a missing pin blocks a script
  // of the verified page, and a pin for text the browser does not run admits
  // that text as a script in altered markup. What to pin comes from
  // readPage, the walk check E makes, which refuses a page wherever it
  // cannot say what the browser will do -- so this throws only for a page
  // check E refuses, and with its reason.
  const b64 = bytes => { let s = ''; for (const x of bytes) s += String.fromCharCode(x); return btoa(s); };
  const sha256Source = async text => "'sha256-" + b64(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(text)))) + "'";

  async function derivePolicy(bytes, pageUrl) {
    const page = readPage(td.decode(bytes));
    if (page.why) throw new Error(page.why);
    const sources = async pins => [...new Set(await Promise.all(pins.map(p => typeof p === 'string' ? p : sha256Source(p.text))))].join(' ') || "'none'";
    return 'script-src ' + await sources(page.scripts) + '; style-src ' + await sources(page.styles) + "; object-src 'none'; frame-src 'none'; base-uri 'none'";
  }

  async function verify(options) {
    const o = { ...DEFAULTS, ...options };
    o.fetch = o.fetch || globalThis.fetch.bind(globalThis);
    const key = o.repo + SITE_SUFFIX;
    const url = 'https://' + o.canister + '.raw.icp0.io/site/' + encodeURIComponent(o.repo) + '/';
    const checks = [];
    const check = (id, ok, label, detail) => { checks.push({ id, ok, label, detail: detail || '' }); return ok; };
    const out = { repo: o.repo, key, url, checks, verified: false };

    const [reg, res, site] = await Promise.all([
      readRecord(o, key).catch(e => e),
      o.fetch(url, { cache: 'no-store', signal: AbortSignal.timeout(TIMEOUT_MS) }).catch(e => e),
      query(o, 'get_site', o.repo).catch(e => e),
    ]);
    if (reg instanceof Error) { check('R', false, 'read the registry', reg.message); return out; }
    Object.assign(out, { via: reg.via, note: reg.note, record: decodeGet(reg.ret) });
    if (!check('R', out.record.present, 'the registry holds "' + key + '"', out.record.present ? '' : 'no record at ' + o.registry)) return out;
    if (res instanceof Error || !res.ok) { check('S', false, 'fetch the served page', res instanceof Error ? res.message : 'HTTP ' + res.status); return out; }
    const served = new Uint8Array(await res.arrayBuffer());
    out.bytes = served;

    const h = await digest('SHA-256', served);
    check('B', h === out.record.bundleHash, 'sha256 of the served page is the recorded bundleHash', h === out.record.bundleHash ? '' : 'served page hashes to ' + h);

    let path = 'index.html';
    try {
      if (site instanceof Error) throw site;
      if (!site[0]) throw new Error('the canister reports no site for ' + o.repo);
      const e = await entrypoint(o, out.record.commit, site[0][0]);
      path = e.path;
      const same = equal(e.bytes, served);
      check('D', same, 'the served page is ' + path + ' at the recorded commit', same ? 'every object on the way checked against its SHA-1' : 'the attested file differs from what was served');
    } catch (e) {
      check('D', false, 'the served page is the recorded commit\'s entrypoint', e.message);
    }
    out.path = path;

    // Read as HTML whatever the entrypoint is named: run() hands the bytes
    // to the HTML parser, which never looks at the name, so a .json root
    // holding markup is not skipped. An XML name is the one exception,
    // refused as at publish: a browser reads that page as XML, which the
    // walk does not follow, and a record from before the guard may name one.
    const why = unverifiableSubresource(/\.(svg|xhtml)$/i.test(path) ? path : 'index.html', served);
    check('E', why === null, 'everything the page loads is inline or SRI-pinned', why || '');

    out.verified = checks.every(c => c.ok);
    // What an extension pins; the loader does not need it. Check E made the
    // same walk, so a page that verifies is one this pins.
    if (out.verified) {
      try { out.policy = await derivePolicy(served, url); } catch (e) { out.policyError = e.message; }
    }
    return out;
  }

  return { verify, derivePolicy, readCanisterState, checkBackends, DEFAULTS };
})();
// === end core ===
