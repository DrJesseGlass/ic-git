// === core ===
// Verification with no DOM: Verifier.verify(options) -> result, and
// Verifier.derivePolicy(bytes, url) -> the CSP that pins a verified page's
// scripts and styles (docs/EXTENSION.md).
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
  const DEFAULTS = {
    canister: 'umobs-yiaaa-aaaab-agyrq-cai',
    registry: '0xa1362DAda583c56a395D305a8C7A458E0B62A209',
    chainId: 11155111, // Sepolia
    rpc: 'https://ethereum-sepolia-rpc.publicnode.com',
    icApi: 'https://icp-api.io',
    provider: null, // an EIP-1193 provider (window.ethereum), preferred for the registry read
  };
  const GET_SELECTOR = '693ec85e'; // keccak256("get(string)")[..4], as in tools/verify.mjs
  const SITE_SUFFIX = '#site'; // provenance.rs::SITE_KEY_SUFFIX
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

// True when an integrity value holds at least one token the SRI spec
// recognizes (sha256/384/512 + base64, options after `?`). The spec makes the
// browser IGNORE metadata that parses to an empty set -- the resource then
// loads with no check at all -- so presence alone proves nothing, and a token
// counts only if the browser's grammar would KEEP it: padding is trailing
// only, two at most, never the whole value (`sha384-====` is discarded). Like
// the canister, this is a strict subset of the CSP grammar -- a token we
// discard and the browser keeps merely fails closed at digest time.
const integrityEnforceable = (value) =>
  value.split(/[ \t\n\r\f]+/).some((tok) => {
    const m = /^sha(?:256|384|512)-([^?]*)/.exec(tok);
    return m !== null && /^[a-zA-Z0-9+/]+={0,2}$/.test(m[1]);
  });

function unverifiableSubresource(servedPath, body) {
  // Gate on the served file's NAME, case-insensitively; an extensionless
  // blob could be a page, so it is scanned rather than skipped.
  const name = servedPath.split("/").pop();
  const dot = name.lastIndexOf(".");
  const ext = dot === -1 ? null : name.slice(dot + 1).toLowerCase();
  if (ext !== null && !["html", "htm", "xhtml", "svg"].includes(ext)) return null;
  // Plain HTML content, where the long skips are sound: only a page served
  // as HTML, until foreign content or a select begins. See the canister's
  // unverifiable_subresource for why bodies are skipped and where not.
  let plain = ext === "html" || ext === "htm";
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    return "entrypoint is not valid UTF-8, so its references cannot be read";
  }
  // ASCII-only lowercasing, mirroring the canister's to_ascii_lowercase.
  const hay = text.replace(/[A-Z]/g, (c) => c.toLowerCase());

  // Tokenize one tag's attributes the way the browser does: a new attribute
  // may begin after whitespace, `/`, or a closing quote; quotes delimit a
  // value only immediately after `=`; an unquoted value ends at whitespace
  // or `>`. Returns {attrs, end} or null when the tag never closes.
  const parseTag = (from) => {
    const attrs = [];
    let i = from;
    for (;;) {
      while (i < hay.length && (isWs(hay[i]) || hay[i] === "/")) i++;
      if (i >= hay.length) return null;
      if (hay[i] === ">") return { attrs, end: i };
      const nameStart = i;
      if (hay[i] === "=") i++; // a leading `=` is part of the name
      while (i < hay.length && !isWs(hay[i]) && !"/=>".includes(hay[i])) i++;
      const attrName = hay.slice(nameStart, i);
      let j = i;
      while (j < hay.length && isWs(hay[j])) j++;
      if (j < hay.length && hay[j] === "=") {
        j++;
        while (j < hay.length && isWs(hay[j])) j++;
        if (j >= hay.length) return null;
        let value;
        if (hay[j] === '"' || hay[j] === "'") {
          const ve = hay.indexOf(hay[j], j + 1);
          if (ve === -1) return null;
          value = hay.slice(j + 1, ve);
          j = ve + 1;
        } else {
          const vs = j;
          while (j < hay.length && !isWs(hay[j]) && hay[j] !== ">") j++;
          value = hay.slice(vs, j);
        }
        attrs.push([attrName, value]);
        i = j;
      } else {
        attrs.push([attrName, ""]);
      }
    }
  };

  let i = 0;
  for (;;) {
    const lt = hay.indexOf("<", i);
    if (lt === -1 || lt + 1 >= hay.length) return null;
    const c = hay[lt + 1];
    if (!/[a-z]/.test(c)) {
      // End tag (attributes tokenized, quoted values and all), comment (to
      // the tokenizer's end, in plain HTML), doctype, or bogus comment:
      // nothing inside the rest executes before its first `>`, so skip
      // there; a stray `<` is text.
      if (c === "/" && /[a-z]/.test(hay[lt + 2] ?? "")) {
        const parsed = parseTag(tagNameEnd(hay, lt + 2));
        if (parsed === null) return null;
        i = parsed.end + 1;
      } else if (plain && hay.startsWith("\x3c!--", lt)) {
        const end = commentEnd(hay, lt);
        if (end === -1) return null;
        i = end;
      } else if (c === "/" || c === "!" || c === "?") {
        const gt = hay.indexOf(">", lt + 1);
        if (gt === -1) return null;
        i = gt + 1;
      } else {
        i = lt + 1;
      }
      continue;
    }
    let nameEnd = lt + 1;
    while (nameEnd < hay.length && /[a-z0-9]/.test(hay[nameEnd])) nameEnd++;
    // `tag` is the alphanumeric prefix (checks on it over-refuse
    // `<script-x>`); a skip keys on `exact`.
    const tag = hay.slice(lt + 1, nameEnd);
    const fullEnd = tagNameEnd(hay, lt + 1);
    const exact = fullEnd === nameEnd;
    const parsed = parseTag(fullEnd);
    if (parsed === null) return `<${tag}> tag is never closed`;
    i = parsed.end + 1;
    // First occurrence wins, as in the browser.
    const get = (n) => parsed.attrs.find(([an]) => an === n)?.[1];
    // The browser decodes character references in values; this scanner does
    // not, so a keyword value hiding one is refused, not compared wrong.
    const charRef = (an, v) =>
      v.includes("&")
        ? `<${tag} ${an}=...> value holds a character reference this scanner does not decode`
        : null;
    if (tag === "iframe" || tag === "object" || tag === "embed") {
      return `<${tag}> loads content SRI cannot cover; inline the content instead`;
    }
    if (tag === "base" && get("href") !== undefined) {
      return "<base href=...> relocates every relative URL on the page";
    }
    if (tag === "meta") {
      const v = get("http-equiv");
      if (v !== undefined) {
        const bad = charRef("http-equiv", v);
        if (bad) return bad;
        if (v.trim() === "refresh") {
          return "<meta http-equiv=refresh> navigates away from the attested page";
        }
      }
    }
    if (tag === "script") {
      if (get("href") !== undefined || get("xlink:href") !== undefined) {
        return "<script href=...> (SVG form) loads a subresource SRI cannot cover";
      }
      if (get("src") !== undefined) {
        const integ = get("integrity");
        if (integ === undefined || !integrityEnforceable(integ)) {
          return "<script src=...> has no enforceable integrity=";
        }
      } else {
        const t = get("type");
        if (t !== undefined) {
          const bad = charRef("type", t);
          if (bad) return bad;
          if (t.trim() === "module") {
            return "inline <script type=module> imports files SRI cannot cover";
          }
        }
      }
    }
    if (tag === "link") {
      const rel = get("rel") ?? "";
      const bad = charRef("rel", rel);
      if (bad) return bad;
      const enforced = rel
        .split(/[ \t\n\r\f]+/)
        .some((r) => r === "stylesheet" || r === "modulepreload");
      const integ = get("integrity");
      if (
        enforced &&
        get("href") !== undefined &&
        (integ === undefined || !integrityEnforceable(integ))
      ) {
        return `<link rel="${rel}"> has no enforceable integrity=`;
      }
    }
    if (tag === "svg" || tag === "math" || tag === "select") plain = false;
    // Raw text: the browser reads everything to the end tag as text.
    const raw = ["script", "style", "textarea", "title", "xmp", "noembed", "noframes", "noscript"];
    if (plain && exact && raw.includes(tag)) {
      const end = rawTextEnd(hay, i, tag);
      if (end === -1) return `<${tag}> is never closed`;
      if (tag === "noscript") {
        // With scripting off the body is markup: scan it as a page of its
        // own; a comment still open at the end tag would run on past it.
        const inner = hay.slice(i, end);
        const why = unverifiableSubresource("noscript.html", new TextEncoder().encode(inner));
        if (why !== null) return why;
        const p = inner.lastIndexOf("\x3c!--");
        if (p !== -1 && commentEnd(inner, p) === -1) return "<noscript> holds a comment that runs past its end";
        if (["<svg", "<math", "<select"].some((t) => inner.includes(t))) plain = false;
      }
      i = end;
    }
  }
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
        if (chain === o.chainId) return { ret: await o.provider.request({ method: 'eth_call', params }), via: 'wallet' };
        note = 'wallet is on chain ' + chain + ', not ' + o.chainId;
      } catch (e) {
        note = 'wallet read failed: ' + (e.message || e);
      }
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
  // its integrity hashes, each external stylesheet by its exact URL (Chrome
  // takes no hash source for one; its integrity, which check E requires,
  // pins the contents). For a page that passed check E only, so every
  // external reference carries an enforceable integrity.
  //
  // The page is walked as the scanner walks it -- the same tag-name,
  // comment and raw-text rules -- over the original text, since hashes and
  // URLs are case-sensitive. The parser turns CRLF and CR into LF before a
  // script's text exists, and so does this. Where it cannot say exactly
  // what the browser will hash -- a script or style inside <svg> or <math>,
  // whose text is ordinary markup there -- it throws rather than guess: a
  // wrong pin breaks the page, which is loud, but a missing one is not.
  const b64 = bytes => { let s = ''; for (const x of bytes) s += String.fromCharCode(x); return btoa(s); };
  const sha256Source = async text => "'sha256-" + b64(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(text)))) + "'";
  const integritySources = value => (value || '').split(/[ \t\n\r\f]+/)
    .map(t => t.split('?')[0])
    .filter(t => /^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(t))
    .map(t => "'" + t + "'");

  async function derivePolicy(bytes, pageUrl) {
    const text = td.decode(bytes).replace(/\r\n?/g, '\n');
    const hay = text.replace(/[A-Z]/g, c => c.toLowerCase());
    const scripts = [], styles = [];
    // One start tag's attributes, first occurrence winning, values taken
    // from the original text; {attrs, end} or null if it never closes.
    const startTag = from => {
      const attrs = new Map();
      for (let i = from; ;) {
        while (i < hay.length && (isWs(hay[i]) || hay[i] === '/')) i++;
        if (i >= hay.length) return null;
        if (hay[i] === '>') return { attrs, end: i };
        const ns = i;
        if (hay[i] === '=') i++;
        while (i < hay.length && !isWs(hay[i]) && !'/=>'.includes(hay[i])) i++;
        const name = hay.slice(ns, i);
        let j = i, value = '';
        while (j < hay.length && isWs(hay[j])) j++;
        if (hay[j] === '=') {
          j++;
          while (j < hay.length && isWs(hay[j])) j++;
          if (j >= hay.length) return null;
          if (hay[j] === '"' || hay[j] === "'") {
            const ve = hay.indexOf(hay[j], j + 1);
            if (ve === -1) return null;
            value = text.slice(j + 1, ve);
            j = ve + 1;
          } else {
            const vs = j;
            while (j < hay.length && !isWs(hay[j]) && hay[j] !== '>') j++;
            value = text.slice(vs, j);
          }
          i = j;
        }
        if (!attrs.has(name)) attrs.set(name, value);
      }
    };
    let foreign = false;
    for (let i = 0; ;) {
      const lt = hay.indexOf('<', i);
      if (lt === -1) break;
      const c = hay[lt + 1] || '';
      if (hay.startsWith('\x3c!--', lt)) {
        const end = commentEnd(hay, lt);
        if (end === -1) break;
        i = end;
        continue;
      }
      if (!/[a-z]/.test(c)) {
        if (c === '/' && /[a-z]/.test(hay[lt + 2] || '')) {
          const t = startTag(tagNameEnd(hay, lt + 2));
          if (!t) break;
          i = t.end + 1;
        } else if (c === '/' || c === '!' || c === '?') {
          const gt = hay.indexOf('>', lt + 1);
          if (gt === -1) break;
          i = gt + 1;
        } else {
          i = lt + 1;
        }
        continue;
      }
      const nameEnd = tagNameEnd(hay, lt + 1);
      const name = hay.slice(lt + 1, nameEnd);
      const t = startTag(nameEnd);
      if (!t) throw new Error('<' + name + '> tag is never closed');
      i = t.end + 1;
      if (name === 'svg' || name === 'math') foreign = true;
      if ((name === 'script' || name === 'style') && foreign) {
        throw new Error('cannot pin a <' + name + '> inside <svg> or <math>: its text is markup there');
      }
      if (name === 'link') {
        const rel = (t.attrs.get('rel') || '').toLowerCase().split(/[ \t\n\r\f]+/);
        const href = t.attrs.get('href');
        if (href !== undefined && rel.includes('stylesheet')) {
          const u = new URL(href, pageUrl).href;
          if (!/^[^\s;,']+$/.test(u)) throw new Error('stylesheet URL cannot be written as a CSP source: ' + u);
          styles.push(u);
        }
        if (href !== undefined && rel.includes('modulepreload')) scripts.push(...integritySources(t.attrs.get('integrity')));
      }
      if (['script', 'style', 'textarea', 'title', 'xmp', 'noembed', 'noframes', 'noscript'].includes(name)) {
        const end = rawTextEnd(hay, i, name);
        if (end === -1) throw new Error('<' + name + '> is never closed');
        const body = text.slice(i, end);
        if (name === 'script') {
          if (t.attrs.has('src')) {
            const pins = integritySources(t.attrs.get('integrity'));
            if (!pins.length) throw new Error('<script src=' + t.attrs.get('src') + '> has no integrity to pin');
            scripts.push(...pins);
          } else {
            scripts.push(await sha256Source(body));
          }
        }
        if (name === 'style') styles.push(await sha256Source(body));
        i = end;
      }
    }
    const sources = list => [...new Set(list)].join(' ') || "'none'";
    return 'script-src ' + sources(scripts) + '; style-src ' + sources(styles) + "; object-src 'none'; base-uri 'none'";
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

    // Scanned as markup whatever the entrypoint is named: run() hands the
    // bytes to the HTML parser, which never looks at the extension.
    const why = unverifiableSubresource('index.html', served);
    check('E', why === null, 'everything the page loads is inline or SRI-pinned', why || '');

    out.verified = checks.every(c => c.ok);
    // What an extension pins; the loader does not need it. A page that
    // verifies but cannot be pinned says why instead.
    if (out.verified) {
      try { out.policy = await derivePolicy(served, url); } catch (e) { out.policyError = e.message; }
    }
    return out;
  }

  return { verify, derivePolicy, DEFAULTS };
})();
// === end core ===
