#!/usr/bin/env node
// Checks loader/index.html's verification core:
//   - its unverifiableSubresource block is byte-identical to tools/verify.mjs's;
//   - run in node against mainnet (canister, Sepolia registry), it verifies the
//     live sites, reads the registry through an EIP-1193 provider when one is
//     on the right chain and falls back to the RPC when not, and refuses a
//     tampered page and a repo with no record;
//   - its core is core/verifier.js, byte-identical (tools/sync-core.mjs);
//   - derivePolicy pins exactly the scripts and styles a page loads: fixed
//     cases offline, and both live sites produce a policy;
//   - with --browser, in headless Chrome: the crossorigin edit "run it" makes
//     is refused whenever it would change anything but the pinned tags, the
//     page runs when opened from disk, and derivePolicy agrees with a second
//     derivation from the browser's own parser on both live pages.
//
//   node tools/loader-test.mjs            # all of it (needs the network)
//   node tools/loader-test.mjs --offline  # the block comparison only
//   node tools/loader-test.mjs --browser "/path/to/Google Chrome"   # adds the
//     DOM cases; any Chromium works (the offline cases need no network)
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
globalThis.crypto ??= webcrypto;

const read = p => readFileSync(new URL(p, import.meta.url), 'utf8');
const between = (s, a, b) => {
  const i = s.indexOf(a), j = s.indexOf(b);
  assert.ok(i >= 0 && j > i, `markers ${a} .. ${b}`);
  return s.slice(i, j);
};
const html = read('../loader/index.html');
const SHARED = ['// === shared: unverifiableSubresource ===', '// === end shared ==='];
assert.equal(between(html, ...SHARED), between(read('./verify.mjs'), ...SHARED), 'the loader\'s scanner differs from tools/verify.mjs\'s');
console.log('PASS  shared scanner block is identical to tools/verify.mjs');

// Each <script> element must end where its source ends. The HTML parser ends
// one at the first end tag it meets, and after a "<!--" in its text a later
// "<script" defers even that (the script-escaped state) -- either way the
// code and the element part company and the page fails to parse. Every
// script here opens with "<script>" and closes with "</script>" on its own
// line. As the parser does, each ends at the first "</script" after it; that
// one must be the own-line end tag, and the page holds no other, so no end
// tag hides in a script's text.
{
  const bad = [];
  const lower = html.toLowerCase();
  const opens = [...html.matchAll(/^<script\b[^>]*>$/gim)];
  const ends = lower.split('</script').length - 1;
  for (const m of opens) {
    const at = html.slice(0, m.index).split('\n').length;
    const start = m.index + m[0].length;
    const end = lower.indexOf('</script', start);
    if (end < 0 || html[end - 1] !== '\n' || !/^<\/script>(\n|$)/.test(html.slice(end, end + 10))) {
      bad.push(`script at line ${at} does not end at its own-line end tag`);
    } else if (html.slice(start, end).includes('<!--')) {
      bad.push(`script at line ${at} contains <!--`);
    }
  }
  if (ends !== opens.length) bad.push(`${ends} "</script" in the page for ${opens.length} scripts`);
  const ok = bad.length === 0;
  console.log(`${ok ? 'PASS' : 'FAIL'}  loader scripts hold no comment opener or end tag in their text${ok ? '' : ': ' + bad.join('; ')}`);
  if (!ok) process.exitCode = 1;
}

// The shared scanner on its own, against the cases the canister's tests pin
// (site.rs: text_the_browser_never_parses_as_markup_is_not_scanned and
// skips_never_hide_what_the_browser_parses), and against the loader itself,
// which is published as a site record and must pass its own check.
{
  const scan = new Function(between(html, ...SHARED) + '\nreturn unverifiableSubresource;')();
  const bytes = t => new TextEncoder().encode(t);
  const accepted = [
    "<script>const s = '<base href=x>' + '<script src=y>';</script>",
    "<script src=a.js integrity=sha384-AAAA></script><script>'<iframe>'</script>",
    '<style>/* <link rel=stylesheet href=x> */</style>',
    '<title><base href=x></title>',
    '<textarea><meta http-equiv=refresh content=0></textarea>',
    "<SCRIPT>'<base href=x>'</Script >",
    "<script>'</scripts><base href=x>'</script>",
    '<!-- a > <base href=x> -->',
    '<!-- <script src=x> --><p>after</p>',
    "<noscript>enable JavaScript</noscript><script>'<base href=x>'</script>",
    '<xmp><base href=x></xmp>',
  ];
  const refused = [
    ['index.html', '<!-- x --!><base href=y>'],
    ['index.html', '<!--><base href=y>'],
    ['index.html', '<!---><base href=y>'],
    ['index.html', '<!-- a --> <base href=y> -->'],
    ['index.html', '<script>a</script><base href=y>'],
    ['index.html', '<script><!--<script>x</script><base href=y></script>-->'],
    ['index.html', "<script>'<base href=y>'"],
    ['index.html', '<svg><script/><base href=y></svg>'],
    ['index.html', "<svg></svg><script>'<base href=y>'</script>"],
    ['index.html', '<math><style><base href=y></style></math>'],
    ['page.svg', "<svg><script>'<base href=y>'</script></svg>"],
    ['page.xhtml', "<script>'<base href=y>'</script>"],
    ['page', "<script>'<base href=y>'</script>"],
    ['index.html', '<p></p title="> <!--"><base href=y><!-- -->'],
    ['index.html', '<xmp><!--</xmp><base href=y>-->'],
    ['index.html', '<noembed><!--</noembed><base href=y>-->'],
    ['index.html', '<noframes><!--</noframes><base href=y>-->'],
    ['index.html', '<noscript><!--</noscript><base href=y>-->'],
    ['index.html', '<xmp><a title="</xmp><base href=y>">'],
    ['index.html', '<noscript><base href=y></noscript>'],
    ['index.html', '<noscript><!-- </noscript><a title=" --><base href=y>">'],
    ['index.html', '<script-x><base href=y></script>'],
    ['index.html', '<title:x><base href=y></title>'],
    ['index.html', '<select><style><base href=y></style></select>'],
    ['index.html', '<svg><![CDATA[ a > <!-- ]]><base href=y> -->'],
    ['page.svg', '<?pi > <!-- ?><script href="y"/><!-- -->'],
    ['index.html', `<a"b='><base href=y>'>`],
    ['index.html', "<a ='><base href=y>'>"],
  ];
  const bad = [
    ...accepted.filter(t => scan('index.html', bytes(t)) !== null).map(t => 'refused: ' + t),
    ...refused.filter(([p, t]) => scan(p, bytes(t)) === null).map(([p, t]) => 'accepted: ' + p + ' ' + t),
  ];
  for (const b of bad) console.log('        ' + b);
  const self = scan('index.html', readFileSync(new URL('../loader/index.html', import.meta.url)));
  const ok = bad.length === 0 && self === null;
  console.log(`${ok ? 'PASS' : 'FAIL'}  scanner: ${accepted.length} accepted, ${refused.length} refused, and the loader passes its own check${self ? ' (it did not: ' + self + ')' : ''}`);
  if (!ok) process.exitCode = 1;
}

// The loader's core is core/verifier.js, not an edited copy of it.
{
  const src = read('../core/verifier.js').replace(/\n$/, '');
  const inline = between(html, '// === core ===', '// === end core ===') + '// === end core ===';
  const ok = inline === src;
  console.log(`${ok ? 'PASS' : 'FAIL'}  loader core is core/verifier.js${ok ? '' : ' (run node tools/sync-core.mjs)'}`);
  if (!ok) process.exitCode = 1;
}

const Verifier = new Function(between(html, '// === core ===', '// === end core ===') + '\nreturn Verifier;')();

// derivePolicy on fixed pages: what it pins, what it ignores, where it
// refuses. Hashes are sha256 over the text as the parser leaves it.
// `pinnedPages` keeps the pages it pins, for --browser to put to the
// browser's own parser.
const pinnedPages = [];
{
  const { createHash } = await import('node:crypto');
  const h = t => "'sha256-" + createHash('sha256').update(t).digest('base64') + "'";
  const I = 'sha384-XIhEYmHnXytH69pjI0KFgnptcvdZ2ZdkD3c+uSIC3Xoxuc+tCO3UX4l1/JieQMTS';
  const J = 'sha512-' + 'A'.repeat(86) + '==';
  const page = 'https://example.raw.icp0.io/site/r/';
  const tail = "; object-src 'none'; frame-src 'none'; base-uri 'none'";
  const none = "script-src 'none'; style-src 'none'" + tail, one = `script-src ${h('x()')}; style-src 'none'` + tail;
  const policy = t => Verifier.derivePolicy(new TextEncoder().encode(t), page);
  const cases = [
    ['nothing to run', '<p>hi</p>', "script-src 'none'; style-src 'none'" + tail],
    ['inline script and style, in order', '<style>a{}</style><script>x()</script><script>y()</script>',
      `script-src ${h('x()')} ${h('y()')}; style-src ${h('a{}')}` + tail],
    ['CRLF and CR become LF before hashing', '<script>a()\r\nb()\rc()</script>', `script-src ${h('a()\nb()\nc()')}; style-src 'none'` + tail],
    ['uppercase tags, original text hashed', '<SCRIPT>Go()</SCRIPT>', `script-src ${h('Go()')}; style-src 'none'` + tail],
    ['external script by every integrity token', `<script src=a.js integrity="${I} ${J}?x"></script>`, `script-src '${I}' '${J}'; style-src 'none'` + tail],
    ['an external stylesheet, even with integrity', `<link rel="Stylesheet" href="./s.css" integrity="${I}">`, /external stylesheet/],
    ['modulepreload by integrity', `<link rel=modulepreload href=m.js integrity="${I}">`, `script-src '${I}'; style-src 'none'` + tail],
    ['same script twice, pinned once', '<script>x()</script><script>x()</script>', `script-src ${h('x()')}; style-src 'none'` + tail],
    ['a script in a comment is not pinned', '\x3c!-- <script>no()</script> --><script>yes()</script>', `script-src ${h('yes()')}; style-src 'none'` + tail],
    ['a script in an attribute value is not pinned', '<p title="<script>no()</script>"><script>yes()</script>', `script-src ${h('yes()')}; style-src 'none'` + tail],
    ['a script in a title is not pinned', '<title><script>no()</script></title><script>yes()</script>', `script-src ${h('yes()')}; style-src 'none'` + tail],
    ['a <script-x> element is not a script', '<script-x>no()</script-x>', "script-src 'none'; style-src 'none'" + tail],
    ['external script without integrity', '<script src=a.js></script>', /no integrity to pin/],
    ['a script inside svg', '<svg><script>x()</script></svg>', /inside <svg> or <math>/],
    ['a style inside math', '<math><style>a{}</style></math>', /inside <svg> or <math>/],
    ['a script never closed', '<script>x()', /never closed/],
    ['a script under an svg title', '<svg><title><script>x()</script></title></svg>', /markup in <title> inside <svg> or <math>/],
    ['a script under a raw-text tag in a select', '<select><xmp><script>x()</script></xmp></select>', /<xmp> inside <select>/],
    ['a script after a closed svg', '<svg viewBox="0 0 1 1"><title>Icon</title><g><path d="M0 0"/></g></svg><script>x()</script>', one],
    ['a script after a self-closing svg', '<svg/><script>x()</script>', one],
    ['an unquoted value ending in / does not self-close', '<svg a=b/><script>x()</script>', /inside <svg> or <math>/],
    ['a script after a nested svg closes', '<svg><svg></svg></svg><script>x()</script>', one],
    ['a script between a nested svg and the outer end tag', '<svg><svg></svg><script>x()</script></svg>', /inside <svg> or <math>/],
    ['CDATA in svg is text', '<svg><![CDATA[ </svg> ]]></svg><script>x()</script>', one],
    ['a script after markup in foreignObject', '<svg><foreignObject><p>a</p></foreignObject></svg><script>x()</script>', /markup in <foreignobject>/],
    ['a script after a tag that breaks out of svg', '<svg><p></svg><script>x()</script>', /<p> inside <svg> or <math>/],
    ['a script after an end tag the svg does not own', '<div><svg></div><script>x()</script>', /<\/div> inside <svg> or <math>/],
    ['foreignObject with nothing to pin after it', '<script>x()</script><svg><foreignObject><p>a</p></foreignObject></svg>', one],
    ['svg textarea is markup, its script refused', '<svg><textarea><script>x()</script></textarea></svg>', /inside <svg> or <math>/],
    ['a textarea after a closed select is raw text again', '<select><option>a</option></select><textarea><script>no()</script></textarea>', none],
    ['a script after a closed select', '<select><optgroup><option>a</select><script>x()</script>', one],
    ['a script after a select that holds more than options', '<select><button>a</button></select><script>x()</script>', /<button> inside <select>/],
    ['a script in an iframe is not pinned', '<iframe><script>no()</script></iframe>', none],
    ['a script after plaintext is not pinned', '<plaintext><script>no()</script>', none],
    ['a double-escaped script', '<script>\x3c!-- <script> </script> --></script>', /where it ends is ambiguous/],
  ];
  const bad = [];
  for (const [name, input, want] of cases) {
    let got;
    try { got = await policy(input); } catch (e) { got = e; }
    const ok = want instanceof RegExp ? got instanceof Error && want.test(got.message) : got === want;
    if (typeof want === 'string') pinnedPages.push([name, input, want]);
    if (!ok) bad.push(`${name}: got ${got instanceof Error ? 'Error ' + got.message : got}`);
  }
  for (const b of bad) console.log('        ' + b);
  console.log(`${bad.length ? 'FAIL' : 'PASS'}  derivePolicy: ${cases.length - bad.length}/${cases.length} fixed pages`);
  if (bad.length) process.exitCode = 1;
}

const browser = process.argv[process.argv.indexOf('--browser') + 1];
if (process.argv.includes('--browser')) await domCases(browser);
if (process.argv.includes('--offline')) process.exit(process.exitCode ?? 0);

const { rpc } = Verifier.DEFAULTS;
const pass = (label, cond, r) => {
  if (!cond) {
    console.log(`FAIL  ${label}`);
    for (const c of r?.checks ?? []) console.log(`        ${c.ok ? 'pass' : 'fail'} ${c.id} ${c.label} ${c.detail}`);
    process.exitCode = 1;
  } else console.log(`PASS  ${label}`);
};
// A stand-in for window.ethereum that answers eth_calls from the public RPC.
const provider = chainId => ({
  async request({ method, params }) {
    if (method === 'eth_chainId') return '0x' + chainId.toString(16);
    const r = await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    return (await r.json()).result;
  },
});

for (const repo of ['ic-vote', 'ic-git']) {
  const r = await Verifier.verify({ repo });
  pass(`${repo}: verified through the RPC`, r.verified && r.checks.map(c => c.id).join() === 'R,B,D,E', r);
  // A page that links a stylesheet cannot be pinned until it inlines it.
  const unpinned = /external stylesheet/.test(r.policyError || '');
  pass(`${repo}: and ${unpinned ? 'refused a pin' : 'pinned'} (${r.policy ? r.policy.split(';').slice(0, 2).map(d => d.trim().split(' ').length - 1).join(' script, ') + ' style source(s)' : r.policyError})`, unpinned || (typeof r.policy === 'string' && !r.policyError), r);
}

let r = await Verifier.verify({ repo: 'ic-vote', provider: provider(11155111) });
pass('a provider on Sepolia is used for the registry read', r.verified && r.via === 'wallet', r);

r = await Verifier.verify({ repo: 'ic-vote', provider: provider(1) });
pass('a provider on another chain falls back to the RPC, and says so', r.verified && r.via !== 'wallet' && /chain 1\b/.test(r.note), r);

// One byte appended to the served page: both the hash and the git walk must
// catch it, and nothing may call it verified.
const tampered = async (url, init) => {
  const res = await fetch(url, init);
  if (!String(url).includes('/site/')) return res;
  const body = new Uint8Array(await res.arrayBuffer());
  return new Response(Uint8Array.from([...body, 0x20]), { status: res.status, headers: res.headers });
};
r = await Verifier.verify({ repo: 'ic-vote', fetch: tampered });
const failed = r.checks.filter(c => !c.ok).map(c => c.id).join();
pass('a tampered page fails B and D', !r.verified && failed === 'B,D', r);

// A canister that answers get_object with the wrong object: every reply
// after the first replays the first (the commit). The SHA-1 check must
// refuse it rather than walk a tree it was handed.
let first = null;
const lying = async (url, init) => {
  const isObject = init?.body instanceof Uint8Array && Buffer.from(init.body).includes('get_object');
  if (!isObject) return fetch(url, init);
  if (first) return new Response(first, { status: 200 });
  const res = await fetch(url, init);
  first = new Uint8Array(await res.arrayBuffer());
  return new Response(first, { status: 200 });
};
r = await Verifier.verify({ repo: 'ic-vote', fetch: lying });
pass('a wrong object from get_object fails D on its hash', !r.verified && /hashes to/.test(r.checks.find(c => c.id === 'D')?.detail), r);

r = await Verifier.verify({ repo: 'no-such-repo-' + Date.now() });
pass('a repo with no record fails at the registry', !r.verified && r.checks.length === 1 && r.checks[0].id === 'R', r);

// The crossorigin edit, run where DOMParser exists. withCrossorigin is taken
// from the file as written and evaluated in a page, over the DevTools
// protocol (no dependencies).
async function domCases(bin) {
  const fn = between(html, '  function withCrossorigin(src) {', '  function run(r) {');
  const S = "sha384-XIhEYmHnXytH69pjI0KFgnptcvdZ2ZdkD3c+uSIC3Xoxuc+tCO3UX4l1/JieQMTS";
  const cases = [
    ['pinned stylesheet and module script', `<!doctype html><head><link rel="stylesheet" href="a.css" integrity="${S}"><script type="module" src="a.js" integrity="${S}"></script></head><body>x</body>`, 2],
    ['self-closing and unquoted', `<!doctype html><link rel=stylesheet href=a.css integrity="${S}"/><link rel=stylesheet href=b.css integrity=${S} /><link rel=stylesheet href=c.css integrity=${S}>`, 3],
    ['unquoted value ending in / before >: refused, the edit would change it', `<!doctype html><link rel=stylesheet href=a.css integrity=${S}/>`, 'refused'],
    ['decoy in a comment inside <html>', `<!doctype html><p>x</p><!-- <script src=x integrity=${S}> -->`, 'refused'],
    ['already crossorigin: untouched', `<!doctype html><link rel=stylesheet href=a.css integrity="${S}" crossorigin="use-credentials">`, 0],
    ['decoy in inline script text', `<!doctype html><script>const t = '<script src=x integrity=${S}>';</script>`, 'refused'],
    ['decoy in a comment', `<!doctype html><!-- <link rel=stylesheet href=x integrity=${S}> --><p>x</p>`, 'refused'],
    ['decoy in a style block', `<!doctype html><style>/* <link integrity=${S}> */</style>`, 'refused'],
    ['> inside a quoted value', `<!doctype html><link title="a>b" rel=stylesheet href=x integrity="${S}">`, 'refused'],
  ];
  const expr = `(() => { ${fn.replace(/\n  }\n?$/, '\n  }')} ; return ${JSON.stringify(cases)}.map(([name, src]) => { try { const out = withCrossorigin(src); return (out.match(/crossorigin="anonymous"/g) || []).length; } catch (e) { return 'refused'; } }); })()`;
  const dir = mkdtempSync(join(tmpdir(), 'loader-test-'));
  const port = 9400 + Math.floor(Math.random() * 500);
  const chrome = spawn(bin, ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${dir}`, 'about:blank'], { stdio: 'ignore' });
  try {
    const sleep = ms => new Promise(r => setTimeout(r, ms));
    let target;
    for (let i = 0; i < 50 && !target; i++) {
      await sleep(200);
      try { target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json(); } catch {}
    }
    assert.ok(target, 'headless browser did not start');
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise(r => { ws.onopen = r; });
    let seq = 0;
    const pending = {}, thrown = [];
    let loaded = null;
    ws.onmessage = m => {
      const d = JSON.parse(m.data);
      if (pending[d.id]) { pending[d.id](d.error ? Promise.reject(new Error(`${d.error.message} (${d.error.code})`)) : d.result); delete pending[d.id]; }
      if (d.method === 'Runtime.exceptionThrown') thrown.push(d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text);
      if (d.method === 'Page.loadEventFired' && loaded) loaded();
    };
    const send = (method, params = {}) => new Promise(r => { pending[++seq] = r; ws.send(JSON.stringify({ id: seq, method, params })); });
    const res = await send('Runtime.evaluate', { expression: expr, returnByValue: true });
    assert.ok(!res.exceptionDetails, JSON.stringify(res.exceptionDetails));
    res.result.value.forEach((got, i) => {
      const [name, , want] = cases[i];
      const ok = got === want;
      console.log(`${ok ? 'PASS' : 'FAIL'}  crossorigin edit: ${name} -> ${want}${ok ? '' : ` (got ${got})`}`);
      if (!ok) process.exitCode = 1;
    });

    // The page itself, opened from disk as a user opens it: every script
    // parses and runs, and ?repo= fills the form and starts a check.
    await send('Runtime.enable');
    await send('Page.enable');
    const load = new Promise(r => { loaded = () => r(true); setTimeout(() => r(false), 15_000).unref(); });
    const nav = await send('Page.navigate', { url: new URL('../loader/index.html?repo=no-such-repo', import.meta.url).href });
    assert.ok(!nav.errorText, nav.errorText);
    assert.ok(await load, 'loader/index.html did not fire load');
    const page = (await send('Runtime.evaluate', { returnByValue: true, expression:
      "JSON.stringify({ core: typeof Verifier, repo: document.getElementById('repo').value, out: document.getElementById('out').textContent.length > 0 })" })).result.value;
    const want = JSON.stringify({ core: 'object', repo: 'no-such-repo', out: true });
    const loads = page === want && thrown.length === 0;
    console.log(`${loads ? 'PASS' : 'FAIL'}  loader/index.html opened from disk: scripts run, ?repo= fills the form and starts a check${loads ? '' : ` (got ${page}; ${thrown.join(' | ') || 'no exceptions'})`}`);
    if (!loads) process.exitCode = 1;

    // derivePolicy against a second derivation written from the browser's
    // own parser, on both live pages: the scripts and styles the DOM holds,
    // in document order, hashed from their parsed text.
    const fromDom = `async (url, html) => {
      const doc = new DOMParser().parseFromString(html ?? await (await fetch(url, { cache: 'no-store' })).text(), 'text/html');
      const b64 = a => btoa(String.fromCharCode(...a));
      const h = async t => "'sha256-" + b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)))) + "'";
      const ints = v => (v || '').split(/[ \\t\\n\\r\\f]+/).map(t => t.split('?')[0]).filter(t => /^sha(256|384|512)-[A-Za-z0-9+\\/]+={0,2}$/.test(t)).map(t => "'" + t + "'");
      const scripts = [], styles = [];
      for (const el of doc.querySelectorAll('script, link[rel~="modulepreload" i]')) {
        if (el.localName === 'link' || el.hasAttribute('src')) scripts.push(...ints(el.getAttribute('integrity')));
        else scripts.push(await h(el.textContent));
      }
      if (doc.querySelector('link[rel~="stylesheet" i][href]')) return 'refused: external stylesheet';
      for (const el of doc.querySelectorAll('style')) styles.push(await h(el.textContent));
      const s = l => [...new Set(l)].join(' ') || "'none'";
      return 'script-src ' + s(scripts) + '; style-src ' + s(styles) + "; object-src 'none'; frame-src 'none'; base-uri 'none'";
    }`;
    // The same on the fixed pages derivePolicy pins: the browser's parser
    // finds the scripts and styles it found, and no others.
    const differ = [];
    for (const [name, input, want] of pinnedPages) {
      const dom = await send('Runtime.evaluate', { awaitPromise: true, returnByValue: true, expression: `(${fromDom})('https://example.raw.icp0.io/site/r/', ${JSON.stringify(input)})` });
      if (dom.result?.value !== want) differ.push(`${name}: dom ${dom.result?.value ?? JSON.stringify(dom.exceptionDetails)}`);
    }
    for (const d of differ) console.log('        ' + d);
    console.log(`${differ.length ? 'FAIL' : 'PASS'}  derivePolicy agrees with the browser's parser on ${pinnedPages.length - differ.length}/${pinnedPages.length} fixed pages it pins`);
    if (differ.length) process.exitCode = 1;
    for (const repo of process.argv.includes('--offline') ? [] : ['ic-git', 'ic-vote']) {
      const url = `https://${Verifier.DEFAULTS.canister}.raw.icp0.io/site/${repo}/`;
      const dom = (await send('Runtime.evaluate', { awaitPromise: true, returnByValue: true, expression: `(${fromDom})(${JSON.stringify(url)})` }));
      const mine = await Verifier.derivePolicy(new Uint8Array(await (await fetch(url, { cache: 'no-store' })).arrayBuffer()), url)
        .catch(e => /external stylesheet/.test(e.message) ? 'refused: external stylesheet' : Promise.reject(e));
      const agree = dom.result?.value === mine;
      console.log(`${agree ? 'PASS' : 'FAIL'}  derivePolicy agrees with the browser's parser on live ${repo}${agree ? '' : `\n        core: ${mine}\n        dom:  ${dom.result?.value ?? JSON.stringify(dom.exceptionDetails)}`}`);
      if (!agree) process.exitCode = 1;
    }
    ws.close();
  } finally {
    const exited = new Promise(r => chrome.once('exit', r));
    chrome.kill();
    await exited;
    rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  }
}
