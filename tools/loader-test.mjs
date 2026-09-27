#!/usr/bin/env node
// Checks loader/index.html's verification core:
//   - its unverifiableSubresource block is byte-identical to tools/verify.mjs's;
//   - run in node against mainnet (canister, Sepolia registry), it verifies the
//     live sites, reads the registry through an EIP-1193 provider when one is
//     on the right chain and falls back to the RPC when not, and refuses a
//     tampered page and a repo with no record;
//   - with --browser, in headless Chrome: the crossorigin edit "run it" makes
//     is refused whenever it would change anything but the pinned tags.
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

const browser = process.argv[process.argv.indexOf('--browser') + 1];
if (process.argv.includes('--browser')) await domCases(browser);
if (process.argv.includes('--offline')) process.exit(process.exitCode ?? 0);

const Verifier = new Function(between(html, '// === core ===', '// === end core ===') + '\nreturn Verifier;')();
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
    const reply = new Promise(r => { ws.onmessage = m => { const d = JSON.parse(m.data); if (d.id === 1) r(d.result); }; });
    ws.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: expr, returnByValue: true } }));
    const res = await reply;
    ws.close();
    assert.ok(!res.exceptionDetails, JSON.stringify(res.exceptionDetails));
    res.result.value.forEach((got, i) => {
      const [name, , want] = cases[i];
      const ok = got === want;
      console.log(`${ok ? 'PASS' : 'FAIL'}  crossorigin edit: ${name} -> ${want}${ok ? '' : ` (got ${got})`}`);
      if (!ok) process.exitCode = 1;
    });
  } finally {
    const exited = new Promise(r => chrome.once('exit', r));
    chrome.kill();
    await exited;
    rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  }
}
