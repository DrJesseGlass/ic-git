#!/usr/bin/env node
// Checks loader/index.html's verification core:
//   - its unverifiableSubresource block is byte-identical to tools/verify.mjs's;
//   - run in node against mainnet (canister, Sepolia registry), it verifies the
//     live sites, reads the registry through an EIP-1193 provider when one is
//     on the right chain and falls back to the RPC when not, and refuses a
//     tampered page and a repo with no record.
//
//   node tools/loader-test.mjs            # all of it (needs the network)
//   node tools/loader-test.mjs --offline  # the block comparison only
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
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
if (process.argv.includes('--offline')) process.exit(0);

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
