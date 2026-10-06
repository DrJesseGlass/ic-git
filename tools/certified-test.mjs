#!/usr/bin/env node
// Checks the certified reader, Verifier.readCanisterState (core/verifier.js,
// with the vendored BLS verifier core/bls12-381.js):
//   - fixed vectors: read_state replies captured from mainnet
//     (tools/vectors/read_state.json) verify, and yield the module hash,
//     controllers and subnet they held when captured;
//   - a tamper suite: each way a certificate can lie is caught by the check
//     that owns it, and nothing tampered is ever reported certified --
//     a flipped signature, an altered leaf, a wrong root key, a canister
//     outside the delegated ranges, a nested delegation, a pruned path, a
//     reply with no certificate, and the core loaded without the BLS code;
//   - freshness: a certificate older than the bound is stale, not failed;
//   - with --live: umobs and the ICP ledger verify against mainnet now, and
//     the pinned root key is the one /api/v2/status reports.
//
//   node tools/certified-test.mjs           # offline
//   node tools/certified-test.mjs --live    # plus mainnet
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
globalThis.crypto ??= webcrypto;

const read = p => readFileSync(new URL(p, import.meta.url), 'utf8');
const bls = read('../core/bls12-381.js'), core = read('../core/verifier.js');
const load = withBls => new Function((withBls ? bls + '\n' : '') + core + '\nreturn Verifier;')();
const Verifier = load(true);
const vectors = JSON.parse(read('./vectors/read_state.json'));

const te = new TextEncoder(), td = new TextDecoder();
const unhex = h => Uint8Array.from(h.match(/../g), x => parseInt(x, 16));
const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const sha256 = b => new Uint8Array(createHash('sha256').update(b).digest());
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

// CBOR enough to take a certificate apart and put it back: maps keep key
// order, so an untouched certificate re-encodes to the same bytes.
function dec(b) {
  let p = 0;
  const item = () => {
    const ib = b[p++], mt = ib >> 5, ai = ib & 31;
    let n = ai;
    if (ai >= 24 && ai <= 27) { n = 0; for (let i = 0; i < 2 ** (ai - 24); i++) n = n * 256 + b[p++]; }
    if (mt === 0) return n;
    if (mt === 2) { const r = b.slice(p, p + n); p += n; return r; }
    if (mt === 3) { const s = td.decode(b.subarray(p, p + n)); p += n; return s; }
    if (mt === 4) { const a = []; for (let i = 0; i < n; i++) a.push(item()); return a; }
    if (mt === 5) { const o = {}; for (let i = 0; i < n; i++) { const k = item(); o[k] = item(); } return o; }
    if (mt === 6) return item();
    throw new Error('cbor: unsupported');
  };
  return item();
}
function enc(v, tag = true) {
  const out = tag ? [0xd9, 0xd9, 0xf7] : [];
  const head = (mt, n) => { if (n < 24) out.push((mt << 5) | n); else if (n < 256) out.push((mt << 5) | 24, n); else if (n < 65536) out.push((mt << 5) | 25, n >> 8, n & 255); else out.push((mt << 5) | 26, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255); };
  const item = v => {
    if (typeof v === 'number') head(0, v);
    else if (typeof v === 'string') { const u = te.encode(v); head(3, u.length); out.push(...u); }
    else if (v instanceof Uint8Array) { head(2, v.length); out.push(...v); }
    else if (Array.isArray(v)) { head(4, v.length); for (const x of v) item(x); }
    else { const k = Object.keys(v); head(5, k.length); for (const x of k) { item(x); item(v[x]); } }
  };
  item(v);
  return Uint8Array.from(out);
}
const sep = s => concat(Uint8Array.of(s.length), te.encode(s));
const treeHash = t => t[0] === 0 ? sha256(sep('ic-hashtree-empty'))
  : t[0] === 1 ? sha256(concat(sep('ic-hashtree-fork'), treeHash(t[1]), treeHash(t[2])))
  : t[0] === 2 ? sha256(concat(sep('ic-hashtree-labeled'), t[1], treeHash(t[2])))
  : t[0] === 3 ? sha256(concat(sep('ic-hashtree-leaf'), t[1])) : t[1];
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
// The labeled node at `path` (so a test can alter or prune it in place).
function nodeAt(t, path) {
  const find = (n, label) => n[0] === 2 ? (eq(n[1], label) ? n : null) : n[0] === 1 ? find(n[1], label) ?? find(n[2], label) : null;
  let n = t;
  for (const s of path) { n = find(n, typeof s === 'string' ? te.encode(s) : s); assert.ok(n, 'path present'); if (s !== path[path.length - 1]) n = n[2]; }
  return n;
}

let passed = 0;
const pass = m => { passed++; console.log('PASS  ' + m); };
const UMOBS = 'umobs-yiaaa-aaaab-agyrq-cai', LEDGER = 'ryjl3-tyaaa-aaaaa-aaaba-cai';
const reply = bytes => ({ fetch: async () => ({ ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) }) });
// A reader over `body`, dated a second after the certificate it holds.
const run = (id, body, extra = {}, V = Verifier) => V.readCanisterState(id, { ...reply(body), now: vectors[id].time + 1000, ...extra });
const failedAt = (r, want) => {
  assert.equal(r.certified, false, 'must not be certified');
  const bad = r.checks.filter(c => !c.ok).map(c => c.id);
  assert.deepEqual(bad, [want], 'expected ' + want + ' to fail, got ' + JSON.stringify(r.checks.filter(c => !c.ok)));
  return r.checks.find(c => c.id === want).detail;
};

for (const [id, v] of Object.entries(vectors)) {
  const r = await run(id, unhex(v.reply_hex));
  assert.equal(r.certified, true, JSON.stringify(r.checks));
  assert.equal(r.moduleHash, v.moduleHash);
  assert.deepEqual(r.controllers, v.controllers);
  assert.equal(r.subnet, v.subnet);
  assert.equal(r.time, v.time);
  assert.equal(r.stale, false);
  assert.equal(r.checks.length, 5);
  pass(`${id}: the captured certificate verifies (${v.subnet ? 'delegated to ' + v.subnet.slice(0, 5) : 'signed by the root key'}), module ${v.moduleHash.slice(0, 8)}..., ${v.controllers.length} controller`);
}

// Freshness is a flag on a verified result, in either direction.
{
  const body = unhex(vectors[UMOBS].reply_hex);
  const old = await run(UMOBS, body, { now: vectors[UMOBS].time + 6 * 60_000 });
  assert.equal(old.certified, true); assert.equal(old.stale, true);
  assert.match(old.checks.find(c => c.id === 'C4').detail, /^STALE/);
  const future = await run(UMOBS, body, { now: vectors[UMOBS].time - 6 * 60_000 });
  assert.equal(future.certified, true); assert.equal(future.stale, true);
  const edge = await run(UMOBS, body, { now: vectors[UMOBS].time + 5 * 60_000 });
  assert.equal(edge.stale, false);
  const tight = await run(UMOBS, body, { now: vectors[UMOBS].time + 2000, freshMs: 1000 });
  assert.equal(tight.stale, true);
  pass('a certificate past the freshness bound (default 5 min) is certified and stale, not failed');
}

// --- tamper suite, on the delegated certificate (umobs) and the direct one (ledger)
const parts = id => { const body = dec(unhex(vectors[id].reply_hex)); const cert = dec(body.certificate); return { body, cert }; };
const rebuild = (body, cert) => enc({ ...body, certificate: enc(cert) });

for (const id of [UMOBS, LEDGER]) {
  const { body, cert } = parts(id);
  assert.ok(eq(rebuild(body, cert), unhex(vectors[id].reply_hex)), 'the test codec reproduces the reply byte for byte');

  let c = structuredClone(cert); c.signature[7] ^= 1;
  assert.match(failedAt(await run(id, rebuild(body, c)), 'C3'), /does not verify/);
  c = structuredClone(cert); c.signature = Uint8Array.of(...c.signature.subarray(0, 47)); // 47 bytes: not a point
  assert.match(failedAt(await run(id, rebuild(body, c)), 'C3'), /does not verify/);
  pass(`${id}: a tampered or malformed signature fails C3`);

  c = structuredClone(cert);
  // The canister's id bytes: the one label under /canister in this reply.
  const firstLabel = n => n[0] === 2 ? n[1] : n[0] === 1 ? firstLabel(n[1]) ?? firstLabel(n[2]) : null;
  const cid = firstLabel(nodeAt(c.tree, ['canister'])[2]);
  const leaf = nodeAt(c.tree, ['canister', cid, 'module_hash'])[2];
  assert.equal(leaf[0], 3); leaf[1][0] ^= 1;
  assert.match(failedAt(await run(id, rebuild(body, c)), 'C3'), /does not verify/);
  pass(`${id}: an altered module hash leaf breaks the signed root (C3)`);

  c = structuredClone(cert);
  const t = nodeAt(c.tree, ['time'])[2]; t[1] = Uint8Array.of(...t[1]); t[1][0] ^= 1;
  failedAt(await run(id, rebuild(body, c)), 'C3');
  pass(`${id}: an altered time leaf breaks the signed root (C3)`);

  // A pruned subtree keeps the root (its hash stands in), so the signature
  // holds and the reader must notice the value is simply not shown.
  c = structuredClone(cert);
  const node = nodeAt(c.tree, ['canister', cid, 'module_hash']);
  node[2] = [4, treeHash(node[2])];
  assert.match(failedAt(await run(id, rebuild(body, c)), 'C5'), /pruned/);
  c = structuredClone(cert);
  const ctl = nodeAt(c.tree, ['canister', cid, 'controllers']);
  ctl[2] = [4, treeHash(ctl[2])];
  assert.match(failedAt(await run(id, rebuild(body, c)), 'C5'), /pruned/);
  pass(`${id}: a pruned module hash or controllers is "not shown", never a value (C5)`);

  const badKey = Verifier.DEFAULTS.rootKey.slice(0, -2) + (Verifier.DEFAULTS.rootKey.endsWith('ae') ? 'af' : 'ae');
  const r = await run(id, rebuild(body, cert), { rootKey: badKey });
  assert.match(failedAt(r, cert.delegation ? 'C2' : 'C3'), cert.delegation ? /not signed by the NNS root key/ : /does not verify/);
  pass(`${id}: under another root key nothing verifies (${cert.delegation ? 'C2, the delegation' : 'C3, the certificate'})`);

  const noBls = await run(id, rebuild(body, cert), {}, load(false));
  assert.match(failedAt(noBls, cert.delegation ? 'C2' : 'C3'), /BLS verifier not loaded/);
  pass(`${id}: without core/bls12-381.js the certificate is reported unverified, not trusted`);
}

{
  const { body, cert } = parts(UMOBS);
  // umobs's certificate asked about the ledger: the ledger is on another
  // subnet, so the delegation does not cover it (and the tree would not
  // hold its paths either; the range check comes first).
  assert.match(failedAt(await run(LEDGER, rebuild(body, cert), { now: vectors[UMOBS].time + 1000 }), 'C2'), /outside the ranges/);
  pass('a certificate from one subnet does not speak for a canister on another (C2)');

  let c = structuredClone(cert);
  const dc = dec(c.delegation.certificate);
  dc.delegation = { subnet_id: c.delegation.subnet_id, certificate: c.delegation.certificate };
  c.delegation = { ...c.delegation, certificate: enc(dc) };
  assert.match(failedAt(await run(UMOBS, rebuild(body, c)), 'C2'), /delegation of its own/);
  pass('a delegation certificate carrying its own delegation is refused (C2)');

  c = structuredClone(cert);
  const ranges = nodeAt(dec(c.delegation.certificate).tree, ['subnet', c.delegation.subnet_id, 'canister_ranges']);
  const dc2 = dec(c.delegation.certificate);
  nodeAt(dc2.tree, ['subnet', c.delegation.subnet_id, 'canister_ranges'])[2] = [4, treeHash(ranges[2])];
  c.delegation = { ...c.delegation, certificate: enc(dc2) };
  assert.match(failedAt(await run(UMOBS, rebuild(body, c)), 'C2'), /no canister ranges/);
  pass('a delegation that hides its canister ranges is refused (C2)');

  // The delegation's own signature, altered: the subnet key is then
  // anyone's claim.
  c = structuredClone(cert);
  const dc3 = dec(c.delegation.certificate); dc3.signature[3] ^= 1;
  c.delegation = { ...c.delegation, certificate: enc(dc3) };
  assert.match(failedAt(await run(UMOBS, rebuild(body, c)), 'C2'), /not signed by the NNS root key/);
  pass('a delegation certificate with an altered signature is refused (C2)');

  // The time leaf pruned: a verified certificate with no date is a failure,
  // since freshness could not be judged.
  c = structuredClone(cert);
  const tn = nodeAt(c.tree, ['time']); tn[2] = [4, treeHash(tn[2])];
  assert.match(failedAt(await run(UMOBS, rebuild(body, c)), 'C4'), /no \/time/);
  pass('a certificate that hides /time fails C4');

  assert.match(failedAt(await run(UMOBS, enc({ nothing: 1 })), 'C1'), /no certificate/);
  const http = await Verifier.readCanisterState(UMOBS, { fetch: async () => ({ ok: false, status: 503 }) });
  assert.match(failedAt(http, 'C1'), /HTTP 503/);
  assert.match(failedAt(await Verifier.readCanisterState('not-a-canister', {}), 'C1'), /bad canister id/);
  pass('a reply without a certificate, an HTTP error, and a bad id fail C1 before anything is believed');
}

if (process.argv.includes('--live')) {
  for (const id of [UMOBS, LEDGER]) {
    const r = await Verifier.readCanisterState(id);
    assert.equal(r.certified, true, JSON.stringify(r.checks));
    assert.equal(r.stale, false);
    assert.match(r.moduleHash, /^[0-9a-f]{64}$/);
    pass(`live: ${id} certified now; module ${r.moduleHash.slice(0, 8)}..., controllers ${r.controllers.join(' ')}`);
  }
  const status = dec(new Uint8Array(await (await fetch(Verifier.DEFAULTS.icApi + '/api/v2/status')).arrayBuffer()));
  assert.equal(hex(status.root_key), Verifier.DEFAULTS.rootKey);
  pass('live: the pinned root key is the one /api/v2/status reports');
}

console.log(`certified reader: ${passed} checks passed`);
