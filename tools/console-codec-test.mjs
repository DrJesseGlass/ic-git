#!/usr/bin/env node
// Checks the console's inline Candid/CBOR code (browser/index.html, the
// "candid" block) against encodings produced by the Rust candid crate:
//   cargo test -q --test candid_vectors -- --nocapture > vectors.txt
//   node tools/console-codec-test.mjs vectors.txt
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
globalThis.crypto ??= webcrypto;

const html = readFileSync(new URL('../browser/index.html', import.meta.url), 'utf8');
const block = html.slice(html.indexOf('// === candid ==='), html.indexOf('// === end candid ==='));
const IC = new Function(block + '\nreturn IC;')();
const vectors = Object.fromEntries(readFileSync(process.argv[2], 'utf8').split('\n')
  .filter(l => l.includes(' ') && !l.startsWith('VECTORS')).map(l => l.split(' ')));
const hex = b => IC.hex(b), unhex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));

const CANISTER = 'umobs-yiaaa-aaaab-agyrq-cai';
const USER = '3kq6u-eptpm-egjdi-5qvjv-twk23-m4ymt-qqrcs-tdkvy-ob7zx-x6qq3-wqe';
const ACCOUNT = { record: { owner: 'principal', subaccount: { opt: 'blob' } } };
const APPROVE = { record: { from_subaccount: { opt: 'blob' }, spender: ACCOUNT, amount: 'nat', expected_allowance: { opt: 'nat' }, expires_at: { opt: 'nat64' }, fee: { opt: 'nat' }, memo: { opt: 'blob' }, created_at_time: { opt: 'nat64' } } };

// Principal text round-trips through bytes and the checksum.
assert.equal(IC.principalToText(IC.principalFromText(USER)), USER);
assert.equal(IC.principalToText(IC.principalFromText(CANISTER)), CANISTER);
assert.throws(() => IC.principalFromText('aaaaa-aa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaa'));

// Argument encodings, byte for byte.
const enc = (types, values) => hex(IC.encode(types, values));
assert.equal(enc(['text'], ['ic-git']), vectors['args:text']);
assert.equal(enc(['text', 'principal', 'text'], ['ic-git', USER, 'writer']), vectors['args:text,principal,text']);
assert.equal(enc(['nat64'], [1_000_000_000_000n]), vectors['args:nat64']);
assert.equal(enc(['text', 'text', 'bool'], ['r', '0123456789abcdef0123456789abcdef01234567', true]), vectors['args:text,text,bool']);
assert.equal(enc(['text', 'nat32'], ['r', 2]), vectors['args:text,nat32']);
// create_push_token's lifetime, a trailing opt nat32.
assert.deepEqual(IC.decode(IC.encode(['text', { opt: 'nat32' }], ['r', 30])), IC.decode(unhex(vectors['args:text,opt_nat32_some'])));
assert.deepEqual(IC.decode(IC.encode(['text', { opt: 'nat32' }], ['r', null])), IC.decode(unhex(vectors['args:text,opt_nat32_none'])));
// ...and the SSH key a token is bound to, another trailing opt.
assert.deepEqual(IC.decode(IC.encode(['text', { opt: 'nat32' }, { opt: 'text' }], ['r', null, 'ssh-ed25519 AAAA'])), IC.decode(unhex(vectors['args:text,opt_nat32,opt_text'])));
// Composite types: the Rust crate orders its type table differently (both
// are valid Candid), so compare structurally after decoding both.
const approve = { from_subaccount: null, spender: { owner: CANISTER, subaccount: null }, amount: 5_000_000_000n, expected_allowance: null, expires_at: null, fee: null, memo: null, created_at_time: null };
const mine = IC.encode([APPROVE], [approve]);
assert.deepEqual(IC.decode(mine), IC.decode(unhex(vectors['args:approve'])));
assert.equal(hex(mine).slice(-40), vectors['args:approve'].slice(-40), 'value bytes identical');

// Reply decodings.
const dec = name => IC.decode(unhex(vectors[name]))[0];
assert.deepEqual(dec('reply:result_unit_ok'), { Ok: null });
assert.deepEqual(dec('reply:result_unit_err'), { Err: 'insufficient balance' });
assert.deepEqual(dec('reply:result_text_ok'), { Ok: '274f84a4' });
assert.deepEqual(dec('reply:result_nat64_ok'), { Ok: 123_456_789_012n });
assert.deepEqual(dec('reply:result_vote_ok'), { Ok: { 0: 1, 1: 2 } });
assert.deepEqual(dec('reply:result_members_ok'), { Ok: [{ principal: USER, role: { Voter: null } }] });
assert.deepEqual(dec('reply:result_account_ok'), { Ok: { balance: 7n, deposited: 8n, spent: 1n, created_ns: 1_700_000_000_000_000_000n } });
assert.deepEqual(dec('reply:result_principal_ok'), { Ok: CANISTER });
assert.deepEqual(dec('reply:icrc2_approve_ok'), { Ok: 42n });
// The two per-repo configs the ownership panel reads: opt records, with a
// variant for the install mode. Field and variant names must resolve, or
// the panel would print hashes.
assert.deepEqual(dec('reply:opt_deploy_config_some'), { target: CANISTER, source_path: 'app.wasm', mode: { upgrade: null } });
assert.equal(dec('reply:opt_deploy_config_none'), null);
assert.deepEqual(dec('reply:opt_site_some'), { root: 'browser' });
// The EVM leg's config, which the panel names (with its cost) before a deploy.
assert.deepEqual(dec('reply:opt_evm_deploy_config_some'), { source_path: 'build/Registry.hex', gas_limit: 1_500_000n });
assert.deepEqual(dec('reply:opt_site_reinstall_mode'), { target: CANISTER, source_path: 'x.wat', mode: { reinstall: null } });
// list_push_tokens: legacy tokens have no minter or creation time.
assert.deepEqual(dec('reply:push_tokens'), [
  { id: '0123456789abcdef', repo: 'r', minted_by: USER, created_ns: 1n, expires_ns: 2n, key: 'ssh-ed25519 AAAA' },
  { id: 'fedcba9876543210', repo: 'r', minted_by: null, created_ns: null, expires_ns: 3n, key: null }]);
// ICP deposits: the CMC's rate (for the estimate) and the pending list.
const rate = dec('reply:cmc_rate');
assert.equal(rate.data.xdr_permyriad_per_icp, 45_000n);
assert.equal(rate.data.timestamp_seconds, 1_790_000_000n);
assert.deepEqual(dec('reply:pending_icp'), [{ block_index: 42n, who: USER, e8s: 50_000_000n, at_ns: 7n, last_error: 'Processing' }]);
// deploy_now's reply, which the deploy-now and reinstall controls report.
assert.deepEqual(dec('reply:result_deploy_status_ok'), { Ok: { commit: '0123456789abcdef0123456789abcdef01234567', ok: true, message: 'installed', wasm_len: 365_000n, wasm_sha256: 'ab'.repeat(32) } });

// CBOR + hash tree: build a certificate-shaped structure by hand and look up a reply.
// CBOR bytes: {"tree": [2, "request_status", [2, <id>, [1, [2, "reply", [3, <candid>]], [2, "status", [3, "replied"]]]]]}
const te = new TextEncoder();
const bstr = b => [0x40 + b.length, ...b]; // short byte strings only
const tstr = s => { const b = te.encode(s); return [0x60 + b.length, ...b]; };
const arr = (...items) => [0x80 + items.length, ...items.flat()];
const reply = unhex(vectors['reply:result_unit_ok']);
const id = Uint8Array.from({ length: 20 }, (_, i) => i);
// Labels in a real certificate are byte strings.
const lbl = s => bstr(te.encode(s));
const tree = arr([2], lbl('request_status'), arr([2], bstr(id), arr([1], arr([2], lbl('reply'), arr([3], bstr(reply))), arr([2], lbl('status'), arr([3], bstr(te.encode('replied')))))));
const cert = Uint8Array.from([0xa1, ...tstr('tree'), ...tree]);
const parsed = IC.cbor(cert);
assert.deepEqual(IC.decode(IC.lookup(parsed.tree, ['request_status', id, 'reply']))[0], { Ok: null });
assert.equal(new TextDecoder().decode(IC.lookup(parsed.tree, ['request_status', id, 'status'])), 'replied');
assert.equal(IC.lookup(parsed.tree, ['request_status', id, 'nope']), undefined);

// Request id: the IC spec's worked example for a content map.
const spec = { request_type: 'call', canister_id: Uint8Array.from([0, 0, 0, 0, 0, 0, 4, 210]), method_name: 'hello', arg: Uint8Array.from([68, 73, 68, 76, 0, 253, 42]) };
assert.equal(hex(await IC.requestId(spec)), '8781291c347db32a9d8c10eb62b710fce5a93be676474c42babc74c51858f94b');

// CBOR encoder: a query envelope round-trips through the decoder, and the
// bytes match a hand-assembled encoding (self-describing tag, then a map).
const envelope = { content: { request_type: 'query', sender: Uint8Array.of(4), canister_id: IC.principalFromText(CANISTER), method_name: 'icrc1_balance_of', arg: IC.encode([ACCOUNT], [{ owner: USER, subaccount: null }]), ingress_expiry: 1_700_000_000_000_000_000n } };
const back = IC.cbor(IC.cborEnc(envelope));
assert.equal(back.content.request_type, 'query');
assert.deepEqual(Array.from(back.content.sender), [4]);
assert.equal(IC.principalToText(back.content.canister_id), CANISTER);
assert.deepEqual(IC.decode(back.content.arg), IC.decode(envelope.content.arg));
assert.equal(back.content.ingress_expiry, 1_700_000_000_000_000_000n);
assert.equal(hex(IC.cborEnc({ a: 1, b: 'x', c: Uint8Array.of(9), d: [23, 24, 256, 65536] })), 'd9d9f7a461610161626178616341096164841718181901001a00010000');
assert.equal(hex(IC.cborEnc(4294967296n)), 'd9d9f71b0000000100000000');

console.log('console codec: all vector checks passed');
