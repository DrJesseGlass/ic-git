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

console.log('console codec: all vector checks passed');
