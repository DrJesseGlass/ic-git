#!/usr/bin/env node
// Checks the console's routes block (browser/index.html, "routes"): which
// canister each of its calls goes to, after the canister split
// (docs/CANISTER_SPLIT.md, step 14c). Offline.
//   - the pinned mainnet ids are canister_ids.json's;
//   - on a pinned host the authority is known without asking; on another
//     canister's host it is the serving canister's get_authority, a
//     canister without that method is the authority itself, and one naming
//     none is refused;
//   - at its home (ic-git.com, exactly) the canisters are the pinned ones,
//     at their raw hosts, and only there does the console sign; every
//     spelling of a canister's host is one, a prefix up to "--" included;
//     a page that is at neither has no canister to talk to;
//   - reads go by the page's base URL, signing by its address;
//   - the other canister's origin keeps the host's gateway and port;
//   - the routes run before the git browser, which reads through them;
//   - every method the console signs or queries on its own canisters is
//     routed to one that has it: the git canister's methods in git.did,
//     the rest in authority.did, and all of them in the combined build.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const read = p => readFileSync(new URL(p, import.meta.url), 'utf8');
const html = read('../browser/index.html');
const block = (a, b) => html.slice(html.indexOf(a), html.indexOf(b));
const Routes = new Function(block('// === routes ===', '// === end routes ===') + '\nreturn Routes;')();
const ids = JSON.parse(read('../canister_ids.json'));
const AUTH = ids.git.ic, GIT = ids.git_canister.ic;

// A canister's service methods, as its .did declares them.
const methods = did => new Set([...did.matchAll(/^\s*"?([a-z_0-9]+)"?\s*:\s*\(/gm)].map(m => m[1]));
const git = methods(read('../canisters/git/git.did')), authority = methods(read('../canisters/authority/authority.did'));
const combined = methods(read('../canisters/combined/combined.did'));

const loc = (host, protocol = 'https:') => ({ hostname: host.replace(/:\d+$/, ''), host, protocol });
const never = () => { throw new Error('asked'); };

// The pins.
assert.equal(await Routes.authorityOf(loc(AUTH + '.raw.icp0.io'), never), AUTH);
assert.equal(await Routes.authorityOf(loc(GIT + '.raw.icp0.io'), never), AUTH);
console.log('PASS  mainnet: the authority is pinned for both ids, as canister_ids.json has them');

// Elsewhere: asked of the serving canister.
const local = loc('bkyz2-fmaaa-aaaaa-qaaaq-cai.raw.localhost:4943', 'http:');
const asks = answer => async (id, method) => { assert.equal(id, 'bkyz2-fmaaa-aaaaa-qaaaq-cai'); assert.equal(method, 'get_authority'); return answer(); };
const reject = (message, errorCode) => () => { const e = new Error(message); e.errorCode = errorCode; e.rejectCode = 3; throw e; };
assert.equal(await Routes.authorityOf(local, asks(() => [AUTH])), AUTH);
// The one-canister build: told by the error code, or by the replica's words when a gateway drops it.
assert.equal(await Routes.authorityOf(local, asks(reject('get_authority rejected: method not found', 'IC0536'))), 'bkyz2-fmaaa-aaaaa-qaaaq-cai');
assert.equal(await Routes.authorityOf(local, asks(reject("get_authority rejected: Canister bkyz2-fmaaa-aaaaa-qaaaq-cai has no query method 'get_authority'"))), 'bkyz2-fmaaa-aaaaa-qaaaq-cai');
await assert.rejects(Routes.authorityOf(local, asks(() => [null])), /names no authority/);
await assert.rejects(Routes.authorityOf(local, asks(() => { throw new Error('get_authority: HTTP 502'); })), /502/);
await assert.rejects(Routes.authorityOf(local, asks(reject('get_authority rejected: canister trapped', 'IC0503'))), /trapped/);
console.log('PASS  elsewhere: the serving canister is asked; no method means one canister; no answer is refused');

// At home: the pinned canisters, nothing asked, and the only place the
// console signs.
const home = loc('ic-git.com');
assert.equal(Routes.HOME, 'https://ic-git.com');
assert.equal(await Routes.authorityOf(home, never), AUTH);
assert.equal(Routes.hostOf(home), GIT);
assert.equal(Routes.originOf(home, GIT), 'https://' + GIT + '.raw.icp0.io');
assert.equal(Routes.originOf(home, AUTH), 'https://' + AUTH + '.raw.icp0.io');
assert.equal(Routes.signs(home), true);
console.log('PASS  at home: the pinned canisters at their raw hosts, and a wallet may be asked to sign');

// On a canister's own host, which every site there shares, in any of the
// spellings a gateway serves it at: the canister it names, no signing.
for (const h of [GIT + '.raw.icp0.io', GIT + '.icp0.io', GIT + '.icp1.io', GIT + '.raw.ic0.app', 'x--' + GIT + '.raw.icp0.io', 'a--b--' + GIT + '.icp0.io', 'ic-git--' + GIT + '.icp.net']) {
  assert.equal(Routes.signs(loc(h)), false, h);
  assert.equal(Routes.hostOf(loc(h)), GIT, h);
  assert.equal(await Routes.authorityOf(loc(h), never), AUTH, h);
  assert.equal(Routes.originOf(loc(h), AUTH), 'https://' + h.replace(/^[^.]+/, AUTH), h);
}
for (const l of [loc(AUTH + '.raw.icp0.io'), local, loc('x--bkyz2-fmaaa-aaaaa-qaaaq-cai.raw.localhost:4943', 'http:')]) {
  assert.equal(Routes.signs(l), false, l.host);
}
console.log('PASS  on a canister\'s own host, a gateway\'s prefix and domain included, the console signs nothing');

// Neither: said plainly, nothing asked, nothing signed. Another domain is
// not home, whoever serves the page there.
for (const l of [loc('git.example.org'), loc('constructor.example'), loc('www.ic-git.com'), loc('ic-git.com.'), loc('ic-git.com:8443'), loc('ic-git.com', 'http:'),
  loc('localhost:4943', 'http:'), loc('x.localhost:4943', 'http:'), loc('umobs-yiaaa-aaaab-agyrq-cai'), loc('x--y.icp0.io'), loc('', 'file:')]) {
  await assert.rejects(Routes.authorityOf(l, never), /neither at a canister's own host nor at https:\/\/ic-git\.com/, l.host);
  assert.match(Routes.nowhere(l), /no canister to talk to/, l.host);
  assert.equal(Routes.signs(l), false, l.host);
}
for (const l of [home, loc(GIT + '.raw.icp0.io'), loc('x--' + GIT + '.icp0.io'), local]) assert.equal(Routes.nowhere(l), null, l.host);
console.log('PASS  another domain, a bare localhost, plain http or a file: no canister to talk to, nothing signed');

// The git browser reads through the routes as it starts, so they must be
// defined by then: a script of their own, ahead of it.
// Both read by the page's base URL (where the loader's run of the page
// reads too) and sign by its address.
const browserSrc = block('// === end diff ===', '// === console ===');
const firstRead = html.indexOf('const GIT = Routes.originOf(HERE, Routes.hostOf(HERE));');
assert.ok(firstRead > 0 && html.indexOf('// === end routes ===') < firstRead, 'the routes are defined after the git browser that uses them');
assert.match(browserSrc, /const HERE = new URL\(document\.baseURI\);\n  const GIT = Routes\.originOf\(HERE, Routes\.hostOf\(HERE\)\);/);
// And the console holds no principal and opens no wallet where it may not
// sign, nor in a frame, and drops one stored there before.
const consoleSrc = block('// === console ===', '// === end console ===');
assert.match(consoleSrc, /const HERE = new URL\(document\.baseURI\);\n  const HOST = Routes\.hostOf\(HERE\);/);
assert.match(consoleSrc, /Routes\.authorityOf\(HERE, IC\.query\)/);
assert.doesNotMatch(consoleSrc, /Routes\.(hostOf|originOf|authorityOf)\(location/);
assert.match(consoleSrc, /const FRAMED = window\.top !== window\.self;\n  const SIGNS = Routes\.signs\(location\) && !FRAMED;/);
assert.match(consoleSrc, /if \(SIGNS\) me = localStorage\.getItem\('ic-git\.principal'\); else localStorage\.removeItem\('ic-git\.principal'\);/);
assert.match(consoleSrc, /async function session\(fn\) \{\n    if \(!SIGNS\) throw/);
assert.match(consoleSrc, /async function signIn\(\) \{\n    if \(!SIGNS\) return;/);
console.log('PASS  the routes run before the git browser; the console signs only where they say');

// Origins.
assert.equal(Routes.hostOf(loc(GIT + '.raw.icp0.io')), GIT);
assert.equal(Routes.originOf(loc(GIT + '.raw.icp0.io'), AUTH), 'https://' + AUTH + '.raw.icp0.io');
assert.equal(Routes.originOf(local, AUTH), 'http://' + AUTH + '.raw.localhost:4943');
assert.equal(Routes.originOf(loc(AUTH + '.raw.icp0.io'), AUTH), 'https://' + AUTH + '.raw.icp0.io');
console.log('PASS  the other canister\'s origin keeps the gateway and the port');

// Every call the console makes on its own canisters lands on one that has
// the method. Ledger calls name their canister and are not routed.
const console_ = block('// === console ===', '// === end console ===');
const LEDGER = new Set(['icrc2_approve', 'icrc1_balance_of', 'icrc1_fee', 'icrc1_decimals', 'icrc1_symbol', 'get_icp_xdr_conversion_rate']);
const called = new Set([...console_.matchAll(/\b(?:write|s)\('([a-z_0-9]+)'/g), ...console_.matchAll(/IC\.query\([A-Za-z_().']+, '([a-z_0-9]+)'/g)].map(m => m[1]).filter(m => !LEDGER.has(m)));
const cfg = [...console_.matchAll(/cfg\('([a-z_0-9]+)'\)/g)].map(m => m[1]);
// Every query names its canister through the routes (at(method)), a
// ledger constant, or the cfg helper, so GIT_METHODS is the one source.
for (const m of console_.matchAll(/IC\.query\(([^,]+), ('[a-z_0-9]+'|method)/g)) {
  assert.ok(new RegExp('^(at\\(' + m[2] + '\\)|ledger|CMC)$').test(m[1]), 'IC.query(' + m[1] + ', ' + m[2] + ') names its canister outside the routes');
}
for (const m of [...called, ...cfg]) {
  const want = Routes.canisterFor('git', 'authority', m);
  assert.ok((want === 'git' ? git : authority).has(m), m + ' is routed to the ' + want + ' canister, whose .did lacks it');
  assert.ok(combined.has(m), m + ' is missing from the combined build');
}
for (const m of Routes.GIT_METHODS) assert.ok(git.has(m) && !authority.has(m), m + ' is listed as the git canister\'s, but authority.did has it too');
assert.ok(called.size >= 20, 'found only ' + called.size + ' routed calls');
console.log('PASS  ' + (called.size + cfg.length) + ' console calls each land on a canister that has the method');
console.log('\nall passed');
