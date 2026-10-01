#!/usr/bin/env node
// Checks tools/extension-sums.mjs and the SHA256SUMS it keeps:
//   - extension/SHA256SUMS and extension-firefox/SHA256SUMS are current;
//   - each passes the canister's reference scan, as publishing requires;
//   - an install that changes only what a store changes -- manifest.json
//     re-serialized with update_url added, _metadata/ and META-INF/ added --
//     has the same digest, and any other change has a different one.
//
//   node tools/extension-sums-test.mjs
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest, listing } from './extension-sums.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
let failed = 0;
const report = (name, ok, got) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || got === undefined ? '' : '\n        got ' + got}`);
  if (!ok) failed++;
};

// The scanner, from the shared block in tools/verify.mjs.
const v = readFileSync(join(root, 'tools/verify.mjs'), 'utf8');
const block = v.slice(v.indexOf('// === shared: unverifiableSubresource ==='), v.indexOf('// === end shared ==='));
const scan = new Function(block + '\nreturn unverifiableSubresource;')();

for (const pkg of ['extension', 'extension-firefox']) {
  const dir = join(root, pkg);
  const sums = readFileSync(join(dir, 'SHA256SUMS'));
  report(`${pkg}/SHA256SUMS is current`, sums.toString('utf8') === listing(dir));
  const why = scan(pkg + '/SHA256SUMS', sums);
  report(`${pkg}/SHA256SUMS passes the reference scan (publishable)`, why === null, why);

  const want = digest(dir);
  const work = mkdtempSync(join(tmpdir(), 'sums-'));
  try {
    const fresh = () => { rmSync(join(work, 'p'), { recursive: true, force: true }); cpSync(dir, join(work, 'p'), { recursive: true }); return join(work, 'p'); };
    const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));

    // What a store install changes: the manifest's layout and key order,
    // update_url, and its own files.
    let p = fresh();
    const reordered = Object.fromEntries(Object.entries({ ...manifest, update_url: 'https://clients2.google.com/service/update2/crx' }).reverse());
    writeFileSync(join(p, 'manifest.json'), JSON.stringify(reordered, null, 3) + '\r\n');
    mkdirSync(join(p, '_metadata'), { recursive: true });
    writeFileSync(join(p, '_metadata', 'verified_contents.json'), '{}');
    mkdirSync(join(p, 'META-INF'), { recursive: true });
    writeFileSync(join(p, 'META-INF', 'cose.sig'), 'sig');
    report(`${pkg}: a store-style install (manifest re-serialized, update_url, _metadata/, META-INF/) has the same digest`, digest(p) === want);

    // What it must not hide.
    p = fresh();
    writeFileSync(join(p, 'manifest.json'), JSON.stringify({ ...manifest, version: manifest.version + '.1' }));
    report(`${pkg}: a changed manifest value changes the digest`, digest(p) !== want);
    p = fresh();
    const bg = readFileSync(join(p, 'background.js'));
    bg[bg.length - 2] ^= 1;
    writeFileSync(join(p, 'background.js'), bg);
    report(`${pkg}: one changed byte in a script changes the digest`, digest(p) !== want);
    p = fresh();
    writeFileSync(join(p, 'extra.js'), 'void 0;\n');
    report(`${pkg}: an added file changes the digest`, digest(p) !== want);
    p = fresh();
    rmSync(join(p, 'content.js'));
    report(`${pkg}: a removed file changes the digest`, digest(p) !== want);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
