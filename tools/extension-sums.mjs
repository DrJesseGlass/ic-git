#!/usr/bin/env node
// The file list of an extension package, as its registry record attests it
// (docs/EXTENSION.md, "How the extension's own package is verified").
//
//   node tools/extension-sums.mjs <dir>            # print the listing
//   node tools/extension-sums.mjs --digest <dir>   # print sha256 of the listing
//   node tools/extension-sums.mjs --write <dir>    # write <dir>/SHA256SUMS
//   node tools/extension-sums.mjs --check <dir>... # exit 1 if a SHA256SUMS is stale
//
// <dir> is the package as committed (extension/, extension-firefox/) or as
// installed: Chrome's .../Extensions/<id>/<version>/, or an unzipped .xpi.
// The digest of an installed copy equals the record's bundleHash exactly
// when it holds the published files.
//
// The listing: one line per file, "<sha256>  <path>", in byte order of path
// (the format of `shasum -a 256`, and independent of the user's locale),
// over every file in <dir> except SHA256SUMS itself and what a store adds
// (Chrome's _metadata/, the .xpi signature in META-INF/). Every file is
// hashed as its bytes but one: manifest.json, which Chrome's installer
// re-serializes and adds update_url to, is hashed as its canonical JSON --
// keys sorted, no whitespace, update_url removed. An honest install then
// lists the same, and a manifest with any other value changed does not.
// Zero dependencies (node >= 18).
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const SKIP_TOP = new Set(['SHA256SUMS', '_metadata', 'META-INF']);
const sha256 = data => createHash('sha256').update(data).digest('hex');

// Canonical JSON: object keys sorted by code unit, arrays in order, no
// whitespace -- the same text whatever layout and key order a tool wrote.
const canonical = v => Array.isArray(v) ? '[' + v.map(canonical).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}'
  : JSON.stringify(v);

export function manifestHash(bytes) {
  const m = JSON.parse(bytes.toString('utf8'));
  delete m.update_url;
  return sha256(canonical(m));
}

function files(dir) {
  const out = [];
  const walk = d => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      const rel = relative(dir, p).split(sep).join('/');
      if (!rel.includes('/') && SKIP_TOP.has(name)) continue;
      if (statSync(p).isDirectory()) walk(p); else out.push(rel);
    }
  };
  walk(dir);
  // Byte order of path, not the locale's.
  return out.sort((a, b) => (Buffer.compare(Buffer.from(a), Buffer.from(b))));
}

export function listing(dir) {
  return files(dir).map(rel => {
    if (rel.includes('<') || rel.includes('\n')) throw new Error('a path the listing cannot carry: ' + JSON.stringify(rel));
    const bytes = readFileSync(join(dir, rel));
    return (rel === 'manifest.json' ? manifestHash(bytes) : sha256(bytes)) + '  ' + rel + '\n';
  }).join('');
}

export const digest = dir => sha256(listing(dir));

if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1]).href) {
  const args = process.argv.slice(2);
  const mode = args[0] && args[0].startsWith('--') ? args.shift() : '--list';
  if (!args.length) {
    console.error('usage: extension-sums.mjs [--digest|--write|--check] <dir>...');
    process.exit(2);
  }
  let stale = 0;
  for (const dir of args) {
    if (!existsSync(join(dir, 'manifest.json'))) { console.error(`${dir}: no manifest.json -- not an extension package`); process.exit(2); }
    const text = listing(dir);
    if (mode === '--list') process.stdout.write(text);
    else if (mode === '--digest') console.log(sha256(text) + (args.length > 1 ? '  ' + dir : ''));
    else if (mode === '--write') { writeFileSync(join(dir, 'SHA256SUMS'), text); console.log(`${dir}/SHA256SUMS: ${sha256(text)}`); }
    else if (mode === '--check') {
      const have = existsSync(join(dir, 'SHA256SUMS')) ? readFileSync(join(dir, 'SHA256SUMS'), 'utf8') : '';
      if (have !== text) { console.error(`${dir}/SHA256SUMS is stale: run node tools/extension-sums.mjs --write ${dir}`); stale++; }
      else console.log(`${dir}/SHA256SUMS is current (${sha256(text)})`);
    } else { console.error('unknown mode ' + mode); process.exit(2); }
  }
  process.exit(stale ? 1 : 0);
}
