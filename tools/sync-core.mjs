#!/usr/bin/env node
// Copies core/verifier.js, the source of truth for the verification core,
// and core/bls12-381.js, the vendored BLS verifier it needs for certified
// reads (tools/vendor-bls.mjs), to the places that carry them:
//   - loader/index.html, inline between its "// === bls ===" ..
//     "// === end bls ===" and "// === core ===" .. "// === end core ==="
//     lines: the loader is one self-contained file, and its registry record
//     is that file's hash;
//   - extension/ and extension-firefox/, as bls12-381.js and verifier.js,
//     whole: an extension can load only files inside its own package.
// It also copies extension/content.js, the content script both extensions
// share, to extension-firefox/content.js.
// Edits go to core/verifier.js and extension/content.js, and are synced
// from here; core/bls12-381.js is regenerated, never edited.
//
//   node tools/sync-core.mjs          # rewrite every copy
//   node tools/sync-core.mjs --check  # exit 1 if any copy differs
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const block = (file, START, END) => {
  const text = readFileSync(new URL('../' + file, import.meta.url), 'utf8').replace(/\n$/, '');
  if (!text.startsWith(START) || !text.endsWith(END)) {
    console.error(`${file} must start with "${START}" and end with "${END}"`);
    process.exit(2);
  }
  return { text, START, END };
};
const core = block('core/verifier.js', '// === core ===', '// === end core ===');
const bls = block('core/bls12-381.js', '// === bls ===', '// === end bls ===');
const loaderUrl = new URL('../loader/index.html', import.meta.url);
const loader = readFileSync(loaderUrl, 'utf8');
let want = loader;
for (const { text, START, END } of [bls, core]) {
  const a = want.indexOf(START), b = want.indexOf(END);
  if (a === -1 || b < a) {
    console.error(`loader/index.html has no ${START} block to replace`);
    process.exit(2);
  }
  want = want.slice(0, a) + text + want.slice(b + END.length);
}
const copies = [
  { name: 'loader/index.html', url: loaderUrl, now: loader, want },
];
const whole = (name, want) => {
  const url = new URL('../' + name, import.meta.url);
  copies.push({ name, url, now: existsSync(url) ? readFileSync(url, 'utf8') : '', want });
};
whole('extension/verifier.js', core.text + '\n');
whole('extension-firefox/verifier.js', core.text + '\n');
whole('extension/bls12-381.js', bls.text + '\n');
whole('extension-firefox/bls12-381.js', bls.text + '\n');
whole('extension-firefox/content.js', readFileSync(new URL('../extension/content.js', import.meta.url), 'utf8'));
const stale = copies.filter(c => c.now !== c.want);
if (process.argv.includes('--check')) {
  for (const c of stale) console.error(`${c.name} is out of step with its source: run node tools/sync-core.mjs`);
  if (stale.length) process.exit(1);
  console.log('every copy is in step: ' + copies.map(c => c.name).join(', '));
} else {
  for (const c of stale) { writeFileSync(c.url, c.want); console.log(`synced ${c.name}`); }
  if (!stale.length) console.log('every copy already in step');
}
