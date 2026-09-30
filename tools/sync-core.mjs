#!/usr/bin/env node
// Copies core/verifier.js, the source of truth for the verification core,
// to the two places that carry it:
//   - loader/index.html, inline between its "// === core ===" and
//     "// === end core ===" lines: the loader is one self-contained file,
//     and its registry record is that file's hash;
//   - extension/verifier.js and extension-firefox/verifier.js, whole: an
//     extension can load only files inside its own package.
// It also copies extension/content.js, the content script both extensions
// share, to extension-firefox/content.js.
// Edits go to core/verifier.js and extension/content.js, and are synced
// from here.
//
//   node tools/sync-core.mjs          # rewrite every copy
//   node tools/sync-core.mjs --check  # exit 1 if any copy differs
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const START = '// === core ===', END = '// === end core ===';
const core = readFileSync(new URL('../core/verifier.js', import.meta.url), 'utf8').replace(/\n$/, '');
if (!core.startsWith(START) || !core.endsWith(END)) {
  console.error(`core/verifier.js must start with "${START}" and end with "${END}"`);
  process.exit(2);
}
const loaderUrl = new URL('../loader/index.html', import.meta.url);
const loader = readFileSync(loaderUrl, 'utf8');
const a = loader.indexOf(START), b = loader.indexOf(END);
if (a === -1 || b < a) {
  console.error('loader/index.html has no core block to replace');
  process.exit(2);
}
const copies = [
  { name: 'loader/index.html', url: loaderUrl, now: loader, want: loader.slice(0, a) + core + loader.slice(b + END.length) },
];
const whole = (name, want) => {
  const url = new URL('../' + name, import.meta.url);
  copies.push({ name, url, now: existsSync(url) ? readFileSync(url, 'utf8') : '', want });
};
whole('extension/verifier.js', core + '\n');
whole('extension-firefox/verifier.js', core + '\n');
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
