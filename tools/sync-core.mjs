#!/usr/bin/env node
// Copies core/verifier.js, the source of truth for the verification core,
// into loader/index.html between its "// === core ===" and
// "// === end core ===" lines. The loader has to carry the core inline --
// it is one self-contained file, and its registry record is that file's
// hash -- so edits go to core/verifier.js and are synced here.
//
//   node tools/sync-core.mjs          # rewrite the loader's copy
//   node tools/sync-core.mjs --check  # exit 1 if the copy differs
import { readFileSync, writeFileSync } from 'node:fs';

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
const synced = loader.slice(0, a) + core + loader.slice(b + END.length);
if (process.argv.includes('--check')) {
  if (synced !== loader) {
    console.error('loader/index.html is out of step with core/verifier.js: run node tools/sync-core.mjs');
    process.exit(1);
  }
  console.log('loader/index.html carries core/verifier.js');
} else if (synced !== loader) {
  writeFileSync(loaderUrl, synced);
  console.log('synced core/verifier.js into loader/index.html');
} else {
  console.log('loader/index.html already carries core/verifier.js');
}
