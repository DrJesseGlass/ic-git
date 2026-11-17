#!/usr/bin/env node
// Checks the repo browser's line diff (browser/index.html, the "diff"
// block) three ways:
//   - fixed cases, against the hunks `git diff` prints for them;
//   - random files: the hunks, applied to the old file, give the new one,
//     and they hold exactly as many changed lines as git's own Myers diff
//     of the same two files (both are shortest, so the counts agree even
//     where the scripts do not);
//   - the limit: two files too far apart are refused, not half-compared.
//
//   node tools/browser-diff-test.mjs
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const html = readFileSync(new URL('../browser/index.html', import.meta.url), 'utf8');
const start = html.indexOf('// === diff ==='), end = html.indexOf('// === end diff ===');
assert.ok(start >= 0 && end > start, 'browser/index.html has no diff block');
const Diff = new Function(html.slice(start, end) + '\nreturn Diff;')();

let checks = 0;
const pass = what => { checks++; console.log('PASS  ' + what); };

// The hunks as `git diff` prints them, from the first "@@" on.
const NOEOL = '\\ No newline at end of file';
function unified(a, b, ctx) {
  const hs = Diff.hunks(a, b, ctx);
  assert.ok(hs, 'within the limit');
  let out = '';
  for (const h of hs) {
    out += Diff.header(h) + '\n';
    for (const [op, text, , , bare] of h.lines) out += op + text + '\n' + (bare ? NOEOL + '\n' : '');
  }
  return out;
}

// Apply hunks to the old text: the lines between hunks are the old
// file's, the hunk's lines without '-' are the new file's.
function apply(a, hs) {
  const A = Diff.split(a);
  const out = [];
  let at = 0, bare = A.noeol;
  for (const h of hs) {
    const first = h.an ? h.a - 1 : h.a;
    while (at < first) out.push(A.lines[at++]);
    for (const [op, text, oldNo, newNo, noNewline] of h.lines) {
      if (op !== '+') {
        assert.equal(text, A.lines[at], 'a hunk line is the old file\'s line');
        assert.equal(oldNo, at + 1, 'and numbered as it');
        at++;
      } else assert.equal(oldNo, null);
      if (op !== '-') {
        out.push(text);
        assert.equal(newNo, out.length, 'new lines are numbered in order');
        bare = noNewline;
      } else assert.equal(newNo, null);
    }
    assert.equal(h.lines.filter(l => l[0] !== '+').length, h.an);
    assert.equal(h.lines.filter(l => l[0] !== '-').length, h.bn);
  }
  if (at < A.lines.length) bare = A.noeol;
  while (at < A.lines.length) out.push(A.lines[at++]);
  return out.length ? out.join('\n') + (bare ? '' : '\n') : '';
}

// The hunks git prints for two files (its Myers diff, hunks not slid),
// past the four header lines, a hunk header's trailing section name off.
const dir = mkdtempSync(join(tmpdir(), 'ic-git-diff-'));
function gitDiff(a, b) {
  writeFileSync(join(dir, 'a'), a);
  writeFileSync(join(dir, 'b'), b);
  let out = '';
  try {
    // git as it ships, whatever this machine's configuration says.
    execFileSync('git', ['diff', '--no-index', '--no-color', '--no-ext-diff', '--no-textconv', '--diff-algorithm=myers', '--no-indent-heuristic', '--inter-hunk-context=0', '-U3', 'a', 'b'],
      { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_EXTERNAL_DIFF: '' } });
  } catch (e) { out = e.stdout; }
  return out.split('\n').slice(4).join('\n').replace(/^(@@ [^@]* @@).*$/gm, '$1');
}
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));

// --- fixed cases, as git prints them ---
const seq = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => 'line ' + (from + i) + '\n').join('');
const cases = [
  ['nothing changed', seq(1, 5), seq(1, 5), ''],
  ['a new file', '', 'one\ntwo\nthree\n', '@@ -0,0 +1,3 @@\n+one\n+two\n+three\n'],
  ['a file emptied', 'one\ntwo\n', '', '@@ -1,2 +0,0 @@\n-one\n-two\n'],
  ['one line of one', 'one\n', 'uno\n', '@@ -1 +1 @@\n-one\n+uno\n'],
  ['a line changed in the middle, three lines around it',
    seq(1, 10), seq(1, 4) + 'changed\n' + seq(6, 10),
    '@@ -2,7 +2,7 @@\n line 2\n line 3\n line 4\n-line 5\n+changed\n line 6\n line 7\n line 8\n'],
  ['a line added at the end', seq(1, 4), seq(1, 4) + 'more\n',
    '@@ -2,3 +2,4 @@\n line 2\n line 3\n line 4\n+more\n'],
  ['two changes six lines apart share a hunk',
    seq(1, 20), 'first\n' + seq(2, 7) + 'second\n' + seq(9, 20),
    '@@ -1,11 +1,11 @@\n-line 1\n+first\n' + seq(2, 7).replace(/^/gm, ' ').replace(/ $/, '') + '-line 8\n+second\n line 9\n line 10\n line 11\n'],
  ['seven lines apart, two hunks',
    seq(1, 20), 'first\n' + seq(2, 8) + 'second\n' + seq(10, 20),
    '@@ -1,4 +1,4 @@\n-line 1\n+first\n line 2\n line 3\n line 4\n@@ -6,7 +6,7 @@\n line 6\n line 7\n line 8\n-line 9\n+second\n line 10\n line 11\n line 12\n'],
  ['the last line loses its newline', 'a\nb\n', 'a\nb',
    '@@ -1,2 +1,2 @@\n a\n-b\n+b\n' + NOEOL + '\n'],
  ['and gains it', 'a\nb', 'a\nb\n', '@@ -1,2 +1,2 @@\n a\n-b\n' + NOEOL + '\n+b\n'],
  ['a line added after a last line without one', 'a\nb', 'a\nb\nc',
    '@@ -1,2 +1,3 @@\n a\n-b\n' + NOEOL + '\n+b\n+c\n' + NOEOL + '\n'],
  ['unchanged, no newline at the end of either', 'a\nb\nc', 'x\nb\nc',
    '@@ -1,3 +1,3 @@\n-a\n+x\n b\n c\n' + NOEOL + '\n'],
];
for (const [what, a, b, want] of cases) {
  assert.equal(unified(a, b), want, what);
  assert.equal(gitDiff(a, b), want, what + ': git prints the same');
  assert.equal(apply(a, Diff.hunks(a, b)), b, what + ': applies');
}
pass(cases.length + ' fixed cases print as git prints them');

assert.equal(unified(seq(1, 10), seq(1, 4) + 'changed\n' + seq(6, 10), 0), '@@ -5 +5 @@\n-line 5\n+changed\n');
assert.equal(unified(seq(1, 4), seq(1, 2) + 'new\n' + seq(3, 4), 0), '@@ -2,0 +3 @@\n+new\n');
assert.equal(unified(seq(1, 4), seq(1, 2) + seq(4, 4), 0), '@@ -3 +2,0 @@\n-line 3\n');
pass('with no context a side without lines is numbered by the line before');

// --- random files, against git itself ---
let seed = 20261117;
const rnd = n => { seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff; return seed % n; };
const changed = text => text.split('\n').filter(l => /^[+-]/.test(l)).length;
let n = 0, identical = 0;
{
  for (let t = 0; t < 400; t++) {
    const alphabet = 2 + rnd(8);
    const file = len => Array.from({ length: len }, () => 'l' + rnd(alphabet)).join('\n') + (len && rnd(4) ? '\n' : '');
    const a = file(rnd(60));
    let b = file(rnd(60));
    // Half the time, an edit of the old file, as a commit is.
    if (rnd(2)) {
      const L = Diff.split(a).lines.slice();
      for (let i = rnd(5); i >= 0; i--) L.splice(rnd(L.length + 1), rnd(3), ...Array.from({ length: rnd(3) }, () => 'x' + rnd(9)));
      b = L.join('\n') + (L.length && rnd(4) ? '\n' : '');
    }
    const hs = Diff.hunks(a, b);
    assert.ok(hs);
    assert.equal(apply(a, hs), b, JSON.stringify([a, b]));
    if (a === b) { assert.equal(hs.length, 0); continue; }
    const theirs = gitDiff(a, b);
    const ours = unified(a, b);
    assert.equal(changed(ours), changed(theirs), 'as many changed lines as git\n' + JSON.stringify([a, b]));
    n++;
    if (ours === theirs) identical++;
  }
}
// Where two shortest scripts exist git may print the other, so only the
// count is held to; how many came out the same to the letter is reported.
pass(n + ' random pairs apply, and are as short as git\'s (' + identical + ' of them git\'s to the letter)');

// --- the limit ---
const far = (tag, len) => Array.from({ length: len }, (_, i) => tag + i + '\n').join('');
assert.equal(Diff.hunks(far('a', 1500), far('b', 1500)), null);
assert.ok(Diff.hunks(far('a', 900), far('b', 900)));
const big = far('same', 50000);
const one = Diff.hunks(big, big.replace('same25000\n', 'other\n'));
assert.equal(one.length, 1);
assert.equal(Diff.header(one[0]), '@@ -24998,7 +24998,7 @@');
// Lines only added, or only taken away, are never too many: a new file,
// a file gone, a block put into the middle of one.
const added = Diff.hunks('', far('n', 5000));
assert.equal(added.length, 1);
assert.equal(Diff.header(added[0]), '@@ -0,0 +1,5000 @@');
assert.equal(Diff.header(Diff.hunks(far('n', 5000), '')[0]), '@@ -1,5000 +0,0 @@');
const put = Diff.hunks(seq(1, 10), seq(1, 5) + far('n', 3000) + seq(6, 10));
assert.equal(Diff.header(put[0]), '@@ -3,6 +3,3006 @@');
assert.equal(apply(seq(1, 10), put), seq(1, 5) + far('n', 3000) + seq(6, 10));
pass('files more than 2000 edits apart are refused; a long file with one change, a long new file and a long block added are not');

console.log('browser diff: ' + checks + ' checks passed');
