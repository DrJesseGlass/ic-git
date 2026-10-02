#!/usr/bin/env node
// Puts pages to the walk that check E and derivePolicy share (readPage in
// core/verifier.js), and to what it must agree with:
//
//   node tools/walk-fuzz.mjs --browser <binary> [--firefox]
//     In a browser, with no driver.
//     Random pages: for every one check E accepts, the browser's own HTML
//     parser must find nothing check E exists to refuse, and exactly the
//     scripts and styles derivePolicy pins -- parsed with DOMParser
//     (scripting off), and --frames of them by a real navigation (scripting
//     on, under a policy that runs nothing), those with a <noscript> first.
//     Every context: up to --depth structural tags, then something the walk
//     reads as text, then up to one end tag, then an <iframe>. Where check E
//     accepts the page, the parser must not have built the iframe: if it
//     did, the walk skipped what the browser parsed.
//   node tools/walk-fuzz.mjs --rust
//     The canister's port (site.rs read_page) must give every random page
//     the same verdict, reason and all. Runs the ignored cargo test that
//     checks it.
//
//   --seed N (1)   --pages N (100000)   --frames N (3000)   --depth N (2)
//
// A random page is a few tokens from VOCAB, drawn with a seeded generator,
// so a run can be repeated. Edit the walk, run both.
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const arg = (name, fallback) => process.argv.includes(name) ? process.argv[process.argv.indexOf(name) + 1] : fallback;
const seed = Number(arg('--seed', 1)), count = Number(arg('--pages', 100000)), frames = Number(arg('--frames', 3000)), depth = Number(arg('--depth', 2));
const bin = arg('--browser'), rust = process.argv.includes('--rust');
if (!bin && !rust) {
  console.error('usage: walk-fuzz.mjs --browser <binary> [--firefox] | --rust   [--seed N] [--pages N] [--frames N] [--depth N]');
  process.exit(2);
}

// What the walk turns on: every element it treats specially, open and
// closed, the ways text is not markup, half-written tags and quotes that
// can swallow what follows, and each thing check E refuses; then every
// element the HTML parser's tree builder has a rule for.
const ELEMENTS = ('a address applet area article aside b base basefont bgsound big blockquote body br button caption center code col colgroup '
  + 'dd details dialog dir div dl dt em embed fieldset figcaption figure font footer form frame frameset h1 h6 head header hgroup hr html i '
  + 'iframe image img input keygen li link listing main malignmark marquee math menu meta mglyph mi mn mo ms mtext nav nobr noembed noframes '
  + 'noscript object ol optgroup option p param plaintext pre rb rp rt rtc ruby s script search section select selectedcontent small source '
  + 'span strike strong style sub summary sup svg table tbody td template textarea tfoot th thead title tr track tt u ul var wbr xmp').split(' ');
const VOCAB = [
  ...ELEMENTS.flatMap(n => ['<' + n + '>', '</' + n + '>']),
  '<svg>', '</svg>', '<svg/>', '<SVG a=b/>', '<math>', '</math>', '<select>', '</select>', '<option>', '</option>', '<optgroup>', '<hr>',
  '<script>', '</script>', '<Script >', '</SCRIPT >', '<script/>', '<script src=a.js integrity=sha384-abc>', '<script src=a.js>',
  '<script type=module>', '<script type="text/plain">', '<script type="application/json" src=d.json>', '<script nomodule>',
  '<script for=window event=onload>', '<script for=x event=y>', '<script language=vbscript>', '<script type="">', '<script type=" text/javascript ">',
  '<script type=importmap>', '<script type=speculationrules>', '<script type="text/&#106;avascript">', '<script src=a.js integrity=SHA384-abc>',
  '<style>', '</style>', '<!--', '-->', '--!>', '<!-->', '<!--->', '<![CDATA[', ']]>', '<!doctype html>', '<?pi', '?>', '</>', '</ x>',
  '<title>', '</title>', '<textarea>', '</textarea>', '<xmp>', '</xmp>', '<noembed>', '</noembed>', '<noframes>', '</noframes>',
  '<template>', '</template>', '<noscript>', '</noscript>', '<plaintext>',
  '<p>', '</p>', '<b>', '</b>', '<div>', '</div>', '<br>', '</br>', '<g>', '</g>', '<path d="M0 0"/>', '<text>', '</text>',
  '<foreignObject>', '</foreignObject>', '<desc>', '</desc>', '<mi>', '</mi>', '<annotation-xml>', '</annotation-xml>', '<font>', '<img src=i.png>',
  '<a title="', "<a title='", '<a href="javascript:x()">', '<a href=" java\tscript:x()">', '<a href="/ok?a=1&b=2">', '<a href="&#106;avascript:x()">',
  '"', "'", '>', '<', '/', ' ', '=', 'x', '\n', '\r', '\r\n', '\t', '&', '-', '!',
  '<base href=y>', '<base target=_blank>', '<iframe src=x>', '</iframe>', '<frame src=x>', '<frameset>', '</frameset>', '<object data=x>', '<embed src=x>',
  '<meta http-equiv=refresh content=0>', '<meta charset=utf-8>', '<meta http-equiv="re&#102;resh">',
  '<link rel=modulepreload href=m.js integrity=sha384-abc>', '<link rel=modulepreload href=m.js>', '<link rel=stylesheet href=s.css>', '<link rel=icon href=i.ico>',
  '<link rel="style&#115;heet" href=s.css>', '<p onclick=x()>', '<p one=1>', '<p style="color:red">', '<p data-on=1>',
  '@import url(a.css);', '@\\69mport url(a.css);', '.\\@md{}', 'b{}', 'x()', "'<base href=y>'", '<table>', '</table>', '<td>', '<tr>', '<caption>',
  '<head>', '</head>', '<body>', '</body>', '<html>', '</html>', '<form action="javascript:x()">', '<button formaction="/go">', '<input>', '<keygen>',
  '<svg><title>', '<math><mtext>', '<mglyph>', '<malignmark>', '<svg xlink:href="javascript:x()">', '<script-x>', '</script-x>', '<title:x>',
  '<textarea/>', '<style/>', '<title/>', '<svg ', '<script ', '<p ', 'a=b/', 'a="b"', "a='b'", 'src=q.js', 'integrity=sha256-abc', 'onload=x', 'style=y', 'href=javascript:z',
];
// The context search. STRUCTURAL: the elements that change how the parser
// reads what follows. TEXT: what the walk reads as text, and how each ends.
const STRUCTURAL = ('html head body table caption colgroup col tbody tr td th select option optgroup template svg math foreignObject desc title mi '
  + 'annotation-xml noscript p button form a b li dd h1 input hr br textarea style script xmp noembed noframes object applet marquee nobr font div '
  + 'ruby rt selectedcontent keygen image mglyph frameset').split(' ');
const TEXT = [['<textarea>', '</textarea>'], ['<title>', '</title>'], ['<style>', '</style>'], ['<xmp>', '</xmp>'], ['<noembed>', '</noembed>'],
  ['<noframes>', '</noframes>'], ['<noscript>', '</noscript>'], ['<script type=text/plain>', '</script>'], ['<plaintext>', ''], ['<!--', '-->'],
  ['<![CDATA[', ']]>'], ['<a title="', '">'], ['', '']];

// mulberry32
const random = a => () => { a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
const rnd = random(seed);
const pages = Array.from({ length: count }, () => Array.from({ length: 1 + Math.floor(rnd() * 12) }, () => VOCAB[Math.floor(rnd() * VOCAB.length)]).join(''));

const core = readFileSync(new URL('../core/verifier.js', import.meta.url), 'utf8');
const shared = core.slice(core.indexOf('// === shared: unverifiableSubresource ==='), core.indexOf('// === end shared ==='));
let failed = false;
const report = (ok, label) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`); if (!ok) failed = true; };

if (rust) {
  const scan = new Function(shared + '\nreturn unverifiableSubresource;')();
  const hex = s => Buffer.from(s, 'utf8').toString('hex');
  const dir = mkdtempSync(join(tmpdir(), 'walk-fuzz-'));
  const file = join(dir, 'pages');
  writeFileSync(file, pages.map(p => hex(p) + ' ' + hex(scan('index.html', Buffer.from(p, 'utf8')) ?? '')).join('\n') + '\n');
  let why = '';
  try {
    execFileSync('cargo', ['test', '--release', '-p', 'git_canister', '--lib', 'agrees_with_the_js_port_on_random_pages', '--', '--ignored'],
      { cwd: fileURLToPath(new URL('..', import.meta.url)), env: { ...process.env, WALK_FUZZ: file }, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    why = '\n' + String(e.stdout).split('\n').filter(l => /panicked|assertion|left:|right:/.test(l)).join('\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  report(!why, `the canister's port and the JS port give ${pages.length} random pages the same verdict (seed ${seed})${why}`);
}

if (bin) {
  // Runs in the browser: the scanner over every page, then the browser's
  // parser over each one accepted.
  const runner = String(async function run() {
    const HTML = 'http://www.w3.org/1999/xhtml', SVG = 'http://www.w3.org/2000/svg';
    const bytes = t => new TextEncoder().encode(t);
    const hash = async t => "'sha256-" + btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(t))))) + "'";
    const pins = v => (v || '').split(/[ \t\n\r\f]+/).map(t => t.split('?')[0]).filter(t => /^sha(256|384|512)-[A-Za-z0-9+\/]+={0,2}$/.test(t)).map(t => "'" + t + "'");
    const strip = v => v.replace(/^[ \t\n\f\r]+|[ \t\n\f\r]+$/g, '');
    const JS = /^(application\/(x-)?(ecma|java)script|text\/((x-)?(ecma|java)script|javascript1\.[0-5]|jscript|livescript))$/i;
    // What the browser makes of a script element, from its attributes as
    // the parser decoded them.
    const kind = el => {
      const type = el.getAttribute('type'), lang = el.getAttribute('language');
      const t = type !== null ? (type === '' ? 'text/javascript' : strip(type)) : lang ? 'text/' + lang : 'text/javascript';
      if (/^(module|importmap)$/i.test(t)) return t.toLowerCase();
      if (!JS.test(t) || el.hasAttribute('nomodule')) return null;
      if (el.hasAttribute('for') && el.hasAttribute('event')
        && !(/^window$/i.test(strip(el.getAttribute('for'))) && /^onload(\(\))?$/i.test(strip(el.getAttribute('event'))))) return null;
      return 'classic';
    };
    const rels = el => (el.getAttribute('rel') || '').toLowerCase().split(/[ \t\n\r\f]+/);
    // Every element in document order, a template's content after it.
    const each = function* (root, templates) {
      for (const el of root.querySelectorAll('*')) {
        yield el;
        if (templates && el.namespaceURI === HTML && el.localName === 'template') yield* each(el.content, true);
      }
    };
    // What the parsed document holds that check E exists to refuse.
    const refusable = doc => {
      const found = [];
      for (const el of each(doc, false)) {
        const html = el.namespaceURI === HTML, n = el.localName;
        for (const a of el.attributes) {
          if (a.name.length > 2 && a.name.startsWith('on')) found.push('handler ' + a.name);
          if (a.name === 'style') found.push('style attribute');
          if (['href', 'xlink:href', 'action', 'formaction'].includes(a.name) && /^[\x00-\x20]*javascript:/i.test(a.value.replace(/[\t\n\r]/g, ''))) found.push('javascript: url');
        }
        if (html && ['iframe', 'frame', 'frameset', 'object', 'embed'].includes(n)) found.push(n);
        if (html && n === 'base' && el.hasAttribute('href')) found.push('base href');
        if (html && n === 'meta' && /^refresh$/i.test(el.getAttribute('http-equiv') || '')) found.push('meta refresh');
        if (html && n === 'link' && el.hasAttribute('href') && rels(el).includes('stylesheet')) found.push('stylesheet');
        if (html && n === 'link' && el.hasAttribute('href') && rels(el).includes('modulepreload') && !pins(el.getAttribute('integrity')).length) found.push('modulepreload without integrity');
        if (el.namespaceURI === SVG && (n === 'script' || n === 'style')) found.push('svg ' + n);
        if (html && n === 'script' && kind(el) && (el.hasAttribute('src') ? !pins(el.getAttribute('integrity')).length : kind(el) === 'module')) found.push('script no record covers');
        if (html && n === 'style' && /@import/i.test(el.textContent)) found.push('@import');
      }
      return found;
    };
    // The sources the parsed document calls for, sorted: a foster-parented
    // element is not where the page wrote it.
    const sorted = (scripts, styles) => [scripts, styles].map(l => [...new Set(l)].sort().join(' ') || "'none'").join(' | ');
    const fromDom = async doc => {
      const scripts = [], styles = [];
      for (const el of each(doc, true)) {
        if (el.namespaceURI !== HTML) continue;
        if (el.localName === 'script' && el.getRootNode() === doc && kind(el)) scripts.push(...(el.hasAttribute('src') ? pins(el.getAttribute('integrity')) : [await hash(el.textContent)]));
        if (el.localName === 'link' && el.hasAttribute('href') && rels(el).includes('modulepreload')) scripts.push(...pins(el.getAttribute('integrity')));
        if (el.localName === 'style') styles.push(await hash(el.textContent));
      }
      return sorted(scripts, styles);
    };
    const fromWalk = async page => {
      const m = /^script-src (.*); style-src (.*); object-src/.exec(await Verifier.derivePolicy(bytes(page), location.href));
      return sorted(m[1].split(' '), m[2].split(' '));
    };
    const differs = async (how, page, doc) => {
      const found = refusable(doc);
      if (found.length) return { how, page, found };
      const walk = await fromWalk(page).catch(e => 'no policy: ' + e.message), dom = await fromDom(doc);
      return walk === dom ? null : { how, page, walk, dom };
    };

    // A task boundary, taken now and then: the browser frees parsed
    // documents at one.
    const task = () => new Promise(r => { const c = new MessageChannel(); c.port1.onmessage = r; c.port2.postMessage(0); });

    const pages = await (await fetch('/pages')).json();
    const out = { accepted: 0, parsed: 0, framed: 0, bad: [], searched: 0, built: [] };
    const accepted = pages.map((p, i) => i).filter(i => scan('index.html', bytes(pages[i])) === null);
    out.accepted = accepted.length;
    const noscript = i => /<noscript/i.test(pages[i]);
    for (const i of accepted) {
      const doc = new DOMParser().parseFromString(pages[i], 'text/html');
      // With scripting off a <noscript> body is elements, which no policy
      // for a browser with scripting on would pin.
      const bad = noscript(i) ? (refusable(doc).length ? { how: 'DOMParser', page: pages[i], found: refusable(doc) } : null) : await differs('DOMParser', pages[i], doc);
      if (bad) out.bad.push(bad);
      if (++out.parsed % 200 === 0) await task();
    }
    const frame = i => new Promise(resolve => {
      const f = document.createElement('iframe');
      const done = r => { clearTimeout(timer); f.remove(); resolve(r); };
      const timer = setTimeout(() => done({ how: 'navigation', page: pages[i], found: ['did not load'] }), 20000);
      f.onload = () => differs('navigation', pages[i], f.contentDocument).then(done, e => done({ how: 'navigation', page: pages[i], found: [String(e)] }));
      f.src = '/page?i=' + i;
      document.body.append(f);
    });
    const framed = [...accepted.filter(noscript), ...accepted.filter(i => !noscript(i))].slice(0, FRAMES);
    for (let k = 0; k < framed.length; k += 40) {
      const batch = await Promise.all(framed.slice(k, k + 40).map(frame));
      out.framed += batch.length;
      out.bad.push(...batch.filter(Boolean));
    }

    const ends = STRUCTURAL.map(n => '</' + n + '>');
    const tokens = [...STRUCTURAL.map(n => '<' + n + '>'), ...ends, '<svg/>', '<!--', '-->', '<![CDATA[', ']]>', 'x'];
    const contexts = [''];
    for (let level = [''], d = 0; d < DEPTH; d++) contexts.push(...(level = level.flatMap(c => tokens.map(t => c + t))));
    // One document, written again for each page: millions of new ones
    // slow a browser down.
    const doc = document.implementation.createHTMLDocument('');
    for (const [k, context] of contexts.entries()) {
      for (const [open, close] of TEXT) {
        for (const end of ['', '>', ...ends]) {
          const page = context + open + end + '<iframe src=x></iframe>' + close;
          out.searched++;
          if (scan('index.html', bytes(page)) !== null) continue;
          doc.open();
          doc.write(page);
          doc.close();
          if ([...doc.querySelectorAll('iframe')].some(el => el.namespaceURI === HTML)) out.built.push(page);
        }
      }
      if (k % 20 === 0) await task();
    }
    return out;
  });
  // Served as a file, so nothing in it has to survive an inline <script>.
  const host = '<!doctype html><meta charset=utf-8><title>walk-fuzz</title><body><script src="/run.js"></script>';
  const js = `const FRAMES = ${frames}, DEPTH = ${depth}, STRUCTURAL = ${JSON.stringify(STRUCTURAL)}, TEXT = ${JSON.stringify(TEXT)};
const Verifier = (() => { ${core}; return Verifier; })();
const scan = (() => { ${shared}; return unverifiableSubresource; })();
(${runner})().catch(e => ({ error: String(e && e.stack || e) })).then(out => fetch('/report', { method: 'POST', body: JSON.stringify(out) }));`;
  let done;
  const result = new Promise(r => { done = r; });
  const server = createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (req.method === 'POST') { let b = ''; req.on('data', c => b += c); req.on('end', () => { res.end(); done(JSON.parse(b)); }); return; }
    const send = (type, body, extra) => { res.writeHead(200, { 'content-type': type, ...extra }); res.end(body); };
    if (u.pathname === '/') send('text/html; charset=utf-8', host);
    else if (u.pathname === '/run.js') send('text/javascript; charset=utf-8', js);
    else if (u.pathname === '/pages') send('application/json', JSON.stringify(pages));
    else if (u.pathname === '/page') send('text/html; charset=utf-8', pages[Number(u.searchParams.get('i'))], { 'content-security-policy': "default-src 'none'" });
    else { res.writeHead(404); res.end(); }
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/`;
  const dir = mkdtempSync(join(tmpdir(), 'walk-fuzz-'));
  const firefox = process.argv.includes('--firefox');
  const child = spawn(bin, firefox ? ['--headless', '--no-remote', '--profile', dir, url] : ['--headless=new', `--user-data-dir=${dir}`, '--no-first-run', url], { stdio: 'ignore' });
  const exited = new Promise(r => child.once('exit', r));
  // A browser that is quit, or never starts, is said so at once rather than
  // waited out.
  const r = await Promise.race([
    result,
    exited.then(() => ({ error: 'the browser exited before it reported' })),
    new Promise(r => setTimeout(() => r({ error: 'no report from the browser within 15 minutes' }), 900_000).unref()),
  ]);
  child.kill();
  await exited;
  server.close();
  rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  if (r.error) report(false, r.error);
  else {
    for (const b of r.bad.slice(0, 20)) console.log('        ' + JSON.stringify(b));
    report(r.bad.length === 0, `the browser's parser agrees with the walk on every page check E accepts: ${r.accepted} of ${pages.length} random pages (seed ${seed}), `
      + `${r.parsed} read by DOMParser, ${r.framed} by a navigation${r.bad.length ? '; ' + r.bad.length + ' differ' : ''}`);
    for (const p of r.built.slice(0, 20)) console.log('        ' + JSON.stringify(p));
    report(r.built.length === 0, `in no context of up to ${depth} structural tags does the walk skip what the browser parses: ${r.searched} pages`
      + (r.built.length ? '; ' + r.built.length + ' where it does' : ''));
  }
}
process.exit(failed ? 1 : 0);
