#!/usr/bin/env node
// Drives extension-firefox/ in headless Firefox against the live ic-git
// canister and the Sepolia registry, over WebDriver BiDi.
//
//   node tools/extension-firefox-test.mjs [--firefox /path/to/firefox] [--strict]
//
// --strict: a case that cannot run against what is live (SKIP) fails;
// before a release, every case must run.
//
// Every request goes through a local HTTPS proxy, set by Firefox's proxy
// preferences: it tunnels other hosts untouched, and for the canister's host
// terminates TLS with its own certificate, forwards to the real canister,
// and rewrites what a case asks it to -- a man in the middle, as a
// TLS-inspecting proxy is. The BiDi session accepts that certificate, as a
// machine that trusts the proxy's root does. The proxy also logs what reaches
// the canister, so a case can show that a tampered page asked for nothing.
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createHttp } from 'node:http';
import { createServer as createHttps } from 'node:https';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';

const FIREFOX = process.argv.includes('--firefox')
  ? process.argv[process.argv.indexOf('--firefox') + 1]
  : '/Applications/Firefox.app/Contents/MacOS/firefox';
const EXT = fileURLToPath(new URL('../extension-firefox', import.meta.url));
// The git canister's host: since the cut (docs/CANISTER_SPLIT.md, step 16,
// 2026-11-16) it serves every site, and ic-git's own host only redirects.
const GW = 'https://34koz-jyaaa-aaaab-ahejq-cai.raw.icp0.io';
const HOST = new URL(GW).host;
const VOTE = GW + '/site/ic-vote/';
const CONSOLE = GW + '/site/ic-git/';
// The console's home, a domain the core pins (Verifier.DEFAULTS.domains).
const HOME = 'https://ic-git.com/';
// Its subdomain, which the same DNS answers: the stand-in serves a page of
// its own there, so no case reaches the real one.
const WWW = 'https://www.ic-git.com/';
const sleep = ms => new Promise(r => setTimeout(r, ms));
// What a tampering case injects: a script that marks the page, a script and
// an image from the same host. None may run, and on Firefox none may even be
// requested, since the page is held until it verifies.
const INJECT = '<script>window.__pwned = 1;</script><script src="/site/ic-git/evil.js"></script><img src="/site/ic-git/tracker.png">';

// The proxy. `rewrite(path, text, headers)` returns the body to serve instead,
// or { body, type } to serve it as another content type, or null to pass it
// through; `log` gets every path requested of the canister. The console's
// home is answered by `home(path, headers)` -- { status, type, body,
// headers } -- as whoever holds its DNS serves it, and logged too; its
// subdomain www answers a page of its own.
async function proxy(dir, rewrite, log, home) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=' + HOST,
    '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
  const tls = createHttps({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, async (req, res) => {
    log.push({ path: req.url, dest: req.headers['sec-fetch-dest'] || '' });
    try {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const headers = Object.fromEntries(Object.entries(req.headers).filter(([k]) => !['host', 'connection', 'accept-encoding'].includes(k)));
      const up = await fetch(GW + req.url, { method: req.method, headers, body: chunks.length ? Buffer.concat(chunks) : undefined, redirect: 'manual' });
      let body = Buffer.from(await up.arrayBuffer());
      const got = rewrite(req.url, body.toString('utf8'), req.headers);
      if (got !== null) body = Buffer.from(typeof got === 'string' ? got : got.body);
      const out = {};
      up.headers.forEach((v, k) => { if (!['content-encoding', 'content-length', 'transfer-encoding', 'connection'].includes(k)) out[k] = v; });
      if (got !== null && typeof got !== 'string') out['content-type'] = got.type;
      res.writeHead(up.status, out);
      res.end(body);
    } catch (e) { res.writeHead(502); res.end(String(e)); }
  });
  const domain = createHttps({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, async (req, res) => {
    const www = (req.headers.host || '').split(':')[0] === new URL(WWW).hostname;
    log.push({ path: req.url, dest: req.headers['sec-fetch-dest'] || '', home: true, www });
    try {
      const { status, type, body, headers = {} } = www
        ? { status: 200, type: 'text/html', body: '<!doctype html><title>ic-git</title><script>window.__pwned = 9;</script><p>HACKED at www</p>' }
        : await home(req.url, req.headers);
      res.writeHead(status, { 'content-type': type, ...headers });
      res.end(body);
    } catch (e) { res.writeHead(502); res.end(String(e)); }
  });
  // Plain http is the extension's to upgrade before it leaves (rules.json):
  // what still reaches the proxy is refused at once, so a case that it
  // reaches fails rather than waits.
  const server = createHttp((req, res) => { res.writeHead(502, { 'content-type': 'text/plain' }); res.end('plain http reached the proxy'); });
  server.on('connect', (req, socket, head) => {
    const [host, port] = req.url.split(':');
    const to = host === HOST ? tls : [new URL(HOME).host, new URL(WWW).host].includes(host) && home ? domain : null;
    if (to) {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) socket.unshift(head);
      to.emit('connection', socket);
      return;
    }
    const upstream = connect(Number(port) || 443, host, () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      upstream.pipe(socket); socket.pipe(upstream);
    });
    upstream.on('error', () => socket.destroy());
    socket.on('error', () => upstream.destroy());
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return server;
}

// A Firefox with the extension, all traffic through the proxy, and a BiDi
// session on its one tab. `extension: false`: without it, until install().
async function open({ rewrite = () => null, home = null, extension = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ff-ext-test-'));
  const log = [];
  const server = await proxy(dir, (...a) => rewrite(...a), log, home);
  const p = server.address().port;
  writeFileSync(join(dir, 'user.js'), [
    ['network.proxy.type', 1], ['network.proxy.ssl', '"127.0.0.1"'], ['network.proxy.ssl_port', p],
    ['network.proxy.http', '"127.0.0.1"'], ['network.proxy.http_port', p], ['network.proxy.no_proxies_on', '""'],
    ['browser.shell.checkDefaultBrowser', false], ['app.update.enabled', false], ['network.captive-portal-service.enabled', false],
    ['browser.safebrowsing.malware.enabled', false], ['browser.safebrowsing.phishing.enabled', false],
    ['datareporting.policy.dataSubmissionEnabled', false], ['toolkit.telemetry.enabled', false],
    // A service worker from a host whose certificate the session accepts
    // (the stand-in's), as one from a trusted host is.
    ['dom.serviceWorkers.testing.enabled', true],
  ].map(([k, v]) => `user_pref("${k}", ${v});`).join('\n') + '\n');
  const port = 9800 + Math.floor(Math.random() * 150);
  const ff = spawn(FIREFOX, ['--headless', '--no-remote', '--profile', dir, `--remote-debugging-port=${port}`, 'about:blank'], { stdio: 'ignore' });
  let ws;
  for (let i = 0; i < 80 && !ws; i++) {
    await sleep(250);
    try {
      const w = new WebSocket(`ws://127.0.0.1:${port}/session`);
      await new Promise((ok, no) => { w.onopen = ok; w.onerror = no; });
      ws = w;
    } catch {}
  }
  if (!ws) throw new Error('Firefox did not start');
  let seq = 0;
  const pending = new Map();
  let loads = 0;
  ws.onmessage = m => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
    if (d.method === 'browsingContext.load') loads++;
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, d => (d.type === 'error' ? reject(new Error(method + ': ' + d.error + ' ' + d.message)) : resolve(d.result)));
    ws.send(JSON.stringify({ id, method, params }));
  });
  await send('session.new', { capabilities: { alwaysMatch: { acceptInsecureCerts: true } } });
  const install = () => send('webExtension.install', { extensionData: { type: 'path', path: EXT } });
  if (extension) await install();
  await send('session.subscribe', { events: ['browsingContext.load'] });
  const { contexts } = await send('browsingContext.getTree', {});
  const context = contexts[0].context;
  const evaluate = async expression =>
    (await send('script.evaluate', { expression, target: { context }, awaitPromise: true })).result.value;
  const go = async (url, wait = 12_000) => {
    loads = 0; log.length = 0;
    await send('browsingContext.navigate', { context, url, wait: 'none' });
    await sleep(wait);
  };
  const state = async () => ({
    overlay: await evaluate("!!document.querySelector('ic-git-verifier')"),
    text: await evaluate("document.body ? document.body.innerText.replace(/\\s+/g, ' ').slice(0, 200) : ''"),
    pwned: await evaluate('window.__pwned || 0'),
    loads,
    injected: log.filter(r => /evil\.js|tracker\.png/.test(r.path)).map(r => r.path),
  });
  const close = async () => {
    try { await send('session.end', {}); } catch {}
    ws.close();
    const exited = new Promise(r => ff.once('exit', r));
    ff.kill('SIGTERM');
    await Promise.race([exited, sleep(5000)]);
    server.close();
    rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  };
  // What a call from the page to the IC's API comes to: an HTTP status, or
  // "blocked" when the extension's listener cancels it.
  const call = url => evaluate(`fetch(${JSON.stringify(url)}, { method: 'POST', headers: { 'content-type': 'application/cbor' }, body: new Uint8Array([0]) }).then(r => 'http ' + r.status, e => 'blocked')`);
  // What a navigation comes to: 'loaded', or the error it ended in, or
  // that it had not ended in 20 s -- as a page left to load at a host no
  // rule stops may not, and a case must fail then, not wait forever.
  const nav = url => Promise.race([
    send('browsingContext.navigate', { context, url, wait: 'complete' }).then(() => 'loaded', e => String(e.message)),
    sleep(20_000).then(() => 'still loading after 20 s'),
  ]);
  // What each frame of the page holds, by its document's address: a page
  // the extension's rule cancels is an error page, and says so.
  const frames = async () => {
    const { contexts: [top] } = await send('browsingContext.getTree', { root: context });
    const out = [];
    for (const c of top.children || []) {
      let uri = '';
      try { uri = (await send('script.evaluate', { expression: 'document.documentURI', target: { context: c.context }, awaitPromise: false })).result.value; }
      catch (e) { uri = 'error: ' + e.message; }
      out.push({ url: c.url, uri });
    }
    return out;
  };
  // The stop page's "Open anyway", pressed twice as a user would: found
  // in a screenshot (its closed shadow root is out of a page script's
  // reach) as the lowest band of its red. Where there is no such button
  // the press lands on red text, and does nothing.
  const pressRisk = async () => {
    for (let i = 0; i < 2; i++) {
      const at = riskButton(Buffer.from((await send('browsingContext.captureScreenshot', { context })).data, 'base64'));
      if (!at) return 'no red on the page';
      await send('input.performActions', { context, actions: [{ type: 'pointer', id: 'm', parameters: { pointerType: 'mouse' },
        actions: [{ type: 'pointerMove', x: at.x, y: at.y }, { type: 'pointerDown', button: 0 }, { type: 'pointerUp', button: 0 }] }] });
      await sleep(1_500);
    }
    return 'pressed';
  };
  return { go, nav, state, evaluate, log, close, call, frames, install, pressRisk, set rewrite(f) { rewrite = f; } };
}

// A screenshot's pixels (8-bit RGB or RGBA PNG, not interlaced).
function png(buf) {
  let o = 8, w, h, ct;
  const idat = [];
  while (o < buf.length) {
    const len = buf.readUInt32BE(o), type = buf.toString('ascii', o + 4, o + 8), data = buf.subarray(o + 8, o + 8 + len);
    if (type === 'IHDR') { w = data.readUInt32BE(0); h = data.readUInt32BE(4); ct = data[9]; }
    if (type === 'IDAT') idat.push(data);
    o += 12 + len;
  }
  const bpp = ct === 6 ? 4 : 3, raw = inflateSync(Buffer.concat(idat)), stride = w * bpp, px = Buffer.alloc(h * stride);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)], line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? px[y * stride + x - bpp] : 0, b = y ? px[(y - 1) * stride + x] : 0, c = x >= bpp && y ? px[(y - 1) * stride + x - bpp] : 0;
      let v = line[x];
      if (f === 1) v += a; else if (f === 2) v += b; else if (f === 3) v += (a + b) >> 1;
      else if (f === 4) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      px[y * stride + x] = v & 255;
    }
  }
  return { w, h, at: (x, y) => [px[y * stride + x * bpp], px[y * stride + x * bpp + 1], px[y * stride + x * bpp + 2]] };
}
// Where the stop page's lowest red (#b3261e) is: "Open anyway" when it is
// offered, last on the page.
function riskButton(buf) {
  const im = png(buf), red = [];
  for (let y = 0; y < im.h; y++) for (let x = 0; x < im.w; x++) {
    const [r, g, b] = im.at(x, y);
    if (Math.abs(r - 179) < 20 && Math.abs(g - 38) < 20 && Math.abs(b - 30) < 20) red.push([x, y]);
  }
  if (!red.length) return null;
  const maxY = Math.max(...red.map(p => p[1]));
  const band = red.filter(p => p[1] > maxY - 34);
  const xs = band.map(p => p[0]), ys = band.map(p => p[1]);
  return { x: Math.round((Math.min(...xs) + Math.max(...xs)) / 2), y: Math.round((Math.min(...ys) + Math.max(...ys)) / 2) };
}

let failed = 0;
const report = (name, ok, got) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '\n        got ' + JSON.stringify(got)}`);
  if (!ok) failed++;
};
// A case that cannot run against what is live, and why; with --strict, a
// failure.
let skipped = 0;
const skip = (name, why) => {
  if (process.argv.includes('--strict')) return report(name + ' (--strict: it must run)', false, why);
  skipped++;
  console.log(`SKIP  ${name}\n        ${why}`);
};
// Whether the console the registry records knows its home: one published
// before it did reads its /api on its own origin, which at the domain is
// the domain's, so only its being written there can be checked.
const homeAware = async () => (await (await fetch(CONSOLE)).text()).includes("const HOME = '" + new URL(HOME).origin + "';");
const tamper = (only) => (path, text, headers) => {
  if (path !== '/site/ic-git/') return null;
  if (only && headers['sec-fetch-dest'] !== only) return null;
  return text.replace('</head>', INJECT + '</head>').replace('a git remote on the Internet Computer', 'HACKED: send your keys here');
};

// 1-3. First and second visit to the console, then ic-vote.
{
  const b = await open();
  try {
    await b.go(CONSOLE, 20_000);
    let s = await b.state();
    report('first visit: held until verified, runs, no reload', !s.overlay && /repositories/.test(s.text) && s.loads === 1, s);
    await b.go(CONSOLE, 10_000);
    s = await b.state();
    report('second visit: runs', !s.overlay && /repositories/.test(s.text) && s.loads === 1, s);
    await b.go(GW + '/site/ic-git', 15_000);
    s = await b.state();
    const href = await b.evaluate('location.href');
    report('the address without the slash goes to the entrypoint and runs',
      href === CONSOLE && !s.overlay && /repositories/.test(s.text), { href, ...s });
    // The console routes by fragment, so a link to a repo's page carries one.
    await b.go(GW + '/site/ic-git?x=1#/ic-git', 12_000);
    s = await b.state();
    const deep = await b.evaluate('location.href');
    report('without the slash, the query and the fragment are kept',
      deep === CONSOLE + '?x=1#/ic-git' && !s.overlay && /commits/.test(s.text), { href: deep, ...s });
    await b.go(VOTE, 20_000);
    s = await b.state();
    report('ic-vote (stylesheet inlined in ic-vote #9) verifies and runs under its pinned policy',
      !s.overlay && /YELLOW/.test(s.text) && s.loads === 1, s);
    // The backend check (docs/GOVERNANCE.md, section 4): the page's calls
    // to judged canisters are released, the rest cancelled in the listener.
    const calls = {
      ledger: await b.call('https://icp-api.io/api/v2/canister/ryjl3-tyaaa-aaaaa-aaaba-cai/query'),
      poll: await b.call('https://icp-api.io/api/v2/canister/gjob4-qqaaa-aaaab-ag4mq-cai/query'),
      icgit: await b.call('https://icp-api.io/api/v2/canister/umobs-yiaaa-aaaab-agyrq-cai/read_state'),
      unknown: await b.call('https://icp-api.io/api/v2/canister/aaaaa-aa/query'),
      otherHost: await b.call('https://icp0.io/api/v2/canister/ryjl3-tyaaa-aaaaa-aaaba-cai/query'),
      status: await b.call('https://icp-api.io/api/v2/status'),
    };
    report('the page\'s calls to judged canisters go through (the ledger, its poll canister, ic-git)',
      /^http/.test(calls.ledger) && /^http/.test(calls.poll) && /^http/.test(calls.icgit), calls);
    report('a call to a canister nobody judged, through another IC host, or to the API root is blocked',
      calls.unknown === 'blocked' && calls.otherHost === 'blocked' && calls.status === 'blocked', calls);
  } finally { await b.close(); }
}

// 4. Targeted: only the navigation (Sec-Fetch-Dest: document) is rewritten,
// with an injected script, image and changed text. The extension's own
// fetch is honest; the bytes that arrived are not, and they never load.
{
  const b = await open();
  try {
    await b.go(CONSOLE, 20_000);
    b.rewrite = tamper('document');
    await b.go(CONSOLE, 15_000);
    const s = await b.state();
    report('targeted tampering: the delivered page is stopped, never shown, and asks for nothing',
      s.overlay && s.pwned === 0 && !/HACKED/.test(s.text) && s.injected.length === 0, s);
  } finally { await b.close(); }
}

// 4b. Targeted, by type: the navigation's bytes are the recorded page, but
// typed as XML, XHTML or SVG, or as HTML in another charset. What check E
// read was UTF-8 HTML, and that is how the tab parses it.
{
  let type = null;
  const b = await open();
  try {
    await b.go(CONSOLE, 20_000);
    b.rewrite = (path, text, headers) => (type && path === '/site/ic-git/' && headers['sec-fetch-dest'] === 'document' ? { body: text, type } : null);
    for (type of ['text/xml', 'application/xhtml+xml', 'image/svg+xml', 'text/html; charset=iso-2022-jp']) {
      await b.go(CONSOLE, 12_000);
      const s = await b.state();
      const as = await b.evaluate('document.contentType + " " + document.characterSet');
      report('the recorded page served as ' + type + ': parsed as UTF-8 HTML, runs',
        as === 'text/html UTF-8' && !s.overlay && /repositories/.test(s.text) && s.pwned === 0, { as, ...s });
    }
  } finally { await b.close(); }
}

// 5-6. Consistent tampering, then the proxy goes away and a reload recovers.
{
  const b = await open({ rewrite: tamper(null) });
  try {
    await b.go(CONSOLE, 20_000);
    let s = await b.state();
    report('consistent tampering: stop page, nothing shown or run or fetched',
      s.overlay && s.pwned === 0 && !/HACKED/.test(s.text) && s.injected.length === 0, s);
    b.rewrite = () => null;
    await b.go(CONSOLE, 20_000);
    s = await b.state();
    report('after a failure, a reload checks again: the proxy gone, the console runs',
      !s.overlay && /repositories/.test(s.text) && s.pwned === 0, s);
  } finally { await b.close(); }
}

// 7. A page under /site/ that no record covers.
{
  const b = await open();
  try {
    await b.go(GW + '/site/ic-vote/nope.html', 10_000);
    const s = await b.state();
    report('a page no record covers: stop page, nothing runs', s.overlay && s.pwned === 0, s);
  } finally { await b.close(); }
}

// 8. The same canisters at any other host: no page under /site/ loads.
// A navigation the extension's rule cancels ends in NS_ERROR_ABORT.
{
  const b = await open();
  const ID = '34koz-jyaaa-aaaab-ahejq-cai', OLD = 'umobs-yiaaa-aaaab-agyrq-cai';
  try {
    for (const url of [
      `https://${ID}.icp0.io/site/ic-git/`,
      `https://${ID}.raw.ic0.app/site/ic-git/`,
      `https://${ID}.raw.icp1.io/site/ic-vote/`,
      `https://${ID}.icp.net/site/ic-git/`,
      `https://${ID}.raw.icp.net/site/ic-git/index.html?x=1#y`,
      `https://${OLD}.icp0.io/site/ic-git/`,
      `http://${ID}.icp0.io/site/ic-git/`,
      `https://${ID}.icp0.io/site/ic-git`,
      `https://${ID}.icp0.io/site`,
      `https://x--${ID}.raw.icp0.io/site/ic-git/`,
      // A prefix a hostname may have and a DNS name may not.
      `https://x_y--${ID}.icp0.io/site/ic-git/`,
      // The checked host spelled as another origin: with the root's dot
      // (the gateways answer there), or at another port.
      `https://${ID}.raw.icp0.io./site/ic-git/`,
      `https://${ID}.raw.icp0.io:8443/site/ic-git/`,
      `https://${ID}.gateway.example/site/ic-git/`,
      `https://user@${ID}.icp0.io/site/ic-git/`,
    ]) {
      const got = await b.nav(url);
      report('blocked: ' + url, /NS_ERROR_ABORT/.test(got), got);
    }
    for (const url of [
      `https://${ID}.icp0.io/`,
      `https://${ID}.icp0.io/api/repos`,
      `https://${ID}.icp0.io/sites/x`,
      'https://ryjl3-tyaaa-aaaaa-aaaba-cai.icp0.io/site/x/',
    ]) {
      const got = await b.nav(url);
      report('not blocked: ' + url, got === 'loaded', got);
    }
    await b.go(`http://${ID}.raw.icp0.io/site/ic-git/`, 20_000);
    const at = await b.evaluate('location.href');
    const s = await b.state();
    report('the checked host over http: upgraded, checked, runs', at === CONSOLE && !s.overlay && /repositories/.test(s.text), { at, ...s });
  } finally { await b.close(); }
}

// 9. The checked host in a frame or an object of anyone's page: nothing of
// it loads there, since a page of it would run there as that host,
// unchecked, and could reach a checked page of it. A frame and an object
// of the page's own site load, so the check sees both at all.
{
  const b = await open();
  try {
    await b.go('https://example.com/', 4_000);
    await b.evaluate(`(() => {
      for (const src of ['https://example.com/?framed', '${GW}/site/ic-vote/', '${GW.replace('//', '//x@')}/site/ic-vote/']) {
        const f = document.createElement('iframe');
        f.src = src;
        document.body.append(f);
      }
      for (const data of ['https://example.com/?object', '${GW}/site/ic-git/']) {
        const o = document.createElement('object');
        o.type = 'text/html';
        o.data = data;
        document.body.append(o);
      }
    })()`);
    await sleep(8_000);
    // Each frame's document, read in it: a frame that cannot be read is
    // not taken to be blocked, so every one must be readable, the two of
    // another site loaded (so frames and objects are seen at all), and
    // none of them a document of the checked host. A blocked object may
    // have no frame.
    const frames = await b.frames();
    const hostOf = url => { try { return new URL(url).host; } catch { return ''; } };
    report('the checked host blocked in a frame and in an object, with a user name too',
      frames.every(f => !f.uri.startsWith('error: ')) &&
      ['https://example.com/?framed', 'https://example.com/?object'].every(u => frames.some(f => f.uri === u)) &&
      frames.every(f => hostOf(f.uri) !== hostOf(GW)), frames);
  } finally { await b.close(); }
}

// What the canister serves at the domain: the site's root at /, the same
// bytes as at /site/ic-git/ (docs/TENANCY.md, "Custom domains").
const honest = async path => {
  if (!/^\/(index\.html)?(\?|$)/.test(path)) return { status: 404, type: 'text/plain', body: 'not found' };
  const r = await fetch(CONSOLE);
  return { status: r.status, type: r.headers.get('content-type'), body: Buffer.from(await r.arrayBuffer()) };
};
// A hijacker's page there: it marks the page, and names a script and an
// image at the domain, which must never be requested.
const EVIL = '<!doctype html><html><head><title>ic-git</title><script>window.__pwned = 1;</script><script src="/evil.js"></script></head><body><p>HACKED: send your keys here</p><img src="/tracker.png"></body></html>';

// 10. The console's home, ic-git.com, a domain the core pins: its root is
// the ic-git site's entrypoint, held until what arrived is checked against
// the site's record as the git canister serves it on its own host. An
// honest domain's page loads; a hijacked one's is never shown or run, and
// asks for nothing. Every other page there is covered by no record, and
// the domain loads in no frame and under no other spelling.
{
  let hijacked = false;
  const b = await open({ home: async (path, headers) => (hijacked ? { status: 200, type: 'text/html', body: EVIL } : honest(path, headers)) });
  const wallet = () => b.evaluate("(document.getElementById('wallet') || {}).innerText || ''");
  const aware = await homeAware();
  try {
    await b.go(HOME, 20_000);
    let s = await b.state();
    const at = await b.evaluate('location.href');
    report('at home: held until verified, loads, no reload', at === HOME && !s.overlay && /a git remote on the Internet Computer/.test(s.text) && s.loads === 1, { at, ...s });
    const w = await wallet();
    if (aware) report('at home the console offers a wallet, and reads the git canister across origins', /connect/i.test(w) && /ic-vote/.test(await b.evaluate('document.body.innerText')), w);
    else skip('at home the console offers a wallet, and reads the git canister across origins', 'the recorded ic-git#site predates its home (docs/TENANCY.md, "Putting the console at its domain", step 3)');
    const calls = {
      ledger: await b.call('https://icp-api.io/api/v2/canister/ryjl3-tyaaa-aaaaa-aaaba-cai/query'),
      icgit: await b.call('https://icp-api.io/api/v2/canister/umobs-yiaaa-aaaab-agyrq-cai/query'),
      unknown: await b.call('https://icp-api.io/api/v2/canister/aaaaa-aa/query'),
      otherHost: await b.call('https://icp0.io/api/v2/canister/ryjl3-tyaaa-aaaaa-aaaba-cai/query'),
    };
    report('at home: calls to judged canisters go through, a canister nobody judged or another IC host is blocked',
      /^http/.test(calls.ledger) && /^http/.test(calls.icgit) && calls.unknown === 'blocked' && calls.otherHost === 'blocked', calls);
    hijacked = true;
    await b.go(HOME, 15_000);
    s = await b.state();
    const asked = b.log.filter(r => r.home && /evil\.js|tracker\.png/.test(r.path)).map(r => r.path);
    report('hijacked home: stop page, the domain\'s page never shown or run, and asks for nothing',
      s.overlay && s.pwned === 0 && !/HACKED/.test(s.text) && asked.length === 0, { asked, ...s });
    await b.go(new URL('/login.html', HOME).href, 10_000);
    s = await b.state();
    report('hijacked home, another page there: covered by no record, stop page, nothing runs', s.overlay && s.pwned === 0 && !/HACKED/.test(s.text), s);
    hijacked = false;
    for (const url of ['https://ic-git.com./', 'https://ic-git.com:8443/', 'https://user@ic-git.com./']) {
      const got = await b.nav(url);
      report('blocked: ' + url, /NS_ERROR_ABORT/.test(got), got);
    }
    await b.go('http://ic-git.com/', 20_000);
    const up = await b.evaluate('location.href');
    s = await b.state();
    report('home over http: upgraded, checked, loads', up === HOME && !s.overlay && /a git remote on the Internet Computer/.test(s.text), { at: up, ...s });
    await b.go('https://example.com/', 4_000);
    await b.evaluate(`(() => {
      for (const src of ['https://example.com/?framed', '${HOME}', 'https://x@ic-git.com/']) {
        const f = document.createElement('iframe');
        f.src = src;
        document.body.append(f);
      }
      const o = document.createElement('object');
      o.type = 'text/html';
      o.data = '${HOME}';
      document.body.append(o);
    })()`);
    await sleep(8_000);
    const frames = await b.frames();
    const hostOf = url => { try { return new URL(url).host; } catch { return ''; } };
    report('home blocked in a frame and in an object, with a user name too',
      frames.every(f => !f.uri.startsWith('error: ')) && frames.some(f => f.uri === 'https://example.com/?framed') &&
      frames.every(f => hostOf(f.uri) !== 'ic-git.com'), frames);
  } finally { await b.close(); }
}

// 10b. Hijacked, subtler: the recorded bytes, with headers that act after
// the check (a move elsewhere, a cookie, a preload); then a redirect to a
// subdomain, which the same DNS answers.
{
  let mode = 'headers';
  const b = await open({ home: async (path, h) => {
    if (mode === 'redirect' && /^\/(\?|$)/.test(path)) return { status: 302, type: 'text/plain', body: '', headers: { location: WWW } };
    const r = await honest(path, h);
    if (mode === 'headers' && r.status === 200) r.headers = { refresh: '3; url=https://example.com/moved', 'set-cookie': 'planted=1; Path=/; Secure', link: '</evil.css>; rel=preload; as=style' };
    return r;
  } });
  try {
    await b.go(HOME, 20_000);
    await sleep(6_000);
    const at = await b.evaluate('location.href'), cookie = await b.evaluate('document.cookie');
    let s = await b.state();
    const asked = b.log.filter(r => /evil\.css/.test(r.path)).map(r => r.path);
    report('hijacked home\'s headers: no move after the check, no cookie, no preload, the page loads',
      at === HOME && !/planted/.test(cookie) && asked.length === 0 && !s.overlay && /a git remote on the Internet Computer/.test(s.text), { at, cookie, asked, ...s });
    mode = 'redirect';
    const got = await b.nav(HOME);
    const to = await b.evaluate('location.href');
    s = await b.state();
    const www = b.log.filter(r => r.www).map(r => r.path);
    report('hijacked home redirecting to its subdomain: stopped, nothing there is asked for or runs', !String(to).startsWith(WWW) && www.length === 0 && s.pwned === 0, { got, to, www, ...s });
  } finally { await b.close(); }
}

// 10c. "Open anyway" never at home: a failed check there offers none, and
// one given on the git canister's host does not carry to the domain.
{
  let hijacked = true;
  const b = await open({ home: async (path, h) => (hijacked ? { status: 200, type: 'text/html', body: EVIL } : honest(path, h)), rewrite: tamper() });
  try {
    await b.go(HOME, 15_000);
    const pressed = await b.pressRisk();
    await sleep(10_000);
    let s = await b.state();
    report('a failed check at home: no "open anyway" to press, the domain\'s page never runs', s.overlay && s.pwned === 0 && !/HACKED/.test(s.text), { pressed, ...s });
    await b.go(CONSOLE, 20_000);
    const control = await b.pressRisk();
    await sleep(12_000);
    s = await b.state();
    report('...while on the git canister\'s host the same failure offers it, and it runs the page as served', control === 'pressed' && !s.overlay && s.pwned === 1, { control, ...s });
    await b.go(HOME, 15_000);
    s = await b.state();
    report('...and that tab\'s exception does not open the hijacked domain', s.overlay && s.pwned === 0 && !/HACKED/.test(s.text), s);
  } finally { await b.close(); }
}

// 10d. A service worker at home, registered before the extension was
// installed: it would answer the navigation itself, where no listener
// holds it, and the page's requests too. At install every pinned domain's
// workers are removed.
{
  const SW = `self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(clients.claim()));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.hostname === 'icp-api.io') return e.respondWith(new Response('forged', { status: 299 }));
  if (u.pathname === '/sw-ping') return e.respondWith(new Response('sw alive'));
  if (e.request.mode === 'navigate') e.respondWith(new Response('<!doctype html><title>ic-git</title><script>window.__pwned = 1;</script><p>HACKED by a worker</p>', { headers: { 'content-type': 'text/html' } }));
});`;
  const REG = "<!doctype html><title>reg</title><script>navigator.serviceWorker.register('/sw.js', { scope: '/' }).then(() => navigator.serviceWorker.ready).then(() => { document.title = 'registered'; }, e => { document.title = 'failed: ' + e.message; });</script>";
  const b = await open({ extension: false, home: async (path, h) => path === '/sw.js' ? { status: 200, type: 'text/javascript', body: SW } : path === '/reg.html' ? { status: 200, type: 'text/html', body: REG } : honest(path, h) });
  try {
    await b.go(new URL('/reg.html', HOME).href, 5_000);
    const planted = await b.evaluate('document.title');
    await b.go(HOME, 4_000);
    const before = await b.state();
    await b.install();
    await sleep(3_000);
    await b.go(HOME, 25_000);
    const s = await b.state();
    const controller = await b.evaluate('navigator.serviceWorker.controller ? navigator.serviceWorker.controller.scriptURL : "none"');
    const ping = await b.evaluate("fetch('/sw-ping').then(r => r.text(), () => 'err')");
    const call = await b.call('https://icp-api.io/api/v2/canister/aaaaa-aa/query');
    report('a worker planted at home before the extension was installed answers for the page', planted === 'registered' && before.pwned === 1, { planted, before });
    report('...and is gone once it is: the checked console from the network, its calls judged',
      controller === 'none' && ping !== 'sw alive' && call === 'blocked' && s.pwned === 0 && !s.overlay && /a git remote on the Internet Computer/.test(s.text), { controller, ping, call, ...s });
  } finally { await b.close(); }
}

console.log(failed ? `\n${failed} failed` : '\nall passed' + (skipped ? ` (${skipped} skipped; --strict, before a release, runs them or fails)` : ''));
process.exit(failed ? 1 : 0);
