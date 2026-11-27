#!/usr/bin/env node
// Drives extension-firefox/ in headless Firefox against the live ic-git
// canister and the Sepolia registry, over WebDriver BiDi.
//
//   node tools/extension-firefox-test.mjs [--firefox /path/to/firefox]
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
const sleep = ms => new Promise(r => setTimeout(r, ms));
// What a tampering case injects: a script that marks the page, a script and
// an image from the same host. None may run, and on Firefox none may even be
// requested, since the page is held until it verifies.
const INJECT = '<script>window.__pwned = 1;</script><script src="/site/ic-git/evil.js"></script><img src="/site/ic-git/tracker.png">';

// The proxy. `rewrite(path, text, headers)` returns the body to serve instead,
// or { body, type } to serve it as another content type, or null to pass it
// through; `log` gets every path requested of the canister.
async function proxy(dir, rewrite, log) {
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
  const server = createHttp();
  server.on('connect', (req, socket, head) => {
    const [host, port] = req.url.split(':');
    if (host === HOST) {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) socket.unshift(head);
      tls.emit('connection', socket);
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
// session on its one tab.
async function open({ rewrite = () => null } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ff-ext-test-'));
  const log = [];
  const server = await proxy(dir, (...a) => rewrite(...a), log);
  const p = server.address().port;
  writeFileSync(join(dir, 'user.js'), [
    ['network.proxy.type', 1], ['network.proxy.ssl', '"127.0.0.1"'], ['network.proxy.ssl_port', p],
    ['network.proxy.http', '"127.0.0.1"'], ['network.proxy.http_port', p], ['network.proxy.no_proxies_on', '""'],
    ['browser.shell.checkDefaultBrowser', false], ['app.update.enabled', false], ['network.captive-portal-service.enabled', false],
    ['browser.safebrowsing.malware.enabled', false], ['browser.safebrowsing.phishing.enabled', false],
    ['datareporting.policy.dataSubmissionEnabled', false], ['toolkit.telemetry.enabled', false],
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
  await send('webExtension.install', { extensionData: { type: 'path', path: EXT } });
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
  // What a navigation comes to: 'loaded', or the error it ended in.
  const nav = async url => {
    try { await send('browsingContext.navigate', { context, url, wait: 'complete' }); return 'loaded'; } catch (e) { return String(e.message); }
  };
  // What each frame of the page holds, by its document's address: a page
  // the extension's rule cancels is an error page, and says so.
  const frames = async () => {
    const { contexts: [top] } = await send('browsingContext.getTree', { root: context });
    const out = [];
    for (const c of top.children || []) {
      try { out.push((await send('script.evaluate', { expression: 'document.documentURI', target: { context: c.context }, awaitPromise: false })).result.value); }
      catch (e) { out.push('error: ' + e.message); }
    }
    return out;
  };
  return { go, nav, state, evaluate, log, close, call, frames, set rewrite(f) { rewrite = f; } };
}

let failed = 0;
const report = (name, ok, got) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '\n        got ' + JSON.stringify(got)}`);
  if (!ok) failed++;
};
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
// unchecked, and could reach a checked page of it. A frame of another
// site loads, so the check sees frames at all.
{
  const b = await open();
  try {
    await b.go('https://example.com/', 4_000);
    await b.evaluate(`(() => {
      for (const src of ['https://example.com/?framed', '${GW}/site/ic-vote/']) {
        const f = document.createElement('iframe');
        f.src = src;
        document.body.append(f);
      }
      const o = document.createElement('object');
      o.type = 'text/html';
      o.data = '${GW}/site/ic-git/';
      document.body.append(o);
    })()`);
    await sleep(8_000);
    const uris = await b.frames();
    report('the checked host blocked in a frame and in an object',
      uris.some(u => u.startsWith('https://example.com/')) && uris.every(u => !u.startsWith(GW)), uris);
  } finally { await b.close(); }
}

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
