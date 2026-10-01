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
const GW = 'https://umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io';
const HOST = new URL(GW).host;
const VOTE = GW + '/site/ic-vote/';
const CONSOLE = GW + '/site/ic-git/';
const sleep = ms => new Promise(r => setTimeout(r, ms));
// What a tampering case injects: a script that marks the page, a script and
// an image from the same host. None may run, and on Firefox none may even be
// requested, since the page is held until it verifies.
const INJECT = '<script>window.__pwned = 1;</script><script src="/site/ic-git/evil.js"></script><img src="/site/ic-git/tracker.png">';

// The proxy. `rewrite(path, text, headers)` returns the body to serve instead,
// or null to pass it through; `log` gets every path requested of the canister.
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
      const text = rewrite(req.url, body.toString('utf8'), req.headers);
      if (text !== null) body = Buffer.from(text);
      const out = {};
      up.headers.forEach((v, k) => { if (!['content-encoding', 'content-length', 'transfer-encoding', 'connection'].includes(k)) out[k] = v; });
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
  return { go, state, evaluate, log, close, set rewrite(f) { rewrite = f; } };
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
    await b.go(VOTE, 20_000);
    s = await b.state();
    report('ic-vote (stylesheet inlined in ic-vote #9) verifies and runs under its pinned policy',
      !s.overlay && /YELLOW/.test(s.text) && s.loads === 1, s);
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

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
