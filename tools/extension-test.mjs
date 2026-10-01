#!/usr/bin/env node
// Drives extension/ in headless Chromium against the live ic-git canister and
// the Sepolia registry, playing a man in the middle with the DevTools Fetch
// domain where a case needs one.
//
//   node tools/extension-test.mjs --browser "/path/to/Chrome for Testing"
//
// It needs a Chromium that loads unpacked extensions from the command line
// (Chrome for Testing does; branded Chrome no longer does), and the network.
// Every case starts from a fresh profile, so each first visit is a first.
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const bin = process.argv[process.argv.indexOf('--browser') + 1];
if (!process.argv.includes('--browser') || !bin) {
  console.error('usage: extension-test.mjs --browser <chromium binary>');
  process.exit(2);
}
const EXT = fileURLToPath(new URL('../extension', import.meta.url));
const GW = 'https://umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io';
const VOTE = GW + '/site/ic-vote/';
const CONSOLE = GW + '/site/ic-git/';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const INJECT = '<script>window.__pwned = 1;</script><script src="' + GW + '/api/repos"></script>';

// A browser with the extension, one page, and a flat-session CDP client.
// A man in the middle on the network, as a TLS-inspecting proxy is: the
// canister's hostname resolves to this server, which forwards every request
// to the real canister and passes responses through `rewrite`. Page and
// extension alike fetch through it. Its certificate is self-signed, so the
// browser runs with --ignore-certificate-errors -- as a machine that trusts
// the proxy's root does.
async function proxy(dir, rewrite) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=proxy',
    '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
  const server = createServer({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, async (req, res) => {
    try {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const headers = Object.fromEntries(Object.entries(req.headers).filter(([k]) => !['host', 'connection', 'accept-encoding'].includes(k)));
      const up = await fetch(GW + req.url, { method: req.method, headers, body: chunks.length ? Buffer.concat(chunks) : undefined, redirect: 'manual' });
      let body = Buffer.from(await up.arrayBuffer());
      const text = rewrite(req.url, body.toString('utf8'));
      if (text !== null) body = Buffer.from(text);
      const out = {};
      up.headers.forEach((v, k) => { if (!['content-encoding', 'content-length', 'transfer-encoding', 'connection'].includes(k)) out[k] = v; });
      res.writeHead(up.status, out);
      res.end(body);
    } catch (e) { res.writeHead(502); res.end(String(e)); }
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return server;
}

async function open({ mitm } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ext-test-'));
  const server = mitm ? await proxy(dir, mitm) : null;
  const net = server ? [`--host-resolver-rules=MAP ${new URL(GW).host}:443 127.0.0.1:${server.address().port}`, '--ignore-certificate-errors'] : [];
  const port = 9600 + Math.floor(Math.random() * 300);
  const chrome = spawn(bin, ['--headless=new', '--window-size=1280,900', ...net, `--remote-debugging-port=${port}`, `--user-data-dir=${dir}`,
    `--load-extension=${EXT}`, `--disable-extensions-except=${EXT}`, 'about:blank'], { stdio: 'ignore' });
  let version;
  for (let i = 0; i < 60 && !version; i++) {
    await sleep(200);
    try { version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json(); } catch {}
  }
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise(r => { ws.onopen = r; });
  let seq = 0;
  const pending = new Map(), handlers = [];
  ws.onmessage = m => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
    for (const h of handlers) h(d);
  };
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, d => (d.error ? reject(new Error(method + ': ' + d.error.message)) : resolve(d.result)));
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
  const on = h => handlers.push(h);

  // The extension's worker, once it is up. Chromium runs component
  // extensions of its own, some with a background.js too, so it is picked
  // by its manifest's name.
  let sw;
  for (let i = 0; i < 50 && !sw; i++) {
    const { targetInfos } = await send('Target.getTargets');
    for (const t of targetInfos.filter(t => t.type === 'service_worker' && t.url.startsWith('chrome-extension://'))) {
      const { sessionId } = await send('Target.attachToTarget', { targetId: t.targetId, flatten: true });
      const name = (await send('Runtime.evaluate', { expression: 'chrome.runtime.getManifest().name', returnByValue: true }, sessionId)).result.value;
      if (name === 'ic-git verifier') { sw = sessionId; break; }
      await send('Target.detachFromTarget', { sessionId });
    }
    if (!sw) await sleep(200);
  }
  if (!sw) throw new Error('the extension did not load');
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId: page } = await send('Target.attachToTarget', { targetId, flatten: true });
  await send('Page.enable', {}, page);
  await send('Runtime.enable', {}, page);

  // Rewrite matching responses in the given sessions: the man in the middle.
  const intercept = async (sessions, pattern, rewrite) => {
    on(async d => {
      if (d.method !== 'Fetch.requestPaused' || !sessions.includes(d.sessionId)) return;
      const { requestId, responseStatusCode, responseHeaders } = d.params;
      const { body, base64Encoded } = await send('Fetch.getResponseBody', { requestId }, d.sessionId);
      const text = base64Encoded ? Buffer.from(body, 'base64').toString('utf8') : body;
      await send('Fetch.fulfillRequest', {
        requestId, responseCode: responseStatusCode,
        responseHeaders: responseHeaders.filter(h => !/^content-length$/i.test(h.name)),
        body: Buffer.from(rewrite(text)).toString('base64'),
      }, d.sessionId);
    });
    for (const s of sessions) await send('Fetch.enable', { patterns: [{ urlPattern: pattern, requestStage: 'Response' }] }, s);
  };

  let loads = 0;
  // Navigations of the tab's main frame: a reload counts, a written
  // document does not.
  on(d => { if (d.method === 'Page.frameNavigated' && d.sessionId === page && !d.params.frame.parentId) loads++; });
  const refused = [];
  on(d => {
    if (d.sessionId === page && d.method === 'Runtime.consoleAPICalled') return;
    if (d.sessionId === page && d.method === 'Log.entryAdded' && /Content Security Policy/.test(d.params.entry.text)) refused.push(d.params.entry.text);
  });
  await send('Log.enable', {}, page);

  const evaluate = async (expression, session = page) => (await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, session)).result.value;
  const go = async (url, wait = 14_000) => { loads = 0; await send('Page.navigate', { url }, page); await sleep(wait); };
  // What the tab shows: whether the overlay is up and what it says, the
  // page's own text, whether injected code ran, and the badge.
  const state = async () => ({
    overlay: await evaluate("!!document.querySelector('ic-git-verifier')"),
    text: await evaluate("document.body ? document.body.innerText.replace(/\\s+/g, ' ').slice(0, 200) : ''"),
    pwned: await evaluate('window.__pwned || 0'),
    // The test's tab is the newest one (the first is the browser's own).
    badge: await evaluate('(async () => { const ts = await chrome.tabs.query({}); const text = await chrome.action.getBadgeText({ tabId: Math.max(...ts.map(t => t.id)) }); return text; })()', sw),
    loads,
  });
  // Press a button on the stop page by its text. The page is in a closed
  // shadow root, which page scripts cannot reach but DevTools can.
  const press = async label => {
    const { root } = await send('DOM.getDocument', { depth: -1, pierce: true }, page);
    const find = n => {
      if (n.nodeName === 'BUTTON' && (n.children || []).some(c => c.nodeValue && c.nodeValue.startsWith(label))) return n;
      for (const k of [...(n.children || []), ...(n.shadowRoots || [])]) { const f = find(k); if (f) return f; }
      return null;
    };
    const button = find(root);
    if (!button) throw new Error('no button "' + label + '"');
    await send('DOM.scrollIntoViewIfNeeded', { nodeId: button.nodeId }, page);
    const { model } = await send('DOM.getBoxModel', { nodeId: button.nodeId }, page);
    const [x1, y1, , , x2, y2] = model.content;
    const x = (x1 + x2) / 2, y = (y1 + y2) / 2;
    for (const type of ['mousePressed', 'mouseReleased']) {
      await send('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: 1 }, page);
    }
  };
  const close = async () => {
    ws.close();
    const exited = new Promise(r => chrome.once('exit', r));
    chrome.kill();
    await exited;
    if (server) server.close();
    rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  };
  return { send, page, sw, go, state, intercept, evaluate, refused, press, close };
}

let failed = 0;
const report = (name, ok, got) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '\n        got ' + JSON.stringify(got)}`);
  if (!ok) failed++;
};

// 1-3. First and second visit to the console, then ic-vote.
{
  const b = await open();
  try {
    await b.go(CONSOLE, 20_000);
    let s = await b.state();
    report('first visit: checked, reloaded once under the pinned policy, runs, badge OK',
      !s.overlay && /repositories/.test(s.text) && s.badge === 'OK' && s.loads === 2, s);
    await b.go(CONSOLE, 8_000);
    s = await b.state();
    report('second visit: no checking screen and no reload', !s.overlay && /repositories/.test(s.text) && s.badge === 'OK' && s.loads === 1, s);
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
    report('ic-vote (stylesheet inlined in ic-vote #9) verifies and runs under its pinned policy, badge OK',
      !s.overlay && /YELLOW/.test(s.text) && s.badge === 'OK', s);
  } finally { await b.close(); }
}

// 4. Targeted: only the page's copy is rewritten. The extension's own check
// passes, and the tab is written from the checked bytes.
{
  const b = await open();
  try {
    await b.go(CONSOLE, 20_000);
    await b.intercept([b.page], '*raw.icp0.io/site/ic-git/', t => t.replace('</head>', INJECT + '</head>'));
    b.refused.length = 0;
    await b.go(CONSOLE, 10_000);
    const s = await b.state();
    // The delivered page is dropped unparsed, so its injected scripts are
    // not even refused by the policy: they never reach it.
    report('targeted tampering: injected scripts never run, the console runs as checked',
      s.pwned === 0 && /repositories/.test(s.text) && !s.overlay, { ...s, refused: b.refused.length });
  } finally { await b.close(); }
}

// 4b. Targeted, markup only: the page's copy says something else, with no
// script at all. The tab shows the checked bytes, not the delivered ones.
{
  const b = await open();
  try {
    await b.go(CONSOLE, 20_000);
    await b.intercept([b.page], '*raw.icp0.io/site/ic-git/', t => t.replace('a git remote on the Internet Computer', 'HACKED: send your keys here'));
    await b.go(CONSOLE, 10_000);
    const s = await b.state();
    report('targeted markup tampering: the tab shows the checked page, not the delivered one',
      !/HACKED/.test(s.text) && /a git remote on the Internet Computer/.test(s.text) && /repositories/.test(s.text) && !s.overlay, s);
  } finally { await b.close(); }
}

// 5, 7. Consistent: the page and the extension's fetch are both rewritten,
// as a TLS-inspecting proxy does; then "open anyway", two clicks.
{
  const b = await open({ mitm: (url, t) => (url === '/site/ic-git/' ? t.replace('</head>', INJECT + '</head>') : null) });
  try {
    await b.go(CONSOLE, 20_000);
    let s = await b.state();
    report('consistent tampering: stop page, badge !, nothing of the page runs',
      s.overlay && s.pwned === 0 && !/repositories/.test(s.text) && s.badge === '!', s);
    await b.press('Open anyway');
    await new Promise(r => setTimeout(r, 1000));
    s = await b.state();
    report('open anyway, first click: only arms it', s.overlay && s.pwned === 0 && s.loads === 1, s);
    await b.press('Click again');
    await new Promise(r => setTimeout(r, 12_000));
    s = await b.state();
    report('open anyway, second click: the page runs as served, injection included, and the badge keeps warning',
      !s.overlay && s.pwned === 1 && /repositories/.test(s.text) && s.badge === '!', s);
  } finally { await b.close(); }
}

// 5b. The proxy goes away (a VPN's inspection paused): a plain reload checks
// again rather than showing the remembered failure.
{
  let tampering = true;
  const b = await open({ mitm: (url, t) => (tampering && url === '/site/ic-git/' ? t.replace('</head>', INJECT + '</head>') : null) });
  try {
    await b.go(CONSOLE, 20_000);
    let s = await b.state();
    const stopped = s.overlay && s.badge === '!';
    tampering = false;
    await b.go(CONSOLE, 20_000);
    s = await b.state();
    report('after a failure, a reload checks again: the proxy gone, the console runs',
      stopped && !s.overlay && /repositories/.test(s.text) && s.badge === 'OK' && s.pwned === 0, { stopped, ...s });
  } finally { await b.close(); }
}

// 6. A page under /site/ that no record covers.
{
  const b = await open();
  try {
    await b.go(GW + '/site/ic-vote/nope.html', 8_000);
    const s = await b.state();
    report('a page no record covers: stop page, nothing runs', s.overlay && s.pwned === 0, s);
  } finally { await b.close(); }
}

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
