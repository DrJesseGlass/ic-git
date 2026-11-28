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
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
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
// The git canister's host: since the cut (docs/CANISTER_SPLIT.md, step 16,
// 2026-11-16) it serves every site, and ic-git's own host only redirects.
const GW = 'https://34koz-jyaaa-aaaab-ahejq-cai.raw.icp0.io';
const VOTE = GW + '/site/ic-vote/';
const CONSOLE = GW + '/site/ic-git/';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const INJECT = '<script>window.__pwned = 1;</script><script src="' + GW + '/api/repos"></script>';
// The console's home, a domain the core pins (Verifier.DEFAULTS.domains).
const HOME = 'https://ic-git.com/';

// A browser with the extension, one page, and a flat-session CDP client.
// A man in the middle on the network, as a TLS-inspecting proxy is: the
// canister's hostname resolves to this server, which forwards every request
// to the real canister and passes responses through `rewrite`. Page and
// extension alike fetch through it. Its certificate is self-signed, so the
// browser runs with --ignore-certificate-errors -- as a machine that trusts
// the proxy's root does. `rewrite(path, text, headers)` returns the body to
// serve instead, or { body, type } to serve it as another content type, or
// null to pass the response through.
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
      const got = rewrite(req.url, body.toString('utf8'), req.headers);
      if (got !== null) body = Buffer.from(typeof got === 'string' ? got : got.body);
      const out = {};
      up.headers.forEach((v, k) => { if (!['content-encoding', 'content-length', 'transfer-encoding', 'connection'].includes(k)) out[k] = v; });
      if (got !== null && typeof got !== 'string') out['content-type'] = got.type;
      res.writeHead(up.status, out);
      res.end(body);
    } catch (e) { res.writeHead(502); res.end(String(e)); }
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return server;
}

// The console's home as whoever holds its DNS serves it: `serve(path,
// headers)` answers { status, type, body }. The domain resolves to this
// server, with a self-signed certificate, as a hijacker's would. So does
// FRAMER, anyone's page, which a frame case frames the domain in: on this
// server too, since Chrome lets no public page frame a loopback address
// (Private Network Access), with or without the extension.
const FRAMER = 'https://framer.example/';
async function domain(dir, serve) {
  if (!existsSync(join(dir, 'key.pem'))) execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=domain',
    '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
  const server = createServer({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, async (req, res) => {
    try {
      const { status, type, body } = req.headers.host === new URL(FRAMER).host
        ? { status: 200, type: 'text/html', body: '<!doctype html><title>framer</title><p>anyone\'s page</p>' }
        : await serve(req.url, req.headers);
      res.writeHead(status, { 'content-type': type });
      res.end(body);
    } catch (e) { res.writeHead(502); res.end(String(e)); }
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return server;
}
// What the canister serves at the domain: the site's root at /, the same
// bytes as at /site/ic-git/ (docs/TENANCY.md, "Custom domains").
const honest = async path => {
  if (!/^\/(index\.html)?(\?|$)/.test(path)) return { status: 404, type: 'text/plain', body: 'not found' };
  const r = await fetch(CONSOLE);
  return { status: r.status, type: r.headers.get('content-type'), body: Buffer.from(await r.arrayBuffer()) };
};

async function open({ mitm, home } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ext-test-'));
  const server = mitm ? await proxy(dir, mitm) : null;
  const homeServer = home ? await domain(dir, home) : null;
  const maps = [
    ...(server ? [`MAP ${new URL(GW).host}:443 127.0.0.1:${server.address().port}`] : []),
    ...(homeServer ? [HOME, FRAMER].map(u => `MAP ${new URL(u).host}:443 127.0.0.1:${homeServer.address().port}`) : []),
  ];
  const net = maps.length ? [`--host-resolver-rules=${maps.join(', ')}`, '--ignore-certificate-errors'] : [];
  const port = 9600 + Math.floor(Math.random() * 300);
  // --use-mock-keychain: a fresh profile otherwise asks the macOS keychain
  // for a password at every launch.
  const chrome = spawn(bin, ['--headless=new', '--window-size=1280,900', '--use-mock-keychain', '--password-store=basic', ...net, `--remote-debugging-port=${port}`, `--user-data-dir=${dir}`,
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
    color: await evaluate('(async () => { const ts = await chrome.tabs.query({}); const c = await chrome.action.getBadgeBackgroundColor({ tabId: Math.max(...ts.map(t => t.id)) }); return c.slice(0, 3).join(","); })()', sw),
    loads,
  });
  // What a call from the page to the IC's API comes to: an HTTP status, or
  // "blocked" when the extension's rules cancel it before it leaves.
  const call = url => evaluate(`fetch(${JSON.stringify(url)}, { method: 'POST', headers: { 'content-type': 'application/cbor' }, body: new Uint8Array([0]) }).then(r => 'http ' + r.status, e => 'blocked')`);
  // Press a button on the stop page by its text. The page is in a closed
  // shadow root, which page scripts cannot reach but DevTools can.
  // The labels of the stop page's buttons. In an XML document a node's
  // name keeps its case.
  const buttons = async () => {
    const { root } = await send('DOM.getDocument', { depth: -1, pierce: true }, page);
    const out = [];
    const walk = n => {
      if (n.nodeName.toLowerCase() === 'button') out.push((n.children || []).map(c => c.nodeValue || '').join(''));
      for (const k of [...(n.children || []), ...(n.shadowRoots || [])]) walk(k);
    };
    walk(root);
    return out;
  };
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
    if (homeServer) homeServer.close();
    rmSync(dir, { recursive: true, force: true, maxRetries: 5 });
  };
  return { send, page, sw, go, state, intercept, evaluate, refused, buttons, press, close, call };
}

let failed = 0;
const report = (name, ok, got) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '\n        got ' + JSON.stringify(got)}`);
  if (!ok) failed++;
};
// A case that cannot run against what is live, and why.
const skip = (name, why) => console.log(`SKIP  ${name}\n        ${why}`);
// Whether the console the registry records knows its home: one published
// before it did reads its /api on its own origin, which at the domain is
// the domain's, so only its being written there can be checked.
const homeAware = async () => (await (await fetch(CONSOLE)).text()).includes("const HOME = '" + new URL(HOME).origin + "';");

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
    // The backend check (docs/GOVERNANCE.md, section 4). Since 2026-10-14
    // every canister ic-vote's page may call is judged clean -- its poll
    // canister governed by ic-git, ic-git under its governor, the system
    // canisters -- so the badge is OK in green, not amber, and the page's
    // calls reach them; a canister nobody judged, or any IC API host but
    // icp-api.io, is blocked before the request leaves. (The amber case is
    // covered offline by tools/certified-test.mjs.)
    report('every backend governed or system: the badge is OK in green', s.badge === 'OK' && s.color === '26,127,55', s);
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

// 4c. Targeted, by type: the page's copy is another document, typed as XML,
// XHTML or SVG -- which document.open() cannot replace -- or as HTML in
// another charset, which the written page would keep. The static rule
// types every page under /site/ as UTF-8 HTML, so the checked bytes are
// written as ever. Then the XML types with the static rules off, which
// leaves what stands behind that rule: main.js stops and empties the
// document, takes no write, and the badge is never OK.
{
  const XML = '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><head><title>x</title></head><body><p>HACKED: send your keys here</p><script>window.__pwned = 1;</script></body></html>';
  const TYPES = ['text/xml', 'application/xhtml+xml', 'image/svg+xml', 'text/html; charset=iso-2022-jp'];
  let type = null;
  // Only the tab's copy: the extension's own fetch of the page is honest.
  const b = await open({ mitm: (url, t, h) => (type && url === '/site/ic-git/' && h['sec-fetch-dest'] === 'document' ? { body: XML, type } : null) });
  try {
    await b.go(CONSOLE, 20_000);
    for (type of TYPES) {
      await b.go(CONSOLE, 10_000);
      const s = await b.state();
      const ct = await b.evaluate('document.contentType + " " + document.characterSet');
      report('the page\'s copy served as ' + type + ': typed as UTF-8 HTML, the checked page is written, badge OK',
        ct === 'text/html UTF-8' && !/HACKED/.test(s.text) && /repositories/.test(s.text) && !s.overlay && s.pwned === 0 && s.badge === 'OK', { ct, ...s });
    }
    await b.evaluate("chrome.declarativeNetRequest.updateEnabledRulesets({ disableRulesetIds: ['default'] })", b.sw);
    for (type of TYPES.slice(0, 3)) {
      await b.go(CONSOLE, 10_000);
      const s = await b.state();
      const ct = await b.evaluate('document.contentType');
      // Anywhere in the document, not only a body (an XML one may have none).
      const all = await b.evaluate("document.documentElement ? document.documentElement.textContent : ''");
      // "Open anyway" could only meet the same emptied document again.
      const offered = await b.buttons();
      report('without the static rules, served as ' + type + ': stopped and emptied, stop page with no "open anyway", badge !',
        ct === type && !/HACKED/.test(all) && s.overlay && s.pwned === 0 && s.badge === '!' && offered.length === 1 && offered[0] === 'Check again',
        { ct, all: all.slice(0, 80), offered, ...s });
    }
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

// 7. The same canisters at any other host: no page under /site/ loads.
// The rule needs no permission for those hosts, and the manifest has none.
{
  const b = await open();
  const ID = '34koz-jyaaa-aaaab-ahejq-cai', OLD = 'umobs-yiaaa-aaaab-agyrq-cai';
  // What a navigation comes to: 'blocked' when the extension's rule
  // cancels it, else the network's error, or 'loaded'.
  const nav = async url => {
    const r = await b.send('Page.navigate', { url }, b.page);
    await sleep(300);
    return r.errorText === 'net::ERR_BLOCKED_BY_CLIENT' ? 'blocked' : r.errorText || 'loaded';
  };
  try {
    const stopped = [
      // The gateways' other domains, certified and raw.
      `https://${ID}.icp0.io/site/ic-git/`,
      `https://${ID}.ic0.app/site/ic-git/`,
      `https://${ID}.raw.ic0.app/site/ic-git/`,
      `https://${ID}.icp1.io/site/ic-git/`,
      `https://${ID}.raw.icp1.io/site/ic-vote/`,
      `https://${ID}.icp.net/site/ic-git/`,
      `https://${ID}.raw.icp.net/site/ic-git/index.html?x=1#y`,
      `https://${OLD}.icp0.io/site/ic-git/`,
      `http://${ID}.icp0.io/site/ic-git/`,
      // The slash-less address, and /site itself.
      `https://${ID}.icp0.io/site/ic-git`,
      `https://${ID}.icp0.io/site`,
      // A prefix, which a gateway drops, at the checked domain too.
      `https://x--${ID}.raw.icp0.io/site/ic-git/`,
      // A prefix a hostname may have and a DNS name may not.
      `https://x_y--${ID}.icp0.io/site/ic-git/`,
      // The checked host spelled as another origin: with the root's dot
      // (the gateways answer there), or at another port.
      `https://${ID}.raw.icp0.io./site/ic-git/`,
      `https://${ID}.raw.icp0.io:8443/site/ic-git/`,
      `https://a--b--${ID}.icp0.io/site/ic-git/`,
      // A domain no list knows: the rule goes by the canister's id.
      `https://${ID}.gateway.example/site/ic-git/`,
      `https://${ID}.raw.gateway.example:8443/site/ic-git/`,
      `https://user@${ID}.icp0.io/site/ic-git/`,
    ];
    for (const url of stopped) {
      const got = await nav(url);
      report('blocked: ' + url, got === 'blocked', got);
    }
    const passed = [
      // Not under /site/: the canister's index and its API are not pages.
      `https://${ID}.icp0.io/`,
      `https://${ID}.icp0.io/api/repos`,
      `https://${ID}.icp0.io/sites/x`,
      // Another canister.
      'https://ryjl3-tyaaa-aaaaa-aaaba-cai.icp0.io/site/x/',
      // The canister's id elsewhere than the host's first label.
      `https://example.com/site/${ID}.icp0.io/`,
    ];
    for (const url of passed) {
      const got = await nav(url);
      report('not blocked: ' + url, got !== 'blocked', got);
    }
    // The checked host over http is asked for over https.
    await b.send('Page.navigate', { url: `http://${ID}.raw.icp0.io/site/ic-git/` }, b.page);
    await sleep(15_000);
    const at = await b.evaluate('location.href');
    const s = await b.state();
    report('the checked host over http: upgraded, checked, runs', at === CONSOLE && !s.overlay && s.badge === 'OK', { at, ...s });
    // In a frame, inside a page of anyone's: the canister's index at
    // that host loads there, a page under /site/ does not. Nor does one of
    // the checked host, in a frame or an object: it would run there as
    // that host, unchecked, and could reach a checked page of it.
    await b.send('Page.navigate', { url: 'https://example.com/' }, b.page);
    await sleep(3_000);
    await b.evaluate(`for (const path of ['/', '/site/ic-git/']) {
      const f = document.createElement('iframe');
      f.src = 'https://${ID}.icp0.io' + path;
      document.body.append(f);
    }
    for (const src of ['${GW}/site/ic-vote/', '${GW.replace('//', '//x@')}/site/ic-vote/']) {
      const f = document.createElement('iframe');
      f.src = src;
      document.body.append(f);
    }
    // An object of another host that loads, so the check sees objects.
    for (const data of ['https://${ID}.icp0.io/?object', '${GW}/site/ic-git/']) {
      const o = document.createElement('object');
      o.type = 'text/html';
      o.data = data;
      document.body.append(o);
    }`);
    await sleep(8_000);
    // A frame of another site is a target of its own, and keeps the
    // address it was given: where it is says whether it loaded.
    const frames = {};
    for (const t of (await b.send('Target.getTargets')).targetInfos.filter(t => t.type === 'iframe')) {
      const { sessionId } = await b.send('Target.attachToTarget', { targetId: t.targetId, flatten: true });
      frames[t.url] = await b.evaluate('location.href', sessionId);
    }
    const hostOf = url => { try { return new URL(url).host; } catch { return ''; } };
    report('blocked in a frame', frames[`https://${ID}.icp0.io/`] === `https://${ID}.icp0.io/` && frames[`https://${ID}.icp0.io/site/ic-git/`] === 'chrome-error://chromewebdata/', frames);
    report('the checked host blocked in a frame and in an object, with a user name too',
      frames[`https://${ID}.icp0.io/?object`] === `https://${ID}.icp0.io/?object` && frames[GW + '/site/ic-vote/'] === 'chrome-error://chromewebdata/' &&
      !Object.values(frames).some(u => hostOf(u) === hostOf(GW)), frames);
  } finally { await b.close(); }
}

// 8. The console's home, ic-git.com, a domain the core pins: its root is
// the ic-git site's entrypoint, checked as the git canister serves it on
// its own host, and the tab shows those checked bytes whatever the domain
// served -- so a hijacked domain's page never runs. Every other page there
// is covered by no record, and the domain loads in no frame and under no
// other spelling.
{
  const wallet = b => b.evaluate("(document.getElementById('wallet') || {}).innerText || ''");
  const aware = await homeAware();
  const b = await open({ home: honest });
  try {
    await b.go(HOME, 20_000);
    let s = await b.state();
    const at = await b.evaluate('location.href');
    report('at home: checked, reloaded once under the pinned policy, the checked page written, badge OK',
      at === HOME && !s.overlay && /a git remote on the Internet Computer/.test(s.text) && s.badge === 'OK' && s.loads === 2, { at, ...s });
    const w = await wallet(b);
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
    // The same site as on the git canister's host: checked once for both.
    await b.go(CONSOLE, 8_000);
    s = await b.state();
    report('the same site on the git canister\'s host: no new check, no reload', !s.overlay && /repositories/.test(s.text) && s.badge === 'OK' && s.loads === 1, s);
  } finally { await b.close(); }
}
{
  // Hijacked: the domain serves a page of its own at the root and at
  // another path, and the root once more typed as XML.
  const EVIL = '<!doctype html><html><head><title>ic-git</title><script>window.__pwned = 1;</script></head><body><p>HACKED: send your keys here</p></body></html>';
  let type = 'text/html';
  const b = await open({ home: async () => ({ status: 200, type, body: EVIL }) });
  try {
    await b.go(HOME, 20_000);
    let s = await b.state();
    report('hijacked home: the tab shows the checked console, the domain\'s page never runs, badge OK',
      !/HACKED/.test(s.text) && /a git remote on the Internet Computer/.test(s.text) && !s.overlay && s.pwned === 0 && s.badge === 'OK', s);
    type = 'text/xml';
    await b.go(HOME, 10_000);
    s = await b.state();
    const ct = await b.evaluate('document.contentType');
    report('hijacked home served as XML: typed as HTML, the checked console is written',
      ct === 'text/html' && !/HACKED/.test(s.text) && /a git remote on the Internet Computer/.test(s.text) && s.pwned === 0 && s.badge === 'OK', { ct, ...s });
    type = 'text/html';
    await b.go(new URL('/login.html', HOME).href, 8_000);
    s = await b.state();
    report('hijacked home, another page there: covered by no record, stop page, nothing runs', s.overlay && s.pwned === 0 && !/HACKED/.test(s.text), s);
  } finally { await b.close(); }
}
{
  const b = await open({ home: honest });
  const nav = async url => {
    const r = await b.send('Page.navigate', { url }, b.page);
    await sleep(300);
    return r.errorText === 'net::ERR_BLOCKED_BY_CLIENT' ? 'blocked' : r.errorText || 'loaded';
  };
  try {
    for (const url of ['https://ic-git.com./', 'https://ic-git.com:8443/', 'https://user@ic-git.com./']) {
      const got = await nav(url);
      report('blocked: ' + url, got === 'blocked', got);
    }
    await b.send('Page.navigate', { url: 'http://ic-git.com/' }, b.page);
    await sleep(20_000);
    const at = await b.evaluate('location.href');
    const s = await b.state();
    report('home over http: upgraded, checked, the checked page written', at === HOME && !s.overlay && /a git remote on the Internet Computer/.test(s.text) && s.badge === 'OK', { at, ...s });
    await b.send('Page.navigate', { url: FRAMER }, b.page);
    await sleep(3_000);
    // The control is of another site, so that it is a target of its own.
    const control = 'https://34koz-jyaaa-aaaab-ahejq-cai.icp0.io/?framed';
    await b.evaluate(`for (const src of ['${control}', '${HOME}', 'https://x@ic-git.com/']) {
      const f = document.createElement('iframe');
      f.src = src;
      document.body.append(f);
    }
    const o = document.createElement('object');
    o.type = 'text/html';
    o.data = '${HOME}';
    document.body.append(o);`);
    await sleep(8_000);
    const frames = {};
    for (const t of (await b.send('Target.getTargets')).targetInfos.filter(t => t.type === 'iframe')) {
      const { sessionId } = await b.send('Target.attachToTarget', { targetId: t.targetId, flatten: true });
      frames[t.url] = await b.evaluate('location.href', sessionId);
    }
    const hostOf = url => { try { return new URL(url).host; } catch { return ''; } };
    report('home blocked in a frame and in an object, with a user name too',
      frames[control] === control && !Object.values(frames).some(u => hostOf(u) === 'ic-git.com'), frames);
  } finally { await b.close(); }
}

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed ? 1 : 0);
