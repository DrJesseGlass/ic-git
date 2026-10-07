// ic-git verifier for Firefox -- background. Design: docs/EXTENSION.md.
//
// Firefox lets an extension hold a response (webRequest.filterResponseData),
// so here the page that loads is the page that arrived, byte for byte, and
// only if it is the recorded one:
//
// - onHeadersReceived, before any body: make sure the site is verified
//   (waiting for the check on a first visit) and set the policy
//   derivePolicy pins for it -- or script-src 'none' if it did not verify.
// - onBeforeRequest's filter holds every byte of the body. If what arrived
//   hashes to the verified record, and the right policy went out with its
//   headers, the bytes are released unchanged. Otherwise those delivered
//   bytes are checked against the record themselves; if they pass (a new
//   deploy), a one-line refresh loads them again under their own policy,
//   and if not, the tab gets a bare document under the shared stop page.
//
// Nothing of a held response reaches the parser before that decision, so
// a tampered page is neither shown nor run, and makes no requests.
//
// And what a verified page talks to (docs/GOVERNANCE.md, section 4): every
// call a /site/ page makes to the IC's API is held in onBeforeRequest until
// the canister it names has been judged from a certified read -- a governed
// backend running its approved build, a system canister of the NNS, or,
// with a warning, an ungoverned one -- and cancelled otherwise. The judging
// is checkBackends', shared with Chrome and the loader; the known backends
// are judged with the site, so its first calls do not wait, and an
// unknown one is judged as it is called.

const CANISTER = Verifier.DEFAULTS.canister;
const ORIGIN = 'https://' + CANISTER + '.raw.icp0.io';
// The registry is read through both; they must return the same answer.
const RPCS = ['https://ethereum-sepolia-rpc.publicnode.com', 'https://sepolia.gateway.tenderly.co'];
const REFRESH_MINUTES = 10;
const BLOCK = "script-src 'none'; object-src 'none'; base-uri 'none'";
const BARE = '<!doctype html><html><head><meta charset="utf-8"><title>ic-git verifier</title></head><body></body></html>';
const REFRESH = '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0"><title>ic-git verifier</title></head><body></body></html>';
const FILTER = { urls: [ORIGIN + '/site/*'], types: ['main_frame'] };
// The IC's API, on every host that serves it; pages use icp-api.io.
const API_FILTER = { urls: ['https://icp-api.io/*', 'https://icp0.io/*', 'https://*.icp0.io/*', 'https://ic0.app/*', 'https://*.ic0.app/*'], types: ['xmlhttprequest'] };
const API_PATH = /^\/api\/v[0-9]+\/canister\/([a-z0-9-]+)\//;

const twoRpcs = {
  async request({ method, params = [] }) {
    const answers = await Promise.all(RPCS.map(async url => {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: AbortSignal.timeout(15_000),
      });
      const body = await res.json();
      if (body.error) throw new Error(new URL(url).host + ': ' + (body.error.message || JSON.stringify(body.error)));
      return body.result;
    }));
    if (answers[0] !== answers[1]) throw new Error('the two registry endpoints disagree on ' + method);
    return answers[0];
  },
};

const hex = bytes => Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
const sha256 = async bytes => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
const entryUrl = repo => ORIGIN + '/site/' + encodeURIComponent(repo) + '/';

// Which site a URL is the entrypoint of, or null.
function siteOf(href) {
  try {
    const u = new URL(href);
    if (u.origin !== ORIGIN) return null;
    const m = /^\/site\/([^/]+)\/(index\.html)?$/.exec(u.pathname);
    return m ? decodeURIComponent(m[1]) : null;
  } catch (_) { return null; } // not a URL, or a malformed escape
}

// --- state (storage.session: it outlives this event page, not the browser) ---
// Each read-modify-write of stored state runs alone: two that overlapped
// would write back each other's stale copy and lose an update.
let stateQueue = Promise.resolve();
const exclusive = fn => {
  const p = stateQueue.then(fn);
  stateQueue = p.catch(() => {});
  return p;
};
const load = async () => (await browser.storage.session.get('sites')).sites || {};
const remember = site => exclusive(async () => {
  const sites = await load();
  sites[site.repo] = site;
  await browser.storage.session.set({ sites });
});

// --- verification ---
// With `delivered`, the core checks those bytes -- the ones that actually
// arrived -- instead of fetching the page again.
async function check(repo, delivered) {
  const url = entryUrl(repo);
  const via = delivered
    ? (u, init) => (u === url ? Promise.resolve(new Response(delivered, { status: 200 })) : fetch(u, init))
    : undefined;
  const opts = { repo, provider: twoRpcs, providerOnly: true, providerName: 'two RPCs', fetch: via };
  const r = await Verifier.verify(opts);
  // The backends only matter for a page that will run; they are judged
  // with the site so its first calls find their verdicts waiting.
  let backends = [], warn = false;
  if (r.verified) {
    const be = await Verifier.checkBackends(repo, opts).catch(e => ({ ok: false, warn: false, backends: [], note: e.message || String(e) }));
    r.checks.push({ id: 'G', ok: be.ok, label: 'the canisters the page may call are approved or system canisters',
      detail: be.backends.map(b => b.canister.slice(0, 5) + ': ' + b.detail).concat(be.note ? [be.note] : []).join('; ') });
    r.verified = be.ok;
    backends = be.backends;
    warn = be.warn;
  }
  return {
    repo, checkedAt: Date.now(),
    status: r.verified && r.policy ? 'verified' : r.verified ? 'unpinnable' : 'failed',
    commit: r.record && r.record.commit, bundleHash: r.record && r.record.bundleHash,
    policy: r.policy || null, policyError: r.policyError || null, checks: r.checks, via: r.via,
    backends, warn,
  };
}

// The verdict on one canister a page of `repo` is calling, from the site's
// judged backends or, for one not among them, a judgment made now (and
// kept with the site). Unknown repo or site: nothing is vouched for.
async function backend(repo, canisterId) {
  const site = (await load())[repo];
  const known = site && (site.backends || []).find(b => b.canister === canisterId);
  if (known) return known;
  const be = await Verifier.checkBackends(repo, { provider: twoRpcs, providerOnly: true, providerName: 'two RPCs', canisters: [canisterId] })
    .catch(e => ({ backends: [{ canister: canisterId, kind: 'unreadable', ok: false, warn: false, detail: e.message || String(e) }] }));
  const b = be.backends[0];
  if (site) await exclusive(async () => {
    const sites = await load();
    const s = sites[repo];
    if (s && !(s.backends || []).some(x => x.canister === canisterId)) { s.backends = [...(s.backends || []), b]; await browser.storage.session.set({ sites }); }
  });
  return b;
}

// The site's own state, from a fresh fetch. Concurrent callers share a run.
const inFlight = new Map();
function verifySite(repo) {
  if (inFlight.has(repo)) return inFlight.get(repo);
  const run = check(repo).then(async site => { await remember(site); return site; });
  inFlight.set(repo, run);
  run.finally(() => inFlight.delete(repo)).catch(() => {});
  return run;
}

const failedSite = (repo, e) => ({
  repo, status: 'failed', checkedAt: Date.now(),
  checks: [{ id: 'X', ok: false, label: 'check the site', detail: e.message || String(e) }],
});

// --- tabs ---
const allowedKey = (tabId, repo) => tabId + ':' + repo;
async function allowed(tabId, repo) {
  const { allowed = {} } = await browser.storage.session.get('allowed');
  return Boolean(allowed[allowedKey(tabId, repo)]);
}

function badge(tabId, state, site) {
  if (tabId < 0) return;
  if (state === 'verified' && site && site.warn) state = 'warned';
  const look = {
    verified: ['OK', '#1a7f37', 'verified at commit ' + (site && site.commit || '').slice(0, 12) + '; its backends are approved or system canisters'],
    warned: ['OK', '#b35c00', 'verified at commit ' + (site && site.commit || '').slice(0, 12) + ', but its backend is not governed: the site owner can change it without approval'],
    blockedCall: ['!', '#b3261e', 'verified, but a call to a canister no record approves was blocked: ' + (site && site.blocked || '')],
    checking: ['...', '#6b6b6b', 'checking against its registry record'],
    failed: ['!', '#b3261e', 'NOT verified -- the page was not loaded'],
    unpinnable: ['!', '#b3261e', 'verified, but its scripts cannot be pinned -- the page was not loaded'],
    allowed: ['!', '#b35c00', 'NOT verified -- running anyway, as you chose'],
    uncovered: ['', '#6b6b6b', 'this page is covered by no record; its scripts are blocked'],
  }[state];
  browser.action.setBadgeText({ tabId, text: look[0] }).catch(() => {});
  browser.action.setBadgeBackgroundColor({ tabId, color: look[1] }).catch(() => {});
  browser.action.setTitle({ tabId, title: 'ic-git verifier: ' + (site ? site.repo + ' ' : '') + look[2] }).catch(() => {});
}

// What each tab's latest navigation came to, for the content script. A
// decision is bound to its request: deciding can take a network check,
// and a tab that navigated on meanwhile must not hear about the page it
// left as if it were the page it is on.
const latest = new Map();  // tabId -> requestId of its latest navigation
const results = new Map(); // tabId -> { url, status, site } of that navigation
const summary = site => ({
  repo: site.repo, commit: site.commit || null, checks: site.checks || [],
  via: site.via || null, policyError: site.policyError || null,
  backends: site.backends || [], warn: Boolean(site.warn),
});
function settle(d, status, site) {
  if (latest.get(d.tabId) !== d.requestId) return;
  results.set(d.tabId, { url: d.url, status, site: site ? summary(site) : undefined });
  badge(d.tabId, status, site);
}

// --- the headers: which policy this response goes out with ---
const applied = new Map(); // requestId -> the policy set on its headers

browser.webRequest.onHeadersReceived.addListener(async d => {
  const repo = siteOf(d.url);
  let policy = BLOCK;
  if (repo !== null) {
    if (await allowed(d.tabId, repo)) { applied.set(d.requestId, null); return {}; }
    let site = (await load())[repo];
    if (!site || site.status !== 'verified' || Date.now() - site.checkedAt > REFRESH_MINUTES * 60_000) {
      badge(d.tabId, 'checking', { repo });
      site = await verifySite(repo).catch(e => failedSite(repo, e));
    }
    if (site.status === 'verified') policy = site.policy;
  }
  applied.set(d.requestId, policy);
  const headers = d.responseHeaders.filter(h => h.name.toLowerCase() !== 'content-security-policy');
  headers.push({ name: 'Content-Security-Policy', value: policy });
  return { responseHeaders: headers };
}, FILTER, ['blocking', 'responseHeaders']);

// --- the body: held until it is known to be the recorded page ---
browser.webRequest.onBeforeRequest.addListener(d => {
  // /site/<repo> without the slash: the canister serves the entrypoint
  // there too, but relative URLs then resolve one level up and no record's
  // rule matches it. Send it to the canonical /site/<repo>/ first.
  const u = new URL(d.url);
  if (/^\/site\/[^/]+$/.test(u.pathname)) { u.pathname += '/'; return { redirectUrl: u.href }; }
  latest.set(d.tabId, d.requestId);
  const filter = browser.webRequest.filterResponseData(d.requestId);
  const chunks = [];
  filter.ondata = e => chunks.push(new Uint8Array(e.data));
  // A redirected or cancelled request ends here, never in onstop.
  filter.onerror = () => applied.delete(d.requestId);
  filter.onstop = async () => {
    const bytes = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let at = 0;
    for (const c of chunks) { bytes.set(c, at); at += c.length; }
    let out;
    try { out = await decide(d, bytes); } catch (e) { settle(d, 'failed', failedSite(siteOf(d.url) || '', e)); out = BARE; }
    applied.delete(d.requestId);
    filter.write(typeof out === 'string' ? new TextEncoder().encode(out) : out);
    filter.close();
  };
}, FILTER, ['blocking']);

// What the tab gets for a held response: its own bytes, or a document of ours.
async function decide(d, bytes) {
  const repo = siteOf(d.url);
  if (repo === null) { settle(d, 'uncovered'); return BARE; }
  if (await allowed(d.tabId, repo)) { settle(d, 'allowed', { repo }); return bytes; }
  const site = (await load())[repo];
  const policy = applied.get(d.requestId);
  if (site && site.status === 'verified' && await sha256(bytes) === site.bundleHash) {
    if (policy === site.policy) { settle(d, 'verified', site); return bytes; }
    // Verified since these headers went out: load it again under the policy.
    settle(d, 'checking', site);
    return REFRESH;
  }
  // Not what the site's state says it should be. Check what arrived itself:
  // a new deploy passes and is loaded again under its own policy; anything
  // else is stopped. A failure here is this navigation's, not the site's --
  // a targeted man in the middle can tamper with one response while the
  // record and every other fetch are honest -- so it is not remembered.
  const mine = await check(repo, bytes).catch(e => failedSite(repo, e));
  if (mine.status === 'verified') { await remember(mine); settle(d, 'checking', mine); return REFRESH; }
  settle(d, mine.status, mine);
  return BARE;
}

// --- the calls: held until the canister they name is judged ---
// A request from a /site/ page (its documentUrl is the page) to the IC's
// API. Not ours: anything else, this extension's own reads among them.
browser.webRequest.onBeforeRequest.addListener(async d => {
  const page = d.documentUrl || d.originUrl || '';
  let repo;
  try { const u = new URL(page); if (u.origin !== ORIGIN || !u.pathname.startsWith('/site/')) return {}; repo = siteOf(page); } catch (_) { return {}; }
  if (repo === null) return { cancel: true }; // no record covers the page: it may call nothing
  const u = new URL(d.url);
  // The IC's API lives under /api/vN/; the gateway hosts serve other things
  // too (a canister's own /api/<repo>/... routes, say), which are not ours.
  if (!/^\/api\/v[0-9]+\//.test(u.pathname)) return {};
  if (await allowed(d.tabId, repo)) return {};
  const m = API_PATH.exec(u.pathname);
  // Only the one host pages are expected to use, and only canister calls:
  // anything else of the IC's API is cancelled unjudged.
  if (u.host !== 'icp-api.io' || !m) { noteBlocked(d.tabId, repo, u.host + u.pathname); return { cancel: true }; }
  const b = await backend(repo, m[1]);
  if (b.ok) return {};
  noteBlocked(d.tabId, repo, m[1] + ' (' + b.detail + ')');
  return { cancel: true };
}, API_FILTER, ['blocking']);

async function noteBlocked(tabId, repo, what) {
  const site = (await load())[repo] || { repo };
  badge(tabId, 'blockedCall', { ...site, blocked: what });
}

// --- messages from the shared content script ---
browser.runtime.onMessage.addListener(async (msg, sender) => {
  const tabId = sender.tab && sender.tab.id;
  if (tabId === undefined) return { error: 'no tab' };
  if (msg.type === 'visit') {
    const r = results.get(tabId);
    if (r && r.url === msg.url) return { status: r.status, site: r.site };
    // No held response for this page (one restored from history, say):
    // say what the site's state is, and let a reload settle the rest.
    const repo = siteOf(msg.url);
    if (repo === null) return { status: 'uncovered' };
    const site = (await load())[repo];
    return site && site.status === 'verified' ? { status: 'verified', site: summary(site) } : { status: 'checking', site: { repo } };
  }
  if (msg.type === 'allow') {
    await exclusive(async () => {
      const { allowed = {} } = await browser.storage.session.get('allowed');
      allowed[allowedKey(tabId, msg.repo)] = true;
      await browser.storage.session.set({ allowed });
    });
    return { ok: true };
  }
  if (msg.type === 'retry') {
    const site = await verifySite(msg.repo).catch(e => failedSite(msg.repo, e));
    return { status: site.status, site: summary(site) };
  }
  return { error: 'unknown message' };
});

browser.tabs.onRemoved.addListener(tabId => {
  latest.delete(tabId);
  results.delete(tabId);
  return exclusive(async () => {
    const { allowed = {} } = await browser.storage.session.get('allowed');
    const gone = Object.keys(allowed).filter(k => k.startsWith(tabId + ':'));
    if (!gone.length) return;
    for (const k of gone) delete allowed[k];
    await browser.storage.session.set({ allowed });
  });
});

// Keep verified state current, so the next visit does not wait.
// Created once: this runs on every start of the event page, and creating it
// again would restart its period, so a page woken by visits would never
// refresh.
browser.alarms.get('refresh').then(a => { if (!a) browser.alarms.create('refresh', { periodInMinutes: REFRESH_MINUTES }); });
browser.alarms.onAlarm.addListener(async alarm => {
  if (alarm.name !== 'refresh') return;
  for (const repo of Object.keys(await load())) await verifySite(repo).catch(() => {});
});
