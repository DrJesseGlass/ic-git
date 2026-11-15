// ic-git verifier -- background worker. Design: docs/EXTENSION.md.
//
// Two layers, each enough to stop injected code on its own:
//
// - The page the tab shows is never the one the network delivered. main.js
//   aborts the delivered response at document_start, and the content
//   script writes in the bytes this worker checked against the registry
//   record (cached here, so a verified page needs no network at all), or a
//   bare document under the stop page.
// - Every page under /site/ on an ic-git host is covered by the static
//   rule in rules.json: a Content-Security-Policy that runs no script. Once
//   a site's entrypoint verifies, this worker installs a higher-priority
//   session rule that replaces it with the policy derivePolicy pins for the
//   verified page: its own scripts and styles, nothing else. The written
//   document keeps that policy.
//
// And a third, for what the verified page talks to (docs/GOVERNANCE.md,
// section 4): a static rule blocks every call a /site/ page makes to the
// IC's API, and session allow rules scoped to the tab, installed before
// the page runs, open exactly the canisters checkBackends judged for that
// tab's site -- governed ones running their approved build, and the NNS's
// system canisters -- plus, with a warning, ungoverned ones. Per tab,
// because the verdict is per site and every site on a host shares its
// origin. A
// canister controlled by ic-git that runs no approved build fails the
// site (check G), so the stop page says which and why.
//
// Two hosts serve sites (docs/CANISTER_SPLIT.md): ic-git until the canister
// split, the git canister after, when ic-git's /site/ URLs redirect there.
// A site is a repo on one host, checked as that host serves it.
importScripts('bls12-381.js', 'verifier.js');

const HOSTS = [Verifier.DEFAULTS.canister, Verifier.DEFAULTS.git];
const originOf = host => 'https://' + host + '.raw.icp0.io';
// The registry is read through both; they must return the same answer.
const RPCS = ['https://ethereum-sepolia-rpc.publicnode.com', 'https://sepolia.gateway.tenderly.co'];
const REFRESH_MINUTES = 10;
const PINNED_PRIORITY = 2, ALLOW_PRIORITY = 3;
// Session rule ids: a site's pinned policy from 100; a tab's backend allow
// rules from 10000 (one per canister, below 50000); a tab's "open anyway"
// from 50000 for its policy and from 60000 for its calls.
const BACKEND_RULE_BASE = 10_000, ALLOW_BASE = 50_000, TAB_CALLS_BASE = 60_000;
// The IC's API on every host that serves it: canister calls, subnet reads
// and the status endpoint, under /api/vN/. Not a canister's own /api/
// routes on the gateway (ic-git's JSON API, whatever a repo is named).
const API_HOSTS = '^https://([a-z0-9-]+\\.)*(icp-api\\.io|icp0\\.io|ic0\\.app)/api/v[0-9]+/(canister/|subnet/|status)';
const SITE_DOMAINS = HOSTS.map(h => h + '.raw.icp0.io');

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

// --- state (storage.session: it outlives this worker, not the browser) ---
const load = async () => (await chrome.storage.session.get('sites')).sites || {};
const save = async sites => chrome.storage.session.set({ sites });

// The entrypoint of a repo's site, as a DNR regex: /site/<repo>/ or its
// index.html, with any query and fragment (a navigation's URL is matched
// with its fragment on). Other paths under /site/ are covered by no record
// and keep the static policy.
const escape = s => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const siteUrl = (host, repo) => originOf(host) + '/site/' + encodeURIComponent(repo) + '/';
const entryRegex = (host, repo) => '^' + escape(siteUrl(host, repo)) + '(index\\.html)?(\\?[^#]*)?(#.*)?$';
// A rule for one site's entrypoint. Case matters (DNR's default is that it
// does not): /site/Foo/ and /site/foo/ are different sites to siteOf.
const entryCondition = (host, repo) => ({ regexFilter: entryRegex(host, repo), isUrlFilterCaseSensitive: true, resourceTypes: ['main_frame'] });
// A site's key in state: its host and repo.
const keyOf = (host, repo) => host + '/' + repo;

// Which site a URL is the entrypoint of -- { host, repo } -- or null.
function siteOf(href) {
  try {
    const u = new URL(href);
    const host = HOSTS.find(h => u.origin === originOf(h));
    if (!host) return null;
    const m = /^\/site\/([^/]+)\/(index\.html)?$/.exec(u.pathname);
    return m ? { host, repo: decodeURIComponent(m[1]) } : null;
  } catch (_) { return null; } // not a URL, or a malformed escape
}

// Session rule ids: one per site, from 100 up, remembered in state.
function ruleIdFor(sites, key) {
  if (sites[key] && sites[key].ruleId) return sites[key].ruleId;
  const used = Object.values(sites).map(s => s.ruleId || 0);
  return Math.max(99, ...used) + 1;
}

async function pin(ruleId, host, repo, policy) {
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [ruleId],
    addRules: [{
      id: ruleId,
      priority: PINNED_PRIORITY,
      action: { type: 'modifyHeaders', responseHeaders: [{ header: 'Content-Security-Policy', operation: 'set', value: policy }] },
      condition: entryCondition(host, repo),
    }],
  });
}

async function unpin(ruleId) {
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId] });
}

// A tab's allow rules for backends: exactly the canisters the site it
// shows may call, one rule each, scoped to the tab. Replaced whenever the
// tab is given a verified site (the same site again included: the list
// may have changed), dropped when the tab shows anything else or closes.
// Only on icp-api.io, the host pages are expected to use: a call through
// another IC API host stays blocked, as in Firefox.
const ruleFor = id => '^https://icp-api\\.io/api/v[0-9]+/canister/' + escape(id) + '/';
const tabRules = (tabId, key, ids) => exclusive(async () => {
  const { backends = {} } = await chrome.storage.session.get('backends');
  const removeRuleIds = (backends[tabId] || { ruleIds: [] }).ruleIds;
  const used = new Set(Object.values(backends).flatMap(b => b.ruleIds));
  let next = BACKEND_RULE_BASE;
  const addRules = ids.map(id => {
    while (used.has(next) || removeRuleIds.includes(next)) next++;
    used.add(next);
    return {
      id: next, priority: PINNED_PRIORITY,
      action: { type: 'allow' },
      condition: { regexFilter: ruleFor(id), initiatorDomains: SITE_DOMAINS, resourceTypes: ['xmlhttprequest'], tabIds: [tabId] },
    };
  });
  if (ids.length) backends[tabId] = { site: key, ruleIds: addRules.map(r => r.id) };
  else delete backends[tabId];
  await chrome.storage.session.set({ backends });
  if (removeRuleIds.length || addRules.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds, addRules });
});

// --- verification ---
const inFlight = new Map();
// Updates to the stored sites run one at a time: two repos finishing together
// would otherwise take the same rule id and overwrite each other's entry.
let stateQueue = Promise.resolve();
const exclusive = fn => {
  const p = stateQueue.then(fn);
  stateQueue = p.catch(() => {});
  return p;
};

// Full check: registry record, served bytes, object walk, reference scan,
// the policy to pin, and the backends the page may call -- all as `host`
// serves the site. Concurrent callers for one site share one run.
function verifySite(host, repo) {
  const key = keyOf(host, repo);
  if (inFlight.has(key)) return inFlight.get(key);
  const run = (async () => {
    const opts = { repo, host, provider: twoRpcs, providerOnly: true, providerName: 'two RPCs' };
    const r = await Verifier.verify(opts);
    // The backends only matter for a page that will run: a page that failed
    // runs nothing, and its stop page should say why it failed, not what
    // its backend is.
    if (r.verified) {
      const be = await Verifier.checkBackends(repo, opts).catch(e => ({ ok: false, warning: '', backends: [], allowed: [],
        check: { id: 'G', ok: false, label: 'the canisters the page may call are approved or system canisters', detail: e.message || String(e) } }));
      r.checks.push(be.check);
      r.verified = be.ok;
      r.backends = be.backends;
      r.allowedBackends = be.allowed;
      r.warning = be.warning;
    }
    return exclusive(() => record(host, repo, r));
  })();
  inFlight.set(key, run);
  run.finally(() => inFlight.delete(key)).catch(() => {});
  return run;
}

// Pin (or unpin) what a full check found and store it.
async function record(host, repo, r) {
  const sites = await load();
  const key = keyOf(host, repo);
  const ruleId = ruleIdFor(sites, key);
  const site = {
    host, repo, ruleId, checkedAt: Date.now(),
    commit: r.record && r.record.commit, bundleHash: r.record && r.record.bundleHash,
    checks: r.checks, via: r.via, policyError: r.policyError || null,
    backends: r.backends || [], allowedBackends: r.allowedBackends || [], warning: r.warning || '',
  };
  if (r.verified && r.policy) {
    const was = sites[key];
    await pin(ruleId, host, repo, r.policy);
    site.status = 'verified';
    // A page loaded before this moment ran under an older rule (or none).
    site.pinnedAt = was && was.status === 'verified' && was.policy === r.policy ? was.pinnedAt : Date.now();
    site.policy = r.policy;
    // What the tab is given to show: the bytes just checked, as text.
    site.text = new TextDecoder().decode(r.bytes);
  } else {
    await unpin(ruleId);
    site.status = r.verified ? 'unpinnable' : 'failed';
  }
  sites[key] = site;
  await save(sites);
  return site;
}

// Quick check on every visit: is the entrypoint still the recorded bytes?
// If not -- a redeploy, a new record, or something rewriting the page on
// its way here -- run the full check again.
async function recheck(site) {
  try {
    const res = await fetch(siteUrl(site.host, site.repo), { cache: 'no-store', signal: AbortSignal.timeout(15_000) });
    const bytes = new Uint8Array(await res.arrayBuffer());
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), x => x.toString(16).padStart(2, '0')).join('');
    // Served from the site's host still: a redirect means it moved.
    if (res.ok && !res.redirected && hash === site.bundleHash) return site;
  } catch (_) { /* fall through to the full check */ }
  return verifySite(site.host, site.repo);
}

// --- tabs: what each one is showing ---
const allowedKey = (tabId, key) => tabId + ':' + key;

async function allowed(tabId, key) {
  const { allowed = {} } = await chrome.storage.session.get('allowed');
  return Boolean(allowed[allowedKey(tabId, key)]);
}

function badge(tabId, state, site) {
  // A verified page with a warning on its backends (ungoverned, or a stale
  // certificate): shown, and said in the core's words.
  if (state === 'verified' && site && site.warning) state = 'warned';
  const look = {
    verified: ['OK', '#1a7f37', 'verified at commit ' + (site && site.commit || '').slice(0, 12) + '; its backends are approved or system canisters'],
    warned: ['OK', '#b35c00', 'verified at commit ' + (site && site.commit || '').slice(0, 12) + ', but ' + (site && site.warning || '')],
    checking: ['...', '#6b6b6b', 'checking against its registry record'],
    failed: ['!', '#b3261e', 'NOT verified -- its scripts are blocked'],
    unpinnable: ['!', '#b3261e', 'verified, but its scripts cannot be pinned -- they are blocked'],
    allowed: ['!', '#b35c00', 'NOT verified -- running anyway, as you chose'],
    uncovered: ['', '#6b6b6b', 'this page is covered by no record; its scripts are blocked'],
  }[state];
  chrome.action.setBadgeText({ tabId, text: look[0] }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: look[1] }).catch(() => {});
  chrome.action.setTitle({ tabId, title: 'ic-git verifier: ' + (site ? site.repo + ' ' : '') + look[2] }).catch(() => {});
}

const tell = (tabId, msg) => chrome.tabs.sendMessage(tabId, msg).catch(() => {});

// A page under /site/ has started loading in `tabId` (its delivered bytes
// already dropped by main.js). Answer at once with what the tab should show,
// then check and tell the tab to reload if anything changes.
async function visit(tabId, href, navStart) {
  const at = siteOf(href);
  if (at === null) { badge(tabId, 'uncovered'); await tabRules(tabId, null, []); return { status: 'uncovered' }; }
  const { host, repo } = at, key = keyOf(host, repo);
  if (await allowed(tabId, key)) {
    // "Open anyway": the bytes as served now, unchecked, as the user chose.
    badge(tabId, 'allowed', { repo });
    const res = await fetch(siteUrl(host, repo), { cache: 'no-store' });
    return { status: 'allowed', text: await res.text() };
  }
  const sites = await load();
  const known = sites[key];

  const failSoft = e => {
    const site = { repo, status: 'failed', checks: [{ id: 'X', ok: false, label: 'check the site', detail: e.message || String(e) }] };
    badge(tabId, 'failed', site);
    tell(tabId, { type: 'result', status: 'failed', reload: false, site: summary(site) });
  };

  // Loaded under this site's pinned policy: show the cached checked bytes
  // now, and refresh behind them. A new record, or a page that no longer
  // verifies, reloads the tab, which then gets the new answer.
  if (known && known.status === 'verified' && known.pinnedAt <= navStart && known.text) {
    badge(tabId, 'verified', known);
    // This tab's calls: the site's judged backends, before the page runs.
    await tabRules(tabId, key, known.allowedBackends || []);
    const fresh = Date.now() - known.checkedAt < REFRESH_MINUTES * 60_000;
    (fresh ? recheck(known) : verifySite(host, repo)).then(async site => {
      if (site.status !== 'verified' || site.policy !== known.policy || site.bundleHash !== known.bundleHash) {
        tell(tabId, { type: 'result', status: site.status, reload: true, site: summary(site) });
      } else {
        if (site.warning !== known.warning) badge(tabId, 'verified', site);
        if (JSON.stringify(site.allowedBackends) !== JSON.stringify(known.allowedBackends)) await tabRules(tabId, key, site.allowedBackends || []);
      }
    }, failSoft);
    return { status: 'verified', text: known.text, site: summary(known) };
  }
  // First visit, a stale state, or one that did not verify: check again
  // now. Only a verified result is reused -- a failure may have been a
  // proxy that is since gone, or a record since republished, and the
  // check costs seconds. Then reload under the pinned policy (this load's
  // policy is the static one, which would refuse the verified scripts
  // too), or stop.
  badge(tabId, 'checking', { repo });
  await tabRules(tabId, null, []);
  verifySite(host, repo).then(async site => {
    const reload = site.status === 'verified';
    // The tab's rules before the reload: its first call is already allowed.
    if (reload) await tabRules(tabId, key, site.allowedBackends || []);
    badge(tabId, reload ? 'checking' : site.status, site);
    tell(tabId, { type: 'result', status: site.status, reload, site: summary(site) });
  }, failSoft);
  return { status: 'checking', site: { repo } };
}

// What the page needs to draw, and nothing it could misuse.
const summary = site => ({
  repo: site.repo, commit: site.commit || null, checks: site.checks || [],
  via: site.via || null, policyError: site.policyError || null,
  backends: site.backends || [], warning: site.warning || '',
});

// "Open anyway": run this tab's copy of the site without the pinned
// policy, until the tab closes. Behind a deliberate second click in the
// page; recorded so the badge keeps saying so.
// Its rule ids and stored entries go through the same queue as the sites':
// two tabs allowed together would otherwise take the same id.
const allow = (tabId, host, repo) => exclusive(async () => {
  const { allowed = {} } = await chrome.storage.session.get('allowed');
  const key = allowedKey(tabId, keyOf(host, repo));
  const id = allowed[key] || Math.max(ALLOW_BASE, ...Object.values(allowed)) + 1;
  allowed[key] = id;
  await chrome.storage.session.set({ allowed });
  // Its calls too: a page run unverified is run as it is, backends included.
  const calls = id - ALLOW_BASE + TAB_CALLS_BASE;
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [id, calls],
    addRules: [{
      id, priority: ALLOW_PRIORITY,
      action: { type: 'modifyHeaders', responseHeaders: [{ header: 'Content-Security-Policy', operation: 'remove' }] },
      condition: { ...entryCondition(host, repo), tabIds: [tabId] },
    }, {
      id: calls, priority: ALLOW_PRIORITY,
      action: { type: 'allow' },
      condition: { regexFilter: API_HOSTS, initiatorDomains: SITE_DOMAINS, resourceTypes: ['xmlhttprequest'], tabIds: [tabId] },
    }],
  });
});

chrome.tabs.onRemoved.addListener(tabId => {
  tabRules(tabId, null, []);
  return exclusive(async () => {
    const { allowed = {} } = await chrome.storage.session.get('allowed');
    const gone = Object.keys(allowed).filter(k => k.startsWith(tabId + ':'));
    if (!gone.length) return;
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: gone.flatMap(k => [allowed[k], allowed[k] - ALLOW_BASE + TAB_CALLS_BASE]) });
    for (const k of gone) delete allowed[k];
    await chrome.storage.session.set({ allowed });
  });
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const tabId = sender.tab && sender.tab.id;
  if (tabId === undefined) return false;
  // A visit names its site by URL; the other messages name a repo, on the
  // host of the page that sends them.
  const at = siteOf(msg.type === 'visit' ? msg.url : sender.url);
  const here = at && (msg.type === 'visit' || at.repo === msg.repo) ? at : null;
  const work = msg.type === 'visit' ? visit(tabId, msg.url, msg.navStart)
    : !here ? Promise.reject(new Error('this page is no site\'s entrypoint'))
    : msg.type === 'allow' ? allow(tabId, here.host, here.repo).then(() => ({ ok: true }))
    : msg.type === 'retry' ? verifySite(here.host, here.repo).then(site => ({ status: site.status, site: summary(site) }))
    : Promise.resolve({ error: 'unknown message' });
  const repo = msg.repo || (at && at.repo) || undefined;
  work.then(reply, e => reply({ status: 'failed', site: { repo, checks: [{ id: 'X', ok: false, label: 'check the site', detail: e.message }] } }));
  return true;
});

// Keep what is pinned current: a republished record or a redeploy changes
// the policy, and the next visit should not be the one to find out.
// Created once: this runs on every worker start, and creating it again
// would restart its period, so a worker woken by visits would never refresh.
chrome.alarms.get('refresh').then(a => { if (!a) chrome.alarms.create('refresh', { periodInMinutes: REFRESH_MINUTES }); });
chrome.alarms.onAlarm.addListener(async alarm => {
  if (alarm.name !== 'refresh') return;
  for (const site of Object.values(await load())) await verifySite(site.host, site.repo).catch(() => {});
});
