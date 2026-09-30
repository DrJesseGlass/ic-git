// ic-git verifier -- background worker. Design: docs/EXTENSION.md.
//
// Two layers, each enough to stop injected code on its own:
//
// - The page the tab shows is never the one the network delivered. main.js
//   aborts the delivered response at document_start, and the content
//   script writes in the bytes this worker checked against the registry
//   record (cached here, so a verified page needs no network at all), or a
//   bare document under the stop page.
// - Every page under /site/ on the ic-git canister is covered by the static
//   rule in rules.json: a Content-Security-Policy that runs no script. Once
//   a site's entrypoint verifies, this worker installs a higher-priority
//   session rule that replaces it with the policy derivePolicy pins for the
//   verified page: its own scripts and styles, nothing else. The written
//   document keeps that policy.
importScripts('verifier.js');

const CANISTER = Verifier.DEFAULTS.canister;
const ORIGIN = 'https://' + CANISTER + '.raw.icp0.io';
// The registry is read through both; they must return the same answer.
const RPCS = ['https://ethereum-sepolia-rpc.publicnode.com', 'https://sepolia.gateway.tenderly.co'];
const REFRESH_MINUTES = 10;
const PINNED_PRIORITY = 2, ALLOW_PRIORITY = 3;

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
// index.html, with any query. Other paths under /site/ are covered by no
// record and keep the static policy.
const escape = s => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const entryRegex = repo => '^' + escape(ORIGIN + '/site/' + encodeURIComponent(repo) + '/') + '(index\\.html)?(\\?[^#]*)?$';

// Which site a URL is the entrypoint of, or null.
function siteOf(href) {
  const u = new URL(href);
  if (u.origin !== ORIGIN) return null;
  const m = /^\/site\/([^/]+)\/(index\.html)?$/.exec(u.pathname);
  return m ? decodeURIComponent(m[1]) : null;
}

// Session rule ids: one per repo, from 100 up, remembered in state.
async function ruleIdFor(sites, repo) {
  if (sites[repo] && sites[repo].ruleId) return sites[repo].ruleId;
  const used = Object.values(sites).map(s => s.ruleId || 0);
  return Math.max(99, ...used) + 1;
}

async function pin(ruleId, repo, policy) {
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [ruleId],
    addRules: [{
      id: ruleId,
      priority: PINNED_PRIORITY,
      action: { type: 'modifyHeaders', responseHeaders: [{ header: 'Content-Security-Policy', operation: 'set', value: policy }] },
      condition: { regexFilter: entryRegex(repo), resourceTypes: ['main_frame'] },
    }],
  });
}

async function unpin(ruleId) {
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId] });
}

// --- verification ---
const inFlight = new Map();

// Full check: registry record, served bytes, object walk, reference scan,
// and the policy to pin. Concurrent callers for one repo share one run.
function verifySite(repo) {
  if (inFlight.has(repo)) return inFlight.get(repo);
  const run = (async () => {
    const r = await Verifier.verify({ repo, provider: twoRpcs, providerOnly: true, providerName: 'two RPCs' });
    const sites = await load();
    const ruleId = await ruleIdFor(sites, repo);
    const site = {
      repo, ruleId, checkedAt: Date.now(),
      commit: r.record && r.record.commit, bundleHash: r.record && r.record.bundleHash,
      checks: r.checks, via: r.via, policyError: r.policyError || null,
    };
    if (r.verified && r.policy) {
      const was = sites[repo];
      await pin(ruleId, repo, r.policy);
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
    sites[repo] = site;
    await save(sites);
    return site;
  })();
  inFlight.set(repo, run);
  run.finally(() => inFlight.delete(repo));
  return run;
}

// Quick check on every visit: is the entrypoint still the recorded bytes?
// If not -- a redeploy, a new record, or something rewriting the page on
// its way here -- run the full check again.
async function recheck(site) {
  try {
    const res = await fetch(ORIGIN + '/site/' + encodeURIComponent(site.repo) + '/', { cache: 'no-store', signal: AbortSignal.timeout(15_000) });
    const bytes = new Uint8Array(await res.arrayBuffer());
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), x => x.toString(16).padStart(2, '0')).join('');
    if (res.ok && hash === site.bundleHash) return site;
  } catch (_) { /* fall through to the full check */ }
  return verifySite(site.repo);
}

// --- tabs: what each one is showing ---
const allowedKey = (tabId, repo) => tabId + ':' + repo;

async function allowed(tabId, repo) {
  const { allowed = {} } = await chrome.storage.session.get('allowed');
  return Boolean(allowed[allowedKey(tabId, repo)]);
}

function badge(tabId, state, site) {
  const look = {
    verified: ['OK', '#1a7f37', 'verified at commit ' + (site && site.commit || '').slice(0, 12)],
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
  const repo = siteOf(href);
  if (repo === null) { badge(tabId, 'uncovered'); return { status: 'uncovered' }; }
  if (await allowed(tabId, repo)) {
    // "Open anyway": the bytes as served now, unchecked, as the user chose.
    badge(tabId, 'allowed', { repo });
    const res = await fetch(ORIGIN + '/site/' + encodeURIComponent(repo) + '/', { cache: 'no-store' });
    return { status: 'allowed', text: await res.text() };
  }
  const sites = await load();
  const known = sites[repo];
  const fresh = known && Date.now() - known.checkedAt < REFRESH_MINUTES * 60_000;

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
    (fresh ? recheck(known) : verifySite(repo)).then(site => {
      if (site.status !== 'verified' || site.policy !== known.policy || site.bundleHash !== known.bundleHash) {
        tell(tabId, { type: 'result', status: site.status, reload: true, site: summary(site) });
      }
    }, failSoft);
    return { status: 'verified', text: known.text, site: summary(known) };
  }
  if (known && fresh && known.status !== 'verified') {
    badge(tabId, known.status, known);
    return { status: known.status, site: summary(known) };
  }
  // First visit, or a stale or unpinned state: check, then reload under
  // the pinned policy (this load's policy is the static one, which would
  // refuse the verified scripts too), or stop.
  badge(tabId, 'checking', { repo });
  verifySite(repo).then(site => {
    const reload = site.status === 'verified';
    badge(tabId, reload ? 'checking' : site.status, site);
    tell(tabId, { type: 'result', status: site.status, reload, site: summary(site) });
  }, failSoft);
  return { status: 'checking', site: { repo } };
}

// What the page needs to draw, and nothing it could misuse.
const summary = site => ({
  repo: site.repo, commit: site.commit || null, checks: site.checks || [],
  via: site.via || null, policyError: site.policyError || null,
});

// "Open anyway": run this tab's copy of the site without the pinned
// policy, until the tab closes. Behind a deliberate second click in the
// page; recorded so the badge keeps saying so.
async function allow(tabId, repo) {
  const { allowed = {} } = await chrome.storage.session.get('allowed');
  const id = Math.max(50_000, ...Object.values(allowed)) + 1;
  allowed[allowedKey(tabId, repo)] = id;
  await chrome.storage.session.set({ allowed });
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [id],
    addRules: [{
      id, priority: ALLOW_PRIORITY,
      action: { type: 'modifyHeaders', responseHeaders: [{ header: 'Content-Security-Policy', operation: 'remove' }] },
      condition: { regexFilter: entryRegex(repo), resourceTypes: ['main_frame'], tabIds: [tabId] },
    }],
  });
}

chrome.tabs.onRemoved.addListener(async tabId => {
  const { allowed = {} } = await chrome.storage.session.get('allowed');
  const gone = Object.keys(allowed).filter(k => k.startsWith(tabId + ':'));
  if (!gone.length) return;
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: gone.map(k => allowed[k]) });
  for (const k of gone) delete allowed[k];
  await chrome.storage.session.set({ allowed });
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const tabId = sender.tab && sender.tab.id;
  if (tabId === undefined) return false;
  const work = msg.type === 'visit' ? visit(tabId, msg.url, msg.navStart)
    : msg.type === 'allow' ? allow(tabId, msg.repo).then(() => ({ ok: true }))
    : msg.type === 'retry' ? verifySite(msg.repo).then(site => ({ status: site.status, site: summary(site) }))
    : Promise.resolve({ error: 'unknown message' });
  work.then(reply, e => reply({ status: 'failed', site: { repo: msg.repo, checks: [{ id: 'X', ok: false, label: 'check the site', detail: e.message }] } }));
  return true;
});

// Keep what is pinned current: a republished record or a redeploy changes
// the policy, and the next visit should not be the one to find out.
chrome.alarms.create('refresh', { periodInMinutes: REFRESH_MINUTES });
chrome.alarms.onAlarm.addListener(async alarm => {
  if (alarm.name !== 'refresh') return;
  for (const repo of Object.keys(await load())) await verifySite(repo).catch(() => {});
});
