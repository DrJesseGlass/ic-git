// ic-git verifier -- content script, at document_start on /site/ pages.
//
// main.js (the page's world) has already dropped the delivered response.
// This asks the background what the tab should show and writes it: on a
// verified site, the checked bytes, which then run under the pinned
// policy; otherwise a bare document with a neutral "checking" screen
// while the first check runs, followed by a reload under the pinned policy
// or the stop page. Nothing the network delivered is parsed, and no script
// runs under the checking screen or the stop page, so nothing can remove
// them.
(() => {
  'use strict';
  // When this navigation began, on the clock the background pins by. Not
  // performance.timeOrigin: after the system has slept it can lag
  // Date.now() by minutes, and a load that began after the pin would then
  // look older than it, and be reloaded again and again.
  const navStart = Date.now() - performance.now();
  let root = null;
  let repo = null; // the site this page is, once the background has said

  const CSS = `
    :host { all: initial; }
    .veil { position: fixed; inset: 0; z-index: 2147483647; overflow: auto;
      background: #fafaf8; color: #1c1c1c;
      font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
    @media (prefers-color-scheme: dark) { .veil { background: #161615; color: #e6e4dd; } }
    .box { max-width: 40rem; margin: 0 auto; padding: 3rem 1.25rem; }
    h1 { font-size: 1.15rem; margin: 0 0 .4rem; }
    p { margin: .4rem 0; }
    .muted { opacity: .7; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .86em; }
    ul { list-style: none; padding: 0; margin: 1rem 0; }
    li { padding: .45rem 0; border-top: 1px solid rgba(128,128,128,.3); display: grid; grid-template-columns: 3.2rem 1fr; }
    li .d { grid-column: 2; opacity: .7; font-size: .85rem; overflow-wrap: anywhere; }
    .pass { color: #1a7f37; font-weight: 600; } .fail { color: #b3261e; font-weight: 600; }
    .stop h1 { color: #b3261e; }
    .actions { display: flex; gap: .6rem; flex-wrap: wrap; margin-top: 1.2rem; }
    button { font: inherit; padding: .4rem .9rem; border: 1px solid rgba(128,128,128,.5); border-radius: 6px;
      background: transparent; color: inherit; cursor: pointer; }
    button.risk { border-color: #b3261e; color: #b3261e; }
  `;

  function veil() {
    if (root) return root;
    const host = document.createElement('ic-git-verifier');
    const shadow = host.attachShadow({ mode: 'closed' });
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
    shadow.adoptedStyleSheets = [sheet];
    const div = document.createElement('div');
    div.className = 'veil';
    shadow.append(div);
    (document.documentElement || document).append(host);
    root = { host, div };
    return root;
  }
  // The one write main.js accepts: the document the tab shows.
  const write = text => document.dispatchEvent(new CustomEvent('ic-git-verifier:write', { detail: text }));
  const BARE = '<!doctype html><html><head><meta charset="utf-8"><title>ic-git verifier</title></head><body></body></html>';

  // Built with DOM calls, never innerHTML: check details come from the
  // network (served hashes, error text) and are shown as text only.
  const el = (tag, props = {}, ...kids) => {
    const e = document.createElement(tag);
    Object.assign(e, props);
    e.append(...kids);
    return e;
  };

  function checking(repo) {
    const { div } = veil();
    div.replaceChildren(el('div', { className: 'box' },
      el('h1', { textContent: 'Checking ' + repo }),
      el('p', { className: 'muted', textContent: 'Comparing this page with its record on chain before any of its code runs. This takes a few seconds, once.' })));
  }

  function stop(status, site) {
    const { div } = veil();
    const title = status === 'unpinnable' ? 'Stopped: this page cannot be protected'
      : status === 'uncovered' ? 'Stopped: no record covers this page'
      : 'Stopped: this page is not verified';
    const why = status === 'unpinnable'
      ? 'It matches its record, but its scripts cannot be pinned (' + (site.policyError || 'unknown reason') + '), so they have been blocked.'
      : status === 'uncovered'
        ? 'Records cover a site\'s entry page only. This page\'s scripts have been blocked.'
        : 'What was served does not match what the record attests, so its scripts have been blocked. Nothing on this page can act for you, including through your wallet.';
    const rows = (site.checks || []).map(c => el('li', {},
      el('span', { className: c.ok ? 'pass' : 'fail', textContent: c.ok ? 'PASS' : 'FAIL' }),
      el('span', { textContent: c.label }),
      ...(c.detail ? [el('span', { className: 'd', textContent: c.detail })] : [])));
    const again = el('button', { textContent: 'Check again' });
    const anyway = el('button', { className: 'risk', textContent: 'Open anyway' });
    let armed = false;
    again.onclick = () => {
      // No repo (an uncovered page, or no answer from the verifier): the
      // only check there is to run again is the visit itself.
      if (!site.repo) { location.reload(); return; }
      checking(site.repo);
      chrome.runtime.sendMessage({ type: 'retry', repo: site.repo }, res => {
        if (res && res.status === 'verified') location.reload(); else stop(res ? res.status : 'failed', res ? res.site : site);
      });
    };
    anyway.onclick = () => {
      if (!armed) { armed = true; anyway.textContent = 'Click again to run code that was not verified'; return; }
      chrome.runtime.sendMessage({ type: 'allow', repo: site.repo }, () => location.reload());
    };
    div.replaceChildren(el('div', { className: 'box stop' },
      el('h1', { textContent: title }),
      el('p', { textContent: why }),
      el('p', { className: 'muted' },
        document.createTextNode('Site '), el('span', { className: 'mono', textContent: site.repo || location.pathname }),
        ...(site.commit ? [document.createTextNode(', record at commit '), el('span', { className: 'mono', textContent: site.commit.slice(0, 12) })] : []),
        ...(site.via ? [document.createTextNode(', read via ' + site.via)] : [])),
      ...(rows.length ? [el('ul', {}, ...rows)] : []),
      el('div', { className: 'actions' }, again, ...(site.repo ? [anyway] : []))));
  }

  // Later news for this tab, after the page is written.
  chrome.runtime.onMessage.addListener(msg => {
    if (!msg || msg.type !== 'result') return;
    // The tab may have moved on to another site since the check began.
    if (!msg.site || msg.site.repo !== repo) return;
    if (msg.reload) location.reload();
    else if (msg.status !== 'verified') stop(msg.status, msg.site || {});
  });
  chrome.runtime.sendMessage({ type: 'visit', url: location.href.split('#')[0], navStart }, res => {
    if (chrome.runtime.lastError || !res) {
      write(BARE);
      stop('failed', { checks: [{ ok: false, label: 'reach the verifier', detail: chrome.runtime.lastError ? chrome.runtime.lastError.message : 'no answer' }] });
      return;
    }
    repo = res.site && res.site.repo || null;
    if ((res.status === 'verified' || res.status === 'allowed') && typeof res.text === 'string') { write(res.text); return; }
    write(BARE);
    if (res.status === 'checking') checking(res.site.repo);
    else stop(res.status, res.site || {});
  });
})();
