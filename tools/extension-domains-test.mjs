#!/usr/bin/env node
// Holds both extension packages to the domains the core pins
// (core/verifier.js, Verifier.DEFAULTS.domains), offline:
//   - each domain is a DNS name, and the console's home (browser/index.html,
//     Routes.HOME) is the one pinned to the ic-git repo;
//   - each package may act on each domain (host_permissions), runs its
//     content scripts on every page there, and its worker reads the list
//     from the core, not a copy of its own;
//   - each package's static rules cover each domain as they cover the
//     checked hosts: Chrome's no-script policy and HTML type on every page
//     there, and its IC API block for pages there; in both, http upgraded
//     to https, the domain spelled as another origin (the root's trailing
//     dot, a port) blocked, its subdomains blocked, and the domain blocked
//     in a frame or an object -- while its entrypoint, and other names,
//     load;
//   - the response headers that act after a page is checked are stripped
//     from every covered page, by Chrome's static rules and by Firefox's
//     listener alike;
//   - each worker's own siteOf, run here, takes exactly the entrypoints
//     its rules pin (Chrome's entryRegex), a user name in the URL
//     included, and Firefox holds every page at each domain.
// The rules are read as the browsers read them: a regexFilter is matched as
// a regular expression (the rules use only what RE2 and JavaScript share),
// case-insensitively unless the rule says otherwise, against the URL as
// the browser presents it; a urlFilter starting with "|" as a prefix.
//
//   node tools/extension-domains-test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = p => readFileSync(new URL(p, import.meta.url), 'utf8');
const Verifier = new Function(read('../core/verifier.js') + '\nreturn Verifier;')();
const DOMAINS = Object.entries(Verifier.DEFAULTS.domains);
assert.ok(DOMAINS.length > 0, 'the core pins no domain');

for (const [d, repo] of DOMAINS) {
  assert.match(d, /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/, d + ' is not a DNS name as a gateway sends it');
  assert.equal(typeof repo, 'string', d);
}
const home = /const HOME = '([^']+)';/.exec(read('../browser/index.html'));
assert.ok(home, 'browser/index.html Routes.HOME not found');
assert.deepEqual(DOMAINS.filter(([, r]) => r === 'ic-git').map(([d]) => 'https://' + d), [home[1]], 'the console\'s home is not the domain the core pins to ic-git');
console.log('PASS  the core pins ' + DOMAINS.map(([d, r]) => d + ' -> ' + r).join(', ') + '; the console\'s home is the one pinned to ic-git');

// A URL as a browser presents it to the rules: parsed and serialized.
const canon = url => new URL(url).href;
// Whether a static rule applies to a request of `type` for `url`, the rule
// naming the types it applies to or those it does not.
const appliesAny = (rule, url, type) => {
  const c = rule.condition;
  if (c.resourceTypes) return applies(rule, url, type);
  if ((c.excludedResourceTypes || []).includes(type)) return false;
  return applies({ ...rule, condition: { ...c, resourceTypes: [type] } }, url, type);
};
// Whether a static rule applies to a request of `type` for `url`.
const applies = (rule, url, type) => {
  const c = rule.condition;
  url = canon(url);
  if (!(c.resourceTypes || []).includes(type)) return false;
  const host = new URL(url).hostname;
  const under = (h, list) => (list || []).some(x => h === x || h.endsWith('.' + x));
  if (c.requestDomains && !under(host, c.requestDomains)) return false;
  if (c.excludedRequestDomains && under(host, c.excludedRequestDomains)) return false;
  if (c.regexFilter) return new RegExp(c.regexFilter, c.isUrlFilterCaseSensitive ? '' : 'i').test(url);
  if (c.urlFilter && c.urlFilter.startsWith('|')) return c.isUrlFilterCaseSensitive ? url.startsWith(c.urlFilter.slice(1)) : url.toLowerCase().startsWith(c.urlFilter.slice(1).toLowerCase());
  throw new Error('rule ' + rule.id + ': a condition this test does not read');
};
const blocked = (rules, url, type) => rules.some(r => r.action.type === 'block' && applies(r, url, type));
const upgraded = (rules, url, type) => rules.some(r => r.action.type === 'upgradeScheme' && applies(r, url, type));

for (const pkg of ['extension', 'extension-firefox']) {
  const manifest = JSON.parse(read('../' + pkg + '/manifest.json'));
  const rules = JSON.parse(read('../' + pkg + '/rules.json'));
  const worker = read('../' + pkg + '/background.js');
  assert.match(worker, /Object\.entries\(Verifier\.DEFAULTS\.domains\)/, pkg + '/background.js does not read the core\'s domains');
  for (const [d] of DOMAINS) {
    assert.ok(!worker.includes(d), pkg + '/background.js names ' + d + ' itself');
    assert.ok(manifest.host_permissions.includes('https://' + d + '/*'), pkg + ': no host permission for ' + d);
    for (const cs of manifest.content_scripts) assert.ok(cs.matches.includes('https://' + d + '/*'), pkg + ': ' + cs.js + ' does not run at ' + d);

    // The entrypoint and every page at the domain load; another name does
    // not take the domain's rules.
    for (const url of ['https://' + d + '/', 'https://' + d + '/index.html?x=1#/r', 'https://' + d + '/other.html']) {
      assert.ok(!blocked(rules, url, 'main_frame'), pkg + ': ' + url + ' blocked');
    }
    for (const url of ['https://' + d + '.example/', 'https://x' + d + '/', 'https://example.com/' + d + '/', 'https://example.com/?u=www.' + d]) {
      for (const type of ['main_frame', 'sub_frame', 'object']) assert.ok(!blocked(rules, url, type), pkg + ': ' + url + ' (' + type + ') blocked');
      assert.ok(!upgraded(rules, url.replace('https:', 'http:'), 'main_frame'), pkg + ': ' + url + ' upgraded');
    }
    // Its subdomains: the same DNS, so whoever answers at the domain answers
    // there, and nothing of the extension runs there.
    for (const url of ['https://www.' + d + '/', 'https://a.b.' + d + '/x', 'http://www.' + d + '/', 'https://u@www.' + d + '/', 'https://www.' + d + '.:8443/']) {
      for (const type of ['main_frame', 'sub_frame']) assert.ok(blocked(rules, url, type), pkg + ': ' + url + ' (' + type + ') not blocked');
    }
    // Over http: asked for over https.
    for (const url of ['http://' + d + '/', 'http://' + d + '/x?y', 'http://u@' + d + '/']) {
      assert.ok(upgraded(rules, url, 'main_frame'), pkg + ': ' + url + ' not upgraded');
    }
    // Spelled as another origin: with the root's dot, or at a port.
    for (const url of ['https://' + d + './', 'https://' + d + ':8443/', 'https://' + d + '.:8443/x', 'https://u@' + d + './', 'http://' + d + './']) {
      assert.ok(blocked(rules, url, 'main_frame'), pkg + ': ' + url + ' not blocked');
    }
    // In a frame or an object of anyone's page, however spelled.
    for (const url of ['https://' + d + '/', 'https://' + d + '/x.html', 'https://u@' + d + '/', 'https://' + d + './', 'http://' + d + '/', 'https://' + d + ':8443/', 'https://' + d + '/?x', 'https://' + d + '/#y', 'https://IC-GIT.COM/'.replace('IC-GIT.COM', d.toUpperCase())]) {
      for (const type of ['sub_frame', 'object']) assert.ok(blocked(rules, url, type), pkg + ': ' + url + ' (' + type + ') not blocked');
    }
  }
  console.log('PASS  ' + pkg + ': permissions, content scripts and static rules cover every pinned domain, and only those names');
}

// Chrome's rules hold the page's policy: no script on any page at the
// domain until the worker pins the verified one, typed as UTF-8 HTML, and
// no call to the IC's API from a page there but those the worker allows.
{
  const rules = JSON.parse(read('../extension/rules.json'));
  const policy = r => r.action.type === 'modifyHeaders' && (r.action.responseHeaders || []).some(h => h.header === 'Content-Security-Policy' && h.operation === 'set' && /^script-src 'none'/.test(h.value))
    && (r.action.responseHeaders || []).some(h => h.header === 'Content-Type' && h.value === 'text/html; charset=utf-8');
  const api = rules.find(r => r.action.type === 'block' && /\/api\/v\[0-9\]\+\//.test(r.condition.regexFilter || ''));
  assert.ok(api, 'no IC API block rule');
  for (const [d] of DOMAINS) {
    for (const url of ['https://' + d + '/', 'https://' + d + '/index.html', 'https://' + d + '/other.html', 'https://u@' + d + '/']) {
      assert.ok(rules.some(r => policy(r) && applies(r, url, 'main_frame')), 'extension: ' + url + ' has no static policy');
    }
    assert.ok(api.condition.initiatorDomains.includes(d), 'extension: calls from ' + d + ' to the IC\'s API are not blocked');
  }
  console.log('PASS  extension: every page at a pinned domain gets the no-script policy and the HTML type, and its IC API calls are blocked');
}

// The headers that act after a page is checked: stripped from every page
// the no-script policy covers (Chrome), and in Firefox's listener, alike;
// and from every other response at a pinned domain, which the domain
// answers too.
const STRIP = ['refresh', 'link', 'speculation-rules', 'set-cookie', 'clear-site-data', 'nel', 'report-to', 'reporting-endpoints', 'content-disposition'];
const TYPES = ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'];
{
  const rules = JSON.parse(read('../extension/rules.json'));
  const strips = r => r.action.type === 'modifyHeaders' && (r.action.responseHeaders || []).some(h => h.operation === 'remove');
  for (const r of rules.filter(strips)) {
    const removed = r.action.responseHeaders.filter(h => h.operation === 'remove').map(h => h.header.toLowerCase());
    assert.deepEqual([...removed].sort(), [...STRIP].sort(), 'extension rule ' + r.id + ' strips ' + removed);
  }
  // Chrome: every page under /site/ on both hosts, and every response of
  // every type at each domain, from a rule that strips.
  const covered = (url, type) => rules.some(r => strips(r) && appliesAny(r, url, type));
  for (const h of [Verifier.DEFAULTS.canister, Verifier.DEFAULTS.git]) assert.ok(covered('https://' + h + '.raw.icp0.io/site/x/', 'main_frame'), 'extension: no strip on ' + h);
  for (const d of Object.keys(Verifier.DEFAULTS.domains)) {
    for (const type of TYPES) for (const url of ['https://' + d + '/', 'https://' + d + '/api/x?y', 'https://u@' + d + '/z.png']) {
      assert.ok(covered(url, type), 'extension: ' + url + ' (' + type + ') keeps its headers');
    }
  }
  // Firefox: its page listener drops STRIP, and a second listener drops it
  // from every other response at each domain.
  const ff = read('../extension-firefox/background.js');
  const listed = /const STRIP = (\[[^\]]*\]);/.exec(ff);
  assert.ok(listed, 'extension-firefox/background.js STRIP not found');
  assert.deepEqual([...JSON.parse(listed[1].replace(/'/g, '"'))].sort(), [...STRIP].sort(), 'Firefox strips another list');
  assert.match(ff, /\['content-security-policy', 'content-type', \.\.\.STRIP\]\.includes\(h\.name\.toLowerCase\(\)\)/, 'Firefox pages keep the headers');
  assert.match(ff, /responseHeaders: d\.responseHeaders\.filter\(h => !STRIP\.includes\(h\.name\.toLowerCase\(\)\)\) \};\n\}, DOMAIN_FILTER, \['blocking', 'responseHeaders'\]\);/, 'Firefox: no strip on a domain\'s other responses');
  console.log('PASS  both packages strip ' + STRIP.join(', ') + ' from every covered page and every response at each domain');
}

// Each worker's own siteOf, run here with the core's pins, against its
// rules: a page it takes for an entrypoint is one Chrome pins the policy
// on, and Firefox holds every page at each domain.
{
  const run = (file, end, names) => {
    const src = read(file);
    const a = src.indexOf('const HOSTS'), b = src.indexOf(end);
    assert.ok(a >= 0 && b > a, file + ': the definitions');
    return new Function('Verifier', 'chrome', 'browser', src.slice(a, b) + '\nreturn { ' + names.join(', ') + ' };')(Verifier, {}, { permissions: { contains: async () => true, onAdded: { addListener() {} }, onRemoved: { addListener() {} } }, action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {} } });
  };
  const chrome = run('../extension/background.js', '// Session rule ids: one per site', ['siteOf', 'entryRegex']);
  const firefox = run('../extension-firefox/background.js', '// --- state', ['siteOf', 'FILTER']);
  const git = Verifier.DEFAULTS.git;
  for (const [d, repo] of DOMAINS) {
    const pin = new RegExp(chrome.entryRegex(git, repo));
    const entry = ['https://' + d + '/', 'https://' + d + '/index.html', 'https://' + d + '/?x=1#/r', 'https://u@' + d + '/', 'https://u:p@' + d + '/index.html#x', 'https://' + d.toUpperCase() + '/'];
    const other = ['https://' + d + '/x.html', 'https://' + d + '//', 'https://' + d + '/index.htm', 'https://' + d + '/site/' + repo + '/', 'https://www.' + d + '/', 'https://' + d + ':8443/'];
    for (const url of [...entry, ...other]) {
      const u = canon(url), isEntry = entry.includes(url);
      for (const [name, w] of [['extension', chrome], ['extension-firefox', firefox]]) {
        const at = w.siteOf(u);
        assert.equal(Boolean(at), isEntry, name + ' siteOf(' + u + ')');
        if (at) assert.deepEqual([at.host, at.repo, at.domain], [git, repo, d], name + ' siteOf(' + u + ')');
      }
      assert.equal(pin.test(u), isEntry, 'extension entryRegex on ' + u);
    }
    assert.ok(firefox.FILTER.urls.includes('https://' + d + '/*'), 'extension-firefox holds no page at ' + d);
    // The canister host's entrypoint, with a user name too.
    for (const url of ['https://' + git + '.raw.icp0.io/site/' + repo + '/', 'https://u@' + git + '.raw.icp0.io/site/' + repo + '/index.html?q#f']) {
      assert.ok(pin.test(canon(url)) && chrome.siteOf(canon(url)) && !chrome.siteOf(canon(url)).domain, 'extension on ' + url);
    }
  }
  console.log('PASS  each worker\'s siteOf takes exactly the entrypoints Chrome pins, a user name included; Firefox holds every page at each domain');
}

console.log('\nall passed');
