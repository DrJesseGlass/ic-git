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
//     dot, a port) blocked, and the domain blocked in a frame or an object
//     -- while its entrypoint, and other names, load.
// The rules are read as the browsers read them: a regexFilter is matched as
// a regular expression (the rules use only what RE2 and JavaScript share),
// a urlFilter starting with "|" as a prefix.
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

// Whether a static rule applies to a request of `type` for `url`.
const applies = (rule, url, type) => {
  const c = rule.condition;
  if (!(c.resourceTypes || []).includes(type)) return false;
  const host = new URL(url).hostname;
  const under = (h, list) => (list || []).some(x => h === x || h.endsWith('.' + x));
  if (c.requestDomains && !under(host, c.requestDomains)) return false;
  if (c.excludedRequestDomains && under(host, c.excludedRequestDomains)) return false;
  if (c.regexFilter) return new RegExp(c.regexFilter).test(url);
  if (c.urlFilter && c.urlFilter.startsWith('|')) return url.startsWith(c.urlFilter.slice(1));
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
    for (const url of ['https://www.' + d + '/', 'https://' + d + '.example/', 'https://x' + d + '/', 'https://example.com/' + d + '/']) {
      for (const type of ['main_frame', 'sub_frame', 'object']) assert.ok(!blocked(rules, url, type), pkg + ': ' + url + ' (' + type + ') blocked');
      assert.ok(!upgraded(rules, url.replace('https:', 'http:'), 'main_frame'), pkg + ': ' + url + ' upgraded');
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
    for (const url of ['https://' + d + '/', 'https://' + d + '/x.html', 'https://u@' + d + '/', 'https://' + d + './', 'http://' + d + '/', 'https://' + d + ':8443/', 'https://' + d + '?x', 'https://' + d + '#y']) {
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

console.log('\nall passed');
