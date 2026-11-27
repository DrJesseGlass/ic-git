# The verifier extensions

Two browser extensions check every page they open on an ic-git canister's
sites against the page's registry record, before anything on it runs, and
stop the page if it is not the recorded one. They check the page where it
is, on its own origin, so wallets and sign-in work as on the live site --
which the loader (docs/LOADER.md), running the page on the loader's
origin, cannot offer. This is the F2 rung of VISION.md.

- `extension/` -- Chrome (Manifest V3).
- `extension-firefox/` -- Firefox (Manifest V3). The stronger of the two;
  recommended where the guarantee matters most (operators, observers).

Scope: pages under `/site/` on `umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io`
(ic-git) and `34koz-jyaaa-aaaab-ahejq-cai.raw.icp0.io` (its git canister),
which covers the console (`ic-git`) and ic-vote. Nothing to do when a page
verifies; an unmissable stop when it does not.

Two hosts because of the canister split (docs/CANISTER_SPLIT.md): ic-git
serves the sites until the cut, the git canister after, and ic-git then
answers a site's old URL with a permanent redirect to the git canister. A
site is a repo on one host, checked as that host serves it -- the core's
`verify` with `host`, which fails a page that host only redirects -- and
its objects are read from that host. With no host (the loader), `verify`
fetches ic-git's URL and takes the host from where the page came from, one
of the two pinned ids or the check fails. Both ids are pinned in the core
(`DEFAULTS.canister`, `DEFAULTS.git`); a redirect cannot add a third.

## What it checks

The shared verification core (`core/verifier.js`, the same code the
loader runs): the `<repo>#site` record from the registry, read through
two public RPC endpoints that must agree; sha256 of the page against the
record's `bundleHash`; the recorded commit walked to the page through the
canister's `get_object` query, every object checked against its own
SHA-1; and check E, that everything the page loads is inline or
SRI-pinned. The record attests one file, the entrypoint, and SRI covers
what it loads, so a page needs exactly one response checked: its own.

From the verified page, `derivePolicy` builds the Content-Security-Policy
that admits only that page's scripts and styles: inline ones by the
sha256 of their text, external scripts by their `integrity` hashes, plus
`object-src 'none'`, `frame-src 'none'`, `base-uri 'none'`. External
stylesheets cannot be pinned (Chrome takes no hash for one, and a URL pins
nothing once the markup can be altered), so a site inlines its CSS --
ic-vote does at staging. Check E and `derivePolicy` are one walk over the
page (`readPage`), which follows the browser's HTML parser and refuses
wherever it cannot say what the parser will do: a page the policy could
not pin exactly fails check E, at publish and here, rather than being
guessed at.

## What the page talks to: the backend check

A verified page's code is known; what it calls is not, unless that is
judged too (docs/GOVERNANCE.md, section 4). So the extensions judge the
canisters a page may call and enforce the verdict on the wire. The
judgment is the core's `checkBackends(repo)`, shared with the loader, and
every verdict rests on a certified read (`readCanisterState`,
docs/CERTIFIED.md): the IC's own word on a canister's module hash and
controllers, never ic-git's. For each canister:

- **system** -- its one controller is the NNS root (`r7inp-...`): the ICP
  ledger, the cycles ledger, the cycles minting canister. Allowed.
- **approved** -- its one controller is ic-git and its certified module
  hash is the repo's `<repo>#app` record, read from the registry through
  the same two RPCs that must agree: a governed backend running a build
  the voters approved. Allowed. Or ic-git itself: its one controller is
  the governor pinned in the core (`7kkwl-...`, docs/GOVERNOR.md), whose
  certified state shows no controllers and the module `verified.json`
  records for it, and ic-git's certified module hash is the
  `ic-git#canister` record. ic-git's code then changes only by its
  approvers' vote, and the chain says which build it runs. Or the git
  canister, when it serves the site: likewise under its own governor,
  pinned in the core (`DEFAULTS.gitGovernor`, `3hps4-...`, installed at
  step 15 of the split; a client without the pin judges the git canister
  ungoverned), and running what `ic-git#git` records.
- **governed** -- ic-git (or the git canister) under that governor, but running a module the
  `ic-git#canister` record does not name (yet: the record follows an
  upgrade by a block or two, and a failed publish leaves it behind until
  the next). Allowed, warned: the change was still voted. ic-git is never
  blocked -- every page is served by it -- so each way its governor
  could fall short is a warning that says which.
- **blocked** -- its one controller is ic-git, but no record approves the
  module it runs, or there is no record. The one case a verified page
  must not reach, since governance promised otherwise: the site fails
  check G and the stop page names the canister and the two hashes.
- **immutable** -- nobody holds it: its code can never change. Allowed.
- **ungoverned** -- anyone else holds it (an owner, ic-git among others;
  ic-git under a governor other than the pinned one, or one that has
  controllers or runs another module). Its code is not tampered, but its
  holder can change it without a vote.
  Allowed, and said: the badge stays OK but turns amber, and its hover
  text says the site's owner can change its backend without approval.
  A stale certificate (over five minutes) on an allowed backend turns the
  badge amber too, with its own words.
- **unreadable** -- no certified answer. Not allowed.

Which canisters are judged: ic-git itself (every page reads it), the
three system canisters, and the site's app canister as `/api/<repo>/info`
names it -- the one thing taken from ic-git's API, and the judgment of
that id is certified, so a lie there buys only a different canister
allowed on its own merits. They are judged with the site, so a page's
first calls do not wait, and a stale certificate (over five minutes)
warns without blocking.

Enforcement:

- **Chrome:** a static rule in `rules.json` blocks every call a `/site/`
  page makes to the IC's API (`icp-api.io`, `icp0.io`, `ic0.app` and
  their subdomains; `/api/vN/canister/`, `/subnet/` and `/status`, not a
  canister's own `/api/` routes on the gateway). Session allow rules, one
  per allowed canister on `icp-api.io` only and scoped to the tab, are
  installed before the tab is given the page -- on a first visit, before
  it is told to reload under the pinned policy -- so no first-visit
  reload is spent on them (decision 4 of docs/GOVERNANCE.md, settled:
  derive the list, do not reload). Per tab, because the verdict is per
  site and every site on a host shares its origin: a canister approved
  for site A is not thereby open to site B. A call to a canister nobody
  judged is blocked with no feedback but the badge text; "open anyway"
  opens that tab's calls along with its scripts.
- **Firefox:** the request listener holds each call from a `/site/` page
  to an IC API host, finds the canister in the site's judged backends or
  judges it on the spot (a verdict from a certified read is kept with
  the site; an unreadable one is not, so a transient failure costs one
  call), and releases or cancels it. A cancelled call turns the badge red
  and says what was cancelled on hover. Only `icp-api.io` is released; a
  call through another IC host is cancelled unjudged -- which needs host
  permissions on `icp0.io` and `ic0.app` that MV3 Firefox grants on
  install but not on an update; when they are missing the badge's hover
  text says so, and such calls go through unjudged.
- **The git canister's host, on an update (Firefox).** 0.3.0 is the first
  version to ask for `34koz-...raw.icp0.io`, and an update to it is not
  granted that host either. Without it nothing of the extension runs
  there, so a page on it would load unchecked: the badge says on every
  tab which site host is missing, and a redirect to that host from
  ic-git's (every site's old URL after the cut) is cancelled, with the
  tab's badge saying why, until the user grants it. Chrome instead holds
  an update that asks for a new host until the user accepts it.

Two edges. A page run through the loader (`/site/ic-git-loader/`) under
an extension calls as the loader's site, whose own list has no app
canister, so its backend's calls are blocked: open a site directly under
the extensions; the loader is for a browser without them. And a site's
backend list is refreshed with the site, every ten minutes: an app
canister created since is blocked until then, or until the next visit
after a page change.

What this cannot see: a call the page asks the wallet to make. OISY sends
it from its own window, which neither extension observes; OISY's consent
screen names the target canister and method, and the user reads it. A
page-world shim that refuses wallet calls to unapproved canisters is
defence in depth the extensions could add; it is not watertight (a page
can sometimes reach an unwrapped copy of the messaging function) and is
not built.

## How each browser enforces it

### Firefox: the page that loads is the page that arrived

Firefox lets an extension hold a response (`webRequest.filterResponseData`):

1. Before the body (`onHeadersReceived`), the site is verified -- awaiting
   the check on a first visit -- and the response gets its pinned policy,
   or `script-src 'none'`.
2. The body is held, every byte. If it hashes to the verified record, it
   is released unchanged. Otherwise those delivered bytes are checked
   against the record themselves: a new deploy passes and is loaded again
   under its own policy; anything else becomes a bare page under the stop
   page. A failed delivery is that navigation's, not the site's -- a
   targeted proxy can alter one response while everything else is honest
   -- so it does not undo the site's verified state.

The parser never sees a held page that fails, so it is not shown, not run,
and makes no requests.

### Chrome: only the checked bytes, under the pinned policy

Chrome gives an extension no access to response bodies, so it never uses
the page the network delivered:

1. A static rule (`extension/rules.json`) sets `script-src 'none'` and
   `frame-src 'none'` on every page under `/site/`. Once a site verifies, a higher-priority session rule
   replaces it with the site's pinned policy. Unchecked or failed pages run
   no script, and the static rule outlives a browser restart. The same rule
   sets every such page's type to `text/html; charset=utf-8`, whatever the
   response said (measurement 15).
2. At `document_start`, `extension/main.js` (in the page's world) calls
   `document.open()`, which discards the delivered response unparsed; the
   content script then writes in the bytes the background checked against
   the record -- cached since the check, so a verified page needs no
   network -- or a bare page under the checking screen or the stop page.
   The document keeps its origin and the response's policy.
   `document.open()` throws on a document that is not HTML (one typed as
   XML, XHTML or SVG), which would leave the delivered page to be parsed
   and shown, and keeps the delivered charset (measurement 16): hence the
   type in step 1. Should the type still not be `text/html`, or `open()`
   throw or do nothing, `main.js` stops the load and empties the document
   instead, and the tab gets the stop page, with no "Open anyway": the
   page it would open is gone.
3. The badge says OK only once the page is written: `main.js` acknowledges
   the write, and the content script reports it to the background.
4. A first visit loads under the static rule, so once the site verifies
   the tab reloads once under its pinned policy.

What Chrome cannot stop: its preload scanner reads ahead in the delivered
response and requests the images, stylesheets and scripts it names before
any extension code runs. Nothing it fetches is shown or run, but a
tampered page can make the browser send those GETs. Firefox has no such
residue. (`chrome.debugger` could close it, at the cost of a permanent
"is debugging this browser" bar; not built.)

Firefox sets the type too, in the same listener as the policy: a held page
goes out as `text/html; charset=utf-8`, which is how check E read it. Typed
as the response said, even the recorded bytes could be parsed as XML, or
decoded as other text.

### Both

- Verified state is refreshed every ten minutes and rechecked on each
  visit; a failure is never reused -- the next visit checks again.
- `/site/<repo>` (no slash) is redirected to `/site/<repo>/` before it
  loads: the canister serves the page at both, but relative URLs only
  resolve at the second.
- A site is checked at one host, `<canister>.raw.icp0.io`, and the
  gateways serve the same canister at others: the certified host
  (`<canister>.icp0.io`), every other domain of theirs (`ic0.app`,
  `icp1.io`, `icp.net`, and whatever they add), and the same with a
  prefix, `x--<canister>`, which a gateway drops. A page there is another
  origin's, with none of the extension on it, so it would load unchecked.
  Both extensions block any navigation, of a tab or of a frame, to a
  path under `/site` at a host whose first label is one of the two
  canisters' ids, with or without a prefix, under any domain, except the
  checked host itself, and that host too when it is spelled as another
  origin (with the root's trailing dot, where the gateways answer, or at
  a port): static rules (`rules.json`, in both packages),
  which go by the id and so need no list of the gateways' domains and
  no permission for them (measurement 14). The tab shows the browser's
  own "blocked" page, with no word from the extension: nothing of it may
  run on that host. The checked host over `http` is asked for over
  `https` by the same means. What the rule leaves alone at those hosts
  is what is not under `/site`: the canister's index, its API, the git
  protocol, none of them a site's page. The checked host itself is
  blocked in a frame and in an object, at any page's (a static rule, in
  both packages): a page of it there is no tab's page, so neither
  extension checks it, and it would run as that host -- the origin of
  every checked page, which it could then reach, by `window.open` or as
  a checked page's opener. A checked page frames nothing
  (`frame-src 'none'`). A site at a domain of its own
  (docs/TENANCY.md, "Custom domains") has no canister id in its host
  and is not covered: it loads unchecked, at that domain, until the
  extensions know the domain.
- Check E refuses what the pinned policy would refuse or could not pin:
  inline event handlers (any `on...` attribute), `style=` attributes,
  `javascript:` URLs, external stylesheets, `@import` in an inline
  `<style>`, and a script or style it cannot say the browser will run as
  written (inside `<svg>` or `<math>`, a running script inside
  `<template>`, anything after markup whose parse it does not follow) --
  in the canister, at publish, and in the shared scanner the extensions
  and tools run. So a page that publishes is a page the extensions load
  under a policy that admits everything in its markup.
- What the page's own code does once it runs is out of a markup scan's
  reach, and the policy still governs it. Admitting by hash and nothing
  else, it refuses (measurement 10): `eval`, `new Function` and string
  timers; compiling WebAssembly; workers and service workers; `import()`,
  and a module's static imports unless a `<link rel=modulepreload>` pins
  the file -- a pinned module with an unpinned import does not run at
  all; a script or `<style>` the code adds, unless its text is one the
  page was published with or it carries a pinned `integrity`; an added
  stylesheet link; `style=` and `on...` attributes however they are set
  (`setAttribute`, `innerHTML`); frames and `<base>`. It leaves alone the
  CSSOM (`el.style`, `insertRule`, constructed sheets), handlers set as
  functions, `fetch`, and images. Nothing announces a refusal: the page
  loads, the call throws or does nothing, and the browser's console names
  the directive. A site that needs one of these does not work under the
  extensions until it stops needing it.

## What the user sees

- Verified: the page, as published. The toolbar badge says OK, with the
  commit on hover -- green when every backend it may call is approved or
  a system canister, amber when one is ungoverned (hover says so).
- Not verified: a stop page naming each check that failed, the record and
  what was served, with "Check again" and "Open anyway" -- the second
  armed by a first click and then running the page as served, for that
  tab only, with the badge still warning.
- Not yet checked (Chrome's first visit): a neutral "Checking" screen for
  a few seconds, then the page. Firefox simply waits.
- A page no record covers (anything under `/site/` but an entrypoint):
  stopped.

## Testing

- `node tools/extension-test.mjs --browser <Chrome for Testing>` and
  `node tools/extension-firefox-test.mjs` drive each extension against
  the live canister and registry, with a real TLS-intercepting proxy as
  the man in the middle: first and second visits, the slash-less address,
  ic-vote, tampering of only the page's response (script injected, text
  changed), only the page's response typed as XML, XHTML or SVG (Chrome
  also with its static rules off; Firefox also in another charset),
  tampering of everything, recovery once tampering stops,
  "Open anyway" (Chrome), a page no record covers, and the same sites at
  the gateways' other hosts, which must not load. On Firefox the
  tampered page's injected script and image are shown never to be
  requested.
- `node tools/loader-test.mjs` covers the core, check E and `derivePolicy`
  on fixed pages (the canister's test cases, mirrored), that the two agree
  on every one, and that every copy of the core is in step with
  `core/verifier.js`.
- `node tools/walk-fuzz.mjs` puts pages to the walk. `--browser` (Chrome,
  or Firefox with `--firefox`) checks it against the browser's own
  parser, on random pages and on every context of up to two structural
  tags; `--rust` checks that the canister's port gives each random page
  the same verdict. Run both after any edit to the walk.
- Real browsers, macOS, with NordVPN Threat Protection (a TLS-inspecting
  proxy that injects a script into every page): Chrome on 2026-09-30 and
  Firefox 153 on 2026-10-01 both stopped the console while it was on, ran
  the console and ic-vote once it was paused, and carried an OISY
  sign-in and a push token minted and revoked through the verified page.

## Measurements

What the design rests on, measured in Chrome for Testing (Chromium 1243)
and Firefox 153, headless, against the live sites or an instrumented
local page:

1. Chrome enforces a CSP added by an extension rule, `append` or `set`.
2. A `script-src` hash admits an external script by its `integrity`; a
   script with a copied hash then fails SRI on its contents.
3. Chrome takes no hash source for an external stylesheet.
4. Both live sites run under their full derived policy; injected scripts
   are refused under it, and run without it.
5. Of two rules setting the CSP, the higher priority wins outright.
6. `document.open()` at `document_start`, in the page's world, discards
   the delivered page and the written one keeps the response's CSP.
   `window.stop()` does not work: it makes `document.open()` a no-op.
   From the isolated world the write does nothing.
7. Chrome's preload scanner requests what the delivered page names before
   any extension code runs.
8. Firefox can hold a response and replace it after an async check; a held
   page requests nothing; an async `onHeadersReceived` can set the CSP.
   Match patterns must not name a port (they fail silently).
9. A rule without host permission for the page silently does nothing.

Measured on 2026-10-02, in the same Chromium (153.0.8010) and Firefox 157:

10. Under a derived policy, in both: `eval` and `new Function` throw, a
    string timer does not run, WebAssembly does not compile; a worker
    (from a URL or a blob), a service worker and `import()` are refused; a
    pinned module with an unpinned static import does not run, and runs
    once a `<link rel=modulepreload>` pins the import; an added script
    runs only with the text of a pinned inline script or carrying a
    pinned `integrity` (the URL of a pinned script is not enough), an
    added `<style>` only with the text of a pinned one; an added
    stylesheet link, `setAttribute('style')`, `style=` and `on...` through
    `innerHTML`, `setAttribute('onclick')`, a followed `javascript:` URL,
    an added frame and an added `<base>` do nothing; `el.style`,
    `insertRule`, a constructed sheet, a handler set as a function,
    `fetch` and an image work.
11. Both discard an `integrity` whose algorithm is not in lower case: a
    script with `integrity="SHA384-..."` and the wrong hash runs. Check E
    reads the attribute as the page wrote it.
12. Chrome prerenders a page named by an inline
    `<script type=speculationrules>`, running its scripts on the origin
    with no user action; Firefox does not. Check E refuses the script.
13. The walk reads pages as both browsers' parsers do
    (`tools/walk-fuzz.mjs`, at its defaults). Of 100,000 random pages
    check E accepted 37,260, and on each the parsed document held nothing
    check E refuses and exactly the scripts and styles the policy pins --
    3,000 of them also by a navigation with scripting on. And in none of
    9,049,755 pages -- every context of up to two structural tags, then
    text the walk skips -- did the parser build an element the walk had
    skipped. The canister's port gave the 100,000 the same verdicts.

Measured on 2026-11-18, in Chrome for Testing 158.0.8127 and Firefox 160:

14. A static `block` rule, and an `upgradeScheme` one, act on a host the
    manifest names no permission for, in both (contrast 9, which is of a
    rule that changes headers): `tools/extension-test.mjs` and
    `tools/extension-firefox-test.mjs`, the last case of each. In Chrome
    a blocked tab is `net::ERR_BLOCKED_BY_CLIENT` and a blocked frame an
    error page inside it; in Firefox the navigation ends in
    `NS_ERROR_ABORT`. Firefox needs the `declarativeNetRequest`
    permission for it, which Chrome's package had; the tests load each
    package unpacked, so neither has shown how a store update that adds
    it is offered to the user.

Measured on 2026-11-25, in Chrome for Testing 158.0.8127.88 and Firefox 160.0.1:

15. A rule that sets a main-frame response's `Content-Type` decides the
    document's type and charset: a page served as `text/xml`,
    `application/xhtml+xml`, `image/svg+xml` or `text/html;
    charset=iso-2022-jp` under a rule setting `text/html; charset=utf-8`
    is a UTF-8 HTML document, which `document.open()` replaces. Firefox's
    `onHeadersReceived` does the same for its type and charset; without
    it, Firefox parsed even the recorded bytes as the response typed them:
    as XML (the console came out blank) or in the charset it named
    (ISO-2022-JP).
16. Without that rule, in Chrome, such a response is an XML document:
    `document.open()` throws, the page the network delivered is parsed
    and shown, and the extension as it was before this measurement put
    its green OK on it. `window.stop()` and `document.replaceChildren()`
    at `document_start` leave it empty, and a stop page built of elements
    in the HTML namespace shows there. And a page served as HTML in
    another charset keeps it through `document.open()`: the checked page
    was written into an ISO-2022-JP document.

## The extension's own package, on chain

Each package is checked against the chain the way the loader is: its file
list is published as a site record, and users compare the hash of what
they installed with it.

- Each package is a directory in this repo with no build step, so the
  files a store installs are the files in git.
- `<package>/SHA256SUMS` lists every file as `<sha256>  <path>`, in byte
  order of path, except itself and what a store adds (`_metadata/`,
  `META-INF/`). `manifest.json` is listed by the sha256 of its canonical
  JSON (keys sorted, no whitespace, without `update_url` and `key`),
  because Chrome's installer re-serializes it and adds those two. They
  are checked, not ignored: `update_url` must be the Chrome Web Store's,
  and `key` must give the id passed as `--id`, since the same files under
  another key would be another extension. The Firefox package carries its
  id in its manifest.
- `node tools/extension-sums.mjs <dir>` prints a listing; `--digest` its hash,
  `--write` and `--check` keep `SHA256SUMS` current
  (tools/extension-sums-test.mjs tests the rules). It needs only node.
- The records: `ic-git-extension#site` and `ic-git-extension-firefox#site`,
  each repo's site root being its package's `SHA256SUMS`, so each record's
  `bundleHash` is the hash of that listing.
- A user, once per release: run `--digest` on the installed copy (Chrome:
  `.../Extensions/<id>/<version>_0/` with `--id <id>`; Firefox: the `.xpi`,
  unzipped) and compare with the record, read as for the loader
  (docs/LOADER.md). docs/STORE.md has the paths.
- Auditors can skip the stores: clone at the recorded commit and load the
  package directory unpacked.

A release's record is published before the package reaches a store, since
stores update installs automatically. Submitting: docs/STORE.md.

### Publishing a release (operator, mainnet)

From `main` with the release merged, for each package -- `extension` with
repo `ic-git-extension`, `extension-firefox` with `ic-git-extension-firefox`.
Push main to these repos only as part of a release: a push moves the served
commit away from the recorded one, and `tools/verify.mjs` check A then
fails until the next publish.

```sh
# the authority: the repo, its site, its record
C=umobs-yiaaa-aaaab-agyrq-cai
# the git canister: the token, the push, the served listing
G=34koz-jyaaa-aaaab-ahejq-cai
# or extension-firefox, ic-git-extension-firefox
PKG=extension; REPO=ic-git-extension

# the listing is current
node tools/extension-sums.mjs --check $PKG

# First time only: the repo, with its site root at the listing.
dfx canister --network ic call $C create_repo "(\"$REPO\")"
dfx canister --network ic call $C set_site "(\"$REPO\", \"$PKG/SHA256SUMS\")"

# Push main.
TOKEN=$(dfx canister --network ic call $G create_push_token "(\"$REPO\", opt (1 : nat32), null)" \
  | sed -n 's/.*Ok = "\([0-9a-f]*\)".*/\1/p')
: "${TOKEN:?create_push_token returned no token}"
git push "https://ic:$TOKEN@$G.raw.icp0.io/$REPO.git" main

# The canister serves the listing in git: from a terminal, not a browser.
git show main:$PKG/SHA256SUMS | shasum -a 256
curl -s "https://$G.raw.icp0.io/site/$REPO/" | shasum -a 256

# Publish, then confirm once the transaction is mined: wait for the
# receipt as for the loader, docs/LOADER.md step 5, or verify.mjs still
# reads the old record.
dfx canister --network ic call $C evm_registry_publish_site "(\"$REPO\")"
node tools/verify.mjs $REPO / --record site
```

Then add a row to Releases.

### Releases

The newest row per package is the record on chain. 0.1.0 was published
but never submitted to a store; 0.1.1 superseded it, and was submitted
to both stores on 2026-10-01. Users pass the Chrome store id to `--id`.
0.2.0 -- the tightened check E in the shared scanner (0.1.2, never
published on its own), the certified reader, and the backend check --
was published on 2026-10-09 and submitted to both stores. Firefox's
0.2.0 asks for host permissions on `icp0.io` and `ic0.app` too, to cancel
a page's calls through those hosts. 0.2.1, published on 2026-10-15,
judges ic-git itself by the governor rule ("approved" since the handover
of 2026-10-14, where 0.2.0 still says "ungoverned"), so a site whose
backends are all governed or system gets a green badge.
0.3.0, published on 2026-11-16, holds the canister split's clients
(docs/CANISTER_SPLIT.md, step 14): both pinned canisters as hosts, state
keyed by host and repo, and the git canister's governor pinned beside
ic-git's (step 15); both packages ask for the git canister's host
permission, which an update does not grant in Firefox until the user
accepts it ("The git canister's host, on an update").

| Date | Package | Version | Commit | sha256 of SHA256SUMS | Registry tx | Chrome store id |
|---|---|---|---|---|---|---|
| 2026-10-01 | Chrome (`ic-git-extension`) | 0.1.0 | `0e80cf60a1e6530bd2565260f98c809f67551f53` | `c766bcb27281c20c5564eb322d63e094beaefd970b56e16b315ec740410a8a3a` | [`0xe1ad2e00...f8bb`](https://sepolia.etherscan.io/tx/0xe1ad2e004523fba7f117c0eb65cc06b76f38621eae4fcf3655efdb8fa898f8bb) (Sepolia 11822489) | -- |
| 2026-10-01 | Firefox (`ic-git-extension-firefox`) | 0.1.0 | `0e80cf60a1e6530bd2565260f98c809f67551f53` | `6df0039686c702bff3207feaed50acfdedf257ef0016797a1805a8acb06d77f7` | [`0x4ddb7587...593a`](https://sepolia.etherscan.io/tx/0x4ddb7587547dd46fdcdc18e99138ffbaed945c73c4617d90dc9f9ece5a92593a) (Sepolia 11822495) | n/a |
| 2026-10-01 | Chrome (`ic-git-extension`) | 0.1.1 | `848be9dd48c1db879884076f0e71f8ae1d52e010` | `70696452d02ef89721051b78e73d385e1c557436c65670f659dc57c8475d0cef` | [`0x757dd912...7d1b`](https://sepolia.etherscan.io/tx/0x757dd912d7a416ffbbdd4c84abadd7c0f88db547d3f01183bc11051cd5cc7d1b) (Sepolia 11824283) | `fdcegfanhmpdnbcalfjdlboebhknkhco` |
| 2026-10-01 | Firefox (`ic-git-extension-firefox`) | 0.1.1 | `848be9dd48c1db879884076f0e71f8ae1d52e010` | `44aa3e1d6b860c20be70dc57a91d197290c07efb5cb4c076378fba9bd1323174` | [`0x44169d53...7209`](https://sepolia.etherscan.io/tx/0x44169d53f85a8dcb5ca064f0557ec9feac3ac171f7a2ad366896dd0ade6c7209) (Sepolia 11824285) | n/a |
| 2026-10-09 | Chrome (`ic-git-extension`) | 0.2.0 | `3850d185eb713c96106ead6bbdc49ec9be3f1b23` | `883446f310ef7b732c86f0eab5f6c20af7d694772e5d8329dbf62901ec52be8c` | [`0x0b5cc068...2780`](https://sepolia.etherscan.io/tx/0x0b5cc068d0dcb547eddcc06cac1bac8933da5beb07068307946393009e4c2780) (Sepolia 11878294) | `fdcegfanhmpdnbcalfjdlboebhknkhco` |
| 2026-10-09 | Firefox (`ic-git-extension-firefox`) | 0.2.0 | `3850d185eb713c96106ead6bbdc49ec9be3f1b23` | `fd899007641fc1ee13733bf4f08d2f1cc60c809eaeae6cdf80a459a2539636f7` | [`0x9d61795d...3174`](https://sepolia.etherscan.io/tx/0x9d61795de41de61cfaa7e0151a6950eb57492650b1fb81e28f1ebf6526683174) (Sepolia 11878302) | n/a |
| 2026-10-15 | Chrome (`ic-git-extension`) | 0.2.1 | `51616b86a89743ce6e1e8303e2f44c99e1752f78` | `ad388dea1c25657fca8fdc398afc1fc8ea4fe30ad7a8a5a28c48179e75bcf5dc` | [`0x87ab3f2e...6d26`](https://sepolia.etherscan.io/tx/0x87ab3f2e9931a4886449a3265e616ebc46bfa35b5aca00a29f80ecf4df9e6d26) (Sepolia 11917681) | `fdcegfanhmpdnbcalfjdlboebhknkhco` |
| 2026-10-15 | Firefox (`ic-git-extension-firefox`) | 0.2.1 | `51616b86a89743ce6e1e8303e2f44c99e1752f78` | `f97b5b07b5277f8d384c65c184c9e0c9f8a9701c0237f2016fe9749003a436ea` | [`0x787a49d5...f47c`](https://sepolia.etherscan.io/tx/0x787a49d554e74f0109f5e47b2f37ac2f9f14bcccc31fcc3a65df4d5791d6f47c) (Sepolia 11917693) | n/a |
| 2026-11-16 | Chrome (`ic-git-extension`) | 0.3.0 | `64a6c75730a9586598d18a171e7f9146faf19f0f` | `46039e8185bf0c4f4f0e5985527edfc548790cdf63340b8aad40e0406545bd88` | [`0x548a16cc...5aa1`](https://sepolia.etherscan.io/tx/0x548a16cc29fb3fc60756cff94bfd4eb031a2dc15dbfd22059c1c2e5863045aa1) (Sepolia 12147959) | `fdcegfanhmpdnbcalfjdlboebhknkhco` |
| 2026-11-16 | Firefox (`ic-git-extension-firefox`) | 0.3.0 | `64a6c75730a9586598d18a171e7f9146faf19f0f` | `fd84d305d45e434acb6c9babb829f75c5ea0e1d25665501ec58516ba0c6a9d7d` | [`0x61ffae38...1a0e`](https://sepolia.etherscan.io/tx/0x61ffae38f014fc79dc5009cf68cf04729a2c4c06d538ad5ddf3a01c0aeb31a0e) (Sepolia 12147966) | n/a |

## Next

- Check the first store-installed copy of each package (0.2.1) with
  `--digest` before users are told to rely on it (docs/STORE.md).
  Chrome: done 2026-10-27. 0.2.1 installed from the Chrome Web Store
  (id `fdcegfanhmpdnbcalfjdlboebhknkhco`) digests to `ad388dea...f5dc`,
  the record's `bundleHash`, so the store changed nothing the tool's
  rules do not account for; `tools/verify.mjs ic-git-extension /
  --record site` reads the same hash from the registry and VERIFIED.
  Firefox: not yet checked. Mozilla approved and signed 0.2.1 on
  2026-10-21, minutes after it was submitted, and addons.mozilla.org does
  not list `verifier@ic-git.dev` publicly: it is distributed unlisted
  (docs/STORE.md, "listed or unlisted"), so the copy to check is the
  signed `.xpi` from the developer hub, installed into Firefox.
- The extension hashing its own files and showing whether they match the
  record: catches an unpublished update, not a tampered extension, which
  would lie about itself.
- A successor governor (a Handover vote, docs/GOVERNOR.md) needs a new
  pin in the core and a package release; until then the old pin judges
  ic-git "ungoverned", which is the safe direction.
- The K-of-N attestations (docs/ATTESTATION.md) behind the same stop page.
- Safari (no `filterResponseData`; CSP injection unexamined), other
  hosting, and pages outside `/site/`.
- A site at a tenant's own domain (docs/TENANCY.md, "Custom domains") is
  loaded unchecked by both browsers and the loader: the extension acts on
  the two pinned hosts only, so a hijacked domain shows no badge at all,
  which is what the Curve frontend's DNS hijack of 2022 looked like to its
  users.
  The next leg pins a list of domain to repo in the core, like the
  canister ids: a listed domain gets the same hold, check against the
  record and block, and the record's bytes are fetched from the pinned
  host, never from the domain, so a hijacked one fails closed. An
  unlisted domain stays as it is.
