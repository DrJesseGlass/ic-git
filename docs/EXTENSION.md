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

Scope: pages under `/site/` on `umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io`,
which covers the console (`ic-git`) and ic-vote. Nothing to do when a page
verifies; an unmissable stop when it does not.

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
  the voters approved. Allowed.
- **blocked** -- its one controller is ic-git, but no record approves the
  module it runs, or there is no record. The one case a verified page
  must not reach, since governance promised otherwise: the site fails
  check G and the stop page names the canister and the two hashes.
- **immutable** -- nobody holds it: its code can never change. Allowed.
- **ungoverned** -- anyone else holds it (an owner, ic-git among others,
  ic-git itself until the governor of docs/GOVERNANCE.md section 5). Its
  code is not tampered, but its holder can change it without a vote.
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
  site and every site shares one origin: a canister approved for site A
  is not thereby open to site B. A call to a canister nobody judged is
  blocked with no feedback but the badge text; "open anyway" opens that
  tab's calls along with its scripts.
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

1. A static rule (`extension/rules.json`) sets `script-src 'none'` on every
   page under `/site/`. Once a site verifies, a higher-priority session rule
   replaces it with the site's pinned policy. Unchecked or failed pages run
   no script, and the static rule outlives a browser restart.
2. At `document_start`, `extension/main.js` (in the page's world) calls
   `document.open()`, which discards the delivered response unparsed; the
   content script then writes in the bytes the background checked against
   the record -- cached since the check, so a verified page needs no
   network -- or a bare page under the checking screen or the stop page.
   The document keeps its origin and the response's policy.
3. A first visit loads under the static rule, so once the site verifies
   the tab reloads once under its pinned policy.

What Chrome cannot stop: its preload scanner reads ahead in the delivered
response and requests the images, stylesheets and scripts it names before
any extension code runs. Nothing it fetches is shown or run, but a
tampered page can make the browser send those GETs. Firefox has no such
residue. (`chrome.debugger` could close it, at the cost of a permanent
"is debugging this browser" bar; not built.)

### Both

- Verified state is refreshed every ten minutes and rechecked on each
  visit; a failure is never reused -- the next visit checks again.
- `/site/<repo>` (no slash) is redirected to `/site/<repo>/` before it
  loads: the canister serves the page at both, but relative URLs only
  resolve at the second.
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
  changed), tampering of everything, recovery once tampering stops,
  "Open anyway" (Chrome), and a page no record covers. On Firefox the
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
C=umobs-yiaaa-aaaab-agyrq-cai
PKG=extension; REPO=ic-git-extension          # or extension-firefox, ic-git-extension-firefox

node tools/extension-sums.mjs --check $PKG    # the listing is current

# First time only: the repo, with its site root at the listing.
dfx canister --network ic call $C create_repo "(\"$REPO\")"
dfx canister --network ic call $C set_site "(\"$REPO\", \"$PKG/SHA256SUMS\")"

# Push main.
TOKEN=$(dfx canister --network ic call $C create_push_token "(\"$REPO\", opt (1 : nat32), null)" \
  | sed -n 's/.*Ok = "\([0-9a-f]*\)".*/\1/p')
: "${TOKEN:?create_push_token returned no token}"
git push "https://ic:$TOKEN@$C.raw.icp0.io/$REPO.git" main

# The canister serves the listing in git (from a terminal, not a browser).
git show main:$PKG/SHA256SUMS | shasum -a 256
curl -s "https://$C.raw.icp0.io/site/$REPO/" | shasum -a 256

# Publish, then confirm once the transaction is mined: wait for the
# receipt as for the loader (docs/LOADER.md, step 5), or verify.mjs still
# reads the old record.
dfx canister --network ic call $C evm_registry_publish_site "(\"$REPO\")"
node tools/verify.mjs $REPO / --record site
```

Then add a row to Releases.

### Releases

The newest row per package is the record on chain. 0.1.0 was published
but never submitted to a store; 0.1.1 superseded it, and was submitted
to both stores on 2026-10-01. Users pass the Chrome store id to `--id`.
The packages in git are 0.2.0 -- the tightened check E in their shared
scanner (0.1.2, never published on its own), the certified reader, and
the backend check -- and are not yet published. Firefox's 0.2.0 asks for
host permissions on `icp0.io` and `ic0.app` too, to cancel a page's calls
through those hosts.

| Date | Package | Version | Commit | sha256 of SHA256SUMS | Registry tx | Chrome store id |
|---|---|---|---|---|---|---|
| 2026-10-01 | Chrome (`ic-git-extension`) | 0.1.0 | `0e80cf60a1e6530bd2565260f98c809f67551f53` | `c766bcb27281c20c5564eb322d63e094beaefd970b56e16b315ec740410a8a3a` | [`0xe1ad2e00...f8bb`](https://sepolia.etherscan.io/tx/0xe1ad2e004523fba7f117c0eb65cc06b76f38621eae4fcf3655efdb8fa898f8bb) (Sepolia 11822489) | -- |
| 2026-10-01 | Firefox (`ic-git-extension-firefox`) | 0.1.0 | `0e80cf60a1e6530bd2565260f98c809f67551f53` | `6df0039686c702bff3207feaed50acfdedf257ef0016797a1805a8acb06d77f7` | [`0x4ddb7587...593a`](https://sepolia.etherscan.io/tx/0x4ddb7587547dd46fdcdc18e99138ffbaed945c73c4617d90dc9f9ece5a92593a) (Sepolia 11822495) | n/a |
| 2026-10-01 | Chrome (`ic-git-extension`) | 0.1.1 | `848be9dd48c1db879884076f0e71f8ae1d52e010` | `70696452d02ef89721051b78e73d385e1c557436c65670f659dc57c8475d0cef` | [`0x757dd912...7d1b`](https://sepolia.etherscan.io/tx/0x757dd912d7a416ffbbdd4c84abadd7c0f88db547d3f01183bc11051cd5cc7d1b) (Sepolia 11824283) | `fdcegfanhmpdnbcalfjdlboebhknkhco` |
| 2026-10-01 | Firefox (`ic-git-extension-firefox`) | 0.1.1 | `848be9dd48c1db879884076f0e71f8ae1d52e010` | `44aa3e1d6b860c20be70dc57a91d197290c07efb5cb4c076378fba9bd1323174` | [`0x44169d53...7209`](https://sepolia.etherscan.io/tx/0x44169d53f85a8dcb5ca064f0557ec9feac3ac171f7a2ad366896dd0ade6c7209) (Sepolia 11824285) | n/a |

## Next

- Release the tightened check E: the canister (the next canister release)
  and the extensions (0.1.2, below) -- the 0.1.2 records published and
  submitted once the stores have approved 0.1.1.
- Check the first store-installed copy of each package with `--digest`
  before users are told to rely on it (docs/STORE.md).
- The extension hashing its own files and showing whether they match the
  record: catches an unpublished update, not a tampered extension, which
  would lie about itself.
- ic-git's own canister under the backend check: today it is
  "ungoverned" (its controller is the operator), which every site's badge
  says in amber. The governor (docs/GOVERNANCE.md, section 5) makes it
  "approved": controllers exactly the governor, module hash the recorded
  one; the governor's id is then written into the packages.
- The K-of-N attestations (docs/ATTESTATION.md) behind the same stop page.
- Safari (no `filterResponseData`; CSP injection unexamined), other
  hosting, and pages outside `/site/`.
