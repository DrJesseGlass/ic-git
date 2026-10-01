# The verifier extension -- design

The loader (docs/LOADER.md) checks a site and runs the checked bytes, but on
its own origin. That breaks what matters most on the sites worth checking:
the console's wallet writes (OISY shows and checks the page's origin, which
the loader makes `null`) and anything origin-bound. The extension checks the
page where it really is, on its own origin, as it loads -- the F2 rung of
VISION.md, and step 1 of "How countersign consumes it" in
docs/ATTESTATION.md.

It must be elegant and minimal to use: nothing to do when a page verifies,
and an unmissable stop when one does not.

## What it checks

The loader's core block, unchanged (`// === core ===` in
`loader/index.html`): the `<repo>#site` record from the registry, sha256 of
the entrypoint against its `bundleHash`, the SHA-1-checked object walk from
the recorded commit to the entrypoint, and the reference scan (check E). The
record attests one blob, the entrypoint; SRI, which check E requires,
covers everything the entrypoint loads. So the extension only ever needs the
bytes of one response per page: the top-level document.

Scope, first version: pages under `/site/` on the ic-git canister
(`umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io`), which covers the console
(`ic-git`) and ic-vote. Other ic-git canisters are a settings entry away.

## The hard question: before or after the page's scripts run

A check that finishes after the page's scripts ran reports tampering; it
does not prevent it. What an extension can do about that differs by browser.

| | Sees the exact bytes the page got | Can stop scripts before they run |
|---|---|---|
| Firefox | yes: `webRequest.filterResponseData` | yes: hold the response until the check passes |
| Chrome | no, not without `chrome.debugger`; it runs its own checked copy instead (below) | yes, by pinning scripts with CSP (below) |
| Chrome, `chrome.debugger` | yes: the DevTools `Fetch` domain | yes, but a permanent "is debugging this browser" bar |

### Firefox: hold the document until it verifies

`filterResponseData` streams the main-frame response through the extension
before the page sees a byte. The extension buffers it, runs the core, and
then either writes the bytes through unchanged or writes a block page in
their place. This is the strongest form: the page that runs is the page
that was checked, byte for byte, with no second fetch. Firefox keeps
blocking `webRequest` under Manifest V3, so this does not depend on MV2.

As built (`extension-firefox/`, MV3, background scripts rather than a
worker), in two blocking listeners on the site's main-frame requests:

1. `onHeadersReceived`, before any body: make sure the site is verified
   -- awaiting the check on a first visit, so there is no reload -- and
   set the policy `derivePolicy` pins for it, or `script-src 'none'`.
   Firefox lets a blocking listener return a promise, so the headers wait
   for the check.
2. The `onBeforeRequest` filter holds every byte of the body. If what
   arrived hashes to the verified record, and the matching policy went out
   with the headers, the bytes are released unchanged. Otherwise those
   delivered bytes are checked against the record themselves (the core's
   `verify` with the fetch of the entrypoint answered by them): if they
   pass, a new deploy, the tab gets a one-line refresh that loads the page
   again under its own policy; if not, a bare document under the shared
   stop page. A delivered page that fails is that navigation's failure,
   not the site's -- a targeted proxy can alter one response while the
   record and every other fetch are honest -- so it does not overwrite the
   site's verified state.

Because the parser never sees a held response, a page that fails is not
shown, not run, and makes no requests: the preload fetches that remain
Chrome's residue do not happen here (measured below). So Firefox is the
browser to recommend where the byte-level guarantee matters: operators
and observers.

### Chrome: pin the page's scripts with a Content-Security-Policy

Chrome's Manifest V3 gives an extension no access to response bodies and no
blocking `webRequest` (except for extensions force-installed by enterprise
policy). A content script at `document_start` runs before the page's
scripts but cannot hold the parser, and a second, independent fetch of
the entrypoint is no evidence about the navigation: a MITM that rewrites
every response consistently (the NordVPN case in docs/LOADER.md) answers
both the same, but a targeted one can tell the extension's fetch from the
document request (`Sec-Fetch-Dest`, for one) and answer each differently.
So Chrome gets two mechanisms, neither of which needs the navigation's
bytes: a policy that pins the page's scripts and styles whatever was
delivered, and a document replaced by the checked bytes, the loader's
move.

What Chrome does let an extension do before the response is parsed is
change its headers, with `declarativeNetRequest` rules. So the extension
enforces the verified page's scripts instead of its bytes:

1. In the background, for each site in scope, read the record and verify
   the entrypoint (fetch, hash, object walk, scan) -- on install, on a
   timer, and whenever the record changes.
2. From the verified bytes, derive a policy that allows exactly the scripts
   that page runs: `script-src` listing the sha256 of each inline script and
   the `integrity` hash of each external one; `style-src` listing the
   sha256 of each inline `<style>`, and no URL (below); `object-src
   'none'`, `frame-src 'none'`, `base-uri 'none'`. Check E already
   refuses `<iframe>`, `<object>`, `<embed>` and `<base>`; an injected
   frame from another origin would run that origin's scripts under its
   own policy and could cover the page, so the policy refuses it too.
   An external stylesheet gets no source at all: Chrome takes no hash
   source for one, and a URL source pins nothing, since SRI runs only
   when the markup carries `integrity`, and a proxy that rewrites the
   page can drop the attribute and serve other CSS at that same URL.
   So a stylesheet is inlined at publish, as staging already does for
   ic-vote's modules, and pinned by hash like an inline `<style>` (check
   E tightening, order of work).
3. Install it as a session `declarativeNetRequest` rule that appends that
   `Content-Security-Policy` to the site's main-frame responses. Two CSPs
   both apply, so the page cannot loosen it. The rule applies only where
   the extension has host permission, so the manifest names the canisters
   in scope.
4. Fail closed before that rule exists. A static rule in the manifest
   (`extension/rules.json`) sets `script-src 'none'` on every main-frame
   response under `/site/` on the canisters in scope, and the session rule
   of step 3 outranks it for a verified entrypoint (both `set` the header;
   the higher priority wins, measured below). A page nobody has checked,
   or whose check failed, therefore runs no script at all -- and with step
   5 its delivered markup is never parsed either, so the stop page drawn
   over a bare document is all the tab shows. Session rules and the
   worker's state do not survive a browser restart; the static rule does,
   so the first visit after a restart is checked again, not trusted.
   (An earlier draft blocked the request instead, redirecting to an
   extension page and lifting the block with a paired `allow`; the static
   policy is simpler and, with step 5, shows no delivered byte either.)
5. A page-world script at `document_start` (`extension/main.js`) calls
   `document.open()` before any child of `<html>` exists. That aborts the
   delivered response: its parser is discarded, so none of the page the
   network sent is parsed or run. The isolated content script then asks
   the background for what to show, and writes it through `main.js`,
   once: on a verified site the checked bytes (cached by the background
   since the check, so no network is involved at all), otherwise a bare
   document under the "checking" screen or the stop page. The document
   keeps its origin, so storage and wallet sign-in are the live site's,
   relative URLs need no `<base>`, and same-origin SRI needs no
   `crossorigin` edit; it also keeps the response's policy of step 3,
   since `document.open()` retains the policy container.

   Not `window.stop()`, as an earlier draft said: `stop()` marks the
   parser aborted, and on such a document `document.open()` is a no-op,
   so nothing can be written (measured below). The write must also come
   from the page's world: from the isolated world, `document.write` did
   nothing.

That the fetch is distinguishable from the navigation no longer matters:
its result is not evidence about the page, it is the page. A MITM that
answers it with the recorded bytes has served the honest page; one that
answers with anything else fails the hash. What the navigation's bytes
can still do is make requests: Chrome's preload scanner reads ahead in
the raw response and starts fetching the images, stylesheets and script
URLs it names before any extension code runs (measured below). Nothing
it fetches is parsed, applied or run, but the requests go out -- a
tampered page can make the browser send GETs, cookies attached, to URLs
of its choosing. That is the residue on Chrome; Firefox's hold (above)
has none. A site whose record changes between the rule and the load
simply fails closed until the background check catches up.

The derived policy is stricter than check E, and a site must meet both.
A hash-only `script-src` refuses inline event handlers (`onclick=`),
`javascript:` URLs, workers (`worker-src` falls back to it, and a hash
matches no worker URL), and the import chain of a pinned external module;
a hash-only `style-src` refuses `style=` attributes and
`<link rel=stylesheet>`. Check E lets every
one of those through by design (import specifiers take no integrity;
ic-vote runs only because staging links its modules into one file, and
the console has none of them). A page that passes at publish and fails
at the stop page is the wrong place to learn this, so the scanner should
refuse them where the record is made, when `served_site_record` runs
(order of work, below); until it does, the stop page names the refused
directive.

### The Chrome spikes, run 2026-09-29

Chrome for Testing (Chromium 1243, headless) with a minimal Manifest V3
extension whose static `declarativeNetRequest` rule adds the policy, against
the live pages on mainnet. Chrome for Testing is used because a TLS proxy on
the development machine intercepts the branded browser (docs/LOADER.md).

1. **An extension-added CSP is enforced: yes.** With `script-src 'none'`,
   by `append` and by `set` alike, Chrome refused ic-vote's `app.js` and the
   page stayed on its static text. DevTools does not display the added
   header; enforcement is the evidence.
2. **A hash source admits an external script by its `integrity`: yes.**
   With `app.js`'s `sha384` in `script-src`, it ran and ic-vote reached
   YELLOW; with one character of the hash changed, it was refused. A
   script injected with a copied hash passes CSP and then fails SRI on its
   contents.
3. **Both sites run under the full derived policy: yes, with one change.**
   The console (three inline scripts, one inline style, all by hash) ran
   with no refusals: repositories listed, its provenance line shown,
   "connect wallet" offered. ic-vote ran, but Chrome refused its
   stylesheet by hash; by exact URL it loaded, and ic-vote reached YELLOW
   styled with no refusals. A URL source pins nothing, though (step 2
   above), so the stylesheet is to be inlined at staging instead.
4. **The attack is refused.** A copy of ic-vote with an injected inline
   script and an injected `<script src>` (as the proxy does), under
   ic-vote's derived policy: both refused, and neither ran. Without the
   policy both ran. This needed host permission for the page's origin --
   a rule without it silently does nothing.

5. **In a real browser, with a wallet: works.** Branded Chrome on macOS,
   the same policies loaded as an unpacked extension, with the machine's
   TLS-inspecting proxy (NordVPN Threat Protection) on. The console
   loaded normally and its only CSP report was the proxy's injected
   script, refused. OISY sign-in worked, and a push token was minted and
   revoked through OISY-signed calls. One sign-in attempt stalled on
   OISY's "Waiting for Dapp interaction" and was not reproducible: it
   worked with the proxy paused and again with it on, extension on both
   times.

Run 2026-09-30, for the implementation:

6. **Rule priority: the higher `set` wins.** A static priority-1 rule
   setting `script-src 'none'` on all of `/site/`, and a priority-2 rule
   setting ic-vote's pinned policy: ic-vote ran under the pinned policy
   alone (no refusals), and the console, covered only by the static
   rule, had all three of its scripts refused.
7. **Replacing the document: `document.open()`, not `window.stop()`.** A
   local page whose `<head>` and `<body>` scripts each report home if
   they run, served with a hash-only CSP. `window.stop()` at
   `document_start` left the document empty and ran neither script, but
   `document.open()` then did nothing, from the isolated world or the
   page's -- the spec makes it a no-op once `stop()` has aborted the
   parser. `document.open()` alone, synchronously at `document_start` in
   the page's world, aborted the delivered page (neither script ran, its
   markup never reached the DOM, with 1 MB of padding too), and the
   checked bytes written after it became the page: its inline script
   whose hash the response's CSP listed ran, and one it did not list was
   refused -- the policy survives the write.
8. **The preload scanner still fetches.** In every variant above, the
   delivered page's `<link rel=stylesheet>` and `<img>` were requested
   before any extension code ran, though neither was used. Recorded in
   step 5 as Chrome's residue.

Run 2026-09-30 in Firefox 153 (headless, WebDriver BiDi, the add-on
installed with `webExtension.install`), MV2 and MV3 alike:

9. **Holding and replacing the response works.** A blocking
   `onBeforeRequest` with `filterResponseData`, writing a different page
   1.5 s after the body ended: the delivered page never reached the DOM,
   its scripts never ran, and the replacement ran.
10. **A held page asks for nothing.** The delivered page named a
    stylesheet, an external script and an image; none was requested --
    the parser, and its preload scanner, never saw those bytes.
11. **An async `onHeadersReceived` sets the policy.** Returning a promise
    that set `script-src 'none'` 0.8 s later: the replacement's script was
    refused. (Match patterns must not name a port; one that does fails to
    register, silently.)

So Chrome gets both layers: the tab only ever shows the checked bytes,
and they run under a policy that admits only their own scripts. What it
does not get is Firefox's hold on the response itself, so the delivered
page can still make requests it names.

`chrome.debugger` would give Chrome Firefox's guarantee, at the cost of the
debugging bar on every tab while it is attached. It is not the default; it
could be an opt-in "strict" mode for operators.

## How the extension sees the served bytes

- Firefox: the response itself, through `filterResponseData`.
- Chrome: it does not see them. It fetches its own copy of the entrypoint
  from the background service worker, checks that copy against the
  record, and runs it in place of whatever the navigation received (step
  5 above); the policy binds what was received to that copy's scripts
  and styles as well.
- Both: `X-Ic-Git-Commit` from `webRequest.onHeadersReceived` on the actual
  document response (headers are readable without blocking), compared with
  the record's commit.
- The registry is read over JSON-RPC from the background, from two
  independent public endpoints that must agree (the loader's `rpc` setting,
  plural). A wallet's provider is not reachable from a service worker, and
  the page's is exactly the thing under test.

## What the user sees

- Verified: nothing, except the toolbar icon, which shows a check and the
  commit on hover.
- Not verified: the page is replaced by a stop page naming the failing
  check (as the loader reports it), the record, and what was served, with
  "open anyway" behind a deliberate second click -- not a dismissible
  banner.
- Not yet checked (first visit before the background check lands, or no
  network to the registry): the page waits on a neutral screen; it does
  not run unverified.
- No settings to touch for the default scope. Settings exist for more
  canisters, the RPC endpoints, and Chrome's strict mode.

## How the extension's own package is verified

The same answer as the loader's (docs/LOADER.md), adapted to a package of
several files, and with no canister change. There are two packages,
`extension/` (Chrome) and `extension-firefox/`, and each gets the same
treatment and its own record.

- Each package is one directory in this repo with no build step, so the
  files a store installs are the files in git.
- `<package>/SHA256SUMS` is the package's file list:
  `node tools/extension-sums.mjs --write <package>` writes it and `--check`
  says whether it is current (tools/extension-sums-test.mjs checks both).
  One line per file, `<sha256>  <path>`, in byte order of path, over every
  file but `SHA256SUMS` itself and what a store adds (Chrome's
  `_metadata/`, the `.xpi` signature in `META-INF/`).
- Every file is listed by the sha256 of its bytes but one: Chrome's
  installer re-serializes `manifest.json` and adds `update_url` and `key`
  (the package's public key, taken from the `.crx` header; it fixes the
  extension id), so `manifest.json` is listed by the sha256 of its
  canonical JSON -- keys sorted, no whitespace, those two removed. An
  honest install lists the same; a manifest with any other value changed
  does not. The same rule applies to the Firefox package, whose `.xpi`
  keeps the packaged bytes anyway, so one tool checks both. Chrome also
  re-encodes images the manifest names and rewrites `_locales/`; neither
  package has any.
- The two are checked before they are left out, because the files alone
  do not say whose package this is: the same files repackaged under
  another key would be another extension, with its own id and its own
  updates to come, and would digest the same. So the tool refuses a copy
  whose `update_url` is not the Chrome Web Store's, and a copy with a
  `key` unless `--id` names the id it gives (the Releases table carries
  it; the Chrome package carries no `key` of its own, as the store assigns
  one). The Firefox package needs no `--id`: its id is in the manifest it
  ships (`browser_specific_settings.gecko.id`), which the listing covers.
- The canister repos `ic-git-extension` and `ic-git-extension-firefox`
  have their site roots set to those files (a site root may name a blob),
  and `evm_registry_publish_site` records
  `<repo>#site = (commit, sha256(SHA256SUMS))`. Check E scans the listing
  -- a root whose name has no extension is scanned, not exempted -- and it
  passes because no line holds a `<` (the tool refuses a path that does).
- A user, once per release: point the tool at the installed files
  (Chrome: `.../Extensions/<id>/<version>/`, with `--id <id>` from the
  Releases table; Firefox: the `.xpi`, unzipped) with `--digest`, and
  compare the result with the record's `bundleHash`, read as for the
  loader (docs/LOADER.md, "What a user does"). The tool needs only node,
  and is short enough to read first. A store updates the extension on its
  own, so the check holds for the files it was run on; the record is
  published before the store is, and a release is the cue to run it
  again.
- Auditors can skip the stores: clone at the recorded commit and load the
  package directory unpacked.
- The extension can hash its own files (`runtime.getURL`) and show whether
  they match the record. That catches an honest mismatch (an unpublished
  update) and nothing more: a tampered extension would lie about itself.
  The first check is the user's, with their own tools. (Not built yet.)

Store updates are automatic, so a release is published on chain before it
is submitted to a store, and the Releases table carries the version.

### Publishing a release (operator, mainnet)

From a checkout of `main` with the release merged, as an operator
identity, for each package -- `extension` with repo `ic-git-extension`,
`extension-firefox` with repo `ic-git-extension-firefox`. Operators pay no
cycles; each publish spends a little Sepolia gas from the canister's EOA.

```sh
C=umobs-yiaaa-aaaab-agyrq-cai
PKG=extension; REPO=ic-git-extension          # or extension-firefox, ic-git-extension-firefox

# 0. The listing is current (it is committed with the release).
node tools/extension-sums.mjs --check $PKG

# 1. First time only: the repo, with its site root at the listing.
dfx canister --network ic call $C create_repo "(\"$REPO\")"
dfx canister --network ic call $C set_site "(\"$REPO\", \"$PKG/SHA256SUMS\")"

# 2. Push main.
TOKEN=$(dfx canister --network ic call $C create_push_token "(\"$REPO\", opt (1 : nat32), null)" \
  | sed -n 's/.*Ok = "\([0-9a-f]*\)".*/\1/p')
: "${TOKEN:?create_push_token returned no token}"
git push "https://ic:$TOKEN@$C.raw.icp0.io/$REPO.git" main

# 3. The canister serves the listing in git (from a terminal, not a browser).
git show main:$PKG/SHA256SUMS | shasum -a 256
curl -s "https://$C.raw.icp0.io/site/$REPO/" | shasum -a 256

# 4. Publish, then confirm as for the loader (docs/LOADER.md, step 5).
dfx canister --network ic call $C evm_registry_publish_site "(\"$REPO\")"
node tools/verify.mjs $REPO / --record site
```

Then add a row to "Releases" below.

### Releases

| Date | Package | Version | Store id | Commit | sha256 of SHA256SUMS | Registry tx |
|---|---|---|---|---|---|---|
| 2026-10-01 | Chrome (`ic-git-extension`) | 0.1.0 | `0e80cf60a1e6530bd2565260f98c809f67551f53` | `c766bcb27281c20c5564eb322d63e094beaefd970b56e16b315ec740410a8a3a` | [`0xe1ad2e004523fba7f117c0eb65cc06b76f38621eae4fcf3655efdb8fa898f8bb`](https://sepolia.etherscan.io/tx/0xe1ad2e004523fba7f117c0eb65cc06b76f38621eae4fcf3655efdb8fa898f8bb) (Sepolia, block 11822489) |
| 2026-10-01 | Firefox (`ic-git-extension-firefox`) | 0.1.0 | `0e80cf60a1e6530bd2565260f98c809f67551f53` | `6df0039686c702bff3207feaed50acfdedf257ef0016797a1805a8acb06d77f7` | [`0x4ddb7587547dd46fdcdc18e99138ffbaed945c73c4617d90dc9f9ece5a92593a`](https://sepolia.etherscan.io/tx/0x4ddb7587547dd46fdcdc18e99138ffbaed945c73c4617d90dc9f9ece5a92593a) (Sepolia, block 11822495) | |

## What it does not do (yet)

- The certified module-hash read and the K-of-N attestations (ATTESTATION.md
  steps 2 to 4): the extension verifies the frontend against the record,
  not the canister's running code. It is built so those steps slot in
  behind the same stop page.
- Pages outside `/site/` on ic-git canisters, and other hosting.
- Safari: its web extensions have neither `filterResponseData` nor, as far
  as we know, CSP injection on responses; unexamined.

## Order of work

1. Done: the Chrome spikes (above) -- Chrome is buildable.
2. Done: the shared core. `core/verifier.js` is the source; the loader
   inlines it byte-identical (`tools/sync-core.mjs`, checked by
   tools/loader-test.mjs), and the extension's background worker will
   `importScripts` it. It gained `derivePolicy(bytes, url)`, the pinned
   policy above, written without a DOM (a service worker has none) and
   checked against a second derivation from the browser's own parser on
   both live pages; on both it produces exactly the policies tested here.
3. Done: the Chrome extension (`extension/`, tests in
   `tools/extension-test.mjs`) -- background verification through two
   RPCs, the static and pinned rules, the replaced document, the stop
   page with "check again" and a two-click "open anyway", the toolbar
   badge. Tried in branded Chrome on macOS, loaded unpacked, 2026-09-30:
   with the machine's TLS-inspecting proxy (NordVPN Threat Protection)
   on, the console was stopped -- served hash 212c0fd7 against the
   record, check E naming the proxy's injected script; with it paused,
   "check again" verified and the console ran; OISY sign-in, and a push
   token minted and revoked, all through the replaced document. That
   test found a result reused after failure (a reload kept showing the
   stop page until the entry went stale); failures are now rechecked on
   every visit.
3a. Done: ic-vote inlines its stylesheet at staging (ic-vote #9), served
   and recorded at commit 4c500e4; both extensions now pin and run it.
4. Done, but for a wallet in a real Firefox: the Firefox extension
   (`extension-firefox/`, tests in `tools/extension-firefox-test.mjs`),
   holding the response as above and sharing the core and the content
   script (stop page included) with Chrome through `tools/sync-core.mjs`.
5. Tighten check E to the derived policy's contract (inline handlers,
   `javascript:` URLs, workers, `style=` attributes, external stylesheets,
   and the import chain of a pinned module), so a page that publishes is a
   page that runs under the extension; the canister and the shared
   scanner block together.
6. Done but for publishing: `extension/SHA256SUMS` and
   `extension-firefox/SHA256SUMS`, `tools/extension-sums.mjs` (tested by
   `tools/extension-sums-test.mjs`), the operator steps and the Releases
   table above, and both records published (2026-10-01, Releases below).
   Left: submit to the stores, and check the first store-installed copy
   with `--digest` before users are told to rely on it.
