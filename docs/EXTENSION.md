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
| Chrome | no, not without `chrome.debugger` | yes, by pinning scripts with CSP (below) |
| Chrome, `chrome.debugger` | yes: the DevTools `Fetch` domain | yes, but a permanent "is debugging this browser" bar |

### Firefox: hold the document until it verifies

`filterResponseData` streams the main-frame response through the extension
before the page sees a byte. The extension buffers it, runs the core, and
then either writes the bytes through unchanged or writes a block page in
their place. This is the strongest form: the page that runs is the page
that was checked, byte for byte, with no second fetch. Firefox keeps
blocking `webRequest` under Manifest V3, so this does not depend on MV2.

### Chrome: pin the page's scripts with a Content-Security-Policy

Chrome's Manifest V3 gives an extension no access to response bodies and no
blocking `webRequest` (except for extensions force-installed by enterprise
policy). A content script at `document_start` runs before the page's
scripts but cannot hold the parser, so checking "the bytes" means a second,
independent fetch -- which a MITM that rewrites every response consistently
(the NordVPN case in docs/LOADER.md) fails, but a targeted one could answer
differently.

What Chrome does let an extension do before the response is parsed is
change its headers, with `declarativeNetRequest` rules. So the extension
enforces the verified page's scripts instead of its bytes:

1. In the background, for each site in scope, read the record and verify
   the entrypoint (fetch, hash, object walk, scan) -- on install, on a
   timer, and whenever the record changes.
2. From the verified bytes, derive a policy that allows exactly the scripts
   that page runs: `script-src` listing the sha256 of each inline script and
   the `integrity` hash of each external one; `style-src` listing the
   sha256 of each inline `<style>` and the exact URL of each external
   stylesheet (Chrome takes no hash source for an external stylesheet; its
   `integrity`, which check E requires, still pins its contents);
   `object-src 'none'`, `base-uri 'none'`.
3. Install it as a session `declarativeNetRequest` rule that appends that
   `Content-Security-Policy` to the site's main-frame responses. Two CSPs
   both apply, so the page cannot loosen it. The rule applies only where
   the extension has host permission, so the manifest names the canisters
   in scope.

Now whatever the network delivers, only scripts identical to the verified
page's can run; an injected `<script src>` is refused by the browser, not
by us. What CSP does not stop is changed markup -- altered text or a fake
form without script -- so a content script also re-fetches the entrypoint
after load, compares, and replaces the page with the stop page on a
mismatch. A site whose record changes between the rule and the load simply
fails closed until the background check catches up.

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
   stylesheet by hash; by exact URL it loads, and ic-vote reached YELLOW
   styled with no refusals. Step 2 above says so. Wallet sign-in and
   writes were not exercised (headless, no wallet); they are the first
   thing to try in a real browser.
4. **The attack is refused.** A copy of ic-vote with an injected inline
   script and an injected `<script src>` (as the proxy does), under
   ic-vote's derived policy: both refused, and neither ran. Without the
   policy both ran. This needed host permission for the page's origin --
   a rule without it silently does nothing.

So Chrome gets script-level enforcement before anything runs; what it
does not get is Firefox's byte-level hold, which is why the post-load
recheck above stays.

`chrome.debugger` would give Chrome Firefox's guarantee, at the cost of the
debugging bar on every tab while it is attached. It is not the default; it
could be an opt-in "strict" mode for operators.

## How the extension sees the served bytes

- Firefox: the response itself, through `filterResponseData`.
- Chrome: its own fetch of the entrypoint from the background service
  worker, which goes through the same network stack as the page -- so a
  proxy that rewrites the page rewrites this copy too -- plus the policy
  above, which binds the page to that copy's scripts whatever it received.
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
several files, and with no canister change.

- The extension's source is one directory in this repo, `extension/`,
  with no build step, so the files a store installs are the files in git.
- `extension/SHA256SUMS` lists the sha256 of every other file in it, sorted
  by path. It is committed with each release.
- The canister repo `ic-git-extension` has its site root set to that file
  (`set_site("ic-git-extension", "extension/SHA256SUMS")`; a site root may
  name a blob), and `evm_registry_publish_site("ic-git-extension")` records
  `ic-git-extension#site = (commit, sha256(SHA256SUMS))`. SHA256SUMS is not
  markup, so check E does not apply to it.
- A user, once per release: find the installed files (Chrome:
  `.../Extensions/<id>/<version>/`, ignoring the store's `_metadata/`;
  Firefox: unzip the `.xpi`, ignoring `META-INF/`), run
  `tools/extension-sums.sh <dir>` -- or `shasum -a 256` over the files in
  path order, which is all it does -- and compare the digest of that
  listing with the record, exactly as for the loader.
- Auditors can skip the stores: clone at the recorded commit and load
  `extension/` unpacked.
- The extension can hash its own files (`runtime.getURL`) and show whether
  they match the record. That catches an honest mismatch (an unpublished
  update) and nothing more: a tampered extension would lie about itself.
  The first check is the user's, with their own tools.

Store updates are automatic, so a release is published on chain before it
is submitted to a store, and the Releases table carries the version.

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
2. The shared core as a module both the loader and the extension import
   byte-identical, the way the scanner block is shared today.
3. Chrome extension first, for its reach: background verification, the
   CSP rule, post-load recheck, stop page, toolbar state -- and wallet
   sign-in and a write tried on the console under the policy.
4. Firefox extension: `filterResponseData` and the same stop page; the
   recommended browser where the byte-level guarantee matters (operators,
   observers).
5. `extension/SHA256SUMS`, `tools/extension-sums.sh`, the `ic-git-extension`
   record, and a Releases table -- before the first store submission.
