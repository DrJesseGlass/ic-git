# The verifier extensions

Two browser extensions check every page they open on an ic-git canister's
sites against the page's registry record, before anything on it runs, and
stop the page if it is not the recorded one. They check the page where it
is, on its own origin, so wallets and sign-in work as on the live site --
which the loader (docs/LOADER.md), running the page on its own origin,
cannot offer. This is the F2 rung of VISION.md.

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
ic-vote does at staging. A page the policy cannot pin exactly is refused
as "verified but cannot be protected" rather than guessed at.

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
- The derived policy is stricter than check E: it refuses inline event
  handlers, `javascript:` URLs, workers, `style=` attributes and external
  stylesheets, which check E lets through. Until check E is tightened to
  match (below), a page that publishes can still be stopped as unpinnable.

## What the user sees

- Verified: the page, as published. The toolbar badge says OK, with the
  commit on hover.
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
- `node tools/loader-test.mjs` covers the core and `derivePolicy`, and
  that every copy of the core is in step with `core/verifier.js`.
- Real browsers, macOS, with NordVPN Threat Protection (a TLS-inspecting
  proxy that injects a script into every page): Chrome 2026-09-30 and
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
9. A rule or listener without host permission for the page does nothing.

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
- `node tools/extension-sums.mjs` prints a listing; `--digest` its hash,
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

# Publish, then confirm.
dfx canister --network ic call $C evm_registry_publish_site "(\"$REPO\")"
node tools/verify.mjs $REPO / --record site
```

Then add a row to Releases.

### Releases

The newest row per package is current. 0.1.0 was published but never
submitted to a store; 0.1.1 supersedes it.

| Date | Package | Version | Commit | sha256 of SHA256SUMS | Registry tx | Chrome store id |
|---|---|---|---|---|---|---|
| 2026-10-01 | Chrome (`ic-git-extension`) | 0.1.0 | `0e80cf60a1e6530bd2565260f98c809f67551f53` | `c766bcb27281c20c5564eb322d63e094beaefd970b56e16b315ec740410a8a3a` | [`0xe1ad2e00...f8bb`](https://sepolia.etherscan.io/tx/0xe1ad2e004523fba7f117c0eb65cc06b76f38621eae4fcf3655efdb8fa898f8bb) (Sepolia 11822489) | -- |
| 2026-10-01 | Firefox (`ic-git-extension-firefox`) | 0.1.0 | `0e80cf60a1e6530bd2565260f98c809f67551f53` | `6df0039686c702bff3207feaed50acfdedf257ef0016797a1805a8acb06d77f7` | [`0x4ddb7587...593a`](https://sepolia.etherscan.io/tx/0x4ddb7587547dd46fdcdc18e99138ffbaed945c73c4617d90dc9f9ece5a92593a) (Sepolia 11822495) | n/a |

## Next

- Tighten check E to the derived policy (inline handlers, `javascript:`
  URLs, workers, `style=` attributes, external stylesheets, a pinned
  module's import chain), in the canister and the shared scanner together,
  so a page that publishes is a page the extensions run.
- Check the first store-installed copy of each package with `--digest`
  before users are told to rely on it (docs/STORE.md).
- The extension hashing its own files and showing whether they match the
  record: catches an unpublished update, not a tampered extension, which
  would lie about itself.
- The certified module-hash read and the K-of-N attestations
  (docs/ATTESTATION.md): today the extensions verify the frontend, not the
  canister's running code; those checks would sit behind the same stop
  page.
- Safari (no `filterResponseData`; CSP injection unexamined), other
  hosting, and pages outside `/site/`.
