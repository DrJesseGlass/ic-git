# Submitting the extensions to the stores

Both stores take the package as a zip of the package directory, exactly as
committed. Build it from git, not from the working tree, so nothing local
(Chrome's `_metadata/`, a `.DS_Store`) gets in:

```sh
V=$(git show main:extension/manifest.json | node -p 'JSON.parse(require("fs").readFileSync(0, "utf8")).version')
git archive --format=zip -o ic-git-verifier-chrome-$V.zip main:extension
git archive --format=zip -o ic-git-verifier-firefox-$V.zip main:extension-firefox
```

Order, every release: the package's record is published on chain first
(docs/EXTENSION.md, "Publishing a release"), then the zip is submitted,
then the first store-installed copy is checked against the record (below)
before users are told to check theirs. Stores update installs
automatically, so a version must never reach a store before its record.

The packages carry no icons on purpose: Chrome re-encodes images the
manifest names, which would make an honest install hash differently. The
store icon is uploaded in the listing instead, outside the package; the
toolbar shows the browser's default icon.

## What to enter

The same text serves both stores.

**Name:** ic-git verifier

**Summary (short description):** Checks ic-git sites against their
on-chain record before they run, runs only the verified page, and lets it
call only approved canisters.

**Description:**

> Sites served by ic-git (a git host on the Internet Computer) publish a
> record of each page they serve to a public registry contract on chain.
> This extension checks every page it opens on those sites against that
> record before anything on it runs: the page's hash, the git commit it
> came from (every object checked against its own hash), and that
> everything it loads is pinned. If the page is not the recorded one --
> because a proxy, gateway or anyone in between changed it -- the page is
> stopped and you are told which check failed. If it is, only the
> verified page's own scripts are allowed to run.
>
> It also checks what the page talks to. Before the page may call a
> canister, the extension reads that canister's code hash and controllers
> from the Internet Computer's signed state certificate, verified against
> the network's public key. A backend that only ic-git controls, running
> the build its voters approved and recorded on chain, is allowed; so are
> the Internet Computer's own ledgers. A backend whose owner can change it
> without a vote is allowed with a warning; a call to any other canister
> is blocked, and the extension says which canister and why.
>
> It reads public records only: the page itself, the ic-git canister's
> public queries, and the registry through two public Ethereum RPC
> endpoints that must agree. To look a site's record up it has to name
> the site (and, for the backend check, the canisters it calls), so the operators of those endpoints -- the Internet Computer's
> public API gateway and the two RPC providers -- see which ic-git site
> is being checked and from which network address, when you open it and
> every ten minutes after while the browser stays open. That is all it
> sends: no page content, nothing you type, no identifier, and nothing to
> the extension's authors, who run no server and collect nothing.
>
> Its source, and the hash of every file in this package, are public and
> recorded on chain, so you can check the copy you installed: see
> docs/EXTENSION.md in the ic-git repository.

**Category:** Developer Tools (Chrome) / Privacy & Security (Firefox).

**Single purpose (Chrome):** Verify pages served from the ic-git canister
against their on-chain record before they run, and block pages that do
not match.

**Permission justifications (Chrome):**

- `declarativeNetRequest`: to set a Content-Security-Policy on pages of
  the ic-git canister -- no scripts until a page verifies, then only that
  page's own scripts -- and to send `/site/<repo>` to `/site/<repo>/`, the
  address its record covers.
- `storage`: to remember, for the browser session, which sites verified
  and with which policy, so a verified page needs no second check.
- `alarms`: to re-check verified sites every ten minutes, so a new record
  takes effect without waiting for a visit.
- Host permission `umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io`: the ic-git
  canister whose pages are verified.
- Host permission `icp-api.io`: the Internet Computer's public query
  endpoint, to read the canister's git objects for the commit check.
- Host permissions `ethereum-sepolia-rpc.publicnode.com` and
  `sepolia.gateway.tenderly.co`: two public RPC endpoints, read together,
  for the on-chain record.

**Host permissions (Firefox, new in 0.2.0):** `icp0.io`, `*.icp0.io`,
`ic0.app`, `*.ic0.app`, so the extension can see and cancel a verified
page's calls to the Internet Computer through those gateways when they
name a canister that is not approved. It reads only the request's address
(which canister), never its body, and acts only on requests made by
ic-git pages. Chrome needs no new permission: its block rule is
declarative and limited to requests from the ic-git canister's pages.

**Remote code (Chrome):** No. All code is in the package; the extension
runs none it fetches.

**Data usage (Chrome privacy tab):** tick "Web history" and no other
category -- the lookups name the site being checked, and Chrome counts
anything sent off the device as collected, whoever receives it; certify
the three disclosures (no sale, no unrelated use, no creditworthiness
use).

**Privacy policy URL:**
https://drjesseglass.github.io/ic-git/privacy/ -- a page of its own
(`docs/privacy/index.html`, served by GitHub Pages from `/docs`); the
Chrome Web Store rejected the GitHub file view of PRIVACY.md as not a
privacy policy page

**Firefox data collection:** the manifest declares browsing activity as
required (`data_collection_permissions: { required: ["browsingActivity"] }`),
for the same lookups: Mozilla counts any data sent outside the browser,
and the name of the site being checked goes to `icp-api.io` and the two
RPC endpoints. Firefox shows this at install. Nothing else is sent, so no
other category is declared.

**Firefox source code:** not needed -- nothing is minified or built.

**Firefox: listed or unlisted.** Listed puts it on addons.mozilla.org
after review. Unlisted gets a signed `.xpi` back, usually within minutes,
to host and link yourself; it is the quicker first step, and the
installed-copy check below works the same on it.

**Graphics:** in `store/`, outside both packages: `store-icon-128.png`
(from `icon.svg`; Chrome requires a 128x128 store icon in the listing),
and two 1280x800 screenshots taken from the extension under test --
`screenshot-checking-1280x800.png` (a first visit) and
`screenshot-stopped-1280x800.png` (a page altered in transit, stopped).

## Checking the first store-installed copy

Install from the store into a normal browser profile, then point the tool
at the installed files and compare with the record's `bundleHash`:

- Chrome (macOS):
  `~/Library/Application Support/Google/Chrome/Default/Extensions/fdcegfanhmpdnbcalfjdlboebhknkhco/<version>_0/`
  -- the id is on `chrome://extensions` with Developer mode on. The
  installed manifest carries the store's `key`, so the tool needs the id
  it must give (`--id`), and refuses the copy without it.
  ```sh
  node tools/extension-sums.mjs --digest --id fdcegfanhmpdnbcalfjdlboebhknkhco "$HOME/Library/Application Support/Google/Chrome/Default/Extensions/fdcegfanhmpdnbcalfjdlboebhknkhco/<version>_0"
  ```
- Firefox (macOS): the signed `.xpi` in
  `~/Library/Application Support/Firefox/Profiles/<profile>/extensions/verifier@ic-git.dev.xpi`.
  ```sh
  mkdir /tmp/ffx && unzip -q ".../extensions/verifier@ic-git.dev.xpi" -d /tmp/ffx
  node tools/extension-sums.mjs --digest /tmp/ffx
  ```

The digest must equal the package's `bundleHash` (docs/EXTENSION.md,
"Releases"). If it does not, `node tools/extension-sums.mjs <dir>` lists
the installed files; compare with the package's `SHA256SUMS` to see which
file the store changed, and extend the tool's rules (and its tests) for
that change before users are told to rely on the check.
