# ic-git

A minimal git remote that runs *on* the Internet Computer: a git canister
speaking git's smart-HTTP protocol, objects in stable memory, serving every
site it hosts; and an authority canister holding the accounts, the votes,
the deploys and the registry's key (docs/CANISTER_SPLIT.md). A push to
`main` can deploy.

Design: [ARCHITECTURE.md](ARCHITECTURE.md). Built on
[ic-dev-kit-rs](https://github.com/DrJesseGlass/ic-dev-kit-rs).

**Status: milestone 3.** `git clone`, `ls-remote`, `fetch`/`pull`, and
`git push` (token-authenticated, with thin-pack delta resolution,
connectivity and fast-forward checks) all work with a stock git client.
Deploy-on-main (m4) is next. `tools/seed-repo.sh` remains as a bulk-import
convenience.

## Quick start (local)

```sh
dfx start --clean --background
dfx deploy git

dfx canister call git create_repo '("hello")'
TOKEN=$(dfx canister call git create_push_token '("hello")' | sed -n 's/.*Ok = "\([0-9a-f]*\)".*/\1/p')

# Stock git against the local HTTP gateway (`.raw.`: the non-raw gateway
# serves git traffic too, declared uncertified, and the sites certified):
git push "http://ic:$TOKEN@$(dfx canister id git).raw.localhost:$(dfx info webserver-port)/hello.git" main
git clone "http://$(dfx canister id git).raw.localhost:$(dfx info webserver-port)/hello.git"
```

On mainnet the remote URL is
`https://34koz-jyaaa-aaaab-ahejq-cai.raw.icp0.io/<repo>.git`, the git
canister's host (raw domain - see the "Trust model" section in
ARCHITECTURE.md for why that's fine, and sign your tags). The old host,
`umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io`, answers a fetch with a redirect
there; a push needs the new remote.

## Layout

```
canisters/git/          the git canister (34koz-jyaaa-aaaab-ahejq-cai on mainnet):
                        the remote, the objects, every site
canisters/authority/    the authority (umobs-yiaaa-aaaab-agyrq-cai): accounts,
                        ballots, deploys, the registry's key
canisters/combined/     both sides in one module: the local build (`dfx deploy
                        git`) and the rollback artifact (docs/CANISTER_SPLIT.md)
  src/lib.rs            HTTP routing + candid admin API
crates/git/             the git side (docs/CANISTER_SPLIT.md)
  src/store.rs          stable-memory objects/refs/repos
  src/smart_http.rs     pkt-line codec, services, ref advertisement
  src/pack.rs           closure walk, pack writer, streamed upload-pack
  src/site.rs           GET /site/<repo>/<path>: serve a committed static bundle,
                        or GET /<path> at the site's own domain
  src/certify.rs        the certificate on every site response, which the
                        IC's verifying gateway and the custom domains need
  src/api.rs            GET /api/...: read-only JSON for the repo browser
crates/authority/       the authority: tenancy, ballots, deploys, provenance
crates/common/, crates/types/, crates/compiler/
                        shared storage helpers, the wire types and proof
                        checker, the .wat/.lang compiler
canisters/governor/     the governor: ic-git's only controller once handed
                        over; changes its code only by K-of-N vote
                        (docs/GOVERNOR.md; tools/governor.sh drives it)
browser/index.html      the repo browser -- one self-contained page, served by
                        ic-git from its own repo (see "Repo browser")
tools/seed-repo.sh      upload a local repo via the admin API (pre-m3 push)
tools/reproducible-build.sh, tools/check-module-hash.sh
                        prove the deployed wasm is this source (REPRODUCIBLE_BUILD.md)
tools/e2e-local.sh      end-to-end pass on a throwaway local replica, run
                        before every mainnet upgrade
tools/verify.mjs        check a served site against its registry record (CLI)
tools/console-routes-test.mjs
                        the console's routing between the two canisters, offline
core/verifier.js        the verification core: the loader inlines it and the
                        extension copies it (both synced by tools/sync-core.mjs);
                        readCanisterState reads a canister's module hash and
                        controllers from a certificate the IC signed
                        (docs/CERTIFIED.md; tools/certified-test.mjs)
core/bls12-381.js       the BLS verifier that check needs, vendored from
                        @noble/curves by tools/vendor-bls.mjs; generated, not edited
extension/              the Chrome extension: checks ic-git sites as they load
                        and shows only the checked page (docs/EXTENSION.md;
                        tools/extension-test.mjs drives it)
extension-firefox/      the Firefox extension: holds each page until what
                        arrived is the recorded page (docs/EXTENSION.md;
                        tools/extension-firefox-test.mjs drives it)
tools/extension-sums.mjs
                        each extension package's file list (SHA256SUMS), whose
                        hash is its registry record; also how a user checks
                        an installed copy
store/                  store-listing icon and screenshots (outside both
                        packages); docs/STORE.md is the submission guide
loader/index.html       the same check in a browser, then run the checked bytes
                        (see "Verifying a site in the browser")
site/                   placeholder content for the asset canister ("www")
ARCHITECTURE.md         the design
```

## Repo browser

`browser/index.html` is a GitHub-style read-only browser: repositories,
branches and tags, commit log, trees, and files. It is one file with no
external resources, so the registry attestation of that single blob covers
every byte that runs (VISION.md section 2). It talks to the git canister's
own `/api/...` routes on the page's origin (the tenancy routes further
down are the authority's; docs/TENANCY.md, "the console talks to both
canisters"):

```
GET /api/repos                          [{name, head, site}]
GET /api/<repo>/refs                    [{name, oid}]
GET /api/<repo>/commits/<rev>?n=30      first-parent walk, newest first
GET /api/<repo>/commit/<rev>            one commit
GET /api/<repo>/tree/<rev>[/<path>]     {commit, path, entries: [{name, mode, kind, oid}]}
GET /api/<repo>/blob/<rev>/<path>       raw bytes, text/plain, nosniff
GET /api/<repo>/diff/<rev>[?base=<rev>] {commit, base, files: [{path, status, old_path, old, new}], truncated}
GET /api/<repo>/compare/<rev>[?base=<rev>] {head, base, merge_base, ahead, behind, commits, truncated}
```

`/compare` is where `<rev>` (the head) and `base` (the repo's HEAD
unless named) part: their merge base (null for histories that share
nothing), how many commits each has that the other has not, and the
head's own, newest first (the newest 200; `truncated` says there are
more). What a branch changed is then `/diff/<head>?base=<merge_base>`.
The walk reads at most 2000 commits, counting both sides; two revs it
cannot place within that are answered 422.

`/diff` lists the files that differ between two commits' trees, from
`base` (the first parent unless named; null for a commit without one) to
`<rev>`: `status` is `added`, `deleted`, `modified` or `renamed` (the
same content gone from one path and come at one, with `old_path`), and
`old` and `new` are `{oid, mode, kind}` or null. The files come in path
order; `truncated` says the list stops short of them all (1000 files, or
a tree too vast to walk), and then no renames are paired. It reads no
blob; the lines are the reader's to work out from the two.

The commit view does that: under a commit it lists the files `/diff`
names and, for each, fetches the two blobs and shows the lines that
changed, compared in the page itself (the "diff" block of
`browser/index.html`; `node tools/browser-diff-test.mjs` holds it to
`git diff`). `#/<repo>/commit/<rev>/<base>` compares any two revs. A
binary file, a file over a megabyte and two versions more than 2000
changed lines apart are named and not compared.

`<rev>` is `HEAD`, a 40-hex oid, or a bare branch/tag name. Every response
that resolved a commit carries `X-Ic-Git-Commit`.

ic-git hosts the browser from its own source: push this repository to the
git canister as repo `ic-git`, point the site at the `browser` directory,
and attest it like any other frontend. The repo, its site and its record
are the authority's calls; the push token and the push are the git
canister's.

```sh
A=umobs-yiaaa-aaaab-agyrq-cai   # the authority
G=34koz-jyaaa-aaaab-ahejq-cai   # the git canister
dfx canister --network ic call $A create_repo '("ic-git")'
TOKEN=$(dfx canister --network ic call $G create_push_token '("ic-git")' | sed -n 's/.*Ok = "\([0-9a-f]*\)".*/\1/p')
git push "https://ic:$TOKEN@$G.raw.icp0.io/ic-git.git" main
dfx canister --network ic call $A set_site '("ic-git", "browser")'
dfx canister --network ic call $A evm_registry_publish_site '("ic-git")'
node tools/verify.mjs ic-git index.html
```

The page is then at `https://34koz-jyaaa-aaaab-ahejq-cai.raw.icp0.io/site/ic-git/`
and browses, among other things, its own source.

## Verifying a site in the browser

`loader/index.html` is a verifier you keep. Open it from disk (or any origin
you trust -- never from the canister it checks, which could serve a page
that claims success), enter a repo, and it:

1. reads `get("<repo>#site")` from the Sepolia registry, through your
   wallet's provider when one is injected and on Sepolia, else a public RPC;
2. fetches the served entrypoint and checks its sha256 against the record;
3. walks the recorded commit to that entrypoint through the canister's
   `get_object` query, checking every object against its SHA-1, and
   compares the blob with the served bytes;
4. scans the page for references the browser would not enforce (the same
   code as `tools/verify.mjs` check E);

and only when all pass offers **run it**, which runs the bytes it checked
rather than fetching them again. `?repo=ic-vote&run=1` does it in one step.

What it cannot do: the page runs on the loader's origin, so its storage and
any origin-bound sign-in are not the live site's, and a page that chooses
hosts from `location` instead of `document.baseURI` sees the loader's host.
For an always-on check of the live site, on its own origin, use the
browser extensions (docs/EXTENSION.md), which run the same core.

How a user gets a copy they can trust -- the loader's own hash, published
in the registry like any site -- and the operator steps to publish it are
in docs/LOADER.md.

`node tools/loader-test.mjs` runs that core against mainnet: both live sites
verify, a tampered page and a lying `get_object` both fail, and the scanner
is byte-identical to the CLI's.

## Accounts, ownership, and paying for what you use

ic-git is multi-tenant (design: docs/TENANCY.md). Any signed-in principal
with a funded balance can create a repo and owns it; owners add members as
**writers** (push, tokens, config) or **voters** (approve commits before the
deploy queue runs them, once `set_required_votes` is set). Tenants prepay in
cycles and are charged for creation, each push, storage rent, and each
deploy action; an action that would overdraw is refused first. Apps deployed
to the IC run in a canister the owner controls, created from their balance.

From the browser: open `/site/ic-git/` on the git canister's host, connect
a wallet (OISY), and use the console panels; the panel shows the wallet's
ICP and cycles ledger balances next to its ic-git balance. From the command
line, the same calls through dfx; the push tokens are the git canister's,
everything else the authority's:

```sh
C=umobs-yiaaa-aaaab-agyrq-cai   # the authority
G=34koz-jyaaa-aaaab-ahejq-cai   # the git canister
dfx canister --network https://icp-api.io call $C deposit_from_cycles_ledger '(2_000_000_000_000)'   # after icrc2_approve on the cycles ledger
dfx canister --network https://icp-api.io call $C deposit_from_icp '(50_000_000)'   # 0.5 ICP, after icrc2_approve on the ICP ledger for it plus 0.0001 ICP
dfx canister --network https://icp-api.io call $C pending_icp_deposits   # finish_icp_deposit(id) completes one whose conversion did not finish
dfx canister --network https://icp-api.io call $C create_repo '("myapp")'
dfx canister --network https://icp-api.io call $C add_member '("myapp", principal "<friend>", "voter")'
dfx canister --network https://icp-api.io call $C set_required_votes '("myapp", 1)'
dfx canister --network https://icp-api.io call $G create_push_token '("myapp", opt 90)'   # lifetime in days: default 30, max 365
dfx canister --network https://icp-api.io call $G list_push_tokens '("myapp")'
# Signed pushes: bind the token to your SSH key, and have git sign with it
dfx canister --network https://icp-api.io call $G create_push_token "(\"myapp\", null, opt \"$(cat ~/.ssh/id_ed25519.pub)\")"
git config gpg.format ssh && git config user.signingkey ~/.ssh/id_ed25519.pub && git config push.gpgSign if-asked
dfx canister --network https://icp-api.io call $C set_require_signed_push '("myapp", true)'   # optional: refuse unbound tokens
```

`GET /api/account/<principal>`, `/api/<repo>/info`, `/api/<repo>/votes/<commit>`
and `/api/pricing`, on the authority's host, expose the same state read-only. `GET /api/<repo>/deploys`
returns the wasm deploy config, the last attempt, and the provenance log
(commit, target, wasm sha256 per install), so a deployed app can name the
commit it actually came from rather than the branch tip (demo/README.md).

## License

Apache-2.0: LICENSE. The same for every crate in the workspace and for
the demo.

## Reporting

A bug: https://github.com/DrJesseGlass/ic-git/issues/new/choose. A security
problem: privately, through the form SECURITY.md names, never in a public
issue.

## Development

```sh
cargo check
cargo test
tools/e2e-local.sh   # before an upgrade: the whole user path on a local replica
```

`tools/e2e-local.sh` starts its own network (with the ICP ledger and the
CMC) on port 4950 from a temporary project, so a replica you already run is
untouched, and drives the current checkout the way users do: ICP deposits,
signed pushes over HTTP, tokens, the approval-gated site and deploy, the
ic-name-service announce (if `../ic-name-service` exists), an upgrade from
the previous release (`BASE_REF`, by default the newest tag) over state
that release wrote, and the console's reads. It prints PASS or FAIL per check and exits
non-zero on any failure; `KEEP=1` leaves the network up afterwards.

Admin API calls (`put_object`, `set_ref`, and the EVM, Solana, pricing and
other operator calls) are restricted to operators: each canister's controllers
and its admin allowlist. The deploying identity is put on the allowlist at
init (`auth::init_with_caller`), and the allowlist survives upgrades via a
stable snapshot. `create_repo` is open to any signed-in, funded caller (see
docs/TENANCY.md).
