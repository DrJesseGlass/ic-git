# ic-git

A minimal git remote that runs *on* the Internet Computer: one Rust canister
speaking git's smart-HTTP protocol, objects in stable memory, and (soon) an
asset-canister deploy triggered by every push to `main`.

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

# Stock git against the local HTTP gateway (note `.raw.` - the non-raw
# gateway enforces response certification and returns 503):
git push "http://ic:$TOKEN@$(dfx canister id git).raw.localhost:$(dfx info webserver-port)/hello.git" main
git clone "http://$(dfx canister id git).raw.localhost:$(dfx info webserver-port)/hello.git"
```

On mainnet the remote URL is `https://<canister-id>.raw.icp0.io/<repo>.git`
(raw domain - see the "Trust model" section in ARCHITECTURE.md for why that's fine, and
sign your tags).

## Layout

```
canisters/git/          the git canister (Rust)
  src/store.rs          stable-memory objects/refs/repos
  src/smart_http.rs     pkt-line codec, services, ref advertisement
  src/pack.rs           closure walk, pack writer, streamed upload-pack
  src/lib.rs            HTTP routing + candid admin API
  src/site.rs           GET /site/<repo>/<path>: serve a committed static bundle
  src/api.rs            GET /api/...: read-only JSON for the repo browser
browser/index.html      the repo browser -- one self-contained page, served by
                        ic-git from its own repo (see "Repo browser")
tools/seed-repo.sh      upload a local repo via the admin API (pre-m3 push)
tools/reproducible-build.sh, tools/check-module-hash.sh
                        prove the deployed wasm is this source (REPRODUCIBLE_BUILD.md)
site/                   placeholder content for the asset canister ("www")
ARCHITECTURE.md         the design
```

## Repo browser

`browser/index.html` is a GitHub-style read-only browser: repositories,
branches and tags, commit log, trees, and files. It is one file with no
external resources, so the registry attestation of that single blob covers
every byte that runs (VISION.md section 2). It talks to the canister's own
`/api/...` routes on the same origin:

```
GET /api/repos                          [{name, head, site}]
GET /api/<repo>/refs                    [{name, oid}]
GET /api/<repo>/commits/<rev>?n=30      first-parent walk, newest first
GET /api/<repo>/commit/<rev>            one commit
GET /api/<repo>/tree/<rev>[/<path>]     {commit, path, entries: [{name, mode, kind, oid}]}
GET /api/<repo>/blob/<rev>/<path>       raw bytes, text/plain, nosniff
```

`<rev>` is `HEAD`, a 40-hex oid, or a bare branch/tag name. Every response
that resolved a commit carries `X-Ic-Git-Commit`.

ic-git hosts the browser from its own source: push this repository to the
canister as repo `ic-git`, point the site at the `browser` directory, and
attest it like any other frontend.

```sh
dfx canister --network ic call umobs-yiaaa-aaaab-agyrq-cai create_repo '("ic-git")'
TOKEN=$(dfx canister --network ic call umobs-yiaaa-aaaab-agyrq-cai create_push_token '("ic-git")' | sed -n 's/.*Ok = "\([0-9a-f]*\)".*/\1/p')
git push "https://ic:$TOKEN@umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io/ic-git.git" main
dfx canister --network ic call umobs-yiaaa-aaaab-agyrq-cai set_site '("ic-git", "browser")'
dfx canister --network ic call umobs-yiaaa-aaaab-agyrq-cai evm_registry_publish_site '("ic-git")'
node tools/verify.mjs ic-git index.html
```

The page is then at `https://umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io/site/ic-git/`
and browses, among other things, its own source.

## Development

```sh
cargo check
cargo test
```

Admin API calls (`create_repo`, `put_object`, `set_ref`) are restricted to
authorized principals - the deploying identity is authorized at init
(`auth::init_with_caller`), and the allowlist survives upgrades via a stable
snapshot.
