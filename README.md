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
tools/seed-repo.sh      upload a local repo via the admin API (pre-m3 push)
site/                   placeholder content for the asset canister ("www")
ARCHITECTURE.md         the design
```

## Development

```sh
cargo check
cargo test
```

Admin API calls (`create_repo`, `put_object`, `set_ref`) are restricted to
authorized principals - the deploying identity is authorized at init
(`auth::init_with_caller`), and the allowlist survives upgrades via a stable
snapshot.
