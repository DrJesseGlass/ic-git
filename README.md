# ic-git

A minimal git remote that runs *on* the Internet Computer: one Rust canister
speaking git's smart-HTTP protocol, objects in stable memory, and (soon) an
asset-canister deploy triggered by every push to `main`.

Design: [ARCHITECTURE.md](ARCHITECTURE.md). Built on
[ic-dev-kit-rs](https://github.com/DrJesseGlass/ic-dev-kit-rs).

**Status: milestone 2.** `git clone`, `git ls-remote`, and `git fetch`/`pull`
work with a stock git client, including multi-chunk streamed packs for
larger repos. `push` (m3) and deploy-on-main (m4) are stubs; until m3 lands,
`tools/seed-repo.sh` uploads a local repo's objects and refs via the admin
API.

## Quick start (local)

```sh
dfx start --clean --background
dfx deploy git

# Seed any local git repo into the canister (push arrives in milestone 3)
tools/seed-repo.sh /path/to/some/repo hello

# Stock git against the local HTTP gateway (note `.raw.` - the non-raw
# gateway enforces response certification and returns 503):
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
