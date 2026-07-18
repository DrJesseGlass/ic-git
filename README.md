# ic-git

A minimal git remote that runs *on* the Internet Computer: one Rust canister
speaking git's smart-HTTP protocol, objects in stable memory, and (soon) an
asset-canister deploy triggered by every push to `main`.

Design: [ARCHITECTURE.md](ARCHITECTURE.md). Built on
[ic-dev-kit-rs](https://github.com/DrJesseGlass/ic-dev-kit-rs).

**Status: milestone 1.** Object store, refs, auth-guarded admin API, and the
`info/refs` smart-HTTP advertisement - `git ls-remote` works. `clone` (m2),
`push` (m3), and deploy-on-main (m4) are stubs.

## Quick start (local)

```sh
dfx start --clean --background
dfx deploy git

dfx canister call git create_repo '("hello")'

# Seed an object and a ref (admin API; content is not validated at m1)
dfx canister call git put_object '("commit", blob "tree 0000000000000000000000000000000000000000\0a")'
# -> (variant { Ok = "<oid>" })
dfx canister call git set_ref '("hello", "refs/heads/main", "<oid>")'

# Stock git against the local HTTP gateway (note `.raw.` - the non-raw
# gateway enforces response certification and returns 503):
git ls-remote "http://$(dfx canister id git).raw.localhost:$(dfx info webserver-port)/hello.git"
```

On mainnet the remote URL is `https://<canister-id>.raw.icp0.io/<repo>.git`
(raw domain - see the "Trust model" section in ARCHITECTURE.md for why that's fine, and
sign your tags).

## Layout

```
canisters/git/          the git canister (Rust)
  src/store.rs          stable-memory objects/refs/repos
  src/smart_http.rs     pkt-line codec + ref advertisement
  src/lib.rs            HTTP routing + candid admin API
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
