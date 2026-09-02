# Verified deploys of the ic-git canister

Human-readable companion to `verified.json` (the machine-readable record that
`tools/check-module-hash.sh` and the scheduled watch read). How to reproduce
any row yourself: REPRODUCIBLE_BUILD.md. What a row does and does not prove:
the "Residual assumptions" and "Trusting trust" sections of the same file.

Canister: `umobs-yiaaa-aaaab-agyrq-cai`

| Date | Commit | Tag | Module hash (sha256 of the wasm) | On-chain match | Independent rebuilds |
|---|---|---|---|---|---|
| 2026-09-01 | `80bcb4a` | `v0.1.0` | `662990224e41ce296030ce04cb085055b15f2e1abe95b58892f1a93dd65aaec6` | MATCH, 2026-09-01 | deployer (pinned container, macOS arm64 host under Rosetta) |
| 2026-09-01 | `0707147` | `v0.1.1` | `a7156c6dc5eaa03adf9fd1a691550ac702b8adf2bcf8bb7f4d27e2651c601557` | MATCH, 2026-09-01 | deployer (pinned container, two fresh VMs agreed); GitHub Actions amd64 runner, [run 33563166779](https://github.com/DrJesseGlass/ic-git/actions/runs/33563166779), MATCH |
| 2026-09-01 | `2dd941d` | `v0.1.2` | `268c18bbfeb0cda616a55fcd500e62fcfc267c77aa8f297ad046d69108718d8f` | MATCH, 2026-09-01 | deployer (pinned container) |
| 2026-09-02 | `9cdc58c` | `v0.2.0` | `278ebec09bc4d353da718a2751ce01dd74bb44804d1f99abf72b0e08d4b3541a` (gz) | MATCH, 2026-09-02 | deployer (pinned container); GitHub Actions amd64 runner, [run 33653643555](https://github.com/DrJesseGlass/ic-git/actions/runs/33653643555), MATCH |

## v0.2.0 -- 2026-09-02

Multi-tenancy (docs/TENANCY.md): accounts, ownership and roles, votes that
gate the deploy queue, storage rent and push fees, per-user app canisters,
and the wallet console. First release where the canister custodies tenant
balances, and the first installed as a gzipped module: the on-chain hash is
of `git_canister.wasm.gz`; the raw wasm inside hashes to `f49a6d04...360c`,
identical to the build of the merge commit `37e2c3e` before the gzip step
was added, so the recipe change touched nothing in the module.

## v0.1.2 -- 2026-09-01

Adds the read-only JSON API (`/api/...`) and the self-hosted repo browser
(`browser/index.html`). Same recipe and base-image digest as before. The
pre-merge commit `cc3aa28` and the merge commit `2dd941d` produced the same
hash: the review follow-up between them changed only the page, doc comments
and tests, none of which reach the wasm.

## v0.1.1 -- 2026-09-01

Adds admin-allowlist management (`authorize`, `deauthorize`,
`list_authorized`) so a controller cutover can hand over the admin API, not
only the upgrade key. Same recipe and base-image digest as v0.1.0. The hash
was produced twice on two freshly created VMs (the first VM's disk was
corrupted by a full host disk after the compile had already printed the
hash; the rebuild on a new VM printed the same one). A GitHub Actions runner,
native x86_64 and sharing no machine with the deployer, then rebuilt the tag
and reported MATCH against the live module hash: K=2 in the pinned-container
lineage.

## v0.1.0 -- 2026-09-01

The first build of this canister that anyone other than the deployer can
reproduce. The module that ran before it (hash `736e2344...`) was built before
the path-remapping pins existed and embedded the deployer's own cargo registry
paths, so no second machine could ever have matched it; that is the gap this
row closes.

Recipe: `Dockerfile.build` at the tagged commit, `--platform=linux/amd64`,
rustc 1.94.1 (`rust-toolchain.toml`), dfx 0.31.0 in the container, base image
`rust:1.94.1-slim-bookworm` resolved to
`sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2`.

Two builds from two contexts agreed byte-for-byte before the deploy, and the
canister was then upgraded with that exact artifact; `--check` from the tagged
commit reported MATCH against the live module hash the same day. The builds: one from
a working checkout, one from a detached clean worktree of the tag running the
tag's own `tools/reproducible-build.sh --docker --check`. The artifact
contains zero host paths (`strings | grep /Users` is empty; every dependency
path reads `/cargo/registry/...`).

Lineage caveat, stated once so nobody reads the table as more than it is:
every rebuild listed above is the *pinned-container* lineage. It verifies the
source and the recipe. It does not verify the toolchain; a diverse-toolchain
rebuild (see "Trusting trust") is still an open row.
