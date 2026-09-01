# Verified deploys of the ic-git canister

Human-readable companion to `verified.json` (the machine-readable record that
`tools/check-module-hash.sh` and the scheduled watch read). How to reproduce
any row yourself: REPRODUCIBLE_BUILD.md. What a row does and does not prove:
the "Residual assumptions" and "Trusting trust" sections of the same file.

Canister: `umobs-yiaaa-aaaab-agyrq-cai`

| Date | Commit | Tag | Module hash (sha256 of the wasm) | On-chain match | Independent rebuilds |
|---|---|---|---|---|---|
| 2026-09-01 | `80bcb4a` | `v0.1.0` | `662990224e41ce296030ce04cb085055b15f2e1abe95b58892f1a93dd65aaec6` | MATCH, 2026-09-01 | deployer (pinned container, macOS arm64 host under Rosetta) |

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
