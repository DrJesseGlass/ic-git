# Reproducible build -- proving the ic-git backend runs its claimed source

The whole ic-git provenance stack (verifiable frontends, on-chain builds,
registry attestations) rests on one unproven assumption: that the canister
**doing** the serving and attesting is itself running the code we published.
This document closes that gap for the canister
`umobs-yiaaa-aaaab-agyrq-cai`.

## The claim

> The IC reports a **module hash** for the canister -- the sha256 of the wasm
> it is running -- in its certified state. Anyone can read it without trusting
> us. If you rebuild this source and get the same hash, the running canister
> **is** this source. No trust in the deployer, the operator, or the
> canister's own claims.

The module hash the IC reports is not something the canister can forge; it
comes from the subnet. Reproducibility is what ties that unforgeable hash back
to auditable source.

## What is pinned (and why)

The output wasm is a deterministic function of exactly these inputs:

| Input | Pinned by | Note |
|---|---|---|
| Rust compiler | `rust-toolchain.toml` (`1.94.1`) | the rust version is embedded in the module's `icp:public dfx` metadata, so it is literally part of the hash |
| Dependencies | `Cargo.lock` (committed; a real `--locked` preflight, plus a post-build check that the lock did not move) | ic-cdk `0.20.2` etc. -- see below |
| Post-processing | dfx `0.31.0` | dfx's bundled `ic-wasm` runs `shrink` + adds candid/dfx metadata; the deployed artifact is this post-processed wasm, not raw `cargo` output |
| Build path | fixed `/build` in the container | keeps the source tree's own paths out of the wasm |
| Dependency paths | `tools/build-env.sh` | see below -- this, not the build path, is the main cross-machine non-determinism |
| Platform | `--platform=linux/amd64` in `Dockerfile.build` | an arm64 and an amd64 rebuild are not the same build |
| Base image | `BASE_IMAGE` build arg (tag by default) | pass a `@sha256:` digest for the hardened form; the resolved digest belongs in the attested `BuildDescriptor` |

**The dependency-path pin is load-bearing.** `rustc` bakes absolute dependency
source paths into the module's data section -- panic locations, `file!()` --
so an unremapped build embeds strings like
`/Users/<someone>/.cargo/registry/src/index.crates.io-<hash>/lazy_static-1.5.0/src/inline_lazy.rs`.
There are hundreds of these in the artifact. A fixed `WORKDIR` does not touch
them: they come from `CARGO_HOME`, not the source tree, and `CARGO_HOME`
differs between every machine and the container. Without the remap the wasm
hash is a function of where the builder keeps their cargo registry, and no two
people can ever agree on it. The mapping has one definition, `tools/build-env.sh`,
sourced by `Dockerfile.build`'s build step and by `tools/reproducible-build.sh`'s
native branch -- so the two paths cannot drift apart. Build through the script
rather than calling `dfx build` directly, or the mapping is never applied.
(`tools/build-env.sh` explains why this is a shell fragment and not
`.cargo/config.toml`: Cargo has no declarative form that works at this pin.)

**The lockfile pin needs a real `--locked`.** `CARGO_NET_LOCKED` is not a Cargo
setting, despite reading like one. Measured against cargo 1.94.1:
`CARGO_NET_LOCKED=true cargo build` on a stale lock resolved new dependency
versions and rewrote `Cargo.lock` without a word, while `cargo build --locked`
failed with *"cannot update the lock file ... because --locked was passed"*.
dfx does not pass `--locked` through either. Both build paths therefore assert
it explicitly -- `cargo fetch --locked` in the container, `cargo metadata
--locked` natively -- and then re-check `Cargo.lock`'s sha256 after the build,
because a hash built against dependency versions nobody attested is exactly as
wrong as a hash built from the wrong source.

The dfx metadata section was inspected and contains only pinned tool versions
-- no timestamp, path, or git rev -- so the build is deterministic given the
pins above.

## Reproduce it

Portable (fixes the toolchain, dfx version, platform, and all paths):

```bash
tools/reproducible-build.sh --docker --check
```

This builds inside the pinned container and diffs the resulting sha256 against
the module hash the IC reports for the canister. A `MATCH` line is the proof.

Native convenience build (only meaningful if your host already matches the
pins):

```bash
tools/reproducible-build.sh --check
```

Read the on-chain hash yourself, independently, at any time:

```bash
dfx canister --network ic info umobs-yiaaa-aaaab-agyrq-cai | grep 'Module hash'
```

Exit codes: `0` match, `1` mismatch, `2` usage or dirty tree, `3` the on-chain
hash could not be read. `3` is deliberately distinct: "I could not reach the
chain" is not evidence of a mismatch and must never be reported as one.

Always reproduce from a **clean checkout of the attested commit** -- a dirty
tree or a different commit legitimately produces a different hash. The script
does not merely ask you to remember this. It refuses to build a tree with
uncommitted changes, prints the commit it is building, and hands the container
a `git archive` of that commit rather than the working directory, so local
edits are *absent by construction* rather than only forbidden. That matters
because an attestation naming a commit that never produced the hash is exactly
the substitution this whole chain exists to prevent. `--allow-dirty` falls back
to the working tree and marks the printed commit `-dirty`; never attest a
`-dirty` build.

> **Status note.** The currently deployed module was built before the
> path-remapping pins above existed, so it embeds the deployer's own
> `CARGO_HOME` paths. `--check` will therefore report `MISMATCH` against this
> source tree until the canister is redeployed from a build that uses them.
> That is the correct signal: the deployed artifact genuinely is not
> reproducible by anyone else, which is the gap these pins close. Redeploy and
> re-attest to make `MATCH` meaningful.

## Residual assumptions (stated honestly)

This is strong verifiability, not infinite. Two things it does *not* remove:

1. **Toolchain trust.** A reproducible build still assumes the pinned
   `rustc` / dfx / `ic-wasm` are not themselves backdoored. The mitigation is
   *diverse* rebuilders: many independent people reproducing the same hash
   turns "trust the toolchain" into "trust that they did not all collude."
   Only building the canister **on-chain** from attested source removes this
   residue entirely -- that is the self-hosting endgame this rung leads toward.

2. **Upgrade / temporal trust.** "Verified now" is not "verified forever" -- a
   controller can upgrade the canister to different code, which changes the
   module hash. The change is always *publicly visible*, but visibility is not
   prevention. Hardening spectrum: pin the expected hash and **monitor** it,
   then put upgrades under **governance** (a public proposal, not one key),
   then **blackhole** (remove controllers; code frozen, maximally verifiable
   but unfixable). Appropriate as components stabilize.

## Where this sits on the ladder

- **R1 (this):** reproducible build + on-chain-hash check. Shores up the
  off-chain-build weak link today, without an on-chain compiler.
- **R2:** the first app *built on* ic-git, on-chain, in the project's own DSL
  (`compile_lang` -> IC deploy -> attest) -- the same guarantee the frontends
  already enjoy, now for a real build.
- **R3:** ic-git itself, self-hosted -- building the canister on-chain from
  attested source, which removes the toolchain-trust residue above. The
  destination R1 makes credible in the meantime.
