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
| Dependencies | `Cargo.lock` (committed, built `--locked`) | ic-cdk `0.20.2` etc. |
| Post-processing | dfx `0.31.0` | dfx's bundled `ic-wasm` runs `shrink` + adds candid/dfx metadata; the deployed artifact is this post-processed wasm, not raw `cargo` output |
| Build path | fixed `/build` in the container | prevents host absolute paths leaking into the wasm `name` section -- the main cross-machine non-determinism |

The dfx metadata section was inspected and contains only pinned tool versions
-- no timestamp, path, or git rev -- so the build is deterministic given the
pins above.

## Reproduce it

Portable (fixes the toolchain, dfx version, and build path):

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

Always reproduce from a **clean checkout of the attested commit** -- a dirty
tree or a different commit legitimately produces a different hash.

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
