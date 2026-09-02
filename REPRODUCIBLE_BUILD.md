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

> **Status.** Reproducible and matched since 2026-09-01. The commit the live
> module was built from is the **last entry of `verified.json`** (narrative in
> VERIFIED.md); rebuild that commit, not whichever tag this sentence might
> name, because the deploy moves and this paragraph does not. The module
> deployed before 2026-09-01 was built before these pins existed, embedded the
> deployer's `CARGO_HOME` paths, and was therefore reproducible by nobody. The
> watch below fails if the live hash ever departs from the last entry.

## Deploying the artifact

Install the container's output, never a native build, so the on-chain hash
equals the reproducible one by construction:

```bash
dfx canister --network https://icp-api.io --identity <controller> \
  install umobs-yiaaa-aaaab-agyrq-cai --mode upgrade --wasm <container-out>.wasm --yes
```

The module is above the 2 MiB ingress limit, so dfx uploads it in 1 MiB
chunks. The HTTP gateway (`icp0.io`, what `--network ic` uses) buffers each
chunk with a timeout that a slow uplink trips -- the symptom is `408 Request
Timeout ... Unable to buffer body`, and nothing changes on chain. The API
boundary node (`https://icp-api.io`) takes the same calls without the
gateway's buffering and measured about three times faster from the same
machine; dfx accepts the URL directly as the network name.

## The record: `verified.json`

A MATCH that only scrolled past in one terminal is not evidence anyone else
can use. Every verified deploy is recorded in `verified.json` at the repo
root -- one entry per (commit, module hash), newest last -- with the commit,
tag, module hash, the pinned tool versions, the *resolved* base-image digest,
and who reproduced it under which toolchain lineage. The file is the
machine-readable half of the `BuildDescriptor` in docs/ATTESTATION.md and the
source of truth for the monitor below; VERIFIED.md is the human-readable
narrative next to it.

Two independent observers, standing:

- **CI rebuilder** (`.github/workflows/reproducible-build.yml`): a native
  linux/amd64 GitHub runner that shares no machine with the deployer runs the
  same pinned container on every `v*` tag (and on demand, for any ref, with
  `--check`), prints the hash, and keeps the wasm it built as a downloadable
  artifact. Agreement between the deployer's build and CI's is K=2 in the
  pinned-container lineage: it rules out source substitution and a lying
  deployer, and says nothing about the toolchain (see below).
- **Module-hash watch** (`.github/workflows/module-hash-watch.yml`, or
  `tools/check-module-hash.sh` locally): every six hours, read the live module
  hash through a certificate-verifying client and compare it with the latest
  `verified.json` entry. A change is either a deploy that has not been
  reproduced and recorded yet, or an unauthorized upgrade; either way the job
  fails and the owner is notified. This is the cheapest rung of the
  upgrade-trust spectrum in "Residual assumptions" below: monitor first,
  governance later.

## Residual assumptions (stated honestly)

This is strong verifiability, not infinite. Two things it does *not* remove:

1. **Toolchain trust.** A reproducible build still assumes the pinned
   `rustc` / dfx / `ic-wasm` are not themselves backdoored. The mitigation is
   *diverse* rebuilders: independent people reproducing the same hash with
   toolchains that do not share a lineage turns "trust the toolchain" into
   "trust that they did not all collude." The word *diverse* is load-bearing
   and our current pins work against it -- see the next section, which is
   also where the self-hosting endgame gets its honest accounting.

2. **Upgrade / temporal trust.** "Verified now" is not "verified forever" -- a
   controller can upgrade the canister to different code, which changes the
   module hash. The change is always *publicly visible*, but visibility is not
   prevention. Hardening spectrum: pin the expected hash and **monitor** it,
   then put upgrades under **governance** (a public proposal, not one key),
   then **blackhole** (remove controllers; code frozen, maximally verifiable
   but unfixable). Appropriate as components stabilize.

## Trusting trust, and what K-of-N actually buys

Residual assumption 1 is not a footnote. It is Thompson's problem, and the
ladder below has to answer it out loud or R3 is a slogan.

**The attack.** In his 1984 Turing Award lecture, *Reflections on Trusting
Trust*, Ken Thompson describes a compiler that inserts a backdoor into a
target program and -- the part that matters -- also recognizes when it is
compiling *its own source*, reinserting both the backdoor and the recognizer
into the new compiler binary. The backdoor is then deleted from the compiler's
source. Every line anyone can read is clean. Every rebuild from that clean
source reproduces the backdoor, indefinitely, with nothing a source review
could find. Reproducibility does not help here; it makes it worse. The build
is perfectly deterministic *and* perfectly compromised, so all N rebuilders
get the same hash and all N are wrong together.

**Why the self-hosting chain does not, by itself, answer it.** The appeal of
R3 is that version N+1 of the on-chain compiler is compiled by version N,
which was compiled by N-1, back to a root that humans reviewed once. It is
worth building. But as a *trust* argument it is exactly the structure Thompson
subverted: a chain in which every link is checked by the previous link
inherits whatever the previous link was hiding, and adding links does not
dilute it. If the root binary -- or any binary along the way -- carried the
quine, every descendant carries it and every step's check passes. Chain length
is not evidence.

**What the chain does buy is review economy, which is a different and real
thing.** Each N -> N+1 step is a small diff. A reviewer who has read the root
once thereafter reviews deltas instead of a compiler from scratch, and a
malicious change has to survive line-by-line reading at the size where humans
are actually good at it. Front-loading the expensive review once and paying a
small marginal cost per version genuinely beats "audit the whole toolchain,
forever, or trust it." That is a claim about the *cost of the human check*,
not about removing the need for one, and it should never be stated as though
it closed the Thompson gap.

**What answers Thompson is diversity, not depth.** David A. Wheeler's *diverse
double-compiling* (DDC; ACSAC 2005, dissertation 2009) is the standard result.
Given compiler source `Sc` and a claimed binary `A` said to be built from it,
take a second, independently produced compiler `B` -- one that shares no
lineage with `A` -- and compute `X = B(Sc)`. `X` is functionally the same
compiler as `A` but is not bit-identical to it, because `B`'s codegen differs.
The *double* compile is what recovers bit-identity: `X(Sc)` and `A(Sc)` are
both `Sc` compiling itself, so if `A` is honest they agree bit-for-bit, and if
`A` carries the quine they do not. Diversity of the second compiler is what
makes the comparison informative; nothing about the length of `A`'s own
ancestry does.

Applied here, the check is not "use a different compiler," which would just
produce a different wasm for uninteresting reasons. It is: build the *pinned*
`rustc` from its own source through a different bootstrap path -- a
distro-packaged toolchain, or the mrustc/Guix full-source bootstrap -- and
then build ic-git with the result. That wasm should be bit-identical to the
attested one. The practical difficulty is that rustc's codegen depends on how
rustc itself was configured, above all the LLVM version linked into it, so the
diverse builder has to match rustc's build configuration or the outputs differ
for reasons that have nothing to do with a backdoor. Making that reproducible
is real work. It is why this is a rung, not a checkbox.

**K-of-N reproducible builds are DDC executed in public -- but only if the N
are actually diverse, and right now they are not.** Everything in "What is
pinned" pushes reviewers toward *one* environment: `--platform=linux/amd64`,
one `BASE_IMAGE`, the exact `rustc` that `rust-toolchain.toml` names, fetched
from the same place by everyone. N reviewers agreeing under those pins is
strong evidence about the *source and the recipe* -- it catches source
substitution, dependency drift, a lying deployer -- and it is no evidence at
all about the toolchain. A subverted `rustc 1.94.1` tarball would be
reproduced identically by all N, and K-of-N would report GREEN with complete
confidence. Determinism pins and DDC diversity pull in opposite directions,
and both are necessary; the resolution is that they belong to *different
reviewers*.

So the verifier set should be deliberately heterogeneous rather than merely
numerous:

- most reviewers run the pinned container -- cheap, and it is the recipe check
  that catches the overwhelmingly more likely attack;
- at least one reviewer builds through an independent toolchain lineage and
  reports the same hash, which is the DDC arm;
- each attestation records which lineage it used in its `BuildDescriptor`
  (alongside the resolved base-image digest), so a reader can tell whether K
  agreeing signatures are K independent observations or one observation
  counted K times.

That last point is the operational consequence and the easiest to skip: an
attestation set whose diversity is unrecorded is indistinguishable from a
monoculture, and a verifier client cannot weigh what it cannot see.

Wheeler's DDC was a researcher performing an experiment once and publishing a
paper about it. K-of-N attestations on chain make the same argument *standing*:
public, re-runnable by anyone, recorded where the verifier client already
reads, and re-executed on every release rather than once in 2009. That is a
fair thing to claim, and it is the honest version of the claim -- not that
self-hosting removes the toolchain residue, but that a diverse public reviewer
set converts it from an assumption into a continuously tested one.

## Where this sits on the ladder

- **R1 (this):** reproducible build + on-chain-hash check. Shores up the
  off-chain-build weak link today, without an on-chain compiler.
- **R2:** the first app *built on* ic-git, on-chain, in the project's own DSL
  (`compile_lang` -> IC deploy -> attest) -- the same guarantee the frontends
  already enjoy, now for a real build.

  **Candidate customer, proposed 2026-07-26: ic-vote's zero-knowledge
  circuit.** A ZK voting system's membership circuit is compiled by a
  toolchain nobody attests, and a backdoored circuit compiler emits
  constraints that do not match the reviewed source while every proof
  downstream still verifies -- the same shape as the malicious ballot-marking
  device and as Thompson's compiler above. Compiling that circuit on chain is
  therefore load-bearing rather than demonstrative, which is what makes it a
  better R2 than a generic application. It needs a constraint-system backend
  for the existing compiler; see ROADMAP.md "R5-alt" and `ic-vote/ZK.md`.
  Note that it delivers R2 only -- a circuit compiler cannot compile itself,
  so R3 below still depends on the wasm-emitting language.
- **R3:** ic-git itself, self-hosted -- building the canister on-chain from
  attested source. This shrinks the toolchain-trust residue to the on-chain
  compiler and makes each release a small reviewable diff; per the section
  above, it does not by itself remove the residue, and the diverse-rebuilder
  arm is still required. The destination R1 makes credible in the meantime.
