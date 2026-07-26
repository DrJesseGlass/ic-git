# Canister split: separating the key-holder from the parser

Status: **decided; phase 1 DONE.** This document records why ic-git
should be more than one canister, the one constraint that dictates which piece
moves, the module partition, and the order of operations.

Companion to ARCHITECTURE.md (what exists) and docs/ATTESTATION.md (what the
reviewers attest).

## 1. Why split at all

Today one canister (~6,850 lines, 5.71 MiB wasm) is a git smart-HTTP server, a
static site server, a wasm compiler, a wasm interpreter, an EVM signer, a
Solana signer, and a deploy orchestrator. Two arguments for cutting it, and
they are both security arguments rather than aesthetic ones.

### 1.1 Attestation surface

`docs/ATTESTATION.md` asks K independent reviewers to reproduce the canister's
build and attest its module hash. Today that means attesting all 5.71 MiB as
one indivisible unit, so:

- a change to pack-delta handling invalidates the attestation that covers the
  **signing** code;
- reviewer effort is spent re-verifying git plumbing that changes constantly,
  instead of concentrating on the small part that holds keys;
- the trust root is large, fast-moving, and therefore rarely fully re-reviewed
  -- which is the opposite of what a trust root should be.

The shape you want for a trust root is small, stable, and heavily scrutinized.
Today ic-git has the opposite, and the attestation work makes that concrete
rather than theoretical.

### 1.2 Blast radius

`pack.rs` and `receive.rs` parse **attacker-controlled input** -- anyone with a
push token feeds them arbitrary pack bytes, thin-pack deltas, and tree
structures. That code currently shares a trust domain, and an address space,
with threshold ECDSA and Ed25519 signing.

A logic bug in delta resolution sits next to the thing that signs EVM
transactions from an EOA holding real funds. Canister isolation is the only
boundary the IC gives us, and we are not using it.

### 1.3 Secondary benefits

- **Code-section headroom.** wasmi already took the module from 3.95 to 5.71
  MiB against a 10 MiB cap. Anything further (a bigger compiler, solc via
  wasi2ic) runs into the wall.
- **Upgrade cadence.** The git server changes weekly; the signer should change
  approximately never.

## 2. The constraint that decides which piece moves

**Threshold key derivation is bound to the calling canister's principal.**
`sign_with_ecdsa` takes `message_hash`, `derivation_path`, and `key_id` -- and
notably **no `canister_id`**. The signing key is derived from the *caller*.
`ecdsa_public_key` accepts a `canister_id` for *reading* another canister's
public key, but that does not let you sign with it.

Consequence: a new canister gets a new EOA. Unavoidably. And our EOA
`0x6Ad88e005f96B18e8B1C76A9Da85Fa8efA2C848a` is:

- baked into the deployed ProvenanceRegistry's constructor as `owner`;
- the reason the CREATE2 init code -- and therefore the registry address -- is
  identical on every chain (docs/ATTESTATION.md, "Per-chain CREATE2 registry").

Moving the signer to a fresh canister would orphan the registry on every chain
it has been deployed to, and break the one-address-everywhere property before
it is even used.

**Therefore: invert the obvious move.**

> Keep `umobs-yiaaa-aaaab-agyrq-cai` as the **signer/deploy** canister, and
> move the **git server** out to a new canister.

Same EOA, same registry ownership, same CREATE2 scheme, zero on-chain
migration. The piece that migrates is the one with no cryptographic identity
to preserve -- the git server, whose state is objects and refs that can be
re-pushed or copied.

The cost of this decision rises with every chain a registry is deployed to, so
it should be made before the multi-chain work in docs/ATTESTATION.md.

## 3. The partition

Two canisters, plus an optional third. Not eight -- splitting further buys
latency and partial-failure states for no trust gain. **Cut where the trust
boundary is, not where the module boundary is.**

### signer (stays at `umobs-yiaaa-aaaab-agyrq-cai`)

`evm.rs`, `sol.rs`, `rpc_common.rs`, plus the chain half of `deploy.rs`.

Holds: the threshold keys, chain configs, the registry address, the deploy
provenance log, the deploy queue.

Properties: small, stable, no untrusted parsing, rarely re-attested. This is
the artifact the K reviewers actually care about.

### git (new canister)

`store.rs`, `object.rs`, `pack.rs`, `receive.rs`, `smart_http.rs`, `site.rs`,
plus the repo-metadata half of `deploy.rs`.

Holds: objects, refs, repos, per-repo deploy config, site config.

Properties: large, hostile input, changes often, **holds no keys**.

### compiler (optional third)

`compile.rs`, `lang.rs`, `fleet.rs`, `interp.rs`.

Already nearly separate -- `fleet.rs` treats any git-canister instance as a
worker. Compilation is a pure function of its input, which makes it both the
easiest thing in the system to attest and the natural place to apply K-of-N
adversarial verification (ROADMAP.md, "Fault tolerance for the fan-out").

Deferring this one is fine; it carries no keys and no hostile input, so it is
the least urgent cut.

## 4. The interface, and why it is the real prize

Before phase 1, `evm.rs` reached back into git state in exactly two places
(kept here because the shape of the fix is the shape of the interface):

    evm::registry_publish_commit(repo, commit_oid)
        -> deploy::get_evm_config(repo)
        -> deploy::evm_artifact_hex(commit_oid, path)   // reads the object store

    evm::registry_publish_site(repo)
        -> site::resolve_entry(repo, "")                // reads the object store

and `deploy::attempt_evm` resolves a blob before calling `evm::deploy_bytecode`.
(`evm_artifact_hex` is spelled `evm_artifact_bytecode` today; the call graph
above is how it stood before phase 1.)

The split inverts the direction of these calls. **The git canister resolves;
the signer canister signs.** The signer's input becomes a small, typed,
fully-validated message rather than a view into a git object store:

    // git canister -> signer canister
    publish_record(record_key: text, commit: blob(20), bundle_hash: blob(32))
    deploy_bytecode(repo: text, commit: text, bytecode: blob, gas_limit: nat64)

That is the security win, stated precisely: **the signer's input surface
shrinks from "the git object store" to three scalars and a byte array.** No
pack parsing, no tree walking, no delta resolution anywhere near the keys. A
reviewer auditing the signer no longer has to reason about git at all.

Authorization: the signer accepts these calls only from the git canister's
principal, via the existing `auth` allowlist.

Failure modes the queue must now handle (they do not exist today):
- signer canister unreachable or stopped -- retry, do not lose the job;
- call succeeds but response is lost -- the existing same-commit dedupe on the
  provenance log already covers this, and is the reason it was built.

## 5. Order of operations

**Phase 1 -- establish the seam in-canister (no deployment risk).** DONE.

What was built:

- `provenance.rs` (new) -- the git-side resolver. Walks refs/trees/blobs to
  produce a `Record { key, commit[20], bundle[32] }`, and owns
  `SITE_KEY_SUFFIX` (record-key naming is a repo concern, not a chain one).
  Exposes `publish_commit`, `publish_tip`, `publish_site`.
- `evm.rs` -- the three git-aware publishers (`registry_publish`,
  `registry_publish_commit`, `registry_publish_site`) collapse into one
  `registry_publish_record(record_key, commit, bundle)`, which is exactly the
  planned inter-canister message from section 4.
- `kv.rs` (new) -- the narrow persistence seam; `evm.rs` and `sol.rs` now use
  `kv::get_json` / `kv::set_json` instead of `store::meta_*_json`.
- Callers rewired: `deploy::run_evm` and the two `lib.rs` endpoints. The
  candid surface is unchanged -- `evm_registry_publish` and
  `evm_registry_publish_site` keep their names and signatures, so
  `tools/verify.mjs` and any operator scripts are unaffected.

Verified: `evm.rs` and `sol.rs` now contain **zero** references to
`crate::store`, `crate::deploy`, `crate::site`, or `crate::object`.

**Scope of that claim, stated honestly:** it covers the two signing modules
only, and section 3 also assigns the *chain half of `deploy.rs`* to the
signer. That half is not clean: `deploy::run_evm` calls
`provenance::publish_commit`, which reads the object store. Phase 1 moved that
dependency from `evm.rs` into `deploy.rs` rather than removing it, and the
completion check as originally written could not see it. Section 6 records the
resulting open design question.

59 tests pass (3 new: site-record namespacing, the missing-entrypoint error,
and deploy-record hash semantics); `cargo check --target wasm32-unknown-unknown`
is clean.

**Phase 2 -- split the crate.** Workspace gains `canisters/signer` and
`canisters/git`, sharing a `types` crate for the wire structs. Both still
deploy as today; only the build layout changes.

**The deploy leg's hex seam -- DONE, ahead of the crate boundary.** Phase 1 had
established the *publish* half of section 4 but not the *deploy* half:
`evm::deploy_bytecode` took `bytecode_hex: String` and decoded internally while
`provenance.rs` called the then-`pub` `evm::decode_bytecode_hex`, so hex
decoding sat on both sides of the future boundary. Now:

- `decode_bytecode_hex` lives in `deploy.rs`, next to the resolver
  (`evm_artifact_bytecode`, which returns decoded bytes, and
  `evm_artifact_hash`, the one derivation of the bundle hash).
- `evm::deploy_bytecode` takes `Vec<u8>`. The signer's deploy input is bytes
  and scalars, exactly as section 4 specifies.
- `lib.rs`'s operator-facing `evm_deploy` decodes on the way in; its candid
  signature `(text, nat64)` is unchanged.
- `evm::deploy_target` / `require_deploy_target` mirror the existing
  `publish_target` pair, so `deploy::set_evm_config` and `deploy::attempt_evm`
  check config-and-gas from one definition -- and `attempt_evm` checks it
  *before* walking the tree, instead of resolving and decoding an artifact for
  a canister that turns out to have no EVM config.

Two items remain deferred to phase 2, because each needs a crate boundary to be
worth doing:

- **META ownership.** `kv.rs` currently forwards to `store::meta_*_json`, and
  `deploy`/`site`/`fleet` still call `store::` directly -- one bucket, two
  names. Move the `META` map and its JSON codec out of `store.rs` into `kv.rs`
  and point every caller at it, so `store.rs` is objects/refs/repos only.
- **Record-key construction.** `SITE_KEY_SUFFIX` is defined in
  `provenance.rs`, hardcoded in `tools/verify.mjs`, and documented in
  docs/ATTESTATION.md as a registry-contract convention. Put the suffix and a
  `site_record_key(repo)` in the shared `types` crate so signer, git, and the
  verifier derive it from one definition.

The efficiency item that rode along with the hex seam is also done: `run_evm`
used to call `provenance::publish_commit`, which re-read, re-inflated,
re-decoded and re-hashed the artifact `evm::deploy_bytecode` had just hashed as
`bytecode_sha256`. `attempt_evm` now returns that hash alongside the outcome
and `publish_commit` takes it as a parameter. Negligible in cycles either way
against a threshold signature plus RPC outcalls -- the point is that a value
which *must* match is no longer derived twice from mutable state.

**Phase 3 -- cut the boundary.** git canister calls signer over the interface
in section 4. Deploy the new git canister; keep `umobs-...` as signer, upgraded
in place. Migrate objects/refs by re-push or a bulk copy (`tools/seed-repo.sh`
already does bulk import).

**Phase 4 -- re-attest.** The signer's module hash changes exactly once at
phase 3 and then goes quiet. That is the point of the whole exercise.

Phase 1 is the only phase that should proceed without a fresh look at
mainnet state, because it is the only one that cannot affect it.

## 6. Open design question: the auto-publish path crosses the boundary

**This is the one thing in the plan that does not yet work, and it must be
settled before phase 3.**

Section 3 puts the deploy queue (`run_evm`, `attempt_evm`, `drain_one`) on the
**signer**. Section 4 says the split inverts the git/chain call direction: the
git canister resolves, the signer signs. Those two are in conflict, because the
deploy queue reads git state at drain time:

    attempt_evm  (signer)  ->  deploy::evm_artifact_bytecode  (git: object store)

The hex-seam work above narrowed this to one call. The auto-publish that
follows a successful deploy used to be a second crossing --
`run_evm -> provenance::publish_commit -> the object store` -- but
`publish_commit` now takes the bundle hash `attempt_evm` already computed, so
it reads nothing. The artifact resolve is what is left.

Neither obvious repair is free:

- **Move the queue to the git canister.** Contradicts section 3, and it puts
  the retry/timer machinery on the side with the hostile input -- but it keeps
  every call pointing git -> signer, which is the property section 4 exists to
  protect. The signer stays a pure "sign what you are handed" service.
- **Let the signer call back into git.** Contradicts section 4, reintroduces
  the dependency this whole phase removed, and makes the attested signer's
  behavior depend on a second canister's responses.
- **Push the resolution to the enqueue side.** The git canister resolves the
  deploy artifact when it enqueues and hands the signer a job containing
  bytecode plus `(record_key, commit, bundle)`. The signer then deploys and
  publishes without ever reading git. This preserves both sections at the cost
  of a fatter queue entry.

The third is the current preference: it is the only one that leaves the
signer's input surface as section 4 specifies -- scalars and byte arrays, no
git. The hex-seam work is most of it already: `attempt_evm` now produces
exactly `(bytecode, bundle)` from one resolve and hands both onward, so the
remaining move is to do that resolve at enqueue time rather than at drain time.
That changes what a mid-flight config edit means (it can no longer affect an
already-queued job -- arguably a fix, see the TOCTOU note in section 5).

Until this is decided, phase 3 is blocked regardless of how phase 2 goes.

## 7. What this does not change

- The public git remote URL changes (new canister id). Anyone with an existing
  remote must update it; there is no redirect story on the raw domain.
- `verify.mjs`'s `--canister` argument becomes ambiguous -- it needs to know
  which canister serves the site and which one owns the registry record. The
  F2 verifier and docs/ATTESTATION.md's step 5 ("full-stack closure") both
  assume one canister today; closure becomes a two-canister property and the
  spec needs a paragraph on it before phase 3.
- The `agrees()` / K-of-N logic is unaffected -- it is keyed on a canister
  string, so two canisters simply means two attestation targets.
