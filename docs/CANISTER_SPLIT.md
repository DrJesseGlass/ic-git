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

Today `evm.rs` reaches back into git state in exactly two places:

    evm::registry_publish_commit(repo, commit_oid)
        -> deploy::get_evm_config(repo)
        -> deploy::evm_artifact_hex(commit_oid, path)   // reads the object store

    evm::registry_publish_site(repo)
        -> site::resolve_entry(repo, "")                // reads the object store

and `deploy::attempt_evm` resolves a blob before calling `evm::deploy_bytecode`.

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
  planned inter-canister message from section 4. Net -66 lines.
- `kv.rs` (new) -- the narrow persistence seam; `evm.rs` and `sol.rs` now use
  `kv::get_json` / `kv::set_json` instead of `store::meta_*_json`.
- Callers rewired: `deploy::run_evm` and the two `lib.rs` endpoints. The
  candid surface is unchanged -- `evm_registry_publish` and
  `evm_registry_publish_site` keep their names and signatures, so
  `tools/verify.mjs` and any operator scripts are unaffected.

Verified: `evm.rs` and `sol.rs` now contain **zero** references to
`crate::store`, `crate::deploy`, `crate::site`, or `crate::object`. The
signing modules no longer reach into git state at all. 58 tests pass
(2 new, covering site-record namespacing and the missing-entrypoint error);
`cargo check --target wasm32-unknown-unknown` is clean.

**Phase 2 -- split the crate.** Workspace gains `canisters/signer` and
`canisters/git`, sharing a `types` crate for the wire structs. Both still
deploy as today; only the build layout changes.

Three items deliberately deferred from phase 1 to here, because each needs a
crate boundary to be worth doing:

- **The deploy leg's hex seam.** Phase 1 established the *publish* half of
  section 4 but not the *deploy* half: `evm::deploy_bytecode` still takes
  `bytecode_hex: String` and decodes internally, while `provenance.rs` calls
  the now-`pub` `evm::decode_bytecode_hex`. So hex decoding sits on both sides
  of the future boundary, and `decode_bytecode_hex`'s "the single decode path"
  comment stops being true at phase 3. Fix: move the decoder to the git side
  (next to `deploy::evm_artifact_hex`), change `deploy_bytecode` to take
  `Vec<u8>`, and decode in `lib.rs`'s operator-facing `evm_deploy` endpoint.
  Then the signer takes bytes only, matching section 4.
- **META ownership.** `kv.rs` currently forwards to `store::meta_*_json`, and
  `deploy`/`site`/`fleet` still call `store::` directly -- one bucket, two
  names. Move the `META` map and its JSON codec out of `store.rs` into `kv.rs`
  and point every caller at it, so `store.rs` is objects/refs/repos only.
- **Record-key construction.** `SITE_KEY_SUFFIX` is defined in
  `provenance.rs`, hardcoded in `tools/verify.mjs`, and documented in
  docs/ATTESTATION.md as a registry-contract convention. Put the suffix and a
  `site_record_key(repo)` in the shared `types` crate so signer, git, and the
  verifier derive it from one definition.

One efficiency item is worth folding in whenever the deploy leg is touched:
`run_evm` calls `provenance::publish_commit`, which re-reads, re-inflates,
re-decodes and re-hashes the artifact `evm::deploy_bytecode` just hashed as
`bytecode_sha256`. Negligible in cycles against a threshold signature plus RPC
outcalls, but it is a second derivation of a value that must match the first.

**Phase 3 -- cut the boundary.** git canister calls signer over the interface
in section 4. Deploy the new git canister; keep `umobs-...` as signer, upgraded
in place. Migrate objects/refs by re-push or a bulk copy (`tools/seed-repo.sh`
already does bulk import).

**Phase 4 -- re-attest.** The signer's module hash changes exactly once at
phase 3 and then goes quiet. That is the point of the whole exercise.

Phase 1 is the only phase that should proceed without a fresh look at
mainnet state, because it is the only one that cannot affect it.

## 6. What this does not change

- The public git remote URL changes (new canister id). Anyone with an existing
  remote must update it; there is no redirect story on the raw domain.
- `verify.mjs`'s `--canister` argument becomes ambiguous -- it needs to know
  which canister serves the site and which one owns the registry record. The
  F2 verifier and docs/ATTESTATION.md's step 5 ("full-stack closure") both
  assume one canister today; closure becomes a two-canister property and the
  spec needs a paragraph on it before phase 3.
- The `agrees()` / K-of-N logic is unaffected -- it is keyed on a canister
  string, so two canisters simply means two attestation targets.
