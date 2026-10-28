# Canister split: separating the key-holder from the parser

Status: **decided; phase 1 DONE; section 6 restated 2026-10-28 and awaiting a decision.** This document records why ic-git
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
  Exposes `publish_commit`, `tip_record`, `served_site_record`.
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

## 6. Open design question: what the signer may trust from the git canister

**Restated 2026-10-28; awaiting a decision. Phase 3 is blocked on it.**

### 6.1 What changed since this question was first written

When this section was first written the deploy queue's only cross-boundary
read was the EVM artifact, and the question was where to resolve it. Since
then the queue, and the canister that runs it, took on more:

- **The vote gate.** A votes-gated repo's commit deploys only once its
  ballots reach the threshold (`tenancy::approved`, checked at drain time).
  Ballots, voters and the threshold live in tenancy state.
- **Governed app canisters.** ic-git (umobs) is the *only* controller of a
  governed repo's app canister, and the wasm leg's `install_code` into it
  needs that control. Controllership is bound to the principal exactly as
  the threshold keys are (section 2): it moves only by an `update_settings`
  that umobs itself makes, on every app canister.
- **The governor.** Its `target` is set at install, its code can never
  change, and it is umobs. A new canister is outside its reach.
- **Money and records.** The queue charges the repo's account before it
  runs, publishes `<repo>#app` after a governed install, and announces to
  ic-name-service, which lists umobs as the deployer.

So umobs holds more authority than the keys: control of every governed
backend, the governor relationship, the accounts, and the name-service
listing. Section 2's conclusion stands and gets stronger: **umobs stays the
canister that acts** (call it the authority), and the git server moves.

### 6.2 The real question

GOVERNANCE.md's chain says only an approved vote can change a governed
backend. Today that holds because one canister parses the push, counts the
ballots and installs. After the split, the authority installs what the git
canister tells it to. If it believes the git canister about *what bytes a
commit contains* or *whether a commit is approved*, then a compromised git
canister -- the one fed hostile pack bytes -- can install anything into any
governed backend. The split would move the parser away from the keys and
hand it the keys' authority anyway.

So the question is not only which way the calls point. It is: **what may
the authority take on the git canister's word?**

### 6.3 Options

**A. The queue on the git canister.** Every call points git -> authority,
but the git canister would then decide what installs, and it cannot hold
the app canisters' control or the governor's oversight. Rejected.

**B. The authority reads git at drain time, trusting the replies.** This
was the earlier option 2. The authority's behavior then depends on a
second canister's unverified answers. Rejected.

**C. The git canister resolves at enqueue and hands over the bytes.** This
was the earlier preference: the authority's input is scalars and byte
arrays, and the call direction holds. But the bytes, and the claim that
the commit is approved, are still the git canister's word. It fixes the
dependency's direction, not its trust. Insufficient now that backends are
governed.

**D. Proof-carrying jobs, with the votes on the authority (recommended).**

- **Bytes come with their proof.** For each artifact the git canister
  sends the commit oid, the path, the blob, and the raw commit and tree
  objects on the path to it. The authority recomputes each object id
  (SHA-1 over `"<type> <len>\0" + body`), reads the commit's `tree` line
  and, in each tree, the one entry for the next path component. That is a
  bounded, delta-free, zlib-free parse of a handful of small objects --
  nothing like pack ingestion. A blob that is not exactly what commit C
  holds at path P is refused.
- **Votes live where installs happen.** Ballots, voters, the threshold,
  the policy lock and the accounts move to (stay on) the authority, so it
  checks approval from its own state. `cast_ballot` keeps going to umobs,
  so wallets and the consent messages (ICRC-21) do not change for voters.
- **The direction holds.** The git canister pushes a job when an approved
  commit moves or an ungated repo's branch moves; the authority verifies,
  checks its own ballots, charges, installs or deploys, and publishes.
  Resolving at enqueue also means a mid-flight config edit cannot change
  a queued job.

What a compromised git canister can then do: withhold or delay deploys,
and serve wrong bytes on `/site/` -- which the extensions catch, because
the authority signs a site record only for bytes proven to be in an
approved commit. What it cannot do: install unapproved code into a
governed backend, or make the registry attest bytes a commit does not
contain.

The cost: the authority is larger than section 3's signer. It keeps
tenancy, accounts, app-canister management and the deploy queue, about
half of today's 14,700 lines of canister source, against section 1.1's
hope of something tiny. It still parses nothing hostile beyond the bounded proof check,
which is section 1.2's point.

### 6.4 What D brings with it

1. **Builds.** A `.wasm` artifact is proven bytes and installs as is. A
   `.wat` or `.lang` source must be compiled, and compiling on the
   authority would put a parser of pushed text beside the keys. Proposal:
   governed repos deploy committed `.wasm` only, so voters approve the
   exact module and `#app` records its hash; `.wat` and `.lang` builds move
   to the compiler canister (section 3's optional third) and serve
   ungoverned repos.
2. **Repos with no votes required trust the git canister.** For them the
   tip deploys on push, and only the git canister knows the tip. That is
   no weaker than today, where one canister does both, and such repos make
   no governance claim. The docs should say so.
3. **Size.** Proofs carry whole artifacts, and an app module can exceed
   the 2 MiB inter-canister message limit. Jobs are staged in chunks, as
   the governor stages upgrade modules.
4. **Governing the git canister.** The governor cannot take a second
   target. A second instance of the same reproducible governor module,
   with the git canister as its target and the same approvers, governs
   it.
5. **SHA-1.** The proofs rest on git's SHA-1 object ids -- the same ids
   voters already approve. The authority's check should use SHA-1 with
   collision detection, as git itself does.
6. **Serving and pushes.** The authority tells the git canister which
   commit each gated repo serves. Push authorization, writer roles and
   push tokens stay git-side; a push's storage charge becomes one call to
   the authority, which holds the accounts.
7. **The extensions.** The git canister becomes one of the backends a
   page on ic-git talks to, so the expected list (EXTENSION.md, "What the
   page talks to") gains it.

### 6.5 Decisions needed

1. D over C: proof-carrying jobs, with ballots and accounts on the
   authority.
2. Governed repos deploy committed `.wasm` only; `.wat` and `.lang` builds
   go to the compiler canister.
3. A second governor instance for the git canister.
4. Repos with no votes required keep trusting the git canister, and the
   docs say so.

With those settled, section 3's partition is redrawn to match and phase 2
can be planned against it.

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
