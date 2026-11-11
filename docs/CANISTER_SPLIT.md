# Canister split: separating the key-holder from the parser

Status: **decided; phase 1 DONE; section 6 decided 2026-10-28 (proof-carrying
jobs, votes on the authority); phase 2 planned.** This document records why ic-git
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

Two canisters, plus a third for builds. Not eight -- splitting further buys
latency and partial-failure states for no trust gain. **Cut where the trust
boundary is, not where the module boundary is.** Redrawn 2026-10-28 after
the decisions in section 6: the canister that stays is the authority, not
only a signer.

### authority (stays at `umobs-yiaaa-aaaab-agyrq-cai`)

`evm.rs`, `sol.rs`, `rpc_common.rs`, `kv.rs`; the deploy queue and both
deploy legs of `deploy.rs` (install, CREATE, records); `apps.rs`;
`tenancy.rs` (owners, members, policy, ballots, accounts, the governed
lock); `icp.rs` and `ledger.rs` (deposits); `names.rs`; the publishing half
of `provenance.rs`; `feed.rs`; `consent.rs` for the calls that land here;
and a new proof verifier (section 4).

Holds: the threshold keys, chain configs, the registry address, control of
every app canister (and sole control of governed ones), the governor
relationship, the accounts, the ballots and policies, the deploy configs
(phase 3, step 6), the deploy queue and provenance logs, the name-service
listing.

Properties: no hostile parsing beyond the bounded proof check; changes
rarely; governed by the existing governor. About half of today's canister
source -- larger than the signer first planned here, and the price of
keeping the vote check where installs happen.

### git (new canister)

`store.rs`, `object.rs`, `pack.rs`, `receive.rs`, `smart_http.rs`,
`site.rs`, `api.rs` (its git half), `tokens.rs`, `signed_push.rs`, the
resolving half of `provenance.rs`, and a new job builder (section 4).

Holds: objects, refs, repos, site config, push tokens and keys, and
mirrors the authority keeps current: each repo's writers, its approved
commits, and its deploy config (phase 3, step 6: the authority owns the
deploy configs, since a job's config names the canister it installs
into).

Properties: large, hostile input, changes often, **holds no keys and
controls nothing**. A second instance of the governor module governs it.
For a repo with no votes required it decides what deploys (the tip); for
any other repo it can only propose, and the authority checks.

### compiler (third)

`compile.rs`, `lang.rs`, `fleet.rs`, `interp.rs`.

Builds `.wat` and `.lang` sources for repos that are not governed; a
governed repo deploys committed `.wasm` only, so nothing the compiler
produces reaches a governed backend. Compilation is a pure function of its
input, which makes it the natural place for K-of-N adversarial
verification (ROADMAP.md, "Fault tolerance for the fan-out"). It holds no
keys, so it is the least urgent cut.

## 4. The interface, and why it is the real prize

Before phase 1, `evm.rs` reached back into git state in exactly two places
(kept here because the shape of the fix is the shape of the interface):

    evm::registry_publish_commit(repo, commit_oid)
        -> deploy::get_evm_config(repo)
        -> deploy::evm_artifact_hex(commit_oid, path)   // reads the object store

    evm::registry_publish_site(repo)
        -> site::resolve_entry(repo, "")                // reads the object store

Phase 1 turned those into one call that takes scalars. Section 6 adds what
that alone did not give: the authority no longer has to believe the bytes.
**The git canister resolves and proves; the authority verifies, decides and
acts.**

    // git -> authority
    submit_job(repo, commit: blob(20), artifacts: vec Artifact)   // staged in chunks
    notify(repo, event)                    // e.g. a push awaiting votes, for the feed
    charge_push(repo, bytes: nat64)
    publish_git_record(commit, module_sha256)   // the git canister's own module
                                                // record (phase 3, step 12)

    Artifact = record { path: text; blob: blob; proof: vec blob }
      // proof: the raw commit object, then each tree object on the path

    // authority -> git (the mirrors, mirror.rs; each with a sequence
    // number, phase 3 step 8)
    set_push_policy(repo, PushPolicy)      // writers, require_signed_push
    set_approved(repo, opt vec text, retry: bool)
                                           // the commits reaching the threshold,
                                           // by ballot key; null: no votes required
    set_deploy_config(repo, ...)           // the source paths a job resolves
                                           // (phase 3, step 6)
    set_site(repo, root)

    // authority -> git (asked from update calls; phase 3, steps 7 and 10)
    check_new_repo(name) -> label; create_repo(name); has_commit(oid)
    release_job(repo)                      // deploy_now: the job, by submit_job
    record_artifact(repo, kind)            // a registry publish: Artifact + proof

The authority checks a proof by recomputing each object's id (SHA-1 with
collision detection over `"<type> <len>\0" + body`), the first against the
job's commit, reading the commit's `tree` line and in each tree only the
entry for the next path component, and requiring the last entry to be a
regular file whose id is the blob's. No packs, no deltas, no zlib, no
walk beyond one path. Then it checks the commit against its own ballots,
charges the account, and installs, deploys and publishes from the verified
bytes alone.

Authorization: the authority accepts these calls only from the git
canister's principal, and the git canister only the mirrors from the
authority's.

Why the approved set and not the served commit (an earlier draft had
`set_served`): which approved commit a site serves is the newest one on
the branch's first-parent history, and only the git canister has the
history. Sending the authority up to `APPROVAL_WALK` commit ids on every
push would be the price of deciding there. The approved set is what only
the authority knows, it changes only on a ballot or a policy change --
both of which happen at the authority -- and the git canister walks its
own history against it. Commits are named by their ballot key
(`ic_multisig::Subject::of_short_hash("commit", oid).key()`), because the
ballot store is keyed by that hash and the authority cannot list commit
ids from it; the git canister derives the same key for each commit it
walks. The set is recounted from every commit with a ballot whenever it
can change, which is fine at today's ballot counts and the place to look
if a repo collects thousands of voted commits.

Failure modes the queue handles (phase 3 step 8: the git side's outbox):
- authority unreachable or stopped -- the git canister keeps the job in
  its outbox and retries it;
- the call succeeds but the response is lost -- the item is sent again
  with the same sequence number, which the authority takes once; it
  dedupes jobs by (repo, commit) too, as the provenance log already
  dedupes deploys;
- a job whose proof fails -- refused and logged; the repo's status says why.

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

**Phase 2 -- proofs and the crate layout, still one canister.** Each step
ships as an ordinary release through the governor, and none changes which
canister does what:

1. **The proof.** DONE: `gitproof.rs`. `prove` is the git side (resolve a
   path in a commit, collecting the raw objects); `check` is the authority
   side, a pure function doing the bounded walk of section 4 with
   `sha1-checked`, and refusing a detected collision. Tests cover a wrong
   blob, another commit, a swapped or altered object, too few or too many
   objects, symlinks, submodules and trees as the last entry, a file walked
   through as a directory, a name listed twice, paths that are not plain,
   headers that do not match their bodies, malformed commits and truncated
   trees, the SHA-mbles collision, and a 20,000-round mutation fuzz in
   which every altered input is refused.
2. **Jobs carry proofs.** DONE. `enqueue` snapshots the repo's deploy
   configs and proves each leg's artifact out of the commit (`resolve`, the
   git side); the payload goes in its own stable map (memory 9), not the
   JSON meta bucket, since a module can be megabytes. `drain_one` takes it
   and `run` deploys from bytes that `Artifact::verified` has checked
   against the job's commit and the snapshot's path, reading neither the
   configs nor the object store; a refused proof is the deploy's failure
   message. `deploy_now` resolves and runs the same kind of job. A config
   edit cannot change a queued job (since phase 3 step 6 the queue
   refuses one whose configs are no longer the repo's). A job queued by an older release is
   resolved in `post_upgrade`, which also frees any payload whose job is
   gone (drained by an older release after a rollback).
3. **Governed repos deploy `.wasm` only.** DONE. One rule,
   `SourceKind::for_repo`: `set_config` (behind `set_wasm_deploy` and an
   applied `WasmDeploy`), a `WasmDeploy` proposal, and `govern_app_canister`
   refuse a `.wat` or `.lang` source on a governed repo -- governing waits
   until the config names a `.wasm` -- and the drain checks it again as a
   job runs, since a job queued before governing carries the config of
   that time, and once more just before `install_code`, since the repo can
   be governed while the job awaits the target's status. On mainnet the
   only governed repo, ic-vote, deploys `app.wasm`, so nothing live
   changes.
4. **The crate split.** DONE. Workspace crates `types` (wire structs, record keys,
   the proof format and its checker), `authority`, `git` and `compiler`,
   still linked into one canister. The two deferred items below land here.
   First half DONE: `crates/types` (`ic-git-types`: `proof`, the checker,
   `Artifact` and `plain`; `keys`, the record keys, with a test holding
   `tools/verify.mjs` and `core/verifier.js` to them) and
   `crates/compiler` (`ic-git-compiler`: `compile`, `lang`, `interp`), both
   pure and linked into the canister crate; and both deferred items. The
   prover (`gitproof::prove`) stays with the object store. Second half,
   first the one-sided modules, DONE: inside the one crate, every module
   belongs to one side, and the authority reaches the git side only
   through `to_git.rs`.
   - `memory.rs` holds the memory manager and the table of memory ids;
     `records.rs` the authority's maps (accounts, repo metadata, ballots,
     deploy-job payloads); `store.rs` the objects, refs, repos and tokens.
     The ids are unchanged, so nothing migrates.
   - `deploy.rs` splits: `jobs.rs` (git) holds the configs and builds a
     job from a commit; `deploy.rs` (authority) queues, runs and records.
     `enqueue` takes the job lazily, so a duplicate is still not built.
   - `provenance.rs` splits: `attest.rs` (git) resolves the site and
     release records; `provenance.rs` (authority) publishes them.
   - `api.rs` splits: `api.rs` (git) serves repos, refs, commits, trees and
     blobs; `api_authority.rs` serves pricing, accounts, a repo's tenancy,
     ballots, proposals and deploys. `/api` asks the authority half first.
   - Shared, owned by neither side: `clock.rs` (`now_ns`), `kv.rs`,
     `httpjson.rs`, and in `ic_git_types` the wire structs (`deploy`), `oid`
     and `labels`.
   - `to_git.rs`, the authority's whole view of the git side: a repo's
     deploy config, the two mirror writers, whether a repo exists, the
     checks and creation of a new repo, whether a commit exists, and who
     holds a label. Each becomes a message in phase 3.
   - `feed::after_push` takes the branch and both tips from the push glue
     in `lib.rs`, which, with `consent.rs`, is the only code that calls
     both sides.
   Then the crates, DONE: the two sides are `crates/authority`
   (`ic-git-authority`) and `crates/git` (`ic-git-git`), with what neither
   owns in `crates/common` (`ic-git-common`: the memory layout, `kv`, the
   clock, the /api JSON helpers). The canister crate is the glue: its
   endpoints, `consent.rs`, the compile fleet, and the tests that run both
   sides together (`both_sides.rs`).
   - The git crate depends on neither the authority nor the canister.
     `mirror::set_push_policy` takes the operator rule from its caller.
   - `to_git.rs` is now an interface, `ic_git_types::git_side::GitSide`
     (with `PushPolicy`, its wire struct). The git crate implements it
     (`for_authority::Git`); the canister installs that into the authority
     first thing in `init` and `post_upgrade`. The authority crate does not
     depend on the git crate, so the compiler refuses any other way across,
     and phase 3 installs an implementation that sends messages.
   - Tests run against the real git side rather than a fake: the
     authority crate's tests take the git crate as a dev-dependency, and a
     `testing` feature (enabled only from dev-dependencies, never in a
     wasm build) lets the canister's tests do the same and reach the test
     hooks (the settable clock and controllers, timer stubs).
5. **The mirrors.** DONE. Site serving and push authorization read the
   approved commits and the writers through the interfaces they will have
   across the boundary, so phase 3 swaps a function call for a message.
   `mirror.rs` is the git side's copy: a repo's push policy (owner and
   writers, the signed-push flag) and its approved set, in META under
   `mirror:`. `tenancy` writes them when a repo's metadata changes in a way
   they reflect (`save_meta`) and after each commit ballot; `post_upgrade`
   fills them for every repo. `site` (gated, `advance`, `served_commit`),
   the push path, token minting and revoking read only the mirrors; the
   token sweep after a membership change moved into the push-policy
   mirror, so losing write access revokes a principal's tokens as the
   change is saved. Operators are not mirrored: each canister keeps its
   own. What the git side still read of the authority directly after this
   step -- the clock, `charge_push` and the authority's half of `/api` --
   step 4's second half moved to `clock.rs`, the push glue and
   `api_authority.rs`.

**The deploy leg's hex seam -- DONE, ahead of the crate boundary.** Phase 1 had
established the *publish* half of section 4 but not the *deploy* half:
`evm::deploy_bytecode` took `bytecode_hex: String` and decoded internally while
`provenance.rs` called the then-`pub` `evm::decode_bytecode_hex`, so hex
decoding sat on both sides of the future boundary. Now:

- `decode_bytecode_hex` lives in `ic_git_types::deploy`; the resolver
  (`jobs::evm_artifact_bytecode`, which returns decoded bytes, and
  `jobs::evm_artifact_hash`, the one derivation of the bundle hash) uses it.
- `evm::deploy_bytecode` takes `Vec<u8>`. The signer's deploy input is bytes
  and scalars, exactly as section 4 specifies.
- `lib.rs`'s operator-facing `evm_deploy` decodes on the way in; its candid
  signature `(text, nat64)` is unchanged.
- `evm::deploy_target` / `require_deploy_target` mirror the existing
  `publish_target` pair, so the EVM config setter (now `configs::set_evm`)
  and `deploy::attempt_evm`
  check config-and-gas from one definition -- and `attempt_evm` checks it
  *before* walking the tree, instead of resolving and decoding an artifact for
  a canister that turns out to have no EVM config.

Two items were deferred to phase 2, because each needed a crate boundary to be
worth doing. Both DONE in step 4:

- **META ownership.** `kv.rs` used to forward to `store::meta_*_json` while
  `deploy`/`site`/`fleet` called `store::` directly -- one bucket, two names.
  `kv.rs` now owns the `META` map (same memory id, so nothing migrates), its
  JSON codec, the auth snapshot and the raw bytes the schema marker uses;
  the memory layout lives in `memory.rs`. Every
  caller goes through `kv`.
- **Record-key construction.** `SITE_KEY_SUFFIX` was defined in
  `provenance.rs` and hardcoded in `tools/verify.mjs`. The suffixes,
  `CANISTER_KEY` and `site_record_key` / `app_record_key` /
  `artifact_record_key` now live in `ic_git_types::keys`, which
  `provenance.rs` uses; the JavaScript verifiers cannot import them, so a
  test in that crate reads `tools/verify.mjs` and `core/verifier.js` and
  fails if their copies differ.

The efficiency item that rode along with the hex seam is also done: `run_evm`
used to call `provenance::publish_commit`, which re-read, re-inflated,
re-decoded and re-hashed the artifact `evm::deploy_bytecode` had just hashed as
`bytecode_sha256`. `attempt_evm` now returns that hash alongside the outcome
and `publish_commit` takes it as a parameter. Negligible in cycles either way
against a threshold signature plus RPC outcalls -- the point is that a value
which *must* match is no longer derived twice from mutable state.

**Phase 3 -- cut the boundary.** Planned 2026-11-09; the state moves by
bulk copy (decided then; step 13). After phase 2 the two sides are crates
in one canister, and the canister crate's glue is the only code that calls
both: 17 of its 105 endpoints, plus `init`, `post_upgrade` and
`consent.rs`. Phase 3 turns that glue into messages, builds two
canisters, and moves the git side's state off umobs. The steps continue
phase 2's numbering. As in phase 2, steps 6 to 11 and 13 each ship as an
ordinary release of the one canister through the governor, and none
changes which canister does what. Step 12 builds the two canisters and
step 14 the clients; neither reaches mainnet before steps 15 and 16, the
cut.

What a message changes, against today's function calls:

- **It can fail, or succeed with its answer lost.** Every message is a
  full-state write or carries a key the receiver dedupes by, so a retry
  is always safe.
- **The caller's state can change while it waits.** Every check made
  before an await is made again after it, as `create_push_token` already
  does around `raw_rand`.
- **Guaranteed-response calls from one canister to another arrive in
  order, but a failed one can be retried after a later one.** Each mirror write carries a
  sequence number per repo, and the git canister ignores one older than
  what it holds.
- **A query cannot call another canister.** What the authority answers in
  a query (the authority's half of `/api`, `/feed`) must come from its own
  state, never from the git side.
- **The 2 MiB message limit.** Jobs and proofs are staged in chunks
  (section 6.4, item 3).
- **Each canister pays for its own cycles.** The git canister holds the
  objects, and the rent for them is collected on the authority.

The steps in one canister:

6. **The authority owns the deploy configs.** DONE. Before this step the
   git side held them, and a job carried a snapshot of the one it was
   built from. Across
   the cut that snapshot is the git canister's word: a job could name any
   canister the authority controls as its target, another tenant's app
   canister included, and the queue installs into `cfg.target`. Fix: the
   wasm and EVM deploy configs and the install mode are kept at the
   authority, which every setter already goes through (`set_wasm_deploy`,
   `set_deploy_mode`, `set_evm_deploy`, a `WasmDeploy` or `DeployMode`
   policy change). The git side gets a mirror, since it needs the source
   path to build a job. At drain time the queue installs by its own
   config: it refuses a job whose config differs from its own and takes
   nothing but the proven artifacts from the job. `to_git::deploy_config`
   goes away. A test shows that a job naming another repo's app canister
   is refused.
   What shipped:
   - `crates/authority/src/configs.rs` owns the configs, under the META
     keys they always had, so nothing migrates. Every setter writes the
     git side's mirror (`mirror::set_deploy_configs`, through
     `GitSide::set_deploy_configs`, with `DeployConfigs` in
     `ic_git_types::git_side`).
   - The git side's `jobs` reads only the mirror. `post_upgrade` fills
     the mirror by key (`configs::sync_all_mirrors`) before
     `resume_pending`, since a legacy repo can have a config and no
     tenancy metadata.
   - `deploy::run` starts with `configs::check_job`. A job whose configs
     differ is refused, and its status names both sides of the
     difference and points at `deploy_now`. Such a job is either queued
     before a config change or forged.
7. **The authority keeps what it already decides.** DONE. Repos are created
   only through the authority, which charges for them. So it records the
   label `check_new_repo` returns in the repo's metadata, and a release
   fills in metadata, label included, for every legacy ownerless repo.
   With that, `repo_exists` and `label_holder` are answered from the
   authority's own state, and the authority's queries never need the git
   side. What it still asks of the git side, besides the mirrors:
   `check_new_repo`, `create_repo`, `has_commit` (a ballot on a commit it
   does not hold is refused) and the records of step 10. Each of these is
   asked from an update call, so it can await.
   What shipped:
   - `RepoMeta` gains `label`. `tenancy::create_repo` records the label
     `check_new_repo` returns.
   - `tenancy::adopt_repos`, run by `post_upgrade` over the git side's
     repos and the labels they hold (`store::held_label`), gives a repo
     created before tenancy an ownerless record and a repo created
     before this release its label. It is idempotent.
   - `tenancy::repo_exists` is "has metadata". `configs`, `feed` and
     `api_authority` use it, and the legacy fallback that asked the git
     side is gone: a repo with no record does not exist for the
     authority.
   - `names` announces under `RepoMeta::label`. `repo_exists` and
     `label_holder` leave `GitSide`.
8. **Both directions become async traits.** DONE.
   - `GitSide`'s methods return futures.
   - A new `AuthoritySide` in `ic-git-types` carries the git side's calls:
     `charge_push`, `stage_job` and `submit_job`, `notify` (feed events)
     and `publish_git_record` (step 12).
   - The in-canister implementations stay plain function calls behind
     those futures, so behavior is unchanged; the messages start with
     step 12's two builds.
   - Every flow that awaits gets its failure rule here, and each rule is
     tested against an implementation that fails, or loses its answer, on
     the chosen call.
   - The flows:
     - **Creating a repo** reserves the name at the authority, debits,
       then awaits `create_repo`. A definite refusal refunds and releases
       the name. A lost answer is settled by asking again: the name is
       reserved, so nothing else can have taken it.
     - **The push path** checks the certificate, then awaits
       `charge_push`, then checks `may_write` again before it ingests.
       The charge is kept on a refused pack, as it is today.
     - **A ballot** awaits `has_commit` before it counts.
     - **Mirror writes** are full state, sequence-numbered, and kept in a
       per-repo dirty set until the git side acknowledges them, retried
       by a timer.
     - **The git side's outbox.** `submit_job` and `notify` go into an
       outbox in stable memory, drained by a timer and retried until the
       authority acknowledges them. The authority already dedupes jobs by
       (repo, commit) (section 4). It dedupes feed events by a sequence
       number.
   What shipped:
   - `ic_git_types::side`: `Failure` (`NotDelivered`, the call never ran;
     `Lost`, it may have), `Reply<T>`, and the boxed `Fut` the trait
     objects answer with. Every `GitSide` method answers a `Reply`, and
     so does the new `AuthoritySide` (`ic_git_types::authority_side`:
     `charge_push`, `submit_job`, `notify`; `publish_git_record` comes
     with step 12). The in-canister implementations,
     `for_authority::Git` and `for_git::Authority`, answer ready futures
     and never fail, so behavior is unchanged until step 12 installs the
     ones that send messages. Each crate reaches the other only through
     `to_git` and `to_authority`, which tests can stand a failing side
     in for.
   - Creating a repo (`tenancy::create_repo`): `check_new_repo` is
     awaited, then the name is reserved and the fee taken, then
     `create_repo` is awaited. A refusal refunds and releases the name;
     a lost answer is asked again, up to `CREATE_ASKS` times, which the
     git side's idempotent `create_repo` makes safe; past that the owner
     keeps the reservation and the fee, nobody else can take the name,
     and the owner's next call finishes it without paying again. The
     owner may call again while a call waits: the reservation is read
     again after each answer, and the first answer settles it; a later
     one takes that settlement. An upgrade meanwhile does not adopt the
     reserved name as ownerless.
   - The push path (`http_request_update`): the certificate is checked,
     `charge_push` is awaited, the token and the signed-push rule are
     checked again, then the pack is read. A charge the authority does
     not answer refuses the push, and the charge is kept on a refused
     pack.
   - A ballot (`tenancy::cast_ballot`) awaits `has_commit`, reads the
     policy again, then counts; one the git side does not answer for is
     not cast.
   - Mirror writes (`crates/authority/src/mirrors.rs`): whatever changes
     what a mirror reflects marks it, in stable memory; the flow that
     changed it awaits `flush`, which sends each marked mirror's whole
     state under a fresh sequence number, one counter per repo, and
     clears the mark on the answer. The git side (`mirror.rs`) ignores a
     write older than the newest it holds for that mirror, so a retry
     that lands late cannot roll it back. An unanswered write is retried
     on one timer, armed once per outage; `post_upgrade` marks every
     mirror and `mirrors::resume` writes them before the upgrade's first
     message (in one canister the writes complete at once), so no push
     finds a mirror empty; a legacy job is rebuilt there from the
     authority's own configs (`jobs::resolve_with`).
   - The outbox (`crates/git/src/outbox.rs`, stable map `MEM_OUTBOX`):
     `submit_job` and `notify` items, numbered, delivered oldest first
     and one at a time, retried on one timer, and `for_git` takes each
     number once. The push path builds the job and the push event
     there, and awaits the delivery, so in one canister nothing waits.
     Waiting jobs are indexed by (repo, commit): a commit's job is built
     once while it waits, and a deploy-config write on the git side
     rebuilds the repo's waiting jobs under the new configs, so what the
     authority gets is what the configs said when it got it. The drain
     flag is held by a guard, so a trap while the authority answers
     (step 12) does not leave the outbox stalled.
   - Each rule is tested against a side that refuses, does not run, or
     runs and loses the answer of a chosen call: `to_git::flaky` for the
     authority's flows, `both_sides::push` for the push path, and the
     outbox's own tests.
   - Not here: staging a job in chunks (`stage_job`) belongs to the
     message implementation of step 12; `set_approved`'s `retry` flag
     to step 9.
9. **Following approvals moves to the git side.** `follow_approvals` is
   glue: it walks the history (git) and queues a deploy (authority). After
   this step the git side runs it when the approved-set mirror changes:
   `set_approved` carries a `retry` flag for ballots. When the served
   commit moves, the git side submits that commit's job. The authority
   then makes the check that `follow_approvals` makes today: it skips the
   job when the app already runs that commit or a deploy of it is queued
   (`deploy::is_live`, `deploy::in_flight`).
10. **Attestations carry proofs.**
    - `evm_registry_publish` and `evm_registry_publish_site` take the
      record from the git side today (`attest::tip_record`,
      `attest::site_record`). Across the cut, the authority would be
      signing what the git canister says.
    - So the git side returns the artifact with its proof, the same
      `Artifact` a job carries. The authority checks the proof, hashes the
      blob itself, and, for a votes-gated repo, requires the commit to be
      approved.
    - In section 4's listing these are `record_artifact`, and
      `release_job` for `deploy_now`, which asks the git side for its job
      and runs it once it arrives. Either way, the authority acts on bytes it has checked.
11. **Retire the one-time paths.** Some paths exist only for an older
    release's state; once mainnet has run them, they go:
    - `resume_pending`'s `resolve` fallback
    - `tokens::migrate`
    - `site::record_gated_repos`
    - `store::index_repo_labels`
    `post_upgrade` then needs only its own side's state, which is what
    lets it be split in two.

The two canisters:

12. **Two builds.**
    - **`canisters/authority` (`authority_canister.wasm`, for umobs).**
      The lifecycle, the authority's endpoints and their consent
      messages. A `GitSide` that sends messages to the git canister,
      whose id is set once by an operator: the setter checks, through the
      management canister's `canister_info`, that the canister has one
      controller and that the controller itself has none (a governor).
    - **`canisters/git` (`git_canister.wasm`, for the new canister).**
      HTTP, both git services, `/site/`, the git half of `/api`, push
      tokens, the object admin calls and their consent messages. An
      `AuthoritySide` that sends messages to the authority, whose id is
      an init argument.
    - **Who may call.** Each canister accepts the other's calls only from
      the other's principal. Each keeps its own operators (phase 2, step 5: operators are not
      mirrored): controllers and its own allowlist.
    - **The record of the git canister's own module.** The second
      governor calls `registry_publish_canister` on its target after an
      upgrade, as the first governor does on umobs. The git canister holds
      no keys, so it forwards the call (`publish_git_record`). The
      authority reads the git canister's module hash itself, with
      `canister_info`, publishes only if it matches, and writes it under a
      new key in `ic_git_types::keys`, beside `CANISTER_KEY`.
    - **Cycles.** The authority tops up the git canister from the rent it
      collects, on a timer, above a floor it reports in `/api/pricing`.
    - **Where the endpoints land.** They land where their state is, and a
      decision lands where it is made:
      - **The git canister:** `http_request`,
        `http_request_streaming_callback`, `http_request_update`,
        `put_object`, `get_object`, `set_ref`, `list_refs`, `list_repos`,
        every push-token call and `get_site`.
      - **The authority:** everything else, including every setter that
        checks `can_admin` (`set_site` too: the authority decides and
        sends the site config across), membership and ballots, accounts,
        app canisters, the signers, names, the feed, the queue and its
        statuses, and the compile endpoints until the compiler canister.
      - **Clients:** nothing on umobs forwards to the git canister.
        Clients change (step 14).
    - **The reproducible build.** It produces both modules. The recipe in
      REPRODUCIBLE_BUILD.md and `verified.json` name the new artifact
      paths.
13. **The copy and the freeze, in the last one-canister release.**
    - **Freeze.** An operator switch puts the git side in read-only mode:
      pushes, token minting, `create_repo`, `set_site` and the object
      admin calls are refused with a message that names the cut.
      Membership changes and ballots stay open: they reach the git side
      only through the mirrors, which the authority rewrites at the cut.
    - **Export.** Paged update calls export every git-side record:
      objects, repos and refs, push tokens (their hashes, minters, expiries
      and bound keys), site configs and labels. Operators may call them,
      and so may the one importing canister an operator names.
    - **What is not copied.** The push-certificate seed is a secret, and
      the git canister makes its own: a nonce lives for minutes. The
      mirrors are not copied either: the authority rewrites them at the
      cut.
    - **The import.** The git canister pulls the pages with its own update
      calls, so what it gets is what umobs replied, through consensus.
    - **The check.** Each side computes a digest of its copy, record
      count and a hash over the records in key order. The cut proceeds
      only when the two match.
    - **The rehearsal.** The local e2e runs this whole sequence, from the
      last one-canister release.
14. **Clients, before the cut** (as this phase always required):
    - the console talks to both canisters
    - `tools/verify.mjs` takes the site's canister and the registry
      owner's apart
    - `core/verifier.js`, the loader and both extensions have the git
      canister in their expected list (EXTENSION.md, "What the page talks
      to") and a host rule for its `/site/`
    - the verifiers check the git canister's governor and module record
      as they check umobs'
    - docs/ATTESTATION.md gets its two-canister closure paragraph
    - docs/TENANCY.md says that a repo with no votes required trusts the
      git canister for what deploys (decision 6.5.4)

The cut on mainnet, in this order:

15. **The git canister exists before anything moves.** Create it on umobs'
    subnet from the reproducible build, install the second governor with
    the git canister as its target and the same approvers, and hand the
    canister over. Its id is now fixed. Publish the step 14 clients and
    extensions with it.
16. **The cut.**
    1. Freeze umobs (step 13).
    2. The git canister imports, and both digests match.
    3. The governor upgrades umobs to the authority build. Its git-side
       state stays in stable memory, unread.
    4. An operator sets the git canister's id. Until then, every call
       that needs the git side is refused with a message that names the
       cut. The authority rewrites
       every mirror, tops up the git canister's cycles, and publishes both
       canister records.
    5. The git canister unfreezes and takes pushes.
    6. umobs answers the old URLs: `/site/...` and `/<repo>.git/info/refs`
       with a permanent redirect to the same path on the git canister.
       Git follows a redirect on its first request
       (`http.followRedirects`, default `initial`). curl drops the
       credentials on a redirect to another host, so a push through the
       old URL fails, but a fetch still works. A push needs the new
       remote, and the same token works there.
       Until the local e2e confirms this with a real git client, treat it
       as expected, not shown.

    **Rollback** is an upgrade of umobs back to the last one-canister
    release, which still holds every git-side record as of the freeze. The
    authority build keeps the one-canister memory layout throughout the
    retention window, so the authority state written after the cut
    (accounts, ballots, deploys) is kept too. Rollback loses only the git-side
    changes made on the git canister after the cut: pushes, tokens minted
    or revoked, site configs. That is why umobs keeps the
    git-side state for a retention window; a later release frees it.

The compiler canister follows when an ungoverned repo needs `.wat` or
`.lang` builds again.

**Phase 4 -- re-attest.** The authority's module hash changes at phase 3
and then goes quiet. That is the point of the whole exercise.

Phase 1 is the only phase that should proceed without a fresh look at
mainnet state, because it is the only one that cannot affect it.

## 6. Decided: what the authority may trust from the git canister

**Restated and decided 2026-10-28: option D, with the four decisions in
6.5. Sections 3, 4 and 5 are redrawn to match.**

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

The cost: the authority is larger than the signer section 3 first planned. It keeps
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

### 6.5 Decisions (taken 2026-10-28)

1. D over C: proof-carrying jobs, with ballots, policy and accounts on the
   authority.
2. Governed repos deploy committed `.wasm` only; `.wat` and `.lang` builds
   go to the compiler canister. On mainnet this changes nothing: the one
   governed repo, ic-vote, deploys `app.wasm`.
3. A second instance of the governor module governs the git canister.
4. Repos with no votes required keep trusting the git canister for what
   deploys, and the docs say so (TENANCY.md, when the split ships).

## 7. What this does not change

- The public git remote URL changes (new canister id). Anyone with an existing
  remote must update it to push. umobs redirects the old URLs (phase 3,
  step 16), which serves fetches and pages but not pushes: curl drops the
  credentials on a redirect to another host.
- `verify.mjs`'s `--canister` argument becomes ambiguous -- it needs to know
  which canister serves the site and which one owns the registry record. The
  F2 verifier and docs/ATTESTATION.md's step 5 ("full-stack closure") both
  assume one canister today; closure becomes a two-canister property and the
  spec needs a paragraph on it before phase 3.
- The `agrees()` / K-of-N logic is unaffected -- it is keyed on a canister
  string, so two canisters simply means two attestation targets.
