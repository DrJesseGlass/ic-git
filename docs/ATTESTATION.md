# On-chain attestation -- verifiable frontends and backends, per chain

This spec defines how a user, with zero effort, learns that a DeFi frontend
they are looking at is (a) served content that matches attested source, and
(b) served by an IC canister that is running code independent parties
reproduced from that source. Both facts live on the EVM chain the dApp itself
lives on, and the countersign extension reads them automatically.

It closes the two gaps in the provenance stack:

1. Frontend provenance -- "the bytes I loaded match the attested commit."
   Already shipped: the canister writes repo -> commit -> bundleHash, and
   tools/verify.mjs checks a served page against it.
2. Backend verification -- "the canister doing the serving and attesting is
   itself running verified-honest code." New: third parties reproduce the
   canister's wasm (see REPRODUCIBLE_BUILD.md) and attest the result on-chain.

Both are records in one per-chain registry.

## Trust model at a glance

- Native-transaction auth. An attestation is an ordinary Ethereum
  transaction; the verifier's identity is `msg.sender`. There is no signature
  scheme in the payload, no `ecrecover` in the contract, and no Ed25519. On
  EVM chains this is the cleanest and cheapest option, because the
  transaction's own secp256k1 signature already authenticates the verifier
  and there is no Ed25519 precompile to lean on.

- Permissionless contract, trust applied by the client. Anyone may call
  `attest(...)`; the registry stores every attestation. Trust is applied
  off-chain: the extension counts only attestations from its configured set
  of trusted verifier addresses, and requires a threshold K of them to agree.
  The web of trust lives in the extension (like browser CA roots), not on the
  chain. This keeps the contract trivial and censorship-resistant -- the chain
  gatekeeps nothing.

- Two roots of trust for the extension:
  1. the pinned IC root (NNS) BLS public key, used to certify the canister's
     live module hash (see "Certified live module-hash read");
  2. the trusted verifier address set plus threshold K.

- Hashing convention. All content hashes -- moduleHash, bundleHash,
  recipeHash -- are sha256 (moduleHash is the IC's own module hash, sha256 of
  the wasm). keccak256 appears only where the EVM requires it: mapping keys,
  event topics, and ABI selectors.

## The two record types

### 1. Frontend provenance (canister-written)

`recordKey -> commit -> bundleHash`, written only by the canister's EOA (the
registry owner). An entry is the canister's own attestation of what it serves.
Kept as `set`/`get` for backward compatibility -- tools/verify.mjs relies on
the `get(string)` selector `0x693ec85e`.

The key is a namespaced string, not the bare repo name, because the canister
has two independent writers of `set` with incompatible bundleHash semantics:

| recordKey | writer | bundleHash is |
|---|---|---|
| `<repo>` | `registry_publish_commit` (deploy queue auto-publish) | sha256 of the decoded EVM contract bytecode |
| `<repo>#site` | `registry_publish_site` | sha256 of the served site entrypoint |

One slot per bare repo name would let these clobber each other: a repo that
both deploys a contract and serves a site would have its site record
overwritten by the next push, and `verify.mjs` would print `NOT VERIFIED` for a
frontend that is in fact being served correctly. The namespace costs nothing --
the contract is unchanged and the selector is preserved, since the key is just
the string argument -- and keeps the two records independent. `verify.mjs`
resolves which record it needs (see its `--record` flag).

### 2. Backend verification (verifier-written)

`canister -> moduleHash -> commit -> recipeHash`, written by any verifier from
their own address. A verifier is saying: "I ran the build described by
recipeHash on commit, and got moduleHash, which is what the IC reports for
this canister." Latest attestation per (canister, verifier) wins; full history
is in the event log.

## BuildDescriptor and recipeHash

recipeHash binds an attestation to a reproducible procedure, not a bare hash.
It is `sha256(canonical_json(descriptor))`, where the descriptor is the only
language-specific object in the system:

    rust:   { "lang": "rust", "rustc": "1.94.1", "dfx": "0.31.0",
              "target": "wasm32-unknown-unknown",
              "cargoLockSha256": "<hex>", "entry": "canisters/git",
              "baseImage": "rust:1.94.1-slim-bookworm@sha256:<hex>",
              "platform": "linux/amd64", "buildPath": "/build" }

    motoko: { "lang": "motoko", "moc": "0.13.x", "dfx": "0.31.0",
              "entry": "src/main.mo",
              "baseImage": "...", "platform": "linux/amd64",
              "buildPath": "/build" }

`baseImage`, `platform`, and `buildPath` are not decoration: Dockerfile.build
and REPRODUCIBLE_BUILD.md declare all three load-bearing, so a descriptor that
omits them lets two verifiers compute the SAME recipeHash and get DIFFERENT
moduleHashes -- one on linux/amd64, one on darwin/arm64, or against differently
dated `rust:1.94.1-slim-bookworm` tags. On chain that is indistinguishable from
a genuine disagreement about what the canister runs: step 4 below drops the
non-matching attestation, the threshold is missed, and the verdict falls to
YELLOW with no way for a client to tell "different build environment" from "one
verifier is lying". recipeHash claims to encode the environment, so it must.
`buildPath` is likewise the path that `--remap-path-prefix` normalizes to; the
cargo-home token (`/cargo`) is fixed by the recipe and needs no field.

Canonical JSON = UTF-8 (ASCII in practice), keys sorted lexicographically, no
insignificant whitespace. Adding a language is a new descriptor variant; the
attestation record, the contract, and the extension do not change. This is the
"forever" tracking model: language-specific recipe, language-agnostic vouch.

## Contract interface

One contract per chain holds both record types. Reference implementation
(Solidity, sha256/keccak per the convention above):

    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.28;

    /// Provenance + verification registry.
    /// Deployed at a canonical CREATE2 address on every chain it serves,
    /// except chains listed in the client's override table (today: Sepolia,
    /// whose registry predates the scheme). See "Per-chain CREATE2 registry".
    contract Registry {
        address public immutable owner; // the ic-git canister EOA

        // --- Frontend provenance (canister-written) ---------------------
        struct Site { bytes20 commit; bytes32 bundleHash; uint64 updatedAt; }
        // key = keccak256(recordKey), where recordKey is "<repo>" for a
        // deploy-artifact record and "<repo>#site" for a served-site record.
        // The namespace lives in the string, so the contract and the
        // 0x693ec85e selector are unchanged; see "The two record types".
        mapping(bytes32 => Site) private sites;

        event SitePublished(
            bytes32 indexed repoKey, string repo,
            bytes20 commit, bytes32 bundleHash, uint64 at
        );

        /// Bind a record key to its commit and artifact hash.
        /// Owner-only: an entry is the canister's own attestation.
        function set(string calldata repo, bytes20 commit, bytes32 bundleHash)
            external
        {
            require(msg.sender == owner, "only owner");
            bytes32 k = keccak256(bytes(repo));
            sites[k] = Site(commit, bundleHash, uint64(block.timestamp));
            emit SitePublished(k, repo, commit, bundleHash, uint64(block.timestamp));
        }

        /// Current entry. Selector 0x693ec85e -- do not change (verify.mjs).
        function get(string calldata repo)
            external view
            returns (bytes20 commit, bytes32 bundleHash, uint64 updatedAt)
        {
            Site storage s = sites[keccak256(bytes(repo))];
            return (s.commit, s.bundleHash, s.updatedAt);
        }

        // --- Backend verification (verifier-written) --------------------
        struct Attestation {
            bytes32 moduleHash; bytes20 commit; bytes32 recipeHash; uint64 at;
        }
        // keccak256(canister) -> verifier -> latest attestation
        mapping(bytes32 => mapping(address => Attestation)) private attests;

        event Attested(
            bytes32 indexed canisterKey, address indexed verifier,
            string canister, bytes32 moduleHash, bytes20 commit,
            bytes32 recipeHash, uint64 at
        );

        /// Attest that `canister` runs `moduleHash`, reproduced from `commit`
        /// via the build `recipeHash`. Permissionless; identity is msg.sender.
        /// Trust is applied off-chain by the client's verifier set. Latest per
        /// (canister, verifier) wins; history is in the Attested log.
        function attest(
            string calldata canister, bytes32 moduleHash,
            bytes20 commit, bytes32 recipeHash
        ) external {
            bytes32 k = keccak256(bytes(canister));
            attests[k][msg.sender] =
                Attestation(moduleHash, commit, recipeHash, uint64(block.timestamp));
            emit Attested(
                k, msg.sender, canister, moduleHash, commit, recipeHash,
                uint64(block.timestamp)
            );
        }

        /// One verifier's latest attestation for a canister. `at == 0` means
        /// NO attestation exists: an unwritten mapping slot reads back as an
        /// all-zero struct rather than reverting, and `attest` always stamps a
        /// nonzero block.timestamp, so `at` is the existence flag. Callers
        /// MUST check it -- an all-zero return is "never attested", not "the
        /// verifier attested the zero hash".
        function attestation(string calldata canister, address verifier)
            external view
            returns (bytes32 moduleHash, bytes20 commit, bytes32 recipeHash, uint64 at)
        {
            Attestation storage a = attests[keccak256(bytes(canister))][verifier];
            return (a.moduleHash, a.commit, a.recipeHash, a.at);
        }

        /// Convenience: how many DISTINCT `verifiers` have a latest
        /// attestation matching `moduleHash` and `recipeHash` (and `commit`,
        /// if nonzero). Equivalent to the step-4 log scan below, so the
        /// extension may use either; this just saves reads.
        function agrees(
            string calldata canister, bytes32 moduleHash,
            bytes20 commit, bytes32 recipeHash, address[] calldata verifiers
        ) external view returns (uint256 count) {
            // A zero moduleHash is never a real attestation target. Without
            // this, a caller whose certified read failed or decoded to zero
            // would match every never-attested verifier at once (their empty
            // records are all-zero) and get back verifiers.length -- full
            // agreement on a canister nobody has attested.
            require(moduleHash != bytes32(0), "zero moduleHash");
            require(recipeHash != bytes32(0), "zero recipeHash");
            bytes32 k = keccak256(bytes(canister));
            address prev = address(0);
            for (uint256 i = 0; i < verifiers.length; i++) {
                // Strictly ascending, so a repeated address cannot be counted
                // twice. A duplicate in the caller's trusted set (a copy-paste
                // in the shipped config, or a user re-adding an address in
                // different case) would otherwise turn ONE real attestation
                // into a threshold of K, defeating the K-of-N model.
                require(verifiers[i] > prev, "verifiers not sorted/unique");
                prev = verifiers[i];
                Attestation storage a = attests[k][verifiers[i]];
                if (a.at != 0 &&
                    a.moduleHash == moduleHash &&
                    a.recipeHash == recipeHash &&
                    (commit == bytes20(0) || a.commit == commit)) {
                    count++;
                }
            }
        }

        constructor(address _owner) { owner = _owner; }
    }

Notes:
- `attest` is intentionally open. Removing junk attestations is not the
  chain's job; the extension simply never counts an address outside its
  trusted set.
- Events index `verifier` and `canisterKey` so the extension can pull "all
  attestations for canister X by these trusted addresses" in one filtered log
  query. The readable `canister`/`repo` strings ride in the event data.
- `agrees(...)` lets the extension get the threshold count in a single
  `eth_call` if it prefers a point read to a log scan. It takes `recipeHash`
  because step 4's rule requires agreement on it: a variant that compared only
  `moduleHash` would return GREEN where the log scan returns YELLOW, and two
  paths this document calls equivalent must not produce opposite verdicts on
  the same chain state.
- Both read paths are existence-checked (`at != 0`) and both reject a zero
  `moduleHash`. Every "count the agreeing verifiers" implementation must do
  the same: the failure mode is a FALSE GREEN, which is the one direction the
  doctrine below forbids.

## Per-chain CREATE2 registry (one address everywhere)

Deploy through the canonical CREATE2 factory
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`, present on Gnosis, the major
rollups, and Sepolia) with a fixed salt and identical init code. Because the
canister's EOA is the same address on every EVM chain, baking
`owner = <canister EOA>` into the constructor keeps the init code identical
across chains, so the registry lands at the same address everywhere.

Result: the extension has one canonical registry address it uses on any chain,
plus a small, explicitly listed override table for chains whose registry
predates this scheme. When it sees a frontend for a Gnosis dApp, it reads the
registry on Gnosis at the canonical address -- provenance lives on the same
chain as the dApp and the user's wallet, one read, unified trust context.

The override table ships with the trusted-verifier set and today holds exactly
one entry:

    { 11155111: "0xa1362DAda583c56a395D305a8C7A458E0B62A209" }  // Sepolia

Sepolia keeps the existing testnet registry, which was deployed with a raw
CREATE and is therefore nonce-derived: it does NOT sit at the canonical
address, and it is the same address `tools/verify.mjs` defaults to. A chain
absent from the table uses the canonical address. Without the table a client
built on "one address everywhere" reads all-zero words on Sepolia, its
zero-check fires, and it reports "no registry entry for repo" -- a false
absent-provenance verdict on the one chain that currently holds real data.

Deployment reuses the existing push path (the canister already deploys
contracts to EVM chains), with two changes:

1. Send the deploy to the CREATE2 factory (salt + init code) instead of a raw
   CREATE, so the address is deterministic rather than nonce-dependent.
2. Derive and record the CREATE2 address explicitly. The canister's current
   derivation in `canisters/git/src/evm.rs`
   (`contract_address: to.is_none().then(|| checksum_address(&create_address(&from, nonce)))`)
   only fires for a raw CREATE, where `to` is None. A factory deploy sets
   `to = Some(factory)`, so that field comes back None,
   `canisters/git/src/deploy.rs` stores `String::new()`, and the status message
   renders as `deployed to  (chain via evm config)`. The deploy path must
   instead compute
   `keccak256(0xff ++ factory ++ salt ++ keccak256(initCode))[12..]` when the
   destination is the factory. Otherwise the operator has an empty address in
   `evm_deploy_history` and nothing to pass to `verify.mjs --contract`, so
   check C cannot be run against the registry itself.

Recommended first chain: Gnosis -- cheap, EVM-equivalent, mainnet-grade, and
self-contained (its own validators, not dependent on an L1 sequencer for
liveness). A rollup works too.

## The one implementation gap: multi-chain canister config

Verifier attestations need nothing new -- verifiers call `attest(...)` from
their own wallets on whatever chain. But the canister's own frontend-provenance
record (`set`) requires the canister to target that chain, and today
`evm_set_config` holds a single chain (Sepolia). To also write the frontend
record on Gnosis, add multi-chain EVM config. The canister's EOA is the same
address on every chain; fund a little gas per chain.

## Certified live module-hash read

The extension reads the canister's CURRENT module hash from the IC and must
verify it -- an uncertified read from a boundary node is spoofable.

    POST https://icp-api.io/api/v2/canister/<id>/read_state
      path: ["canister", <id>, "module_hash"]

Verification steps:
1. verify the delegation (NNS root key -> subnet key);
2. verify the subnet BLS signature over the state hash-tree;
3. confirm the tree certifies /canister/<id>/module_hash = H_live;
4. check the certificate /time is fresh (bounded staleness), so an attacker
   cannot replay an old certificate showing the previously-verified hash after
   a malicious upgrade.

This needs BLS12-381 verification plus the pinned IC root key -- the one
heavyweight dependency (what @dfinity/agent does internally). Step 4 is what
makes change-detection trustworthy.

## How countersign consumes it

Per page load, in the service worker, honoring the doctrine that a verdict may
only ADD warnings (a check can downgrade, never falsely upgrade):

    1. (existing) Identify the serving canister X and served bundle; confirm
       the loaded frontend matches the attested bundle at commit C_fe.

    2. Read X's CERTIFIED module hash -> H_live (BLS-verified, fresh).

    3. Read the registry on the dApp's chain at the canonical address (or the
       chain's override-table entry):
         - Attested logs for (canisterKey = keccak256(X)) filtered to the
           trusted verifier set; keep each verifier's LATEST record.
         - Frontend record via get("<repo>#site").

    4. Let A = trusted attestations whose moduleHash == H_live. Deduplicate by
       verifier address first, and discard any record that does not exist
       (see the `at != 0` note on the contract). If step 2 did not yield a
       BLS-certified nonzero H_live, A is EMPTY -- never treat a failed or
       zero-decoded read as a hash to match against.
       backendVerified = |A| >= K  AND  all of A agree on one (commit C_be,
       recipeHash).

    5. FULL-STACK CLOSURE: closure means "the canister whose attestations I
       counted is the canister that served me these bytes" -- the H_live of
       step 2 and the canisterKey of step 3 are both for X, the serving
       canister, and the frontend record read in step 3 is the one whose
       bundle matched in step 1.

       Do NOT require C_be == C_fe in the general case. They are commits in
       DIFFERENT repositories: C_fe is the served repo's deploy-branch tip
       (what `registry_publish_site` writes for, say, a third-party DeFi
       frontend), while C_be is the ic-git canister's own source commit that a
       verifier reproduced. Equality essentially never holds, so requiring it
       would make GREEN unreachable for every repo ic-git hosts -- and even for
       ic-git itself, since pushing site content moves C_fe without rebuilding
       or re-attesting the canister.

       Commit equality is meaningful in exactly one case: when the served repo
       IS the canister's own source repo (the self-hosting endgame of
       REPRODUCIBLE_BUILD.md). There, and only there, additionally require
       C_be == C_fe.

    6. Verdict (computed BEFORE step 7):
         GREEN   backendVerified && closure && frontend-match
         YELLOW  frontend matches served bytes, but H_live has < K trusted
                 attestations ("backend running code not yet K-verified")
         RED     H_live matches no trusted attestation, or closure fails
                 ("backend code differs from any verified release")

    7. CHANGE DETECTION: cache (X -> H_live, cert_time). On later loads or a
       periodic alarm, re-read. If H_live changed, ADD the warning "backend
       code changed ~cert_time; awaiting re-verification" and CLAMP the verdict
       to at most YELLOW -- clamp, not set. Step 6 runs first and step 7 may
       only lower its result, per the doctrine above.

       This ordering is the whole point: a compromised controller upgrading X
       to malicious code produces an H_live no trusted verifier has attested,
       which is step 6's RED. A step 7 that assigned YELLOW would RAISE that
       verdict and present the exact scenario this document exists to catch as
       a soft caution. A changed hash that still matches K trusted
       attestations is the benign case -- it is already GREEN at step 6 and
       clamping to YELLOW is the correct, conservative downgrade.

## Manifest mirror (optional, a cache)

An off-chain JSON snapshot of the on-chain records, served from ic-git (itself
hash-attested), lets the extension read fast or offline. It is a cache, not the
root: on-chain records are the source of truth, and the extension can always
fall back to a direct chain read. Shape:

    { "chain": 100,
      "registry": "0x<canonical>",
      "canister": "umobs-yiaaa-aaaab-agyrq-cai",
      "site": { "repo": "...", "commit": "0x..", "bundleHash": "0x.." },
      "attestations": [
        { "verifier": "0x..", "moduleHash": "0x..", "commit": "0x..",
          "recipeHash": "0x..", "at": 0 }
      ] }

## Open decisions and next steps

- Trusted keyset governance: shipped in the extension and user-overridable to
  start (the trust anchor); later it can itself become an attested object.
- Default threshold K (start small, e.g. 2 or 3 named verifiers).
- First chain to deploy the CREATE2 registry (recommend Gnosis).
- Exact canonical-JSON rules for the BuildDescriptor (so recipeHash is
  reproducible byte-for-byte across implementations).

First concrete artifacts to build, in order:
1. The Registry contract above + a CREATE2 deploy through the push path.
2. A `sign-and-attest` step for verifiers: run the reproducible build, then
   send `attest(canister, moduleHash, commit, recipeHash)` from their wallet.
3. The certified module-hash reader (BLS + IC root key + freshness) -- the
   highest-risk piece, worth prototyping first.
4. Wire steps into countersign's service worker and verdict panel.
