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

`repo -> commit -> bundleHash`, written only by the canister's EOA (the
registry owner). An entry is the canister's own attestation of what it serves.
Kept as `set`/`get` for backward compatibility -- tools/verify.mjs relies on
the `get(string)` selector `0x693ec85e`.

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
              "cargoLockSha256": "<hex>", "entry": "canisters/git" }

    motoko: { "lang": "motoko", "moc": "0.13.x", "dfx": "0.31.0",
              "entry": "src/main.mo" }

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
    /// Deployed at a canonical CREATE2 address on every chain it serves.
    contract Registry {
        address public immutable owner; // the ic-git canister EOA

        // --- Frontend provenance (canister-written) ---------------------
        struct Site { bytes20 commit; bytes32 bundleHash; uint64 updatedAt; }
        mapping(bytes32 => Site) private sites; // key = keccak256(repo)

        event SitePublished(
            bytes32 indexed repoKey, string repo,
            bytes20 commit, bytes32 bundleHash, uint64 at
        );

        /// Bind a repo to its deploy-branch tip commit and served bundle hash.
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

        /// One verifier's latest attestation for a canister.
        function attestation(string calldata canister, address verifier)
            external view
            returns (bytes32 moduleHash, bytes20 commit, bytes32 recipeHash, uint64 at)
        {
            Attestation storage a = attests[keccak256(bytes(canister))][verifier];
            return (a.moduleHash, a.commit, a.recipeHash, a.at);
        }

        /// Convenience: how many of `verifiers` have a latest attestation
        /// matching `moduleHash` (and `commit`, if nonzero). The extension can
        /// compute this from the event log instead; this just saves reads.
        function agrees(
            string calldata canister, bytes32 moduleHash,
            bytes20 commit, address[] calldata verifiers
        ) external view returns (uint256 count) {
            bytes32 k = keccak256(bytes(canister));
            for (uint256 i = 0; i < verifiers.length; i++) {
                Attestation storage a = attests[k][verifiers[i]];
                if (a.moduleHash == moduleHash &&
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
  `eth_call` if it prefers a point read to a log scan.

## Per-chain CREATE2 registry (one address everywhere)

Deploy through the canonical CREATE2 factory
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`, present on Gnosis, the major
rollups, and Sepolia) with a fixed salt and identical init code. Because the
canister's EOA is the same address on every EVM chain, baking
`owner = <canister EOA>` into the constructor keeps the init code identical
across chains, so the registry lands at the same address everywhere.

Result: the extension has ONE registry address to look for on any chain. When
it sees a frontend for a Gnosis dApp, it reads the registry on Gnosis at that
canonical address -- provenance lives on the same chain as the dApp and the
user's wallet, one read, unified trust context.

Deployment reuses the existing push path (the canister already deploys
contracts to EVM chains), with one change: send the deploy to the CREATE2
factory (salt + init code) instead of a raw CREATE, so the address is
deterministic rather than nonce-dependent.

Recommended first chain: Gnosis -- cheap, EVM-equivalent, mainnet-grade, and
self-contained (its own validators, not dependent on an L1 sequencer for
liveness). A rollup works too. Sepolia keeps the existing testnet registry.

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

    3. Read the registry on the dApp's chain at the canonical address:
         - Attested logs for (canisterKey = keccak256(X)) filtered to the
           trusted verifier set; keep each verifier's LATEST record.
         - Frontend record via get(repo).

    4. Let A = trusted attestations whose moduleHash == H_live.
       backendVerified = |A| >= K  AND  all of A agree on one (commit C_be,
       recipeHash).

    5. FULL-STACK CLOSURE: require C_be == C_fe -- the backend serving you is
       verified at the same commit whose source produced the frontend you see.

    6. Verdict:
         GREEN   backendVerified && closure && frontend-match
         YELLOW  frontend matches served bytes, but H_live has < K trusted
                 attestations ("backend running code not yet K-verified")
         RED     H_live matches no trusted attestation, or closure fails
                 ("backend code differs from any verified release")

    7. CHANGE DETECTION: cache (X -> H_live, cert_time). On later loads or a
       periodic alarm, re-read. If H_live changed, surface "backend code
       changed ~cert_time; awaiting re-verification" and drop to YELLOW until
       fresh attestations for the new hash reach threshold.

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
