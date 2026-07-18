# Roadmap: cross-chain deploy and on-chain build

This document plans two directions that extend ic-git past milestone 4
(deploy-on-main). Both build on the same spine: the git canister already
holds source and the commit graph in stable memory and already has a
timer-driven deploy trigger. We reuse that trigger to (a) deploy to other
chains and (b) eventually compile on-chain.

Facts below were verified against ICP docs and project sources in July 2026;
see "Sources" at the end. Numbers move -- re-check the load-bearing ones
before you depend on them.

Two tracks, run in parallel:

- Track A -- cross-chain deploy, EVM first. Near-term, high confidence.
- Track B -- a distributed on-chain wasm compiler. Long game, built as a
  ladder of shippable rungs.

--------------------------------------------------------------------------

## The constraints that shape both tracks

Verified IC limits (July 2026):

- Instructions: 40 billion per update call, 5 billion per query. Deterministic
  time slicing (DTS) lets one large message suspend and resume across
  consensus rounds, so a single logical computation can exceed one round --
  but every replica in the subnet re-executes it, so the work must be
  deterministic and is not free.
- Wasm module: 100 MiB total per canister, of which the code section is at
  most 10 MiB. Ingress messages cap at 2 MiB, so large modules install via
  chunked upload (upload_chunk + install_chunked_code).
- Memory: 4 GiB wasm32 heap (hard 32-bit limit), 500 GiB stable memory.
- No filesystem, no threads, no network syscalls, no wall-clock or RNG
  nondeterminism. Anything that assumes those must be shimmed.

Two consequences drive everything:

1. Determinism is mandatory, not optional. Replicas must agree byte-for-byte.
   This is why a compiler on-chain is hard (rustc has nondeterminism sources)
   and why signing other chains' transactions is easy (chain-key crypto is
   deterministic by construction).
2. The instruction budget is a wall only if the unit of work is a whole
   crate. Sharded per-function or per-module, the wall moves. That is the
   central idea behind Track B going "distributed."

--------------------------------------------------------------------------

## Track A: cross-chain deploy, EVM first

### Why EVM first

A contract deployment on any EVM chain is a normal transaction with
`to = null` and `data = <init bytecode>`. The canister derives its own
Ethereum externally-owned account (EOA) via threshold ECDSA, signs the
transaction, and broadcasts it through the EVM RPC canister
(`eth_sendRawTransaction`). This is production machinery today. The same code
path serves Ethereum, Arbitrum, Base, Optimism, Polygon, Avalanche -- only
the chainId and gas parameters change.

Verified building blocks:

- Threshold ECDSA (secp256k1): GA since 2023. `ecdsa_public_key` derives the
  key, `sign_with_ecdsa` signs. Cost 26,153,846,153 cycles (~$0.03) per
  signature on the production fiduciary subnet.
- EVM RPC canister (dfinity): does not sign; it broadcasts signed
  transactions and reads chain state via multi-provider HTTPS outcalls with
  consensus. Cost scales with request/response size, subnet size, and number
  of providers queried.
- ic-alloy: a fork of alloy-rs that plugs ICP in as an Alloy transport and
  signer (threshold ECDSA + EVM RPC). Strongly consider it to collapse most
  of the plumbing into library calls. Verify it is current before adopting.

The one non-negotiable: the canister's derived EOA must hold native gas
(ETH, etc.) on each target chain. The canister pays for its own deploys.

### Phases

Phase E0 -- signing spine.
Derive the canister EOA (ecdsa_public_key -> keccak256 of the uncompressed
pubkey -> last 20 bytes). Fund it by hand on a testnet (Base Sepolia or
Sepolia). Sign and broadcast a plain value transfer via eth_sendRawTransaction.
Deliverable: a transfer lands on-chain, signed by the canister.

Phase E1 -- contract deployment.
Build a CREATE transaction (to = null, data = init bytecode), RLP-encode with
EIP-155 chainId, sign, broadcast, then poll eth_getTransactionReceipt for the
deployed address. Use a trivial precompiled contract's bytecode committed to a
repo as a hex blob.
Deliverable: a contract deployed from the canister, address returned.

Phase E2 -- wire into ic-git.
Extend .ic-deploy.json with a target field. On push to main with
target = "evm", read the bytecode artifact from the pushed tree (reuse the
existing object walk), deploy it, and write {address, tx_hash, chain_id} back
into repo state.
Deliverable: git push compiles-nothing but deploys committed bytecode to EVM.

Phase E3 -- multi-chain.
Parametrize chainId + RPC endpoint. Add EIP-1559 fee logic (eth_feeHistory)
and eth_estimateGas. Test Base, Arbitrum, Optimism testnets -- identical code
path.
Deliverable: one config field selects the target chain.

Phase E4 -- robustness.
Nonce tracking in stable memory (do not trust eth_getTransactionCount
mid-flight). Idempotency keyed on artifact hash (never redeploy identical
bytecode). Gas-balance monitoring so the EOA does not run dry silently.
Retry/replacement logic.
Deliverable: safe to leave running unattended.

### Later: Solana and Bitcoin

Solana (deferred -- mechanically possible, thin prior art).
Threshold Ed25519 signing plus the SOL RPC canister (live via NNS proposal
#136985, 2025) give a canister full Solana access. But deploying a program is
heavy: the SBF ELF is written to a buffer account through many Write
transactions, then finalized via the loader (loader-v3 BPFLoaderUpgradeable
is default; loader-v4 exists and can change the transaction count). A
150-200 KB program is 150-200 signed transactions, each needing a threshold
signature (~$0.03) and an RPC outcall. Feasible; expensive and slow. No known
production prior art beyond value transfers. Re-verify loader-v4 status before
committing -- it changes the arithmetic.

Bitcoin (deferred -- different model).
Native Bitcoin integration plus threshold Schnorr (BIP340) let a canister
spend taproot outputs. Bitcoin has no general contracts, so "deploy" means
inscribing data (ordinals/runes) or committing taproot script trees. BitVM is
experimental. Concrete and doable: a canister anchoring/inscribing data.
General contract deployment: not applicable.

--------------------------------------------------------------------------

## Track B: a distributed on-chain wasm compiler

### The reframe

"Rust -> wasm32 on-chain" hides two very different goals:

Goal 1 (the wall): stock rustc -> wasm32 on-chain. rustc's only production
wasm backend is LLVM (rustc_codegen_cranelift targets native machine code, not
wasm). LLVM-in-wasm is a 100s-of-MB, single-threaded toolchain. This is a
multi-year science project. Do not start here.

Goal 2 (the ladder): a compiler we build, for a language we control, that
emits wasm32 directly via wasm-encoder / walrus (pure Rust, deterministic,
targets wasm32-unknown-unknown). We bypass LLVM entirely. This is buildable
incrementally, and this is where "distributed" earns its keep.

Why the IC is secretly a good host for Goal 2: a canister is a deterministic,
replicated compute node, and compilation is embarrassingly parallel at two
granularities -- separate compilation (per module, given explicit module
interfaces) and codegen (per function). So the distributed model is: a
coordinator canister maps compile jobs across a fleet of worker canisters,
each compiling one module or function inside its own instruction budget, and
links the resulting wasm objects. Determinism is free -- replicas already
agree.

The honest bottleneck: whole-program type inference does not shard. Separate
compilation with explicit module interfaces is exactly how we dodge it -- we
trade global inference for module boundaries we define. That design tax is why
the language is a subset we control, not stock Rust.

### The ladder (each rung ships and demos)

R0 -- wat2wasm on-chain (days).
Canister method compile_wat(text) -> wasm bytes using the pure-Rust `wat`
crate. Trivial compiler, but it proves the whole loop: source in git ->
canister compiles -> deploy the output. This is Day 1.

R1 -- a tiny real compiler in one canister (1-2 weeks).
A small expression/stack language -> wasm via wasm-encoder. We own
lex -> parse -> typecheck -> emit, and we learn how large an input fits in one
update message and how to checkpoint across DTS rounds.

R2 -- instruction-budget engineering (ongoing).
Spill intermediate representation to stable memory, resume a compile across
consensus rounds, and measure the real per-message ceiling. This is the
load-bearing skill for every rung above.

R3 -- separate compilation (2-4 weeks).
Define a module-interface format. Compile one module per message against its
dependencies' published interfaces. Now the frontend shards, not just codegen.

R4 -- go distributed (the milestone).
Coordinator + worker canisters. Fan compile jobs across the fleet via
inter-canister calls, collect wasm objects, link them (walrus / wasm-encoder).
The paper-worthy result.

R5 -- grow toward Rust (open-ended).
Generics via monomorphization, richer types. Borrow-checking is optional and
can come last, or never, if an unsafe subset is acceptable.

### The convergence with Track A

A shortcut that serves both tracks: host solc in a canister via wasi2ic. solc
ships as an emscripten/wasm build; wasi2ic (wasm-forge) rewrites wasm32-wasi
modules to run on the IC by rerouting WASI calls to a stable-memory polyfill.
The polyfill demonstrably carries real C/wasm binaries (see ic-rusqlite, which
runs SQLite this way). If solc fits the module-size and memory limits, ic-git
could compile Solidity on push and deploy to EVM entirely on-chain -- no
external CI in the loop.

Caveat, and the single riskiest claim in this document: solc-in-a-canister is
unproven. It must fit inside 10 MiB code section / 100 MiB module / 4 GiB heap,
and compile within the 40B-instruction budget (DTS across rounds if needed).
Treat "host solc via wasi2ic" as a spike to prove or kill early, not an
assumption. It is a consumer-of-a-big-binary path, distinct from the R0-R5
build-our-own-compiler ladder.

--------------------------------------------------------------------------

## Concrete start

Day 1.
Add a canister method compile_wat. Confirm the `wat` and `wasm-encoder`
crates build for wasm32-unknown-unknown (they are pure Rust; verify by
building). Compile a hello-world WAT string inside the canister, return the
bytes. Pipeline proven.

Day 2-3.
Feed the WAT from a file in a repo via the existing object store. Deploy the
compiled wasm through the m4 install_code path. Now a git push compiles-and-
deploys on-chain -- trivially, but end-to-end.

In parallel (Track A, independent cadence).
Stand up EVM Phase E0 on Base Sepolia: derive the EOA, fund it, broadcast a
transfer. No dependency on the compiler work.

--------------------------------------------------------------------------

## Open decisions

- Track B language target: eventually-real-Rust (Goal 1, the LLVM wall) versus
  a Rust-flavored subset we control (Goal 2, tractable). R3/R4 assume the
  subset. This choice shapes the whole ladder and should be made before R1.
- Whether to spike solc-via-wasi2ic early. It could shortcut the entire
  compile-Solidity-then-deploy-to-EVM story, or prove infeasible on the
  size/memory limits. Cheap to test, high information value.
- Gas funding model for Track A: how the canister's per-chain EOAs are funded
  and topped up (manual, cycles-to-gas swap service, or a treasury canister).

--------------------------------------------------------------------------

## Sources

Verified July 2026.

Chain fusion and signing:
- Threshold ECDSA: https://docs.internetcomputer.org/building-apps/network-features/signatures/t-ecdsa
- Threshold signatures, how it works: https://internetcomputer.org/docs/references/t-sigs-how-it-works
- Threshold Schnorr: https://internetcomputer.org/docs/building-apps/network-features/signatures/t-schnorr
- Signature cycle cost (26,153,846,153 cycles): https://docs.internetcomputer.org/references/cycle-costs/
- EVM RPC canister overview: https://docs.internetcomputer.org/building-apps/chain-fusion/ethereum/evm-rpc/overview
- EVM RPC canister repo: https://github.com/internet-computer-protocol/evm-rpc-canister
- ic-alloy: https://github.com/ic-alloy/ic-alloy
- ic-alloy write-up: https://dev.to/kristoferlund/build-multi-chain-applications-with-ic-alloy-and-the-internet-computer-3k84
- Solana integration overview: https://docs.internetcomputer.org/building-apps/chain-fusion/solana/overview
- SOL RPC canister repo: https://github.com/dfinity/sol-rpc-canister
- SOL RPC announcement: https://medium.com/dfinity/icp-connecting-bitcoin-ethereum-and-now-solana-4565ed602565
- Solana program deployment (loaders): https://solana.com/docs/programs/deploying

IC limits and on-chain build tooling:
- Canister resource limits: https://docs.internetcomputer.org/building-apps/canister-management/resource-limits
- Deterministic time slicing (instruction limit raised to 40B): https://forum.dfinity.org/t/deterministic-time-slicing/10635
- Chunked module install: https://forum.dfinity.org/t/wasm-chunking-for-install-code-method/21944
- wasi2ic: https://github.com/wasm-forge/wasi2ic
- ic-wasi-polyfill carrying SQLite (ic-rusqlite): https://github.com/wasm-forge/ic-rusqlite
