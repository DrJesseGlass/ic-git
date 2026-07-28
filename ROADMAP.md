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

Status as of this writing: R0 through R4 are DONE and verified on a live
replica. Each rung's entry below records what was actually built and measured.
Code lives in canisters/git/src: compile.rs (R0), lang.rs (R1/R2/R3),
deploy.rs (deploy path), fleet.rs (R4).

R0 -- wat2wasm on-chain. DONE.
compile_wat(text) -> wasm via the pure-Rust `wat` crate, plus a wasmparser
validation pass (compile_wat_checked) so type-invalid modules are rejected
before deploy. Wired into the deploy path: a git push of a .wat file compiles,
validates, and install_code's the result into a target canister -- verified by
the deployed canister's module hash matching the on-chain sha256. Finding: the
`wat` crate is an assembler, not a validator; wasmparser::validate is the gate.

R1 -- a real language compiler in one canister. DONE.
A small i32 language (functions, + - * /, precedence, unary minus, parens,
variables, cross-function calls with forward references, // comments) compiled
via lexer + recursive-descent parser + wasm-encoder codegen (no LLVM). Proven
by executing the output in wasmi: add(2,3)=5, 2+3*4 vs (2+3)*4, forward calls.
The deploy path dispatches by extension: .wat -> R0, .lang -> R1.

R2 -- instruction-budget engineering. DONE.
Measured the single-message ceiling with ic_cdk instruction_counter over
generated programs: ~42,000 instructions per function, linear. Against the 40
billion instruction message limit that is ~950,000 functions per message, so
for this language the binding limit is the 10 MiB wasm code section (~400K
functions), NOT instructions. Built the checkpoint mechanism anyway: a
resumable job (heap-persisted across update calls) parses once, then codegens a
bounded batch of functions per call. A 40-function compile driven across
separate calls produced byte-identical output to the one-shot compile.

R3 -- separate compilation. DONE.
A module declares imports via `use name(arity);` and compiles in isolation,
knowing only interfaces, never other modules' bodies. Every call is emitted as
a symbolic relocation (a fixed 5-byte LEB128 slot, the LLVM-wasm-object
technique) that a hand-rolled linker patches after assigning global function
indices and checking imports resolve with matching arity. compile_module ->
portable serde object; link -> validated wasm. Cross-module calls execute
correctly (dist2 over an imported sq); link order is irrelevant; error cases
(unresolved import, arity mismatch, duplicate export, undeclared external) all
caught.

R4 -- distributed compilation. DONE.
The coordinator fans compile_module out to a pool of worker canisters
(concurrent inter-canister calls, round-robin via futures::join_all), collects
the objects, and links them. Any git-canister instance is a worker, since it
already exposes compile_module. Verified on a 3-worker fleet: 4 modules with
cross-module imports distributed and linked to a wasm byte-identical to local
compilation; stopping a worker fails exactly the module routed to it, proving
the workers do the compilation. This realizes the thesis: compilation is now
embarrassingly parallel across canisters, with linking the single join point.

R5 -- grow toward Rust (open-ended, NOT started).
Generics via monomorphization, richer types (beyond i32), control flow,
locals/let bindings. Borrow-checking is optional and can come last, or never,
if an unsafe subset is acceptable. See "R5 and the rustc question" below for
what this can and cannot become.

### R5-alt -- a circuit backend, and why it may be the better next rung

PROPOSED, not started. Raised 2026-07-26 from ic-vote's side -- ic-vote is a
SEPARATE repository, not a path in this one; nothing below exists in an
ic-git-only clone. The argument is in ic-vote's `ZK.md` and is summarized here
because the decision belongs to this ladder.

R5 grows the language toward Rust. The rung below it changes the *backend*
instead of the frontend: keep the language small, emit an **R1CS constraint
system** rather than wasm, and compile zero-knowledge circuits on chain.

Why this is a natural fit rather than a detour:

- **R1's language is already almost the right shape.** It is i32 functions
  over `+ - * /`, variables, cross-function calls, no control flow. A
  Semaphore-style membership circuit is field arithmetic over `+` and `*` in
  named sub-circuits that call each other, with no control flow. Poseidon and
  a Merkle path are *nothing but* that -- which is precisely why Poseidon is
  the hash ZK systems standardized on. The delta is a 255-bit field element
  in place of i32, a signal-versus-constant distinction, and an R1CS emitter
  in place of wasm-encoder.
- **R2/R3/R4 carry over untouched.** Lexer, parser, `use name(arity);` module
  interfaces, the symbolic-relocation linker, the resumable job mechanism,
  and fleet distribution all apply unchanged. Constraint systems concatenate
  more cleanly than wasm function bodies, and renumbering signal indices at
  link time is the same operation the linker already performs on function
  indices. Circuit compilation is, if anything, more embarrassingly parallel
  than wasm codegen.
- **It has a finish line, which R5 does not.** "R5 and the rustc question"
  below concludes correctly that this compiler can never match rustc exactly,
  so the wasm language is open-ended by construction. A constraint system has
  no incumbent to match byte-for-byte -- it has to be *sound*, not identical
  to Circom's output. So the rung has a real completion criterion: does it
  compile the Semaphore circuit into a system that accepts exactly the valid
  witnesses. Testable, and it terminates.
- **It is the first case where on-chain compilation is load-bearing rather
  than demonstrative.** A backdoored circuit compiler emits constraints that
  do not match the reviewed circuit source, and every proof downstream still
  verifies -- the ballot-marking-device attack of `ic-vote/VISION.md`,
  relocated into the build. For a generic app, "compiled on chain" is a nice
  property. For a circuit, it is the only thing that closes the gap.

This does **not** give self-hosting. A circuit compiler emits constraints, not
wasm, so it cannot compile itself; REPRODUCIBLE_BUILD.md's R3 still needs the
R5 path. What it gives is REPRODUCIBLE_BUILD.md's **R2** -- the first real
application built on ic-git's own on-chain compiler -- with a customer that
genuinely needs the property rather than merely exhibiting it.

Costs, stated plainly: a new circuit compiler is a new unreviewed compiler,
and under-constrained circuits accept proofs of false statements while looking
perfectly fine. Circom and Noir have absorbed years of adversarial attention
and this would not have.

The mitigation is specified in ic-vote's `docs/CIRCUIT_TESTING.md`, which also
corrects the sketch that first appeared here. Differential testing against
Circom is one of three axes and it is **not** the one that covers
under-constraining -- an under-constrained circuit still produces honest
outputs on honest inputs, so two compilers can be broken in different ways and
agree on every test. Under-constraining needs a determinism analysis instead,
and that tool is compiler-independent: ic-vote's `tools/r1cs-check` consumes
an R1CS from anywhere and is already built and self-testing, before any of
R5-alt exists.

The harness and that tool live in **ic-vote**, not here, and deliberately.
Neither has any ic-git dependency -- the screen consumes an R1CS whoever
emitted it -- and the one step that can be taken today (run it against Circom's
output for the target circuit) needs a circuit, which ic-vote has and this repo
does not. What belongs on this ladder is the decision above, not the tooling.
If R5-alt is ever taken off the shelf, the harness comes back into scope from
there.

Two scope items that fall out of the testing design and belong in any R5-alt
estimate: the backend needs a **witness generator** as well as an R1CS
emitter, or the differential axis cannot run at all; and compile-twice
determinism plus fleet-equals-local must be verified for constraint systems
exactly as R4 already verifies them for wasm.

### R5 and the rustc question: can this ever match rustc exactly?

Short answer: no -- not "match rustc exactly", and that was never the goal.
Keep the two goals from the reframe distinct.

Producing a compiler that accepts the full Rust language and emits the same
wasm rustc does would require reproducing rustc's frontend (a moving target of
hundreds of thousands of lines: full type inference, trait resolution,
borrow-checking, const evaluation, macro expansion) AND its LLVM backend byte
for byte. Nobody has a second conforming Rust implementation; even gccrs and
the Cranelift backend are partial and diverge. So "exactly rustc" is out.

What R5 CAN become is a real, growing language of our own that happens to look
Rust-flavored -- more types, generics by monomorphization (compile a fresh
specialized copy per concrete type set, which shards across the fleet just like
functions do), control flow, structs. It stays a language WE define, with
module-interface boundaries that keep separate compilation and distribution
working. That is genuinely useful and fully on-chain; it is just not stock Rust.

If the literal requirement is "compile real Rust source on-chain," the only
path is Goal 1: get rustc + LLVM themselves running in a canister (via the
wasm32-wasi + wasi2ic route, vendored crates, DTS across many rounds). That is
the multi-year science project, and even then it is "run the real rustc",
not "reimplement rustc" -- the exactness comes from using rustc itself, not
from matching it. The two honest options are therefore: (a) our own growing
language, distributed and on-chain now; or (b) host the real rustc someday and
inherit its exactness. There is no cheap middle path that is both stock Rust and
our own compiler.

### R6 (Goal 1): host the real rustc on-chain via rubrc

This is the chosen direction for exactness: run the actual rustc in a canister,
so the output IS rustc's output. It is distinct from R5 (our own Rust-flavored
language, Goal 2). R6 is a multi-quarter effort with real unknowns; this section
captures the plan, the verified numbers, the architecture forced by them, and a
spike sequence to get the first measured data point.

All sizes below were verified from primary sources in July 2026 (see the
research notes in the conversation history); estimates are tagged.

#### The core artifact we build on: rubrc

rubrc (github.com/oligamiq/rubrc) is the only known project that compiled rustc
itself to wasm (wasm32-wasip1, via rustc's LLVM backend) and ran it -- in a
browser, behind a WASI shim, using threads (COOP/COEP). We reuse its rustc.wasm.
We do NOT reuse its host: the browser gives rubrc four things the IC does not,
and each is a real gap (below). "Build off rubrc" means "take its rustc.wasm,
then rebuild everything around it for a harsher host."

#### The size reality that forces the architecture

- IC code-section cap: 10 MiB (10,485,760 bytes), plus 50,000 functions and
  1,000,000 instructions per function body per canister module. Total module
  100 MiB, heap 4 GiB (wasm32) / 6 GiB (wasm64), stable memory 500 GiB.
- clang compiled to wasm: 46.7 MB (MEASURED, binji/wasm-clang). rustc + LLVM to
  wasm: 50-100+ MB (ESTIMATED -- rustc's crates on top of the same LLVM).
- LLVM_TARGETS_TO_BUILD=WebAssembly saves only ~20-40% (ESTIMATED): LLVM's bulk
  is target-INDEPENDENT (CodeGen ~24 MB, Core/IR ~21 MB, Analysis ~15 MB), and
  the middle-end cannot be stripped because rustc needs it to emit wasm.

Conclusion: rustc.wasm cannot be a canister's own code -- it is ~5-10x over the
10 MiB code section, and LLVM alone exceeds the 50,000-function cap. Forks
cannot close a 5-10x gap with a 20-40% cut. So rustc.wasm must be DATA, not
code.

#### The architecture: interpret rustc.wasm as data

- Canister code = a wasm interpreter (wasmi -- the same one R1-R4 tests use --
  pure Rust, fits the 10 MiB code section).
- rustc.wasm (46-100 MB) lives in STABLE MEMORY (500 GiB; trivially fits). As
  data, it dodges every module-size/function-count cap.
- rustc's filesystem (sysroot, vendored core/alloc/std for wasm32-unknown-unknown,
  vendored crates) via wasi2ic / ic-wasi-polyfill backed by stable memory.
- rustc's working memory (linear memory of the interpreted module) lives in the
  canister heap, which persists across update calls.
- Output wasm flows into the existing R0-R4 deploy pipeline unchanged.

This respects ALL of IC's structural limits, because the compiler is data. The
price is entirely SPEED.

#### The four gaps vs the browser (why rubrc does not port for free)

1. JIT vs interpret (the expensive one). Browsers JIT rustc.wasm to native;
   near-native speed, no size ceiling. The IC can only run wasm as native when
   it is a canister's own code -- forbidden here by the size/function caps. So
   we INTERPRET rustc.wasm with wasmi: MEASURED ~22x slower (see spike results
   below; was estimated 10-50x). This single difference is the entire
   on-chain-rustc slowdown, and it traces to one number: the 10 MiB
   code-section cap.
2. Threads vs single-threaded. rubrc uses wasm threads; canisters are
   single-threaded and must be deterministic across replicas. Rebuild rustc
   single-threaded (-Z threads=1, single codegen unit) and force determinism
   (hashmap order, timestamps, enumeration order).
3. Browser WASI shim vs wasi2ic. Replace rubrc's browser-shaped syscall/FS shim
   entirely with a stable-memory-backed one.
4. Run-to-completion vs pausable. A browser runs rustc to completion; one
   interpreted compile will exceed even a single DTS message's 40B-instruction
   budget, so wasmi must PAUSE mid-execution and RESUME in the next update call.
   wasmi does not do this natively -- "run N instructions, yield, resume" is a
   real modification. (Upside: the heap persists between calls, so rustc's state
   survives for free.) Plus all crates must be vendored ahead of time -- no
   crates.io fetch.

#### The cost, stated plainly

Exact (it is real rustc) and on-chain (replicated, trustless). But: minutes for
trivial code, plausibly hours for a real crate, spread over many consensus
rounds; cycle-expensive; every subnet node re-runs the whole interpreted
compile. Feasible, not fast.

#### The one external unlock (lobby in parallel)

Every expensive part traces to the 10 MiB code-section cap (and 50k-function
cap). If DFINITY raised those, rubrc's rustc.wasm could deploy as a
chunked-installed canister and the IC's own runtime would JIT it to native --
near-native on-chain rustc, no interpreter tax, and "build off rubrc" becomes
nearly literal (port the shim to wasi2ic, force determinism, done). The 100 MiB
TOTAL module limit already exists; it is the 10 MiB code SUB-limit and the
function count that block it. Worth pushing for -- on-chain compilation is a
flagship use case.

#### Spike sequence (get a measured number before committing)

The research flagged that nobody has published rustc.wasm's actual size or an
interpreted compile time -- we would be first to measure both.

1. Produce rustc.wasm from rubrc's recipe, single-threaded + deterministic;
   measure code-section size and function count with wasm-objdump -h. (Heavy
   external toolchain build -- hours of compiling LLVM+rustc to wasm.) NOT DONE.
2. Stand up wasmi in a canister + a minimal WASI host; run a wasm32-wasip1
   program through it. DONE -- see interp.rs. wasmi builds for
   wasm32-unknown-unknown and fits: the canister grew from 3.95 MiB to 5.71 MiB
   with wasmi embedded, well under the 10 MiB code section. Confirms the R6
   architecture (interpreter as canister code, guest as data) is size-feasible.
3. Feed a program through it and measure interpretation cost. DONE for a
   synthetic guest (the run_wat method: compile WAT via R0, then interpret via
   wasmi, all on-chain). Still PENDING for a real Rust compile, which needs
   rustc.wasm from step 1.
4. Make wasmi pausable/resumable across update calls for real crates. NOT DONE.

#### Spike results (MEASURED, this repo)

- wasmi embedded in the canister: +1.76 MiB (3.95 -> 5.71 MiB code). Fits.
- WASI host: minimal (fd_write capturing stdout/stderr, proc_exit); enough to
  run and observe a guest. The full rustc surface (a filesystem over stable
  memory) is the main remaining work.
- Interpretation multiplier: ~22x canister instructions per guest instruction,
  stable across guest sizes (23.3x at 1e5 loop iters, 22.2x at 1e6, 22.1x at
  5e6 as fixed setup amortizes). This is the load-bearing number.
- Fixed per-run overhead (module load + validate + instantiate): ~1.5M
  canister instructions, negligible once the guest does real work.

Extrapolation from the 22x multiplier: one update message (~40B instructions,
DTS across rounds) interprets ~1.8B guest instructions. A native rustc compile
of hello-world is roughly 1e8-1e9 instructions, so interpreted that is
~2e9-2e10 canister instructions = ~1-6 messages, i.e. seconds-to-minutes of
replicated compute spread over consensus rounds. A real crate (10-100x more) is
minutes-to-hours -- which is exactly why step 4 (pausable wasmi) is mandatory,
not optional. These are extrapolations from the measured 22x, not a measured
rustc compile; step 1 + a real run would confirm them.

#### Kill criteria

- If step 3's hello-world compile needs more instructions than is affordable in
  cycles at any realistic build volume, R6 is uneconomical until the code-section
  cap is raised -- fall back to off-chain rustc + on-chain reproducible-hash
  verification (exact result, trustless, cheap) and revisit R6 if limits change.
- If rustc.wasm's working set exceeds 4 GiB (wasm32 heap) for target crates,
  wasm64 (6 GiB) or per-crate chunking is required; re-scope.

#### Decision (current): the compiler track is shelved

The on-chain-compiler track (R5 own-language, R6 host-rustc) is SHELVED, not
abandoned. Rationale: for "exact rust" the only path is real rustc, and hosting
it on-chain is feasible-but-slow (measured ~22x interpret tax) with heavy
ongoing fork upkeep; a from-scratch compiler cannot be bit-exact with rustc.
Neither is worth the cost right now.

The chosen practical path instead: build locally with real rustc (exact, fast),
push source + prebuilt .wasm to ic-git, which deploys it and records an
immutable commit -> wasm-hash binding (DONE -- see deploy.rs: produce_wasm for
.wasm artifacts, DeployRecord provenance log, get_deploy_history). The commit
SHA content-addresses the exact source tree, so "the build used the on-chain
files" is guaranteed by git hashing; reproducibility makes the source -> binary
link checkable by anyone rebuilding the commit. No on-chain compiler, no ZK
needed for the common case. A K-of-N builder quorum (R4's adversarial-verify
idea applied to whole builds) is the future upgrade if trustlessness is needed;
a ZK proof of compilation is the trustless-someday option, impractical for
rustc today (proving cost) but tractable for our own small compiler as a demo.

Revisit note (rubrc decomposition): the idea of splitting rustc's stages
(parse / typeck / MIR / codegen) into separate canisters does NOT reduce
per-canister size -- rustc is monolithic, its stages share one in-memory
context (TyCtxt) and all pull in most of LLVM. Unlike our own compiler (which we
designed for separation in R3/R4), rustc cannot be sharded that way without
reproducing the whole thing per stage. Captured here so we do not re-derive it.

### Fault tolerance for the fan-out (a concrete R4+ follow-up)

R4 today fails the whole build if any worker fails (a stopped or trapping
worker errors its module). Two independent, cheap hardenings:

- Retry / reassign: on a worker error, re-dispatch that module to another
  worker. compile_module is a pure function of its source, so re-running it
  anywhere is safe and deterministic -- retries cannot corrupt the result.
- Adversarial verification (determinism check): dispatch the same module to two
  or three distinct workers and compare object hashes. They MUST match (the
  compile is deterministic); a mismatch means a faulty or dishonest worker, and
  the majority wins. This is the same quorum idea the IC uses under the hood,
  applied at the compile-object level, and it is what lets an untrusted worker
  pool still produce a trustworthy binary.

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

## Concrete start (historical -- all of this is now DONE)

The plan below is what was executed; R0-R4 are complete. Kept for the record.

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
