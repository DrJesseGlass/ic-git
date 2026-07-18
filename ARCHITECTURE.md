# ic-git - a minimal git remote on an Internet Computer canister

A single Rust canister that speaks git's smart-HTTP protocol, stores objects in
stable memory, and redeploys a stock asset canister whenever `refs/heads/main`
moves. `git clone` / `git push` work with an unmodified git client pointed at
`https://<canister-id>.raw.icp0.io/<repo>.git`.

## Goals / non-goals

**Goals**

- Host public open-source repos: `clone`, `fetch`, `push` with stock git.
- On push to `main`, publish the tree (or a configured subdirectory) to an
  asset canister - merge-to-main *is* the deploy.
- Minimal: one repo type, no issues/PRs/web UI (a read-only file browser can
  come later for free, since the objects are already on-chain).

**Non-goals (v1)**

- Server-side delta storage or optimal packs (we serve non-delta packs).
- Shallow clones, partial clone filters, protocol v2, LFS.
- Build steps. The canister deploys files as they exist in the tree; anything
  that needs `npm build` commits its `dist/` or builds in external CI. (An
  HTTPS-outcall build trigger is a possible v2.)
- Private repos (reads are public queries; auth applies to push only).

## The four ICP constraints that shape everything

| Constraint | Value | Consequence |
|---|---|---|
| Max ingress payload | 2 MiB | A single `git push` packfile must fit in ~1.9 MiB. Large pushes need chunking (see the "Push size" section). |
| Max query response | 3 MiB (streamable) | Clone packfiles are served via the HTTP gateway's **streaming callback** - unlimited total size, ~2 MiB per chunk. |
| Instructions per call | 5 B query / 40 B update (DTS) | zlib inflate/deflate of a few MiB per call is fine; pack generation for huge repos must be chunk-incremental (streaming naturally provides this). |
| Certification on non-raw gateway | required | Serve on `*.raw.icp0.io` in v1. This is not the weak point it looks like - see the "Trust model" section. Integrity comes from signed tags (now) and certified ref advertisements + verifying clients (v2), not from which gateway domain we use. |

Reads (`clone`/`fetch`) are **query calls** - free-ish, fast, streamable.
Writes (`push`) are **update calls** via `http_request_update` - consensus,
2 MiB-capped, cycles-metered. This asymmetry is why the design favors doing
all the clever work on the read path and keeping the write path dumb.

## Components

```mermaid
flowchart LR
    dev[git client] -->|smart HTTP over raw gateway| G[git_canister]
    subgraph IC
        G -->|"objects, refs (stable memory)"| S[(StableBTreeMap store)]
        G -->|"post-receive: chunked upload<br/>create_batch / create_chunk / commit_batch"| A[asset canister]
    end
    A -->|serves site| users[browsers]
```

- **`git_canister`** (Rust, `ic-cdk` + `ic-stable-structures` +
  [`ic-dev-kit-rs`](https://github.com/DrJesseGlass/ic-dev-kit-rs)): HTTP
  endpoints, pkt-line codec,
  packfile reader/writer, object store, refs, push auth, deploy trigger.
  Multi-repo: path prefix `/<repo>.git/...` keys everything.
  From the dev kit: `http` (request/response types, `upgrade_response()`,
  routing helpers), `auth` (principal allowlist guarding the candid admin
  API, persisted across upgrades), and later `large_objects` (chunked
  uploads, see the "Push size" section) and `telemetry`. Streamed clone
  responses use the dev kit's `StreamingStrategy`/`StreamingCallbackToken`
  types (in the dev kit since v0.3.0).
- **asset canister**: the stock certified-assets canister from the SDK
  (`dfx`'s frontend canister). `git_canister`'s principal is granted `Commit`
  permission so it can upload. Zero custom code here.
- **(v2) `git-remote-ic`**: a git remote-helper binary that talks to the
  canister with agent calls (chunked, identity-signed) instead of HTTP -
  lifts the 2 MiB push limit and replaces token auth with II/ed25519
  identities. Not needed for v1.

## Data model (stable memory)

Everything content-addressed and loose - no server-side packs, no GC needed
because objects are immutable and refs only add reachability.

```
objects  : StableBTreeMap<[u8;20], Vec<u8>>   // SHA-1 -> [pack type code][content len u32 LE][zlib(content)]
refs     : StableBTreeMap<(RepoId, String), [u8;20]>   // "refs/heads/main" -> oid
repos    : StableBTreeMap<RepoId, RepoMeta>   // HEAD symref, deploy config, created_at
tokens   : StableBTreeMap<[u8;32], TokenMeta> // sha256(push token) -> repo perms
deploy_q : StableVec<DeployJob>               // pending deploys (see the Deploy section)
```

A schema version stamped in the meta map guards the value encoding:
post_upgrade traps (aborting the upgrade, keeping the old code serving) if
stable data was written under a different layout, so format changes need an
explicit migration and can never be misread mid-request.

At 500 GiB stable memory and ~$5/GiB-year storage cost, capacity is not the
issue; per-message throughput is.

RepoMeta carries the deploy config, read from `.ic-deploy.json` at the repo
root on each main update (fall back to defaults). Two modes:

```json
{ "source_dir": "dist", "asset_canister": "<principal>", "branch": "main" }
```

```json
{ "wasm": "artifacts/canister.wasm.gz", "canister": "<principal>", "mode": "upgrade" }
```

Asset mode publishes a static site; wasm mode reads the blob from the pushed
tree and upgrades the target canister via the management canister's
`install_code` - merge-to-main deploys canister code, not just sites.

## Protocol: what we implement

Smart HTTP, protocol v0/v1 - four routes:

| Route | Call type | Purpose |
|---|---|---|
| `GET /<r>.git/info/refs?service=git-upload-pack` | query | ref advertisement for clone/fetch |
| `POST /<r>.git/git-upload-pack` | query(1) | want/have negotiation -> packfile (streamed) |
| `GET /<r>.git/info/refs?service=git-receive-pack` | query | ref advertisement for push |
| `POST /<r>.git/git-receive-pack` | **update** (`upgrade=true`) | ref update commands + packfile in |

(1) upload-pack is read-only, so it stays a query. The POST body (wants/haves)
is well under limits; the *response* streams.

Advertised capabilities, deliberately tiny:
`report-status delete-refs ofs-delta agent=ic-git/0.1` on receive-pack;
`side-band-64k ofs-delta agent=ic-git/0.1` on upload-pack.
No `multi_ack`/`no-done`: the server single-NAKs every negotiation round
until the client sends `done`, then packs. Correct and simple; the cost is
that incremental fetches receive a full pack (the client never learns which
commits are common, so it reports "no common commits" and takes everything).
Revisit with `multi_ack_detailed` if fetch traffic ever matters. No
`shallow` or `filter` either.

### Clone/fetch path (query, streaming)

1. Parse wants/haves; walk commits from wants, stopping at haves, collecting
   the closure of commits + trees + blobs + tags. Plain BFS over the object
   store; no bitmaps in v1.
2. Emit a packfile with **no deltas**: header, then each object as
   `type+size varint` + its stored zlib stream verbatim (the store's value
   format is `[pack type code][content len u32][zlib(content)]`, so no
   recompression and no inflation on the emit path), trailing SHA-1.
3. Serve via the HTTP gateway streaming strategy: the first response carries
   the first 1.5 MiB and a callback token holding `{wants, haves, sideband,
   chunk index}` (JSON in the token's `key`); the gateway keeps calling
   `http_request_streaming_callback` until done. Each callback
   deterministically regenerates the full body and slices its chunk: objects
   are immutable and the wants are pinned in the token, so the bytes are
   identical on every call - no cross-callback state, and a push landing
   mid-clone cannot corrupt the stream.

Cost: a full body rebuild per chunk (BFS closure + memcpy of stored zlib
streams; nothing is inflated except commit/tree metadata during the walk).
Comfortable within the 5 B-instruction query budget for packs up to tens of
MiB; if bigger repos matter later, cache pack prefixes and their running
SHA-1 keyed by the token.

### Push path (update)

1. `http_request` sees POST to `git-receive-pack`, returns `upgrade = true`;
   the gateway re-sends it as `http_request_update`.
2. Parse pkt-lines: `old-oid new-oid refname` commands, then the packfile.
3. Index the pack: inflate each entry; resolve `OFS_DELTA` against earlier
   entries in the same pack and `REF_DELTA` against the object store (this
   also handles **thin packs**, which git sends by default - bases may live
   only server-side). Verify SHA-1s. Store every resulting object loose.
4. Check fast-forward (walk new commit's ancestry for old oid; reject
   non-ff unless force and token allows), update refs atomically, reply with
   `report-status`.
5. If `refs/heads/main` changed -> enqueue `DeployJob { repo, commit }` and
   `ic_cdk_timers::set_timer(0, run_deploy_queue)` so the push response
   returns immediately.

**Push size (the honest limitation):** one push <= ~1.9 MiB of pack. Three
escalating answers:

1. **v1:** document it, and ship a `tools/ic-push.sh` that splits history into
   <=1.5 MiB increments by pushing intermediate commits
   (`git push origin <rev>:refs/heads/main` walking forward) - stock git only.
2. **v1.5:** chunked candid path using the dev kit's `large_objects` module -
   a wrapper script packs locally (`git pack-objects`), uploads the pack in
   chunks via `dfx canister call` (parallel chunks supported), then calls a
   `receive_pack_from_buffer` update that runs the same indexer as the HTTP
   path. No 2 MiB limit, no custom protocol code, works before the remote
   helper exists. (`large_objects` buffers live on the wasm heap, so
   finalize before any canister upgrade.)
3. **v2:** the `git-remote-ic` helper makes this transparent behind
   `git push`.

### Deploy path (timer-driven, inter-canister)

Runs from the timer, not inside the push call - pushes stay fast and the 40 B
instruction budget per deploy step is fresh.

1. Load `.ic-deploy.json` from the pushed commit's tree; resolve `source_dir`.
2. Walk that subtree; diff against the asset canister's current `list()` by
   sha256 - only changed files upload.
3. `create_batch` -> `create_chunk` (<= ~1.9 MiB per chunk, inter-canister
   same-subnet allows up to 10 MiB but stay conservative cross-subnet) ->
   `commit_batch` with content-type from extension, gzip encoding for text
   types. Atomic flip on commit - no partially-deployed site.
4. A job that exhausts its instruction budget re-arms the timer and resumes
   from a stored cursor (batch id + remaining paths). Failures leave the queue
   entry with an error for `deploy_status` query to report.

Wasm mode replaces steps 2-3: read the configured wasm blob from the tree
and call `install_code` (chunked install when the module exceeds
inter-canister payload limits) with `mode = upgrade` on the target;
`deploy_status` reports the installed module hash so reproducible builders
can verify what is running. Building stays off-chain (rustc cannot run in a
canister); reproducible builds + the reported hash make the off-chain step
verifiable. Self-upgrading the git canister itself needs a small controller
canister between pusher and target - out of scope for m4.

Setup requirement: the asset canister must `grant_permission(Commit)` to the
git canister's principal; wasm-mode targets must have the git canister as a
controller.

### Trust model (why raw-domain is not the weak point)

Who can tamper with what a cloner receives?

- **The subnet/canister:** standard IC consensus trust; nothing git-specific.
- **The boundary-node HTTP gateway:** with a *stock git client*, this is the
  trust boundary - and certification cannot move it. Certificate verification
  for non-raw domains happens *inside the gateway itself*, so serving
  certified responses on `icp0.io` vs uncertified on `raw.icp0.io` changes
  nothing about what a stock client can prove: the client trusts whatever
  bytes the gateway hands it either way. Raw is therefore not a security
  downgrade for git traffic; it's an honest label on an existing trust
  relationship. (Verified locally: dfx's gateway returns 503 for uncertified
  responses on `<id>.localhost` and serves them fine on `<id>.raw.localhost`
  - raw is required until item 2 below lands.)
- **What a malicious gateway can actually do:** it cannot fabricate objects
  matching a commit hash the client already trusts (that's a SHA-1 preimage),
  but it *can* serve stale refs, hide branches, or advertise a fabricated
  alternate history for refs the client has never pinned. The ref
  advertisement is the security-critical surface.

Mitigations, in deployment order:

1. **v1 - signed commits/tags.** Git-native, end-to-end,
   transport-independent, works today. Recommended in the README regardless
   of everything below.
2. **v1.5 - certify the `info/refs` advertisement.** Refs only change at push
   time, so recomputing `set_certified_data` over the advertisement is cheap
   and fits the update call that's already running. A *verifying* client
   (local IC HTTP gateway, or anything built on the `ic-http-gateway`
   library) then gets tamper-proof refs - and given trusted refs, the pack
   stream is self-verifying via SHA-1. Stock clients are unaffected either
   way. The packfile response itself stays uncertified (it's
   negotiation-dependent and self-verifying, so certifying it buys nothing).
3. **v2 - `git-remote-ic`** issues certified query calls and identity-signed
   updates directly: full end-to-end verification with no local gateway,
   plus private repos and unlimited push size.

### Auth

- Reads: public, no auth.
- Push: HTTP Basic - username ignored, password is a bearer token; canister
  stores `sha256(token)`. Minted by the repo owner via a candid
  `create_token` update call (caller principal = owner). Raw-domain HTTPS
  terminates at the boundary node, so the token transits boundary-node
  infrastructure in cleartext at that hop; acceptable for
  public-repo push auth in v1, replaced by identity-signed calls in the v2
  remote helper.

## Implementation notes

- **Crates**: `ic-dev-kit-rs` (git tag, currently v0.3.0), pinned to its
  versions: `ic-cdk 0.20`,
  `candid 0.10`, `ic-stable-structures 0.7`. Plus `ic-cdk-timers` (deploy
  queue), `flate2` (rust-backend/miniz_oxide - pure Rust, wasm-clean),
  `sha1`, `sha2`, `hex`.
  Try `gix-object`/`gix-hash` from gitoxide for object parsing (pure Rust,
  likely compiles to `wasm32-unknown-unknown`); hand-roll the pack
  reader/writer regardless - it's ~500 lines and the streaming/token design
  is IC-specific anyway.
- **pkt-line** is trivial: 4 hex length bytes + payload; `0000` flush.
- Keep hot parsing state in heap; only committed objects/refs touch stable
  structures. Canister upgrades then can't strand a half-parsed pack.
- SHA-1 only in v1 (matches git default); SHA-256 repos out of scope.

## Milestones

1. **Skeleton + store** (done) - canister with candid admin API: put/get
   object, set ref, list refs.
2. **Clone** (done) - pkt-line codec, ref advertisement, upload-pack with
   streaming pack writer. Seed objects via `tools/seed-repo.sh`; `git clone`,
   `git fetch`, and multi-chunk streamed packs verified against a local
   replica.
3. **Push** (done) - receive-pack: pack indexer with delta resolution
   (OFS/REF deltas incl. thin packs), connectivity check, ff-check via
   `object::commit_refs` ancestry, report-status, push tokens with 401
   Basic-auth challenge. Verified: push, re-clone (`git fsck` clean),
   incremental thin-pack push, bad-token 401, non-fast-forward rejection.
4. **Deploy hook** - timer queue, tree walk (`object::tree_entries` already
   preserves names+modes), `.ic-deploy.json` with two modes: asset-canister
   batch upload (sites) and `install_code` (canister upgrades from wasm
   blobs in the tree). Push to main -> site or canister updates.
5. **Self-host** - push this repo's source to its own canister and make that
   the canonical remote. The canister deploys static assets on merge; it
   cannot build Rust on-chain, so upgrading the git canister itself stays an
   off-chain step (clone from the canister, cargo build, dfx deploy - a
   small CI script). The source pack is well under the 2 MiB ingress cap,
   so stock `git push` suffices.
6. **Visibility** - repo ownership + private/public (design below).
7. **Billing** - per-repo cycles balances (design below).
8. **(v2)** `git-remote-ic` helper: chunked, identity-signed push; certified
   read responses; vetKD-encrypted private repos.

## Visibility and billing (design sketch)

**Ownership.** `create_repo` records `msg_caller()` as owner. Owners manage
visibility, reader/writer token grants, and the repo's cycles balance.

**Private repos.** A `visibility` flag per repo. Enforcement on every read
surface:

- Candid queries (`get_object`, `list_refs`, ...): check `msg_caller()`
  against the owner/reader list - identity is free on candid calls.
- Smart HTTP (`info/refs`, `upload-pack`): HTTP-gateway requests are
  anonymous, so private repos require a read-scoped bearer token in the
  Authorization header (hashed server-side, like push tokens).
- Streaming callbacks: `http_request_streaming_callback` is a public query
  and its token names arbitrary wants - unguarded, a forged token would
  stream any private closure. Fix: bind an HMAC over the token state with a
  canister secret (32 bytes from `raw_rand` at init, kept in the meta map);
  the callback recomputes and rejects mismatches.

Honesty note: this is access control, not confidentiality. Replica node
operators can read canister memory; the boundary node sees tokens in
cleartext at TLS termination. True at-rest privacy is vetKD envelope
encryption in v2 - v1 private repos keep honest people and the public out,
nothing stronger.

**Billing.** The canister pays the subnet for storage/compute from one
cycles pool; per-repo accounting is bookkeeping on top of it:

- `deposit(repo)` update call accepting attached cycles
  (`msg_cycles_accept`) into the repo's balance.
- Exact-usage metering (the IC already meters precisely; we attribute):
  storage rent charged periodically by a timer - per-repo stored bytes x
  the subnet storage rate x elapsed time - and execution charged per
  update call (push, deploy) from the call's actual instruction count
  (`performance_counter`) x the subnet's per-instruction cycle price, plus
  ingress costs. No markup beyond a small buffer for the canister's own
  overhead; the goal is self-sustaining, not profitable.
- Balance exhausted: writes and deploys freeze, reads stay up (queries cost
  the canister approximately nothing). A grace window before freezing
  avoids flapping on tiny balances.
- v2: an ICP/ICRC-1 ledger front-end that converts to cycles via the CMC,
  so users pay in tokens instead of raw cycles.

## Open questions

- ~~Store object bodies as pack-entry-compatible zlib streams to make the pack
  writer zero-copy?~~ Resolved: object values are `[pack type code] +
  zlib(content)`, so the pack writer serves stored streams verbatim.
- ~~Negotiation completeness~~ Resolved for now: no `multi_ack`, always NAK
  until `done`, full pack. Refine only if incremental-fetch traffic matters.
- ~~Per-chunk streaming determinism~~ Resolved: recompute per callback from
  the token; determinism follows from object immutability.
