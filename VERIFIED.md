# Verified deploys of the ic-git canister

Human-readable companion to `verified.json` (the machine-readable record that
`tools/check-module-hash.sh` and the scheduled watch read). How to reproduce
any row yourself: REPRODUCIBLE_BUILD.md. What a row does and does not prove:
the "Residual assumptions" and "Trusting trust" sections of the same file.

Canister: `umobs-yiaaa-aaaab-agyrq-cai`

| Date | Commit | Tag | Module hash (sha256 of the wasm) | On-chain match | Independent rebuilds |
|---|---|---|---|---|---|
| 2026-09-01 | `80bcb4a` | `v0.1.0` | `662990224e41ce296030ce04cb085055b15f2e1abe95b58892f1a93dd65aaec6` | MATCH, 2026-09-01 | deployer (pinned container, macOS arm64 host under Rosetta) |
| 2026-09-01 | `0707147` | `v0.1.1` | `a7156c6dc5eaa03adf9fd1a691550ac702b8adf2bcf8bb7f4d27e2651c601557` | MATCH, 2026-09-01 | deployer (pinned container, two fresh VMs agreed); GitHub Actions amd64 runner, [run 33563166779](https://github.com/DrJesseGlass/ic-git/actions/runs/33563166779), MATCH |
| 2026-09-01 | `2dd941d` | `v0.1.2` | `268c18bbfeb0cda616a55fcd500e62fcfc267c77aa8f297ad046d69108718d8f` | MATCH, 2026-09-01 | deployer (pinned container) |
| 2026-09-02 | `9cdc58c` | `v0.2.0` | `278ebec09bc4d353da718a2751ce01dd74bb44804d1f99abf72b0e08d4b3541a` (gz) | MATCH, 2026-09-02 | deployer (pinned container); GitHub Actions amd64 runner, [run 33653643555](https://github.com/DrJesseGlass/ic-git/actions/runs/33653643555), MATCH |
| 2026-09-22 | `bcd6f9b` | `v0.2.1` | `29e5ba3aa7e2dc0c62519c5a9e7e609bf72493971947e565e68daf3d43d29c1a` (gz) | MATCH, 2026-09-22 | deployer (pinned container, macOS arm64 host under emulation); GitHub Actions amd64 runner, [run 35805482289](https://github.com/DrJesseGlass/ic-git/actions/runs/35805482289), identical hash |
| 2026-09-24 to 26 | `5b2b55f` | `v0.2.2` | `f13ff2226676f02cffe3906f641a63e6df0806ef25c093ae159444aeb278cca1` (gz) | MATCH, 2026-09-26 (recorded late) | GitHub Actions amd64 runner, [run 36039724742](https://github.com/DrJesseGlass/ic-git/actions/runs/36039724742), identical hash; deployer (pinned container, macOS arm64 host under emulation), MATCH |
| 2026-09-26 | `07fd244` | `v0.3.0` | `3afcac754d55c6747abda09568412517602710eb91e68a2ac3c7937e4f76db03` (gz) | MATCH, 2026-09-26 | deployer (pinned container, macOS arm64 host under emulation); GitHub Actions amd64 runner, [run 36220841774](https://github.com/DrJesseGlass/ic-git/actions/runs/36220841774), identical hash |
| 2026-09-28 | `0d1d466` | `v0.3.1` | `5f283447bc72c028dd7e2feb51f9edd91e4b1861e1979cb161e8e4f6a1d7ad32` (gz) | MATCH, 2026-09-28 | deployer (pinned container, macOS arm64 host under emulation); GitHub Actions amd64 runner, [run 36506401506](https://github.com/DrJesseGlass/ic-git/actions/runs/36506401506), identical hash |
| 2026-10-03 | `dcb4aa7` | `v0.3.2` | `1efa766581c2ed9d83025f5008b7cd32c3fb86887c5f0b3c4ca74139eac90f92` (gz) | MATCH, 2026-10-03 | deployer (pinned container, macOS arm64 host under emulation); GitHub Actions amd64 runner, [run 37075637669](https://github.com/DrJesseGlass/ic-git/actions/runs/37075637669), identical hash |
| 2026-10-06 | `e48ebdb` | `v0.3.3` | `2bfd212775e572b82ff35997309f2753a273cff114035bc015d14d0841ddcec3` (gz) | MATCH, 2026-10-06 | deployer (pinned container, macOS arm64 host under emulation, built twice); GitHub Actions amd64 runner, [run 37478919057](https://github.com/DrJesseGlass/ic-git/actions/runs/37478919057), identical hash |
| 2026-10-07 | `db8f2bd` | `v0.3.4` | `e25610892fe279e4355d47c16cc1e03cd27732dad8187565e2eb1c36de5b9bad` (gz) | MATCH, 2026-10-07 | deployer (pinned container, macOS arm64 host under emulation); GitHub Actions amd64 runner, [run 37653678100](https://github.com/DrJesseGlass/ic-git/actions/runs/37653678100), identical hash |
| 2026-10-08 | `a23ee31` | `v0.3.5` | `30e76748ddb1487e41ca2718c30aa469c2ffa35f21f4c1936e67509771066d6a` (gz) | MATCH, 2026-10-08 | deployer (pinned container, macOS arm64 host under emulation); GitHub Actions amd64 runner, [run 37803652956](https://github.com/DrJesseGlass/ic-git/actions/runs/37803652956), identical hash |
| 2026-10-10 | `018bf4d` | `v0.3.6` | `eb61f0e10be0b93c1f4162cf040c6dcc69ed1248ac940fc35b89c008ec9762a2` (gz) | MATCH, 2026-10-10 | deployer (pinned container, macOS arm64 host under emulation, at the branch head, same ic-git crate); GitHub Actions amd64 runner, [run 38019976528](https://github.com/DrJesseGlass/ic-git/actions/runs/38019976528), identical hash |

## v0.3.6 -- 2026-10-10

`registry_publish_canister` (#77), and the shorter `deploy_now` consent
message (#73). The new endpoint publishes `ic-git#canister` -- the commit
ic-git was built from and the sha256 of its installed module -- and only
a controller can call it. It is the governor's (`canisters/governor`,
docs/GOVERNOR.md): after each upgrade it installs, the governor asks the
new code to record itself on chain, as `<repo>#app` records a governed
backend. The governor was released in the same tag, built by the same
recipe (its own hash on the CI run below), and is not yet deployed; this
release was installed by the operator, still the canister's controller.

Gated before the deploy by `tools/e2e-local.sh`: 155 checks on `589cba0`,
the branch head, whose ic-git crate is the tag's (review changed only the
governor, its tools and docs), including the governor's whole life
against a second ic-git. After the upgrade all five published site
records still verified with `tools/verify.mjs`, and the core's certified
reader certified the new module hash and the controller.

Same recipe and base image digest as v0.3.5. The raw wasm inside the
gzip hashes to `14459d2b...8907`. The deployer's build was made at
`589cba0` before the merge; CI built the tag on a GitHub Actions x86_64
runner and agreed byte for byte.

## v0.3.5 -- 2026-10-08

Registry writes carry a 1M gas limit (#72). ic-vote's poll canister
(`gjob4-qqaaa-aaaab-ag4mq-cai`) became the first governed app canister on
2026-10-08, and the first governed deploy's `ic-vote#app` record failed
on chain: the transaction (Sepolia nonce 20, `0xd68214fa...16a2`) used
its whole 150k gas limit and reverted. `eth_estimateGas` against the live
contract explained it -- the same `set` costs 57k when the key exists
(the `ic-git#site` republish of v0.3.4) and 354k when it does not, since
Sepolia now prices a fresh storage slot far above the classic 22.1k. Every
first record for a repo would have failed the same way while republishes
passed. The limit is now a named constant with the measurements beside
it; unused gas is refunded, so the limit only sets what the canister's
EOA must hold at the time of the send. The deploy status reads `app
record tx 0x...`, since it reports the broadcast, not inclusion. Nothing
else changed.

Gated before the deploy by `tools/e2e-local.sh`: 120 checks on the branch
commit `a5b5a92`. The merge commit `a23ee31` differs from it only in
comments and a documentation paragraph, which still moves the module hash
(panic-location strings carry line numbers), so the tag was rebuilt and
is what the row records. After the upgrade all five published site records
still verified with `tools/verify.mjs`, and the core's certified reader
certified the new module hash and the controller from the IC's state
certificate. The console was not moved: `/site/ic-git/` still serves and
verifies at `db8f2bd`, whose page is unchanged by this release.

Same recipe and base image digest as v0.3.4. The raw wasm inside the
gzip hashes to `0002b3ab...ad01`. Two hosts agreed byte for byte: the
deployer's arm64 machine running the amd64 image under emulation, and a
GitHub Actions x86_64 runner.

## v0.3.4 -- 2026-10-07

Governed app canisters (#69; docs/GOVERNANCE.md section 2, docs/TENANCY.md
"Governed app canisters"). A repo's owner can hand its app canister to
ic-git alone with `govern_app_canister`: the owner is removed as a
controller, so the backend's code changes only by a commit the voters
approve. One-way, owner only, and only with votes required. The policy
locks with it: the owner's direct changes to the required votes, the
voters, the ownership and the deploy config are refused, required votes
can never return to 0, and `propose_policy_change` is the one path left,
a ballot on the change itself under the same K-of-N and objection rule as
a commit, applied the moment it is reached. Every install into a governed
canister is recorded on chain as `<repo>#app` (the commit and the module's
sha256, which is the hash the IC certifies for the canister), the way
`<repo>#site` records a served page. `/api/<repo>/info` reports
`governed`; `/api/<repo>/proposals` lists pending changes with their
ballots. The console shows a GOVERNED badge, a governance panel, and the
governing step behind a typed confirmation. No repo is governed yet;
ic-vote's poll canister is the first intended one.

Gated before the deploy by `tools/e2e-local.sh`: 120 checks on this
commit, including a governed-backend section (the controller change on
the replica, every lock, policy changes applied under K = 1 and held
under K = 2 by a second approval or an objection, an install into the
governed canister after two approvals with the IC's module hash equal to
the status's) and an upgrade from v0.3.3 -- what mainnet ran -- over
state that release wrote. After the upgrade all five published site
records still verified with `tools/verify.mjs`, and the core's own
certified reader (`readCanisterState`, docs/CERTIFIED.md) certified the
new module hash and the controller from the IC's state certificate. The
console (`/site/ic-git/`) was then moved to this commit -- `main` pushed
into the canister's `ic-git` repo and `ic-git#site` republished (Sepolia
nonce 19, tx `0xc4a8d96a...bf48`) -- and verifies at `db8f2bd`.

Same recipe and base image digest as v0.3.3. The raw wasm inside the
gzip hashes to `cae6fc73...48f5`. Two hosts agreed byte for byte: the
deployer's arm64 machine running the amd64 image under emulation, and a
native x86_64 GitHub runner triggered by the tag push.

## v0.3.3 -- 2026-10-06

Objection ballots (#64, #65). A voter can now approve, reject, or
object with a reason. An objection counts -1: a commit passes when
approvals minus objections reach `required_votes`, so it is not a veto
but costs one more approval to overcome, and its reason is in front of
the other voters -- in `get_votes`, in `/api/<repo>/votes/<commit>`
with the running count, and in the wallet's consent message for the
objection itself. `cast_ballot(repo, commit, Approve|Reject|Object,
opt reason)` is the new call; `vote(repo, commit, bool)` stays and maps
onto it. An objection on a served commit rolls the site and the app
back to the approved commit before it, the way a withdrawn approval
does. The rule is `ic-multisig` 0.2.0's, from crates.io, shared with
ic-vote; ballots recorded by earlier releases read unchanged.
docs/TENANCY.md, "Votes".

Gated before the deploy by `tools/e2e-local.sh`: 87 checks on this
commit, including the new objections section (an objection holds a
deploy until one more approval outweighs it; the reason reaches the
API and the consent message; an objection after a deploy rolls back)
and an upgrade from v0.3.2 -- what mainnet ran -- over state that
release wrote. After the upgrade all five published site records
(ic-git, ic-vote, ic-git-loader, ic-git-extension,
ic-git-extension-firefox) still verified with `tools/verify.mjs`.

Same recipe and base image digest as v0.3.2. The raw wasm inside the
gzip hashes to `2bbe2009...a172`. Three builds agreed byte for byte:
the deployer's arm64 machine running the amd64 image under emulation,
once on the branch before the merge and once on the tag, and a native
x86_64 GitHub runner triggered by the tag push.

## v0.3.2 -- 2026-10-03

One canister change, #60: check E, the scan run when a site record is
published, now refuses what the browser extensions' pinned policy
refuses at run time -- inline event handlers, `style=` attributes,
`javascript:` URLs, external stylesheets, `@import` in an inline style,
and a script or style inside SVG or MathML -- so a page that publishes
is a page the extensions run. Every published site passes it.

Gated before the deploy by `tools/e2e-local.sh`: 69 checks on this
commit, including an upgrade from v0.3.1 -- what mainnet ran -- over
state that release wrote. After the upgrade all five published site
records (ic-git, ic-vote, ic-git-loader, ic-git-extension,
ic-git-extension-firefox) still verified with `tools/verify.mjs`.

Same recipe and base image digest as v0.3.1. The raw wasm inside the
gzip hashes to `66df85cc...6e77`. Two hosts agreed byte for byte: the
deployer's arm64 machine running the amd64 image under emulation, and a
native x86_64 GitHub runner triggered by the tag push.

## v0.3.1 -- 2026-09-28

Fixes and hardening on v0.3.0; no state migrations. Canister changes, #37
to #42: EVM sends sign with the next nonce kept in stable memory rather
than the providers' pending count, which replicas disagreed on, and a
publish that fails before its broadcast refunds its charge (#37); every
operator-only endpoint, including the EVM and Solana ones that checked
the allowlist alone, uses the one operator guard (#38), and billing
exemption follows the same rule (#39); and the subresource scanner skips
what the browser never parses as markup -- comments to their tokenizer
end, script and other raw-text bodies to their end tag, only in plain
HTML -- so an honest page is no longer refused over strings in its own
code, with the bypasses a review found closed (#42). The last is what
lets the loader (docs/LOADER.md) be published as a site record.

Gated before the deploy by `tools/e2e-local.sh`: 69 checks on this
commit, including an upgrade from v0.3.0 -- what mainnet ran -- over
state that release wrote through its own API: a signing-required repo, a
key-bound token, a vote-gated site behind its tip. After the upgrade both
published site records still verified with `tools/verify.mjs`.

Same recipe and base image digest as v0.3.0. The raw wasm inside the
gzip hashes to `5ab7c2f6...41e6`. Two hosts agreed byte for byte: the
deployer's arm64 machine running the amd64 image under emulation, and a
native x86_64 GitHub runner triggered by the tag push.

## v0.3.0 -- 2026-09-26

The release that makes approvals, pushes and funding what the tenancy
design promised. Canister changes since v0.2.2, #26 to #35: a site and
the app both follow the repo's newest approved commit (#26); push tokens
expire, can be listed and revoked by id, and stop working when their
minter loses write access (#27, #29); the optional ic-name-service
announce, and lower-kebab repo labels unique per repo (#28, #32); tokens
bound to an SSH key, with pushes signed by it over HTTPS (#30); deposits
from ICP through the cycles minting canister (#33); ic-dev-kit-rs 0.4
(#34); and one operator rule plus the operator purge of dead token
records (#35).

Gated before the deploy by `tools/e2e-local.sh`: 57 checks on this commit
on a local replica with the NNS ledger and CMC, including an upgrade from
v0.2.2 -- what mainnet ran -- over state that release wrote. After the
upgrade the migrations were visible on mainnet: the existing push tokens
listed without a minter and expiring 30 days out, and every repo's info
reporting `require_signed_push`.

Same recipe and base image digest as v0.2.2. The raw wasm inside the gzip
hashes to `75d3de45...faaf`. Two hosts agreed byte for byte: the
deployer's arm64 machine running the amd64 image under emulation, and a
native x86_64 GitHub runner triggered by the tag push.

## v0.2.2 -- deployed 2026-09-24 to 26, recorded 2026-09-26

Recorded late. v0.2.2 was tagged on 2026-09-24 and deployed without a
record here, so on 2026-09-26 `tools/check-module-hash.sh` reported the
live module as one nobody had recorded -- the drift watch doing its job.
A rebuild of the tag in the pinned container, from a worktree at `v0.2.2`,
matched the IC's certified module hash byte for byte, so the running code
is this source; the exact deploy date was not logged and is bounded by
the tag and the check.

Three merges changed the canister crate since v0.2.1: the console's deploy
configuration (#20), ICRC-21 consent messages and the ICRC-10 standards
list so wallets will sign console calls (#22), and clippy cleanups (#23).
Same recipe and base image digest as v0.2.1. The raw wasm inside the gzip
hashes to `cb6eba84...90be`. Two hosts agreed: a native x86_64 GitHub
runner triggered by the tag push on 2026-09-24, and the deployer's arm64
machine running the amd64 image under emulation on 2026-09-26.

## v0.2.1 -- 2026-09-22

Three merges changed the canister crate since v0.2.0, and all three are in
the hash. Votes now go through the ic-multisig crate rather than a local
rule set (#16: tenancy.rs, store.rs, lib.rs and the new dependency). The
crate is taken from crates.io instead of a git tag (#18): the dependency is
`ic-multisig = "0.1"`, resolved to 0.1.1, with Cargo.lock pinning the
registry checksum. The deploy-on-push demo (#17) added the
`GET /api/<repo>/deploys` route in api.rs and a `target` field on persisted
deploy records in deploy.rs; the demo's own files under `demo/` are outside
the crate. The voting behaviour is the same, counted on the crate's checked
path since every ballot the canister stores was authenticated by the IC on
the way in. Same recipe and base image digest as v0.2.0. The raw wasm inside the gzip hashes to
`703563cd...1cfc`. Two hosts agreed byte-for-byte: the deployer's arm64
machine running the amd64 image under emulation, and a native x86_64
GitHub runner triggered by the tag push.

## v0.2.0 -- 2026-09-02

Multi-tenancy (docs/TENANCY.md): accounts, ownership and roles, votes that
gate the deploy queue, storage rent and push fees, per-user app canisters,
and the wallet console. First release where the canister custodies tenant
balances, and the first installed as a gzipped module: the on-chain hash is
of `git_canister.wasm.gz`; the raw wasm inside hashes to `f49a6d04...360c`,
identical to the build of the merge commit `37e2c3e` before the gzip step
was added, so the recipe change touched nothing in the module.

## v0.1.2 -- 2026-09-01

Adds the read-only JSON API (`/api/...`) and the self-hosted repo browser
(`browser/index.html`). Same recipe and base-image digest as before. The
pre-merge commit `cc3aa28` and the merge commit `2dd941d` produced the same
hash: the review follow-up between them changed only the page, doc comments
and tests, none of which reach the wasm.

## v0.1.1 -- 2026-09-01

Adds admin-allowlist management (`authorize`, `deauthorize`,
`list_authorized`) so a controller cutover can hand over the admin API, not
only the upgrade key. Same recipe and base-image digest as v0.1.0. The hash
was produced twice on two freshly created VMs (the first VM's disk was
corrupted by a full host disk after the compile had already printed the
hash; the rebuild on a new VM printed the same one). A GitHub Actions runner,
native x86_64 and sharing no machine with the deployer, then rebuilt the tag
and reported MATCH against the live module hash: K=2 in the pinned-container
lineage.

## v0.1.0 -- 2026-09-01

The first build of this canister that anyone other than the deployer can
reproduce. The module that ran before it (hash `736e2344...`) was built before
the path-remapping pins existed and embedded the deployer's own cargo registry
paths, so no second machine could ever have matched it; that is the gap this
row closes.

Recipe: `Dockerfile.build` at the tagged commit, `--platform=linux/amd64`,
rustc 1.94.1 (`rust-toolchain.toml`), dfx 0.31.0 in the container, base image
`rust:1.94.1-slim-bookworm` resolved to
`sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2`.

Two builds from two contexts agreed byte-for-byte before the deploy, and the
canister was then upgraded with that exact artifact; `--check` from the tagged
commit reported MATCH against the live module hash the same day. The builds: one from
a working checkout, one from a detached clean worktree of the tag running the
tag's own `tools/reproducible-build.sh --docker --check`. The artifact
contains zero host paths (`strings | grep /Users` is empty; every dependency
path reads `/cargo/registry/...`).

Lineage caveat, stated once so nobody reads the table as more than it is:
every rebuild listed above is the *pinned-container* lineage. It verifies the
source and the recipe. It does not verify the toolchain; a diverse-toolchain
rebuild (see "Trusting trust") is still an open row.
