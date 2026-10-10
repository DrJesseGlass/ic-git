# The governor

ic-git's canister (`umobs-yiaaa-aaaab-agyrq-cai`) cannot move to a new id:
its threshold signing keys, and so its EVM address and the registry it
owns, are bound to its principal (docs/CANISTER_SPLIT.md). So it is not
made to govern itself. A second, small canister -- the governor,
`canisters/governor` -- becomes its only controller, and changes its code
or its controllers only when the governor's approvers have voted for
exactly that change. The design is docs/GOVERNANCE.md, section 5; this is
how it works and how it is put in place.

## What it does

Three kinds of proposal (`governor.did`):

- **Upgrade**: install a module into ic-git in upgrade mode. The proposal
  names the module's sha256, the ic-git commit it is built from, and the
  install argument (ic-git's is empty). An approver then stages the
  module's bytes in chunks; approvals are taken only once the staged
  bytes hash to the named sha256, so nobody approves a module the governor
  does not hold (rejections and objections need no module). After installing, the governor asks the new code to publish
  `ic-git#canister` (commit, module sha256) to the registry, so the chain
  says what ic-git runs, as `<repo>#app` does for a governed backend.
- **Policy**: replace the approvers (1 to 16) and the threshold K (1 to N).
- **Handover**: make another principal ic-git's only controller -- a
  successor governor, or whoever the approvers choose, but never ic-git
  or the governor itself. After it the governor is inert.

Ballots follow docs/GOVERNANCE.md, section 1: approve, reject, or object
with a reason; a later ballot replaces an earlier one; a proposal passes
when approvals less objections reach K. The ballot that reaches K
executes the proposal in the same call. If execution fails (an install
rejected, say), the proposal stays open with the error and any approver
can retry it with `execute`. An execution that never finishes holds its
proposal for at most a day; after that it can be executed again or
withdrawn. After an upgrade the governor waits at most five minutes for
the new code to publish its record; no reply is logged, not fatal. A ballot is bound to the governor, ic-git,
the proposal's id and everything the change would do, so it cannot be
replayed onto another change. At most four proposals are open at once;
the proposer can withdraw one, and so can any approver once the
approvers have turned it down (more of them reject or object than N - K,
so the rest cannot reach K alone), so no one approver can hold the
slots. `info`, `proposals` and `log` (every executed or withdrawn
proposal with its ballots, 100 at a time from a position) are public
queries.

The governor has no controllers. Its code and rules can never change;
the way past them is a Handover, voted under them. It holds its own
cycles, which anyone can top up (`dfx cycles top-up <governor> <amount>`);
the installs themselves are paid by ic-git, whose chunk store holds the
module while it is installed.

There is no emergency path (docs/GOVERNANCE.md, open questions): at 1 of
1 every upgrade is immediate anyway, and the question returns when there
are more approvers.

### What it does not cover

The governor controls ic-git's code. Inside ic-git, the operator role
(`auth`, set at install) keeps its powers: EVM and Solana configuration,
the registry address, seeding, pricing. Those are calls the code allows,
not changes to it, and every one is visible in the code the governor
installed; putting them under a vote is later work.

## Checking a proposal (approvers)

Before approving an Upgrade:

1. `tools/governor.sh status` -- the proposal's `commit`, `module_sha256`,
   `ready = true` and an empty `arg`.
2. Rebuild that commit: `git checkout <commit> && tools/reproducible-build.sh --docker`.
   The `built module sha256` line must equal `module_sha256`.
3. Read what changed since the commit ic-git runs now
   (`verified.json`'s newest entry).

Then `tools/governor.sh vote <id> approve`, or `object "<reason>"`.

## Rehearsal

`tools/e2e-local.sh`, section "governor", runs the whole sequence on a
local replica against a second ic-git: the governor installed 1 of 1 and
made immutable (its own upgrade refused), the target handed to it alone
(its old controller refused), an upgrade proposed, staged in chunks and
executed by one approval, the IC's module hash and the target's state
checked after; the policy grown to 2 of 3 by vote; an upgrade held by an
objection (and not outweighed by a second approval) until the objector
approves instead; a withdrawal, and one by another approver after the
approvers turned it down; a handover to the governor itself refused;
and a handover to a successor, after
which the governor refuses everything and the successor can upgrade.

## Putting it in place (mainnet)

Each step is the operator's, from a terminal (the controller identity is
passphrase-encrypted). Steps 1 to 4 can all be undone; step 5 cannot.

1. **Release ic-git with `registry_publish_canister`** the usual way
   (tag, container build, install, record). The governor calls it after
   every upgrade.
2. **Create and install the governor** from the same tag's container
   build (`target/reproducible/governor-<commit>.wasm.gz`; its hash is the
   build's `governor sha256` line, and CI's):
   ```sh
   dfx canister --network https://icp-api.io --identity icgit-admin-encrypt create governor --no-wallet --with-cycles 2000000000000
   dfx canister --network https://icp-api.io --identity icgit-admin-encrypt install governor \
     --wasm target/reproducible/governor-<commit>.wasm.gz \
     --argument '(record { target = principal "umobs-yiaaa-aaaab-agyrq-cai"; approvers = vec { principal "3kq6u-eptpm-egjdi-5qvjv-twk23-m4ymt-qqrcs-tdkvy-ob7zx-x6qq3-wqe" }; threshold = 1 : nat32 })'
   ```
   The cycles come from the identity's cycles-ledger balance (`dfx cycles
   balance`). `create` adds the new id to `canister_ids.json`, where
   `tools/governor.sh` finds it; commit that. Check its certified module
   hash equals the build's.
3. **Make it immutable**: remove its only controller.
   ```sh
   dfx canister --network https://icp-api.io --identity icgit-admin-encrypt update-settings governor \
     --remove-controller 3kq6u-eptpm-egjdi-5qvjv-twk23-m4ymt-qqrcs-tdkvy-ob7zx-x6qq3-wqe --yes
   ```
   Its certified controllers are then empty.
4. **Trial, with the operator still a controller**: add the governor as a
   second controller of ic-git, then run one real upgrade through it --
   the module ic-git already runs -- with `tools/governor.sh
   propose-upgrade <module> <commit>` (the commit it was built from,
   in full) and `vote <id> approve`. This proves the whole path
   on mainnet (staging, the chunked install, `ic-git#canister` on chain)
   while the operator can still repair anything.
   ```sh
   dfx canister --network https://icp-api.io --identity icgit-admin-encrypt update-settings umobs-yiaaa-aaaab-agyrq-cai --add-controller <governor>
   ```
5. **Hand over** (irreversible): the governor alone.
   ```sh
   dfx canister --network https://icp-api.io --identity icgit-admin-encrypt update-settings umobs-yiaaa-aaaab-agyrq-cai --set-controller <governor> --yes
   ```
   ic-git's certified controllers are then exactly the governor. From
   here every change to ic-git's code is a governor proposal, and the
   only way to change the governor is a Handover it votes for.

Afterwards the extensions can judge ic-git itself: controllers == the
governor, the governor's controllers empty, and the module hash ==
`ic-git#canister` (docs/GOVERNANCE.md, section 4).
