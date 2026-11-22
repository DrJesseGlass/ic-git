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

### Its cycles

A canister pays for every signed message it takes in, by its bytes,
whether or not the call then does anything, and a governor has no
controllers to notice it running low. From 2026-11 the governor's code
has an ingress filter (`canister_inspect_message`, `State::takes`): a
change (`propose`, `stage`, `vote`, `execute`) is taken from an approver
alone, a `withdraw` also from the proposer of an open proposal, a read
sent as an update from anyone, and nothing else. A `withdraw` and a read
carry at most 64 bytes of argument, since someone other than an approver
may send them: a proposer the approvers have voted out keeps the
withdrawal of their own proposal while it is open, and nothing more. A
governor that has handed its target over takes no change at all, only
reads. It saves cycles and decides nothing: every method checks its
caller as before.

The two governors in place run the module from before it
(`a71ff65d...641f`) and cannot be upgraded: anyone can still send
either a message of 2 MiB and have it pay. The filter reaches a
governed canister only by a handover to a governor newly installed
from this code, which the clients would then have to pin in place of
the old one. Nor can anyone read what the two hold: `canister_status`
answers controllers alone and they have none. The code from 2026-11 has
a public `cycle_balance` for that, which reaches them the same way.
Anyone can add cycles to either (`dfx canister deposit-cycles`), seen
or not.

## Following it

The governor has no controllers, so it can never learn to serve a feed.
ic-git serves one for it: `GET /feed` on ic-git's raw domain
(`https://umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io/feed`) is an Atom
feed of every proposal opened, every ballot with its reason, each
threshold reached, each execution or withdrawal, and the
`ic-git#canister` record ic-git publishes after an upgrade. ic-git reads
the governor's public `proposals` and `log` queries every five minutes
and reports what changed since it last looked. A ballot replaced before
the next poll is never seen (the governor keeps each approver's latest),
so the feed shows the ballots that stood at each poll, not every ballot
ever cast. `feed_poll_governor`
(operator) polls now instead of at the next poll, and
`feed_set_governor` (operator) names the governor, which must be a
controller of ic-git -- the feed says who governs it, so it cannot be
pointed at a canister that does not. Approvers subscribe to it the way
they would to any feed; an objection shows up there with its reason.

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

Done 2026-10-11 to 14: the governor is `7kkwl-baaaa-aaaab-ag6rq-cai`,
ic-git's only controller, with two approvers at 1 of 2 (the operator's
key and an offline backup). VERIFIED.md, "The governor", has the record.
The steps, for a successor or a rehearsal:

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
   while the operator can still repair anything. `propose-upgrade` first
   reads the target's `cycle_balance` and refuses under
   `MIN_TARGET_CYCLES` (200 G by default): the install is paid by the
   target, and once the governor is its only controller nothing else
   can see it running low (umobs did, at the cut; a deposit by anyone
   fixes it, `dfx canister --network ic deposit-cycles <amount> <id>`).
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
6. **Point ic-git's feed at it**, so approvers hear about proposals and
   ballots ("Following it"):
   ```sh
   dfx canister --network https://icp-api.io --identity icgit-admin-encrypt call umobs-yiaaa-aaaab-agyrq-cai feed_set_governor '(opt principal "<governor>")'
   ```

Afterwards the extensions can judge ic-git itself: controllers == the
governor, the governor's controllers empty, and the module hash ==
`ic-git#canister` (docs/GOVERNANCE.md, section 4).

## The second governor

The git canister (docs/CANISTER_SPLIT.md, `34koz-jyaaa-aaaab-ahejq-cai`)
has a governor of its own: `3hps4-taaaa-aaaab-ahela-cai`, a second
instance of the same module (`a71ff65d...641f`, the artifact this one
runs, installed again rather than rebuilt), with the git canister as
its target and the same approvers and threshold, 1 of 2, from init. It
was put in place on 2026-11-16 by the split's step 15 the way this one
was: installed, its controller removed, one trial upgrade through it
with the operator still a controller (proposal 1, the module the git
canister already ran), then the handover. Certified since: the git
canister's controllers `[3hps4...]`, the governor's `[]`. After an
upgrade it asks the git canister for `ic-git#git`, which the git
canister asks the authority to publish; before the cut (step 16.4) the
authority did not take that message, so the trial's record publish
failed as expected, and proposal 2, a same-module install after the
cut, published the first `ic-git#git` record (2026-11-16, Sepolia tx
`0x8cd09003...de7c`). Proposal 3 (2026-11-17) was its first real
release, v0.3.12, proposal 4 the next, v0.3.13, proposal 5 v0.3.14,
proposal 6 v0.3.15 (both 2026-11-18) and proposal 7 v0.3.16
(2026-11-22). `tools/governor.sh`
names the governor it was run for in the next-step hints it prints: a
vote cast without `GOVERNOR=` goes to ic-git's governor, which has no
such proposal and says so.
The clients pin it beside this one (`DEFAULTS.gitGovernor`);
`verified.json` records it under `git_canister.governor`, and
`tools/check-module-hash.sh` checks it as it checks this one.
`tools/governor.sh` drives it with `GOVERNOR=git_governor`, the name
`canister_ids.json` holds it under. It has no feed yet: its `proposals`
and `log` are the public record.
