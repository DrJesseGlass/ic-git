# Tenancy -- accounts, ownership, membership, votes, and who pays

ic-git started single-tenant: one allowlisted operator created repos and
minted push tokens, and the canister paid for everything out of its own
cycles. This document describes the multi-tenant model that replaces it,
implemented in `crates/authority/src/tenancy.rs`, `ledger.rs`, and `apps.rs`.

## The one rule

A tenant pays, in cycles, for what their repo costs the shared canister, and
an action that would overdraw is refused before it runs. Balances are
prepaid and held by this canister, so a deposit literally becomes canister
cycles: ic-git cannot be drained by its tenants, because the only cycles it
spends on a repo are cycles that repo's owner already paid in.

## Identity

Everything is keyed by principal. The same principal works from a wallet in
the browser (the console in `browser/index.html`, signing through the IC
signer standards, which OISY implements) and from `dfx` on the command line.
Git itself stays on HTTPS with per-repo push tokens; a canister cannot speak
SSH, and a relay that could would hold exactly the standing credential this
design refuses to have. What SSH gives -- a push authorized by a key that
never leaves your machine -- comes instead from signed pushes (below):
stock git signs a push certificate with your SSH key, over HTTPS.

### Push tokens

A push token is the password git presents; `create_push_token(repo, days)`
mints one for a writer of the repo, returns it once, and stores only its
sha256. Every token expires: `days` defaults to 30 and is capped at 365, so
a token that leaks stops working on its own even if nobody notices the
leak. Tokens minted before expiry existed were given 30 days from the
upgrade that introduced it (September 2026) and have since run out.
`list_push_tokens(repo)` shows the live ones
by id -- the first 16 hex characters of the hash, which names a token
without being usable as one, so the list is public -- with who minted
each and when it expires, and `revoke_push_token_id(id)` revokes one
without holding it (`revoke_push_token(token)` still works for a holder).
A repo holds at most 20 live tokens at once; mint past that and the
call asks you to revoke one first. Expired tokens are swept out, up to 64
at a time, whenever a token is minted, so the shared token map stays
bounded by the number of repos and no single call does unbounded work. The console shows
the list, with a revoke button on each, under the mint form, and after a
mint says when the new token expires.

A token lasts only as long as its minter may write. Removing a writer,
re-adding one as a voter, or transferring the repo revokes the tokens
minted by whoever lost write access (a previous owner keeps theirs only
if they are an operator). A token that records no minter is left to
expire instead.

A dead token record can never authorize again, and no listing shows it
or revoke can remove it: one that does not decode (only a bug leaves one),
or an old-format bare repo name, which only a rolled-back wasm could write
now. Operators list them with `dead_push_tokens` and remove one by id
with `purge_dead_push_token`, which refuses any live record.

### Signed pushes

A token can be bound to an SSH public key at mint:
`create_push_token(repo, days, opt "ssh-ed25519 AAAA...")`, or the key
field in the console's mint form. A push with a bound token must carry a
git push certificate signed by that key, so the token alone -- in a leaked
URL, a CI log, a shell history -- pushes nothing. git does the signing:

```
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config push.gpgSign if-asked
```

The receive-pack advertisement offers `push-cert=<nonce>`, and git then
sends a certificate listing each `<old> <new> <ref>` update with the nonce,
signed with the key (OpenSSH's SSHSIG format, namespace `git`). The canister
checks, before the push is charged or its pack read, that the nonce is one
it issued for this repo within the last 10 minutes (an HMAC under a secret
seed, as git's own `receive.certNonceSeed`), and that the signature is by
exactly the bound key; the updates it then runs are the ones in the
certificate. A refusal reaches git as `! [remote rejected] <ref> (<reason>)`,
the reason saying what to fix. Only `ssh-ed25519` keys are accepted. `list_push_tokens` shows
each token's bound key, and the console its fingerprint.

`set_require_signed_push(repo, true)` (owner; the console's "require
signed pushes") makes the repo refuse pushes with any token that is not
bound to a key. It is off by default.

## Roles

| Role | Granted by | May |
|---|---|---|
| Owner | creating the repo, or accepting a transfer | everything below, plus manage members, config, deploys, and votes threshold; pays |
| Writer | owner, `add_member(repo, p, "writer")` | push, mint and revoke tokens |
| Voter | owner, `add_member(repo, p, "voter")` | cast ballots on commits |
| Operator | controller or the legacy admin allowlist (never ic-git itself) | act on any repo; charged nothing |

What a repo keeps besides its objects is bounded, since none of it is
paid for and all of it is read whenever the repo is touched, by the
hourly rent tick for one: at most 32 members besides the owner (one
already on the list can always change role); a deploy's `source_path`
and a site's root of at most 512 bytes, in the configs and in a pending
policy change that names one; at most 8 pending policy changes for each
approver, so 264 at the very most; at most eight domains. Until 2026-11
the members and the paths had no limit, and with them neither had the
pending changes.

Repos created before tenancy existed have no owner and are treated as
operator repos: exempt from every charge, writable only by operators.

A repo is exempt while its owner is an operator, read live on every
charge: an owner removed as controller or from the allowlist pays from the
next charge on. Rent is not back-billed: the rent clock of an exempt repo
keeps moving, so rent starts when the exemption ends. Pushes to an exempt
repo are free but still count toward its stored bytes, so that rent covers
everything the repo holds. Bytes pushed before v0.3.1 to an operator-owned
repo were not counted.

## Money

`get_pricing` returns the table; operators retune it with `set_pricing`.
Defaults are round numbers above the IC's own rates so the canister runs at a
margin:

| Charge | Default | When |
|---|---|---|
| create_repo | 1B cycles | on creation; also what "positive balance" means |
| push | 100M + 5K per byte the push stores (below) | after the pack is read and before it is stored (refused as `[remote rejected]`, with the reason) |
| site domains | 100M (the push base) | each `set_site_domains` by the owner that the git side takes; refunded when it refuses |
| storage rent | 5K per byte-year of what the repo's pushes stored | hourly timer, pro rata |
| EVM action | 50B | each deploy or registry publish (a t-ECDSA signature plus RPC outcalls) |
| gas markup | 1% (100 bps) | on what each EVM transaction's gas cost, from the gas balance rather than cycles (below); at most 100%; optional in `set_pricing`, null keeps the default |
| IC deploy | 5B | each install from the deploy queue |
| git canister floor | 1T | not a charge: under it, the rent timer tops the git canister up (below); optional in `set_pricing`, null keeps the default |

The table also holds the float's sizes, which are not charges either:
`float_target_txs` (1000), `float_floor_txs` (500) and
`float_margin_txs` (10), how much ETH ic-git keeps in its EOA, counted
in transactions at the measured cost of one (docs/EVM_GAS.md, section
5). Each is optional in `set_pricing`, null keeping the default; a floor
over the target, or a target of 0, is refused.

A push is charged for the bytes it stores, and never less than the bytes
of the request. The pack is read first: every object is inflated and
every delta resolved, nothing stored, and what its new objects come to
as the store keeps them (zlib of each whole object; the store keeps no
deltas) is what the push pays for and what the repo's rent counts.
Objects the store already has add nothing. For a pack of whole objects
that is the pack's own size, as before. A pack of deltas stores more
than it sends -- a one-line change to a large file arrives as a few
bytes and is stored as the file again -- and pays for that; until
2026-11 it paid for the few bytes, and a delta copying a base many
times over stored megabytes for the price of a hundred bytes. A pack
that cannot be read is refused and charged for its own bytes, as
before. Two limits bound the reading: no object over 64 MiB inflated,
and no pack whose objects, with the bases its deltas are applied to,
come to more than 256 MiB inflated; nothing is inflated or built past
the size its entry declares.

A branch moves forward only: a push that is not a fast-forward of the
ref it names is refused (`non-fast-forward`; `--force` does not change
that). The rule holds a ref while it exists, so a branch is rewritten by
deleting it and pushing it again, and any writer may: except the deploy
branch (the repo's HEAD, `main`), which a push cannot delete. What the
site serves and the app runs follow that branch, and with votes required
the approvals are looked for along it, so its history is the one that
is kept. Until 2026-11 it could be deleted like any other, and a delete
and a create in one push replaced its history outright. Nothing but a
push moves a ref, an operator's hand included, so what is pushed to the
deploy branch stays in its history: a commit there is undone by a commit
on top of it.

A push's checks cost what the push brings. Every command is checked for
objects it reaches that the store does not hold, and an update for being
a fast-forward; the commands of one push share that work: the history
the refs reach is read once, and the fast-forward checks may load
100,000 commits between them, past which a command is refused with that
as its reason (a fast-forward is found within the commits it adds, so
one push adding more than that to a ref is pushed in steps). Until
2026-11 each command walked every object the repo holds, so a push
naming a thousand refs, charged as the few kilobytes it is, was a
thousand walks of the repo.

A submodule is pushed as git pushes it: its entry in a tree names a
commit of another repo, which is not asked for in the push and not sent
in a fetch (`git clone --recurse-submodules` fetches it from the URL in
`.gitmodules`, wherever that is). A site does not serve what is under
one. Until 2026-11 the entry's commit was asked for with the tree's
files, so a repo with a submodule could not be pushed.

A push whose request cannot be read is refused and charged nothing, and
a command naming a ref outside `refs/` (`HEAD`, a bare `main`) is such a
request: the whole push is refused with the reason. Until 2026-11 that
name was found only when the ref was written, after the charge, and the
canister trapped there: the pusher paid and was told nothing. A ref the
store refuses at that point is now that ref's refusal (`! [remote
rejected]`), beside whatever else the push did.

The gas of an EVM transaction is paid on the other chain by the
canister's EOA, and each tenant pays it back from a gas balance held in
that chain's asset on the IC side (docs/EVM_GAS.md): ckETH for Ethereum,
ckSepoliaETH for Sepolia, deposited with `deposit_gas` (Funding,
below). Before a
transaction is signed, the most it may cost, its gas limit at the fee
cap with the markup (`gas_markup_bps`, 1% by default and at most 100%)
on it, is reserved from the balance of the principal who pays the
repo's cycles, and the send is refused if the balance is short. It is
refused too when ic-git's own EOA could not cover it with every other
open hold and a margin of ten transactions (`get_gas_float`); the
operators refill the EOA, and the send can be retried then. The receipt
then charges the gas it used at the price it paid, with the markup, and
gives back the rest. What the markup collects beyond what refilling the
EOA costs is credited back to the balances it came from
(`gas_credit_surplus`). A deploy's gas limit, which is its owner's to set (`set_evm_deploy`; on a
governed repo the voters', `EvmDeploy`), is at least 53,000 and at most
10,000,000: enough for a contract of the largest size the chain takes,
with room for its constructor. A tighter limit holds less of the balance
while the transaction is out, and costs no less once it is mined. The
cycles charge, `evm_action`, pays for the signature and the outcalls
alone. Until 2026-11 the limit had a floor and no ceiling, and from then
until the gas balance a cycles rate per unit of gas limit, `evm_gas`,
stood for the gas; it defaulted to 0 and charged nothing.

A deploy's EVM leg is two actions when a registry is set: the deploy,
and the registry record of it that follows, each a signature and a
transaction, each charged an `evm_action` and each holding the gas
balance for its own gas limit. The record's charge
comes back whole when the deploy is skipped or fails, since nothing is
published then. Until 2026-11 the leg was charged the deploy alone and
the record's transaction, a million gas of limit, came free with it.

An EVM action is charged up front, and a failed one gives back what it did
not use:

- **Failed before any outcall** (no config, no registry, send lock held,
  artifact would not decode, or is more init code than a chain takes:
  49,152 bytes) or a deploy skipped as already deployed: the
  whole charge comes back, and nothing is held of the gas balance.
- **No provider can hold the transaction** (a nonce, fee or balance read
  failed, the gas balance or the float could not cover it, the signature
  failed, or a provider refused it: nonce too low or too high,
  insufficient funds, a JSON-RPC error, a 429): the owner pays the cycles
  attached to the outcalls made (3B per RPC call, 30B for the signature),
  and gets the rest back. The worst case is 45B, under the price; a
  tenant's send also reads the EOA's balance for the float, which can
  bring it to 51B, and the owner pays at most the price, ic-git the rest.
  The hold on the gas balance comes back whole.
- **A provider may hold it** (lost consensus on the broadcast reply, a 5xx,
  providers disagreeing, the call to the RPC canister failing): the full
  charge stays, and so does the hold on the gas balance, until a receipt
  settles it or the operators release it (`gas_release_hold`) for a
  transaction that never landed.

Rent is charged on the bytes a repo's pushes ingested. Objects are
content-addressed and shared, so two repos pushing the same blob are both
charged for it: attribution, not a measure of unique storage. An owner who
cannot cover rent pays what they have and the repo goes **delinquent**:
pushes and deploys are refused, and serving continues. What was not paid
stays owed: the repo's rent clock moves only as far as the payment
reached, so the debt grows with the time the bytes are held, and the
tick after a deposit takes it. The repo is cleared when a tick is paid
in full, not by any deposit: one short of the debt is taken whole and
the repo stays delinquent. `get_repo_info` and `/api/<repo>/info` say
what is owed (`rent_owed`), and the console shows it. The debt is the
repo's, so whoever accepts a transfer of a delinquent repo takes it
over. Until 2026-11 the clock moved to now at every tick whatever was
paid: a delinquent repo was held for nothing, and the smallest deposit
cleared it.

The push fee and the rent pay for git-side work, which after the canister
split (docs/CANISTER_SPLIT.md, step 12d) the git canister does. Both go
into a **pool** the authority keeps apart from the accounts: revenue, not
balances, so nothing a tenant could still spend leaves. After each rent
tick (the hourly timer, or `charge_rent_now`) the authority asks the git
canister what it holds and, when that is under the **git canister floor**
in the pricing table, sends the floor's worth from the pool, as far as the
pool goes and never what would leave its own liquid balance under the
floor. `get_git_funding` reports the pool, the floor, what has been sent,
the last top-up and the last tick that could not send; `top_up_git_canister(cycles)` lets an operator send the
canister's own cycles, since an operator's repos pay nothing and cost the
git canister all the same. The pool fills in the one-canister build
already, so what tenants paid before the cut funds the git canister from
it.

### Funding

- `deposit()`: credit the cycles attached to the call. Works from a cycles
  wallet canister and from other canisters, and from nothing else: a
  signed message carries no cycles, and one sent to `deposit` or
  `deposit_for` is refused before the canister pays for it.
  Either takes at least 100,000,000 cycles (`tenancy::MIN_DEPOSIT`) and
  accepts none of a smaller amount: a deposit makes the account's row,
  which is kept for good, and `deposit_for` names any principal, so with
  no minimum a canister made rows without end for the price of a call.
- `deposit_from_cycles_ledger(amount)`: the tenant first approves this
  canister on the cycles ledger (`icrc2_approve`), then calls this; ic-git
  pulls the cycles with `icrc2_transfer_from` and `withdraw`s them into
  itself, crediting the amount net of the withdraw fee. Three ledger fees
  are paid in all. `icrc2_approve` charges the first, straight from the
  wallet. Two more come out of the allowance: `transfer_from` charges its
  fee on top of `amount`, and `withdraw` charges the third out of what was
  moved. The allowance must therefore be `amount` plus one fee; the console
  approves the wanted deposit plus two fees and names it plus one, so the
  balance gains exactly what was typed, and the wallet needs that deposit
  plus three fees. If the withdraw fails
  after the transfer, the tenant is still credited (the cycles are ours,
  just parked on the ledger) and the event is listed in `stranded_deposits`
  for the operator to sweep.
- `deposit_from_icp(e8s)`: the route OISY users hold funds on. The tenant
  approves this canister on the ICP ledger for `e8s` plus one fee (the
  approve costs a second, from the wallet), then calls this. ic-git moves
  the ICP with `icrc2_transfer_from` straight to the cycles minting
  canister's top-up account for ic-git (memo `TPUP`), then calls the CMC's
  `notify_top_up`, which converts it at the current rate and deposits the
  cycles into ic-git; the tenant is credited exactly what the CMC reports.
  At least 0.01 ICP. Each deposit is recorded in `pending_icp_deposits`
  before anything moves, under an id that is also the transfer's
  `created_at_time`, so the ICP ledger treats a replay of the transfer as
  a duplicate and returns its block rather than moving the ICP twice.
  `finish_icp_deposit(id)` (the depositor or an operator) takes a pending
  deposit the rest of the way: it replays a transfer whose outcome was
  unknown, and retries a notify that failed, crediting the depositor once;
  a finish that arrives after the credit reports the balance, and one
  that arrives while an earlier call is still waiting on the ledger or
  the CMC is refused and asked to come again: two at once could drop a
  deposit whose ICP had moved. A definite
  transfer refusal drops the deposit (nothing moved), and a CMC refund
  returns the ICP to the tenant less a fee, uncredited. Errors no retry
  can fix (the CMC's TransactionTooOld or InvalidTransaction, or a replay
  past the ledger's 24-hour dedup window) move it to `failed_icp_deposits`
  for the operator. The
  console's "deposit from ICP" does the approve and the call in one wallet
  session, estimates the cycles from the CMC's rate, and lists any pending
  deposit with a finish button. `set_icp_ledgers(ledger, cmc)` (operators)
  repoints both for local testing; a deposit keeps the pair it started
  with, so repointing never redirects one already under way.
- `deposit_gas(amount)`: the gas balance (docs/EVM_GAS.md, section 3),
  held in the EVM chain's own asset on the ledger `get_gas_ledger`
  names: ckETH for Ethereum, ckSepoliaETH for Sepolia. The tenant
  approves this canister on that ledger for `amount` plus one fee (the
  approve costs a second, from the wallet), then calls this; ic-git
  pulls the amount with `icrc2_transfer_from` and credits it whole. At
  least ten of the ledger's fees. `withdraw_gas(amount)` sends what is
  not held back to the caller's own account on the ledger, less one
  fee; it is refused, costing nothing, during the few seconds an hour
  ic-git reads its own balance there to refill its EOA (docs/EVM_GAS.md,
  section 5), and goes through when asked again. Each transfer is recorded in `pending_gas_transfers` before
  anything moves, under an id that is also its `created_at_time`, and
  `finish_gas_transfer(id)` (the one it is for, or an operator) replays
  one whose outcome was unknown, which the ledger takes only once; past
  its dedup window it goes to `failed_gas_transfers` for the operators.
  `get_gas_account(p)` gives the balance (`available`, what open
  transactions hold as `reserved`, and what has gone in and out), and
  `get_gas_charges(p)` what each recent transaction cost on the chain,
  with its markup. The console's gas section does the approve and the
  deposit in one wallet session, the withdrawal, and a finish button for
  each transfer not yet settled, and lists the recent charges.

A cycles balance is not refundable yet; that needs the reverse of the
ledger flow. A gas balance is, being the same asset going back.

A transfer is an offer. `transfer_repo(repo, p)` names who the repo is
offered to and changes nothing else: the owner still owns, pays and
administers. It is theirs when they call `accept_transfer(repo)`, and
from then they pay, the old owner has no right over it (their push
tokens are revoked), and the members keep their roles. Until then the
one it was offered to can decline and the owner can withdraw
(`cancel_transfer(repo)`); a new offer replaces the last, and naming the
owner withdraws it. Governing the repo withdraws an offer too: from then
a new owner is offered by a vote the owner approves (see Governed app
canisters). `get_repo_info` and `/api/<repo>/info` show a
standing offer as `pending_owner`. A caller who names themself has
agreed by calling, which is how an operator takes a repo over. Until
2026-11 a transfer applied at once and asked nobody: a repo handed to a
funded stranger billed them its rent, and one handed to an operator went
exempt with its writers still pushing.

## Votes

`set_required_votes(repo, k)` makes the deploy queue hold a commit until `k`
voters (the owner counts as one) have approved it with
`cast_ballot(repo, commit, Approve, null)`. Ballots can be changed; a
removed voter's ballot stops counting. A `k` above the owner plus voters is
refused, and so is removing a voter, making one a writer, or
transferring the repo when that would leave `k` out of reach: lower `k`
first. `k = 0`, the default,
deploys on push as before.

A ballot is on a commit of the repo: a commit object that one of the
repo's refs reaches, among the 20,000 nearest them, which the git side
is asked before the ballot counts. Every repo's objects are in one
store, and until 2026-11 the question was only whether the store held
the object: a ballot was taken on any blob or tree and on any other
repo's commit, each a record kept for good and, with one vote required,
an entry in the approved set the git side is sent whole. A commit a
forced push left behind takes no new ballots; the ones it has stay on
record. Ballots are still kept for as long as the repo is: on a commit of
the repo, which a push paid for.

What the ballots are counted for has an end. Every ballot, and every
change of the threshold or the voters, counts the approved set again and
sends it to the git side whole; until 2026-11 that was over every commit
the repo had ever taken a ballot on, so one ballot's work grew with the
repo's whole past. A repo now counts at most 200 commits: the 100
approved commits on the deploy branch nearest its tip, and the 100
others (one still being voted on, one on another branch) with the newest
ballots. Nothing leaves while there is room. When the list is full and a
ballot comes on a commit not on it, the git side is asked where each
commit stands, and the ballot is not cast until it answers; a commit no
ref reaches any more leaves first. So a withdrawn approval falls back as
far as the 100th approved commit behind the tip and no further, and an
approval given to a commit further back than that is recorded and serves
nothing. Leaving the list is not leaving the record: `votes` shows the
ballots as before, and the next ballot on the commit counts them all
again if the list keeps it.

With `k` at 0 a repo trusts the git canister for what deploys. After the
canister split (docs/CANISTER_SPLIT.md, decision 6.5.4) the git canister
holds the branches and the authority holds the accounts, the ballots and
the keys; a deploy is a job the git canister sends with proofs that the
artifact is in the commit it names, and the authority checks the proofs
and hashes the bytes itself. Which commit is the tip, only the git
canister knows, so for a repo with no votes required its word on that is
final: the same trust such a repo placed in the one canister before the
split, and no governance claim is made by it. With `k` above 0 the git
canister can only propose: the authority deploys and attests nothing its
ballots have not approved, and the git canister serves only a commit the
authority has told it is approved, however the git canister answers.

A ballot is one of three. `Approve` counts 1. `Reject` counts 0: it says
"no", or withdraws an earlier approval or objection, and raises the bar
for nobody.
`Object` counts -1 and must give a reason (up to 1 KB, shown to the other
voters): a commit passes when approvals minus objections reach `k`. An
objection is not a veto. It costs one more approval to overcome, and it
puts a reason in front of the people who would cast it. That holds while
the policy has an approval to spare: an objector cannot also approve, so
with `k` at the number of voters or one below it a single objection
holds the commit until its author changes their ballot or leaves the
policy. Keep `k` lower where no one voter should be able to do that.
`vote(repo, commit, approve)` is the older two-way form, kept for clients
that predate objections; it maps onto `Approve` and `Reject`.

`cast_ballot` returns the count it left behind -- approvals, objections,
the threshold, and whether it is reached -- and
`GET /api/<repo>/votes/<commit>` reports the same count with the ballots,
each with its decision, reason and time, and `counts`: false for a ballot
whose caster has since left the policy, which stays on record and is left
out of the count. `get_votes` carries the same flag. The wallet's consent
message for an objection quotes the reason, so the signer sees what the
other voters will read. The one for a rejection says that it replaces the
signer's earlier ballot: after an objection that withdraws the -1, and the
commit may deploy.

With `k > 0` the repo has one approved commit, and both the app and the
site follow it: the newest commit on the deploy branch's first-parent line
that has reached the threshold, looking back up to 10,000 commits from
the tip. The canister records it after every call that can move it -- a
ballot, `set_required_votes`, adding or removing a member, a transfer, a
push -- and when it moves, `/site/<repo>/` serves it from then on and its
deploy is queued. That holds whichever way it moves: approving a commit
below the tip deploys and serves it, and withdrawing the approval on the
served commit, or objecting to it, rolls both the site and the app back to
the approved commit before it. An unapproved push is not served and does
not deploy. Only a
commit on the branch counts: deleting the branch, or replacing it with
history nobody approved, serves nothing rather than leaving an old commit
live, and burying an approved commit under 10,000 unapproved ones takes
it down too. Every site request re-checks the recorded commit's ballots,
so a site never serves a commit that is not approved now; with nothing
approved it answers 404. Approvals on history a merge brought in through
its second parent are not seen.

If the approved commit's deploy fails (the balance ran out, the install
was refused), the site is ahead of the app until it is retried: any
ballot on the repo re-queues the approved commit when the app is not
running it, and `deploy_now` deploys the approved commit, not the tip.
Pushes do not retry, so a deploy that keeps failing is not charged again
on every push.

Setting `k` above 0 on a live site takes the site down until a commit is
approved, so approve the tip right after. Setting it back to 0 serves the
tip and deploys it if the held pushes never did. `evm_registry_publish_site`
attests the served commit, never an unapproved tip; `evm_registry_publish`
likewise attests the approved commit's artifact, and both charge only
once the record resolves.

This is the same K-of-N shape as the release
attestations in docs/ATTESTATION.md, applied one level down: the people
expected to approve a release are named on the repo, and the canister
enforces the count.

The rules live in the `ic-multisig` crate
(https://crates.io/crates/ic-multisig, source at
https://github.com/DrJesseGlass/ic-multisig), shared with ic-vote:
`tenancy.rs` only supplies the policy (owner plus voters, threshold =
required votes), the subject (`Subject::of_short_hash("commit", oid)`), and
a `Store` over the VOTES stable map scoped by repo. Ballots are keyed by
the subject, so nothing written under the earlier per-commit key is read;
no votes had been cast on mainnet when the adapter landed. Objections
came with the crate's 0.2.0; ballots recorded before it read as having no
reason, which is what they had. A signed flavor of the same record type is
what the module-hash attestations will use.

## Feeds

Every repo has an Atom feed at `GET /feed/<repo>` on the canister's raw
domain, and ic-git itself has one at `GET /feed`
(docs/GOVERNANCE.md, section 6). Any feed reader subscribes, or a
feed-to-email service; the canister stores nothing about who reads it.

A repo's feed carries, newest first:

- a push to the deploy branch of a votes-gated repo whose tip nobody has
  approved yet (`awaiting`), with the count it needs;
- every ballot on a commit (`ballot`), with who cast it, the decision,
  the reason when there is one, and the count it left behind, and the
  moment a commit reaches the threshold (`reached`);
- every ballot on a policy change (`policy`), and the change taking
  effect;
- a deploy's outcome, wasm or EVM (`deployed`, `deploy-failed`), with the
  target and the module hash;
- a registry record broadcast for the repo (`published`): `<repo>`,
  `<repo>#site` or `<repo>#app`, with the transaction hash. Broadcast,
  not mined: `evm_receipt` says when the chain has it.

The kind is each entry's `<category>`; the actor, when there is one, its
`<author>`. ic-git's own feed carries the governor's proposals, ballots
and outcomes (docs/GOVERNOR.md, "Following it") and the `ic-git#canister`
record. Each feed keeps its newest 200 events; the records themselves are
elsewhere (`get_deploy_history`, the registry, the governor's `log`), so
a feed tells you to look, it is not what you check.

## App canisters

An app deployed to the IC should burn its own owner's cycles, not ic-git's.
`create_app_canister(repo, cycles)` spends `cycles` from the owner's balance
to create a canister with the owner and ic-git as controllers, records it on
the repo, and `set_wasm_deploy(repo, "app", path)` then targets it by name.
`top_up_app_canister(repo, cycles)` moves more balance into it. The owner
can also top it up from any wallet, since it is theirs.

A deploy config names its target by id, and any id may be named: ic-git
is a controller of every repo's app canister, the only one of a governed
repo's, so that it can install into a canister says nothing of whose the
canister is. The install asks. As it goes out, the deploy reads the
target's controllers from the IC and installs into the repo's own app
canister; never into another repo's, whoever owns either; and into any
other canister only if the repo's owner is a controller of it (the owner
made ic-git a controller of it and could install into it anyway). What
it refuses, the deploy's status says. An ownerless repo, which only
operators configure, has no owner to ask after and is held to the first
two. A repo deploys into its owner's other canisters only once that
owner has accepted the repo (a transfer is an offer; see Roles), and the
wallet's message on accepting says so.
Until 2026-11 nothing asked, and a repo's deploy could install
into any app canister.

A deploy that cannot finish is its own repo's failed deploy. A queued job
is taken off the queue, charged and marked "deploying" in one message,
and what it builds is read and built in the next: a build that traps
undoes only that, so the job is not put back to trap again in front of
every other repo's. Its status then says it trapped and was abandoned,
it stays charged as any failed deploy is, and the queue goes on to the
next job. `deploy_now` runs the same way. A `.lang` expression may be 64
levels deep, counting parentheses, call arguments, negations and each
operator of a chain (`a + b + c` is two), and a deeper one is a build
error: unbounded, a few hundred kilobytes of `(` overflowed the
compiler's stack. Until 2026-11 that trap took the job's removal back
with it, the job stayed at the head of the queue, and no repo's deploy
ran until an upgrade.

## Governed app canisters

docs/GOVERNANCE.md, section 2. With the owner a controller, the owner can
install code no vote approved. `govern_app_canister(repo)` closes that:
ic-git becomes the app canister's only controller and the owner is
removed, so from then on its code changes only by an approved commit's
deploy. Owner only; refused without an app canister, with required votes
at 0 (a governed repo whose pushes deploy unapproved would lock in
nothing), while the deploy config builds a `.wat` or `.lang` source, or
when already governed. A governed repo deploys committed `.wasm` only, so
the voters approve the exact module and `<repo>#app` records its hash;
nothing compiled here reaches a governed backend. A `WasmDeploy` change
naming a compiled source is refused before any ballot, and the deploy
queue refuses one as it runs, for a job queued before the repo was
governed. The repo is marked governed before
the controller call goes out, so the policy is locked while it is in
flight (the mark comes off only if the call fails). One-way: nothing but
an approved commit can give control back, and that is the point and the
price -- a broken backend is fixed by an approved commit, not directly.
The console puts it behind a typed confirmation like a reinstall.

Governing locks the policy, or the owner could set `k` to 0, or make
themselves sole approver, and push anything:

- `set_required_votes`, adding or removing a voter, `transfer_repo`,
  `set_wasm_deploy` and `set_deploy_mode` are refused on a governed repo;
  each names the path that takes it. Writers stay the owner's to manage:
  a writer pushes, and a push deploys only once approved.
- `propose_policy_change(repo, change, decision, reason)` is that path: a
  ballot on the change itself -- `RequiredVotes { k }`, `AddVoter`,
  `RemoveVoter`, `Transfer { new_owner }`, `WasmDeploy { target,
  source_path }`, `DeployMode { mode }` or `EvmDeploy { source_path,
  gas_limit }` -- under the same rule as a
  commit: approve, reject or object with a reason, counted over the
  current approvers, applied by the approval that finds approvals minus
  objections at `k`. Only an approval applies a change: one that came to
  have its votes without a ballot (the threshold was lowered under it, or
  an objector removed) stays pending until an approver says yes again,
  and a rejection or an objection cast on it meanwhile is recorded and
  applies nothing. Any approver may propose, and proposing is approving: the first
  ballot on a change must be an approval (a rejection of nothing is
  refused), and a pending change whose approvals fall to none -- its
  approvers having replaced theirs with rejections -- is withdrawn,
  ballots and all. Each approver holds at most 8 pending changes that
  way, so one voter can fill no one else's slots. A change nobody could
  apply (`k` of 0 or above the approvers, an unknown mode, an install
  mode with no deploy config, a source that is not `.wasm`, removing a
  non-voter) is refused before any
  ballot; a pending change the policy has since moved under is dropped,
  ballots and all, at the next ballot on it. A repo requiring no votes
  refuses every proposal: under `k` of 0 any ballot would be reached at
  once, so there is nothing to vote on and the owner changes it directly.
  The same change proposed by two approvers is one subject, so approvals
  accumulate; once applied its ballots are cleared, so proposing it again
  starts from nothing. A `Transfer` to a new owner is the one change the
  count does not decide alone: it also takes the owner's own approval
  among its ballots, and until then it stays pending and is reported as
  not reached, whatever its count. The votes decide what the repo deploys
  and who votes on it; they do not hand the owner's seat on without the
  owner. Until 2026-11 they did, and under one required vote a voter
  named themself, was reached by their own ballot, and accepted. No rule
  on the count would hold there, since under one required vote a voter
  adds voters alone and may name a principal that is not one. A
  `Transfer` naming the owner withdraws an offer, moves nothing, and
  goes by its votes. When the owner changes, every pending `Transfer` is
  dropped, ballots and all: they were cast under the last owner, and an
  approval the new owner cast as a voter is not the owner's. The same
  holds on a repo that is not governed but
  requires votes. `get_policy_proposals(repo)` and `GET /api/<repo>/proposals`
  list what is pending, with ballots and count. The console shows them
  with approve, reject and object controls, and a form to propose.
- `k` can never return to 0 on a governed repo, by vote or otherwise.

Every install into a governed app canister is recorded on chain: the
deploy queue publishes `<repo>#app` -- the commit and the sha256 of the
module it installed, which is the module hash the IC certifies for the
canister -- the way `evm_registry_publish_site` publishes `<repo>#site`,
charging one `evm_action` with the deploy (refunded if the publish fails
before broadcast; a failed install publishes nothing, since the canister
still runs what the last record says). A verifier that reads the
canister's certified module hash (docs/CERTIFIED.md) can thus check it is
an approved commit's build without asking ic-git. The record follows what
runs: a rollback after an objection installs the earlier commit and
records that. On a network with no registry configured the deploy says
nothing of it. The deploy status carries the transaction hash at
broadcast (`app record tx 0x...`); the record exists once the chain
includes the transaction, which `evm_receipt` shows and the backend check
(docs/EXTENSION.md) reads. A first record creates storage, which the
chain prices far above an overwrite, so registry writes carry a 1M gas
limit. Unused gas is refunded on chain to the canister's EOA (the
`evm_action` charge is unchanged either way), but the EOA must hold the
whole limit times the fee cap when it sends.

`/api/<repo>/info` reports `governed`. ic-vote's poll canister is the first
intended user (docs/GOVERNANCE.md, section 7).

## Custom domains

A site is served at `/site/<repo>/` on the canister's own host. It can
also be served at a domain of the tenant's own, where the whole origin is
the site: `GET /` is the bundle's root, `GET /<path>` the blob at that
path, and nothing else of the canister (no git, no `/api/`, no other
site) is reached there. The bytes, and the `X-Ic-Git-*` headers that bind
them to their commit, are the same as at `/site/<repo>/`.

`set_site_domains(repo, domains)` names them: owner or operator, the whole
list each time (empty takes the site off every domain). The git side
checks each name and keeps the list in the site config, which `get_site`
shows and the console edits. A domain is a DNS name as it would be looked
up (lowercase, no trailing dot) of at least two labels, not an IP address,
and not under the IC's own domains (`icp0.io`, `ic0.app`, `icp-api.io`,
`icp.net`, `localhost` and the like), where a host names a canister by
its id; nor, wherever it is, a name with a canister id for a label (alone
or after a `--`, which a gateway takes as a prefix and drops), since the
gateways add domains and a site holding `<this canister>.<one of
them>` would be served there in the canister's place, index, git and
API. One
repo holds a domain at a time: a second repo is refused it until the first
gives it up, which an operator may do on any repo. A site has at most
eight. Naming a domain does not turn serving on: `set_site` first.

The owner pays a push's base fee for each call the git side takes, as
for a push that stores nothing: like a push, it has the git canister
certify the site again, here at every domain, and the fee goes to the
git canister's pool. A call the git side refuses, or that does not reach
it, is refunded; an operator's call and an exempt repo pay nothing. A
list of more than eight is refused by both sides before anything else is
done with it, a repeat counting, and the list the site already has is
taken without certifying anything. Until 2026-11 the call was free and
the list unbounded: the limit was checked last, after every site's
config had been read once for each element.

Reaching the canister at the domain is the IC's own custom-domain
procedure, which the tenant drives (the boundary nodes' side is documented
at docs.internetcomputer.org under "custom domains", and is theirs to
change: what follows is what it was on 2026-11-18). In order:

1. `set_site_domains` with the domain. That puts it in
   `GET /.well-known/ic-domains` on the canister: every domain any site
   here is served at, one per line. The boundary nodes read that file and
   refuse a domain it does not list.
2. Three DNS records, where the domain's nameservers are (which need not
   be the registrar):

   | name | type | value |
   |---|---|---|
   | `<domain>` | CNAME (ALIAS or ANAME at a zone's apex) | `icp1.io` |
   | `_canister-id.<domain>` | TXT | `34koz-jyaaa-aaaab-ahejq-cai` |
   | `_acme-challenge.<domain>` | CNAME | `_acme-challenge.<domain>.icp2.io` |

   The IC's page now writes the first value as `<domain>.icp1.io`; the
   two resolve alike, and the plain one is accepted. One `_canister-id`
   record only: a second fails the validation. A DNS host that proxies
   or issues certificates of its own has to do neither for the name.
3. Ask whether the boundary nodes would take it, which registers nothing:
   `curl -sL https://icp.net/custom-domains/v1/<domain>/validate`.
4. Register it: `curl -sL -X POST https://icp.net/custom-domains/v1/<domain>`.
5. `curl -sL https://icp.net/custom-domains/v1/<domain>` reports
   `registration_status`: `registering`, then `registered` (or `failed`
   with the reason, or `expired`, which a second POST renews). The
   gateways present the domain's certificate some minutes after
   `registered`; until then a TLS client is refused the name.

To take a domain down: `set_site_domains` without it, remove the
`_canister-id` and `_acme-challenge` records, and
`curl -sL -X DELETE https://icp.net/custom-domains/v1/<domain>`, after
which the status request answers 404.

The canister to name is the one serving the sites: the git canister,
`34koz-jyaaa-aaaab-ahejq-cai`, since the cut (docs/CANISTER_SPLIT.md,
step 16); a domain registered to umobs before it has to be registered
again.
There is no domain for the canister itself, only for sites: a domain a
tenant names is that tenant's until an operator clears it, so an
operator who wants one holds it on a repo of their own.

A custom domain is reached through the IC's verifying gateway alone
(there is no `.raw` form of it), which passes a response only with the
subnet's certificate over it, or with the canister's declaration that it
has none. The git canister certifies every response at
`/site/<repo>/...` on its own host (crates/git/src/certify.rs; VISION.md
F0.5; live since v0.3.12, 2026-11-17) and every response at a site's
own domains (live since v0.3.13, the same day): there the URL is the
site's own, `/` and `/<path>`, which names no repo, and the certification tree is one tree for every host,
so each such entry is certified with the request's Host and method
(GET and HEAD), and a domain's `/` is told from another's, and from
the canister host's own index at `/`, by the Host the certificate
covers. The canister host's answers at the paths a domain's site took
(its index, its 404) are certified beside them, and so is every other
domain's 404, so no host loses a path: a path with an entry for one
host and none for another cannot be witnessed for the other. The edges
of one tree: at a domain page under `/api/`, `/feed/` or a `.git/`
path the canister host's answer stays declared uncertified, as before,
and the declaration sits at the page's own entry, so the page there is
no better certified than the API is; under `/site/`, where the canister
host holds its sites, a domain's 404 is certified at each of the
canister host's entries, the wildcards over the sites and every URL of
every site. These 404s beside other hosts' entries number every domain
times every such path, and an entry costs about a million instructions
to make, so certify.rs's `CROSS_CAP` (4,000) bounds them for the
canister as a whole, whoever's domains and files they come from. What
does not fit is left out by kind, each as a whole: first the 404s at the
URLs of the canister host's sites, then those at the paths of other
domains' sites, then those at the wildcards. A domain's 404 at a path
left out fails the gateway's check rather than passing certified; its
pages are not touched. And the Host a certificate covers is the domain
as it is written, which is what a browser sends, so a request
whose Host spells it otherwise (a port, capitals, a trailing dot) is
answered without one, and fails the gateway's check at a page. A site past
certify.rs's caps is served at its domains declared uncertified, as
every domain was before this.

The tree is heap state, so an upgrade of the git canister builds it
again from stable memory: every file of every site, read and hashed.
No one message holds that for any number of sites (measured, a site of
2,000 small files is about 4 billion instructions, and 20 MB of bodies
about 3.5 billion more), so the rebuild has a budget: 100 billion
instructions of the upgrade's own message, and after that 20 billion a
message, one after another on a timer, until every site is in. A
canister whose sites fit the first is whole when the upgrade ends. A
site the rebuild has not reached is declared uncertified at the
canister host, `/site/<repo>/...`: the gateway passes its pages
unverified until its turn, as the raw host always does. At its own
domain such a site has no entry, and its page is refused by the gateway
wherever a site already certified has a page at the same path (`/`, for
one), since a declaration there would be one for every host; so the
sites with domains are first. A site that is pushed to, or whose
config changes, while it waits is certified in that message. The git
canister's public query `sites_to_certify` says how many wait: 0 once
the tree is whole, and it is worth reading after an upgrade.

The domain form was first served by the real gateways on 2026-11-18, at
`evm-test.jesse.glass` for the `evm-demo` repo (v0.3.15): registered 45
seconds after the request, and reachable a few minutes later. Each of
these came back through the verifying gateway with a certificate: a file
of the site, GET and HEAD, 200 with the bytes and `X-Ic-Git-Commit` of
`/site/evm-demo/` at the canister host; a path nobody has, 404; under
`/site/`, a 404 at a site file's URL, under a site's wildcard, at
`/site/<no such repo>/` and at `/site/` itself; and a 404 at `/api/` and
at a repo's git URL, so nothing of the canister but the site is reached
there. The canister host answered as before at its index, its sites,
their 404s and the API. The domain's `/` was a 404 too, that repo having
no `index.html`: a page at a domain's root is the one case still seen
only by the e2e.

A domain is reached through the DNS its registrar serves, which nothing
here checks. The clients (docs/EXTENSION.md) verify a site on the
canister's own hosts only, so a page at a custom domain is loaded
unchecked until they know the domain: a pinned list of domain to repo
in the shared core, the next leg.

## Console

The repo browser page gains a signed-in mode: connect a wallet, see balance
and repos, create repos, mint, list and revoke push tokens, manage members and votes, deposit,
hold and withdraw gas for EVM transactions,
and set what a push deploys (`set_wasm_deploy`, into the repo's app
canister) and what is served as a site (`set_site`), run the configured
deploy without a push (`deploy_now`), name the site's own domains
(`set_site_domains`), reinstall, and govern the backend.
That is the whole tenant flow: nothing between a funded wallet and a
deployed push needs dfx.

After the canister split (docs/CANISTER_SPLIT.md, step 14c) the console
talks to both canisters. The page is served by the git canister (by
ic-git itself before the cut of 2026-11-16, whose host now redirects
there). Git reads (`/api/repos`, refs, trees,
blobs, commits) go to that canister's `/api` on the page's own origin;
the tenancy reads (`/api/pricing`, `account`, a repo's `info`, `votes`,
`proposals` and `deploys`) go to the authority's host, which the gateway
serves with `access-control-allow-origin: *` (the IC's and the local
replica's both; the e2e checks the header). Push tokens and the site
config are the git canister's, by query and by signed call; every other
call, and the spender a deposit approves on a ledger, is the authority's.
On mainnet the console pins both ids, as the verifier core does: the
canister a page approves as a spender is not learned from the canister
that served the page. On a replica or another deployment it asks the
serving canister (`get_authority`, the git canister's), and a canister
without that method is the one-canister build and the authority itself.
`tools/console-routes-test.mjs` checks the routing offline, against the
two `.did` files, and the e2e runs it; the e2e's console reads learn the
authority the same way on both the combined and the split network. At a
host that is not a canister's own (a domain, a bare localhost) the
console says it has no canister to talk to; the git browser above it
needs none.

A wallet that signs for its user asks this canister, before signing, for a
readable description of the call (ICRC-21, `icrc21_canister_call_consent_
message`; advertised through ICRC-10) and refuses to sign without one. The
canister answers for every method the console signs, with the call's
actual arguments decoded into the text -- the amount of a deposit, the
repository a token is minted for, the words WIPE ALL STATE on a reinstall
-- and refuses any other method rather than describe it vaguely, so a
wallet never signs this canister blind. Until this existed, no console
write to the canister could be signed at all: the wallet asked, got "no
such method", and stopped.

Reinstall is the one destructive control, and it is built to be hard to
do by accident: a red button opens a box naming the configured deploy
target (which is normally the app canister, but `set_wasm_deploy` takes
any canister's id, so the box names the one the config holds and says so
when it is not the app canister) and what will be wiped, and the run button
stays disabled until the owner has typed the repository name. Because the
install mode is a setting rather than an action, the control switches to
reinstall, deploys, and switches back to upgrade, and reports in red if
the switch back did not happen.

A deploy runs every configured leg, and `deploy_now` does not dedupe: a
repo with an EVM leg broadcasts a new CREATE transaction each time, a
fresh contract at a new address, paid for in ic-git's `evm_action` fee and
in gas on the other chain. That is the right behavior (the contract is
meant to track the app), but it is money outside cycles, so both the
deploy-now line and the reinstall box say what the deploy charges and
that the EVM contract will be redeployed, before the owner signs.
Reads go through the canister's `/api` routes; every write is a canister call
the wallet signs, so the page never holds a key. It stays one self-contained
file, so its attestation still covers every byte that runs.

The panel also shows what the wallet holds on the ICP and cycles ledgers, and
on the gas ledger, so a tenant can see what there is to deposit. These ledger
reads cannot go through `/api` (a query cannot make inter-canister calls), so
the page posts anonymous queries straight to the IC HTTP API at `icp-api.io`
and takes the boundary node's reply as is: `icrc1_balance_of` on each ledger,
and on the gas ledger also `icrc1_fee`, `icrc1_decimals` and `icrc1_symbol`,
whose decimals and symbol name its amounts, so the gas section reads the same
for ckETH, ckSepoliaETH, or a local stand-in. A balance that does not answer
shows as `?`, and a gas ledger whose fee, decimals or symbol do not answer
leaves the gas section saying it could not be read; nothing else on the page
depends on them.

## Operator notes

- The canister now custodies tenant balances. That raises the stakes on the
  controller and the attestation work, and is the strongest argument yet for
  docs/CANISTER_SPLIT.md: the ledger belongs in the small, stable canister.
- Every operator-only endpoint uses the one guard, `is_admin`: the admin
  API, pricing and ledgers, the names hook, the compiler workers, the
  build spike's bench (`compile_*`, `link_module_objects`,
  `measure_compile`, `run_wasm`, `run_wat`: they compile and run what
  the caller sends on the canister's cycles, and until 2026-11 anyone
  could call them; a worker authorizes its coordinator for
  `compile_module`), the legacy
  `put_object`/`set_ref` seeding calls, and the EVM and Solana operator calls
  (`evm_set_config`, `evm_send`, `evm_deploy`, `sol_set_config`, ...). Before
  v0.3.1 the last three groups checked the allowlist alone, so a controller
  not on the allowlist was refused there and nowhere else. The billing
  exemption had the same gap: a controller off the allowlist created repos
  free but was then billed for them (rent, pushes, deploy actions). It now
  uses the same rule, `tenancy::is_operator`.
- The ingress filter (`canister_inspect_message`, `ic_git_common::ingress`):
  a canister pays for each signed message it takes in, by its bytes,
  whether or not the call then does anything, so until 2026-11 anyone
  could send any method an argument of 2 MiB and have the canister pay
  for it, as often as the subnet allowed. Each canister now refuses,
  before that charge: a method only the other canister calls, from
  everyone; an operator's method from anyone else; a tenant's call from
  the anonymous principal, with an argument over 16 KiB, or from a
  caller it could not be for (below); a query sent as an update with
  more than 1 KiB, and a consent message with more than 8 KiB; `deposit`
  and `deposit_for`, since a
  signed message carries no cycles to deposit; a method with no rule;
  and on the git canister anything sent to `http_request_update` but a
  push with a push token that authorizes it, read without its pack. A
  push whose token stopped authorizing between the advertisement and
  the pack therefore gets the gateway's own error page in place of the
  401; git asks for the token at the advertisement, so a push without
  one does not get that far. Each method's rule is one line in its side's
  `ingress.rs`, and a canister's tests fail when its `.did` has a
  method with none. The filter saves cycles and decides nothing: a call
  from another canister never passes through it and one replica alone
  runs it, so every guard stays as it was. An operator is bound by none
  of the sizes. A tenant's call is taken only from a caller it could be
  for, asked of the canister's own state: a call on a repo (named by
  its first argument) from its owner, a member, or the one it is
  offered to; `create_repo` from an account that covers the fee, or
  holds the name reserved; `finish_icp_deposit` from the deposit's
  maker; a push token minted or revoked by a writer of its repo. A
  stranger is left the calls that are anyone's, each small: a first
  deposit from a ledger (64 bytes), a query sent as an update, the
  consent message. What remains is the price of a message that is
  taken, its fixed part and its bytes up to those bounds, which no
  filter removes. The filter takes a push by its path and token and
  does not look at its Host: at a site's own domain it is taken and
  then refused, as before, by `http_request_update`.
- The gas float (docs/EVM_GAS.md, section 5): `get_gas_float` gives
  the EOA's balance as last read against its target, floor and margin,
  and the sum of open holds, with no outcall; `gas_float_refresh`
  (operators) reads it now. The six-hourly watch
  (`tools/check-module-hash.sh`) reads the balance from the chain at the
  finalized block and fails under the floor, or under the open holds
  and the margin. It learns the EOA's address from the canister's last
  read, so after the release that brings it, one `gas_float_refresh`
  lets it check. The refill runs hourly; `gas_refill_now`
  runs one on demand and `get_gas_refills` lists every refill as the
  minter reports it. `gas_credit_surplus` credits the markup's surplus
  back to the balances it came from, and is refused while a refill is
  under way. `gas_release_hold(id)` gives back the hold of a
  transaction that never landed. `set_gas_ledger` names a gas ledger
  other than the chain's ck ledger (the local e2e names a stand-in);
  a balance stays on the ledger it was deposited on.
- `charge_rent_now` runs a rent tick on demand; the timer runs hourly and is
  re-armed on every upgrade.
- Existing repos (`evm-demo`, `registry`, `ic-git`) are ownerless and exempt.
  `transfer_repo` can hand any of them to a paying owner.
- Repo names and labels: a repo name is `[A-Za-z0-9._-]+`, at most 100
  characters (so the name service always accepts it), and it also
  maps to a lower-kebab label (lowercased, `.` and `_` as `-`, runs of `-`
  collapsed, ends trimmed; 1 to 63 bytes). The label is unique: once
  `my-app` exists, `My_App` and `my.app` are refused. Repos from before
  labels were indexed at the upgrade that introduced them.
- ic-name-service hook: `names_set_config(canister, handle)` (operators:
  controllers or the admin allowlist) turns on an
  announce after every successful install, naming the repo
  `<handle>/<label>` with its commit and module hash; the handle follows
  the same lower-kebab rule. `names_clear_config` turns it off. The call
  waits at most 60 seconds, and a failed or refused announce only
  annotates the deploy status. This canister's principal must be on the
  name service's deployer list.
