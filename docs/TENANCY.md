# Tenancy -- accounts, ownership, membership, votes, and who pays

ic-git started single-tenant: one allowlisted operator created repos and
minted push tokens, and the canister paid for everything out of its own
cycles. This document describes the multi-tenant model that replaces it,
implemented in `canisters/git/src/tenancy.rs`, `ledger.rs`, and `apps.rs`.

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
upgrade that introduced it. `list_push_tokens(repo)` shows the live ones
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
if they are an operator). Tokens from before expiry existed record no
minter, so they run out their 30 days instead.

A dead token record can never authorize again, and no listing shows it
or revoke can remove it: one that does not decode (only a bug leaves one),
or an old-format bare repo name written after the migration (a rolled-back
wasm). Operators list them with `dead_push_tokens` and remove one by id
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
| Owner | creating the repo, or `transfer_repo` | everything below, plus manage members, config, deploys, and votes threshold; pays |
| Writer | owner, `add_member(repo, p, "writer")` | push, mint and revoke tokens |
| Voter | owner, `add_member(repo, p, "voter")` | cast ballots on commits |
| Operator | controller or the legacy admin allowlist (never ic-git itself) | act on any repo; charged nothing |

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
| push | 100M + 5K per byte of the pack | before the pack is ingested (refused as `[remote rejected]`, with the reason) |
| storage rent | 5K per byte-year of ingested pack data | hourly timer, pro rata |
| EVM action | 50B | each deploy or registry publish (a t-ECDSA signature plus RPC outcalls) |
| IC deploy | 5B | each install from the deploy queue |

An EVM action is charged up front, and a failed one gives back what it did
not use:

- **Failed before any outcall** (no config, no registry, send lock held,
  artifact would not decode) or a deploy skipped as already deployed: the
  whole 50B comes back.
- **No provider can hold the transaction** (a nonce or fee read failed, the
  signature failed, or a provider refused it: nonce too low or too high,
  insufficient funds, a JSON-RPC error, a 429): the owner pays the cycles
  attached to the outcalls made (3B per RPC call, 30B for the signature),
  and gets the rest back. The worst case is 45B, under the price.
- **A provider may hold it** (lost consensus on the broadcast reply, a 5xx,
  providers disagreeing, the call to the RPC canister failing): the full
  charge stays, since the gas may be spent.

Rent is charged on the bytes a repo's pushes ingested. Objects are
content-addressed and shared, so two repos pushing the same blob are both
charged for it: attribution, not a measure of unique storage. An owner who
cannot cover rent pays what they have and the repo goes **delinquent**:
pushes and deploys are refused, serving continues, and the next deposit and
rent tick clear it.

### Funding

- `deposit()`: credit the cycles attached to the call. Works from a cycles
  wallet canister and from other canisters.
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
  a finish that arrives after the credit reports the balance. A definite
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

Balances are not refundable yet; that needs the reverse of the ledger flow.

## Votes

`set_required_votes(repo, k)` makes the deploy queue hold a commit until `k`
voters (the owner counts as one) have approved it with
`cast_ballot(repo, commit, Approve, null)`. Ballots can be changed; a
removed voter's ballot stops counting. A `k` above the owner plus voters is
refused, and so is removing a voter or transferring the repo when that
would leave `k` out of reach: lower `k` first. `k = 0`, the default,
deploys on push as before.

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

## App canisters

An app deployed to the IC should burn its own owner's cycles, not ic-git's.
`create_app_canister(repo, cycles)` spends `cycles` from the owner's balance
to create a canister with the owner and ic-git as controllers, records it on
the repo, and `set_wasm_deploy(repo, "app", path)` then targets it by name.
`top_up_app_canister(repo, cycles)` moves more balance into it. The owner
can also top it up from any wallet, since it is theirs.

## Governed app canisters

docs/GOVERNANCE.md, section 2. With the owner a controller, the owner can
install code no vote approved. `govern_app_canister(repo)` closes that:
ic-git becomes the app canister's only controller and the owner is
removed, so from then on its code changes only by an approved commit's
deploy. Owner only; refused without an app canister, with required votes
at 0 (a governed repo whose pushes deploy unapproved would lock in
nothing), or when already governed. One-way: nothing but an approved
commit can give control back, and that is the point and the price -- a
broken backend is fixed by an approved commit, not directly. The console
puts it behind a typed confirmation like a reinstall.

Governing locks the policy, or the owner could set `k` to 0, or make
themselves sole approver, and push anything:

- `set_required_votes`, adding or removing a voter, `transfer_repo`,
  `set_wasm_deploy` and `set_deploy_mode` are refused on a governed repo;
  each names the path that takes it. Writers stay the owner's to manage:
  a writer pushes, and a push deploys only once approved.
- `propose_policy_change(repo, change, decision, reason)` is that path: a
  ballot on the change itself -- `RequiredVotes { k }`, `AddVoter`,
  `RemoveVoter`, `Transfer { new_owner }`, `WasmDeploy { target,
  source_path }` or `DeployMode { mode }` -- under the same rule as a
  commit: approve, reject or object with a reason, counted over the
  current approvers, applied the moment approvals minus objections reach
  `k`. Any approver may propose, and proposing is approving. A change
  nobody could apply (`k` of 0 or above the approvers, an unknown mode,
  an install mode with no deploy config, removing a non-voter) is refused
  before any ballot; a pending change the policy has since moved under is
  dropped, ballots and all, at the next ballot on it. A repo requiring no
  votes refuses every proposal: under `k` of 0 any ballot would be reached
  at once, so there is nothing to vote on and the owner changes it
  directly. At most 16 changes can be pending at once. The same change
  proposed by two approvers is one subject, so approvals accumulate; once
  applied its ballots are cleared, so proposing it again starts from
  nothing. `get_policy_proposals(repo)` and `GET /api/<repo>/proposals`
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
nothing of it.

`/api/<repo>/info` reports `governed`. ic-vote's poll canister is the first
intended user (docs/GOVERNANCE.md, section 7).

## Console

The repo browser page gains a signed-in mode: connect a wallet, see balance
and repos, create repos, mint, list and revoke push tokens, manage members and votes, deposit,
and set what a push deploys (`set_wasm_deploy`, into the repo's app
canister) and what is served as a site (`set_site`), run the configured
deploy without a push (`deploy_now`), reinstall, and govern the backend.
That is the whole tenant flow: nothing between a funded wallet and a
deployed push needs dfx.

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
target (which is normally the app canister, but `set_wasm_deploy` accepts
any canister, so the box names the one the config holds and says so when
it is not the app canister) and what will be wiped, and the run button
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

The panel also shows what the wallet holds on the ICP and cycles ledgers, so
a tenant can see what there is to deposit. Those two reads cannot go through
`/api` (a query cannot make inter-canister calls), so the page posts anonymous
`icrc1_balance_of` queries straight to the IC HTTP API at `icp-api.io` and
takes the boundary node's reply as is. A ledger that does not answer shows as
`?`; nothing else on the page depends on it.

## Operator notes

- The canister now custodies tenant balances. That raises the stakes on the
  controller and the attestation work, and is the strongest argument yet for
  docs/CANISTER_SPLIT.md: the ledger belongs in the small, stable canister.
- Every operator-only endpoint uses the one guard, `is_admin`: the admin
  API, pricing and ledgers, the names hook, the compiler workers, the legacy
  `put_object`/`set_ref` seeding calls, and the EVM and Solana operator calls
  (`evm_set_config`, `evm_send`, `evm_deploy`, `sol_set_config`, ...). Before
  v0.3.1 the last three groups checked the allowlist alone, so a controller
  not on the allowlist was refused there and nowhere else. The billing
  exemption had the same gap: a controller off the allowlist created repos
  free but was then billed for them (rent, pushes, deploy actions). It now
  uses the same rule, `tenancy::is_operator`.
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
