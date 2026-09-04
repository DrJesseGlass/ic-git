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
design refuses to have.

## Roles

| Role | Granted by | May |
|---|---|---|
| Owner | creating the repo, or `transfer_repo` | everything below, plus manage members, config, deploys, and votes threshold; pays |
| Writer | owner, `add_member(repo, p, "writer")` | push, mint and revoke tokens |
| Voter | owner, `add_member(repo, p, "voter")` | cast ballots on commits |
| Operator | controller or the legacy admin allowlist | act on any repo; charged nothing |

Repos created before tenancy existed have no owner and are treated as
operator repos: exempt from every charge, writable only by operators.

## Money

`get_pricing` returns the table; operators retune it with `set_pricing`.
Defaults are round numbers above the IC's own rates so the canister runs at a
margin:

| Charge | Default | When |
|---|---|---|
| create_repo | 1B cycles | on creation; also what "positive balance" means |
| push | 100M + 5K per byte of the pack | before the pack is ingested (HTTP 402 if refused) |
| storage rent | 5K per byte-year of ingested pack data | hourly timer, pro rata |
| EVM action | 50B | each deploy or registry publish (a t-ECDSA signature plus RPC outcalls) |
| IC deploy | 5B | each install from the deploy queue |

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
  itself, crediting the amount net of the ledger fee. If the withdraw fails
  after the transfer, the tenant is still credited (the cycles are ours,
  just parked on the ledger) and the event is listed in `stranded_deposits`
  for the operator to sweep.
- ICP: not yet. The path is an ICRC-2 approve on the ICP ledger, a transfer
  to the cycles minting canister, and `notify_top_up`; it is the funding
  route OISY users will actually want and is the next item here.

Balances are not refundable yet; that needs the reverse of the ledger flow.

## Votes

`set_required_votes(repo, k)` makes the deploy queue hold a commit until `k`
voters (the owner counts as one) have approved it with
`vote(repo, commit, true)`. Ballots can be changed; a removed voter's ballot
stops counting. When the deploy-branch tip reaches the threshold, its deploy
is queued from the vote call itself. `k = 0`, the default, deploys on push
as before. This is the same K-of-N shape as the release attestations in
docs/ATTESTATION.md, applied one level down: the people expected to approve
a release are named on the repo, and the canister enforces the count.

The rules live in the `ic-multisig` crate
(https://github.com/DrJesseGlass/ic-multisig), shared with ic-vote:
`tenancy.rs` only supplies the policy (owner plus voters, threshold =
required votes), the subject (`Subject::of_short_hash("commit", oid)`), and
a `Store` over the VOTES stable map scoped by repo. A signed flavor of the
same record type is what the module-hash attestations will use.

## App canisters

An app deployed to the IC should burn its own owner's cycles, not ic-git's.
`create_app_canister(repo, cycles)` spends `cycles` from the owner's balance
to create a canister with the owner and ic-git as controllers, records it on
the repo, and `set_wasm_deploy(repo, "app", path)` then targets it by name.
`top_up_app_canister(repo, cycles)` moves more balance into it. The owner
can also top it up from any wallet, since it is theirs.

## Console

The repo browser page gains a signed-in mode: connect a wallet, see balance
and repos, create repos, mint tokens, manage members and votes, deposit.
Reads go through the canister's `/api` routes; every write is a canister call
the wallet signs, so the page never holds a key. It stays one self-contained
file, so its attestation still covers every byte that runs.

## Operator notes

- The canister now custodies tenant balances. That raises the stakes on the
  controller and the attestation work, and is the strongest argument yet for
  docs/CANISTER_SPLIT.md: the ledger belongs in the small, stable canister.
- `charge_rent_now` runs a rent tick on demand; the timer runs hourly and is
  re-armed on every upgrade.
- Existing repos (`evm-demo`, `registry`, `ic-git`) are ownerless and exempt.
  `transfer_repo` can hand any of them to a paying owner.
