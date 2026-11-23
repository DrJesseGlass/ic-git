# EVM gas -- tenants pay in the chain's asset, held on the IC

Status: **design, 2026-11-22. Built: leg 1, the balance (#197); leg 2,
the reservation and settlement of each transaction (#198); and leg 3a,
the float's measure and invariant; and leg 3b, the refill through the
minter and its accounting. Not yet: leg 4 (the console).** It replaces a first draft the same
day that gave each repo an EVM address of its own. That draft was
dropped because it spread ic-git's ETH over one address per
repo and ruled out putting many records in one transaction. Companion
to docs/TENANCY.md (who pays, in cycles) and `crates/authority/src/evm.rs`
(the signer).

## 1. What is wrong today

The authority signs every EVM transaction from one address: the EOA of
its threshold key, on the one chain its `EvmConfig` names (Sepolia).
That address pays the gas of two kinds of transaction:

- a tenant's deploy, a CREATE whose gas limit the repo's config sets,
  anywhere from 53k to `MAX_DEPLOY_GAS` (10M);
- a registry write, `REGISTRY_SET_GAS` (1M), for ic-git's own records
  and for the record a tenant's deploy publishes (#177).

Tenants pay in cycles: `evm_action` for the signature and the outcalls,
plus `evm_gas` per unit of gas limit (#168). `evm_gas` defaults to 0, and
no fixed cycles rate stays right: the gas is paid in the other chain's
token, at a fee that moves by the block. On a testnet this is harmless.
On a chain with real money, every tenant deploy is paid for by the
operators.

## 2. The decision

- **One EOA and one registry contract**, as today. ic-git holds the
  chain's native token in that one address and spends it on every write.
- **Each tenant holds a balance of the chain's asset on the IC side**:
  ckETH for Ethereum, ckSepoliaETH for Sepolia. They deposit it into
  ic-git's ledger account.
- **A tenant's transaction is charged to that balance at what it cost
  on the chain**: the receipt's `gas_used * effective_gas_price`, in
  wei. ckETH has 18 decimals, so one unit of it is one wei: no exchange
  rate comes into it at any point.
- **ic-git turns the ckETH it was paid back into ETH** through the ckETH
  minter, to keep its EOA funded.

Cycles keep paying for what the IC spends: `evm_action` covers the
signature and the outcalls. `evm_gas` is retired.

## 3. The tenant's balance

- **Kept per principal and per ledger**, beside the cycles balance, in
  wei, by the same rule as cycles: the principal who pays a repo's cycles
  pays its gas. A balance on one ledger is never read as one on another,
  so a change of chain leaves what was held where it was.
- **Deposit** by `icrc2_approve` on the asset's ledger, then a call to the
  authority, which pulls the amount with `icrc2_transfer_from` and
  credits it. It has the shape the ICP deposit has: one attempt at a
  time (#186), and `created_at_time` set so that a retry cannot credit
  twice.
- **A deposit is at least ten of the ledger's fees**, read from the
  ledger at the deposit, so that no deposit costs more in fees than it
  holds.
- **Withdraw** by `icrc1_transfer` back to the principal, of what is
  neither reserved nor owed. The amount is debited before the transfer
  goes out, and the ledger's fee comes out of it.
- **A transfer whose outcome is unknown stays pending**, and a replay
  under the same `created_at_time` settles it, as for ICP. Once an
  outcome has been unknown, or an attempt was cut off before its reply
  was handled (an upgrade drops it), a refused replay settles nothing: the first
  transfer may have landed, and a withdrawal given back after it was paid
  would pay twice. Only the first transfer's block settles it, or, past
  the ledger's dedup window, the operators. Unlike cycles, this balance can be taken out
  again, because it is the same asset going back.
- **A query** gives the balance, the amount reserved, and what each
  recent transaction cost. The console shows them.

## 4. Charging a transaction

1. **Reserve before signing.** After the fee read, the send reserves
   `gas_limit * max_fee_per_gas`, with the markup (point 4) on it, from
   the payer's available balance, and is refused before signing if that
   is more than they have. The refusal names the shortfall. The markup
   is reserved too, so that no settlement can come to more than was
   reserved.
2. **Settle on the receipt.** The receipt poll that already runs
   (`schedule_receipt_poll`) debits `gas_used * effective_gas_price` and
   releases the rest of the reservation. A reverted transaction still
   used gas and is charged for it.
3. **A send that may be out stays reserved.** If a broadcast's outcome
   is unknown (`maybe_sent`), the reservation is held until a receipt
   settles it, or an operator resolves it as dropped and it is released.
4. **A small markup** is added to each settled charge, a rate the
   operators set: just enough to cover what turning ckETH back into ETH
   costs (section 5), so that ic-git does not pay for it. It is set to
   err on the high side, because an overcharge is cheap to undo: the
   authority keeps what the markup has collected against what refills
   have cost, and any surplus is credited back to the balances it came
   from. That credit is an entry in ic-git's own ledger, with no ledger
   transfer and no fee.
5. **What is charged this way:** a tenant's deploy, and the registry
   write that the deploy causes. ic-git's own records
   (`ic-git#canister`, `#git`, `#site`) are the operators' cost, as now.

## 5. The float

The EOA's ETH is ic-git's float: ic-git's own money, never a tenant's,
spent first on every transaction and then paid back from tenant
balances. Every amount is an integer in the asset's smallest unit (wei,
later satoshis); there is no floating point anywhere in it.

- **Sized in transactions, not in ETH.** The float's target is
  `float_target_txs` transactions (1000 by default) at the chain's
  measured cost per transaction; its floor is `float_floor_txs` (500).
  The same rule then holds for any chain and asset: ckETH in wei now,
  ckBTC in satoshis later, with only the refill call differing.
- **The cost per transaction** is the mean of what the chain's recent
  transactions cost (`gas_used * effective_gas_price`, the last 50
  receipts of the EOA's own transactions, ic-git's records and tenants'
  sends alike). Each counts once: a receipt counts only if it was mined
  after the newest one counted, so reading an old one again changes
  nothing. Until there are any, it is 100k gas at the current fee cap.
- **The invariant:** after a tenant's send is reserved, the EOA still
  holds at least the sum of all open holds plus `float_margin_txs`
  transactions (10). A send that would break it is refused, as for a
  short balance, and the watch reports it. ic-git's own records are
  never refused by it.
- **Refill:** an hourly tick (and `gas_refill_now`, for the operators)
  withdraws ckETH to the EOA through the minter's `withdraw_eth` when the
  EOA is under its floor, enough to bring it back to the target and never
  under the minter's minimum (0.01 ETH on Sepolia). What it may withdraw
  is read from the ledger, not counted: ic-git's ckETH balance, less all
  it owes tenants (balances, held or not, and every transfer that may
  yet be theirs) and less the markup's surplus not yet credited back.
  That leaves the gas tenants have paid for and the EOA has not been
  given back. The balance and what is owed are taken as of one moment:
  a withdrawal that settles while the balance is read would be in the
  one and gone from the other, so a read during which a tenant's
  transfer moved is made again. The ledger and the minter are asked
  first, so a tick with nothing to refill from pays for no outcall.
- **The minter is the record of each refill.** A tick first reads ic-git's
  withdrawals from the minter (`withdrawal_status`), which also finds a
  refill whose reply an upgrade dropped. One not finished blocks the
  next. The minter takes the gas of its own transaction out of the
  amount and reports it; that, the ledger fees (the approval's, and the
  burn's in case it has one), and any part of a failed refill not given
  back are booked against the markup (section 4, `refill_costs`).
- **The surplus** (markup, less refill costs, less what was credited) is
  credited back by the operators (`gas_credit_surplus`), to each balance
  in proportion to the markup it paid: an entry in ic-git's own books,
  with no transfer and no fee. It is not credited while a refill is
  under way, from a tick's first read until the minter has finished it,
  a lost reply included, since that refill's costs are not booked yet.
- **The operators seed the first float**, and they fund the EOA for
  ic-git's own records.
- **The watch** reads the EOA's balance, the target and floor, and the
  sum of the holds, as it reads the canisters' cycles.

## 6. Many records in one transaction (later)

With one EOA and one contract, records that are not urgent can share a
transaction. They wait in a queue, and one write puts a Merkle root over
all of them on the chain, so each record pays its share of one
transaction's gas. This is a leg of its own, after the balances, because
most of its cost is on the reading side:

- a second registry contract, or a version of it, that stores roots;
- the git canister serves each record's inclusion proof, certified;
- every verifier learns to check a proof against a root:
  `tools/verify.mjs`, `loader/index.html`, both extensions, and ic-vote;
- an urgent write (a release record, a site record a tenant is waiting
  on) still goes out alone, at its full price.

## 7. Chains and assets

- **Ethereum and Sepolia** have ck assets and the minter, and this design
  covers both.
- **A chain without a ck asset** (Gnosis, for instance) has no IC-side
  asset to deposit, so it is not covered. It would need a different
  bridge, or cycles at a rate, and stays out until a tenant needs it.
- **Bitcoin** has the same shape with ckBTC: a tenant's ckBTC balance pays
  for a hash written to Bitcoin (an `OP_RETURN`, signed through the IC's
  Bitcoin integration). That is a leg of its own.

## 8. Moving existing repos over

Nothing about the sender changes: deploys still come from the one EOA,
so contract addresses keep their `CREATE(EOA, nonce)` form and the
registry repo needs no exception. When this is installed, a repo whose
payer has no balance has its next deploy refused, with the reason given.
Before the release: list the live repos that have an EVM config, and
tell their owners.

The local e2e has no ckETH minter. It uses a local ICRC ledger in place
of ckETH, for deposits, reservations, settling and withdrawals, and
leaves the refill to unit tests and an operator run on Sepolia.

## 9. The legs

One PR each, in this order, then one release of the authority:

1. The asset ledger: ledger ids per chain, deposit, withdraw, balance
   query.
2. Reserve and settle on tenant deploys and the records they cause;
   `evm_gas` retired.
3. The float, in two: (a) the cost per transaction, the float's sizes
   and the reservation invariant, with `get_gas_float` for the watch;
   (b) the refill through the minter, the markup's account of what
   refills cost, and its credit back of a surplus.
4. The console and docs/TENANCY.md.

Later, each its own design pass: batched records (section 6), and
Bitcoin (section 7).

## 10. Decided, and still open

- **Decided 2026-11-22: the minter's withdrawal gas is paid by a small
  markup on each charge** (section 4), just enough that ic-git is not
  paying for it, with any surplus credited back on the IC side.
- **Decided 2026-11-23: the float is sized in transactions**: a target
  of 1000 at the measured cost per transaction, a floor of 500 and a
  margin of 10 over open holds, all operator-set integers (section 5).
  Counting transactions rather than ETH carries over to Bitcoin.
- **Decided in leg 1: a deposit is at least ten ledger fees** (section
  3).
