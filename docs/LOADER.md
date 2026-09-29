# Publishing the loader, and how a user gets it

`loader/index.html` verifies a site against its registry record before it
runs it (README, "Verifying a site in the browser"). That leaves one
question: what verifies the loader? Not the loader -- a tampered copy would
report itself fine. The first check has to use tools the user already
trusts and we do not control:

- their operating system's hash command, and
- a block explorer reading the registry contract.

So the loader's hash is published on chain, by the same canister, contract
and record type as every site: the ic-git repo is pushed to the canister a
second time as repo `ic-git-loader`, its site root is `loader/`, and
`evm_registry_publish_site` writes

    ic-git-loader#site = (commit, sha256(loader/index.html), time)

The loader has no build step, so that hash is also the hash of the file in
git at that commit: anyone can recompute it from source.

Where the user downloads the file from does not matter -- the canister,
GitHub, a USB stick. The hash check decides.

## Operator steps (mainnet)

Run from a checkout of `main` with the loader change merged, as a dfx
identity that is an operator (a controller or on the admin allowlist).
Operators are charged nothing, so no balance is needed; the publish does
spend Sepolia gas from the canister's EOA
(`0x6ad88e005f96b18e8b1c76a9da85fa8efa2c848a`), which must hold a little
Sepolia ETH.

```sh
C=umobs-yiaaa-aaaab-agyrq-cai
GW=https://$C.raw.icp0.io
```

### 1. Create the repo and point its site at loader/ (first time only)

```sh
dfx canister --network ic call $C create_repo '("ic-git-loader")'
dfx canister --network ic call $C set_site '("ic-git-loader", "loader")'
```

### 2. Push main

A one-day token is enough; it expires on its own.

```sh
TOKEN=$(dfx canister --network ic call $C create_push_token '("ic-git-loader", opt (1 : nat32), null)' \
  | sed -n 's/.*Ok = "\([0-9a-f]*\)".*/\1/p')
: "${TOKEN:?create_push_token returned no token}"
git push "https://ic:$TOKEN@umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io/ic-git-loader.git" main
```

### 3. Check the canister serves the file in git

The two hashes must be equal before anything is published.

```sh
git show main:loader/index.html | shasum -a 256
curl -s "$GW/site/ic-git-loader/" | shasum -a 256
```

Run the `curl` from a terminal, not a browser: a TLS-inspecting proxy
(some VPN "threat protection" features) rewrites pages in the browser, and
the loader, correctly, then reports NOT VERIFIED.

### 4. Publish the record

```sh
dfx canister --network ic call $C evm_registry_publish_site '("ic-git-loader")'
```

It returns the transaction hash and nonce as soon as the transaction is
broadcast. The canister refuses to publish an entrypoint that loads
anything unpinned. The loader is self-contained, but it passes only on a
canister whose scanner skips `<script>` and `<style>` bodies as a browser
does: the loader's own JavaScript holds strings such as `"<base href=..."`
that an older scanner reads as tags, and refuses. Run these steps only
after the canister release that carries that scanner (v0.3.1 or later).

### 5. Confirm on chain

Step 4 returned before the transaction was mined, and `evm_receipt`
answers `Ok = null` until it is. Poll until the receipt arrives, and stop
if it reverted: the verifier run before then reports the new record as
absent or stale.

```sh
TX=0x...    # the tx hash step 4 returned
until R=$(dfx canister --network ic call $C evm_receipt "(\"$TX\")") &&
      ! echo "$R" | grep -q 'Ok = null'; do
  sleep 15
done
echo "$R"
echo "$R" | grep -q 'status = "success"' &&
  node tools/verify.mjs ic-git-loader index.html --record site    # VERIFIED
```

The verifier runs only on a successful receipt. A reverted receipt (or an
`Err`) means the record did not change: find the cause and publish again
(step 4). The transaction can also be looked up on
https://sepolia.etherscan.io.

### 6. Record the release

Add a row to "Releases" below and commit it, so the hash is also in
the repo's history and in GitHub, a third place a user can compare
against. Optionally attach `loader/index.html` to a GitHub release.

Republish (steps 2 to 6) whenever `loader/index.html` changes. Push to
`ic-git-loader` only as part of a release: a push that leaves the loader
unchanged keeps the hash, so the user's check still passes, but it moves
the served commit away from the recorded one, and `tools/verify.mjs`
check A (served commit == registry commit) then fails until the record is
republished. Between steps 2 and 4 of a release, the served file and the
record disagree; a user who downloads in that window sees a mismatch.

## Verifying the registry contract on Etherscan (once)

A user's easiest check is Etherscan's "Read Contract" tab, which appears
only once the contract's source is verified there. It is not yet. The
source is in the canister's `registry` repo:

```sh
git clone https://umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io/registry.git   # commit f3cd339
```

On https://sepolia.etherscan.io/address/0xa1362DAda583c56a395D305a8C7A458E0B62A209#code,
"Verify and Publish" with:

| Field | Value |
|---|---|
| Compiler type | Solidity (single file) |
| Compiler version | v0.8.28+commit.7893614a |
| License | MIT |
| Optimization | yes, 200 runs |
| EVM version | cancun |
| Constructor arguments | none |
| Source | `ProvenanceRegistry.sol` |

These are the settings in `compile.js` and `registry.metadata.json` in that
repo. Verification changes nothing on chain; it only lets the explorer
show the source and call `get` for the user.

## What a user does (once, about two minutes)

1. **Download** it, as `loader.html`, from anywhere:
   `curl -so loader.html https://umobs-yiaaa-aaaab-agyrq-cai.raw.icp0.io/site/ic-git-loader/`,
   a GitHub release, or `git show <commit>:loader/index.html > loader.html`
   from a clone. Use `curl`, not a browser visit: the browser runs the page
   on the canister's origin (README: never open the loader from the
   canister it checks) and saves it under another name.
2. **Hash it** with the operating system's own tool:
   - macOS, Linux: `shasum -a 256 loader.html`
   - Windows: `certutil -hashfile loader.html SHA256`
3. **Read the published hash** on a block explorer: registry
   `0xa1362DAda583c56a395D305a8C7A458E0B62A209` on Sepolia, "Read Contract",
   `get` with `ic-git-loader#site`. The second value, `bundleHash`, must
   equal step 2. For extra assurance, the contract's separate `owner`
   getter (not a value `get` returns) must read
   `0x6ad88e005f96b18e8b1c76a9da85fa8efa2c848a`, the canister's own
   address -- the only one the contract lets write a record.

   Without the explorer, the same read with `curl` (the call data is
   `get("ic-git-loader#site")`, ABI-encoded; `bundleHash` is the second
   64-hex-digit word of the result):

   ```sh
   curl -s https://ethereum-sepolia-rpc.publicnode.com -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xa1362DAda583c56a395D305a8C7A458E0B62A209","data":"0x693ec85e0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001269632d6769742d6c6f6164657223736974650000000000000000000000000000"},"latest"]}'
   ```

4. **Keep it and bookmark it**, e.g.
   `file:///Users/you/loader.html?repo=ic-vote&run=1`. From then on every
   visit is verified, and the copy never changes under you: a new loader
   release reaches you only when you download and check it again.

An auditor can go one step further: the record's `commit` names the source
revision, and `git show <commit>:loader/index.html | shasum -a 256`
reproduces the hash from a clone of the repository.

## What this does and does not establish

- It establishes that the file you run is the one the ic-git canister
  published. The contract accepts writes only from the canister's
  threshold-ECDSA address, so the record is the canister's statement --
  and so it is as trustworthy as whoever controls the canister. Reading
  the source is what establishes that the loader does what it says.
- The registry here is on Sepolia, a testnet. For a real election the
  loader's record, like the site records, belongs on a mainnet chain
  (docs/ATTESTATION.md names Gnosis as the cheap one).
- Every loader release is a new hash and a new check. That is the price of
  a verifier that cannot change without you; an extension moves the
  distribution to a store but keeps the same first check (publish the
  package hash, compare it with what the store installed).

## Releases

| Date | Commit | sha256 of loader/index.html | Registry tx |
|---|---|---|---|
| (not yet published) | | | |
