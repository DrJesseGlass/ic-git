#!/usr/bin/env bash
# Temporal-trust check: is the canister still running the module hash that was
# last reproduced and recorded in verified.json -- and, once verified.json
# records a governor, is that governor still its only controller, itself
# with no controllers and running its recorded module (docs/GOVERNOR.md)?
# Once verified.json has a `git_canister` section (docs/CANISTER_SPLIT.md,
# step 15), the same three questions are asked of the git canister and
# its governor. A fourth, of each canister: does it hold cycles above a
# floor (CYCLES_FLOOR, 500 G by default)? Its controller is a governor, so
# only its own public `cycle_balance` can say, and an install fails for
# want of cycles nobody saw otherwise, as one did at the cut. A fifth, of
# the authority: does ic-git's EOA hold its float, the ETH it pays EVM
# transactions with (docs/EVM_GAS.md, section 5)? Its balance is read
# from the chain, the sizes from the canister.
#
#   tools/check-module-hash.sh            compare live hash vs the latest record
#
# The read goes through dfx, which verifies the IC certificate (subnet BLS
# signature, delegated from the NNS root key) before reporting the hash, so a
# boundary node cannot spoof it. What this does NOT do is replay-bound the
# certificate's timestamp -- that is the extension's job (docs/ATTESTATION.md,
# "Certified live module-hash read"). For a scheduled monitor whose only
# question is "did the hash change", dfx's verification is sufficient.
#
# Exit codes mirror tools/reproducible-build.sh: 0 match, 1 mismatch, 2 usage
# (no record), 3 the on-chain hash could not be read, which is NOT a mismatch.
set -euo pipefail
cd "$(dirname "$0")/.."

record=verified.json
[ -f "$record" ] || { echo "no $record; nothing has been verified yet." >&2; exit 2; }

# Latest entry = last element of .verified. jq if present, a sed fallback
# otherwise so the script works on a bare macOS/Linux host. The fallback
# finds fields by name and position alone, so once the file has a
# git_canister section, which repeats every name, it refuses rather than
# read the wrong entry.
git_id=
if command -v jq >/dev/null; then
  canister=$(jq -r '.canister' "$record")
  expected=$(jq -r '.verified[-1].module_hash' "$record")
  commit=$(jq -r '.verified[-1].commit' "$record")
  gov_id=$(jq -r '.governor.id // empty' "$record")
  gov_hash=$(jq -r '.governor.module_hash // empty' "$record")
  git_id=$(jq -r '.git_canister.id // empty' "$record")
  git_expected=$(jq -r '.git_canister.verified[-1].module_hash // empty' "$record")
  git_commit=$(jq -r '.git_canister.verified[-1].commit // empty' "$record")
  git_gov_id=$(jq -r '.git_canister.governor.id // empty' "$record")
  git_gov_hash=$(jq -r '.git_canister.governor.module_hash // empty' "$record")
else
  canister=$(sed -n 's/.*"canister": *"\([^"]*\)".*/\1/p' "$record" | head -1)
  expected=$(sed -n 's/.*"module_hash": *"\([^"]*\)".*/\1/p' "$record" | tail -1)
  commit=$(sed -n 's/.*"commit": *"\([^"]*\)".*/\1/p' "$record" | tail -1)
  # The governor's entry sits ahead of the release list, so its fields are
  # the first of their names, as the release list's newest are the last.
  gov_id=$(sed -n 's/.*"id": *"\([^"]*\)".*/\1/p' "$record" | head -1)
  gov_hash=
  [ -z "$gov_id" ] || gov_hash=$(sed -n 's/.*"module_hash": *"\([^"]*\)".*/\1/p' "$record" | head -1)
  if grep -q '"git_canister"' "$record"; then
    echo "$record has a git_canister section, which this script reads only with jq; install jq." >&2
    exit 2
  fi
fi
[ -n "$expected" ] && [ "$expected" != null ] || { echo "no module_hash in $record" >&2; exit 2; }
if [ -n "$git_id" ]; then
  [ -n "$git_expected" ] && [ "$git_expected" != null ] || { echo "git_canister in $record has no verified entry" >&2; exit 2; }
fi

info_err=$(mktemp); trap 'rm -f "$info_err"' EXIT
# `dfx canister info` prints "Controllers: <p> <p>..." and "Module hash: 0x...".
info() { dfx canister --network ic --identity "${DFX_IDENTITY:-anonymous}" info "$1" 2>"$info_err"; }
# Sorted, space-separated; empty for none (awk, so an empty list is no error).
controllers_of() { printf '%s\n' "$1" | sed -n 's/^Controllers: *//p' | tr ' ' '\n' | awk 'NF' | sort | tr '\n' ' ' | sed 's/ $//'; }
hash_of() { printf '%s\n' "$1" | awk '/Module hash/{sub(/^0x/, "", $3); print $3}'; }

status=0
# check <canister> <expected hash> <commit> [<governor id> <governor hash>]:
# the canister runs the recorded module; with a governor, it is controlled
# by that governor alone, which runs its own recorded module and has no
# controllers. Folds the worst outcome so far into $status.
check() {
  local canister=$1 expected=$2 commit=$3 gov_id=${4:-} gov_hash=${5:-} out onchain ctl gout ghash gctl
  echo "canister            : $canister"
  echo "recorded commit     : $commit"
  echo "recorded module hash: $expected"
  out=$(info "$canister") || out=""
  onchain=$(hash_of "$out")
  if [ -z "$onchain" ]; then
    echo "on-chain module hash: <unreadable>"
    echo "could not read the on-chain module hash -- this is NOT a mismatch." >&2
    sed 's/^/  dfx: /' "$info_err" >&2 || true
    [ "$status" = 1 ] || status=3
    return 0
  fi
  echo "on-chain module hash: $onchain"
  if [ "$onchain" = "$expected" ]; then
    echo "MATCH -- $canister still runs the recorded module (commit $commit)."
  else
    echo "MISMATCH -- $canister was upgraded to a module nobody has recorded."
    echo "Reproduce the new module from its source and add a verified.json entry,"
    echo "or treat this as an unauthorized upgrade."
    status=1
  fi
  [ -n "$gov_id" ] || return 0
  ctl=$(controllers_of "$out")
  echo "controllers         : ${ctl:-<none>}"
  if [ "$ctl" = "$gov_id" ]; then
    echo "MATCH -- $canister is controlled by its recorded governor alone."
  else
    echo "MISMATCH -- $canister should be controlled by the governor $gov_id alone."
    status=1
  fi
  gout=$(info "$gov_id") || gout=""
  ghash=$(hash_of "$gout")
  if [ -z "$ghash" ]; then
    echo "governor            : <unreadable> -- this is NOT a mismatch." >&2
    sed 's/^/  dfx: /' "$info_err" >&2 || true
    [ "$status" = 1 ] || status=3
    return 0
  fi
  gctl=$(controllers_of "$gout")
  echo "governor module hash: $ghash"
  echo "governor controllers: ${gctl:-<none>}"
  if [ "$ghash" = "$gov_hash" ] && [ -z "$gctl" ]; then
    echo "MATCH -- the governor runs its recorded module and nobody controls it."
  else
    echo "MISMATCH -- the governor should run $gov_hash with no controllers."
    status=1
  fi
}

# cycles <canister> <did>: the canister's own cycle_balance query against
# CYCLES_FLOOR. A module without the query is noted, not failed (the
# authority gained it after the cut); a read that fails otherwise is
# status 3, not a mismatch; under the floor is status 1, so the watch
# notifies while there is still time to deposit.
CYCLES_FLOOR=${CYCLES_FLOOR:-500000000000}
cycles() {
  local canister=$1 did=$2 out bal
  out=$(dfx canister --network ic --identity "${DFX_IDENTITY:-anonymous}" call "$canister" cycle_balance '()' --candid "$did" --query 2>"$info_err") || out=""
  bal=$(printf '%s\n' "$out" | tr -d '_ ' | sed -n 's/^(\([0-9]*\):nat64)$/\1/p')
  if [ -z "$bal" ]; then
    if grep -q "no query method" "$info_err"; then
      echo "cycles              : not reported by the module it runs (no cycle_balance query)"
    else
      echo "cycles              : <unreadable> -- this is NOT a mismatch." >&2
      sed 's/^/  dfx: /' "$info_err" >&2 || true
      [ "$status" = 1 ] || status=3
    fi
    return 0
  fi
  echo "cycles              : $bal (floor $CYCLES_FLOOR)"
  if [ "$bal" -lt "$CYCLES_FLOOR" ]; then
    echo "LOW -- $canister holds fewer cycles than the floor; deposit some:"
    echo "  dfx canister --network ic deposit-cycles <amount> $canister"
    status=1
  else
    echo "OK -- $canister holds cycles above the floor."
  fi
}

# Exact arithmetic on non-negative integers of any size, as decimal
# strings: a balance in wei passes what the shell's 64 bits hold, and the
# watch takes no floating point.
dec_norm() { local a=${1#"${1%%[!0]*}"}; echo "${a:-0}"; }
dec_lt() { local a b LC_ALL=C; a=$(dec_norm "$1"); b=$(dec_norm "$2"); [ ${#a} -ne ${#b} ] && { [ ${#a} -lt ${#b} ]; return; }; [[ "$a" < "$b" ]]; }
dec_add() {
  local a=$1 b=$2 r= c=0 i s
  while [ ${#a} -lt ${#b} ]; do a=0$a; done
  while [ ${#b} -lt ${#a} ]; do b=0$b; done
  for ((i = ${#a} - 1; i >= 0; i--)); do s=$((${a:i:1} + ${b:i:1} + c)); r=$((s % 10))$r; c=$((s / 10)); done
  dec_norm "$c$r"
}
dec_mul16() {
  local a=$1 r= c=0 i s
  for ((i = ${#a} - 1; i >= 0; i--)); do s=$((${a:i:1} * 16 + c)); r=$((s % 10))$r; c=$((s / 10)); done
  dec_norm "$c$r"
}
hex_dec() { local h=${1#0x} r=0 i; for ((i = 0; i < ${#h}; i++)); do r=$(dec_add "$(dec_mul16 "$r")" $((16#${h:i:1}))); done; echo "$r"; }
# wei as ETH: the point put in 18 digits from the right, trailing zeros trimmed.
eth() { local w f; w=$(dec_norm "$1"); while [ ${#w} -lt 19 ]; do w=0$w; done; f=$(printf '%s' "${w: -18}" | sed 's/0*$//'); echo "$(dec_norm "${w:0:${#w}-18}")${f:+.$f} ETH"; }
# nat_field <candid text> <name>: the value of a record field `name = 1_000 : nat`.
nat_field() { printf '%s\n' "$1" | sed -n "s/.*[^a-z_]$2 = \([0-9_]*\) : nat.*/\1/p" | tr -d _; }

# rpc <url> <method> <params>: a JSON-RPC call's hex result, empty when there is none.
rpc() { curl -fsS --max-time 20 -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"'"$2"'","params":'"$3"'}' "$1" 2>"$info_err" | sed -n 's/.*"result" *: *"\(0x[0-9a-fA-F]*\)".*/\1/p'; }
# The chain's public RPC, for a canister that names none of its own: it
# then sends through the EVM RPC canister's presets, which only it reaches.
default_rpc() { case $1 in 1) echo https://ethereum-rpc.publicnode.com ;; 11155111) echo https://ethereum-sepolia-rpc.publicnode.com ;; esac; }

# gas_float <canister> <did>: ic-git's float (docs/EVM_GAS.md, section 5),
# the ETH its EOA holds to pay for EVM transactions before tenants pay it
# back. The canister's get_gas_float names the floor, the target, the
# margin and what open transactions hold; its own balance read is as old
# as the last send or refresh, and a refill does not renew it, so the
# balance is read here, from the chain, at the address and on the chain
# of the canister's last read. The RPC URL is the canister's own
# (evm_get_config), else the chain's public one; GAS_RPC_URL overrides
# both, and an endpoint on another chain is refused. Like the canister at
# a send, it reads the finalized block, whose balance has not yet paid for
# a transaction mined since, and whose hold is still counted. Under the
# floor is status 1: the hourly refill should have brought it back from
# what tenants paid (get_gas_refills says why not), or the operators fund
# it. Under the open holds and the margin, tenants' sends are refused,
# also status 1. A module without the query, a canister with no chain,
# and a balance never read are noted, not failed; a read that fails
# otherwise is status 3, not a low balance. Only the URL's host is
# printed: an override may carry a provider key.
gas_float() {
  local canister=$1 did=$2 out cfg addr chain url host cid hex wei floor target margin held need
  out=$(dfx canister --network ic --identity "${DFX_IDENTITY:-anonymous}" call "$canister" get_gas_float '()' --candid "$did" --query 2>"$info_err") || out=""
  if [ -z "$out" ]; then
    if grep -q "no query method" "$info_err"; then
      echo "gas float           : not reported by the module it runs (no get_gas_float query)"
    else
      echo "gas float           : <unreadable> -- this is NOT a low balance." >&2
      sed 's/^/  dfx: /' "$info_err" >&2 || true
      [ "$status" = 1 ] || status=3
    fi
    return 0
  fi
  case "$out" in *'Err = '*)
    echo "gas float           : none ($(printf '%s\n' "$out" | sed -n 's/.*Err = "\(.*\)".*/\1/p'))"
    return 0 ;;
  esac
  addr=$(printf '%s\n' "$out" | sed -n 's/.*address = "\(0x[0-9a-fA-F]\{40\}\)".*/\1/p')
  chain=$(nat_field "$out" chain_id)
  floor=$(nat_field "$out" floor) target=$(nat_field "$out" target) margin=$(nat_field "$out" margin) held=$(nat_field "$out" held)
  if [ -z "$addr" ] || [ -z "$chain" ]; then
    echo "gas float           : not checked -- the canister has not read the EOA's balance yet, so"
    echo "                      its address is not known here; an operator's gas_float_refresh reads it"
    return 0
  fi
  if [ -z "$floor" ] || [ -z "$target" ] || [ -z "$margin" ] || [ -z "$held" ]; then
    echo "gas float           : <unreadable> -- get_gas_float's answer lacks a size. This is NOT a low balance." >&2
    [ "$status" = 1 ] || status=3
    return 0
  fi
  url=${GAS_RPC_URL:-}
  if [ -z "$url" ]; then
    cfg=$(dfx canister --network ic --identity "${DFX_IDENTITY:-anonymous}" call "$canister" evm_get_config '()' --candid "$did" --query 2>"$info_err") || cfg=""
    url=$(printf '%s\n' "$cfg" | tr -d '\n' | sed -n 's/.*rpc_urls = vec { *"\([^"]*\)".*/\1/p')
    [ -n "$url" ] || url=$(default_rpc "$chain")
  fi
  if [ -z "$url" ]; then
    echo "gas float           : <unread> -- chain $chain has no RPC URL to read the EOA's balance from;" >&2
    echo "  set GAS_RPC_URL. This is NOT a low balance." >&2
    [ "$status" = 1 ] || status=3
    return 0
  fi
  host=${url#*://} host=${host%%/*} host=${host##*@}
  cid=$(rpc "$url" eth_chainId '[]') || cid=""
  if [ -n "$cid" ] && [ "$(hex_dec "$cid")" != "$chain" ]; then
    echo "gas float           : <unread> -- the RPC at $host is on chain $(hex_dec "$cid"), not the float's chain $chain." >&2
    echo "  This is NOT a low balance." >&2
    [ "$status" = 1 ] || status=3
    return 0
  fi
  hex=
  [ -z "$cid" ] || hex=$(rpc "$url" eth_getBalance '["'"$addr"'","finalized"]') || hex=""
  if [ -z "$hex" ]; then
    echo "gas float           : <unreadable> -- the RPC at $host did not answer. This is NOT a low balance." >&2
    sed 's/^/  curl: /' "$info_err" >&2 || true
    [ "$status" = 1 ] || status=3
    return 0
  fi
  wei=$(hex_dec "$hex")
  need=$(dec_add "$held" "$margin")
  echo "gas float           : EOA $addr holds $(eth "$wei") ($wei wei, finalized, chain $chain at $host)"
  echo "                      floor $(eth "$floor"), target $(eth "$target"); open holds $(eth "$held") + margin $(eth "$margin")"
  if dec_lt "$wei" "$floor"; then
    echo "LOW -- the EOA is under its floor; the hourly refill should bring it back to the"
    echo "  target from what tenants paid (get_gas_refills says why it has not), or fund it."
    status=1
  elif dec_lt "$wei" "$need"; then
    echo "LOW -- the EOA cannot cover its open holds and the margin; tenants' EVM sends are"
    echo "  refused until it is refilled or funded."
    status=1
  else
    echo "OK -- the EOA holds its floor and covers every open hold and the margin."
  fi
}

check "$canister" "$expected" "$commit" "$gov_id" "$gov_hash"
cycles "$canister" canisters/authority/authority.did
gas_float "$canister" canisters/authority/authority.did
if [ -n "$git_id" ]; then
  echo
  check "$git_id" "$git_expected" "$git_commit" "$git_gov_id" "$git_gov_hash"
  cycles "$git_id" canisters/git/git.did
fi
exit "$status"
