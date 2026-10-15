#!/usr/bin/env bash
# Temporal-trust check: is the canister still running the module hash that was
# last reproduced and recorded in verified.json -- and, once verified.json
# records a governor, is that governor still its only controller, itself
# with no controllers and running its recorded module (docs/GOVERNOR.md)?
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
# otherwise so the script works on a bare macOS/Linux host.
if command -v jq >/dev/null; then
  canister=$(jq -r '.canister' "$record")
  expected=$(jq -r '.verified[-1].module_hash' "$record")
  commit=$(jq -r '.verified[-1].commit' "$record")
  gov_id=$(jq -r '.governor.id // empty' "$record")
  gov_hash=$(jq -r '.governor.module_hash // empty' "$record")
else
  canister=$(sed -n 's/.*"canister": *"\([^"]*\)".*/\1/p' "$record" | head -1)
  expected=$(sed -n 's/.*"module_hash": *"\([^"]*\)".*/\1/p' "$record" | tail -1)
  commit=$(sed -n 's/.*"commit": *"\([^"]*\)".*/\1/p' "$record" | tail -1)
  # The governor's entry sits ahead of the release list, so its fields are
  # the first of their names, as the release list's newest are the last.
  gov_id=$(sed -n 's/.*"id": *"\([^"]*\)".*/\1/p' "$record" | head -1)
  gov_hash=
  [ -z "$gov_id" ] || gov_hash=$(sed -n 's/.*"module_hash": *"\([^"]*\)".*/\1/p' "$record" | head -1)
fi
[ -n "$expected" ] && [ "$expected" != null ] || { echo "no module_hash in $record" >&2; exit 2; }

echo "canister            : $canister"
echo "recorded commit     : $commit"
echo "recorded module hash: $expected"

info_err=$(mktemp); trap 'rm -f "$info_err"' EXIT
# `dfx canister info` prints "Controllers: <p> <p>..." and "Module hash: 0x...".
info() { dfx canister --network ic --identity "${DFX_IDENTITY:-anonymous}" info "$1" 2>"$info_err"; }
# Sorted, space-separated; empty for none (awk, so an empty list is no error).
controllers_of() { printf '%s\n' "$1" | sed -n 's/^Controllers: *//p' | tr ' ' '\n' | awk 'NF' | sort | tr '\n' ' ' | sed 's/ $//'; }
hash_of() { printf '%s\n' "$1" | awk '/Module hash/{sub(/^0x/, "", $3); print $3}'; }
out=$(info "$canister") || out=""
onchain=$(hash_of "$out")
if [ -z "$onchain" ]; then
  echo "on-chain module hash: <unreadable>"
  echo "could not read the on-chain module hash -- this is NOT a mismatch." >&2
  sed 's/^/  dfx: /' "$info_err" >&2 || true
  exit 3
fi
echo "on-chain module hash: $onchain"
status=0
if [ "$onchain" = "$expected" ]; then
  echo "MATCH -- $canister still runs the recorded module (commit $commit)."
else
  echo "MISMATCH -- $canister was upgraded to a module nobody has recorded."
  echo "Reproduce the new module from its source and add a verified.json entry," 
  echo "or treat this as an unauthorized upgrade."
  status=1
fi

if [ -n "$gov_id" ]; then
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
  else
    gctl=$(controllers_of "$gout")
    echo "governor module hash: $ghash"
    echo "governor controllers: ${gctl:-<none>}"
    if [ "$ghash" = "$gov_hash" ] && [ -z "$gctl" ]; then
      echo "MATCH -- the governor runs its recorded module and nobody controls it."
    else
      echo "MISMATCH -- the governor should run $gov_hash with no controllers."
      status=1
    fi
  fi
fi
exit "$status"
