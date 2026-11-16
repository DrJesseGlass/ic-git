#!/usr/bin/env bash
# Temporal-trust check: is the canister still running the module hash that was
# last reproduced and recorded in verified.json -- and, once verified.json
# records a governor, is that governor still its only controller, itself
# with no controllers and running its recorded module (docs/GOVERNOR.md)?
# Once verified.json has a `git_canister` section (docs/CANISTER_SPLIT.md,
# step 15), the same three questions are asked of the git canister and
# its governor.
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

check "$canister" "$expected" "$commit" "$gov_id" "$gov_hash"
if [ -n "$git_id" ]; then
  echo
  check "$git_id" "$git_expected" "$git_commit" "$git_gov_id" "$git_gov_hash"
fi
exit "$status"
