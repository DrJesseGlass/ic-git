#!/usr/bin/env bash
# Drive the governor (docs/GOVERNOR.md) from an approver's terminal.
#
#   tools/governor.sh status                       policy, open proposals, log
#   tools/governor.sh propose-upgrade <module.gz> [commit]
#                                                  propose installing the module
#                                                  into ic-git and stage it; prints
#                                                  the proposal id
#   tools/governor.sh vote <id> approve|reject     cast or replace your ballot
#   tools/governor.sh vote <id> object "<reason>"
#   tools/governor.sh execute <id>                 retry a reached proposal
#   tools/governor.sh withdraw <id>                drop your own proposal
#
# Policy and handover proposals are rarer and are made with dfx directly
# (docs/GOVERNOR.md has the commands).
#
# Environment: GOVERNOR (the governor's canister id; default: canister_ids.json
# "governor" on ic), APPROVER (dfx identity; default icgit-admin-encrypt),
# NETWORK (default https://icp-api.io). Each update call is signed by the
# approver's identity, so an encrypted identity asks for its passphrase per
# call: one to propose, one per 1 MiB of module, one per ballot.
set -euo pipefail
cd "$(dirname "$0")/.."

NETWORK=${NETWORK:-https://icp-api.io}
APPROVER=${APPROVER:-icgit-admin-encrypt}
DID=canisters/governor/governor.did
GOVERNOR=${GOVERNOR:-$(sed -n '/"governor"/,/}/s/.*"ic": *"\([^"]*\)".*/\1/p' canister_ids.json 2>/dev/null | head -1)}
[ -n "$GOVERNOR" ] || { echo "set GOVERNOR to the governor's canister id" >&2; exit 2; }

gov() { dfx canister --network "$NETWORK" --identity "$APPROVER" call "$GOVERNOR" --candid "$DID" "$@"; }
query() { dfx canister --network "$NETWORK" --identity anonymous call "$GOVERNOR" --candid "$DID" --query "$@"; }

cmd=${1:-}
[ -n "$cmd" ] || { sed -n '2,22p' "$0"; exit 2; }
shift
case "$cmd" in
  status)
    query info
    query proposals
    query log
    ;;
  propose-upgrade)
    module=${1:?module file (.wasm.gz from tools/reproducible-build.sh --docker)}
    commit=${2:-$(git rev-parse HEAD)}
    [ ${#commit} -eq 40 ] || { echo "commit must be the full 40-digit hash" >&2; exit 2; }
    sha=$(shasum -a 256 "$module" | cut -d' ' -f1)
    echo "proposing: commit $commit, module $sha ($(wc -c <"$module" | tr -d ' ') bytes)"
    out=$(gov propose "(variant { Upgrade = record { commit = \"$commit\"; module_sha256 = \"$sha\"; arg = blob \"\" } })")
    id=$(printf '%s' "$out" | sed -n 's/.*Ok = \([0-9_]*\) : nat64.*/\1/p' | tr -d _)
    [ -n "$id" ] || { echo "$out" >&2; exit 1; }
    echo "proposal $id; staging"
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    split -b 1048576 "$module" "$work/c."
    off=0
    for part in "$work"/c.*; do
      printf '(%s : nat64, %s : nat64, blob "%s")' "$id" "$off" "$(od -An -v -tx1 "$part" | tr -d ' \n' | sed 's/../\\&/g')" >"$part.arg"
      # A resent chunk is a no-op, so a failed call is simply retried.
      for try in 1 2 3; do
        out=$(gov stage --argument-file "$part.arg" 2>&1) && printf '%s' "$out" | grep -q 'Ok = record' && break
        echo "stage at offset $off failed (try $try): $out" >&2
        [ "$try" -lt 3 ] || exit 1
      done
      printf '%s\n' "$out"
      off=$((off + $(wc -c <"$part")))
    done
    echo "proposal $id is staged; vote with: tools/governor.sh vote $id approve"
    ;;
  vote)
    id=${1:?proposal id}
    case "${2:-}" in
      approve) gov vote "($id : nat64, variant { Approve }, null)" ;;
      reject) gov vote "($id : nat64, variant { Reject }, null)" ;;
      object)
        reason=${3:?an objection needs a reason}
        reason=${reason//\\/\\\\}
        gov vote "($id : nat64, variant { Object }, opt \"${reason//\"/\\\"}\")"
        ;;
      *) echo "approve, reject or object" >&2; exit 2 ;;
    esac
    ;;
  execute) gov execute "(${1:?proposal id} : nat64)" ;;
  withdraw) gov withdraw "(${1:?proposal id} : nat64)" ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
