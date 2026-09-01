#!/usr/bin/env bash
# Temporal-trust check: is the canister still running the module hash that was
# last reproduced and recorded in verified.json?
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
else
  canister=$(sed -n 's/.*"canister": *"\([^"]*\)".*/\1/p' "$record" | head -1)
  expected=$(sed -n 's/.*"module_hash": *"\([^"]*\)".*/\1/p' "$record" | tail -1)
  commit=$(sed -n 's/.*"commit": *"\([^"]*\)".*/\1/p' "$record" | tail -1)
fi
[ -n "$expected" ] && [ "$expected" != null ] || { echo "no module_hash in $record" >&2; exit 2; }

echo "canister            : $canister"
echo "recorded commit     : $commit"
echo "recorded module hash: $expected"

info_err=$(mktemp); trap 'rm -f "$info_err"' EXIT
onchain=$(dfx canister --network ic --identity "${DFX_IDENTITY:-anonymous}" info "$canister" 2>"$info_err" \
          | awk '/Module hash/{sub(/^0x/, "", $3); print $3}') || onchain=""
if [ -z "$onchain" ]; then
  echo "on-chain module hash: <unreadable>"
  echo "could not read the on-chain module hash -- this is NOT a mismatch." >&2
  sed 's/^/  dfx: /' "$info_err" >&2 || true
  exit 3
fi
echo "on-chain module hash: $onchain"
if [ "$onchain" = "$expected" ]; then
  echo "MATCH -- $canister still runs the recorded module (commit $commit)."
else
  echo "MISMATCH -- $canister was upgraded to a module nobody has recorded."
  echo "Reproduce the new module from its source and add a verified.json entry," 
  echo "or treat this as an unauthorized upgrade."
  exit 1
fi
