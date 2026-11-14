#!/usr/bin/env bash
# End-to-end pass on a throwaway local replica, run before a mainnet upgrade.
#
# Starts its own network (--system-canisters: the ICP ledger and the CMC at
# their mainnet ids) from a temporary project directory on its own port, so
# a replica you already run is not touched. Deploys the current checkout's
# canister and drives it the way users do: dfx calls, and real git over HTTP
# through the local gateway. Every check prints PASS or FAIL; the script
# exits non-zero if any failed.
#
#   tools/e2e-local.sh                 # the whole pass, on the combined canister
#   E2E_SPLIT=1 tools/e2e-local.sh     # the same flows across the two canisters
#                                      # (docs/CANISTER_SPLIT.md, phase 3 step 12c)
#   KEEP=1 tools/e2e-local.sh          # leave the network running after
#   E2E_PORT=4960 tools/e2e-local.sh   # another port (default 4950)
#   NAMES_REPO=../ic-name-service ...  # where ic-name-service is (optional)
#   BASE_REF=v0.3.8 tools/e2e-local.sh # the release to upgrade from (default:
#                                      # the newest tag; v0.3.8 or later);
#                                      # BASE_REF=none skips
#
# Identities: e2e-local (controller and operator) and e2e-tenant (a paying,
# non-operator user), plaintext and local-only, created if missing. Never
# use them on mainnet.
#
# Covered: ICP deposit through the CMC; the push-certificate nonce; signed
# pushes (bound token unsigned, wrong key, unbound before and after
# require_signed_push, GPG-signed with an unbound token); token listing and
# revoke by id; the operator guard on the EVM, Solana and seeding calls;
# the approval-gated site (hidden until approved, rollback on a withdrawn
# approval); an approval-gated deploy of a .wat app into the
# repo's app canister, its certified module hash, and the ic-name-service
# announce; an upgrade in place; an upgrade from the previous release
# (BASE_REF) over state that release wrote through its own API -- a
# signing-required repo with a key-bound token and a gated site behind its
# tip, checking the state carries over unchanged and each rule still holds,
# and membership, votes and a name that only maps to a label; the governor's whole life against a
# second ic-git (docs/GOVERNOR.md: made immutable, an upgrade staged and
# voted, the policy grown, an objection, a withdrawal, the handover); the
# freeze and the copy (docs/CANISTER_SPLIT.md, step 13: the git side
# frozen, its writes refused naming the cut, a git canister pulling every
# record in pages, and both digests agreeing); the console's query-backed
# reads through the page's own code, and the /api reads.
#
# E2E_SPLIT=1 runs the user flows against the authority and git canisters
# instead: the git canister is governed before the authority names it (the
# setter's rule), each side refuses the other's messages from anyone else,
# a job larger than a message crosses in chunks, deploy_now's job comes back
# staged, and each canister is upgraded in place (the git canister by its
# governor). The freeze and the copy, the upgrade from BASE_REF and the
# governor's own section run only on the combined canister: the first two
# are the cut's rehearsal, the third the governor's, and none changes
# with the split.
#
# Not covered: wallet writes (OISY signs mainnet only), the EVM leg (no EVM
# RPC locally), ICP recovery paths (lost reply, refund), expiry by time.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${E2E_PORT:-4950}
KEEP=${KEEP:-0}
SPLIT=${E2E_SPLIT:-0}
# The release a mainnet upgrade starts from: by default the newest tag. Set
# it to what mainnet actually runs (tools/check-module-hash.sh says whether
# that is a recorded release).
BASE_REF=${BASE_REF-$(git -C "$(dirname "$0")/.." describe --tags --abbrev=0 2>/dev/null || true)}
NAMES_REPO=${NAMES_REPO:-$ROOT/../ic-name-service}
OP=e2e-local
TEN=e2e-tenant
# Two more voters, for the objections section: 1 of 3 lets one objection be
# outweighed by one more approval.
V1=e2e-voter1
V2=e2e-voter2
ICP_LEDGER=ryjl3-tyaaa-aaaaa-aaaba-cai
CMC=rkp4c-7iaaa-aaaaa-aaaca-cai
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ic-git-e2e.XXXXXX")

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf 'FAIL  %s\n      got: %s\n' "$1" "$(printf '%s' "$2" | tr '\n' ' ' | cut -c1-300)"; }
# expect NAME TEXT PATTERN: pass if TEXT contains PATTERN (grep -E).
expect() { if printf '%s' "$2" | grep -qE -- "$3"; then pass "$1"; else fail "$1" "$2"; fi; }
# refuse NAME TEXT PATTERN: pass if TEXT does not contain PATTERN.
refuse() { if printf '%s' "$2" | grep -qE -- "$3"; then fail "$1" "$2"; else pass "$1"; fi; }
section() { printf '\n== %s\n' "$1"; }
flat() { printf '%s' "$1" | tr '\n' ' '; }

cleanup() {
  if [ "$KEEP" = 1 ]; then
    printf '\nnetwork left running on 127.0.0.1:%s (project %s); stop it with: (cd %s && dfx stop)\n' "$PORT" "$WORK" "$WORK"
  else
    (cd "$WORK" && dfx stop >/dev/null 2>&1) || true
  fi
  if [ -d "$WORK/base-src" ]; then
    git -C "$ROOT" worktree remove --force "$WORK/base-src" >/dev/null 2>&1 || true
  fi
  [ "$KEEP" = 1 ] || rm -rf "$WORK"
}
trap cleanup EXIT

for tool in dfx git ssh-keygen curl cargo; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 2; }
done
# Read the list first: grep -q closing the pipe early makes dfx abort.
IDS=$(dfx identity list 2>/dev/null)
for id in "$OP" "$TEN" "$V1" "$V2"; do
  printf '%s\n' "$IDS" | grep -qx "$id" || dfx identity new "$id" --storage-mode plaintext >/dev/null 2>&1
done

# dfx call through the throwaway project, without dfx's candid-metadata
# warnings. Never fails: the checks judge the output.
call() {
  local who=$1; shift
  (cd "$WORK" && dfx canister call "$@" --identity "$who" 2>&1) \
    | grep -v -e '^WARNING' -e '"metadata"' -e '^   {$' -e '"name": "candid:service"' -e '^   }$' -e '^]$' || true
}
ok_text() { sed -n 's/.*Ok = "\([^"]*\)".*/\1/p'; }
# ic WHO METHOD ARGS...: the call, to whichever canister has the method.
# One canister has them all; with E2E_SPLIT the git canister has the
# methods of GIT_METHODS (read from the two candid files once they are
# known, below) and the authority the rest (docs/CANISTER_SPLIT.md, step
# 12, "Where the endpoints land").
GIT_METHODS=
ic() {
  local who=$1 m=$2; shift 2
  if [ "$SPLIT" = 1 ] && [[ "$GIT_METHODS" != *" $m "* ]]; then
    call "$who" authority "$m" "$@"
  else
    call "$who" git "$m" "$@"
  fi
}
# The method names a candid service declares, one per line.
did_methods() { awk '/^service/ { s = 1 } s' "$1" | sed -n 's/^  \([a-z_0-9]*\) *:.*/\1/p' | sort; }

section "build"
(cd "$ROOT" && cargo build -q --target wasm32-unknown-unknown --release -p combined_canister -p authority_canister -p git_canister -p governor_canister)
# The combined canister (umobs until the cut), and the two it splits into.
GIT_WASM=$ROOT/target/wasm32-unknown-unknown/release/combined_canister.wasm
DID=$ROOT/canisters/combined/combined.did
AUTH_WASM=$ROOT/target/wasm32-unknown-unknown/release/authority_canister.wasm
AUTH_DID=$ROOT/canisters/authority/authority.did
GITC_WASM=$ROOT/target/wasm32-unknown-unknown/release/git_canister.wasm
GITC_DID=$ROOT/canisters/git/git.did
# What only the git canister answers: the rest a call for either reaches
# on the authority (create_repo, the allowlist, the ICRC methods).
GIT_METHODS=" $(comm -23 <(did_methods "$GITC_DID") <(did_methods "$AUTH_DID") | tr '\n' ' ')"
GOV_WASM=$ROOT/target/wasm32-unknown-unknown/release/governor_canister.wasm
NAMES_WASM=
if [ -d "$NAMES_REPO/canisters/names" ]; then
  (cd "$NAMES_REPO" && cargo build -q --target wasm32-unknown-unknown --release -p name_canister)
  NAMES_WASM=$NAMES_REPO/target/wasm32-unknown-unknown/release/name_canister.wasm
fi
echo "ic-git wasm: $GIT_WASM${NAMES_WASM:+; ic-name-service wasm: $NAMES_WASM}"
BASE_WASM=
if [ "$SPLIT" = 1 ]; then
  echo "two canisters: $AUTH_WASM and $GITC_WASM"
elif [ -n "$BASE_REF" ] && [ "$BASE_REF" != none ]; then
  # Built from a worktree of the release, into its own target dir so later
  # runs reuse it.
  BASE_SRC=$WORK/base-src
  # Releases before v0.3.8 left state (bare-name tokens, unrecorded gated
  # sites, unindexed labels, repos the authority has no record of, empty
  # mirrors) that only one-time upgrade paths converted; mainnet has run
  # them and this build no longer carries them. v0.3.8 is the first
  # release with the authority's own repo records (phase 3, step 7).
  if ! git -C "$ROOT" merge-base --is-ancestor e55d0bc "$BASE_REF"; then
    echo "BASE_REF $BASE_REF is older than v0.3.8; upgrades from it are no longer supported" >&2
    exit 1
  fi
  git -C "$ROOT" worktree add -q --detach "$BASE_SRC" "$BASE_REF"
  # Releases before step 12 of the canister split call the canister
  # git_canister, in canisters/git.
  if [ -d "$BASE_SRC/canisters/combined" ]; then
    BASE_PKG=combined_canister BASE_DID=$BASE_SRC/canisters/combined/combined.did
  else
    BASE_PKG=git_canister BASE_DID=$BASE_SRC/canisters/git/git.did
  fi
  (cd "$BASE_SRC" && CARGO_TARGET_DIR="$ROOT/target/e2e-base" cargo build -q --target wasm32-unknown-unknown --release -p "$BASE_PKG")
  BASE_WASM=$ROOT/target/e2e-base/wasm32-unknown-unknown/release/$BASE_PKG.wasm
  echo "base release $BASE_REF: $BASE_WASM"
fi

section "network"
NAMES_ENTRY=
if [ -n "$NAMES_WASM" ]; then
  NAMES_ENTRY=",
    \"names\": { \"type\": \"custom\", \"wasm\": \"$NAMES_WASM\", \"candid\": \"$NAMES_REPO/canisters/names/names.did\", \"build\": [] }"
fi
# With E2E_SPLIT, "git" is the git canister and "authority" the authority;
# "gitgov" is the git canister's governor (the authority is left to the
# operator, as "git" is on the combined run). Otherwise "git" is the
# combined canister and the rest go unused.
if [ "$SPLIT" = 1 ]; then
  GIT_ENTRY="\"git\": { \"type\": \"custom\", \"wasm\": \"$GITC_WASM\", \"candid\": \"$GITC_DID\", \"build\": [] }"
else
  GIT_ENTRY="\"git\": { \"type\": \"custom\", \"wasm\": \"$GIT_WASM\", \"candid\": \"$DID\", \"build\": [] }"
fi
cat > "$WORK/dfx.json" <<EOF
{
  "version": 1,
  "canisters": {
    $GIT_ENTRY,
    "authority": { "type": "custom", "wasm": "$AUTH_WASM", "candid": "$AUTH_DID", "build": [] },
    "gitgov": { "type": "custom", "wasm": "$GOV_WASM", "candid": "$ROOT/canisters/governor/governor.did", "build": [] },
    "base": { "type": "custom", "wasm": "$GIT_WASM", "candid": "$DID", "build": [] },
    "ruled": { "type": "custom", "wasm": "$GIT_WASM", "candid": "$DID", "build": [] },
    "copy": { "type": "custom", "wasm": "$GITC_WASM", "candid": "$GITC_DID", "build": [] },
    "governor": { "type": "custom", "wasm": "$GOV_WASM", "candid": "$ROOT/canisters/governor/governor.did", "build": [] }$NAMES_ENTRY
  },
  "networks": { "local": { "bind": "127.0.0.1:$PORT", "type": "ephemeral" } }
}
EOF
(cd "$WORK" && dfx start --background --clean --system-canisters >"$WORK/replica.log" 2>&1)
T=$(dfx identity get-principal --identity "$TEN")
OPP=$(dfx identity get-principal --identity "$OP")
# The dfx name of the canister that holds accounts and repos: what the
# controller checks below are made against.
AUTH=git
if [ "$SPLIT" = 1 ]; then
  AUTH=authority
  # More than the git canister: the funding section below raises the
  # floor past what the git canister holds, and the authority never sends
  # what would leave itself under the floor.
  (cd "$WORK" && dfx canister create authority --identity "$OP" --no-wallet --with-cycles 400000000000000 >/dev/null 2>&1)
  (cd "$WORK" && dfx canister install authority --identity "$OP" --wasm "$AUTH_WASM" >/dev/null 2>&1)
  A=$(cd "$WORK" && dfx canister id authority)
  (cd "$WORK" && dfx canister create git --identity "$OP" --no-wallet --with-cycles 50000000000000 >/dev/null 2>&1)
  (cd "$WORK" && dfx canister install git --identity "$OP" --wasm "$GITC_WASM" --argument "(record { authority = principal \"$A\" })" >/dev/null 2>&1)
  G=$(cd "$WORK" && dfx canister id git)
  section "the git canister is named once it is governed"
  # docs/CANISTER_SPLIT.md, step 12: the setter checks, through canister_info,
  # that one canister alone controls the git canister and that it has no
  # controllers itself -- a governor. Until then nothing crosses.
  expect "the authority is not its own git canister" "$(call "$OP" authority set_git_canister "(principal \"$A\")")" 'its own git canister'
  expect "a git canister controlled by a person is refused" "$(call "$OP" authority set_git_canister "(principal \"$G\")")" 'controller|canister_info'
  expect "  ...and nothing is named" "$(call "$OP" authority get_git_canister --query)" '^\(null\)$'
  expect "  ...so a repo cannot be created yet" "$(call "$OP" authority create_repo '("too-early")')" 'not set|not delivered'
  (cd "$WORK" && dfx canister create gitgov --identity "$OP" --no-wallet --with-cycles 20000000000000 >/dev/null 2>&1)
  (cd "$WORK" && dfx canister install gitgov --identity "$OP" --wasm "$GOV_WASM" \
    --argument "(record { target = principal \"$G\"; approvers = vec { principal \"$OPP\" }; threshold = 1 : nat32 })" >/dev/null 2>&1)
  GITGOV=$(cd "$WORK" && dfx canister id gitgov)
  (cd "$WORK" && dfx canister update-settings gitgov --remove-controller "$OPP" --yes --identity "$OP" >/dev/null 2>&1)
  (cd "$WORK" && dfx canister update-settings git --set-controller "$GITGOV" --yes --identity "$OP" >/dev/null 2>&1)
  expect "governed by a governor with no controllers: named" "$(call "$OP" authority set_git_canister "(principal \"$G\")")" 'Ok'
  expect "  ...the same again is fine" "$(call "$OP" authority set_git_canister "(principal \"$G\")")" 'Ok'
  expect "  ...another is refused: named once" "$(call "$OP" authority set_git_canister "(principal \"$A\")")" 'named once'
  expect "  ...a tenant cannot name it" "$(call "$TEN" authority set_git_canister "(principal \"$G\")")" 'is not an operator'
  expect "the authority knows its git canister" "$(call "$OP" authority get_git_canister --query)" "principal \"$G\""
  expect "the git canister knows its authority" "$(ic "$OP" get_authority --query)" "principal \"$A\""
  # Called on the git canister by name: the router would send these to the
  # authority, which has create_repo for people and no set_approved.
  expect "the authority's messages are refused from anyone else" "$(call "$OP" git set_approved '(record { repo = "x"; seq = 1 : nat64; approved = null; retry = null })')" 'only the authority may call this'
  expect "  ...create_repo on the git canister too" "$(call "$OP" git create_repo '(record { name = "x" })')" 'only the authority may call this'
  expect "the git canister's messages likewise" "$(call "$OP" authority charge_push '(record { repo = "x"; bytes = 1 : nat64 })')" 'only the git canister may call this'
  expect "  ...submit_job too" "$(call "$OP" authority submit_job '(record { seq = 1 : nat64; repo = "x"; commit = "0"; staged = 0 : nat32; tail = blob "" })')" 'only the git canister may call this'
  expect "the git host has no feed" "$(curl -s -o /dev/null -w '%{http_code}' "http://$G.raw.localhost:$PORT/feed")" '^404$'
  # The git canister's record (step 12d): its controller asks it, it asks
  # the authority, and nobody else may ask either.
  expect "only a controller may ask the git canister for its record" "$(call "$OP" git registry_publish_canister "(\"$(printf 'a%.0s' $(seq 40))\", \"$(printf 'b%.0s' $(seq 64))\")")" 'only a controller'
  expect "  ...and only the git canister may ask the authority to publish it" "$(call "$OP" authority publish_git_record "(record { commit = \"$(printf 'a%.0s' $(seq 40))\"; module_sha256 = \"$(printf 'b%.0s' $(seq 64))\" })")" 'only the git canister may call this'
  expect "the git canister says what it holds" "$(call "$OP" git cycle_balance --query)" '^\([0-9_]+ : nat64\)$'
else
  (cd "$WORK" && dfx canister create git --identity "$OP" --no-wallet --with-cycles 50000000000000 >/dev/null 2>&1)
  (cd "$WORK" && dfx canister install git --identity "$OP" --wasm "$GIT_WASM" >/dev/null 2>&1)
  G=$(cd "$WORK" && dfx canister id git)
  A=$G
fi
# HTTP: git, /site/ and the git half of /api on the git canister; the
# authority's half of /api and the feeds on the authority.
HOST="$G.raw.localhost:$PORT"
AHOST="$A.raw.localhost:$PORT"
echo "ic-git $G on 127.0.0.1:$PORT${A:+; authority $A}; tenant $T"

section "ICP deposit"
call anonymous "$ICP_LEDGER" icrc1_transfer "(record { to = record { owner = principal \"$T\"; subaccount = null }; amount = 10_000_000_000 : nat; fee = null; memo = null; from_subaccount = null; created_at_time = null })" >/dev/null
call "$TEN" "$ICP_LEDGER" icrc2_approve "(record { spender = record { owner = principal \"$A\"; subaccount = null }; amount = 100_010_000 : nat; expected_allowance = null; expires_at = null; fee = null; memo = null; from_subaccount = null; created_at_time = null })" >/dev/null
RATE=$(call "$OP" "$CMC" get_icp_xdr_conversion_rate '()' --query | sed -n 's/.*xdr_permyriad_per_icp = \([0-9_]*\).*/\1/p' | tr -d _)
OUT=$(ic "$TEN" deposit_from_icp '(100_000_000 : nat64)')
expect "deposit_from_icp credits exactly the CMC's cycles for 1 ICP" "$(echo "$OUT" | tr -d _)" "Ok = $((RATE * 100000000)) "
expect "nothing left pending" "$(ic "$TEN" pending_icp_deposits)" '^\(vec \{\}\)$'

section "push certificates"
KEY=$WORK/key
ssh-keygen -q -t ed25519 -N "" -C e2e@local -f "$KEY"
ssh-keygen -q -t ed25519 -N "" -C other@local -f "$WORK/otherkey"
ic "$TEN" create_repo '("e2e-app")' >/dev/null
BOUND=$(ic "$TEN" create_push_token "(\"e2e-app\", opt (7 : nat32), opt \"$(cat "$KEY.pub")\")" | ok_text)
PLAIN=$(ic "$TEN" create_push_token '("e2e-app", null, null)' | ok_text)
URL="http://ic:$BOUND@$HOST/e2e-app.git"
PURL="http://ic:$PLAIN@$HOST/e2e-app.git"
expect "receive-pack advertises push-cert=<nonce>" "$(curl -s "http://ic:$BOUND@$HOST/e2e-app.git/info/refs?service=git-receive-pack" | tr '\0' ' ')" 'push-cert=[0-9]+-[0-9a-f]{32}'

W=$WORK/work
git init -q -b main "$W"
git -C "$W" config user.name E2E
git -C "$W" config user.email e2e@local
mkdir -p "$W/site"
commit() { printf '%s\n' "$2" >"$W/$1"; git -C "$W" add -A; git -C "$W" commit -qm "$3"; }
signed() { git -C "$W" -c gpg.format=ssh -c user.signingkey="${2:-$KEY.pub}" push --signed "$1" main 2>&1; }
commit site/index.html '<!doctype html><title>v1</title><h1>one</h1>' v1
expect "bound token, unsigned: refused with the key and the fix" "$(git -C "$W" push "$URL" main 2>&1)" 'remote rejected.*bound to the SSH key SHA256:.*gpg.format ssh'
expect "bound token, signed: accepted" "$(signed "$URL")" 'new branch'
commit site/b.txt b v2
expect "signed by another key: refused, naming both keys" "$(signed "$URL" "$WORK/otherkey.pub")" 'remote rejected.*not by the key bound'
OUT=$(git -C "$W" push "$PURL" main 2>&1 || true)
expect "unbound token, not required: accepted" "$OUT" 'main -> main'
refuse "  ...and not rejected" "$OUT" 'rejected'
ic "$TEN" set_require_signed_push '("e2e-app", true)' >/dev/null
commit site/c.txt c v3
expect "unbound token, signing required: refused" "$(git -C "$W" push "$PURL" main 2>&1)" 'remote rejected.*requires signed pushes'
OUT=$(signed "$URL" || true)
expect "bound token, signed, signing required: accepted" "$OUT" 'main -> main'
refuse "  ...and not rejected" "$OUT" 'rejected'

section "tokens"
LIST=$(ic "$TEN" list_push_tokens '("e2e-app")')
expect "list shows both tokens, one with its key" "$(echo "$LIST" | grep -c 'id =')" '^2$'
expect "  ...the bound key" "$LIST" 'key = opt "ssh-ed25519 '
# The id of the record that carries a key.
ID=$(echo "$LIST" | awk '/record \{/{id=""; k=0} /id = "/{match($0,/"[0-9a-f]+"/); id=substr($0,RSTART+1,RLENGTH-2)} /key = opt/{k=1} k && id!=""{print id; exit}')
expect "revoke by id" "$(ic "$TEN" revoke_push_token_id "(\"$ID\")")" 'Ok'
commit site/d.txt d v4
expect "revoked token: authentication fails" "$(GIT_TERMINAL_PROMPT=0 signed "$URL")" 'Authentication failed|401'
git -C "$W" reset -q --hard HEAD~1
BOUND=$(ic "$TEN" create_push_token "(\"e2e-app\", null, opt \"$(cat "$KEY.pub")\")" | ok_text)
URL="http://ic:$BOUND@$HOST/e2e-app.git"

if command -v gpg >/dev/null; then
  section "GPG-signed certificate, unbound token"
  # A short GNUPGHOME: the agent's socket path has a length limit.
  export GNUPGHOME
  GNUPGHOME=$(mktemp -d /tmp/g.XXXXXX)
  gpg --batch --quiet --passphrase '' --quick-gen-key "E2E <gpg@local>" ed25519 sign never >/dev/null 2>&1
  GKEY=$(gpg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec/{print $5; exit}')
  ic "$TEN" create_repo '("e2e-gpg")' >/dev/null
  GT=$(ic "$TEN" create_push_token '("e2e-gpg", null, null)' | ok_text)
  GW=$WORK/gw
  git init -q -b main "$GW"
  git -C "$GW" config user.name E2E
  git -C "$GW" config user.email gpg@local
  echo x >"$GW/a"; git -C "$GW" add a; git -C "$GW" commit -qm g
  expect "accepted" "$(GIT_TERMINAL_PROMPT=0 git -C "$GW" -c user.signingkey="$GKEY" push --signed "http://ic:$GT@$HOST/e2e-gpg.git" main 2>&1)" 'new branch'
  gpgconf --kill gpg-agent 2>/dev/null || true
  rm -rf "$GNUPGHOME"
  unset GNUPGHOME
fi

section "operator guard"
expect "tenant: evm_set_config refused" "$(ic "$TEN" evm_set_config '("x", "dfx_test_key", 11155111 : nat64, vec {})')" 'is not an operator'
expect "tenant: sol_send refused" "$(ic "$TEN" sol_send '("x", 1 : nat64)')" 'is not an operator'
expect "tenant: put_object refused" "$(ic "$TEN" put_object '("blob", blob "x")')" 'is not an operator'
refuse "operator: evm_reset_nonce passes the guard" "$(ic "$OP" evm_reset_nonce)" 'rror|not an operator'
# The change itself: a controller that is not on the allowlist is an operator
# here too (these calls used to check the allowlist alone). $OP is both, so
# make the tenant a controller for one call.
(cd "$WORK" && dfx canister update-settings "$AUTH" --add-controller "$T" --identity "$OP" >/dev/null)
refuse "controller not on the allowlist: evm_reset_nonce passes the guard" "$(ic "$TEN" evm_reset_nonce)" 'rror|not an operator'
# Billing follows the same rule: the tenant's repo is exempt while it is a
# controller, and pays again once it is not.
expect "  ...and its repo is exempt from charges" "$(ic "$OP" get_repo_info '("e2e-app")')" 'exempt = true'
(cd "$WORK" && dfx canister update-settings "$AUTH" --remove-controller "$T" --identity "$OP" >/dev/null)
expect "  ...and refused again once it is not a controller" "$(ic "$TEN" evm_reset_nonce)" 'is not an operator'
expect "  ...and its repo pays again" "$(ic "$OP" get_repo_info '("e2e-app")')" 'exempt = false'

section "approval-gated site"
SITE="http://$HOST/site/e2e-app/"
# "<status> <commit>" of a site's root: the X-Ic-Git-Commit header names it.
served_at() {
  curl -s -D "$WORK/h" -o "$WORK/b" "$1" -w '%{http_code} ' || true
  tr -d '\r' <"$WORK/h" | grep -i '^x-ic-git-commit:' | cut -d' ' -f2 || true
}
served() { served_at "$SITE"; }
ic "$TEN" set_site '("e2e-app", "site")' >/dev/null
TIP=$(git -C "$W" rev-parse HEAD)
expect "served at the tip without votes" "$(served)" "^200 $TIP"
ic "$TEN" set_required_votes '("e2e-app", 1 : nat32)' >/dev/null
expect "votes required, nothing approved: 404" "$(served)" '^404'
ic "$TEN" vote "(\"e2e-app\", \"$TIP\", true)" >/dev/null
expect "approved: served" "$(served)" "^200 $TIP"
commit site/index.html '<!doctype html><title>v2</title><h1>two</h1>' site-v2
signed "$URL" >/dev/null || true
NEW=$(git -C "$W" rev-parse HEAD)
expect "new push, unapproved: the approved commit stays up" "$(served)" "^200 $TIP"
ic "$TEN" vote "(\"e2e-app\", \"$NEW\", true)" >/dev/null
expect "new push approved: served" "$(served)" "^200 $NEW"
ic "$TEN" vote "(\"e2e-app\", \"$NEW\", false)" >/dev/null
expect "approval withdrawn: rolled back" "$(served)" "^200 $TIP"
ic "$TEN" vote "(\"e2e-app\", \"$NEW\", true)" >/dev/null

section "approval-gated deploy and announce"
if [ -n "$NAMES_WASM" ]; then
  (cd "$WORK" && dfx canister create names --identity "$OP" --no-wallet --with-cycles 20000000000000 >/dev/null 2>&1)
  (cd "$WORK" && dfx canister install names --identity "$OP" --wasm "$NAMES_WASM" >/dev/null 2>&1)
  N=$(cd "$WORK" && dfx canister id names)
  call "$OP" names add_deployer "(principal \"$A\")" >/dev/null
  expect "names hook configured" "$(ic "$OP" names_set_config "(\"$N\", \"solo\")")" 'Ok'
fi
APP=$(ic "$TEN" create_app_canister '("e2e-app", 1_000_000_000_000 : nat64)' | sed -n 's/.*principal "\([^"]*\)".*/\1/p')
expect "app canister created" "$APP" '-cai$'
ic "$TEN" set_wasm_deploy '("e2e-app", "app", "app.wat")' >/dev/null
commit app.wat '(module (func (export "canister_query hello")))' app-v1
signed "$URL" >/dev/null || true
A1=$(git -C "$W" rev-parse HEAD)
expect "push held for approval" "$(ic "$TEN" get_deploy_status '("e2e-app")')" 'awaiting voter approval'
ic "$TEN" vote "(\"e2e-app\", \"$A1\", true)" >/dev/null
STATUS=
for _ in $(seq 1 30); do
  STATUS=$(ic "$TEN" get_deploy_status '("e2e-app")')
  echo "$STATUS" | grep -q 'ok = true' && break
  sleep 1
done
expect "approved: deployed" "$STATUS" 'ok = true'
WASM_SHA=$(echo "$STATUS" | sed -n 's/.*wasm_sha256 = "\([0-9a-f]*\)".*/\1/p')
expect "the IC's module hash is the deployed wasm's" "$(cd "$WORK" && dfx canister info "$APP" --identity "$OP" 2>&1)" "Module hash: 0x$WASM_SHA"
if [ -n "$NAMES_WASM" ]; then
  expect "announced" "$STATUS" 'announced as solo/e2e-app'
  REC=$(call "$OP" names get_record '("solo/e2e-app")' --query)
  expect "  ...record names the commit" "$REC" "\"commit\"; \"$A1\""
  expect "  ...and the module hash" "$REC" "\"$WASM_SHA\""
fi

section "objections"
# An objection counts -1 with a reason: a commit passes when approvals minus
# objections reach the threshold (docs/TENANCY.md, "Votes"). The site and the
# app are on $A1; the tenant is the only voter so far, with 1 required.
P1=$(dfx identity get-principal --identity "$V1")
P2=$(dfx identity get-principal --identity "$V2")
ic "$TEN" add_member "(\"e2e-app\", principal \"$P1\", \"voter\")" >/dev/null
ic "$TEN" add_member "(\"e2e-app\", principal \"$P2\", \"voter\")" >/dev/null
commit app.wat '(module (func (export "canister_query hello")) (func (export "canister_query hi")))' app-v2
signed "$URL" >/dev/null || true
A2=$(git -C "$W" rev-parse HEAD)
expect "an objection without a reason is refused" "$(ic "$V1" cast_ballot "(\"e2e-app\", \"$A2\", variant { Object }, null)")" 'needs a reason'
expect "  ...and a blank one" "$(ic "$V1" cast_ballot "(\"e2e-app\", \"$A2\", variant { Object }, opt \"  \")")" 'needs a reason'
OUT=$(ic "$V1" cast_ballot "(\"e2e-app\", \"$A2\", variant { Object }, opt \"the second export is untested\")")
expect "objection recorded" "$OUT" 'objections = 1'
expect "  ...nothing approved" "$OUT" 'approvals = 0'
OUT=$(ic "$TEN" vote "(\"e2e-app\", \"$A2\", true)")
expect "one approval over one objection: 1 of 1 by the old count" "$OUT" 'Ok = record \{ 1 : nat32; 1 : nat32 \}'
expect "  ...but held: net 0" "$(ic "$TEN" get_deploy_status '("e2e-app")')" 'awaiting voter approval'
expect "  ...and the site stays on the commit before it" "$(served)" "^200 $A1"
VOTES=$(curl -s "http://$AHOST/api/e2e-app/votes/$A2")
expect "/api votes: the objection with its reason" "$VOTES" '"decision":"object","approve":false,"reason":"the second export is untested"'
expect "  ...and the count" "$VOTES" '"approvals":1,"objections":1,"required":1,"reached":false'
# The wallet's consent message for an objection names the reason: OISY shows
# it to the signer. The encoded argument comes from the codec vectors.
ARG=$(cd "$ROOT" && cargo test -q -p combined_canister --test candid_vectors -- --nocapture 2>/dev/null | awk '$1 == "args:cast_ballot_object" { print $2 }' | sed 's/../\\&/g')
CONSENT=$(ic anonymous icrc21_canister_call_consent_message "(record { method = \"cast_ballot\"; arg = blob \"$ARG\"; user_preferences = record { metadata = record { language = \"en\"; utc_offset_minutes = null }; device_spec = null } })")
expect "consent message: an objection, with its reason" "$CONSENT" 'Object to commit 0123456789ab.*Reason: skips the migration'
OUT=$(ic "$V2" cast_ballot "(\"e2e-app\", \"$A2\", variant { Approve }, null)")
expect "a second approval outweighs the objection" "$OUT" 'reached = true'
for _ in $(seq 1 30); do
  STATUS=$(ic "$TEN" get_deploy_status '("e2e-app")')
  echo "$STATUS" | grep -q "$A2" && echo "$STATUS" | grep -q 'ok = true' && break
  sleep 1
done
expect "  ...and it deploys" "$(printf '%s' "$STATUS" | tr '\n' ' ')" "ok = true.*commit = \"$A2\""
expect "  ...and is served" "$(served)" "^200 $A2"
# An objection after the deploy drops the commit below the threshold: the
# site rolls back to the approved commit before it, and so does the app,
# the same way a withdrawn approval does.
ic "$V2" cast_ballot "(\"e2e-app\", \"$A2\", variant { Object }, opt \"regressed in production\")" >/dev/null
expect "an objection after the deploy rolls the site back" "$(served)" "^200 $A1"
for _ in $(seq 1 30); do
  STATUS=$(ic "$TEN" get_deploy_status '("e2e-app")')
  echo "$STATUS" | grep -q "$A1" && echo "$STATUS" | grep -q 'ok = true' && break
  sleep 1
done
expect "  ...and the app" "$(printf '%s' "$STATUS" | tr '\n' ' ')" "ok = true.*commit = \"$A1\""
expect "  ...two objections on record" "$(curl -s "http://$AHOST/api/e2e-app/votes/$A2")" '"objections":2'
FEED=$(curl -s -D "$WORK/feed.h" "http://$AHOST/feed/e2e-app")
expect "the repo's feed is Atom" "$(cat "$WORK/feed.h")" 'application/atom\+xml'
expect "  ...with the push awaiting votes" "$(flat "$FEED")" "<category term=\"awaiting\"/>.*$A2 on refs/heads/main needs"
expect "  ...the objection with its reason" "$(flat "$FEED")" 'object commit.*Reason: regressed in production'
expect "  ...the threshold reached" "$FEED" '<category term="reached"/>'
expect "  ...and the deploy" "$(flat "$FEED")" "deployed to.*<category term=\"deployed\"/>"
expect "  ...newest first: the rollback deploy" "$(printf '%s' "$FEED" | grep -n '<category' | head -1)" 'deployed'
expect "a feed for a repo that does not exist is a 404" "$(curl -s -o /dev/null -w '%{http_code}' "http://$AHOST/feed/no-such-repo")" '^404$'
# Withdrawing both (a rejection weighs nothing) approves it again.
ic "$V1" cast_ballot "(\"e2e-app\", \"$A2\", variant { Reject }, null)" >/dev/null
ic "$V2" cast_ballot "(\"e2e-app\", \"$A2\", variant { Reject }, null)" >/dev/null
expect "objections withdrawn: served again" "$(served)" "^200 $A2"
# Let the app's re-deploy finish before the canister is upgraded underneath it.
for _ in $(seq 1 30); do
  STATUS=$(ic "$TEN" get_deploy_status '("e2e-app")')
  echo "$STATUS" | grep -q "$A2" && echo "$STATUS" | grep -q 'ok = true' && break
  sleep 1
done
expect "  ...and deployed again" "$(printf '%s' "$STATUS" | tr '\n' ' ')" "ok = true.*commit = \"$A2\""

section "governed backend"
# docs/GOVERNANCE.md, section 2. Governing hands the app canister to ic-git
# alone and locks the policy: the owner's direct changes to it are refused,
# and every such change is a ballot under the current K of N.
INFO=$(cd "$WORK" && dfx canister info "$APP" --identity "$OP" 2>&1)
expect "before: the owner and ic-git control the app canister" "$(flat "$INFO")" "Controllers:.*$T"
expect "a voter cannot govern" "$(ic "$V1" govern_app_canister '("e2e-app")')" 'only the owner'
# A governed repo deploys committed .wasm only (docs/CANISTER_SPLIT.md,
# phase 2 step 3): nothing compiled here reaches a governed backend.
expect "governing while the config compiles app.wat is refused" "$(ic "$TEN" govern_app_canister '("e2e-app")')" '.wasm only.*app.wat'
expect "  ...the canister is untouched" "$(flat "$(cd "$WORK" && dfx canister info "$APP" --identity "$OP" 2>&1)")" "Controllers:.*$T"
ic "$TEN" set_wasm_deploy '("e2e-app", "app", "app.wasm")' >/dev/null
expect "the owner governs" "$(ic "$TEN" govern_app_canister '("e2e-app")')" "Ok = principal \"$APP\""
INFO=$(cd "$WORK" && dfx canister info "$APP" --identity "$OP" 2>&1)
expect "after: ic-git is the only controller" "$(flat "$INFO")" "Controllers: $A *Module"
refuse "  ...the owner is gone" "$INFO" "$T"
expect "governing twice is refused" "$(ic "$TEN" govern_app_canister '("e2e-app")')" 'already governed'
expect "/api info says governed" "$(curl -s "http://$AHOST/api/e2e-app/info")" '"governed":true'
expect "owner: required votes locked" "$(ic "$TEN" set_required_votes '("e2e-app", 0 : nat32)')" 'propose_policy_change'
expect "owner: voters locked" "$(ic "$TEN" add_member "(\"e2e-app\", principal \"$P1\", \"writer\")")" 'propose_policy_change'
expect "owner: removing a voter locked" "$(ic "$TEN" remove_member "(\"e2e-app\", principal \"$P1\")")" 'propose_policy_change'
expect "owner: transfer locked" "$(ic "$TEN" transfer_repo "(\"e2e-app\", principal \"$P1\")")" 'propose_policy_change'
expect "owner: deploy config locked" "$(ic "$TEN" set_wasm_deploy '("e2e-app", "app", "other.wat")')" 'propose_policy_change'
expect "owner: install mode locked" "$(ic "$TEN" set_deploy_mode '("e2e-app", "reinstall")')" 'propose_policy_change'
OPP=$(dfx identity get-principal --identity "$OP")
expect "writers are still the owner's to manage" "$(ic "$TEN" add_member "(\"e2e-app\", principal \"$OPP\", \"writer\")")" 'Ok'
ic "$TEN" remove_member "(\"e2e-app\", principal \"$OPP\")" >/dev/null
# Policy changes by vote. K is 1 of 3, so the proposer's approval applies.
expect "required votes 1 -> 2 by vote: applied at once under K = 1" "$(flat "$(ic "$TEN" propose_policy_change '("e2e-app", variant { RequiredVotes = record { k = 2 : nat32 } }, variant { Approve }, null)')")" 'reached = true'
expect "  ...and in effect" "$(curl -s "http://$AHOST/api/e2e-app/info")" '"required_votes":2'
expect "a compiled source is refused before any ballot" "$(ic "$TEN" propose_policy_change "(\"e2e-app\", variant { WasmDeploy = record { target = \"$APP\"; source_path = \"app.wat\" } }, variant { Approve }, null)")" '.wasm only'
expect "k = 0 is refused before any ballot" "$(ic "$TEN" propose_policy_change '("e2e-app", variant { RequiredVotes = record { k = 0 : nat32 } }, variant { Approve }, null)')" 'at least one required vote'
# Under K = 2 a change waits, is listed with its count, and an objection holds it.
expect "lowering back to 1 waits for a second approval" "$(flat "$(ic "$V1" propose_policy_change '("e2e-app", variant { RequiredVotes = record { k = 1 : nat32 } }, variant { Approve }, null)')")" 'reached = false'
PROPS=$(curl -s "http://$AHOST/api/e2e-app/proposals")
expect "/api proposals lists it" "$PROPS" '"change":\{"RequiredVotes":\{"k":1\}\}'
expect "  ...with the count" "$PROPS" '"approvals":1,"objections":0,"required":2,"reached":false'
expect "an objection with a reason holds it" "$(flat "$(ic "$V2" propose_policy_change '("e2e-app", variant { RequiredVotes = record { k = 1 : nat32 } }, variant { Object }, opt "two sets of eyes on the backend")')")" 'objections = 1'
expect "  ...the reason is in the API" "$(curl -s "http://$AHOST/api/e2e-app/proposals")" '"reason":"two sets of eyes on the backend"'
expect "  ...and the owner's approval does not outweigh it (2 - 1 < 2)" "$(flat "$(ic "$TEN" propose_policy_change '("e2e-app", variant { RequiredVotes = record { k = 1 : nat32 } }, variant { Approve }, null)')")" 'reached = false'
expect "still 2 required" "$(curl -s "http://$AHOST/api/e2e-app/info")" '"required_votes":2'
# The governed canister still deploys approved commits, and only those.
# A committed module, (module (func (export "canister_query hey"))), as bytes.
printf '\x00\x61\x73\x6d\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00\x03\x02\x01\x00\x07\x16\x01\x12canister_query hey\x00\x00\x0a\x04\x01\x02\x00\x0b' >"$W/app.wasm"
git -C "$W" add -A
git -C "$W" commit -qm app-v3
signed "$URL" >/dev/null || true
A3=$(git -C "$W" rev-parse HEAD)
ic "$TEN" cast_ballot "(\"e2e-app\", \"$A3\", variant { Approve }, null)" >/dev/null
expect "one of two approvals: held" "$(ic "$TEN" get_deploy_status '("e2e-app")')" 'awaiting voter approval'
ic "$V1" cast_ballot "(\"e2e-app\", \"$A3\", variant { Approve }, null)" >/dev/null
for _ in $(seq 1 30); do
  STATUS=$(ic "$TEN" get_deploy_status '("e2e-app")')
  echo "$STATUS" | grep -q "$A3" && echo "$STATUS" | grep -q 'ok = true' && break
  sleep 1
done
expect "two approvals: the governed canister is upgraded" "$(flat "$STATUS")" "ok = true.*commit = \"$A3\""
WASM_SHA=$(echo "$STATUS" | sed -n 's/.*wasm_sha256 = "\([0-9a-f]*\)".*/\1/p')
expect "  ...to the module the status names" "$(cd "$WORK" && dfx canister info "$APP" --identity "$OP" 2>&1)" "Module hash: 0x$WASM_SHA"
refuse "  ...no app record here: no registry on this network" "$STATUS" 'app record'
expect "  ...and served" "$(served)" "^200 $A3"
# A module larger than a message (docs/CANISTER_SPLIT.md, step 12b): the
# job crosses to the authority in chunks, and deploy_now's job comes back
# the same way. A valid module: the header and one custom section of
# 1,200,000 zero bytes (section size 1,200,004 as LEB128: 84 9f 49).
{ printf '\x00\x61\x73\x6d\x01\x00\x00\x00\x00\x84\x9f\x49\x03pad'; head -c 1200000 /dev/zero; } >"$W/app.wasm"
git -C "$W" add -A
git -C "$W" commit -qm app-v4
signed "$URL" >/dev/null || true
A4=$(git -C "$W" rev-parse HEAD)
expect "a module past the message limit: pushed, held" "$(ic "$TEN" get_deploy_status '("e2e-app")')" 'awaiting voter approval'
ic "$TEN" cast_ballot "(\"e2e-app\", \"$A4\", variant { Approve }, null)" >/dev/null
ic "$V1" cast_ballot "(\"e2e-app\", \"$A4\", variant { Approve }, null)" >/dev/null
# The job crosses in chunks and the drain runs on a timer, so the status
# passes through "awaiting voter approval" and "deploying" on its way to
# an outcome: wait for one.
for _ in $(seq 1 30); do
  STATUS=$(flat "$(ic "$TEN" get_deploy_status '("e2e-app")')")
  echo "$STATUS" | grep -q "$A4" && ! echo "$STATUS" | grep -qE 'message = "(deploying|awaiting voter approval)' && break
  sleep 1
done
expect "  ...approved: its job crossed and it is installed" "$STATUS" "ok = true.*commit = \"$A4\""
WASM_SHA=$(echo "$STATUS" | sed -n 's/.*wasm_sha256 = "\([0-9a-f]*\)".*/\1/p')
expect "  ...the IC reports it" "$(cd "$WORK" && dfx canister info "$APP" --identity "$OP" 2>&1)" "Module hash: 0x${WASM_SHA:-none}"
expect "deploy_now installs the release commit again (its job in a staged reply)" "$(flat "$(ic "$TEN" deploy_now '("e2e-app")')")" "ok = true.*commit = \"$A4\""
expect "  ...a voter cannot" "$(ic "$V1" deploy_now '("e2e-app")')" 'does not own'
# A deploy config change by vote (K = 2): applied when the second approval lands.
ic "$V1" propose_policy_change '("e2e-app", variant { DeployMode = record { mode = "reinstall" } }, variant { Approve }, null)' >/dev/null
expect "install mode unchanged after one approval" "$(ic "$TEN" get_deploy_config '("e2e-app")')" 'upgrade'
expect "second approval applies the deploy config change" "$(flat "$(ic "$V2" propose_policy_change '("e2e-app", variant { DeployMode = record { mode = "reinstall" } }, variant { Approve }, null)')")" 'reached = true'
expect "  ...install mode is now reinstall" "$(ic "$TEN" get_deploy_config '("e2e-app")')" 'reinstall'
# Back to upgrade the same way, so the rest of the run keeps its state.
ic "$V1" propose_policy_change '("e2e-app", variant { DeployMode = record { mode = "upgrade" } }, variant { Approve }, null)' >/dev/null
ic "$V2" propose_policy_change '("e2e-app", variant { DeployMode = record { mode = "upgrade" } }, variant { Approve }, null)' >/dev/null
expect "  ...and back to upgrade" "$(ic "$TEN" get_deploy_config '("e2e-app")')" 'upgrade'

# The governor's calls, to the governor $GOVN names (a dfx name).
gov() { local who=$1; shift; call "$who" "$GOVN" "$@"; }
# Stage MODULE for proposal ID in 512 KiB chunks, as blob arguments in files,
# each at its offset; a call that fails is retried (a resent chunk is a no-op).
stage() {
  local who=$1 id=$2 file=$3 part last= off=0 try
  rm -rf "$WORK/chunks"; mkdir "$WORK/chunks"
  split -b 524288 "$file" "$WORK/chunks/c."
  for part in "$WORK/chunks"/c.*; do
    printf '(%s : nat64, %s : nat64, blob "%s")' "$id" "$off" "$(od -An -v -tx1 "$part" | tr -d ' \n' | sed 's/../\\&/g')" >"$part.arg"
    for try in 1 2 3; do
      last=$(gov "$who" stage --argument-file "$part.arg")
      printf '%s' "$last" | grep -q 'Ok = record' && break
    done
    off=$((off + $(wc -c <"$part")))
  done
  printf '%s' "$last"
}
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
COMMIT=$(git -C "$ROOT" rev-parse HEAD)
upgrade_to() { printf '(variant { Upgrade = record { commit = "%s"; module_sha256 = "%s"; arg = blob "" } })' "$COMMIT" "$1"; }
id_of() { sed -n 's/.*Ok = \([0-9_]*\) : nat64.*/\1/p' | tr -d _; }

section "pricing"
expect "the table names the git canister's floor" "$(ic "$OP" get_pricing --query)" 'git_canister_floor = opt \(1_000_000_000_000 : nat64\)'
expect "  ...and /api/pricing reports it" "$(curl -s "http://$AHOST/api/pricing")" '"git_canister_floor":1000000000000'
# The whole table, with the git canister's floor as given.
pricing() { printf '(record { create_repo = 1000000000 : nat64; push_base = 100000000 : nat64; push_per_byte = 5000 : nat64; rent_per_byte_year = 5000 : nat64; evm_action = 50000000000 : nat64; ic_deploy = 5000000000 : nat64; git_canister_floor = opt (%s : nat64) })' "$1"; }
expect "a tenant cannot retune it" "$(ic "$TEN" set_pricing "$(pricing 1)")" 'is not an operator'
# The table as it was before the floor: still taken, the floor the default.
ic "$OP" set_pricing '(record { create_repo = 1000000000 : nat64; push_base = 100000000 : nat64; push_per_byte = 5000 : nat64; rent_per_byte_year = 5000 : nat64; evm_action = 50000000000 : nat64; ic_deploy = 5000000000 : nat64 })' >/dev/null
expect "a table without the floor keeps the default" "$(ic "$OP" get_pricing --query)" 'git_canister_floor = opt \(1_000_000_000_000 : nat64\)'

if [ "$SPLIT" = 1 ]; then
section "funding the git canister"
# docs/CANISTER_SPLIT.md, step 12d: what tenants paid for git-side work
# (pushes, rent) is the pool, and the rent timer sends the floor's worth
# across when the git canister is under the floor. The floor is raised past
# what the git canister holds and the tick run by hand.
bal() { call "$OP" git cycle_balance --query | sed -n 's/^(\([0-9_]*\) : nat64)$/\1/p' | tr -d _; }
# The funding record on one line, with the digit groups' underscores gone.
funding() { flat "$(call "$OP" authority get_git_funding --query)" | perl -pe 's/(?<=\d)_(?=\d)//g'; }
field() { printf '%s' "$1" | sed -n "s/.*$2 = \([0-9]*\) : nat64.*/\1/p"; }
FUND=$(funding)
expect "the pool holds the tenant's push fees" "$FUND" 'pool = [1-9][0-9]* : nat64'
expect "  ...nothing sent yet" "$FUND" 'sent = 0 : nat64.*last = null|last = null.*sent = 0 : nat64'
expect "  ...and it names the git canister" "$FUND" "git_canister = opt principal \"$G\""
POOL=$(field "$FUND" pool)
B0=$(bal)
expect "the git canister holds what it was created with" "$B0" '^[1-9][0-9]*$'
call "$OP" authority set_pricing "$(pricing 100000000000000)" >/dev/null
ic "$OP" charge_rent_now >/dev/null
FUND=$(funding)
SENT=$(field "$FUND" sent)
# The tick collects rent first, so a few cycles more than the pool read above.
expect "under the floor: the tick sent the whole pool" "$(( SENT >= POOL && SENT - POOL < 1000000 ))" '^1$'
expect "  ...the pool is empty" "$FUND" 'pool = 0 : nat64'
expect "  ...and the top-up is on record with what the git canister held" "$FUND" "last = opt record \{.*balance_before = opt \([0-9]+ : nat64\)"
B1=$(bal)
expect "  ...and the git canister holds more" "$(( B1 > B0 ))" '^1$'
ic "$OP" charge_rent_now >/dev/null
SENT2=$(field "$(funding)" sent)
expect "a second tick sends only the rent it just collected" "$(( SENT2 >= SENT && SENT2 - SENT < 1000000 ))" '^1$'
expect "a tenant cannot send the authority's own cycles" "$(ic "$TEN" top_up_git_canister '(1000000000000 : nat64)')" 'is not an operator'
expect "an operator can" "$(ic "$OP" top_up_git_canister '(1000000000000 : nat64)')" '^\(variant \{ Ok \}\)$'
B2=$(bal)
expect "  ...and the git canister holds about a T more" "$(( B2 - B1 > 900000000000 ))" '^1$'
FUND=$(funding)
expect "  ...on record, not from the pool" "$FUND" "sent = $(( SENT2 + 1000000000000 )) : nat64"
expect "  ...and not asked what it held" "$FUND" 'balance_before = null'
call "$OP" authority set_pricing "$(pricing 1000000000000)" >/dev/null
fi

if [ "$SPLIT" != 1 ]; then
section "the freeze and the copy (step 13)"
# docs/CANISTER_SPLIT.md, step 13: an operator freezes the git side, and
# what writes it is refused with a message naming the cut, uncharged;
# reads go on, and so do the authority's own decisions. A git canister
# that answers to this one is named as the importer, pulls every git-side
# record in pages, and digests its copy; the exporter's digest, stepped
# by hand, agrees. Then the thaw, and pushes again.
expect "not frozen" "$(ic "$OP" frozen --query)" '^\(false\)$'
expect "no export before the freeze" "$(ic "$OP" export_page '(null)')" 'freeze first'
expect "a tenant cannot freeze" "$(ic "$TEN" freeze)" 'is not an operator'
expect "an operator can" "$(ic "$OP" freeze)" 'Ok'
expect "  ...and the canister says so" "$(ic "$OP" frozen --query)" '^\(true\)$'
FROZEN_SITE=$(served)
SPENT0=$(ic "$TEN" get_account "(principal \"$T\")" | sed -n 's/.*spent = \([0-9_]*\).*/\1/p')
commit site/f.txt f while-frozen
expect "a push is refused, naming the cut" "$(signed "$URL")" 'remote rejected.*frozen.*step 16'
git -C "$W" reset -q --hard HEAD~1
expect "a token cannot be minted" "$(ic "$TEN" create_push_token '("e2e-app", null, null)')" 'frozen'
expect "a repo cannot be created" "$(ic "$TEN" create_repo '("while-frozen")')" 'frozen'
expect "a site config cannot change" "$(ic "$TEN" set_site '("e2e-app", "site")')" 'frozen'
expect "an operator cannot write an object" "$(ic "$OP" put_object '("blob", blob "x")')" 'frozen'
expect "  ...nor a ref" "$(ic "$OP" set_ref "(\"e2e-app\", \"refs/heads/x\", \"$A4\")")" 'frozen'
expect "nothing was charged" "$(ic "$TEN" get_account "(principal \"$T\")")" "spent = $SPENT0 "
expect "the site still serves" "$(served)" "^${FROZEN_SITE%% *} ${FROZEN_SITE#* }"
expect "a fetch still works" "$(git ls-remote "http://$HOST/e2e-app.git" 2>&1)" 'refs/heads/main'
expect "the tokens are still listed" "$(ic "$TEN" list_push_tokens '("e2e-app")' | grep -c 'id =')" '^[1-9]'
expect "membership changes stay open" "$(ic "$TEN" add_member "(\"e2e-app\", principal \"$OPP\", \"writer\")")" 'Ok'
ic "$TEN" remove_member "(\"e2e-app\", principal \"$OPP\")" >/dev/null
# The copy: a git canister answering to this one, named as the importer.
(cd "$WORK" && dfx canister create copy --identity "$OP" --no-wallet --with-cycles 50000000000000 >/dev/null 2>&1)
(cd "$WORK" && dfx canister install copy --identity "$OP" --wasm "$GITC_WASM" --argument "(record { authority = principal \"$G\" })" >/dev/null 2>&1)
C=$(cd "$WORK" && dfx canister id copy)
expect "a stranger cannot read the export" "$(ic "$TEN" export_page '(null)')" 'operator or the named importer'
expect "the exporter cannot be its own importer" "$(ic "$OP" set_importer "(principal \"$G\")")" 'own importer'
expect "the copy must be frozen before it imports" "$(call "$OP" copy import_start "(principal \"$G\")")" 'freeze this canister first'
call "$OP" copy freeze >/dev/null
expect "  ...and cannot import from itself" "$(call "$OP" copy import_start "(principal \"$C\")")" 'itself'
# Not yet named: the first page is refused, and the import stops there.
call "$OP" copy import_start "(principal \"$G\")" >/dev/null
for _ in $(seq 1 30); do
  ST=$(flat "$(call "$OP" copy import_status --query)")
  echo "$ST" | grep -q 'running = false' && break
  sleep 1
done
expect "unnamed, the copy is refused the export, on record" "$ST" 'error = opt ".*operator or the named importer'
expect "the copy is named as the importer" "$(ic "$OP" set_importer "(principal \"$C\")")" 'Ok'
expect "  ...and the exporter says so" "$(ic "$OP" get_importer --query)" "principal \"$C\""
expect "the import resumes" "$(call "$OP" copy import_start "(principal \"$G\")")" 'Ok'
for _ in $(seq 1 120); do
  ST=$(flat "$(call "$OP" copy import_status --query)")
  echo "$ST" | grep -q 'running = false' && break
  sleep 1
done
expect "every page taken" "$ST" 'copied = true'
expect "  ...with no error" "$ST" 'error = null'
expect "  ...in pages" "$ST" 'pages = [1-9][0-9_]* : nat64'
expect "  ...and the copy's digest done" "$ST" 'done = true'
COPY_SHA=$(printf '%s' "$ST" | sed -n 's/.*sha256 = opt "\([0-9a-f]*\)".*/\1/p')
expect "  ...a sha256" "$COPY_SHA" '^[0-9a-f]{64}$'
D=
for _ in $(seq 1 200); do
  D=$(flat "$(ic "$OP" digest_step)")
  echo "$D" | grep -q 'done = true' && break
done
expect "the exporter's digest, stepped by an operator, is done" "$D" 'done = true'
expect "  ...and the two agree" "$D" "sha256 = opt \"$COPY_SHA\""
expect "  ...over the same count of records" "$(printf '%s' "$D" | sed -n 's/.*records = \([0-9_]*\).*/\1/p')" "^$(printf '%s' "$ST" | sed -n 's/.*records = \([0-9_]*\).*/\1/p')\$"
expect "  ...and the query says the same" "$(flat "$(ic "$OP" get_digest --query)")" "sha256 = opt \"$COPY_SHA\""
same() { if [ "$1" = "$2" ]; then echo same; else printf 'differ: %s | %s' "$1" "$2"; fi; }
expect "the copy lists the same repos" "$(same "$(call "$OP" copy list_repos --query)" "$(ic "$OP" list_repos --query)")" '^same$'
expect "  ...the same refs" "$(same "$(call "$OP" copy list_refs '("e2e-app")' --query)" "$(ic "$OP" list_refs '("e2e-app")' --query)")" '^same$'
expect "  ...the same objects" "$(same "$(call "$OP" copy get_object "(\"$A4\")" --query)" "$(ic "$OP" get_object "(\"$A4\")" --query)")" '^same$'
expect "  ...the same push tokens" "$(same "$(call "$OP" copy list_push_tokens '("e2e-app")' --query)" "$(ic "$OP" list_push_tokens '("e2e-app")' --query)")" '^same$'
expect "  ...and the same site config" "$(same "$(call "$OP" copy get_site '("e2e-app")' --query)" "$(ic "$OP" get_site '("e2e-app")' --query)")" '^same$'
# The copy serves the site: with no approvals mirror yet, the tip, which
# is the approved commit here. The mirrors are rewritten at the cut.
expect "the copy serves the site from the same commit" "$(served_at "http://$C.raw.localhost:$PORT/site/e2e-app/")" "^${FROZEN_SITE%% *} ${FROZEN_SITE#* }"
expect "the thaw" "$(ic "$OP" unfreeze)" 'Ok'
expect "  ...forgets the digest" "$(ic "$OP" get_digest --query)" '^\(null\)$'
expect "  ...and pushes are taken again" "$(signed "$URL")" 'main -> main'
# The pushed commit awaits votes (K = 2); the upgrade below takes the site
# as it finds it. The copy stays frozen, as it would until the cut.
fi

section "upgrade in place (same build)"
BEFORE=$(served)
if [ "$SPLIT" = 1 ]; then
  (cd "$WORK" && dfx canister install authority --mode upgrade --yes --identity "$OP" --wasm "$AUTH_WASM" >/dev/null 2>&1)
  # The git canister is governed: its upgrade is a proposal (docs/GOVERNOR.md).
  GOVN=gitgov
  GITC_SHA=$(sha "$GITC_WASM")
  UG=$(gov "$OP" propose "$(upgrade_to "$GITC_SHA")" | id_of)
  expect "the git canister's upgrade is proposed to its governor" "$UG" '^[0-9]+$'
  stage "$OP" "$UG" "$GITC_WASM" >/dev/null
  UGOUT=$(flat "$(gov "$OP" vote "($UG : nat64, variant { Approve }, null)")")
  expect "  ...and executed" "$UGOUT" "upgraded $G to $GITC_SHA"
  # The new code asked the authority to publish ic-git#git: the authority
  # read the module hash the IC holds for the git canister and found it the
  # stated one (a mismatch would say so), and had no registry to publish to.
  expect "  ...and the git canister's record went to the authority, which checked its module (no registry here)" "$UGOUT" 'record not published: no (EVM config|registry)'
  GOVN=governor
else
  (cd "$WORK" && dfx canister install git --mode upgrade --yes --identity "$OP" --wasm "$GIT_WASM" >/dev/null 2>&1)
fi
expect "site unchanged" "$(served)" "^${BEFORE%% *} ${BEFORE#* }"
expect "tokens kept" "$(ic "$TEN" list_push_tokens '("e2e-app")' | grep -c 'id =')" '^[1-9]'
expect "balance kept" "$(ic "$TEN" get_account "(principal \"$T\")")" 'deposited = [1-9]'
expect "push-cert still offered (the seed survived)" "$(curl -s "http://ic:$BOUND@$HOST/e2e-app.git/info/refs?service=git-receive-pack" | tr '\0' ' ')" 'push-cert='
commit site/e.txt e after-upgrade
expect "signed push after upgrade" "$(signed "$URL")" 'main -> main'

if [ -n "$BASE_WASM" ]; then
  section "upgrade from $BASE_REF"
  # State written by the release mainnet starts from, through its own API
  # (its candid), then an upgrade to this build and a check that it carries over.
  OLD_DID=$BASE_DID
  NEW_DID=$DID
  (cd "$WORK" && dfx canister create base --identity "$OP" --no-wallet --with-cycles 50000000000000 >/dev/null 2>&1)
  (cd "$WORK" && dfx canister install base --identity "$OP" --wasm "$BASE_WASM" >/dev/null 2>&1)
  BID=$(cd "$WORK" && dfx canister id base)
  BHOST="$BID.raw.localhost:$PORT"
  old() { local who=$1; shift; call "$who" base "$@" --candid "$OLD_DID"; }
  new() { local who=$1; shift; call "$who" base "$@" --candid "$NEW_DID"; }
  old "$OP" create_repo '("legacy-app")' >/dev/null
  old "$OP" create_repo '("legacy.name")' >/dev/null
  old "$OP" add_member "(\"legacy-app\", principal \"$T\", \"writer\")" >/dev/null
  LW=$WORK/legacy
  git init -q -b main "$LW"
  git -C "$LW" config user.name E2E
  git -C "$LW" config user.email e2e@local
  LSITE="http://$BHOST/site/legacy-app/"
  exp_of() { sed -n 's/.*expires_ns = \([0-9_]*\).*/\1/p' | tr -d _; }
  # The base wrote tokens with an expiry, a minter and optionally a key,
  # and sites already follow the newest approved commit. What must carry
  # over is that state, unchanged, and each rule still enforced.
  LT=$(old "$TEN" create_push_token "(\"legacy-app\", opt (7 : nat32), opt \"$(cat "$KEY.pub")\")" | ok_text)
  LURL="http://ic:$LT@$BHOST/legacy-app.git"
  lsigned() { git -C "$LW" -c gpg.format=ssh -c user.signingkey="$KEY.pub" push --signed "$LURL" main 2>&1 || true; }
  old "$OP" set_require_signed_push '("legacy-app", true)' >/dev/null
  echo '<!doctype html><title>l1</title>' >"$LW/index.html"; git -C "$LW" add -A; git -C "$LW" commit -qm l1
  expect "$BASE_REF: signed push with a key-bound token" "$(lsigned)" 'new branch'
  L1=$(git -C "$LW" rev-parse HEAD)
  old "$OP" set_site '("legacy-app", "")' >/dev/null
  old "$OP" set_required_votes '("legacy-app", 1 : nat32)' >/dev/null
  old "$OP" vote "(\"legacy-app\", \"$L1\", true)" >/dev/null
  echo '<!doctype html><title>l2</title>' >"$LW/index.html"; git -C "$LW" commit -qam l2
  expect "$BASE_REF: a second signed push" "$(lsigned)" 'main -> main'
  expect "$BASE_REF: serves the approved commit, not the tip" "$(served_at "$LSITE")" "^200 $L1"
  EXP_BEFORE=$(old "$TEN" list_push_tokens '("legacy-app")' | exp_of)

  (cd "$WORK" && dfx canister install base --mode upgrade --yes --identity "$OP" --wasm "$GIT_WASM" >/dev/null 2>&1)
  expect "upgraded: still serves the approved commit" "$(served_at "$LSITE")" "^200 $L1"
  TOK=$(new "$TEN" list_push_tokens '("legacy-app")')
  expect "the token is listed with its key" "$TOK" 'key = opt "ssh-ed25519 '
  expect "  ...its minter" "$TOK" "minted_by = opt principal \"$T\""
  expect "  ...and its expiry unchanged" "$(echo "$TOK" | exp_of)" "^${EXP_BEFORE:-missing}\$"
  echo x >"$LW/x.txt"; git -C "$LW" add -A; git -C "$LW" commit -qm l3
  L3=$(git -C "$LW" rev-parse HEAD)
  # A bound token refuses unsigned pushes on its own; only an unbound one
  # shows the repo's require_signed_push survived.
  LPLAIN=$(new "$TEN" create_push_token '("legacy-app", null, null)' | ok_text)
  expect "signing still required: an unbound token's unsigned push is refused" "$(git -C "$LW" push "http://ic:$LPLAIN@$BHOST/legacy-app.git" main 2>&1 || true)" 'remote rejected.*requires signed pushes'
  expect "the key-bound token still pushes, signed" "$(lsigned)" 'main -> main'
  expect "the pushed commit is not served until approved" "$(served_at "$LSITE")" "^200 $L1"
  new "$OP" vote "(\"legacy-app\", \"$L3\", true)" >/dev/null
  expect "a vote after the upgrade moves the site" "$(served_at "$LSITE")" "^200 $L3"
  expect "push-cert still offered" "$(curl -s "$LURL/info/refs?service=git-receive-pack" | tr '\0' ' ')" 'push-cert='
  expect "the EVM nonce store starts empty (no pending tx carried over)" "$(new "$OP" evm_next_nonce)" '^\(null\)$'
  expect "a label taken by an old repo is refused" "$(new "$OP" create_repo '("legacy-name")')" "maps to the label .{0,2}legacy-name.{0,2}, which repo .{0,2}legacy[.]name"
  INFO=$(new "$OP" get_repo_info '("legacy-app")')
  expect "membership kept" "$INFO" "$T"
  expect "required votes kept" "$INFO" 'required_votes = 1'
fi

if [ "$SPLIT" != 1 ]; then
section "governor"
GZ=$WORK/git.wasm.gz
gzip -9 -n -c "$GIT_WASM" >"$GZ"
GZ_SHA=$(sha "$GZ")
RAW_SHA=$(sha "$GIT_WASM")
# docs/GOVERNANCE.md, section 5, rehearsed on a second ic-git: the governor
# becomes its only controller and has none itself; an upgrade is a proposal
# whose module is staged in chunks and voted on by hash; the policy grows
# by vote; an objection holds an upgrade until outweighed or withdrawn; and
# a handover gives the target away, after which the governor is inert.
(cd "$WORK" && dfx canister create ruled --identity "$OP" --no-wallet --with-cycles 50000000000000 >/dev/null 2>&1)
(cd "$WORK" && dfx canister install ruled --identity "$OP" --wasm "$GIT_WASM" >/dev/null 2>&1)
R=$(cd "$WORK" && dfx canister id ruled)
call "$OP" ruled create_repo '("kept")' >/dev/null
(cd "$WORK" && dfx canister create governor --identity "$OP" --no-wallet --with-cycles 20000000000000 >/dev/null 2>&1)
(cd "$WORK" && dfx canister install governor --identity "$OP" --wasm "$GOV_WASM" \
  --argument "(record { target = principal \"$R\"; approvers = vec { principal \"$OPP\" }; threshold = 1 : nat32 })" >/dev/null 2>&1)
GOV=$(cd "$WORK" && dfx canister id governor)
GOVN=governor
expect "governor installed, 1 of 1" "$(flat "$(gov "$OP" info --query)")" "threshold = 1 : nat32.*target = principal \"$R\""
# Immutable: the governor drops its last controller. Then the target goes to it alone.
(cd "$WORK" && dfx canister update-settings governor --remove-controller "$OPP" --yes --identity "$OP" >/dev/null 2>&1)
expect "the governor has no controllers" "$(flat "$(cd "$WORK" && dfx canister info "$GOV" --identity "$OP" 2>&1)")" "Controllers: *Module"
# A different module each time: dfx skips an install of the module already
# there without asking the IC, which would prove nothing.
expect "  ...so nobody can upgrade it" "$(cd "$WORK" && dfx canister install governor --mode upgrade --yes --identity "$OP" --wasm "$GIT_WASM" 2>&1 || true)" 'controller'
(cd "$WORK" && dfx canister update-settings ruled --set-controller "$GOV" --yes --identity "$OP" >/dev/null 2>&1)
expect "the target is controlled by the governor alone" "$(flat "$(cd "$WORK" && dfx canister info "$R" --identity "$OP" 2>&1)")" "Controllers: $GOV *Module"
# The target mirrors the governor into its own feed (docs/GOVERNOR.md,
# "Following it"): only a controller qualifies.
expect "a non-controller is not the governor" "$(call "$OP" ruled feed_set_governor "(opt principal \"$T\")")" 'does not control'
expect "the governor is" "$(call "$OP" ruled feed_set_governor "(opt principal \"$GOV\")")" 'Ok'
expect "  ...and a tenant cannot set it" "$(call "$TEN" ruled feed_set_governor "(opt principal \"$GOV\")")" 'is not an operator'
expect "  ...so its old controller cannot upgrade it" "$(cd "$WORK" && dfx canister install ruled --mode upgrade --yes --identity "$OP" --wasm "$GOV_WASM" 2>&1 || true)" 'controller'
expect "only a controller may publish the target's record" "$(call "$OP" ruled registry_publish_canister "(\"$(printf 'a%.0s' $(seq 40))\", \"$(printf 'b%.0s' $(seq 64))\")")" 'only a controller'

expect "a non-approver cannot propose" "$(gov "$TEN" propose "$(upgrade_to "$GZ_SHA")")" 'only an approver'
U1=$(gov "$OP" propose "$(upgrade_to "$GZ_SHA")" | id_of)
expect "an upgrade is proposed" "$U1" '^[0-9]+$'
expect "no approval before the module is staged" "$(gov "$OP" vote "($U1 : nat64, variant { Approve }, null)")" 'stage the whole module'
expect "a non-approver cannot stage" "$(gov "$TEN" stage "($U1 : nat64, 0 : nat64, blob \"\\00\")")" 'only an approver'
expect "a chunk at the wrong offset is refused" "$(gov "$OP" stage "($U1 : nat64, 7 : nat64, blob \"\\00\")")" 'expected offset 0'
expect "the module is staged in chunks, hash matching" "$(flat "$(stage "$OP" "$U1" "$GZ")")" "ready = true.*staged_sha256 = \"$GZ_SHA\"|staged_sha256 = \"$GZ_SHA\".*ready = true"
OUT=$(flat "$(gov "$OP" vote "($U1 : nat64, variant { Approve }, null)")")
expect "1 of 1 approves: executed in the same call" "$OUT" "reached = true.*Ok = \"upgraded $R to $GZ_SHA"
expect "  ...the target asked the new code to publish its record (no registry here)" "$OUT" 'record not published'
expect "  ...the IC reports the voted module" "$(cd "$WORK" && dfx canister info "$R" --identity "$OP" 2>&1)" "Module hash: 0x$GZ_SHA"
expect "  ...and the target's state survived" "$(call "$OP" ruled get_repo_info '("kept")' --query)" 'opt record'
expect "  ...and it is logged with its ballot" "$(flat "$(gov "$OP" log '(0 : nat64, 100 : nat32)' --query)")" "id = $U1 : nat64.*outcome = \"executed: upgraded"

# The policy grows by vote: 1 of 1 adds two approvers and raises K to 2.
P1=$(dfx identity get-principal --identity "$V1")
P2=$(dfx identity get-principal --identity "$V2")
PO=$(gov "$OP" propose "(variant { Policy = record { approvers = vec { principal \"$OPP\"; principal \"$P1\"; principal \"$P2\" }; threshold = 2 : nat32 } })" | id_of)
expect "K = 0 is refused when proposed" "$(gov "$OP" propose "(variant { Policy = record { approvers = vec { principal \"$OPP\" }; threshold = 0 : nat32 } })")" 'at least 1'
expect "policy change executed by the one approver" "$(flat "$(gov "$OP" vote "($PO : nat64, variant { Approve }, null)")")" 'policy is now 2 of 3'
expect "  ...in effect" "$(flat "$(gov "$OP" info --query)")" 'threshold = 2 : nat32'

# Under 2 of 3 an upgrade (back to the raw module) waits, and an objection holds it.
U2=$(gov "$V1" propose "$(upgrade_to "$RAW_SHA")" | id_of)
stage "$V1" "$U2" "$GIT_WASM" >/dev/null
expect "one approval of two: held" "$(flat "$(gov "$OP" vote "($U2 : nat64, variant { Approve }, null)")")" 'reached = false'
expect "an objection needs a reason" "$(gov "$V2" vote "($U2 : nat64, variant { Object }, null)")" 'reason'
expect "an objection with a reason is counted" "$(flat "$(gov "$V2" vote "($U2 : nat64, variant { Object }, opt \"rebuild did not match yet\")")")" 'objections = 1'
expect "  ...and a second approval does not outweigh it (2 - 1 < 2)" "$(flat "$(gov "$V1" vote "($U2 : nat64, variant { Approve }, null)")")" 'reached = false'
expect "  ...the proposal lists the objection's reason" "$(gov "$OP" proposals --query)" 'rebuild did not match yet'
# A poll now, while the objection stands: a ballot replaced before the
# next poll is never seen, since the governor keeps only the latest.
expect "a poll reports the governor's history so far" "$(call "$OP" ruled feed_poll_governor)" 'Ok = [0-9_]+ : nat64'
GFEED=$(curl -s "http://$R.raw.localhost:$PORT/feed")
expect "  ...as ic-git's own feed" "$(flat "$GFEED")" '<title>ic-git</title>'
expect "  ...with the first upgrade executed" "$(flat "$GFEED")" "proposal $U1 executed"
expect "  ...the policy change" "$(flat "$GFEED")" 'policy 2 of 3'
expect "  ...the objection with its reason" "$(flat "$GFEED")" 'object proposal.*Reason: rebuild did not match yet'
expect "  ...and the module is unchanged" "$(cd "$WORK" && dfx canister info "$R" --identity "$OP" 2>&1)" "Module hash: 0x$GZ_SHA"
expect "the objector approves instead: 3 approvals, executed" "$(flat "$(gov "$V2" vote "($U2 : nat64, variant { Approve }, null)")")" "Ok = \"upgraded $R to $RAW_SHA"

# The next poll adds only what changed since: the approval that replaced
# the objection, and the execution.
expect "the next poll adds the approval and the execution" "$(call "$OP" ruled feed_poll_governor)" 'Ok = 2 : nat64'
GFEED=$(curl -s "http://$R.raw.localhost:$PORT/feed")
expect "  ...so the feed has the second upgrade executed" "$(flat "$GFEED")" "proposal $U2 executed"
expect "  ...and nothing twice" "$(call "$OP" ruled feed_poll_governor)" 'Ok = 0 : nat64'
expect "  ...the IC reports it" "$(cd "$WORK" && dfx canister info "$R" --identity "$OP" 2>&1)" "Module hash: 0x$RAW_SHA"

# A withdrawn proposal is logged and gone.
W=$(gov "$V1" propose "(variant { Handover = record { successor = principal \"$P1\" } })" | id_of)
expect "only the proposer withdraws" "$(gov "$OP" withdraw "($W : nat64)")" 'only the proposer'
gov "$V1" withdraw "($W : nat64)" >/dev/null
expect "  ...withdrawn and logged" "$(flat "$(gov "$OP" log '(0 : nat64, 100 : nat32)' --query)")" "id = $W : nat64.*outcome = \"withdrawn\""
# One the approvers turn down (2 of 3: two against) any approver can withdraw.
D=$(gov "$V1" propose "$(upgrade_to "$(printf '0%.0s' $(seq 64))")" | id_of)
gov "$OP" vote "($D : nat64, variant { Reject }, null)" >/dev/null
expect "one rejection of three: only the proposer can still withdraw" "$(gov "$OP" withdraw "($D : nat64)")" 'not turned down'
gov "$V2" vote "($D : nat64, variant { Object }, opt \"no such build\")" >/dev/null
gov "$OP" withdraw "($D : nat64)" >/dev/null
expect "  ...two against: another approver withdraws it" "$(flat "$(gov "$OP" log '(0 : nat64, 100 : nat32)' --query)")" "id = $D : nat64.*outcome = \"withdrawn\""
expect "a handover to the governor itself is refused" "$(gov "$OP" propose "(variant { Handover = record { successor = principal \"$GOV\" } })")" 'this governor'

# The handover: the target to a successor (here the operator), 2 of 3.
H=$(gov "$OP" propose "(variant { Handover = record { successor = principal \"$OPP\" } })" | id_of)
gov "$OP" vote "($H : nat64, variant { Approve }, null)" >/dev/null
expect "handover executed at the second approval" "$(flat "$(gov "$V2" vote "($H : nat64, variant { Approve }, null)")")" "is now controlled by $OPP alone"
expect "  ...the target's only controller is the successor" "$(flat "$(cd "$WORK" && dfx canister info "$R" --identity "$OP" 2>&1)")" "Controllers: $OPP *Module"
expect "  ...the governor says so" "$(flat "$(gov "$OP" info --query)")" "handed_over_to = opt principal \"$OPP\""
expect "  ...and refuses anything further" "$(gov "$OP" propose "$(upgrade_to "$GZ_SHA")")" 'inert'
expect "the successor can upgrade the target again" "$( (cd "$WORK" && dfx canister install ruled --mode upgrade --yes --identity "$OP" --wasm "$GZ" 2>&1) || true)" 'Upgraded|Installed|Module hash'
fi

section "console reads"
for p in pricing e2e-app/info "account/$T" e2e-app/deploys; do
  expect "/api/$p" "$(curl -s "http://$AHOST/api/$p")" '^\{'
done
if command -v node >/dev/null; then
  cat >"$WORK/reads.mjs" <<'EOF'
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
globalThis.crypto ??= webcrypto;
const [page, port, G, A, T] = process.argv.slice(2);
// As if the page were served by the local gateway.
globalThis.location = { hostname: 'localhost', origin: 'http://localhost:' + port };
const html = readFileSync(page, 'utf8');
const IC = new Function(html.slice(html.indexOf('// === candid ==='), html.indexOf('// === end candid ===')) + '\nreturn IC;')();
const ACCOUNT = { record: { owner: 'principal', subaccount: { opt: 'blob' } } };
const reads = {
  ledger: () => IC.query('ryjl3-tyaaa-aaaaa-aaaba-cai', 'icrc1_balance_of', [ACCOUNT], [{ owner: T, subaccount: null }]),
  cmc_rate: () => IC.query('rkp4c-7iaaa-aaaaa-aaaca-cai', 'get_icp_xdr_conversion_rate', [], []),
  get_site: () => IC.query(G, 'get_site', ['text'], ['e2e-app']),
  get_deploy_config: () => IC.query(A, 'get_deploy_config', ['text'], ['e2e-app']),
  list_push_tokens: () => IC.query(G, 'list_push_tokens', ['text'], ['e2e-app']),
  pending_icp_deposits: () => IC.query(A, 'pending_icp_deposits', [], []),
};
for (const [name, f] of Object.entries(reads)) {
  try { await f(); console.log('ok ' + name); } catch (e) { console.log('err ' + name + ': ' + e.message); }
}
EOF
  OUT=$(node "$WORK/reads.mjs" "$ROOT/browser/index.html" "$PORT" "$G" "$A" "$T" 2>&1 || true)
  for r in ledger cmc_rate get_site get_deploy_config list_push_tokens pending_icp_deposits; do
    expect "console query $r (page code, local origin)" "$OUT" "ok $r"
  done
fi

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
