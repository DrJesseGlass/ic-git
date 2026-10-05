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
#   tools/e2e-local.sh                 # the whole pass
#   KEEP=1 tools/e2e-local.sh          # leave the network running after
#   E2E_PORT=4960 tools/e2e-local.sh   # another port (default 4950)
#   NAMES_REPO=../ic-name-service ...  # where ic-name-service is (optional)
#   BASE_REF=v0.2.2 tools/e2e-local.sh # the release to upgrade from (default:
#                                      # the newest tag); BASE_REF=none skips
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
# (BASE_REF) over state that release wrote through its own API -- from
# v0.3.x, a signing-required repo with a key-bound token and a gated site
# behind its tip, checking the state carries over unchanged and each rule
# still holds; from v0.2.x, an old-format token and a tip-serving site,
# checking each migration lands -- and in both, membership, votes and a
# name that only maps to a label; the console's query-backed reads
# through the page's own code, and the /api reads.
#
# Not covered: wallet writes (OISY signs mainnet only), the EVM leg (no EVM
# RPC locally), ICP recovery paths (lost reply, refund), expiry by time.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${E2E_PORT:-4950}
KEEP=${KEEP:-0}
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

section "build"
(cd "$ROOT" && cargo build -q --target wasm32-unknown-unknown --release -p git_canister)
GIT_WASM=$ROOT/target/wasm32-unknown-unknown/release/git_canister.wasm
NAMES_WASM=
if [ -d "$NAMES_REPO/canisters/names" ]; then
  (cd "$NAMES_REPO" && cargo build -q --target wasm32-unknown-unknown --release -p name_canister)
  NAMES_WASM=$NAMES_REPO/target/wasm32-unknown-unknown/release/name_canister.wasm
fi
echo "ic-git wasm: $GIT_WASM${NAMES_WASM:+; ic-name-service wasm: $NAMES_WASM}"
BASE_WASM=
if [ -n "$BASE_REF" ] && [ "$BASE_REF" != none ]; then
  # Built from a worktree of the release, into its own target dir so later
  # runs reuse it.
  BASE_SRC=$WORK/base-src
  git -C "$ROOT" worktree add -q --detach "$BASE_SRC" "$BASE_REF"
  (cd "$BASE_SRC" && CARGO_TARGET_DIR="$ROOT/target/e2e-base" cargo build -q --target wasm32-unknown-unknown --release -p git_canister)
  BASE_WASM=$ROOT/target/e2e-base/wasm32-unknown-unknown/release/git_canister.wasm
  echo "base release $BASE_REF: $BASE_WASM"
fi

section "network"
NAMES_ENTRY=
if [ -n "$NAMES_WASM" ]; then
  NAMES_ENTRY=",
    \"names\": { \"type\": \"custom\", \"wasm\": \"$NAMES_WASM\", \"candid\": \"$NAMES_REPO/canisters/names/names.did\", \"build\": [] }"
fi
cat > "$WORK/dfx.json" <<EOF
{
  "version": 1,
  "canisters": {
    "git": { "type": "custom", "wasm": "$GIT_WASM", "candid": "$ROOT/canisters/git/git.did", "build": [] },
    "base": { "type": "custom", "wasm": "$GIT_WASM", "candid": "$ROOT/canisters/git/git.did", "build": [] }$NAMES_ENTRY
  },
  "networks": { "local": { "bind": "127.0.0.1:$PORT", "type": "ephemeral" } }
}
EOF
(cd "$WORK" && dfx start --background --clean --system-canisters >"$WORK/replica.log" 2>&1)
(cd "$WORK" && dfx canister create git --identity "$OP" --no-wallet --with-cycles 50000000000000 >/dev/null 2>&1)
(cd "$WORK" && dfx canister install git --identity "$OP" --wasm "$GIT_WASM" >/dev/null 2>&1)
G=$(cd "$WORK" && dfx canister id git)
T=$(dfx identity get-principal --identity "$TEN")
HOST="$G.raw.localhost:$PORT"
echo "ic-git $G on 127.0.0.1:$PORT; tenant $T"

section "ICP deposit"
call anonymous "$ICP_LEDGER" icrc1_transfer "(record { to = record { owner = principal \"$T\"; subaccount = null }; amount = 10_000_000_000 : nat; fee = null; memo = null; from_subaccount = null; created_at_time = null })" >/dev/null
call "$TEN" "$ICP_LEDGER" icrc2_approve "(record { spender = record { owner = principal \"$G\"; subaccount = null }; amount = 100_010_000 : nat; expected_allowance = null; expires_at = null; fee = null; memo = null; from_subaccount = null; created_at_time = null })" >/dev/null
RATE=$(call "$OP" "$CMC" get_icp_xdr_conversion_rate '()' --query | sed -n 's/.*xdr_permyriad_per_icp = \([0-9_]*\).*/\1/p' | tr -d _)
OUT=$(call "$TEN" git deposit_from_icp '(100_000_000 : nat64)')
expect "deposit_from_icp credits exactly the CMC's cycles for 1 ICP" "$(echo "$OUT" | tr -d _)" "Ok = $((RATE * 100000000)) "
expect "nothing left pending" "$(call "$TEN" git pending_icp_deposits)" '^\(vec \{\}\)$'

section "push certificates"
KEY=$WORK/key
ssh-keygen -q -t ed25519 -N "" -C e2e@local -f "$KEY"
ssh-keygen -q -t ed25519 -N "" -C other@local -f "$WORK/otherkey"
call "$TEN" git create_repo '("e2e-app")' >/dev/null
BOUND=$(call "$TEN" git create_push_token "(\"e2e-app\", opt (7 : nat32), opt \"$(cat "$KEY.pub")\")" | ok_text)
PLAIN=$(call "$TEN" git create_push_token '("e2e-app", null, null)' | ok_text)
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
call "$TEN" git set_require_signed_push '("e2e-app", true)' >/dev/null
commit site/c.txt c v3
expect "unbound token, signing required: refused" "$(git -C "$W" push "$PURL" main 2>&1)" 'remote rejected.*requires signed pushes'
OUT=$(signed "$URL" || true)
expect "bound token, signed, signing required: accepted" "$OUT" 'main -> main'
refuse "  ...and not rejected" "$OUT" 'rejected'

section "tokens"
LIST=$(call "$TEN" git list_push_tokens '("e2e-app")')
expect "list shows both tokens, one with its key" "$(echo "$LIST" | grep -c 'id =')" '^2$'
expect "  ...the bound key" "$LIST" 'key = opt "ssh-ed25519 '
# The id of the record that carries a key.
ID=$(echo "$LIST" | awk '/record \{/{id=""; k=0} /id = "/{match($0,/"[0-9a-f]+"/); id=substr($0,RSTART+1,RLENGTH-2)} /key = opt/{k=1} k && id!=""{print id; exit}')
expect "revoke by id" "$(call "$TEN" git revoke_push_token_id "(\"$ID\")")" 'Ok'
commit site/d.txt d v4
expect "revoked token: authentication fails" "$(GIT_TERMINAL_PROMPT=0 signed "$URL")" 'Authentication failed|401'
git -C "$W" reset -q --hard HEAD~1
BOUND=$(call "$TEN" git create_push_token "(\"e2e-app\", null, opt \"$(cat "$KEY.pub")\")" | ok_text)
URL="http://ic:$BOUND@$HOST/e2e-app.git"

if command -v gpg >/dev/null; then
  section "GPG-signed certificate, unbound token"
  # A short GNUPGHOME: the agent's socket path has a length limit.
  export GNUPGHOME
  GNUPGHOME=$(mktemp -d /tmp/g.XXXXXX)
  gpg --batch --quiet --passphrase '' --quick-gen-key "E2E <gpg@local>" ed25519 sign never >/dev/null 2>&1
  GKEY=$(gpg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec/{print $5; exit}')
  call "$TEN" git create_repo '("e2e-gpg")' >/dev/null
  GT=$(call "$TEN" git create_push_token '("e2e-gpg", null, null)' | ok_text)
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
expect "tenant: evm_set_config refused" "$(call "$TEN" git evm_set_config '("x", "dfx_test_key", 11155111 : nat64, vec {})')" 'is not an operator'
expect "tenant: sol_send refused" "$(call "$TEN" git sol_send '("x", 1 : nat64)')" 'is not an operator'
expect "tenant: put_object refused" "$(call "$TEN" git put_object '("blob", blob "x")')" 'is not an operator'
refuse "operator: evm_reset_nonce passes the guard" "$(call "$OP" git evm_reset_nonce)" 'rror|not an operator'
# The change itself: a controller that is not on the allowlist is an operator
# here too (these calls used to check the allowlist alone). $OP is both, so
# make the tenant a controller for one call.
(cd "$WORK" && dfx canister update-settings git --add-controller "$T" --identity "$OP" >/dev/null)
refuse "controller not on the allowlist: evm_reset_nonce passes the guard" "$(call "$TEN" git evm_reset_nonce)" 'rror|not an operator'
# Billing follows the same rule: the tenant's repo is exempt while it is a
# controller, and pays again once it is not.
expect "  ...and its repo is exempt from charges" "$(call "$OP" git get_repo_info '("e2e-app")')" 'exempt = true'
(cd "$WORK" && dfx canister update-settings git --remove-controller "$T" --identity "$OP" >/dev/null)
expect "  ...and refused again once it is not a controller" "$(call "$TEN" git evm_reset_nonce)" 'is not an operator'
expect "  ...and its repo pays again" "$(call "$OP" git get_repo_info '("e2e-app")')" 'exempt = false'

section "approval-gated site"
SITE="http://$HOST/site/e2e-app/"
# "<status> <commit>" of a site's root: the X-Ic-Git-Commit header names it.
served_at() {
  curl -s -D "$WORK/h" -o "$WORK/b" "$1" -w '%{http_code} ' || true
  tr -d '\r' <"$WORK/h" | grep -i '^x-ic-git-commit:' | cut -d' ' -f2 || true
}
served() { served_at "$SITE"; }
call "$TEN" git set_site '("e2e-app", "site")' >/dev/null
TIP=$(git -C "$W" rev-parse HEAD)
expect "served at the tip without votes" "$(served)" "^200 $TIP"
call "$TEN" git set_required_votes '("e2e-app", 1 : nat32)' >/dev/null
expect "votes required, nothing approved: 404" "$(served)" '^404'
call "$TEN" git vote "(\"e2e-app\", \"$TIP\", true)" >/dev/null
expect "approved: served" "$(served)" "^200 $TIP"
commit site/index.html '<!doctype html><title>v2</title><h1>two</h1>' site-v2
signed "$URL" >/dev/null || true
NEW=$(git -C "$W" rev-parse HEAD)
expect "new push, unapproved: the approved commit stays up" "$(served)" "^200 $TIP"
call "$TEN" git vote "(\"e2e-app\", \"$NEW\", true)" >/dev/null
expect "new push approved: served" "$(served)" "^200 $NEW"
call "$TEN" git vote "(\"e2e-app\", \"$NEW\", false)" >/dev/null
expect "approval withdrawn: rolled back" "$(served)" "^200 $TIP"
call "$TEN" git vote "(\"e2e-app\", \"$NEW\", true)" >/dev/null

section "approval-gated deploy and announce"
if [ -n "$NAMES_WASM" ]; then
  (cd "$WORK" && dfx canister create names --identity "$OP" --no-wallet --with-cycles 20000000000000 >/dev/null 2>&1)
  (cd "$WORK" && dfx canister install names --identity "$OP" --wasm "$NAMES_WASM" >/dev/null 2>&1)
  N=$(cd "$WORK" && dfx canister id names)
  call "$OP" names add_deployer "(principal \"$G\")" >/dev/null
  expect "names hook configured" "$(call "$OP" git names_set_config "(\"$N\", \"solo\")")" 'Ok'
fi
APP=$(call "$TEN" git create_app_canister '("e2e-app", 1_000_000_000_000 : nat64)' | sed -n 's/.*principal "\([^"]*\)".*/\1/p')
expect "app canister created" "$APP" '-cai$'
call "$TEN" git set_wasm_deploy '("e2e-app", "app", "app.wat")' >/dev/null
commit app.wat '(module (func (export "canister_query hello")))' app-v1
signed "$URL" >/dev/null || true
A1=$(git -C "$W" rev-parse HEAD)
expect "push held for approval" "$(call "$TEN" git get_deploy_status '("e2e-app")')" 'awaiting voter approval'
call "$TEN" git vote "(\"e2e-app\", \"$A1\", true)" >/dev/null
STATUS=
for _ in $(seq 1 30); do
  STATUS=$(call "$TEN" git get_deploy_status '("e2e-app")')
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
call "$TEN" git add_member "(\"e2e-app\", principal \"$P1\", \"voter\")" >/dev/null
call "$TEN" git add_member "(\"e2e-app\", principal \"$P2\", \"voter\")" >/dev/null
commit app.wat '(module (func (export "canister_query hello")) (func (export "canister_query hi")))' app-v2
signed "$URL" >/dev/null || true
A2=$(git -C "$W" rev-parse HEAD)
expect "an objection without a reason is refused" "$(call "$V1" git cast_ballot "(\"e2e-app\", \"$A2\", variant { Object }, null)")" 'needs a reason'
expect "  ...and a blank one" "$(call "$V1" git cast_ballot "(\"e2e-app\", \"$A2\", variant { Object }, opt \"  \")")" 'needs a reason'
OUT=$(call "$V1" git cast_ballot "(\"e2e-app\", \"$A2\", variant { Object }, opt \"the second export is untested\")")
expect "objection recorded" "$OUT" 'objections = 1'
expect "  ...nothing approved" "$OUT" 'approvals = 0'
OUT=$(call "$TEN" git vote "(\"e2e-app\", \"$A2\", true)")
expect "one approval over one objection: 1 of 1 by the old count" "$OUT" 'Ok = record \{ 1 : nat32; 1 : nat32 \}'
expect "  ...but held: net 0" "$(call "$TEN" git get_deploy_status '("e2e-app")')" 'awaiting voter approval'
expect "  ...and the site stays on the commit before it" "$(served)" "^200 $A1"
VOTES=$(curl -s "http://$HOST/api/e2e-app/votes/$A2")
expect "/api votes: the objection with its reason" "$VOTES" '"decision":"object","approve":false,"reason":"the second export is untested"'
expect "  ...and the count" "$VOTES" '"approvals":1,"objections":1,"required":1,"reached":false'
# The wallet's consent message for an objection names the reason: OISY shows
# it to the signer. The encoded argument comes from the codec vectors.
ARG=$(cd "$ROOT" && cargo test -q -p git_canister --test candid_vectors -- --nocapture 2>/dev/null | awk '$1 == "args:cast_ballot_object" { print $2 }' | sed 's/../\\&/g')
CONSENT=$(call anonymous git icrc21_canister_call_consent_message "(record { method = \"cast_ballot\"; arg = blob \"$ARG\"; user_preferences = record { metadata = record { language = \"en\"; utc_offset_minutes = null }; device_spec = null } })")
expect "consent message: an objection, with its reason" "$CONSENT" 'Object to commit 0123456789ab.*Reason: skips the migration'
OUT=$(call "$V2" git cast_ballot "(\"e2e-app\", \"$A2\", variant { Approve }, null)")
expect "a second approval outweighs the objection" "$OUT" 'reached = true'
for _ in $(seq 1 30); do
  STATUS=$(call "$TEN" git get_deploy_status '("e2e-app")')
  echo "$STATUS" | grep -q "$A2" && echo "$STATUS" | grep -q 'ok = true' && break
  sleep 1
done
expect "  ...and it deploys" "$(printf '%s' "$STATUS" | tr '\n' ' ')" "ok = true.*commit = \"$A2\""
expect "  ...and is served" "$(served)" "^200 $A2"
# An objection after the deploy drops the commit below the threshold: the
# site rolls back to the approved commit before it, and so does the app,
# the same way a withdrawn approval does.
call "$V2" git cast_ballot "(\"e2e-app\", \"$A2\", variant { Object }, opt \"regressed in production\")" >/dev/null
expect "an objection after the deploy rolls the site back" "$(served)" "^200 $A1"
for _ in $(seq 1 30); do
  STATUS=$(call "$TEN" git get_deploy_status '("e2e-app")')
  echo "$STATUS" | grep -q "$A1" && echo "$STATUS" | grep -q 'ok = true' && break
  sleep 1
done
expect "  ...and the app" "$(printf '%s' "$STATUS" | tr '\n' ' ')" "ok = true.*commit = \"$A1\""
expect "  ...two objections on record" "$(curl -s "http://$HOST/api/e2e-app/votes/$A2")" '"objections":2'
# Withdrawing both (a rejection weighs nothing) approves it again.
call "$V1" git cast_ballot "(\"e2e-app\", \"$A2\", variant { Reject }, null)" >/dev/null
call "$V2" git cast_ballot "(\"e2e-app\", \"$A2\", variant { Reject }, null)" >/dev/null
expect "objections withdrawn: served again" "$(served)" "^200 $A2"
# Let the app's re-deploy finish before the canister is upgraded underneath it.
for _ in $(seq 1 30); do
  STATUS=$(call "$TEN" git get_deploy_status '("e2e-app")')
  echo "$STATUS" | grep -q "$A2" && echo "$STATUS" | grep -q 'ok = true' && break
  sleep 1
done
expect "  ...and deployed again" "$(printf '%s' "$STATUS" | tr '\n' ' ')" "ok = true.*commit = \"$A2\""

section "upgrade in place (same build)"
BEFORE=$(served)
(cd "$WORK" && dfx canister install git --mode upgrade --yes --identity "$OP" --wasm "$GIT_WASM" >/dev/null 2>&1)
expect "site unchanged" "$(served)" "^${BEFORE%% *} ${BEFORE#* }"
expect "tokens kept" "$(call "$TEN" git list_push_tokens '("e2e-app")' | grep -c 'id =')" '^[1-9]'
expect "balance kept" "$(call "$TEN" git get_account "(principal \"$T\")")" 'deposited = [1-9]'
expect "push-cert still offered (the seed survived)" "$(curl -s "http://ic:$BOUND@$HOST/e2e-app.git/info/refs?service=git-receive-pack" | tr '\0' ' ')" 'push-cert='
commit site/e.txt e after-upgrade
expect "signed push after upgrade" "$(signed "$URL")" 'main -> main'

if [ -n "$BASE_WASM" ]; then
  section "upgrade from $BASE_REF"
  # State written by the release mainnet starts from, through its own API
  # (its candid), then an upgrade to this build and a check per migration.
  OLD_DID=$BASE_SRC/canisters/git/git.did
  NEW_DID=$ROOT/canisters/git/git.did
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
  # The base's candid says which API wrote the state: v0.3.x takes
  # create_push_token's lifetime and key, v0.2.x only a repo name.
  if grep -q 'create_push_token : (text, opt nat32' "$OLD_DID"; then
    # v0.3.x wrote tokens with an expiry, a minter and optionally a key,
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
  else
    # A token in the old format (a bare repo name): no expiry, no minter.
    LT=$(old "$TEN" create_push_token '("legacy-app")' | ok_text)
    LURL="http://ic:$LT@$BHOST/legacy-app.git"
    echo '<!doctype html><title>l1</title>' >"$LW/index.html"; git -C "$LW" add -A; git -C "$LW" commit -qm l1
    expect "$BASE_REF: push with its token" "$(git -C "$LW" push "$LURL" main 2>&1 || true)" 'new branch'
    L1=$(git -C "$LW" rev-parse HEAD)
    old "$OP" set_site '("legacy-app", "")' >/dev/null
    old "$OP" set_required_votes '("legacy-app", 1 : nat32)' >/dev/null
    old "$OP" vote "(\"legacy-app\", \"$L1\", true)" >/dev/null
    echo '<!doctype html><title>l2</title>' >"$LW/index.html"; git -C "$LW" commit -qam l2
    git -C "$LW" push "$LURL" main >/dev/null 2>&1 || true
    L2=$(git -C "$LW" rev-parse HEAD)
    expect "$BASE_REF: serves the tip, approved or not" "$(served_at "$LSITE")" "^200 $L2"

    (cd "$WORK" && dfx canister install base --mode upgrade --yes --identity "$OP" --wasm "$GIT_WASM" >/dev/null 2>&1)
    expect "upgraded: the gated site serves its approved commit, not the tip" "$(served_at "$LSITE")" "^200 $L1"
    TOK=$(new "$TEN" list_push_tokens '("legacy-app")')
    expect "the old-format token is listed" "$(echo "$TOK" | grep -c 'id =')" '^1$'
    expect "  ...with no minter recorded" "$TOK" 'minted_by = null'
    EXP=$(echo "$TOK" | exp_of)
    NOW_S=$(date +%s)
    DAYS=$(( (EXP / 1000000000 - NOW_S + 43200) / 86400 ))
    expect "  ...expiring in the 30-day grace" "$DAYS" '^30$'
    echo x >"$LW/x.txt"; git -C "$LW" add -A; git -C "$LW" commit -qm l3
    expect "the old-format token still pushes" "$(git -C "$LW" push "$LURL" main 2>&1 || true)" 'main -> main'
    expect "the pushed commit is not served until approved" "$(served_at "$LSITE")" "^200 $L1"
    expect "push-cert offered (the nonce seed was created on upgrade)" "$(curl -s "$LURL/info/refs?service=git-receive-pack" | tr '\0' ' ')" 'push-cert='
  fi
  expect "the EVM nonce store starts empty (no pending tx carried over)" "$(new "$OP" evm_next_nonce)" '^\(null\)$'
  expect "a label taken by an old repo is refused" "$(new "$OP" create_repo '("legacy-name")')" "maps to the label .{0,2}legacy-name.{0,2}, which repo .{0,2}legacy[.]name"
  INFO=$(new "$OP" get_repo_info '("legacy-app")')
  expect "membership kept" "$INFO" "$T"
  expect "required votes kept" "$INFO" 'required_votes = 1'
fi

section "console reads"
for p in pricing e2e-app/info "account/$T" e2e-app/deploys; do
  expect "/api/$p" "$(curl -s "http://$HOST/api/$p")" '^\{'
done
if command -v node >/dev/null; then
  cat >"$WORK/reads.mjs" <<'EOF'
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
globalThis.crypto ??= webcrypto;
const [page, port, G, T] = process.argv.slice(2);
// As if the page were served by the local gateway.
globalThis.location = { hostname: 'localhost', origin: 'http://localhost:' + port };
const html = readFileSync(page, 'utf8');
const IC = new Function(html.slice(html.indexOf('// === candid ==='), html.indexOf('// === end candid ===')) + '\nreturn IC;')();
const ACCOUNT = { record: { owner: 'principal', subaccount: { opt: 'blob' } } };
const reads = {
  ledger: () => IC.query('ryjl3-tyaaa-aaaaa-aaaba-cai', 'icrc1_balance_of', [ACCOUNT], [{ owner: T, subaccount: null }]),
  cmc_rate: () => IC.query('rkp4c-7iaaa-aaaaa-aaaca-cai', 'get_icp_xdr_conversion_rate', [], []),
  get_site: () => IC.query(G, 'get_site', ['text'], ['e2e-app']),
  get_deploy_config: () => IC.query(G, 'get_deploy_config', ['text'], ['e2e-app']),
  list_push_tokens: () => IC.query(G, 'list_push_tokens', ['text'], ['e2e-app']),
  pending_icp_deposits: () => IC.query(G, 'pending_icp_deposits', [], []),
};
for (const [name, f] of Object.entries(reads)) {
  try { await f(); console.log('ok ' + name); } catch (e) { console.log('err ' + name + ': ' + e.message); }
}
EOF
  OUT=$(node "$WORK/reads.mjs" "$ROOT/browser/index.html" "$PORT" "$G" "$T" 2>&1 || true)
  for r in ledger cmc_rate get_site get_deploy_config list_push_tokens pending_icp_deposits; do
    expect "console query $r (page code, local origin)" "$OUT" "ok $r"
  done
fi

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
