#!/usr/bin/env bash
# Stand up the deploy-on-push demo: a repo on the ic-git canister, an app
# canister of its own, and a `git push` that deploys into it.
#
#   demo/hello/setup.sh [--network local|ic] [--identity NAME] [--repo NAME]
#
# Every step is idempotent, so a failed run can be repeated. The caller must
# be an ic-git operator (see list_authorized) or a tenant with a funded
# balance; an operator's repo is exempt from charges and its app canister is
# created from the ic-git canister's own cycles.
set -euo pipefail
cd "$(dirname "$0")"

network=local
identity=""
repo=hello
app_cycles=1000000000000   # 1T, apps::MIN_CREATE_CYCLES

while [ $# -gt 0 ]; do
  case "$1" in
    --network)  network=$2; shift 2 ;;
    --identity) identity=$2; shift 2 ;;
    --repo)     repo=$2; shift 2 ;;
    -h|--help)  sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

dfxc=(dfx canister --network "$network")
[ -n "$identity" ] && dfxc+=(--identity "$identity")

say() { printf '\n== %s\n' "$*"; }
# Ok payload of a candid Result, or "" for Err. Errors that a rerun should
# tolerate (already exists) are handled by the callers.
ok_text() { sed -n 's/.*Ok = "\([^"]*\)".*/\1/p'; }
ok_principal() { sed -n 's/.*Ok = principal "\([^"]*\)".*/\1/p'; }

git_id=$("${dfxc[@]}" id git)
say "ic-git canister: $git_id (network $network)"

# The `raw.` gateway is the one git talks to: the certifying gateway rejects
# a dynamic smart-HTTP response (README, "Quick start").
if [ "$network" = ic ]; then
  scheme=https; host="$git_id.raw.icp0.io"
  app_origin() { echo "https://$1.raw.icp0.io"; }
else
  port=$(dfx info webserver-port)
  scheme=http; host="$git_id.raw.localhost:$port"
  app_origin() { echo "http://$1.raw.localhost:$port"; }
fi
origin="$scheme://$host"

say "build the demo canister"
./build.sh >/dev/null
wasm_sha=$(shasum -a 256 dist/app.wasm | cut -d' ' -f1)
echo "app.wasm $(wc -c < dist/app.wasm) bytes, sha256 $wasm_sha"

say "repo '$repo'"
out=$("${dfxc[@]}" call git create_repo "(\"$repo\")" 2>&1 || true)
case "$out" in
  *"Ok"*)            echo "created" ;;
  *"already exists"*) echo "already exists" ;;
  *) echo "create_repo failed: $out" >&2; exit 1 ;;
esac

say "app canister"
info=$("${dfxc[@]}" call git get_repo_info "(\"$repo\")" 2>&1)
app=$(echo "$info" | sed -n 's/.*app_canister = opt principal "\([^"]*\)".*/\1/p')
if [ -z "$app" ]; then
  out=$("${dfxc[@]}" call git create_app_canister "(\"$repo\", $app_cycles : nat64)" 2>&1)
  app=$(echo "$out" | ok_principal)
  [ -n "$app" ] || { echo "create_app_canister failed: $out" >&2; exit 1; }
  echo "created $app"
else
  echo "already had $app"
fi

say "point the deploy at it"
"${dfxc[@]}" call git set_wasm_deploy "(\"$repo\", \"app\", \"app.wasm\")" >/dev/null
echo "app.wasm in the pushed commit -> $app"

say "push token"
token=$("${dfxc[@]}" call git create_push_token "(\"$repo\")" 2>&1 | ok_text)
[ -n "$token" ] || { echo "create_push_token failed" >&2; exit 1; }
echo "minted"

say "git push"
# A fresh history each run: the point of the demo is the push, and the repo
# on the canister keeps whatever it was pushed before.
rm -rf dist/.git
git -C dist init -q -b main
git -C dist add -A
git -C dist -c user.name="ic-git demo" -c user.email="demo@ic-git.invalid" \
    commit -q -m "Hello from a canister deployed by git push

app.wasm sha256 $wasm_sha"
commit=$(git -C dist rev-parse HEAD)
echo "commit $commit"
# The token is the credential; it goes in the URL git is handed, not in
# anything this script prints.
git -C dist push -q --force "$scheme://ic:$token@$host/$repo.git" main
echo "pushed to $origin/$repo.git"

say "deploy"
for i in $(seq 1 30); do
  st=$("${dfxc[@]}" call git get_deploy_status "(\"$repo\")" 2>&1 || true)
  case "$st" in
    *deploying*) sleep 2; continue ;;
    *"ok = true"*) echo "$st" | sed -n 's/.*message = "\([^"]*\)".*/deployed: \1/p'; break ;;
    *"ok = false"*) echo "deploy failed:"; echo "$st"; exit 1 ;;
    *) sleep 2 ;;
  esac
  [ "$i" = 30 ] && { echo "timed out waiting for the deploy; last status:"; echo "$st"; exit 1; }
done

url=$(app_origin "$app")
say "done"
echo "demo app:   $url/"
echo "repo:       $origin/site/ic-git/#/$repo"
echo "commit:     $commit"
echo "app.wasm:   $wasm_sha"
