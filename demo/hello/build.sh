#!/usr/bin/env bash
# Build the demo canister and stage it as the repo that gets pushed to ic-git.
#
#   demo/hello/build.sh --git-canister ID --git-origin URL --repo NAME [--out DIR]
#
# The three coordinates are compiled into the module (env! in src/lib.rs),
# so the page can only describe the deployment it belongs to; setup.sh
# passes the ones it resolved. Produces DIR (default demo/hello/dist)
# holding exactly what the deploy reads: the source, and app.wasm at the
# path named by set_wasm_deploy(repo, "app", "app.wasm").
set -euo pipefail
cd "$(dirname "$0")"
out=dist
git_id=""; git_origin=""; repo=""
while [ $# -gt 0 ]; do
  case "$1" in
    --git-canister) git_id=$2; shift 2 ;;
    --git-origin)   git_origin=$2; shift 2 ;;
    --repo)         repo=$2; shift 2 ;;
    --out)          out=$2; shift 2 ;;
    -h|--help)      sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
if [ -z "$git_id" ] || [ -z "$git_origin" ] || [ -z "$repo" ]; then
  echo "usage: build.sh --git-canister ID --git-origin URL --repo NAME [--out DIR]" >&2
  exit 2
fi

HELLO_IC_GIT=$git_id HELLO_GIT_ORIGIN=$git_origin HELLO_REPO=$repo \
  cargo build --release --target wasm32-unknown-unknown
wasm=target/wasm32-unknown-unknown/release/hello_canister.wasm

mkdir -p "$out/src"
cp Cargo.toml Cargo.lock hello.did build.sh "$out/"
cp src/lib.rs src/index.html "$out/src/"
cp "$wasm" "$out/app.wasm"

echo "staged $out"
echo "app.wasm  $(wc -c < "$out/app.wasm") bytes  sha256 $(shasum -a 256 "$out/app.wasm" | cut -d' ' -f1)"
