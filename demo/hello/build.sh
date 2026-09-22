#!/usr/bin/env bash
# Build the demo canister and stage it as the repo that gets pushed to ic-git.
#
#   demo/hello/build.sh [outdir]
#
# Produces <outdir> (default demo/hello/dist) holding exactly what the deploy
# reads: the source, and app.wasm at the path named by
# set_wasm_deploy(repo, "app", "app.wasm").
set -euo pipefail
cd "$(dirname "$0")"
out=${1:-dist}

cargo build --release --target wasm32-unknown-unknown
wasm=target/wasm32-unknown-unknown/release/hello_canister.wasm

mkdir -p "$out/src"
cp Cargo.toml Cargo.lock hello.did build.sh "$out/"
cp src/lib.rs src/index.html "$out/src/"
cp "$wasm" "$out/app.wasm"

echo "staged $out"
echo "app.wasm  $(wc -c < "$out/app.wasm") bytes  sha256 $(shasum -a 256 "$out/app.wasm" | cut -d' ' -f1)"
