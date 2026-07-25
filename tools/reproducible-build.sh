#!/usr/bin/env bash
# Reproducible build of the ic-git canister, and (optionally) proof that the
# deployed canister runs exactly this source. (R1: verifiable backend.)
# See REPRODUCIBLE_BUILD.md.
#
#   tools/reproducible-build.sh            build natively (host dfx), print sha256
#   tools/reproducible-build.sh --docker   build in the pinned container (portable)
#   tools/reproducible-build.sh --check    also diff the result vs the IC module hash
#
# The IC module hash is the sha256 of the deployed wasm module, so a matching
# sha256 here means the running code is byte-identical to this tree -- verified
# from the IC's own certified state, without trusting the deployer.
#
# For a real third-party verification use --docker (fixes the toolchain, dfx
# version, and build path); the native path is a convenience that is only
# meaningful when the host already matches rust-toolchain.toml + dfx 0.31.0.
set -euo pipefail
cd "$(dirname "$0")/.."

CANISTER=umobs-yiaaa-aaaab-agyrq-cai
use_docker=0
do_check=0
for arg in "$@"; do
  case "$arg" in
    --docker) use_docker=1 ;;
    --check)  do_check=1 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if [ "$use_docker" = 1 ]; then
  command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
  docker build -f Dockerfile.build -t ic-git-build .
  built=$(docker run --rm ic-git-build | awk '{print $1}')
else
  command -v dfx >/dev/null || { echo "dfx not found; try --docker" >&2; exit 1; }
  dfx build --network ic git >/dev/null
  wasm=.dfx/ic/canisters/git/git.wasm
  [ -f "$wasm" ] || wasm=$(ls .dfx/*/canisters/git/git.wasm | head -1)
  built=$(shasum -a 256 "$wasm" | awk '{print $1}')
fi
echo "built module sha256 : $built"

if [ "$do_check" = 1 ]; then
  onchain=$(dfx canister --network ic info "$CANISTER" 2>/dev/null \
            | awk '/Module hash/{print $3}' | sed 's/^0x//')
  echo "on-chain module hash: ${onchain:-<unreadable>}"
  if [ -n "$onchain" ] && [ "$built" = "$onchain" ]; then
    echo "MATCH -- $CANISTER is running exactly this source."
  else
    echo "MISMATCH -- deployed code differs from this source tree."
    echo "(expected after local edits; rebuild from the attested commit to compare.)"
    exit 1
  fi
fi
