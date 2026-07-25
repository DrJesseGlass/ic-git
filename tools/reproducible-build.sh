#!/usr/bin/env bash
# Reproducible build of the ic-git canister, and (optionally) proof that the
# deployed canister runs exactly this source. (R1: verifiable backend.)
# See REPRODUCIBLE_BUILD.md.
#
#   tools/reproducible-build.sh            build natively (host dfx), print sha256
#   tools/reproducible-build.sh --docker   build in the pinned container (portable)
#   tools/reproducible-build.sh --check    also diff the result vs the IC module hash
#   tools/reproducible-build.sh --allow-dirty  build a tree with uncommitted edits
#
# The IC module hash is the sha256 of the deployed wasm module, so a matching
# sha256 here means the running code is byte-identical to this tree -- verified
# from the IC's own certified state, without trusting the deployer.
#
# For a real third-party verification use --docker (fixes the toolchain, dfx
# version, platform, and every path baked into the wasm); the native path is a
# convenience that is only meaningful when the host already matches
# rust-toolchain.toml + dfx 0.31.0. Either way, build through this script: it
# applies the --remap-path-prefix mapping that makes the hash machine-
# independent, which a bare `dfx build` does not.
#
# Exit codes: 0 match (or no --check), 1 mismatch, 2 usage, 3 could not read
# the on-chain hash (which is NOT a mismatch and must not be reported as one).
set -euo pipefail
cd "$(dirname "$0")/.."

CANISTER=umobs-yiaaa-aaaab-agyrq-cai
use_docker=0
do_check=0
allow_dirty=0
for arg in "$@"; do
  case "$arg" in
    --docker) use_docker=1 ;;
    --check)  do_check=1 ;;
    --allow-dirty) allow_dirty=1 ;;
    -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

# Which tree is being built. An attestation names a commit, so a hash produced
# from a working tree with local edits must never be presented as that commit's
# hash: the container build copies the working tree and .git is excluded from
# the build context, so nothing downstream can detect the difference.
commit=unknown
if git rev-parse --git-dir >/dev/null 2>&1; then
  commit=$(git rev-parse HEAD)
  if [ -n "$(git status --porcelain)" ]; then
    if [ "$allow_dirty" = 1 ]; then
      commit="$commit-dirty"
      echo "WARNING: building a dirty tree; the resulting hash belongs to no commit." >&2
    else
      echo "refusing to build: the working tree has uncommitted changes." >&2
      echo "Reproduce from a clean checkout of the attested commit, or pass" >&2
      echo "--allow-dirty for a local experiment (never for an attestation)." >&2
      exit 2
    fi
  fi
fi
echo "source commit       : $commit"

if [ "$use_docker" = 1 ]; then
  command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
  docker build -f Dockerfile.build --build-arg SOURCE_COMMIT="$commit" \
    -t ic-git-build .
  built=$(docker run --rm ic-git-build | awk 'NR==1{print $1}')
else
  command -v dfx >/dev/null || { echo "dfx not found; try --docker" >&2; exit 1; }
  # Match the container's path normalization. rustc bakes dependency source
  # paths into the wasm data section, so without this the native hash is a
  # function of this machine's cargo registry location and can never equal a
  # container build's. The container remaps /usr/local/cargo -> /cargo; do the
  # same for whatever CARGO_HOME this host uses, and map the source root to the
  # container's fixed /build. Keep these two mappings in sync with
  # Dockerfile.build's RUSTFLAGS.
  cargo_home=${CARGO_HOME:-$HOME/.cargo}
  export RUSTFLAGS="--remap-path-prefix=${cargo_home}=/cargo --remap-path-prefix=$(pwd -P)=/build${RUSTFLAGS:+ $RUSTFLAGS}"
  dfx build --network ic git >/dev/null
  wasm=.dfx/ic/canisters/git/git.wasm
  [ -f "$wasm" ] || wasm=$(ls .dfx/*/canisters/git/git.wasm | head -1)
  built=$(shasum -a 256 "$wasm" | awk '{print $1}')
fi
echo "built module sha256 : $built"

if [ "$do_check" = 1 ]; then
  # Read the on-chain hash without letting `set -e`/`pipefail` abort the script:
  # a plain assignment takes the pipeline's status, so a missing dfx or a failed
  # boundary-node call would kill the run here and print no verdict at all.
  # Keep stderr so the reason is visible instead of silently discarded.
  info_err=$(mktemp)
  onchain=""
  if info=$(dfx canister --network ic info "$CANISTER" 2>"$info_err"); then
    onchain=$(printf '%s\n' "$info" | awk '/Module hash/{print $3}' | sed 's/^0x//')
  fi
  if [ -z "$onchain" ]; then
    echo "on-chain module hash: <unreadable>"
    echo "could not read the on-chain module hash -- this is NOT a mismatch." >&2
    if command -v dfx >/dev/null; then
      sed 's/^/  dfx: /' "$info_err" >&2 || true
    else
      echo "  dfx not found on PATH (the --docker build does not require it," >&2
      echo "  but --check does; install dfx or read the hash yourself:" >&2
      echo "  https://dashboard.internetcomputer.org/canister/$CANISTER)" >&2
    fi
    rm -f "$info_err"
    exit 3
  fi
  rm -f "$info_err"
  echo "on-chain module hash: $onchain"
  if [ "$built" = "$onchain" ]; then
    echo "MATCH -- $CANISTER is running exactly this source."
  else
    echo "MISMATCH -- deployed code differs from this source tree."
    echo "(expected after local edits; rebuild from the attested commit to compare.)"
    exit 1
  fi
fi
