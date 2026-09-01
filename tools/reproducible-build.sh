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
cleanup_paths=()
cleanup() { [ ${#cleanup_paths[@]} -eq 0 ] || rm -rf "${cleanup_paths[@]}"; }
trap cleanup EXIT

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
  # Build the COMMIT, not the directory. `git archive` gives docker a context
  # containing exactly the tracked files at $commit, so uncommitted edits are
  # absent by construction rather than merely refused above, and SOURCE_COMMIT
  # describes what was actually fed in instead of asserting it. --allow-dirty
  # falls back to the working tree, which is why that mode must never back an
  # attestation.
  if [ "$allow_dirty" = 1 ] || [ "$commit" = unknown ]; then
    ctx=.
  else
    ctx=$(mktemp -d)
    cleanup_paths+=("$ctx")
    git archive --format=tar "$commit" | tar -x -C "$ctx"
  fi
  # Take the Dockerfile from the context too, so the recipe and the sources it
  # builds come from the same commit rather than from the working tree.
  # Pull the base image explicitly so its resolved digest is readable
  # afterwards: a BuildKit-driven build (the default on CI runners) keeps
  # what it pulls out of the image store, and `docker image inspect` would
  # find nothing to report.
  base_image=$(sed -n 's/^ARG BASE_IMAGE=//p' "$ctx/Dockerfile.build" | head -1)
  docker pull --platform=linux/amd64 -q "$base_image" >/dev/null
  docker build -f "$ctx/Dockerfile.build" --build-arg SOURCE_COMMIT="$commit" \
    -t ic-git-build "$ctx"
  built=$(docker run --rm ic-git-build | awk 'NR==1{print $1}')
  # The resolved base-image digest belongs in the attested BuildDescriptor
  # (docs/ATTESTATION.md): the Dockerfile pins a tag by default, and a tag can
  # move. Print what was actually used so verified.json can record it.
  base_digest=$(docker image inspect --format '{{join .RepoDigests ","}}' "$base_image" 2>/dev/null || true)
  base_digest=${base_digest:-unknown}
  dfx_version=$(sed -n 's/^ARG DFX_VERSION=//p' "$ctx/Dockerfile.build" | head -1)
  echo "base image digest   : $base_digest"
  echo "dfx (in container)  : $dfx_version"
else
  command -v dfx >/dev/null || { echo "dfx not found; try --docker" >&2; exit 1; }
  # Assert the committed lockfile actually resolves the manifest before
  # building. dfx does not pass --locked to cargo, and CARGO_NET_LOCKED is not
  # a Cargo setting -- measured against cargo 1.94.1, it does not prevent a
  # rewrite -- so without this a stale Cargo.lock is silently updated and the
  # resulting hash describes dependency versions nobody attested.
  cargo metadata --locked --format-version 1 >/dev/null
  lock_before=$(shasum -a 256 Cargo.lock | awk '{print $1}')
  # The same path normalization the container applies, from the same file, so
  # the native and container hashes cannot drift apart. Without it the native
  # hash is a function of this machine's cargo registry location.
  . ./tools/build-env.sh
  dfx build --network ic git >/dev/null
  if [ "$(shasum -a 256 Cargo.lock | awk '{print $1}')" != "$lock_before" ]; then
    echo "Cargo.lock changed during the build; the artifact does not match the" >&2
    echo "committed lockfile. Restore it (git checkout -- Cargo.lock) or commit" >&2
    echo "the update deliberately, then rebuild." >&2
    exit 1
  fi
  wasm=.dfx/ic/canisters/git/git.wasm
  [ -f "$wasm" ] || wasm=$(ls .dfx/*/canisters/git/git.wasm | head -1)
  built=$(shasum -a 256 "$wasm" | awk '{print $1}')
fi
echo "built module sha256 : $built"

if [ "$do_check" = 1 ]; then
  # `|| onchain=""` is load-bearing: a plain assignment takes the pipeline's
  # status, so under `set -e`/`pipefail` a missing dfx or a failed boundary-node
  # call would kill the run here and print no verdict at all. Keep stderr so the
  # reason is visible instead of silently discarded.
  info_err=$(mktemp)
  cleanup_paths+=("$info_err")
  # A read needs no identity, and dfx refuses insecurely stored ones on
  # mainnet (a fresh CI runner's default identity is exactly that), so ask as
  # anonymous unless the caller says otherwise. dfx still verifies the
  # certificate, so the hash is the subnet's word, not the boundary node's.
  onchain=$(dfx canister --network ic --identity "${DFX_IDENTITY:-anonymous}" info "$CANISTER" 2>"$info_err" \
            | awk '/Module hash/{sub(/^0x/, "", $3); print $3}') || onchain=""
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
    exit 3
  fi
  echo "on-chain module hash: $onchain"
  if [ "$built" = "$onchain" ]; then
    echo "MATCH -- $CANISTER is running exactly this source."
  else
    echo "MISMATCH -- deployed code differs from this source tree."
    echo "(expected after local edits; rebuild from the attested commit to compare.)"
    exit 1
  fi
fi
