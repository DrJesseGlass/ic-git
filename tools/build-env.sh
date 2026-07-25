# Sourced, never executed. POSIX sh: Dockerfile.build sources this with
# /bin/sh inside its build step, and tools/reproducible-build.sh sources it for
# a native build. One definition, so the container hash and the native hash
# cannot drift apart -- which is the whole point, since a reproducible build
# whose two paths disagree proves nothing.
#
# What it does: rustc bakes absolute dependency source paths into the module's
# data section (panic locations, file!()), so an unremapped build embeds
# hundreds of strings like
# /Users/<someone>/.cargo/registry/src/index.crates.io-<hash>/lazy_static-1.5.0/...
# and the wasm hash becomes a function of where the builder keeps their cargo
# registry. Remapping CARGO_HOME to a fixed /cargo token is what actually makes
# the artifact machine-independent; a fixed WORKDIR does not touch those paths.
#
# In the container CARGO_HOME is /usr/local/cargo (set by the rust:*-slim base)
# and the source root is already /build, so the second mapping is an identity
# no-op there; natively both differ and both are rewritten.
#
# Why a shell fragment and not Cargo configuration: at the pinned 1.94.1 there
# is no declarative form that works. .cargo/config.toml does not interpolate
# environment variables, so it cannot express the host's CARGO_HOME; an
# exported RUSTFLAGS silently DISCARDS [build] rustflags rather than merging
# with it, so a config file plus this fragment would leave the file's mapping
# quietly unapplied; and [profile] trim-paths, the feature designed for exactly
# this, is not stabilized in 1.94.1. Revisit when the pin moves.
#
# Must be sourced from the source root (both callers already are).
RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$(pwd -P)=/build${RUSTFLAGS:+ $RUSTFLAGS}"
export RUSTFLAGS
