#!/usr/bin/env bash
# Seed a local git repository into an ic-git canister repo via the admin API.
# A stand-in for push until milestone 3 lands.
#
# Usage: tools/seed-repo.sh <path-to-git-repo> <canister-repo-name>
#
# Limitations: annotated tag objects are not uploaded (rev-list --objects
# does not enumerate them), and each object must fit in one ingress message
# (< ~1.9 MiB).
set -euo pipefail

src=$1
name=$2

dfx canister call git create_repo "(\"$name\")" >/dev/null 2>&1 || true

arg_file=$(mktemp)
trap 'rm -f "$arg_file"' EXIT

count=0
while read -r oid; do
    t=$(git -C "$src" cat-file -t "$oid")
    hex=$(git -C "$src" cat-file "$t" "$oid" | xxd -p | tr -d '\n' | sed 's/../\\&/g')
    printf '("%s", blob "%s")' "$t" "$hex" > "$arg_file"
    got=$(dfx canister call git put_object --argument-file "$arg_file" \
        | sed -n 's/.*Ok = "\([0-9a-f]*\)".*/\1/p')
    if [ "$got" != "$oid" ]; then
        echo "oid mismatch for $oid: canister returned '$got'" >&2
        exit 1
    fi
    count=$((count + 1))
done < <(git -C "$src" rev-list --objects --all | cut -d' ' -f1 | sort -u)
echo "uploaded $count objects"

git -C "$src" for-each-ref refs/heads refs/tags --format='%(refname) %(objectname)' \
| while read -r ref oid; do
    dfx canister call git set_ref "(\"$name\", \"$ref\", \"$oid\")" >/dev/null
    echo "ref $ref -> $oid"
done
