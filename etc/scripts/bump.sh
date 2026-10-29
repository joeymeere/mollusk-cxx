#!/usr/bin/env bash
# Move mollusk-cxx onto a new mollusk-svm release
#
#   etc/scripts/bump.sh 0.16.5
set -euo pipefail

ver="${1:?usage: bump.sh <mollusk-svm version>}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

lock_url="https://raw.githubusercontent.com/anza-xyz/mollusk/${ver}/Cargo.lock"

curl -fsSL "$lock_url" -o Cargo.lock.upstream ||
    { echo "bump: no Cargo.lock at Mollusk tag ${ver}" >&2; exit 1; }
mv Cargo.lock.upstream Cargo.lock

sed -E -i.bak "s/^(mollusk-svm(-programs-token)? = \")=[^\"]+/\1=${ver}/" Cargo.toml
sed -E -i.bak "s/^(#define MOLLUSK_UPSTREAM_VERSION[[:space:]]+)\"[^\"]+\"/\1\"${ver}\"/" \
    include/mollusk.h
rm -f Cargo.toml.bak include/mollusk.h.bak

cargo metadata --format-version 1 >/dev/null

msrv="$(cargo metadata --format-version 1 |
    python3 -c 'import json,sys
pk=[p for p in json.load(sys.stdin)["packages"] if p["name"]=="mollusk-svm"]
print(pk[0].get("rust_version") or "")')"
echo "bump: mollusk-svm ${ver} (declares rust-version ${msrv:-unset})"
echo "bump: build with 'make lib test'; if Agave crates need a newer rustc,"
echo "      raise rust-toolchain.toml and rust-version in Cargo.toml together"
