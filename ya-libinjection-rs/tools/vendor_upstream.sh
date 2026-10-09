#!/bin/sh
# Refresh tests/upstream from a libinjection checkout, then regenerate the
# tables ported from it.
#
#     tools/vendor_upstream.sh path/to/libinjection
#
# Copied over: the library sources (the differential oracle is built from
# them), the expected-output tests and the sample corpora.
set -eu

src=${1:?usage: $0 path/to/libinjection}
root=$(cd "$(dirname "$0")/.." && pwd)
dst=$root/tests/upstream

rm -rf "$dst"
mkdir -p "$dst/src" "$dst/tests" "$dst/data"
cp "$src/COPYING" "$dst/"
cp "$src"/src/libinjection*.c "$src"/src/libinjection*.h "$dst/src/"
cp "$src"/tests/test-*.txt "$dst/tests/"
cp "$src"/data/*.txt "$dst/data/"
{
    git -C "$src" describe --tags --always
    git -C "$src" rev-parse HEAD
} >"$dst/REVISION"

python3 "$root/tools/gen_tables.py"
