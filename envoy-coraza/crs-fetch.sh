#!/usr/bin/env bash
# Copyright Coraza Kubernetes Operator contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Downloads the pinned CRS release and keeps only the files the filter includes.
# Usage: crs-fetch.sh [clean]
set -eu

# The tracked pin is the single source of truth for the embedded CRS release.
# A bump must update this file; this script and build.rs both verify against it.
# The pin is read as data and never interpolated into shell code.
pin="envoy-coraza/crs.pin"
# Fixed on purpose: this script removes the tree. CRS_DIR is also a documented
# CRS *checkout* variable in the FTW harness, so it must not be reused as a
# delete target. build.rs expects exactly envoy-coraza/crs.
dir="envoy-coraza/crs"

if [ "${1:-}" = "clean" ]; then
	rm -rf "$dir"
	exit 0
fi

if [ ! -f "$pin" ]; then echo "error: missing CRS pin $pin; check out the repository and run make crs-fetch" >&2; exit 1; fi
if ! read -r version sha extra < "$pin"; then echo "error: cannot read CRS pin $pin" >&2; exit 1; fi
case "$version" in
	v[0-9]*.[0-9]*.[0-9]*) ;;
	*) echo "error: CRS pin version '$version' must match vN.N.N" >&2; exit 1 ;;
esac
case "$version$sha" in
	*[!0-9A-Za-z._-]*) echo "error: CRS pin contains characters outside [0-9A-Za-z._-]" >&2; exit 1 ;;
esac
if [ -z "$sha" ] || [ "${#sha}" -ne 64 ] || [ -n "$extra" ]; then
	echo "error: CRS pin must be exactly '<version> <64-char sha256>'" >&2; exit 1
fi

# Restamps a locally modified tree: keeps the pinned release and tarball sha as
# provenance, recomputes the file count the marker and build.rs verify.
if [ "${1:-}" = "restamp" ]; then
	count="$(find "$dir" -type f ! -name '.version' -print 2>/dev/null | wc -l | tr -d ' ')"
	printf '%s %s %s\n' "$version" "$sha" "$count" > "$dir/.version"
	echo "Restamped $dir against CRS $version ($count files)"
	exit 0
fi

release="${version#v}"
url="https://github.com/coreruleset/coreruleset/releases/download/$version/coreruleset-$release-minimal.tar.gz"
marker="$dir/.version"
count="$(find "$dir" -type f ! -name '.version' -print 2>/dev/null | wc -l | tr -d ' ')"
if [ -f "$marker" ] \
	&& [ "$(cat "$marker")" = "$version $sha $count" ] \
	&& [ -f "$dir/crs-setup.conf.example" ] \
	&& [ -n "$(find "$dir/rules" -maxdepth 1 -type f -name '*.conf' -print -quit 2>/dev/null)" ]; then
	echo "CRS $version is already fetched in $dir"
	exit 0
fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if command -v sha256sum >/dev/null 2>&1; then
	sha_tool=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
	sha_tool=(shasum --algorithm 256)
else
	echo "error: sha256sum (or shasum) is required to verify the CRS tarball" >&2; exit 1
fi
echo "Fetching CRS $version from $url"
curl --fail --silent --show-error --location --retry 3 --retry-all-errors --output "$tmp/crs.tar.gz" "$url"
if ! printf '%s  %s\n' "$sha" "$tmp/crs.tar.gz" | "${sha_tool[@]}" --check --strict; then
	echo "error: CRS $version tarball does not match the pinned SHA256 $sha" >&2
	exit 1
fi
if [ -d "$marker" ]; then rm -rf "$marker"; else rm -f "$marker"; fi
rm -rf "$dir"
mkdir -p "$dir"
tar --extract --gzip --no-same-owner --no-same-permissions --file "$tmp/crs.tar.gz" --directory "$dir" --strip-components=1 \
	"coreruleset-$release/rules" "coreruleset-$release/crs-setup.conf.example" "coreruleset-$release/LICENSE"
find "$dir" -type f ! -name '.version' -print > "$tmp/files" 2>/dev/null \
	|| { echo "error: cannot count the fetched CRS tree in $dir" >&2; exit 1; }
count="$(wc -l < "$tmp/files" | tr -d ' ')"
printf '%s %s %s\n' "$version" "$sha" "$count" > "$marker"
