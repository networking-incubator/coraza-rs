#!/usr/bin/env bash
# Table test for release-tag.sh: every tag shape from the PR #195 review.
set -euo pipefail
cd "$(dirname "$0")"

fail=0
# check TAG EXPECT existing-tags...   EXPECT is PUSH_LATEST=true|false or "invalid"
check() {
  local tag=$1 want=$2 out got
  shift 2
  if out="$(printf '%s\n' "$@" | ./release-tag.sh "$tag" 2>/dev/null)"; then
    got="$(grep '^PUSH_LATEST=' <<<"$out")"
    grep -qx "GORELEASER_CURRENT_TAG=${tag}" <<<"$out" || got="wrong GORELEASER_CURRENT_TAG"
  else
    got=invalid
  fi
  if [[ $got != "$want" ]]; then
    echo "FAIL: $tag want '$want' got '$got' (existing: $*)"
    fail=1
  fi
}

# final tags: only the highest final takes latest
check v0.0.3 PUSH_LATEST=true v0.0.2 v0.0.3 v0.0.3-rc.1 v0.0.3-rc.2
check v0.0.10 PUSH_LATEST=true v0.0.9 v0.0.10
check v0.0.2 PUSH_LATEST=false v0.0.2 v0.1.0 # backport after a newer final
check v1.0.0 PUSH_LATEST=true               # first final release
# a stray non-semver tag never freezes latest
check v0.0.3 PUSH_LATEST=true v0.0.2 v0.0.3 v9.9.9.9 v1.2 v1 v01.2.3 v1.2.3+meta v1.2.3-
# prereleases never take latest, even above every final
check v0.0.3-rc.2 PUSH_LATEST=false v0.0.2 v0.0.3-rc.1 v0.0.3-rc.2
check v9.0.0-rc.1 PUSH_LATEST=false v0.0.2 v9.0.0-rc.1
check v1.2.3-alpha PUSH_LATEST=false v1.2.3-alpha
check v1.2.3-rc.1-hotfix PUSH_LATEST=false v1.2.3-rc.1-hotfix
check v0.0.0-nightly.20261126 PUSH_LATEST=false v0.0.0-nightly.20261126
# not strict semver: fail the run
for bad in v1.2 v1 v9.9.9.9 v1.2.3- v01.2.3 v1.2.3-01 V1.2.3 1.2.3 v1.2.3+build v1.2.3+build-5 v1.2.3-rc.1+build.5 v1.2.3-rc..1 v1.2.3-rc_1; do
  check "$bad" invalid "$bad" v0.0.2
done

((fail == 0)) && echo "release-tag tests passed"
exit "$fail"
