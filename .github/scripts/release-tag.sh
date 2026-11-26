#!/usr/bin/env bash
# Classify a pushed release tag for the release workflow.
#
# Usage: release-tag.sh TAG < existing-tags   (one tag per line, e.g. `git tag --list 'v*'`)
#
# Prints, for $GITHUB_ENV:
#   GORELEASER_CURRENT_TAG=TAG  GoReleaser must release the pushed tag, not whichever tag it
#                               finds first at HEAD (an RC sorts above its final tag there).
#   PUSH_LATEST=true|false      true only for the highest final tag; prereleases and older
#                               (backport) finals never take `latest`.
# Exits 1 for a tag that is not strict semver (vX.Y.Z or vX.Y.Z-prerelease, no build metadata:
# Docker tags cannot contain `+`), so a typo cannot publish anything.
set -euo pipefail
export LC_ALL=C

tag="${1:?usage: release-tag.sh TAG < existing-tags}"

num='(0|[1-9][0-9]*)'
ident='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
final="^v${num}\.${num}\.${num}\$"
semver="^v${num}\.${num}\.${num}(-${ident}(\.${ident})*)?\$"

if ! [[ $tag =~ $semver ]]; then
  echo "::error::Tag '${tag}' is not strict semver (vX.Y.Z or vX.Y.Z-prerelease); refusing to release" >&2
  exit 1
fi

push_latest=false
if [[ $tag =~ $final ]]; then
  # The pushed tag is always a candidate; keep strict final tags only (v1.2, v1.2.3.4 never count).
  newest="$({ cat; echo "$tag"; } | grep -E "$final" | sort -V | tail -n 1)"
  [[ $newest == "$tag" ]] && push_latest=true
fi

echo "GORELEASER_CURRENT_TAG=${tag}"
echo "PUSH_LATEST=${push_latest}"
