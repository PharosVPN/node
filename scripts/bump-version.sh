#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Semantic-version bump for this component. Reads + writes ./VERSION.
#   scripts/bump-version.sh [major|minor|patch] [--tag]
# With no part given, it ASKS which part to bump. --tag also creates git tag vX.Y.Z.
set -euo pipefail
cd "$(dirname "$0")/.."
part=""; tag=0
for a in "$@"; do case "$a" in
  major|minor|patch) part="$a";;
  --tag) tag=1;;
  *) echo "usage: $0 [major|minor|patch] [--tag]" >&2; exit 2;;
esac; done
cur="$(tr -d '[:space:]' < VERSION)"; base="${cur%%-*}"
IFS=. read -r ma mi pa <<< "$base"
if [ -z "$part" ]; then
  echo "Current version: $cur"
  echo "  patch -> $ma.$mi.$((pa+1))    (bug fixes, no API change)"
  echo "  minor -> $ma.$((mi+1)).0    (new features, back-compatible)"
  echo "  major -> $((ma+1)).0.0    (breaking changes)"
  read -rp "Bump which part? [patch/minor/major] (default patch): " part
  part="${part:-patch}"
  case "$part" in major|minor|patch) ;; *) echo "unknown part: $part" >&2; exit 2;; esac
fi
case "$part" in
  major) ma=$((ma+1)); mi=0; pa=0;;
  minor) mi=$((mi+1)); pa=0;;
  patch) pa=$((pa+1));;
esac
new="$ma.$mi.$pa"; printf '%s\n' "$new" > VERSION
echo "VERSION: $cur -> $new"
[ "$tag" = 1 ] && git tag "v$new" && echo "tagged v$new"
exit 0
