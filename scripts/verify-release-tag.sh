#!/usr/bin/env bash
# Read-only release identity fence, repeated immediately before publication.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
test "$#" -ge 2 && test "$#" -le 3 || { echo 'usage: verify-release-tag.sh TAG COMMIT [TAG_OBJECT]' >&2; exit 2; }
tag=$1
commit=$2
python3 scripts/release_contract.py validate --tag "$tag" --commit "$commit" >/dev/null
ref="refs/tags/$tag"
test "$(git cat-file -t "$ref")" = tag
test "$(git rev-parse "$ref^{commit}")" = "$commit"
test "$(git rev-parse HEAD)" = "$commit"
git fetch --no-tags origin main:refs/remotes/origin/main
git merge-base --is-ancestor "$commit" refs/remotes/origin/main
object=$(git rev-parse "$ref")
test "$object" = "${3:-$object}"
remote=$(git ls-remote --exit-code --refs origin "$ref")
test "$remote" = "${object}"$'\t'"${ref}"
printf '%s\n' "$object"
