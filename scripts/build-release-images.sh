#!/usr/bin/env bash
# Produce version-stamped native OCI artifacts after verified ordinary CI reuse.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# != 4 ]]; then
  echo 'usage: build-release-images.sh linux/amd64|linux/arm64 /tmp/ABS_OUTPUT TAG COMMIT' >&2
  exit 2
fi
platform=$1
output=$2
tag=$3
commit=$4
case "$platform" in linux/amd64|linux/arm64) ;; *) echo 'Unsupported native platform' >&2; exit 2 ;; esac
output=$(python3 - "$output" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
if not path.is_absolute() or Path('/tmp') not in path.resolve().parents:
    raise SystemExit('release image output must resolve below /tmp')
if path.exists() or path.is_symlink():
    raise SystemExit('refusing to replace release image output')
print(path.resolve())
PY
)
scripts/check-native-platform.sh "$platform"
scripts/verify-release-tag.sh "$tag" "$commit"
version=$(python3 scripts/release_contract.py stamp --tag "$tag" --commit "$commit")
export TMPDIR=/tmp CARGO_TARGET_DIR=/buildcache/rust/target
mkdir -p -- "$(dirname -- "$output")"
mkdir -- "$output"
for target in server probe audit-worker; do
  scripts/test-image.sh --platform "$platform" --target "$target" \
    --revision "$commit" --version "$version" --oci-output "$output/$target"
  python3 scripts/release_images.py verify --directory "$output/$target" \
    --target "$target" --arch "${platform#linux/}" --tag "$tag" --commit "$commit" \
    --output "$output/verified-$target.json"
done
