#!/usr/bin/env bash
# Build only an immutable Git archive, never a reference checkout's working tree.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ${DEVRES_TMP_STATE:-} != 1 ]]; then
  exec "$repo/scripts/with-tmp-state.sh" "$0" "$@"
fi
revision=4f3154d8db0e0a49bce7a528c0a0f4c36d169040
scratch=$(mktemp -d "$TMPDIR/devres-oxibelt.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
source_checkout=${OXIBELT_SOURCE:-"$scratch/git"}
if [[ -z ${OXIBELT_SOURCE:-} ]]; then
  git init -q "$source_checkout"
  git -C "$source_checkout" fetch --depth 1 https://github.com/OxiBelt/OxiBelt.git "$revision"
fi
test "$(git -C "$source_checkout" rev-parse "$revision^{commit}")" = "$revision"
mkdir "$scratch/source"
git -C "$source_checkout" archive "$revision" | tar -x -C "$scratch/source"
target_dir=$(realpath -m -- "${OXIBELT_TARGET_DIR:-$DEVRES_TMP_ROOT/oxibelt-target}")
OXIBELT_BUILD_VERSION=0.0.0-dev.g4f3154d8 \
OXIBELT_BUILD_REVISION="$revision" OXIBELT_BUILD_REF=unknown \
OXIBELT_BUILD_DIRTY=clean OXIBELT_BUILD_KIND=git_development \
CARGO_TARGET_DIR="$target_dir" CARGO_PROFILE_DEV_DEBUG=0 \
  cargo build --manifest-path "$scratch/source/Cargo.toml" -p oxibelt --bin oxibelt \
    --locked --no-default-features --features admin-runtime -j "${OXIBELT_BUILD_JOBS:-2}"
"$target_dir/debug/oxibelt" --version | python3 -c '
import json,sys
lines=sys.stdin.read().splitlines()
identity=next((json.loads(line.split("=",1)[1]) for line in lines if line.startswith("OXIBELT_BUILD_IDENTITY_V1=")),None)
assert identity and identity.get("revision")==sys.argv[1] and identity.get("dirty")=="clean", "wrong OxiBelt build identity"
print("Pinned OxiBelt identity verified",file=sys.stderr)
' "$revision"
printf '%s\n' "$target_dir/debug/oxibelt"
