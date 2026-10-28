#!/usr/bin/env bash
set -euo pipefail
test "$#" = 2 || { echo 'usage: build-harness.sh SCRATCH IMAGE' >&2; exit 2; }
scratch=$1
image=$2
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
command -v strip >/dev/null || { echo 'strip is required to stage harness binaries' >&2; exit 1; }
if [[ -z ${SERVER_BINARY:-} || -z ${PROBE_BINARY:-} ]]; then cargo build --workspace --bins --locked; fi
cargo build --locked -p devres-adapters --example storage-probe --bin devres-audit-worker --bin devres-pdf-worker
target_dir=$(cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
edge_binary=${OXIBELT_BINARY:-}
if [[ -z $edge_binary ]]; then edge_binary=$(scripts/build-oxibelt.sh | tail -n 1); fi
"$edge_binary" --version | python3 -c '
import json,sys
identity=next((json.loads(line.split("=",1)[1]) for line in sys.stdin.read().splitlines() if line.startswith("OXIBELT_BUILD_IDENTITY_V1=")),None)
assert identity and identity.get("revision")=="4f3154d8db0e0a49bce7a528c0a0f4c36d169040" and identity.get("dirty")=="clean", "wrong edge binary"
'
mkdir -p "$scratch/build/bin" "$scratch/build/scripts"
if docker image inspect "$image" >/dev/null 2>&1; then
  echo 'Refusing to overwrite an existing harness image tag' >&2; exit 1
fi
cp "${SERVER_BINARY:-$target_dir/debug/devres-server}" "$scratch/build/bin/devres-server"
cp "${PROBE_BINARY:-$target_dir/debug/devres-probe}" "$scratch/build/bin/devres-probe"
cp "$target_dir/debug/examples/storage-probe" "$scratch/build/bin/storage-probe"
cp "$target_dir/debug/devres-audit-worker" "$scratch/build/bin/devres-audit-worker"
cp "$target_dir/debug/devres-pdf-worker" "$scratch/build/bin/devres-pdf-worker"
cp "$edge_binary" "$scratch/build/bin/oxibelt"
# Remove debug information only from disposable copies, preserving shared builds.
for binary in devres-server devres-probe storage-probe devres-audit-worker devres-pdf-worker oxibelt; do
  strip --strip-debug "$scratch/build/bin/$binary"
done
cp scripts/mcp_smoke.py "$scratch/build/scripts/"
cp deploy/oxibelt/Dockerfile.harness "$scratch/build/Dockerfile"
docker build --label "devres.test-owner=$image" -t "$image" "$scratch/build"
