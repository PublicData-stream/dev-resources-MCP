#!/usr/bin/env bash
# Confine generated tool/test state to an owned /tmp directory; retain it for reuse.
# Seed cargo/rustup caches separately by copying them, never by hard-linking them.
set -euo pipefail
test "$#" -gt 0 || { echo 'usage: scripts/with-tmp-state.sh COMMAND [ARG ...]' >&2; exit 2; }
state=$(PYTHONDONTWRITEBYTECODE=1 python3 - "${DEVRES_TMP_ROOT:-/tmp/devres-state-$UID}" <<'PY'
import os
from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve()
if root == Path('/tmp') or Path('/tmp') not in root.parents:
    raise SystemExit('temporary state root must resolve below /tmp')
root.mkdir(parents=True, exist_ok=True)
if root.stat().st_uid != os.getuid():
    raise SystemExit('temporary state root is owned by another user')
marker = root / 'devres-tmp-state-v1'
expected = f'devres-tmp-state-v1:{os.getuid()}\n'
try:
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except FileExistsError:
    if marker.is_symlink() or marker.read_text() != expected:
        raise SystemExit('temporary state ownership marker mismatch')
else:
    with os.fdopen(fd, 'w') as output:
        output.write(expected)
for name in ('cargo', 'rustup', 'target', 'oxibelt-target', 'tmp', 'cache',
             'python-cache', 'docker-client', 'minikube', 'kube', 'runtime', 'pnpm'):
    child = root / name
    if child.is_symlink():
        raise SystemExit('temporary state child must not be a symlink')
    child.mkdir(exist_ok=True)
print(root)
PY
)
export DEVRES_TMP_ROOT="$state" DEVRES_TMP_STATE=1
export CARGO_HOME="$state/cargo" RUSTUP_HOME="$state/rustup"
export CARGO_TARGET_DIR="$state/target" OXIBELT_TARGET_DIR="$state/oxibelt-target"
export TMPDIR="$state/tmp" TMP="$state/tmp" TEMP="$state/tmp"
export XDG_CACHE_HOME="$state/cache" XDG_RUNTIME_DIR="$state/runtime"
export PYTHONPYCACHEPREFIX="$state/python-cache"
export DOCKER_CONFIG="$state/docker-client" MINIKUBE_HOME="$state/minikube"
export KUBECONFIG="$state/kube/config" PNPM_HOME="$state/pnpm"
export npm_config_cache="$state/cache/npm" npm_config_store_dir="$state/cache/pnpm"
# Existing toolchain executables remain discoverable; their mutable state is isolated.
exec "$@"
