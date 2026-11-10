#!/usr/bin/env bash
# Explicit opt-in only. Run via the privileged channel when sharing Cargo caches.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $# != 2 || ! ${1:-} =~ ^--(live|resume|initialize)$ || ${2:-} != /tmp/* ]]; then
  echo 'usage: scripts/deployment-live-probe.sh --live NEW_ROOT | --resume OWNED_ROOT | --initialize NEW_ROOT (no network; below /tmp)' >&2
  exit 2
fi
revision=a938112b5af87996661ddd91ae68755dc0d579b9
# Tooling may be added on top of this release, but released runtime/library source
# and dependency resolution must remain exact. This does not stamp another image.
git cat-file -e "$revision^{commit}"
git diff --exit-code "$revision" -- crates/adapters/src crates/application/src crates/domain/src Cargo.lock Cargo.toml crates/domain/Cargo.toml crates/application/Cargo.toml >/dev/null
python3 - "$revision" <<'PY'
import pathlib
import subprocess
import sys
import tomllib

path = "crates/adapters/Cargo.toml"
baseline = tomllib.loads(subprocess.check_output(["git", "show", f"{sys.argv[1]}:{path}"], text=True))
current = tomllib.loads(pathlib.Path(path).read_text())
# Adding a private example is allowed; changing library features/dependencies is not.
baseline.pop("example", None)
current.pop("example", None)
if baseline != current:
    raise SystemExit("Released adapter manifest changed; source acceptance refused")
PY
export CARGO_TARGET_DIR=/tmp/rust/target TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1
exec cargo run --locked -p devres-adapters --example deployment-live-probe -- "$@"
