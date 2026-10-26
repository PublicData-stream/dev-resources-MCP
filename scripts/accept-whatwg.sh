#!/usr/bin/env bash
# Explicit retained WHATWG acceptance; never delete its database or public captures.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
case "${1:-}:${2:-}:$#" in
  --live:current:2|--live:full:2|--resume:full:2) ;;
  *) echo 'usage: scripts/accept-whatwg.sh --live current|full | --resume full' >&2; exit 2 ;;
esac
if [[ ${DEVRES_TMP_STATE:-} != 1 ]]; then
  exec "$repo/scripts/with-tmp-state.sh" "$0" "$@"
fi
if [[ -z ${DEVRES_WHATWG_ACCEPTANCE_ROOT:-} ]]; then
  [[ $1 == --live ]] || { echo 'resume requires DEVRES_WHATWG_ACCEPTANCE_ROOT' >&2; exit 2; }
  DEVRES_WHATWG_ACCEPTANCE_ROOT=$(mktemp -d "$TMPDIR/devres-whatwg-retained.XXXXXX")
  export DEVRES_WHATWG_ACCEPTANCE_ROOT
  printf 'devres-whatwg-retained-acceptance-v1\n' > "$DEVRES_WHATWG_ACCEPTANCE_ROOT/owner-v1"
fi
DEVRES_WHATWG_ACCEPTANCE_ROOT=$(python3 - "$DEVRES_WHATWG_ACCEPTANCE_ROOT" <<'PY'
import os
from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve(strict=True)
if root == Path('/tmp') or Path('/tmp') not in root.parents or root.stat().st_uid != os.getuid():
    raise SystemExit('Retained acceptance requires an owned directory below /tmp')
marker = root / 'owner-v1'
if marker.is_symlink() or not marker.is_file() or marker.read_bytes() != b'devres-whatwg-retained-acceptance-v1\n':
    raise SystemExit('Unowned WHATWG acceptance directory')
for name in ('postgres', 'blobs', 'acceptance.lock', 'frozen.json'):
    if (root / name).is_symlink():
        raise SystemExit('Retained acceptance state must not be symlinked')
print(root)
PY
)
export DEVRES_WHATWG_ACCEPTANCE_ROOT
printf 'Retained WHATWG evidence: %s\n' "$DEVRES_WHATWG_ACCEPTANCE_ROOT" >&2
exec 9> "$DEVRES_WHATWG_ACCEPTANCE_ROOT/acceptance.lock"
flock -n 9 || { echo 'Retained WHATWG acceptance is already running for this directory' >&2; exit 1; }
if [[ $1 == --resume ]]; then
  [[ -f $DEVRES_WHATWG_ACCEPTANCE_ROOT/frozen.json ]] || { echo 'resume requires a retained frozen observation' >&2; exit 1; }
elif [[ -e $DEVRES_WHATWG_ACCEPTANCE_ROOT/frozen.json ]]; then
  echo 'Frozen observation already exists; use --resume full or a new retained directory' >&2; exit 1
fi
running=$(docker ps -q --filter "label=devres.whatwg-acceptance-owner=$DEVRES_WHATWG_ACCEPTANCE_ROOT")
[[ -z $running ]] || { echo 'Retained WHATWG PostgreSQL is still running for this directory' >&2; exit 1; }
# Build before starting PostgreSQL; all build/cache paths come from with-tmp-state.
cargo build --release --locked -p devres-adapters --example whatwg-probe --bin devres-pdf-worker
# PDF parsing resolves a fixed sibling worker, including for this release example.
install -m 755 "$CARGO_TARGET_DIR/release/devres-pdf-worker" "$CARGO_TARGET_DIR/release/examples/devres-pdf-worker"
mkdir -p "$DEVRES_WHATWG_ACCEPTANCE_ROOT/blobs" "$DEVRES_WHATWG_ACCEPTANCE_ROOT/postgres"
run_id="devres-whatwg-acceptance-$$"
cleanup() {
  status=$?
  if [[ $(docker inspect --format '{{index .Config.Labels "devres.whatwg-acceptance-owner"}}' "$run_id" 2>/dev/null) == "$DEVRES_WHATWG_ACCEPTANCE_ROOT" ]]; then
    docker stop --time 30 "$run_id" >/dev/null 2>&1 || true
    docker rm -f "$run_id" >/dev/null 2>&1 || true
  fi
  printf 'Retained WHATWG evidence: %s\n' "$DEVRES_WHATWG_ACCEPTANCE_ROOT" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker run -d --name "$run_id" --label "devres.whatwg-acceptance-owner=$DEVRES_WHATWG_ACCEPTANCE_ROOT" \
  -e POSTGRES_USER=devres -e POSTGRES_PASSWORD=acceptance-only -e POSTGRES_DB=devres \
  -v "$DEVRES_WHATWG_ACCEPTANCE_ROOT/postgres:/var/lib/postgresql" -p 127.0.0.1::5432 \
  postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a >/dev/null
for attempt in {1..60}; do
  if docker exec "$run_id" pg_isready -h 127.0.0.1 -U devres -d devres >/dev/null 2>&1; then break; fi
  if (( attempt == 60 )); then echo 'Acceptance PostgreSQL readiness failed' >&2; exit 1; fi
  sleep 1
done
binding=$(docker port "$run_id" 5432/tcp)
port=${binding#127.0.0.1:}
[[ $binding == 127.0.0.1:* && $port =~ ^[0-9]+$ && $port -gt 0 && $port -le 65535 ]] || {
  echo 'Acceptance PostgreSQL port binding is invalid' >&2; exit 1;
}
export DATABASE_URL="postgres://devres:acceptance-only@127.0.0.1:$port/devres"
export BLOB_DIR="$DEVRES_WHATWG_ACCEPTANCE_ROOT/blobs"
"$CARGO_TARGET_DIR/release/examples/whatwg-probe" "$@"
