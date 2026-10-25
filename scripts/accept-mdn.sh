#!/usr/bin/env bash
# Explicit retained acceptance; never a production or disposable fixture database.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
test "$#" = 2 && [[ $1 == --live || $1 == --resume ]] && [[ $2 == full || $2 == current ]] || {
  echo 'usage: scripts/accept-mdn.sh --live current|full | --resume full' >&2; exit 2;
}
if [[ -z ${DEVRES_MDN_ACCEPTANCE_ROOT:-} ]]; then
  [[ $1 == --live ]] || { echo 'resume requires DEVRES_MDN_ACCEPTANCE_ROOT' >&2; exit 2; }
  export DEVRES_MDN_ACCEPTANCE_ROOT
  DEVRES_MDN_ACCEPTANCE_ROOT=$(mktemp -d /tmp/devres-mdn-retained.XXXXXX)
  printf 'devres-mdn-retained-acceptance-v1\n' > "$DEVRES_MDN_ACCEPTANCE_ROOT/owner-v1"
fi
test "$(cat "$DEVRES_MDN_ACCEPTANCE_ROOT/owner-v1")" = devres-mdn-retained-acceptance-v1 || { echo 'Unowned acceptance directory' >&2; exit 1; }
if [[ -f $DEVRES_MDN_ACCEPTANCE_ROOT/volume.json ]] && ! mountpoint -q "$DEVRES_MDN_ACCEPTANCE_ROOT/native"; then
  echo 'Retained native volume is not mounted; restore the mount recorded in volume.json before resuming' >&2
  exit 1
fi
mkdir -p "$DEVRES_MDN_ACCEPTANCE_ROOT/blobs" "$DEVRES_MDN_ACCEPTANCE_ROOT/postgres"
run_id="devres-mdn-acceptance-$$"
cleanup() {
  status=$?
  if [[ $(docker inspect --format '{{index .Config.Labels "devres.mdn-acceptance-owner"}}' "$run_id" 2>/dev/null) == "$DEVRES_MDN_ACCEPTANCE_ROOT" ]]; then docker rm -f "$run_id" >/dev/null 2>&1 || true; fi
  echo "Retained MDN evidence: $DEVRES_MDN_ACCEPTANCE_ROOT" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker run -d --name "$run_id" --label "devres.mdn-acceptance-owner=$DEVRES_MDN_ACCEPTANCE_ROOT" \
  -e POSTGRES_USER=devres -e POSTGRES_PASSWORD=acceptance-only -e POSTGRES_DB=devres \
  -v "$DEVRES_MDN_ACCEPTANCE_ROOT/postgres:/var/lib/postgresql" -p 127.0.0.1::5432 \
  postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a >/dev/null
for attempt in {1..60}; do
  if docker exec "$run_id" pg_isready -U devres >/dev/null 2>&1; then break; fi
  if (( attempt == 60 )); then echo 'Acceptance PostgreSQL readiness failed' >&2; exit 1; fi
  sleep 1
done
port=$(docker port "$run_id" 5432/tcp | sed 's/.*://')
export DATABASE_URL="postgres://devres:acceptance-only@127.0.0.1:$port/devres"
export BLOB_DIR="$DEVRES_MDN_ACCEPTANCE_ROOT/blobs"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/buildcache/rust/target}
cargo build --locked -p devres-adapters --example mdn-probe
"$CARGO_TARGET_DIR/debug/examples/mdn-probe" "$@"
