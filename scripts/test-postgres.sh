#!/usr/bin/env bash
# Disposable PostgreSQL. Requires Docker and the pinned Rust toolchain.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
scratch=$(mktemp -d)
token=${scratch##*/}
run_id="devres-postgres-$$-${token,,}"
postgres_image=postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a
cleanup() {
  if [[ $(docker inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$run_id" 2>/dev/null) == "$run_id" ]]; then
    docker rm -fv "$run_id" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker run -d --name "$run_id" --label devres.test-owner="$run_id" \
  -e POSTGRES_USER=devres -e POSTGRES_PASSWORD=fixture-only -e POSTGRES_DB=devres \
  -p 127.0.0.1::5432 "$postgres_image" >/dev/null
for attempt in {1..60}; do
  if docker exec "$run_id" pg_isready -h 127.0.0.1 -U devres -d devres >/dev/null 2>&1; then break; fi
  if (( attempt == 60 )); then echo 'PostgreSQL readiness timed out' >&2; exit 1; fi
  sleep 1
done
port=$(docker port "$run_id" 5432/tcp | sed 's/.*://')
export DATABASE_URL="postgres://devres:fixture-only@127.0.0.1:$port/devres"
export DEVRES_TEST_DATABASE_URL="$DATABASE_URL"
cargo test --locked -p devres-adapters --test persistence -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --test migration_batching -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --test seal_owner_loss -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --test file_migration_batching -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --test mdn_persistence -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --test whatwg_persistence -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --test w3c_persistence -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --test chromium_persistence -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --test npm_persistence -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --lib mdn_corpus_git_postgres_history_research_restart_and_restore -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --lib crate_corpus_captured_inventory_acquisition_research_and_restart -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --lib storage::payload_integrity -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --lib storage::sequence_integrity -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --lib storage::acceptance -- --ignored --test-threads=1
cargo test --locked -p devres-adapters --lib storage::visibility -- --ignored --test-threads=1
echo 'Real PostgreSQL persistence checks passed'
