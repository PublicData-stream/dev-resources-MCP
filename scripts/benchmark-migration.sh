#!/usr/bin/env bash
# Bounded synthetic fixtures only. Never use a retained/provider/staging pair.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
original_args=("$@")
binary=${MIGRATION_BENCHMARK_BINARY:-/tmp/rust/target/release/examples/migration-benchmark}
repeats=3
workers='1 4 8 16 32'
rows=128
payload_kib=256
files=16
file_mib=8
payload_budget_mib=64
while (( $# )); do
  case "$1" in
    --binary|--repeats|--workers|--rows|--payload-kib|--files|--file-mib|--payload-budget-mib)
      [[ $# -ge 2 && -n $2 && $2 != -* ]] || { echo 'benchmark option requires a value' >&2; exit 2; }
      case "$1" in
        --binary) binary=$2 ;; --repeats) repeats=$2 ;; --workers) workers=$2 ;;
        --rows) rows=$2 ;; --payload-kib) payload_kib=$2 ;; --files) files=$2 ;;
        --file-mib) file_mib=$2 ;; --payload-budget-mib) payload_budget_mib=$2 ;;
      esac
      shift 2 ;;
    --help) echo 'usage: scripts/benchmark-migration.sh [--binary PATH] [--repeats N>=3] [--workers "1 4 8 16 32"] [--rows N] [--payload-kib N] [--files N] [--file-mib N] [--payload-budget-mib N]'; exit 0 ;;
    *) echo 'unknown benchmark option' >&2; exit 2 ;;
  esac
done
for value in "$repeats" "$rows" "$payload_kib" "$files" "$file_mib" "$payload_budget_mib"; do
  [[ $value =~ ^[1-9][0-9]{0,4}$ ]] || { echo 'invalid bounded positive benchmark option' >&2; exit 2; }
done
(( repeats >= 3 && repeats <= 10 && rows <= 4096 && payload_kib <= 2048 && files <= 128 && file_mib <= 32 && payload_budget_mib <= 4096 )) || { echo 'benchmark option exceeds its bounded range' >&2; exit 2; }
[[ -x $binary ]] || { echo 'build the release migration-benchmark example first, or pass --binary' >&2; exit 2; }
read -r -a matrix <<< "$workers"
[[ ${matrix[0]:-} == 1 ]] || { echo 'workers must start with the serial reference 1' >&2; exit 2; }
previous=0
for value in "${matrix[@]}"; do
  [[ $value =~ ^[1-9][0-9]?$ ]] && (( value <= 64 && value > previous )) || { echo 'workers must be strictly increasing integers in 1..64' >&2; exit 2; }
  previous=$value
done
if [[ ${DEVRES_TMP_STATE:-} != 1 ]]; then
  exec scripts/with-tmp-state.sh env CARGO_TARGET_DIR=/tmp/rust/target OXIBELT_TARGET_DIR=/tmp/rust/target "$0" "${original_args[@]}"
fi
if [[ -z ${DEVRES_DOCKER_HOST:-} ]]; then
  exec scripts/with-local-docker.sh "$0" "${original_args[@]}"
fi
export DOCKER_HOST="$DEVRES_DOCKER_HOST"
unset DOCKER_CONTEXT
for command in docker python3 sha256sum nproc timeout; do command -v "$command" >/dev/null; done
[[ -x /usr/bin/time ]] || { echo '/usr/bin/time is required' >&2; exit 2; }
root=$(mktemp -d "$TMPDIR/devres-migration-benchmark.XXXXXX")
run_id="devres-benchmark-$$-${root##*.}"
postgres_image=postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a
cleanup() {
  status=$?
  if [[ $(docker inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$run_id" 2>/dev/null) == "$run_id" ]]; then docker rm -fv "$run_id" >/dev/null 2>&1 || true; fi
  if [[ $(docker network inspect --format '{{index .Labels "devres.test-owner"}}' "$run_id" 2>/dev/null) == "$run_id" ]]; then docker network rm "$run_id" >/dev/null 2>&1 || true; fi
  printf 'Synthetic benchmark output retained: %s\n' "$root" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 scripts/migration-benchmark-report.py metadata "$binary" "$(git rev-parse HEAD)" \
  "repeats=$repeats" "workers=$workers" "rows=$rows" "payload_kib=$payload_kib" \
  "files=$files" "file_mib=$file_mib" "payload_budget_mib=$payload_budget_mib" \
  'postgres_cpus=2' 'postgres_memory=1GiB' 'worker_cpu_quota=host/cgroup' 'fixture_durability=checkpoint+syncfs_before_timing' 'revision_is_checkout_head_not_source_attestation=true' > "$root/metadata.json"
df -PT "$root" > "$root/filesystem.txt"
# A private bridge permits the loopback-only published SQL port. Docker
# discards published-port mappings on internal-only bridges. No provider work runs.
docker network create --label "devres.test-owner=$run_id" "$run_id" >/dev/null
docker run -d --name "$run_id" --label "devres.test-owner=$run_id" --network "$run_id" \
  --cpus=2 --memory=1g -e POSTGRES_USER=devres -e POSTGRES_PASSWORD=fixture-only \
  -e POSTGRES_DB=postgres -p 127.0.0.1::5432 "$postgres_image" >/dev/null
for attempt in {1..60}; do
  if docker exec "$run_id" pg_isready -U devres -d postgres >/dev/null 2>&1; then break; fi
  if (( attempt == 60 )); then echo 'benchmark PostgreSQL readiness timed out' >&2; exit 1; fi
  sleep 1
done
port=$(docker port "$run_id" 5432/tcp | sed 's/.*://')
[[ $port =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= 65535 )) || { echo 'benchmark PostgreSQL loopback port unavailable' >&2; exit 1; }
psql() { docker exec "$run_id" psql -U devres -d postgres -v ON_ERROR_STOP=1 -q -c "$1" >/dev/null; }
headroom=$(( $(nproc) - 2 ))
(( headroom >= 1 )) || headroom=1
for worker in "${matrix[@]}"; do
  if (( worker > headroom )); then printf 'Stopped worker matrix at available CPU headroom (%s workers).\n' "$headroom" >&2; break; fi
  for (( repeat=1; repeat<=repeats; repeat++ )); do
    output="$root/workers-$worker/repeat-$repeat"
    mkdir -p "$output"
    export DEVRES_TEST_DATABASE_URL="postgres://devres:fixture-only@127.0.0.1:$port/devres_benchmark"
    psql 'CREATE DATABASE devres_benchmark'
    "$binary" prepare "$output/blobs" "$rows" "$payload_kib" "$files" "$file_mib" > "$output/fixture.json" 2> "$output/prepare.stderr"
    # Fresh identical pair per run. Preparation, backup and restore are not timed as migration.
    /usr/bin/time -v -o "$output/process-time.txt" timeout --signal=TERM --kill-after=30s 15m \
      "$binary" run "$output/blobs" "$worker" "$payload_budget_mib" > "$output/result.json" 2> "$output/progress.jsonl"
    /usr/bin/time -v -o "$output/backup-time.txt" sh -eu -c '
      docker exec "$1" pg_dump -U devres -d devres_benchmark -Fc > "$2/database.dump"
      cp -a -- "$2/blobs" "$2/restored-blobs"
    ' sh "$run_id" "$output"
    psql 'CREATE DATABASE devres_benchmark_restored'
    /usr/bin/time -v -o "$output/restore-time.txt" sh -eu -c '
      docker exec -i "$1" pg_restore -U devres -d devres_benchmark_restored --exit-on-error < "$2/database.dump"
    ' sh "$run_id" "$output"
    export DEVRES_TEST_DATABASE_URL="postgres://devres:fixture-only@127.0.0.1:$port/devres_benchmark_restored"
    /usr/bin/time -v -o "$output/restored-startup-time.txt" "$binary" check "$output/restored-blobs" > "$output/restored.json" 2> "$output/restored.stderr"
    psql 'DROP DATABASE devres_benchmark WITH (FORCE)'
    psql 'DROP DATABASE devres_benchmark_restored WITH (FORCE)'
    rm -rf -- "$output/blobs" "$output/restored-blobs" "$output/database.dump"
  done
  python3 scripts/migration-benchmark-report.py summarize "$root" --repeats "$repeats" > "$root/summary.json"
  if python3 scripts/migration-benchmark-report.py summarize "$root" --repeats "$repeats" --continue-after "$worker"; then
    :
  else
    status=$?
    if (( status == 3 )); then echo 'Stopped increasing workers: median throughput improved by less than two percent.' >&2; break; fi
    exit "$status"
  fi
done
cat "$root/summary.json"
