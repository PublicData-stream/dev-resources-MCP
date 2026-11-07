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
graph_memory_budget_mib=1024
graph_snapshots=0
graph_generations=1
crate_artifacts=0
crate_staging_rows=1024
baseline_binary=
baseline_revision=unattested
while (( $# )); do
  case "$1" in
    --binary|--repeats|--workers|--rows|--payload-kib|--files|--file-mib|--payload-budget-mib|--graph-memory-budget-mib|--graph-snapshots|--graph-generations|--crate-artifacts|--crate-staging-rows|--baseline-binary|--baseline-revision)
      [[ $# -ge 2 && -n $2 && $2 != -* ]] || { echo 'benchmark option requires a value' >&2; exit 2; }
      case "$1" in
        --binary) binary=$2 ;; --repeats) repeats=$2 ;; --workers) workers=$2 ;;
        --rows) rows=$2 ;; --payload-kib) payload_kib=$2 ;; --files) files=$2 ;;
        --file-mib) file_mib=$2 ;; --payload-budget-mib) payload_budget_mib=$2 ;;
        --graph-memory-budget-mib) graph_memory_budget_mib=$2 ;; --graph-snapshots) graph_snapshots=$2 ;;
        --graph-generations) graph_generations=$2 ;;
        --crate-artifacts) crate_artifacts=$2 ;; --crate-staging-rows) crate_staging_rows=$2 ;;
        --baseline-binary) baseline_binary=$2 ;; --baseline-revision) baseline_revision=$2 ;;
      esac
      shift 2 ;;
    --help) echo 'usage: scripts/benchmark-migration.sh [--binary PATH] [--repeats N>=3] [--workers "1 4 8 16 32"] [--rows N] [--payload-kib N] [--files N] [--file-mib N] [--payload-budget-mib N] [--graph-memory-budget-mib N] [--graph-snapshots 0..64] [--graph-generations N<=snapshots, default 1] [--crate-artifacts 1..16384] [--crate-staging-rows 1..16384] [--baseline-binary PATH --baseline-revision SHA] (crate profile fixes ancillary work to 2 SQL rows of 1 KiB and 2 files of 1 MiB)'; exit 0 ;;
    *) echo 'unknown benchmark option' >&2; exit 2 ;;
  esac
done
for value in "$repeats" "$rows" "$payload_kib" "$files" "$file_mib" "$payload_budget_mib" "$graph_memory_budget_mib" "$graph_generations" "$crate_staging_rows"; do
  [[ $value =~ ^[1-9][0-9]{0,4}$ ]] || { echo 'invalid bounded positive benchmark option' >&2; exit 2; }
done
[[ $graph_snapshots =~ ^(0|[1-9][0-9]?)$ ]] || { echo 'invalid graph snapshot count' >&2; exit 2; }
[[ $crate_artifacts =~ ^(0|[1-9][0-9]{0,4})$ ]] || { echo 'invalid crate artifact count' >&2; exit 2; }
(( crate_artifacts <= 16384 && crate_staging_rows <= 16384 )) || { echo 'crate fixture exceeds bounded range' >&2; exit 2; }
if (( crate_artifacts > 0 )); then
  (( graph_snapshots == 0 )) || { echo 'crate and RFC benchmark profiles cannot be mixed' >&2; exit 2; }
  if [[ $workers == '1 4 8 16 32' ]]; then workers='1 2 4 8'; fi
  # prepare-crates fixes ancillary SQL/file work; record the actual profile.
  rows=2 payload_kib=1 files=2 file_mib=1
fi
if [[ -n $baseline_binary ]]; then
  (( crate_artifacts > 0 )) || { echo 'baseline comparison requires crate artifacts' >&2; exit 2; }
  [[ -x $baseline_binary ]] || { echo 'baseline binary unavailable' >&2; exit 2; }
  [[ $baseline_revision =~ ^[0-9a-f]{40}$ ]] || { echo 'baseline comparison requires full source revision' >&2; exit 2; }
  [[ $workers == '1 2 4 8' ]] || { echo 'baseline comparison requires fixed workers 1 2 4 8' >&2; exit 2; }
fi
(( repeats >= 3 && repeats <= 10 && rows <= 4096 && payload_kib <= 2048 && files <= 128 && file_mib <= 32 && payload_budget_mib <= 4096 && graph_memory_budget_mib <= 65536 && graph_snapshots <= 64 )) || { echo 'benchmark option exceeds its bounded range' >&2; exit 2; }
if (( graph_snapshots == 0 )); then
  (( graph_generations == 1 )) || { echo 'graph generations require enabled graph snapshots' >&2; exit 2; }
else
  (( graph_generations <= graph_snapshots )) || { echo 'graph generations cannot exceed graph snapshots' >&2; exit 2; }
fi
[[ -x $binary ]] || { echo 'build the release migration-benchmark example first, or pass --binary' >&2; exit 2; }
read -r -a matrix <<< "$workers"
[[ ${matrix[0]:-} == 1 ]] || { echo 'workers must start with the serial reference 1' >&2; exit 2; }
previous=0
for value in "${matrix[@]}"; do
  [[ $value =~ ^[1-9][0-9]?$ ]] && (( value <= 64 && value > previous )) || { echo 'workers must be strictly increasing integers in 1..64' >&2; exit 2; }
  previous=$value
done
if [[ -n $baseline_binary ]] && cmp -s -- "$binary" "$baseline_binary"; then
  echo 'identical baseline and candidate binaries cannot establish a comparison' >&2
  exit 2
fi
if [[ ${DEVRES_TMP_STATE:-} != 1 ]]; then
  exec scripts/with-tmp-state.sh env CARGO_TARGET_DIR=/tmp/rust/target OXIBELT_TARGET_DIR=/tmp/rust/target "$0" "${original_args[@]}"
fi
if [[ -z ${DEVRES_DOCKER_HOST:-} ]]; then
  exec scripts/with-local-docker.sh "$0" "${original_args[@]}"
fi
export DOCKER_HOST="$DEVRES_DOCKER_HOST"
unset DOCKER_CONTEXT
for command in docker python3 sha256sum nproc timeout cmp; do command -v "$command" >/dev/null; done
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
  "crate_artifacts=$crate_artifacts" "crate_staging_rows=$crate_staging_rows" \
  "graph_snapshots=$graph_snapshots" "graph_generations=$graph_generations" "graph_memory_budget_mib=$graph_memory_budget_mib" \
  'postgres_cpus=2' 'postgres_memory=1GiB' 'worker_cpu_quota=host/cgroup' 'fixture_durability=checkpoint+syncfs_before_timing' 'revision_is_checkout_head_not_source_attestation=true' > "$root/metadata.json"
if [[ -n $baseline_binary ]]; then
  python3 scripts/migration-benchmark-report.py metadata "$baseline_binary" "$baseline_revision" \
    "crate_artifacts=$crate_artifacts" "crate_staging_rows=$crate_staging_rows" \
    'runtime_algorithm_unchanged=true' 'common_fixture_and_timing_hooks=true' > "$root/baseline-metadata.json"
fi
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
run_one() {
  local run_binary=$1 output=$2 worker=$3
  mkdir -p "$output"
  local -a prepare_args
  export DEVRES_TEST_DATABASE_URL="postgres://devres:fixture-only@127.0.0.1:$port/devres_benchmark"
  psql 'CREATE DATABASE devres_benchmark'
  prepare_args=(prepare "$output/blobs" "$rows" "$payload_kib" "$files" "$file_mib")
  if (( graph_snapshots > 0 )); then prepare_args+=("$graph_snapshots" "$graph_generations"); fi
  if (( crate_artifacts > 0 )); then prepare_args=(prepare-crates "$output/blobs" "$crate_artifacts" "$crate_staging_rows"); fi
  "$run_binary" "${prepare_args[@]}" > "$output/fixture.json" 2> "$output/prepare.stderr"
  # Fresh identical pair per run. Preparation, backup and restore are not timed as migration.
  /usr/bin/time -v -o "$output/process-time.txt" timeout --signal=TERM --kill-after=30s 15m \
    "$run_binary" run "$output/blobs" "$worker" "$payload_budget_mib" "$graph_memory_budget_mib" > "$output/result.json" 2> "$output/progress.jsonl"
  /usr/bin/time -v -o "$output/backup-time.txt" sh -eu -c '
    docker exec "$1" pg_dump -U devres -d devres_benchmark -Fc > "$2/database.dump"
    cp -a -- "$2/blobs" "$2/restored-blobs"
  ' sh "$run_id" "$output"
  psql 'CREATE DATABASE devres_benchmark_restored'
  /usr/bin/time -v -o "$output/restore-time.txt" sh -eu -c '
    docker exec -i "$1" pg_restore -U devres -d devres_benchmark_restored --exit-on-error < "$2/database.dump"
  ' sh "$run_id" "$output"
  export DEVRES_TEST_DATABASE_URL="postgres://devres:fixture-only@127.0.0.1:$port/devres_benchmark_restored"
  /usr/bin/time -v -o "$output/restored-startup-time.txt" "$run_binary" check "$output/restored-blobs" > "$output/restored.json" 2> "$output/restored.stderr"
  psql 'DROP DATABASE devres_benchmark WITH (FORCE)'
  psql 'DROP DATABASE devres_benchmark_restored WITH (FORCE)'
  rm -rf -- "$output/blobs" "$output/restored-blobs" "$output/database.dump"

}
if [[ -n $baseline_binary ]]; then
  (( headroom >= 8 )) || { echo 'fixed comparison requires eight workers plus CPU headroom' >&2; exit 1; }
  # Alternate pair order to avoid charging cache/thermal drift to one algorithm.
  for (( repeat=1; repeat<=repeats; repeat++ )); do
    variants=(baseline candidate)
    if (( repeat % 2 == 0 )); then variants=(candidate baseline); fi
    for variant in "${variants[@]}"; do
      run_binary=$binary
      if [[ $variant == baseline ]]; then run_binary=$baseline_binary; fi
      run_one "$run_binary" "$root/$variant/workers-8/repeat-$repeat" 8
    done
  done
  for worker in 1 2 4; do
    for (( repeat=1; repeat<=repeats; repeat++ )); do
      run_one "$binary" "$root/candidate/workers-$worker/repeat-$repeat" "$worker"
    done
  done
  python3 scripts/migration-benchmark-report.py compare "$root" --repeats "$repeats" > "$root/summary.json"
else
  for worker in "${matrix[@]}"; do
    if (( worker > headroom )); then printf 'Stopped worker matrix at available CPU headroom (%s workers).\n' "$headroom" >&2; break; fi
    for (( repeat=1; repeat<=repeats; repeat++ )); do
      run_one "$binary" "$root/workers-$worker/repeat-$repeat" "$worker"
    done
    python3 scripts/migration-benchmark-report.py summarize "$root" --repeats "$repeats" > "$root/summary.json"
    # Crate measurements always execute the complete requested matrix.
    if (( crate_artifacts == 0 )); then
      if python3 scripts/migration-benchmark-report.py summarize "$root" --repeats "$repeats" --continue-after "$worker"; then :
      else
        status=$?
        if (( status == 3 )); then echo 'Stopped increasing workers: median throughput improved by less than two percent.' >&2; break; fi
        exit "$status"
      fi
    fi
  done
fi
cat "$root/summary.json"
