#!/usr/bin/env bash
# Disposable broker/IAM/Kubernetes identity/PostgreSQL/RustFS acceptance; no live providers.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
requested=("$@")
supplied_image=
while (( $# )); do
  case "$1" in
    --image) [[ $# -ge 2 && -n $2 && $2 != -* ]] || exit 2; supplied_image=$2; shift 2 ;;
    *) echo 'usage: scripts/test-credential-broker.sh [--image IMAGE]' >&2; exit 2 ;;
  esac
done
if [[ ${DEVRES_TMP_STATE:-} != 1 ]]; then
  docker_endpoint=${DEVRES_DOCKER_HOST:-${DOCKER_HOST:-}}
  if [[ -z $docker_endpoint ]]; then docker_endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}'); fi
  toolchain_bin=$(dirname -- "$(rustup which cargo)")
  exec scripts/with-tmp-state.sh env PATH="$toolchain_bin:$PATH" DEVRES_DOCKER_HOST="$docker_endpoint" "$0" "${requested[@]}"
fi
export CARGO_TARGET_DIR=/tmp/rust/target OXIBELT_TARGET_DIR=/tmp/rust/target PYTHONDONTWRITEBYTECODE=1
if [[ -n ${DEVRES_DOCKER_HOST:-} ]]; then unset DOCKER_CONTEXT; export DOCKER_HOST="$DEVRES_DOCKER_HOST"; fi
scratch=$(mktemp -d /tmp/devres-broker.XXXXXX)
token=${scratch##*/}; token=${token,,}; token=${token//./-}
run_id="devres-broker-$$-$token"
image=${supplied_image:-$run_id:local}
postgres_image=postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a
rustfs_image=rustfs/rustfs@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2
cleanup() {
  status=$?
  if (( status )); then docker logs --tail 20 "$run_id-broker" >&2 2>/dev/null || true; fi
  for component in broker iam identity objectstore postgres; do
    name="$run_id-$component"
    if [[ $(docker inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$name" 2>/dev/null) == "$run_id" ]]; then docker rm -fv "$name" >/dev/null 2>&1 || true; fi
  done
  if [[ $(docker network inspect --format '{{index .Labels "devres.test-owner"}}' "$run_id" 2>/dev/null) == "$run_id" ]]; then docker network rm "$run_id" >/dev/null 2>&1 || true; fi
  for suffix in fixture objects; do
    if [[ $(docker volume inspect --format '{{index .Labels "devres.test-owner"}}' "$run_id-$suffix" 2>/dev/null) == "$run_id" ]]; then docker volume rm "$run_id-$suffix" >/dev/null 2>&1 || true; fi
  done
  if [[ -z $supplied_image ]] && [[ $(docker image inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$image" 2>/dev/null) == "$image" ]]; then docker image rm "$image" >/dev/null 2>&1 || true; fi
  rm -rf -- "$scratch"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
scripts/make-fixture.sh "$scratch"
python3 -I -B scripts/kube-identity-fixture.py prepare "$scratch"
python3 -I -B scripts/credential-broker-fixture.py prepare "$scratch" docker
if [[ -z $supplied_image ]]; then scripts/build-harness.sh "$scratch" "$image"; else docker image inspect "$image" >/dev/null; fi
docker network create --internal --label "devres.test-owner=$run_id" "$run_id" >/dev/null
for suffix in fixture objects; do
  if docker volume inspect "$run_id-$suffix" >/dev/null 2>&1; then echo 'Refusing to reuse an existing fixture volume' >&2; exit 1; fi
  docker volume create --label "devres.test-owner=$run_id" "$run_id-$suffix" >/dev/null
done
tar -C "$scratch/fixture" -cf - . | docker run --rm -i --network none --user 0 \
  -v "$run_id-fixture:/fixture" -v "$run_id-objects:/objects" --entrypoint sh "$image" \
  -c 'tar -xf - -C /fixture && chown -R 65532:65532 /fixture && chown 10001:10001 /objects'
probe() {
  docker run --rm --network "$run_id" --read-only --cap-drop ALL --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    -v "$run_id-fixture:/fixture" --entrypoint python3 "$image" -I -B /harness/credential-broker-probe.py "$@"
}
docker run --rm --network none -v "$run_id-fixture:/fixture" --entrypoint sh "$image" -ec \
  'devres-credential-broker profile-fingerprints /fixture/broker/broker.toml > /fixture/broker/fingerprints.json
   devres-credential-broker issuer-fingerprint /fixture/broker/broker.toml > /fixture/broker/issuer-fingerprint
   python3 -I -B /harness/credential-broker-fixture.py receipt /fixture/broker /fixture/broker/fingerprints.json'
docker run -d --name "$run_id-postgres" --label "devres.test-owner=$run_id" --network "$run_id" --network-alias postgres \
  --env-file "$scratch/fixture/broker/postgres.env" "$postgres_image" >/dev/null
for attempt in {1..60}; do
  if docker exec "$run_id-postgres" pg_isready -h 127.0.0.1 -U devres_fixture_admin -d postgres >/dev/null 2>&1; then break; fi
  if (( attempt == 60 )); then echo 'Broker fixture PostgreSQL startup failed' >&2; exit 1; fi
  sleep 1
done
docker exec -i "$run_id-postgres" psql -v ON_ERROR_STOP=1 -U devres_fixture_admin -d postgres < "$scratch/fixture/broker/database-init.sql" >/dev/null
docker run -d --name "$run_id-objectstore" --label "devres.test-owner=$run_id" --network "$run_id" --network-alias objectstore \
  --user 10001:10001 --env-file "$scratch/fixture/broker/rustfs.env" -v "$run_id-objects:/data" "$rustfs_image" /data >/dev/null
docker run -d --name "$run_id-identity" --label "devres.test-owner=$run_id" --network "$run_id" --network-alias identity-fixture \
  --read-only --cap-drop ALL -v "$run_id-fixture:/fixture:ro" --entrypoint python3 "$image" -I -B /harness/kube-identity-fixture.py serve /fixture/identity >/dev/null
for attempt in {1..60}; do
  if docker run --rm --network "$run_id" --entrypoint curl "$image" --noproxy '*' -fsS --max-time 2 -o /dev/null http://objectstore:9000/health 2>/dev/null; then break; fi
  if (( attempt == 60 )); then echo 'Broker fixture object storage startup failed' >&2; exit 1; fi
  sleep 1
done
docker run -d --name "$run_id-iam" --label "devres.test-owner=$run_id" --network "$run_id" --network-alias iam-fixture \
  --read-only --cap-drop ALL -v "$run_id-fixture:/fixture" --entrypoint python3 "$image" -I -B /harness/scaleway-iam-fixture.py /fixture/broker/iam-fixture.json >/dev/null
probe provider-ready
start_broker() {
  docker run -d --name "$run_id-broker" --label "devres.test-owner=$run_id" --network "$run_id" --network-alias credential-broker \
    --read-only --cap-drop ALL --tmpfs /tmp:rw,noexec,nosuid,size=32m -v "$run_id-fixture:/fixture:ro" \
    -e NO_PROXY=iam-fixture,identity-fixture,postgres,objectstore,credential-broker \
    -e no_proxy=iam-fixture,identity-fixture,postgres,objectstore,credential-broker \
    --entrypoint devres-credential-broker "$image" /fixture/broker/broker.toml >/dev/null
}
start_broker
probe provider-errors
probe initial
docker stop "$run_id-broker" >/dev/null
docker rm "$run_id-broker" >/dev/null
start_broker
probe recovered
probe refresh
probe rotate
docker stop "$run_id-broker" >/dev/null
docker rm "$run_id-broker" >/dev/null
start_broker
probe recovered
probe revoked
# The ignored adapter test uses its own database after the running broker releases ownership.
docker stop "$run_id-broker" >/dev/null
docker exec "$run_id-postgres" psql -v ON_ERROR_STOP=1 -U devres_fixture_admin -d postgres \
  -c 'CREATE DATABASE devres_broker_test_regressions OWNER devres_broker' \
  -c 'REVOKE CONNECT ON DATABASE devres_broker_test_regressions FROM PUBLIC' \
  -c 'GRANT CONNECT ON DATABASE devres_broker_test_regressions TO devres_broker' >/dev/null
cargo test --locked --no-run --message-format=json -p devres-adapters --lib > "$scratch/test-artifacts.json"
broker_test_binary=$(python3 -I -B - "$scratch/test-artifacts.json" <<'PY'
import json
from pathlib import Path
import sys
artifacts = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
binaries = [Path(item['executable']).resolve(strict=True) for item in artifacts
            if item.get('reason') == 'compiler-artifact' and item.get('executable')
            and item.get('target', {}).get('name') == 'devres_adapters'
            and item.get('profile', {}).get('test')]
assert len(binaries) == 1 and Path('/tmp/rust/target') in binaries[0].parents
print(binaries[0])
PY
)
docker run --rm --network "$run_id" --read-only --cap-drop ALL --tmpfs /tmp:rw,nosuid,size=64m \
  -e NO_PROXY=postgres,127.0.0.1,localhost -e no_proxy=postgres,127.0.0.1,localhost \
  -v "$run_id-fixture:/fixture:ro" --mount "type=bind,src=$broker_test_binary,dst=/harness/broker-tests,readonly" \
  --entrypoint python3 "$image" -I -B -c '
from pathlib import Path
import os
from urllib.parse import urlsplit
url = urlsplit(Path("/fixture/broker/database-url").read_text())
assert url.hostname == "postgres"
os.environ["DEVRES_TEST_BROKER_DATABASE_URL"] = url._replace(path="/devres_broker_test_regressions").geturl()
os.execv("/harness/broker-tests", ["broker-tests", "credential_broker_", "--ignored", "--test-threads=1"])
'
echo 'Disposable broker/RustFS credential acceptance passed'
