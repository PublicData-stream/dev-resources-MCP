#!/usr/bin/env bash
# Exact Alpine PostgreSQL identity/initialization; synthetic, isolated /tmp only.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export PYTHONDONTWRITEBYTECODE=1
if [[ ${DEVRES_TMP_STATE:-} != 1 || ${DEVRES_DOCKER_HOST:-${DOCKER_HOST:-}} != unix:///tmp/* ]]; then
  echo 'Run this fixture through scripts/with-tmp-state.sh scripts/with-local-docker.sh' >&2
  exit 2
fi
export DOCKER_HOST=${DEVRES_DOCKER_HOST:-$DOCKER_HOST}
unset DOCKER_CONTEXT
docker info --format '{{.DockerRootDir}}' | python3 -c 'import pathlib,sys; p=pathlib.Path(sys.stdin.read().strip()).resolve(); assert pathlib.Path("/tmp") in p.parents, "Fixture Docker storage must remain below /tmp"'
scratch=$(mktemp -d /tmp/devres-production-postgres.XXXXXX)
chmod 700 "$scratch"
run_id=${scratch##*/}
image=postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395
cleanup() {
  local status=$?
  for name in "$run_id-corpus" "$run_id-broker"; do
    if [[ $(docker inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$name" 2>/dev/null) == "$run_id" ]]; then
      docker rm -fv "$name" >/dev/null 2>&1 || true
    fi
  done
  printf 'Retained private synthetic PostgreSQL fixture: %s\n' "$scratch" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 - "$scratch" <<'PY'
import base64
import importlib.util
import os
from pathlib import Path
import sys
root=Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('production_operator', 'scripts/production-operator.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
values, manifests=module.postgres_inputs()
for name, manifest, password, database in (
    ('corpus', manifests[0], values['corpus_admin'], 'devres'),
    ('broker', manifests[1], values['broker_admin'], 'devres_broker')):
    path=root/name
    path.mkdir(mode=0o700)
    for filename, content in (
        ('init.sql',base64.b64decode(manifest['data']['init.sql'])),
        ('password',password.encode()),
        ('postgres.env',f'POSTGRES_USER=devres_admin\nPOSTGRES_DB={database}\nPGDATA=/var/lib/postgresql/18/docker\nPOSTGRES_PASSWORD_FILE=/run/postgres-private/password\n'.encode())):
        fd=os.open(path/filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as output: output.write(content)
    (path/'data').mkdir(mode=0o700)
PY
# The test deliberately models production's pinned Alpine uid/gid, not Debian999.
for role in corpus broker; do
  sudo -n chown 70:70 "$scratch/$role/data" "$scratch/$role/init.sql" "$scratch/$role/password"
  docker run -d --name "$run_id-$role" --label "devres.test-owner=$run_id" \
    --network none --user 70:70 --read-only --cap-drop ALL --memory 512m \
    --env-file "$scratch/$role/postgres.env" \
    --mount "type=bind,src=$scratch/$role/data,dst=/var/lib/postgresql" \
    --mount "type=bind,src=$scratch/$role/password,dst=/run/postgres-private/password,readonly" \
    --mount "type=bind,src=$scratch/$role/init.sql,dst=/docker-entrypoint-initdb.d/10-init.sql,readonly" \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m,uid=70,gid=70 \
    --tmpfs /var/run/postgresql:rw,noexec,nosuid,size=32m,uid=70,gid=70 \
    "$image" >/dev/null
done
ready() {
  local name=$1 database=$2
  for attempt in {1..60}; do
    if docker exec "$name" sh -c 'test "$(head -n 1 /var/lib/postgresql/18/docker/postmaster.pid)" = 1' >/dev/null 2>&1 \
        && docker exec "$name" pg_isready -U devres_admin -d "$database" >/dev/null 2>&1; then return; fi
    sleep 1
  done
  echo 'Pinned Alpine PostgreSQL startup failed' >&2
  return 1
}
ready "$run_id-corpus" devres
ready "$run_id-broker" devres_broker
# Complete initialization can briefly follow readiness of the temporary init server.
for attempt in {1..60}; do
  if docker exec "$run_id-corpus" psql -U devres_writer -d devres -Atc 'SELECT 1' >/dev/null 2>&1 \
      && docker exec "$run_id-broker" psql -U devres_broker -d devres_broker -Atc 'SELECT 1' >/dev/null 2>&1; then break; fi
  if (( attempt == 60 )); then echo 'Application role initialization failed' >&2; exit 1; fi
  sleep 1
done
docker exec "$run_id-corpus" psql -v ON_ERROR_STOP=1 -U devres_writer -d devres \
  -c 'CREATE TABLE deployment_probe (value integer); INSERT INTO deployment_probe VALUES (172)' >/dev/null
test "$(docker exec "$run_id-corpus" psql -U devres_reader -d devres -Atc 'SELECT value FROM deployment_probe')" = 172
test "$(docker exec "$run_id-corpus" psql -U devres_admin -d devres -Atc "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit FROM pg_roles WHERE rolname='devres_reader'")" = f
if docker exec "$run_id-corpus" psql -v ON_ERROR_STOP=1 -U devres_reader -d devres \
    -c 'SET default_transaction_read_only=off' -c 'INSERT INTO deployment_probe VALUES (999)' > "$scratch/reader-write.log" 2>&1; then
  echo 'Reader unexpectedly acquired SQL write authority' >&2; exit 1
fi
if docker exec "$run_id-broker" psql -U devres_writer -d devres_broker -Atc 'SELECT 1' > "$scratch/cross-broker.log" 2>&1; then
  echo 'Corpus role unexpectedly connected to broker database' >&2; exit 1
fi
if docker exec "$run_id-corpus" psql -U devres_broker -d devres -Atc 'SELECT 1' > "$scratch/cross-corpus.log" 2>&1; then
  echo 'Broker role unexpectedly connected to corpus database' >&2; exit 1
fi
docker restart "$run_id-corpus" >/dev/null
ready "$run_id-corpus" devres
test "$(docker exec "$run_id-corpus" psql -U devres_reader -d devres -Atc 'SELECT value FROM deployment_probe')" = 172
test "$(docker exec "$run_id-corpus" cat /var/lib/postgresql/18/docker/PG_VERSION)" = 18
echo 'Pinned Alpine PostgreSQL persistence, RO and database-isolation acceptance passed'
