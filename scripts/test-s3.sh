#!/usr/bin/env bash
# Disposable RustFS/PostgreSQL acceptance; no public source collection.
# Invoke through with-tmp-state.sh; both services bind only to loopback.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ ${DEVRES_TMP_STATE:-} != 1 ]]; then
  # Resolve selectors before isolating client configuration. Direct toolchain
  # binaries remain usable with a fresh RUSTUP_HOME and dependency cache.
  docker_endpoint=${DEVRES_DOCKER_HOST:-${DOCKER_HOST:-}}
  if [[ -z $docker_endpoint ]]; then
    docker_endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
  fi
  toolchain_bin=$(dirname -- "$(rustup which cargo)")
  exec scripts/with-tmp-state.sh env \
    PATH="$toolchain_bin:$PATH" DEVRES_DOCKER_HOST="$docker_endpoint" "$0" "$@"
fi
export CARGO_TARGET_DIR=/tmp/rust/target
export OXIBELT_TARGET_DIR=/tmp/rust/target
export TMPDIR="${TMPDIR:-/tmp}"
scratch=$(mktemp -d /tmp/devres-s3.XXXXXX)
run_id="devres-s3-$$-${scratch##*.}"
postgres="$run_id-postgres"
rustfs="$run_id-rustfs"
postgres_image=postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a
# Official multi-platform index, verified to include native amd64 and arm64.
rustfs_image=rustfs/rustfs@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2
cleanup() {
  status=$?
  for container in "$postgres" "$rustfs"; do
    if [[ $(docker inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$container" 2>/dev/null) == "$run_id" ]]; then
      docker rm -fv "$container" >/dev/null 2>&1 || true
    fi
  done
  rm -rf -- "$scratch"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for command in docker curl python3 cargo; do command -v "$command" >/dev/null; done
if [[ -n ${DEVRES_DOCKER_HOST:-} ]]; then
  unset DOCKER_CONTEXT
  export DOCKER_HOST="$DEVRES_DOCKER_HOST"
fi
mkdir "$scratch/rustfs"
fixture_user="$(id -u):$(id -g)"
# Rootless container root maps to the invoking host user; a numbered container
# user maps to a subordinate host UID and cannot write this private bind mount.
if [[ $(docker info --format '{{json .SecurityOptions}}') == *rootless* ]]; then
  fixture_user=0:0
fi
python3 - "$scratch" <<'PY'
import json
from pathlib import Path
import secrets
import sys

root = Path(sys.argv[1])
access = "fixture-" + secrets.token_hex(12)
secret = secrets.token_hex(32)
files = {
    "access-key": access + "\n",
    "secret-key": secret + "\n",
    "rustfs.env": "RUSTFS_ACCESS_KEY=" + access + "\nRUSTFS_SECRET_KEY=" + secret + "\n"
                  "RUSTFS_CONSOLE_ENABLE=false\nRUSTFS_OBS_LOG_DIRECTORY=/data/logs\n",
    "postgres.env": "POSTGRES_USER=devres\nPOSTGRES_PASSWORD=fixture-only\nPOSTGRES_DB=devres\n",
}
for name, body in files.items():
    path = root / name
    path.write_text(body)
    path.chmod(0o600)
PY
docker run -d --name "$postgres" --label devres.test-owner="$run_id" \
  --env-file "$scratch/postgres.env" \
  -p 127.0.0.1::5432 "$postgres_image" >/dev/null
docker run -d --name "$rustfs" --label devres.test-owner="$run_id" \
  --user "$fixture_user" --env-file "$scratch/rustfs.env" \
  --mount "type=bind,src=$scratch/rustfs,dst=/data" \
  -p 127.0.0.1::9000 "$rustfs_image" /data >/dev/null
postgres_port=$(docker port "$postgres" 5432/tcp | sed 's/.*://')
s3_port=$(docker port "$rustfs" 9000/tcp | sed 's/.*://')
for attempt in {1..60}; do
  if docker exec "$postgres" pg_isready -h 127.0.0.1 -U devres -d devres >/dev/null 2>&1; then break; fi
  if (( attempt == 60 )); then echo 'Disposable PostgreSQL readiness timed out' >&2; exit 1; fi
  sleep 1
done
for attempt in {1..60}; do
  if curl --noproxy '*' --silent --fail --output /dev/null "http://127.0.0.1:$s3_port/health"; then break; fi
  if (( attempt == 60 )); then echo 'Disposable RustFS readiness timed out' >&2; exit 1; fi
  sleep 1
done
python3 - "$scratch" "$s3_port" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
endpoint = "http://127.0.0.1:" + sys.argv[2]
access = (root / "access-key").read_text().strip()
secret = (root / "secret-key").read_text().strip()
config = (
    "endpoint = " + json.dumps(endpoint) + "\n"
    'bucket = "devres-fixture"\nregion = "us-east-1"\nprefix = "acceptance"\n'
    "path_style = true\nallow_http = true\ncache_max_bytes = 134217728\n"
    '[credentials]\nmode = "files"\n'
    "access_key_file = " + json.dumps(str(root / "access-key")) + "\n"
    "secret_key_file = " + json.dumps(str(root / "secret-key")) + "\n"
)
(root / "s3.toml").write_text(config)
(root / "s3.toml").chmod(0o600)
# Authentication stays in a private configuration file, never process arguments.
request = (
    "url = " + json.dumps(endpoint + "/devres-fixture") + "\n"
    'request = "PUT"\naws-sigv4 = "aws:amz:us-east-1:s3"\n'
    "user = " + json.dumps(access + ":" + secret) + "\n"
    'data = ""\nnoproxy = "*"\nsilent\nshow-error\nfail\noutput = "/dev/null"\n'
)
(root / "create-bucket.curl").write_text(request)
(root / "create-bucket.curl").chmod(0o600)
PY
curl --config "$scratch/create-bucket.curl"
export DEVRES_TEST_DATABASE_URL="postgres://devres:fixture-only@127.0.0.1:$postgres_port/devres"
export DEVRES_TEST_S3_CONFIG="$scratch/s3.toml"
cargo test --locked -p devres-adapters --lib s3_ -- --ignored --test-threads=1
echo 'Disposable RustFS/PostgreSQL acceptance passed'
