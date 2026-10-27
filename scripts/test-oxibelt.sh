#!/usr/bin/env bash
# Both transports through the exact pinned edge. Internal Docker network, no providers.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
scratch=$(mktemp -d)
token=${scratch##*/}
run_id="devres-edge-$$-${token,,}"
image="$run_id:local"
cleanup() {
  status=$?
  if (( status != 0 )); then
    docker logs "$run_id-backend" >&2 2>/dev/null || true
    docker logs "$run_id-edge" >&2 2>/dev/null || true
  fi
  for name in "$run_id-edge" "$run_id-backend" "$run_id-postgres"; do
    if [[ $(docker inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$name" 2>/dev/null) == "$run_id" ]]; then
      docker rm -fv "$name" >/dev/null 2>&1 || true
    fi
  done
  if [[ $(docker network inspect --format '{{index .Labels "devres.test-owner"}}' "$run_id" 2>/dev/null) == "$run_id" ]]; then
    docker network rm "$run_id" >/dev/null 2>&1 || true
  fi
  for name in "$run_id-fixture" "$run_id-data"; do
    if [[ $(docker volume inspect --format '{{index .Labels "devres.test-owner"}}' "$name" 2>/dev/null) == "$run_id" ]]; then
      docker volume rm "$name" >/dev/null 2>&1 || true
    fi
  done
  if [[ $(docker image inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$image" 2>/dev/null) == "$image" ]]; then
    docker image rm "$image" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$scratch"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
scripts/make-fixture.sh "$scratch"
scripts/build-harness.sh "$scratch" "$image"
docker network create --internal --label "devres.test-owner=$run_id" "$run_id" >/dev/null
for volume in "$run_id-fixture" "$run_id-data"; do
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    echo 'Refusing to reuse an existing fixture volume' >&2; exit 1
  fi
done
docker volume create --label "devres.test-owner=$run_id" "$run_id-fixture" >/dev/null
docker volume create --label "devres.test-owner=$run_id" "$run_id-data" >/dev/null
tar -C "$scratch/fixture" -cf - . | docker run --rm -i --network none --user 0 \
  -v "$run_id-fixture:/fixture" -v "$run_id-data:/data" --entrypoint sh "$image" \
  -c 'tar -xf - -C /fixture && chown -R 65532:65532 /fixture /data && chmod 600 /fixture/cert/*-key.pem'
docker run -d --name "$run_id-postgres" --label "devres.test-owner=$run_id" --network "$run_id" --network-alias postgres \
  -e POSTGRES_USER=devres -e POSTGRES_PASSWORD=fixture-only -e POSTGRES_DB=devres \
  postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a >/dev/null
for attempt in {1..60}; do
  if docker exec "$run_id-postgres" pg_isready -h 127.0.0.1 -U devres -d devres >/dev/null 2>&1; then break; fi
  if (( attempt == 60 )); then exit 1; fi
  sleep 1
done
backend() {
  docker run -d --name "$run_id-backend" --label "devres.test-owner=$run_id" --network "$run_id" --network-alias backend \
    --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m -v "$run_id-fixture:/fixture:ro" \
    -v "$run_id-data:/data" "$image" >/dev/null
}
edge() {
  probe oxibelt --config /fixture/config/oxibelt.toml --check
  docker run -d --name "$run_id-edge" --label "devres.test-owner=$run_id" --network "$run_id" --network-alias edge \
    --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --ulimit stack=67108864:67108864 \
    -v "$run_id-fixture:/fixture:ro" --entrypoint oxibelt "$image" \
    --config /fixture/config/oxibelt.toml >/dev/null
}
probe() { docker run --rm --network "$run_id" --ulimit stack=67108864:67108864 -v "$run_id-fixture:/fixture:ro" --entrypoint "$1" "$image" "${@:2}"; }
expect_failure() { if "$@" >/dev/null 2>&1; then echo 'Expected boundary rejection' >&2; exit 1; fi; }
assert_upstream_rejected() {
  test "$(docker inspect --format '{{.State.Running}}' "$run_id-edge")" = true
  status=$(probe curl --connect-timeout 3 --max-time 10 --silent --cacert /fixture/cert/ca.pem \
    --output /dev/null --write-out '%{http_code}' https://edge:8443/mcp)
  [[ $status == 502 || $status == 503 ]] || { echo 'Edge did not establish a bounded upstream failure' >&2; exit 1; }
}
backend
probe oxibelt --config /fixture/config/oxibelt.toml --check
edge
for attempt in {1..30}; do
  if probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem --no-negative >/dev/null 2>&1; then break; fi
  if (( attempt == 30 )); then exit 1; fi
  sleep 1
done
probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem
probe python3 /harness/mcp_smoke.py --url https://backend:8080/mcp --ca /fixture/cert/ca.pem \
  --cert /fixture/cert/edge-client.pem --key /fixture/cert/edge-client-key.pem
expect_failure probe python3 /harness/mcp_smoke.py --url https://backend:8080/mcp --ca /fixture/cert/ca.pem
expect_failure probe python3 /harness/mcp_smoke.py --url https://backend:8080/mcp --ca /fixture/cert/ca.pem \
  --cert /fixture/cert/wrong-client.pem --key /fixture/cert/wrong-client-key.pem
expect_failure probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/wrong-ca.pem
for revision in 2026-07-28 2025-11-25; do
  probe devres-probe https://edge:8443/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example
  probe devres-probe https://backend:4433/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example \
    /fixture/cert/edge-client.pem /fixture/cert/edge-client-key.pem
done
expect_failure probe devres-probe https://backend:4433/mcp-wt/v1 /fixture/cert/ca.pem 2026-07-28 https://client.example
expect_failure probe devres-probe https://backend:4433/mcp-wt/v1 /fixture/cert/ca.pem 2026-07-28 https://client.example \
  /fixture/cert/wrong-client.pem /fixture/cert/wrong-client-key.pem
expect_failure probe devres-probe https://edge:8443/mcp-wt/v1 /fixture/cert/wrong-ca.pem 2026-07-28 https://client.example
expect_failure probe devres-probe https://edge:8443/mcp-wt/v1 /fixture/cert/ca.pem 2026-07-28 https://untrusted.invalid
expect_failure probe devres-probe https://edge:8443/wrong /fixture/cert/ca.pem 2026-07-28 https://client.example
# Seed only task-owned public synthetic evidence while the serving fence is released.
mdn_content=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:mdn-content:v1").hexdigest())')
mdn_compat=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:mdn-compat:v1").hexdigest())')
whatwg_snapshot=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:whatwg:v1").hexdigest())')
w3c_snapshot=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:w3c:v1").hexdigest())')
advisory_snapshot=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:rustsec:v1").hexdigest())')
fixture_storage() { docker run --rm --network "$run_id" -v "$run_id-data:/data" \
  -e DATABASE_URL=postgres://devres:fixture-only@postgres/devres -e BLOB_DIR=/data/blobs \
  --entrypoint storage-probe "$image" "$1"; }
docker stop --time 15 "$run_id-backend" >/dev/null
docker rm "$run_id-backend" >/dev/null
before=$(fixture_storage write)
capture=${before%% *}
backend
probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem --wait-ready 30
probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
for revision in 2026-07-28 2025-11-25; do
  probe env DEVRES_PROBE_MDN_SNAPSHOT="$mdn_content" DEVRES_PROBE_MDN_COMPAT_SNAPSHOT="$mdn_compat" \
    DEVRES_PROBE_ADVISORY_SNAPSHOT="$advisory_snapshot" DEVRES_PROBE_WHATWG_SNAPSHOT="$whatwg_snapshot" DEVRES_PROBE_W3C_SNAPSHOT="$w3c_snapshot" devres-probe https://edge:8443/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example
  probe env DEVRES_PROBE_MDN_SNAPSHOT="$mdn_content" DEVRES_PROBE_MDN_COMPAT_SNAPSHOT="$mdn_compat" \
    DEVRES_PROBE_ADVISORY_SNAPSHOT="$advisory_snapshot" DEVRES_PROBE_WHATWG_SNAPSHOT="$whatwg_snapshot" DEVRES_PROBE_W3C_SNAPSHOT="$w3c_snapshot" devres-probe https://backend:4433/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example \
    /fixture/cert/edge-client.pem /fixture/cert/edge-client-key.pem
done
docker stop --time 15 "$run_id-backend" >/dev/null
docker rm "$run_id-backend" >/dev/null
test "$(fixture_storage read)" = "$before"
backend
probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem --wait-ready 30
probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
# Change only backend CA trust. Both transports must reject, then recover.
docker rm -f "$run_id-edge" >/dev/null
docker run --rm --network none --user 0 -v "$run_id-fixture:/fixture" --entrypoint sh "$image" \
  -c 'cp /fixture/config/oxibelt.toml /fixture/config/original.toml; sed -i "s/\[\"ca.pem\"\]/[\"wrong-ca.pem\"]/" /fixture/config/oxibelt.toml'
edge
sleep 2
assert_upstream_rejected
expect_failure probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem --no-negative
expect_failure probe devres-probe https://edge:8443/mcp-wt/v1 /fixture/cert/ca.pem 2026-07-28 https://client.example
docker rm -f "$run_id-edge" >/dev/null
docker run --rm --network none --user 0 -v "$run_id-fixture:/fixture" --entrypoint sh "$image" \
  -c 'cp /fixture/config/original.toml /fixture/config/oxibelt.toml'
edge
sleep 2
probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem
probe devres-probe https://edge:8443/mcp-wt/v1 /fixture/cert/ca.pem 2026-07-28 https://client.example
# Remove only the edge's client identity: a trusted server CA is insufficient.
docker rm -f "$run_id-edge" >/dev/null
docker run --rm --network none --user 0 -v "$run_id-fixture:/fixture" --entrypoint python3 "$image" -c '
import pathlib,re
p=pathlib.Path("/fixture/config/oxibelt.toml")
s=p.read_text()
s,n=re.subn(r"\[upstreams\.tls\.client_identity\]\ncert_chain = [^\n]+\nprivate_key = [^\n]+\n", "", s)
assert n==2
p.write_text(s)
'
edge
sleep 2
assert_upstream_rejected
expect_failure probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem --no-negative
expect_failure probe devres-probe https://edge:8443/mcp-wt/v1 /fixture/cert/ca.pem 2026-07-28 https://client.example
docker rm -f "$run_id-edge" >/dev/null
docker run --rm --network none --user 0 -v "$run_id-fixture:/fixture" --entrypoint sh "$image" \
  -c 'cp /fixture/config/original.toml /fixture/config/oxibelt.toml'
edge
sleep 2
probe python3 /harness/mcp_smoke.py --url https://edge:8443/mcp --ca /fixture/cert/ca.pem
probe devres-probe https://edge:8443/mcp-wt/v1 /fixture/cert/ca.pem 2026-07-28 https://client.example
echo 'Pinned OxiBelt Docker HTTP/WebTransport acceptance passed; no Kubernetes or live-provider claim'
