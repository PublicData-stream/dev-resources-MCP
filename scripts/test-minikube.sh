#!/usr/bin/env bash
# Isolated real Kubernetes/CNI/NodePort acceptance; never reuses an existing profile.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
requested_args=("$@")
live=0
s3=0
live_rfc_args=()
supplied_image=
while (( $# )); do
  case "$1" in
    --image) [[ $# -ge 2 && -n $2 && $2 != -* ]] || { echo '--image requires an image' >&2; exit 2; }; supplied_image=$2; shift 2 ;;
    --live) live=1; shift ;;
    --s3) s3=1; shift ;;
    --rfc-text-only) live_rfc_args=(--rfc-text-only); shift ;;
    *) echo 'usage: scripts/test-minikube.sh [--image IMAGE] [--s3] [--live [--rfc-text-only]]' >&2; exit 2 ;;
  esac
done
if (( ! live && ${#live_rfc_args[@]} )); then echo '--rfc-text-only requires --live' >&2; exit 2; fi
if (( s3 && live )); then echo '--s3 is an isolated fixture scenario and does not accept --live' >&2; exit 2; fi
if [[ ${DEVRES_TMP_STATE:-} != 1 ]]; then
  docker_endpoint=${DEVRES_DOCKER_HOST:-${DOCKER_HOST:-}}
  if [[ -z $docker_endpoint ]]; then
    docker_endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
  fi
  toolchain_bin=$(dirname -- "$(rustup which cargo)")
  exec scripts/with-tmp-state.sh env PATH="$toolchain_bin:$PATH" \
    DEVRES_DOCKER_HOST="$docker_endpoint" CARGO_TARGET_DIR=/tmp/rust/target \
    OXIBELT_TARGET_DIR=/tmp/rust/target "$0" "${requested_args[@]}"
fi
export CARGO_TARGET_DIR=/tmp/rust/target OXIBELT_TARGET_DIR=/tmp/rust/target
if [[ -n ${DEVRES_DOCKER_HOST:-} ]]; then
  unset DOCKER_CONTEXT
  export DOCKER_HOST="$DEVRES_DOCKER_HOST"
else
  export DOCKER_CONTEXT=default
fi
scratch=$(mktemp -d /tmp/devres-minikube.XXXXXX)
token=${scratch##*/}
token=${token//./-}
run_id="devres-acceptance-$$-${token,,}"
profile="$run_id"
namespace=devres-acceptance
image="${supplied_image:-$run_id:local}"
created=0
k() { minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=30s -n "$namespace" "$@"; }
# Fixed allowlist only; never copy fixtures, secrets, container inspect, or data.
diag_capture() {
  local file=$1; shift
  timeout 15s "$@" 2>&1 | head -c 65536 > "$diagnostics/$file" || true
}
collect_diagnostics() {
  [[ -n ${DEVRES_E2E_DIAGNOSTICS_DIR:-} ]] || return 0
  local diagnostics="$DEVRES_E2E_DIAGNOSTICS_DIR/$run_id"
  mkdir -p -- "$diagnostics" || return 0
  if (( created )); then
    diag_capture pods.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" get pods -o wide
    diag_capture pvc.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" get pvc -o 'custom-columns=NAME:.metadata.name,PHASE:.status.phase,VOLUME:.spec.volumeName,CAPACITY:.status.capacity.storage'
    diag_capture container-state.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" get pods -o 'jsonpath={range .items[*]}{.metadata.name}{" phase="}{.status.phase}{"\n"}{range .status.initContainerStatuses[*]}{.name}{" restarts="}{.restartCount}{" waiting="}{.state.waiting.reason}{" terminated="}{.state.terminated.reason}{" exit="}{.state.terminated.exitCode}{" last="}{.lastState.terminated.reason}{" lastExit="}{.lastState.terminated.exitCode}{"\n"}{end}{range .status.containerStatuses[*]}{.name}{" ready="}{.ready}{" restarts="}{.restartCount}{" waiting="}{.state.waiting.reason}{" terminated="}{.state.terminated.reason}{" exit="}{.state.terminated.exitCode}{" signal="}{.state.terminated.signal}{" last="}{.lastState.terminated.reason}{" lastExit="}{.lastState.terminated.exitCode}{"\n"}{end}{end}'
    diag_capture backend-memory.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" exec deployment/backend -- sh -c 'for file in /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.events; do if test -r "$file"; then echo "$file"; cat "$file"; fi; done'
    diag_capture events.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" get events --field-selector type=Warning --sort-by=.lastTimestamp
    diag_capture backend-previous.log minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" logs deploy/backend --previous --tail=100 --limit-bytes=65536
    for component in backend edge postgres; do
      diag_capture "$component.log" minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" logs "deploy/$component" --tail=100 --limit-bytes=65536
    done
  fi
}
cleanup() {
  status=$?
  if (( status != 0 )); then collect_diagnostics || true; fi
  if (( status != 0 && created )); then
    k get pods >&2 2>/dev/null || true
    k logs deploy/backend --tail=40 >&2 2>/dev/null || true
    k logs deploy/edge --tail=40 >&2 2>/dev/null || true
  fi
  if (( created )); then minikube -p "$profile" delete >/dev/null 2>&1 || true; fi
  if [[ -z $supplied_image ]] && [[ $(docker image inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$image" 2>/dev/null) == "$image" ]]; then
    docker image rm "$image" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$scratch"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for command in minikube docker openssl python3; do command -v "$command" >/dev/null; done
if minikube profile list -o json | python3 -c 'import json,sys; p=json.load(sys.stdin); sys.exit(not any(v.get("Name")==sys.argv[1] for v in p.get("valid",[])+p.get("invalid",[])))' "$profile"; then
  echo 'Refusing to reuse an existing minikube profile' >&2; exit 1
fi
scripts/make-fixture.sh "$scratch"
if (( s3 )); then python3 scripts/s3-kubernetes-fixture.py prepare "$scratch"; fi
if [[ -z $supplied_image ]]; then
  scripts/build-harness.sh "$scratch" "$image"
else
  docker image inspect "$image" >/dev/null
fi
# Set the cleanup fence before startup so partially created task-owned profiles go away.
created=1
scripts/e2e-storage.sh before-minikube-start "$image" "$scratch" || true
minikube -p "$profile" start --driver=docker --container-runtime=containerd --cni=calico \
  --kubernetes-version="${DEVRES_KUBERNETES_VERSION:-v1.37.0}" \
  --cpus=4 --memory=6144 --subnet=10.223.254.0/24 --keep-context || {
    status=$?
    scripts/e2e-storage.sh minikube-start-failed "$image" "$scratch" || true
    exit "$status"
  }
scripts/e2e-storage.sh after-minikube-start "$image" "$scratch" || true
minikube -p "$profile" image load "$image" || {
  status=$?
  scripts/e2e-storage.sh minikube-import-failed "$image" "$scratch" || true
  exit "$status"
}
scripts/e2e-storage.sh after-minikube-import "$image" "$scratch" || true
k create namespace "$namespace" --dry-run=client -o yaml | k apply -f -
if (( s3 )); then
  k create secret generic devres-s3-credentials --from-file="$scratch/fixture/s3/"
fi
k create secret generic devres-config --from-file=backend.toml="$scratch/fixture/backend.toml" \
  --from-literal=postgres-password=fixture-only
k create secret generic devres-tls --from-file="$scratch/fixture/cert/"
k create configmap devres-edge-config --from-file=oxibelt.toml="$scratch/fixture/config/oxibelt.toml"
sed "s|DEVRES_HARNESS_IMAGE|$image|g" deploy/kubernetes/foundation.yaml > "$scratch/foundation.yaml"
if (( s3 )); then python3 scripts/s3-kubernetes-fixture.py foundation "$scratch/foundation.yaml"; fi
k apply -f "$scratch/foundation.yaml"
if (( s3 )); then
  k apply -f deploy/kubernetes/s3-fixture.yaml
  k -n kube-system rollout status deployment/coredns --timeout=120s
  k rollout status deployment/objectstore --timeout=180s
  python3 scripts/s3-kubernetes-fixture.py initializer "$image" > "$scratch/objectstore-init.json"
  k apply -f "$scratch/objectstore-init.json"
  k wait --for=condition=Complete job/objectstore-init --timeout=120s
  k delete job/objectstore-init --wait=true
  k scale deployment/backend --replicas=1
fi
for deployment in postgres backend edge; do k rollout status deployment/"$deployment" --timeout=180s; done
node_ip=$(minikube -p "$profile" ip)
docker_network=$(docker inspect --format '{{range $name, $value := .NetworkSettings.Networks}}{{$name}}{{end}}' "$profile")
external() {
  docker run --rm --network "$docker_network" --add-host "edge:$node_ip" \
    -v "$scratch/fixture:/fixture:ro" --entrypoint "$1" "$image" "${@:2}"
}
wait_edge() {
  external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --wait-ready 30
}
wait_edge
external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem
for revision in 2026-07-28 2025-11-25; do
  external devres-probe https://edge:30443/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example
done
# An in-cluster probe has valid backend mTLS credentials. Its untrusted twin has
# the same credentials but a different label, proving policy rather than TLS rejection.
python3 - "$image" > "$scratch/probe.yaml" <<'PY'
import json,sys
image=sys.argv[1]
for name,app in (("trusted-probe","acceptance-probe"),("untrusted-probe","untrusted-probe")):
    pod={"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"labels":{"app":app}},"spec":{
      "automountServiceAccountToken":False,"restartPolicy":"Never","securityContext":{"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532,"runAsNonRoot":True},
      "containers":[{"name":"probe","image":image,"imagePullPolicy":"Never","command":["sleep","3600"],
        "securityContext":{"allowPrivilegeEscalation":False,"capabilities":{"drop":["ALL"]}},
        "volumeMounts":[{"name":"tls","mountPath":"/fixture/cert","readOnly":True}]}],
      "volumes":[{"name":"tls","secret":{"secretName":"devres-tls","defaultMode":288}}]}}
    print(json.dumps(pod)); print("---")
PY
k apply -f "$scratch/probe.yaml"
for pod in trusted-probe untrusted-probe; do k wait --for=condition=Ready pod/"$pod" --timeout=120s; done
k exec trusted-probe -- python3 /harness/mcp_smoke.py --url https://backend:8080/mcp --ca /fixture/cert/ca.pem \
  --cert /fixture/cert/edge-client.pem --key /fixture/cert/edge-client-key.pem
for revision in 2026-07-28 2025-11-25; do
  k exec trusted-probe -- devres-probe https://backend:4433/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example \
    /fixture/cert/edge-client.pem /fixture/cert/edge-client-key.pem
done
if k exec untrusted-probe -- curl --connect-timeout 3 --max-time 5 --silent \
  --cacert /fixture/cert/ca.pem --cert /fixture/cert/edge-client.pem --key /fixture/cert/edge-client-key.pem \
  https://backend:8080/mcp -o /dev/null; then
  echo 'CNI admitted an untrusted Pod to the private backend' >&2; exit 1
fi
if k exec untrusted-probe -- devres-probe https://backend:4433/mcp-wt/v1 /fixture/cert/ca.pem \
  2026-07-28 https://client.example /fixture/cert/edge-client.pem /fixture/cert/edge-client-key.pem; then
  echo 'CNI admitted untrusted UDP WebTransport to the private backend' >&2; exit 1
fi
if (( s3 )); then
  for caller in trusted-probe untrusted-probe deployment/edge; do
    if k exec "$caller" -- curl --connect-timeout 3 --max-time 5 --silent \
      http://objectstore:9000/health -o /dev/null; then
      echo 'CNI exposed object storage beyond the backend/maintenance boundary' >&2; exit 1
    fi
  done
fi
backend_ip=$(k get pod -l app=backend -o jsonpath='{.items[0].status.podIP}')
if k exec trusted-probe -- curl --connect-timeout 3 --max-time 5 --silent "http://$backend_ip:9090/live" -o /dev/null; then
  echo 'CNI exposed private health to a caller Pod' >&2; exit 1
fi
# Exclusive storage ownership: stop serving before a maintenance connection or backup.
stop_backend() {
  k scale deployment/backend --replicas=0
  k wait --for=delete pod -l app=backend --timeout=120s
}
maintenance_start() {
  python3 - "$image" "$s3" > "$scratch/maintenance.yaml" <<'PY'
import json,sys
pod={"apiVersion":"v1","kind":"Pod","metadata":{"name":"storage-maintenance","labels":{"app":"backend"}},"spec":{
 "automountServiceAccountToken":False,"restartPolicy":"Never","securityContext":{"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532},
 "containers":[{"name":"maintenance","image":sys.argv[1],"imagePullPolicy":"Never","command":["sleep","3600"],
 "env":[{"name":"DATABASE_URL","value":"postgres://devres:fixture-only@postgres/devres"},{"name":"BLOB_DIR","value":"/data/blobs"}],
 "volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"devres-data"}}]}}
if sys.argv[2]=='1':
    pod['spec']['containers'][0]['env'].append({'name':'DEVRES_TEST_S3_CONFIG','value':'/fixture/s3/s3.toml'})
    pod['spec']['containers'][0]['volumeMounts'].append({'name':'s3','mountPath':'/fixture/s3','readOnly':True})
    pod['spec']['volumes'].append({'name':'s3','secret':{'secretName':'devres-s3-credentials','defaultMode':0o440}})
print(json.dumps(pod))
PY
  k apply -f "$scratch/maintenance.yaml"
  k wait --for=condition=Ready pod/storage-maintenance --timeout=120s
}
maintenance_stop() { k delete pod/storage-maintenance --wait=true; }
start_backend() {
  k scale deployment/backend --replicas=1
  k rollout status deployment/backend --timeout=120s
  wait_edge
}
# Share the inspectable BLAKE3 golden fixture identities with the HTTP smoke.
read -r mdn_content mdn_compat whatwg_snapshot w3c_snapshot chromium_snapshot advisory_snapshot < <(
  python3 - <<'PYIDS'
import runpy
fixture = runpy.run_path("scripts/mcp_smoke.py")
print(*(fixture[name] for name in ("SYNTHETIC_MDN_CONTENT", "SYNTHETIC_MDN_COMPAT", "SYNTHETIC_WHATWG", "SYNTHETIC_W3C", "SYNTHETIC_CHROMIUM", "SYNTHETIC_SNAPSHOT")))
PYIDS
)
seeded_webtransport() {
  for revision in 2026-07-28 2025-11-25; do
    external env DEVRES_PROBE_MDN_SNAPSHOT="$mdn_content" DEVRES_PROBE_MDN_COMPAT_SNAPSHOT="$mdn_compat" \
      DEVRES_PROBE_ADVISORY_SNAPSHOT="$advisory_snapshot" DEVRES_PROBE_WHATWG_SNAPSHOT="$whatwg_snapshot" DEVRES_PROBE_W3C_SNAPSHOT="$w3c_snapshot" DEVRES_PROBE_CHROMIUM_SNAPSHOT="$chromium_snapshot" DEVRES_PROBE_NPM_FIXTURE=1 devres-probe https://edge:30443/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example
    k exec trusted-probe -- env DEVRES_PROBE_MDN_SNAPSHOT="$mdn_content" DEVRES_PROBE_MDN_COMPAT_SNAPSHOT="$mdn_compat" \
      DEVRES_PROBE_ADVISORY_SNAPSHOT="$advisory_snapshot" DEVRES_PROBE_WHATWG_SNAPSHOT="$whatwg_snapshot" DEVRES_PROBE_W3C_SNAPSHOT="$w3c_snapshot" DEVRES_PROBE_CHROMIUM_SNAPSHOT="$chromium_snapshot" DEVRES_PROBE_NPM_FIXTURE=1 devres-probe https://backend:4433/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example \
      /fixture/cert/edge-client.pem /fixture/cert/edge-client-key.pem
  done
}
s3_capture_state() {
  k exec -i deployment/backend -- python3 - "$capture" "$1" <<'PYS3CAPTURE'
import http.client, json, runpy, socket, sys, types
class LoopbackHTTPS(http.client.HTTPSConnection):
    def connect(self):
        connection = socket.create_connection(("127.0.0.1", self.port), self.timeout)
        self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
Client = runpy.run_path("/harness/mcp_smoke.py")["Client"]
# Change only the fixture client constructor lookup. Replacing the stdlib
# class itself changes the explicit super() lookup in HTTPSConnection.__init__.
Client.exchange.__globals__["http"] = types.SimpleNamespace(client=types.SimpleNamespace(
    HTTPSConnection=LoopbackHTTPS, HTTPConnection=http.client.HTTPConnection))
client = Client("https://backend:8080/mcp", "/fixture/cert/ca.pem",
                "/fixture/cert/edge-client.pem", "/fixture/cert/edge-client-key.pem")
client.timeout = 20
status, response = client.exchange("tools/call", {
    "name": "fetch", "arguments": {"id": "devres://capture/" + sys.argv[1]}})
assert status == 200 and response and "result" in response, "backend RPC exchange failed"
result = response["result"]
if sys.argv[2] == "unavailable":
    assert result.get("isError") is True, "warm cached capture escaped the archive outage gate"
    assert result.get("structuredContent", {}).get("code") == "unavailable", "unexpected storage error"
else:
    assert not result.get("isError"), "healthy archive read failed"
    assert "Synthetic dev-resources persistence acceptance fixture" in json.dumps(result)
PYS3CAPTURE
}
stop_backend
maintenance_start
before=$(k exec storage-maintenance -- storage-probe write)
capture=${before%% *}
maintenance_stop
start_backend
external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
seeded_webtransport
if (( s3 )); then
  # A warm cache cannot mask loss of the authoritative archive. The same backend
  # process must become ready again when storage recovers.
  backend_uid=$(k get pod -l app=backend -o jsonpath='{.items[0].metadata.uid}')
  backend_restarts=$(k get pod -l app=backend -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')
  s3_capture_state healthy
  echo 'S3 warm-cache read verified before outage'
  k scale deployment/objectstore --replicas=0
  k wait --for=delete pod -l app=objectstore --timeout=120s
  echo 'Checking private readiness during object-store outage'
  k exec -i deployment/backend -- python3 - <<'PYS3READY'
import time, urllib.error, urllib.request
for attempt in range(20):
    try:
        urllib.request.urlopen("http://127.0.0.1:9090/ready", timeout=2).close()
    except urllib.error.HTTPError as error:
        if error.code == 503:
            break
        raise
    time.sleep(1)
else:
    raise SystemExit("archive outage did not make storage unready")
PYS3READY
  echo 'Private readiness rejected the object-store outage'
  s3_capture_state unavailable
  echo 'Warm-cache capture returned typed storage unavailable'
  k scale deployment/objectstore --replicas=1
  k rollout status deployment/objectstore --timeout=180s
  wait_edge
  test "$(k get pod -l app=backend -o jsonpath='{.items[0].metadata.uid}')" = "$backend_uid"
  test "$(k get pod -l app=backend -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')" = "$backend_restarts"
  s3_capture_state healthy
  echo 'Same backend process recovered after object-store restart'
fi
stop_backend
maintenance_start
test "$(k exec storage-maintenance -- storage-probe read)" = "$before"
k exec deployment/postgres -- pg_dump -U devres -Fc devres > "$scratch/postgres.dump"
if (( s3 )); then
  # The archive remains authoritative while every disposable local file is lost.
  # Database restore is against the same frozen immutable object inventory;
  # separate-prefix backup/restore is covered by the object archive acceptance.
  k exec storage-maintenance -- sh -c 'find /data/blobs -mindepth 1 -delete'
  k exec deployment/postgres -- psql -U devres -d postgres -c 'DROP DATABASE devres WITH (FORCE)'
  k exec deployment/postgres -- psql -U devres -d postgres -c 'CREATE DATABASE devres OWNER devres'
  k exec -i deployment/postgres -- pg_restore -U devres -d devres < "$scratch/postgres.dump"
  test "$(k exec storage-maintenance -- storage-probe read)" = "$before"
  k exec storage-maintenance -- sh -c 'find /data/blobs -mindepth 1 -delete'
  maintenance_stop
  start_backend
  external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
  seeded_webtransport
  echo 'Real minikube S3 isolation, complete cache loss, database restore, and HTTP/WebTransport acceptance passed'
  exit 0
fi
k exec storage-maintenance -- tar -C /data -cf - blobs > "$scratch/blobs.tar"
# Destructive restore is confined to this newly created, task-owned profile.
k exec storage-maintenance -- sh -c 'find /data/blobs -type f -delete'
k exec deployment/postgres -- psql -U devres -d postgres -c 'DROP DATABASE devres WITH (FORCE)'
k exec deployment/postgres -- psql -U devres -d postgres -c 'CREATE DATABASE devres OWNER devres'
k exec -i deployment/postgres -- pg_restore -U devres -d devres < "$scratch/postgres.dump"
k exec -i storage-maintenance -- tar -C /data -xf - < "$scratch/blobs.tar"
test "$(k exec storage-maintenance -- storage-probe read)" = "$before"
maintenance_stop
start_backend
external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
seeded_webtransport
if (( live )); then
  external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --live "${live_rfc_args[@]}"
fi
echo 'Real minikube NodePort TCP/UDP, CNI isolation, PVC restart, and coordinated restore passed'
