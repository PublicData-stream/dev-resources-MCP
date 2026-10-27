#!/usr/bin/env bash
# Isolated real Kubernetes/CNI/NodePort acceptance; never reuses an existing profile.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
live=0
live_rfc_args=()
if [[ ${1:-} == --live ]]; then live=1; shift; fi
if (( live )) && [[ ${1:-} == --rfc-text-only ]]; then live_rfc_args=(--rfc-text-only); shift; fi
test "$#" = 0 || { echo 'usage: scripts/test-minikube.sh [--live [--rfc-text-only]]' >&2; exit 2; }
if [[ -n ${DEVRES_DOCKER_HOST:-} ]]; then
  unset DOCKER_CONTEXT
  export DOCKER_HOST="$DEVRES_DOCKER_HOST"
else
  export DOCKER_CONTEXT=default
fi
scratch=$(mktemp -d)
token=${scratch##*/}
token=${token//./-}
run_id="devres-acceptance-$$-${token,,}"
profile="$run_id"
namespace=devres-acceptance
image="$run_id:local"
created=0
k() { minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=30s -n "$namespace" "$@"; }
cleanup() {
  status=$?
  if (( status != 0 && created )); then
    k get pods >&2 2>/dev/null || true
    k logs deploy/backend --tail=40 >&2 2>/dev/null || true
    k logs deploy/edge --tail=40 >&2 2>/dev/null || true
  fi
  if (( created )); then minikube -p "$profile" delete >/dev/null 2>&1 || true; fi
  if [[ $(docker image inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$image" 2>/dev/null) == "$image" ]]; then
    docker image rm "$image" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$scratch"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for command in minikube docker openssl python3 cargo; do command -v "$command" >/dev/null; done
if minikube profile list -o json | python3 -c 'import json,sys; p=json.load(sys.stdin); sys.exit(not any(v.get("Name")==sys.argv[1] for v in p.get("valid",[])+p.get("invalid",[])))' "$profile"; then
  echo 'Refusing to reuse an existing minikube profile' >&2; exit 1
fi
scripts/make-fixture.sh "$scratch"
scripts/build-harness.sh "$scratch" "$image"
# Set the cleanup fence before startup so partially created task-owned profiles go away.
created=1
minikube -p "$profile" start --driver=docker --container-runtime=containerd --cni=calico \
  --cpus=4 --memory=6144 --subnet=10.223.254.0/24 --keep-context
minikube -p "$profile" image load "$image"
k create namespace "$namespace" --dry-run=client -o yaml | k apply -f -
k create secret generic devres-config --from-file=backend.toml="$scratch/fixture/backend.toml" \
  --from-literal=postgres-password=fixture-only
k create secret generic devres-tls --from-file="$scratch/fixture/cert/"
k create configmap devres-edge-config --from-file=oxibelt.toml="$scratch/fixture/config/oxibelt.toml"
sed "s|DEVRES_HARNESS_IMAGE|$image|g" deploy/kubernetes/foundation.yaml | k apply -f -
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
  python3 - "$image" > "$scratch/maintenance.yaml" <<'PY'
import json,sys
print(json.dumps({"apiVersion":"v1","kind":"Pod","metadata":{"name":"storage-maintenance","labels":{"app":"backend"}},"spec":{
 "automountServiceAccountToken":False,"restartPolicy":"Never","securityContext":{"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532},
 "containers":[{"name":"maintenance","image":sys.argv[1],"imagePullPolicy":"Never","command":["sleep","3600"],
 "env":[{"name":"DATABASE_URL","value":"postgres://devres:fixture-only@postgres/devres"},{"name":"BLOB_DIR","value":"/data/blobs"}],
 "volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"devres-data"}}]}}))
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
mdn_content=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:mdn-content:v1").hexdigest())')
mdn_compat=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:mdn-compat:v1").hexdigest())')
whatwg_snapshot=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:whatwg:v1").hexdigest())')
w3c_snapshot=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:w3c:v1").hexdigest())')
advisory_snapshot=$(python3 -c 'import hashlib;print(hashlib.sha256(b"devres:storage-probe:rustsec:v1").hexdigest())')
seeded_webtransport() {
  for revision in 2026-07-28 2025-11-25; do
    external env DEVRES_PROBE_MDN_SNAPSHOT="$mdn_content" DEVRES_PROBE_MDN_COMPAT_SNAPSHOT="$mdn_compat" \
      DEVRES_PROBE_ADVISORY_SNAPSHOT="$advisory_snapshot" DEVRES_PROBE_WHATWG_SNAPSHOT="$whatwg_snapshot" DEVRES_PROBE_W3C_SNAPSHOT="$w3c_snapshot" devres-probe https://edge:30443/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example
    k exec trusted-probe -- env DEVRES_PROBE_MDN_SNAPSHOT="$mdn_content" DEVRES_PROBE_MDN_COMPAT_SNAPSHOT="$mdn_compat" \
      DEVRES_PROBE_ADVISORY_SNAPSHOT="$advisory_snapshot" DEVRES_PROBE_WHATWG_SNAPSHOT="$whatwg_snapshot" DEVRES_PROBE_W3C_SNAPSHOT="$w3c_snapshot" devres-probe https://backend:4433/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example \
      /fixture/cert/edge-client.pem /fixture/cert/edge-client-key.pem
  done
}
stop_backend
maintenance_start
before=$(k exec storage-maintenance -- storage-probe write)
capture=${before%% *}
maintenance_stop
start_backend
external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
seeded_webtransport
stop_backend
maintenance_start
test "$(k exec storage-maintenance -- storage-probe read)" = "$before"
k exec deployment/postgres -- pg_dump -U devres -Fc devres > "$scratch/postgres.dump"
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
