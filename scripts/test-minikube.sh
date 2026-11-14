#!/usr/bin/env bash
# Isolated real Kubernetes/CNI/NodePort acceptance; never reuses an existing profile.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
requested_args=("$@")
live=0
s3=0
credential_broker=0
live_rfc_args=()
supplied_image=
while (( $# )); do
  case "$1" in
    --image) [[ $# -ge 2 && -n $2 && $2 != -* ]] || { echo '--image requires an image' >&2; exit 2; }; supplied_image=$2; shift 2 ;;
    --live) live=1; shift ;;
    --s3) s3=1; shift ;;
    --credential-broker) credential_broker=1; shift ;;
    --rfc-text-only) live_rfc_args=(--rfc-text-only); shift ;;
    *) echo 'usage: scripts/test-minikube.sh [--image IMAGE] [--s3 [--credential-broker]] [--live [--rfc-text-only]]' >&2; exit 2 ;;
  esac
done
if (( ! live && ${#live_rfc_args[@]} )); then echo '--rfc-text-only requires --live' >&2; exit 2; fi
if (( s3 && live )); then echo '--s3 is an isolated fixture scenario and does not accept --live' >&2; exit 2; fi
if (( credential_broker && ! s3 )); then echo '--credential-broker requires --s3' >&2; exit 2; fi
# Canonical synthetic RFC captures must never satisfy later live-provider probes.
collector_providers=(w3c chromium)
if (( ! live )); then collector_providers+=(rfc rustsec); fi
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
  # Explicitly validate this metadata allowlist before retaining it. Credential
  # responses and arbitrary fixture files must never enter diagnostics.
  python3 - "$scratch" "$diagnostics" <<'PYBROKERDIAG' || true
import json, math, pathlib, sys
for name in ('reader-key-metadata.json', 'recovered-reader-key-metadata.json'):
    try:
        with (pathlib.Path(sys.argv[1]) / name).open('rb') as source:
            raw = source.read(4097)
        assert len(raw) <= 4096
        value = json.loads(raw)
        assert set(value) == {'key_hash', 'expires_at', 'observed_at'}
        assert isinstance(value['key_hash'], str) and len(value['key_hash']) == 64
        assert all(char in '0123456789abcdef' for char in value['key_hash'])
        assert all(isinstance(value[key], (int, float)) and math.isfinite(value[key])
                   for key in ('expires_at', 'observed_at'))
        (pathlib.Path(sys.argv[2]) / name).write_text(json.dumps(value) + '\n')
    except (OSError, ValueError, TypeError, AssertionError):
        pass
PYBROKERDIAG
  if (( created )); then
    diag_capture pods.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" get pods -o wide
    diag_capture pvc.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" get pvc -o 'custom-columns=NAME:.metadata.name,PHASE:.status.phase,VOLUME:.spec.volumeName,CAPACITY:.status.capacity.storage'
    diag_capture container-state.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" get pods -o 'jsonpath={range .items[*]}{.metadata.name}{" phase="}{.status.phase}{"\n"}{range .status.initContainerStatuses[*]}{.name}{" restarts="}{.restartCount}{" waiting="}{.state.waiting.reason}{" terminated="}{.state.terminated.reason}{" exit="}{.state.terminated.exitCode}{" last="}{.lastState.terminated.reason}{" lastExit="}{.lastState.terminated.exitCode}{"\n"}{end}{range .status.containerStatuses[*]}{.name}{" ready="}{.ready}{" restarts="}{.restartCount}{" waiting="}{.state.waiting.reason}{" terminated="}{.state.terminated.reason}{" exit="}{.state.terminated.exitCode}{" signal="}{.state.terminated.signal}{" last="}{.lastState.terminated.reason}{" lastExit="}{.lastState.terminated.exitCode}{"\n"}{end}{end}'
    diag_capture backend-memory.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" exec deployment/backend -- sh -c 'for file in /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.events; do if test -r "$file"; then echo "$file"; cat "$file"; fi; done'
    diag_capture events.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" get events --field-selector type=Warning --sort-by=.lastTimestamp
    diag_capture backend-previous.log minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" logs deploy/backend --previous --tail=100 --limit-bytes=65536
    if [[ ${credential_broker:-0} == 1 ]]; then
      diag_capture archive-control-state.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" exec deployment/postgres -- psql -U devres -d devres -Atc "SELECT backend,binding IS NOT NULL AS has_binding,pending_binding IS NOT NULL AS has_pending,initializing_s3,epoch FROM devres_archive_control WHERE singleton"
      diag_capture broker-journal-state.txt minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" exec deployment/postgres -- psql -U devres -d devres_broker_test -Atc "SELECT state,expires_at<EXTRACT(EPOCH FROM now()) AS expired,expires_at-requested_expiry AS expiry_delta,access_key IS NULL AS missing_public_key,ciphertext IS NULL AS missing_ciphertext,encryption_key IS NULL AS missing_key_id,count(*) FROM devres_credential_broker_keys GROUP BY 1,2,3,4,5,6 ORDER BY 1,2,3,4,5,6"
      diag_capture iam-fixture-counters.json minikube -p "$profile" kubectl -- --cache-dir="${DEVRES_TMP_ROOT:-$scratch}/kube/cache" --context="$profile" --request-timeout=10s -n "$namespace" exec deployment/iam-fixture -- python3 -I -B -c 'import json,pathlib; raw=pathlib.Path("/fixture/broker-state/iam-state.json").read_bytes(); assert len(raw)<=1048576; state=json.loads(raw); counters=state["counters"]; selected={key:counters[key] for key in ("create","delete","list")}; assert all(isinstance(value,int) and 0<=value<=1000000 for value in selected.values()); selected["entries"]=len(state["entries"]); print(json.dumps(selected))'
    fi
  for component in backend writer credential-broker iam-fixture edge postgres; do
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
if (( credential_broker )); then python3 scripts/credential-broker-fixture.py prepare "$scratch" kubernetes; fi
python3 scripts/split-runtime-fixture.py "$scratch" kubernetes
# Exercise mounted Wikipedia credentials without an operator User-Agent: both
# roles must start and serve retained fixtures while Wikimedia I/O stays paused.
python3 - "$scratch/fixture" <<'PYWIKIPEDIA'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
for name in ('backend.toml', 'writer.toml'):
    path = root / name
    text = path.read_text()
    assert text.count('[wikipedia]') == 1
    text = text.replace('[wikipedia]', '[wikipedia]\noauth2_token_file = "/run/devres-wikipedia/token"', 1)
    path.write_text(text)
token = root / 'wikipedia-token'
token.write_text('synthetic-wikipedia-token\n')
token.chmod(0o600)
PYWIKIPEDIA
if (( credential_broker )); then python3 scripts/broker-kubernetes-fixture.py configure "$scratch"; fi
python3 scripts/secrets-encryption-fixture.py prepare "$MINIKUBE_HOME"
if [[ -z $supplied_image ]]; then
  scripts/build-harness.sh "$scratch" "$image"
else
  docker image inspect "$image" >/dev/null
fi
if (( credential_broker )); then
  for command in profile-fingerprints issuer-fingerprint; do
    docker run --rm --network none --read-only --user "$(id -u):$(id -g)" --cap-drop ALL \
      -v "$scratch/fixture:/fixture:ro" --entrypoint devres-credential-broker "$image" \
      "$command" /fixture/broker/broker.toml > "$scratch/fixture/broker/$command"
  done
  python3 scripts/credential-broker-fixture.py receipt "$scratch/fixture/broker" "$scratch/fixture/broker/profile-fingerprints"
fi
# Set the cleanup fence before startup so partially created task-owned profiles go away.
created=1
scripts/e2e-storage.sh before-minikube-start "$image" "$scratch" || true
minikube -p "$profile" start --driver=docker --container-runtime=containerd --cni=calico \
  --kubernetes-version="${DEVRES_KUBERNETES_VERSION:-v1.37.0}" \
  --extra-config=apiserver.encryption-provider-config=/var/lib/minikube/certs/devres-encryption.json \
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
k create secret generic devres-encryption-canary --from-literal=value=devres-synthetic-encryption-canary
etcd_pod=$(k -n kube-system get pods -l component=etcd -o jsonpath='{.items[0].metadata.name}')
k -n kube-system get pod "$etcd_pod" -o json > "$scratch/etcd-pod.json"
python3 - "$scratch/etcd-pod.json" > "$scratch/etcd-paths" <<'PYETCD'
import json, sys
pod = json.load(open(sys.argv[1]))
arguments = pod['spec']['containers'][0]['command']
for flag in ('--trusted-ca-file=', '--cert-file=', '--key-file='):
    values = [value[len(flag):] for value in arguments if value.startswith(flag)]
    if len(values) != 1 or not values[0].startswith('/'):
        raise SystemExit('Expected explicit etcd TLS identity paths')
    print(values[0])
PYETCD
mapfile -t etcd_paths < "$scratch/etcd-paths"
k -n kube-system exec "$etcd_pod" -- etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert="${etcd_paths[0]}" --cert="${etcd_paths[1]}" --key="${etcd_paths[2]}" \
  get "/registry/secrets/$namespace/devres-encryption-canary" --print-value-only > "$scratch/encrypted-secret"
python3 scripts/secrets-encryption-fixture.py verify "$scratch/encrypted-secret"
k delete secret devres-encryption-canary
if (( s3 )); then
  k create secret generic devres-s3-credentials --from-file="$scratch/fixture/s3/"
  k create secret generic devres-serving-s3 --from-file="$scratch/fixture/s3-serving/"
  k create secret generic devres-writer-s3 --from-file="$scratch/fixture/s3-writer/"
fi
k create secret generic devres-config --from-file=backend.toml="$scratch/fixture/backend.toml" \
  --from-literal=postgres-password=fixture-only
k create secret generic devres-writer-config --from-file=writer.toml="$scratch/fixture/writer.toml"
k create secret generic devres-wikipedia-identity --from-file=token="$scratch/fixture/wikipedia-token"
if (( credential_broker )); then
  broker_files=()
  for name in broker.toml database-url keyring.json issuer-key receipt.json; do
    broker_files+=(--from-file="$name=$scratch/fixture/broker/$name")
  done
  k create secret generic devres-broker-private "${broker_files[@]}"
  k create secret generic devres-iam-fixture --from-file=iam-fixture.json="$scratch/fixture/broker/iam-fixture.json"
fi
k create secret generic devres-tls --from-file="$scratch/fixture/cert/"
k create configmap devres-edge-config --from-file=oxibelt.toml="$scratch/fixture/config/oxibelt.toml"
sed "s|DEVRES_HARNESS_IMAGE|$image|g" deploy/kubernetes/foundation.yaml > "$scratch/foundation.yaml"
if (( s3 && ! credential_broker )); then python3 scripts/s3-kubernetes-fixture.py foundation "$scratch/foundation.yaml"; fi
if (( credential_broker )); then python3 scripts/broker-kubernetes-fixture.py workloads "$scratch/foundation.yaml"; fi
k apply -f "$scratch/foundation.yaml"
sed -e "s|DEVRES_HARNESS_IMAGE|$image|g" -e "s|DEVRES_AUTH_REVIEWER|$run_id-reviewer|g" \
  deploy/kubernetes/split-runtime.yaml > "$scratch/split-runtime.yaml"
if (( s3 && ! credential_broker )); then python3 scripts/s3-kubernetes-fixture.py writer "$scratch/split-runtime.yaml"; fi
if (( credential_broker )); then python3 scripts/broker-kubernetes-fixture.py workloads "$scratch/split-runtime.yaml"; fi
k apply -f "$scratch/split-runtime.yaml"
k patch deployment writer --type=json -p='[
  {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"wikipedia-identity","secret":{"secretName":"devres-wikipedia-identity","defaultMode":288}}},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"wikipedia-identity","mountPath":"/run/devres-wikipedia","readOnly":true}}
]'
k rollout status deployment/postgres --timeout=180s
k exec -i deployment/postgres -- psql -v ON_ERROR_STOP=1 -U devres -d devres < "$scratch/reader-role.sql" >/dev/null
if (( credential_broker )); then
  k exec -i deployment/postgres -- psql -v ON_ERROR_STOP=1 -U devres -d postgres < "$scratch/fixture/broker/database-init.sql" >/dev/null
  python3 scripts/broker-kubernetes-fixture.py manifests "$image" "$run_id-reviewer" > "$scratch/broker.json"
  k apply -f "$scratch/broker.json"
fi
if (( s3 )); then
  k apply -f deploy/kubernetes/s3-fixture.yaml
  k -n kube-system rollout status deployment/coredns --timeout=120s
  k rollout status deployment/objectstore --timeout=180s
  python3 scripts/s3-kubernetes-fixture.py initializer "$image" > "$scratch/objectstore-init.json"
  k apply -f "$scratch/objectstore-init.json"
  k wait --for=condition=Complete job/objectstore-init --timeout=120s
  k delete job/objectstore-init --wait=true
  if (( credential_broker )); then
    k rollout status deployment/iam-fixture --timeout=180s
    k rollout status deployment/credential-broker --timeout=180s
  fi
fi
k scale deployment/writer --replicas=1
k rollout status deployment/writer --timeout=180s
k scale deployment/backend --replicas=1
for deployment in postgres writer backend edge; do k rollout status deployment/"$deployment" --timeout=180s; done
k exec deployment/writer -- python3 -I -B -c 'import pathlib; p=pathlib.Path("/run/devres-wikipedia/token"); assert p.is_file() and p.read_text().strip()=="synthetic-wikipedia-token"'
k exec deployment/backend -- python3 -I -B -c 'import pathlib; assert not pathlib.Path("/run/devres-wikipedia/token").exists()'
echo 'Wikipedia writer-only Secret mount and startup without User-Agent verified'
if (( credential_broker )); then
  wait_broker_service() {
    # Pod readiness precedes Service endpoint convergence. Check the same DNS,
    # CA and HTTPS path the serving workload will use, without sending a token.
    k exec -i deployment/backend -- python3 -I -B - <<'PYBROKERREADY'
import ssl, time, urllib.error, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile='/fixture/cert/ca.pem')))
deadline = time.monotonic() + 20
while True:
    try:
        with opener.open('https://credential-broker:8444/healthz', timeout=2) as response:
            if response.status == 204:
                break
    except (urllib.error.URLError, TimeoutError, OSError):
        pass
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SystemExit('CA-validated broker Service health did not become ready within 20 seconds')
    time.sleep(min(0.2, remaining))
PYBROKERREADY
  }
  # Run the actual S3 authorization probe and retain only public identifier hashes
  # and expiry metadata. A 60-second fixture lease can enter its refresh window
  # during a slow broker rollout; renewal then must not be mistaken for data loss.
  broker_reader_probe() {
    k exec -i deployment/backend -- python3 -I -B - <<'PYBROKERPROBE'
import datetime, json, pathlib, runpy, time, traceback, types
probe = runpy.run_path('/harness/broker-pod-probe.py')['check']
expiration = []
def decode(value):
    credential = json.loads(value)
    expiration.append((datetime.datetime.fromisoformat(
        credential['Expiration'].replace('Z', '+00:00')).timestamp(), time.time()))
    return credential
probe.__globals__['json'] = types.SimpleNamespace(loads=decode)
try:
    key_hash = probe('readonly')
    assert len(expiration) == 1
    assert expiration[0][0] > time.time(), 'Probe credential expired'
    print(json.dumps({'key_hash': key_hash, 'expires_at': expiration[0][0],
                      'observed_at': expiration[0][1]}))
except Exception as error:
    location = traceback.extract_tb(error.__traceback__)[-1]
    detail = f'{type(error).__name__} at {pathlib.Path(location.filename).name}:{location.lineno}'
    status = getattr(error, 'code', None)
    if isinstance(status, int):
        detail += f' HTTP {status}'
    if isinstance(error, AssertionError) and str(error) in (
            'prefix read', 'prefix listing', 'outside prefix denied', 'administration denied',
            'reader write denied', 'reader delete denied', 'Probe credential expired'):
        detail += ': ' + str(error)
    raise SystemExit('Workload credential role acceptance failed: ' + detail) from None
PYBROKERPROBE
  }
  wait_broker_service
  k exec deployment/writer -- python3 -I -B /harness/broker-pod-probe.py readwrite > "$scratch/writer-key-id"
  broker_reader_probe > "$scratch/reader-key-metadata.json"
  python3 - "$scratch/reader-key-metadata.json" "$scratch/writer-key-id" <<'PYBROKERIDENTITY'
import json, pathlib, sys
reader = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert reader['key_hash'] != pathlib.Path(sys.argv[2]).read_text().strip(), 'Distinct pod identities received the same key'
PYBROKERIDENTITY
  k rollout restart deployment/credential-broker
  k rollout status deployment/credential-broker --timeout=180s
  wait_broker_service
  broker_reader_probe > "$scratch/recovered-reader-key-metadata.json"
  python3 - "$scratch/reader-key-metadata.json" "$scratch/recovered-reader-key-metadata.json" <<'PYBROKERRECOVERY'
import json, pathlib, sys
before, after = (json.loads(pathlib.Path(path).read_text()) for path in sys.argv[1:])
assert after['expires_at'] > after['observed_at'], 'Recovered credentials already expired'
if before['key_hash'] == after['key_hash']:
    assert before['expires_at'] == after['expires_at'], 'Recovery changed an existing lease expiry'
    print('Encrypted broker restart reused the unexpired pod credential; S3 role enforcement verified')
else:
    assert after['observed_at'] >= before['expires_at'] - 10, 'Broker lost a credential before its refresh window'
    assert after['expires_at'] > before['expires_at'], 'Renewal did not extend the lease'
    print('Broker restart crossed the fixture refresh window; valid distinct renewal and S3 role enforcement verified')
PYBROKERRECOVERY
  echo 'Real pod identities and distinct S3 role enforcement verified'
fi
if (( s3 && ! credential_broker )); then
  k exec deployment/writer -- python3 -I -B /harness/static-s3-fixture.py check writer \
    /fixture/s3/probe.json /fixture/s3 > "$scratch/static-writer-id"
  k exec deployment/backend -- python3 -I -B /harness/static-s3-fixture.py check serving \
    /fixture/s3/probe.json /fixture/s3 > "$scratch/static-serving-id"
  if cmp -s "$scratch/static-writer-id" "$scratch/static-serving-id"; then
    echo 'Static serving and writer received the same key' >&2; exit 1
  fi
  echo 'Distinct static credentials and S3 read/write boundaries verified'
fi
static_admin_action() {
  python3 - "$scratch/objectstore-init.json" "$1" > "$scratch/static-s3-operation.json" <<'PYSTATICJOB'
import json, sys
assert sys.argv[2] in ('bootstrap', 'revoke-serving')
manifest = json.load(open(sys.argv[1]))
manifest['metadata']['name'] = 'static-s3-operation'
manifest['spec']['template']['spec']['containers'][0]['command'] = [
    'python3', '-I', '-B', '/harness/static-s3-fixture.py', sys.argv[2], '/fixture/s3/static-fixture.json']
print(json.dumps(manifest))
PYSTATICJOB
  k apply -f "$scratch/static-s3-operation.json"
  k wait --for=condition=Complete job/static-s3-operation --timeout=120s
  k delete job/static-s3-operation --wait=true
}
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
  k scale deployment/writer --replicas=0
  k wait --for=delete pod -l app=writer --timeout=120s
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
    pod['spec']['volumes'].append({'name':'s3','secret':{'secretName':'devres-writer-s3','defaultMode':0o440}})
print(json.dumps(pod))
PY
  k apply -f "$scratch/maintenance.yaml"
  k wait --for=condition=Ready pod/storage-maintenance --timeout=120s
}
maintenance_stop() { k delete pod/storage-maintenance --wait=true; }
start_backend() {
  k scale deployment/writer --replicas=1
  k rollout status deployment/writer --timeout=120s
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
      DEVRES_PROBE_ADVISORY_SNAPSHOT="$advisory_snapshot" DEVRES_PROBE_WHATWG_SNAPSHOT="$whatwg_snapshot" DEVRES_PROBE_W3C_SNAPSHOT="$w3c_snapshot" DEVRES_PROBE_CHROMIUM_SNAPSHOT="$chromium_snapshot" DEVRES_PROBE_NPM_FIXTURE=1 DEVRES_PROBE_WIKIPEDIA_FIXTURE=1 devres-probe https://edge:30443/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example
    k exec trusted-probe -- env DEVRES_PROBE_MDN_SNAPSHOT="$mdn_content" DEVRES_PROBE_MDN_COMPAT_SNAPSHOT="$mdn_compat" \
      DEVRES_PROBE_ADVISORY_SNAPSHOT="$advisory_snapshot" DEVRES_PROBE_WHATWG_SNAPSHOT="$whatwg_snapshot" DEVRES_PROBE_W3C_SNAPSHOT="$w3c_snapshot" DEVRES_PROBE_CHROMIUM_SNAPSHOT="$chromium_snapshot" DEVRES_PROBE_NPM_FIXTURE=1 DEVRES_PROBE_WIKIPEDIA_FIXTURE=1 devres-probe https://backend:4433/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example \
      /fixture/cert/edge-client.pem /fixture/cert/edge-client-key.pem
  done
}
collector_reads() {
  external python3 /harness/collector-smoke.py --url https://edge:30443/mcp \
    --ca /fixture/cert/ca.pem --receipts /fixture/collector-receipts.json
  for revision in 2026-07-28 2025-11-25; do
    external env DEVRES_PROBE_COLLECTOR_RECEIPTS=/fixture/collector-receipts.json \
      devres-probe https://edge:30443/mcp-wt/v1 /fixture/cert/ca.pem "$revision" https://client.example
  done
}
attribution_readback() {
  # The receipt contains bounded first-party fixture evidence only. Keep it under
  # /tmp across maintenance-pod replacement, backend restart and database restore.
  k exec -i storage-maintenance -- sh -c 'cat > /tmp/attribution-backlog-receipt.json' \
    < "$scratch/attribution-backlog-receipt.json"
  k exec storage-maintenance -- devres-collector-tests --ignored --test-threads=1 \
    attribution_backlog_cluster_readback
  if [[ -f $scratch/attribution-origins-v2-receipt.json ]]; then
    k exec -i storage-maintenance -- sh -c 'cat > /tmp/attribution-origins-v2-receipt.json' \
      < "$scratch/attribution-origins-v2-receipt.json"
    k exec storage-maintenance -- devres-collector-tests --ignored --test-threads=1 \
      attribution_origins_v2_cluster_readback
  fi
  if [[ -f $scratch/rustsec-collector.json ]]; then
    k exec -i storage-maintenance -- sh -c 'cat > /tmp/rustsec-collector-receipt.json' \
      < "$scratch/rustsec-collector.json"
    k exec storage-maintenance -- devres-collector-tests --ignored --test-threads=1 \
      rustsec_collector_cluster_readback
  fi
}
s3_capture_state() {
  k exec -i deployment/backend -- python3 - "$capture" "$1" <<'PYS3CAPTURE'
import http.client, re, runpy, socket, sys, time, types, urllib.error, urllib.request
def capture_state(client, capture, expected, clock=time.monotonic, sleep=time.sleep, deadline_secs=180, ready=None):
    assert expected in ("healthy", "unavailable", "recover"), "unknown capture state"
    deadline = clock() + deadline_secs if expected == "recover" else None
    uri = "devres://capture/" + capture
    while True:
        remaining = deadline - clock() if deadline is not None else 20
        assert remaining > 0, "authoritative capture recovery deadline exceeded"
        client.timeout = min(20, remaining)
        try:
            status, response = client.exchange("tools/call", {
                "name": "fetch", "arguments": {"id": uri}})
        except (OSError, ValueError):
            raise AssertionError("backend RPC transport or decoding failed") from None
        if deadline is not None:
            assert clock() <= deadline, "authoritative capture recovery deadline exceeded"
        assert status == 200 and isinstance(response, dict) and "error" not in response, "backend RPC exchange failed"
        result = response.get("result")
        assert isinstance(result, dict), "backend RPC result missing"
        if result.get("isError") is True:
            error = result.get("structuredContent")
            assert isinstance(error, dict), "typed capture error missing"
            code = error.get("code")
            assert isinstance(code, str) and re.fullmatch(r"[a-z0-9_]{1,64}", code), "typed capture error code invalid"
            print("Archive capture state code=" + code, flush=True)
            if expected == "unavailable":
                assert code == "unavailable", "unexpected storage error code=" + code
                return
            assert expected == "recover" and code == "unavailable", "healthy archive read failed code=" + code
            remaining = deadline - clock()
            assert remaining > 0, "authoritative capture recovery deadline exceeded"
            sleep(min(1, remaining))
            continue
        assert result.get("isError") is None or result.get("isError") is False, "invalid capture error flag"
        assert expected != "unavailable", "warm cached capture escaped the archive outage gate"
        value = result.get("structuredContent")
        assert isinstance(value, dict), "structured capture result missing"
        contents = value.get("contents")
        assert isinstance(contents, list) and all(isinstance(item, dict) for item in contents), "capture contents invalid"
        selected = [item for item in contents if item.get("uri") == uri]
        assert len(selected) == 1, "capture identity changed"
        for item in contents:
            if item.get("uri") != uri:
                assert isinstance(item.get("uri"), str) and item["uri"].startswith("devres://attribution/"), "unexpected capture resource"
        item = selected[0]
        assert item.get("mimeType") == "text/plain", "capture media type changed"
        assert item.get("text") == "Synthetic dev-resources persistence acceptance fixture\n", "capture body changed"
        if expected == "recover" and ready is not None:
            while True:
                remaining = deadline - clock()
                assert remaining > 0, "private storage readiness recovery deadline exceeded"
                available = ready(min(2, remaining))
                assert clock() <= deadline, "private storage readiness recovery deadline exceeded"
                if available:
                    break
                remaining = deadline - clock()
                assert remaining > 0, "private storage readiness recovery deadline exceeded"
                sleep(min(1, remaining))
        return

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
def private_ready(timeout):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open("http://127.0.0.1:9090/ready", timeout=timeout) as response:
            assert response.status == 200, "private health returned an unexpected status"
            return True
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        assert status == 503, "private health returned an unexpected error status"
        return False
    except (OSError, ValueError):
        raise AssertionError("private health transport failed") from None
capture_state(client, sys.argv[1], sys.argv[2], ready=private_ready)
PYS3CAPTURE
}
stop_backend
maintenance_start
k exec storage-maintenance -- devres-collector-tests --ignored --test-threads=1 \
  attribution_backlog_cluster_seed
k exec storage-maintenance -- cat /tmp/attribution-backlog-receipt.json \
  > "$scratch/attribution-backlog-receipt.json"
test "$(wc -c < "$scratch/attribution-backlog-receipt.json")" -le 32768
attribution_readback
before=$(k exec storage-maintenance -- storage-probe write)
for provider in "${collector_providers[@]}"; do
  k exec storage-maintenance -- devres-collector-tests --ignored --test-threads=1 "${provider}_collector_cluster_seed"
  k exec storage-maintenance -- cat "/tmp/${provider}-collector-receipt.json" > "$scratch/$provider-collector.json"
done
k exec storage-maintenance -- devres-collector-tests --ignored --test-threads=1 \
  attribution_origins_v2_cluster_seed
k exec storage-maintenance -- cat /tmp/attribution-origins-v2-receipt.json \
  > "$scratch/attribution-origins-v2-receipt.json"
test "$(wc -c < "$scratch/attribution-origins-v2-receipt.json")" -le 262144
attribution_readback
if (( ! live )); then
  k exec storage-maintenance -- devres-collector-tests --ignored --test-threads=1 \
    rustsec_collector_cluster_readback
fi
python3 - "$scratch" "${collector_providers[@]}" <<'PYCOLLECTOR'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
providers = tuple(sys.argv[2:])
assert providers in (('w3c', 'chromium'), ('w3c', 'chromium', 'rfc', 'rustsec')), 'unexpected fixture provider selection'
receipts = []
for provider in providers:
    with (root / (provider + '-collector.json')).open('rb') as source:
        raw = source.read(32769)
    assert len(raw) <= 32768, 'collector receipt exceeds bound'
    receipts.append(json.loads(raw))
(root / 'fixture/collector-receipts.json').write_text(json.dumps(receipts))
PYCOLLECTOR
capture=${before%% *}
maintenance_stop
start_backend
external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
seeded_webtransport
collector_reads
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
  # Ambiguous credential renewal during the outage remains reserved until the
  # fixture lease (60s) plus uncertainty (60s) expires. Only typed unavailable is
  # retryable; a fixed capture and exact body must recover within 180 seconds.
  s3_capture_state recover
  test "$(k get pod -l app=backend -o jsonpath='{.items[0].metadata.uid}')" = "$backend_uid"
  test "$(k get pod -l app=backend -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')" = "$backend_restarts"
  echo 'Same backend process recovered after object-store restart'
fi
if (( s3 && ! credential_broker )); then
  static_admin_action revoke-serving
  k exec -i deployment/backend -- python3 -I -B - <<'PYSTATICREADY'
import time, urllib.error, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for attempt in range(20):
    try:
        opener.open('http://127.0.0.1:9090/ready', timeout=2).close()
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        assert status == 503
        break
    time.sleep(1)
else:
    raise SystemExit('Revoked static credentials did not withhold readiness')
PYSTATICREADY
  s3_capture_state unavailable
  stop_backend
  python3 -I -B scripts/s3-kubernetes-fixture.py rotate "$scratch"
  for name in devres-s3-credentials devres-serving-s3 devres-writer-s3; do
    case "$name" in
      devres-s3-credentials) directory=s3 ;;
      devres-serving-s3) directory=s3-serving ;;
      devres-writer-s3) directory=s3-writer ;;
    esac
    k create secret generic "$name" --from-file="$scratch/fixture/$directory/" --dry-run=client -o yaml | k apply -f -
  done
  static_admin_action bootstrap
  start_backend
  k exec deployment/backend -- python3 -I -B /harness/static-s3-fixture.py check serving /fixture/s3/probe.json /fixture/s3 > "$scratch/rotated-static-serving-id"
  k exec deployment/writer -- python3 -I -B /harness/static-s3-fixture.py check writer /fixture/s3/probe.json /fixture/s3 > "$scratch/rotated-static-writer-id"
  if cmp -s "$scratch/static-serving-id" "$scratch/rotated-static-serving-id" || cmp -s "$scratch/static-writer-id" "$scratch/rotated-static-writer-id"; then
    echo 'Static rotation did not replace both role identities' >&2; exit 1
  fi
  s3_capture_state recover
  echo 'Static revocation failed closed; stopped role rotation preserved historical reads'
fi
stop_backend
maintenance_start
test "$(k exec storage-maintenance -- storage-probe read)" = "$before"
attribution_readback
k exec deployment/postgres -- pg_dump -U devres -Fc devres > "$scratch/postgres.dump"
if (( s3 )); then
  # The archive remains authoritative while every disposable local file is lost.
  # Database restore is against the same frozen immutable object inventory;
  # separate-prefix backup/restore is covered by the object archive acceptance.
  k exec storage-maintenance -- sh -c 'find /data/blobs -mindepth 1 -delete'
  k exec deployment/postgres -- psql -U devres -d postgres -c 'DROP DATABASE devres WITH (FORCE)'
  k exec deployment/postgres -- psql -U devres -d postgres -c 'CREATE DATABASE devres OWNER devres_writer'
  k exec -i deployment/postgres -- pg_restore -U devres -d devres < "$scratch/postgres.dump"
  test "$(k exec storage-maintenance -- storage-probe read)" = "$before"
  attribution_readback
  k exec storage-maintenance -- sh -c 'find /data/blobs -mindepth 1 -delete'
  maintenance_stop
  start_backend
  external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
  seeded_webtransport
  collector_reads
  if (( credential_broker )); then
    # Rehearse credential-method changes against one committed binding. Serving's
    # emptyDir cache is lost with each stopped Pod; no archive or journal is pruned.
    k exec deployment/postgres -- psql -U devres -d devres -Atc \
      'SELECT binding,epoch FROM devres_archive_control WHERE singleton' > "$scratch/broker-original-binding"
    stop_backend
    deadline=$((SECONDS+180))
    until [[ $(k exec deployment/postgres -- psql -U devres -d devres_broker_test -Atc \
      "SELECT count(*) FROM devres_credential_broker_keys WHERE state <> 'revoked'") == 0 ]]; do
      if (( SECONDS >= deadline )); then echo 'Broker journal did not drain before static cutover' >&2; exit 1; fi
      sleep 2
    done
    k scale deployment/credential-broker --replicas=0
    k wait --for=delete pod -l app=credential-broker --timeout=120s
    cp -p "$scratch/fixture/backend.toml" "$scratch/broker-backend.toml"
    cp -p "$scratch/fixture/writer.toml" "$scratch/broker-writer.toml"
    python3 -I -B scripts/s3-kubernetes-fixture.py configure-static "$scratch"
    k create secret generic devres-config --from-file=backend.toml="$scratch/fixture/backend.toml" \
      --from-literal=postgres-password=fixture-only --dry-run=client -o yaml | k apply -f -
    k create secret generic devres-writer-config --from-file=writer.toml="$scratch/fixture/writer.toml" \
      --dry-run=client -o yaml | k apply -f -
    for deployment in backend writer; do
      k get deployment "$deployment" -o json > "$scratch/$deployment-broker-deployment.json"
      python3 - "$scratch/$deployment-broker-deployment.json" "$scratch/$deployment" "$deployment" <<'PYCUTOVERTEMPLATE'
import json, pathlib, sys
original = json.loads(pathlib.Path(sys.argv[1]).read_text())['spec']['template']
pathlib.Path(sys.argv[2] + '-broker-template.json').write_text(json.dumps({'spec': {'template': original}}))
pod = original['spec']
pod['volumes'] = [value for value in pod['volumes'] if value['name'] != 'broker-identity']
role = 'serving' if sys.argv[3] == 'backend' else 'writer'
pod['volumes'].append({'name': 's3', 'secret': {'secretName': 'devres-' + role + '-s3', 'defaultMode': 0o440}})
for container in pod['containers']:
    container['volumeMounts'] = [value for value in container['volumeMounts'] if value['name'] != 'broker-identity']
    container['volumeMounts'].append({'name': 's3', 'mountPath': '/fixture/s3', 'readOnly': True})
pathlib.Path(sys.argv[2] + '-static-template.json').write_text(json.dumps({'spec': {'template': original}}))
PYCUTOVERTEMPLATE
      k patch deployment "$deployment" --type merge --patch-file "$scratch/$deployment-static-template.json"
    done
    start_backend
    external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
    k exec deployment/backend -- python3 -I -B /harness/static-s3-fixture.py check serving /fixture/s3/probe.json /fixture/s3 > "$scratch/cutover-static-serving-id"
    k exec deployment/writer -- python3 -I -B /harness/static-s3-fixture.py check writer /fixture/s3/probe.json /fixture/s3 > "$scratch/cutover-static-writer-id"
    k exec deployment/postgres -- psql -U devres -d devres -Atc \
      'SELECT binding,epoch FROM devres_archive_control WHERE singleton' > "$scratch/static-binding"
    cmp "$scratch/broker-original-binding" "$scratch/static-binding"
    stop_backend
    cp -p "$scratch/broker-backend.toml" "$scratch/fixture/backend.toml"
    cp -p "$scratch/broker-writer.toml" "$scratch/fixture/writer.toml"
    k create secret generic devres-config --from-file=backend.toml="$scratch/fixture/backend.toml" \
      --from-literal=postgres-password=fixture-only --dry-run=client -o yaml | k apply -f -
    k create secret generic devres-writer-config --from-file=writer.toml="$scratch/fixture/writer.toml" \
      --dry-run=client -o yaml | k apply -f -
    for deployment in backend writer; do
      k patch deployment "$deployment" --type merge --patch-file "$scratch/$deployment-broker-template.json"
    done
    k scale deployment/credential-broker --replicas=1
    k rollout status deployment/credential-broker --timeout=180s
    start_backend
    wait_broker_service
    broker_reader_probe > "$scratch/rollback-reader-key-metadata.json"
    k exec deployment/writer -- python3 -I -B /harness/broker-pod-probe.py readwrite > "$scratch/rollback-writer-key-id"
    python3 - "$scratch/rollback-reader-key-metadata.json" "$scratch/recovered-reader-key-metadata.json" \
      "$scratch/rollback-writer-key-id" "$scratch/writer-key-id" <<'PYCUTOVERKEYS'
import json, pathlib, sys
reader, previous = (json.loads(pathlib.Path(name).read_text()) for name in sys.argv[1:3])
assert reader['key_hash'] != previous['key_hash'], 'Rollback reused a revoked serving key'
assert pathlib.Path(sys.argv[3]).read_text() != pathlib.Path(sys.argv[4]).read_text(), 'Rollback reused a revoked writer key'
PYCUTOVERKEYS
    external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
    k exec deployment/postgres -- psql -U devres -d devres -Atc \
      'SELECT binding,epoch FROM devres_archive_control WHERE singleton' > "$scratch/rollback-binding"
    cmp "$scratch/broker-original-binding" "$scratch/rollback-binding"
    echo 'Stopped broker-to-static-to-broker cutover preserved binding, epoch, and cold historical reads'
  fi
  echo 'Real minikube S3 isolation, complete cache loss, database restore, and HTTP/WebTransport acceptance passed'
  exit 0
fi
k exec storage-maintenance -- tar -C /data -cf - blobs > "$scratch/blobs.tar"
# Destructive restore is confined to this newly created, task-owned profile.
k exec storage-maintenance -- sh -c 'find /data/blobs -type f -delete'
k exec deployment/postgres -- psql -U devres -d postgres -c 'DROP DATABASE devres WITH (FORCE)'
k exec deployment/postgres -- psql -U devres -d postgres -c 'CREATE DATABASE devres OWNER devres_writer'
k exec -i deployment/postgres -- pg_restore -U devres -d devres < "$scratch/postgres.dump"
k exec -i storage-maintenance -- tar -C /data -xf - < "$scratch/blobs.tar"
test "$(k exec storage-maintenance -- storage-probe read)" = "$before"
attribution_readback
maintenance_stop
start_backend
external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --capture "$capture"
seeded_webtransport
collector_reads
if (( live )); then
  external python3 /harness/mcp_smoke.py --url https://edge:30443/mcp --ca /fixture/cert/ca.pem --live "${live_rfc_args[@]}"
fi
echo 'Real minikube NodePort TCP/UDP, CNI isolation, PVC restart, and coordinated restore passed'
