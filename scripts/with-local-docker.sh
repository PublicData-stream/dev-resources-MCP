#!/usr/bin/env bash
# Optional environment workaround: an isolated daemon on native local storage.
# Does not edit daemon.json, contexts, or shared Docker caches.
set -euo pipefail
test "$#" -gt 0 || { echo 'usage: scripts/with-local-docker.sh COMMAND [ARG ...]' >&2; exit 2; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ${DEVRES_TMP_STATE:-} != 1 ]]; then
  exec "$repo/scripts/with-tmp-state.sh" "$0" "$@"
fi
storage_root=$(python3 - "${DEVRES_DOCKER_STATE_ROOT:-$DEVRES_TMP_ROOT}" <<'PY'
from pathlib import Path
import os
import sys
root = Path(sys.argv[1]).resolve(strict=True)
if Path('/tmp') not in root.parents or root.stat().st_uid != os.getuid():
    raise SystemExit('isolated Docker state requires an owned directory below /tmp')
print(root)
PY
)
state=$(mktemp -d "$storage_root/docker-local.XXXXXX")
runtime_state=$(mktemp -d "$storage_root/docker-runtime.XXXXXX")
mkdir "$state/tmp"
bridge="dvrs$$"
if [[ ${DEVRES_DOCKER_STORAGE_DRIVER:-} == vfs ]]; then
  printf '{"features":{"containerd-snapshotter":false},"storage-driver":"vfs"}\n' > "$state/daemon.json"
elif [[ -n ${DEVRES_DOCKER_STORAGE_DRIVER:-} ]]; then
  echo 'Unsupported isolated Docker storage driver' >&2; exit 2
else
  printf '{}\n' > "$state/daemon.json"
fi
export DOCKER_HOST="unix://$state/docker.sock"
export DEVRES_DOCKER_HOST="$DOCKER_HOST"
unset DOCKER_CONTEXT
daemon_pid=
bridge_created=0
nat_created=0
forward_created=0
chain="DVRS$$"
cleanup() {
  status=$?
  if (( status != 0 )); then tail -40 "$state/daemon.log" >&2 2>/dev/null || true; fi
  if [[ -s $state/daemon.pid ]]; then
    daemon_pid=$(cat "$state/daemon.pid")
    sudo -n kill -TERM "$daemon_pid" 2>/dev/null || true
  fi
  if [[ -n ${launcher:-} ]]; then wait "$launcher" 2>/dev/null || true; fi
  if [[ -s $state/containerd.pid ]]; then sudo -n kill -TERM "$(cat "$state/containerd.pid")" 2>/dev/null || true; fi
  if [[ -n ${container_launcher:-} ]]; then wait "$container_launcher" 2>/dev/null || true; fi
  if (( nat_created )); then
    sudo -n iptables -w -t nat -D POSTROUTING -j "$chain" 2>/dev/null || true
    sudo -n iptables -w -t nat -F "$chain" 2>/dev/null || true
    sudo -n iptables -w -t nat -X "$chain" 2>/dev/null || true
  fi
  if (( forward_created )); then
    sudo -n iptables -w -D FORWARD -j "$chain" 2>/dev/null || true
    sudo -n iptables -w -F "$chain" 2>/dev/null || true
    sudo -n iptables -w -X "$chain" 2>/dev/null || true
  fi
  if (( bridge_created )); then sudo -n ip link delete "$bridge" 2>/dev/null || true; fi
  # The dedicated daemon exclusively created this directory. Do not touch any
  # configured daemon's data, containers, bridge, or cache.
  # Retain this dedicated daemon's caches and logs for inspection/reuse. Permanent
  # acceptance captures live outside these disposable daemon directories.
  printf 'Retained isolated Docker state: %s\n' "$state" >&2
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Refuse address collisions instead of changing an operator's existing routes.
ip -j -4 route | python3 -c '
import ipaddress,json,sys
requested=[ipaddress.ip_network("10.222.0.0/16"),ipaddress.ip_network("10.223.0.0/16")]
for route in json.load(sys.stdin):
    destination=route.get("dst", "default")
    if destination=="default": continue
    network=ipaddress.ip_network(destination,strict=False)
    if any(network.overlaps(candidate) for candidate in requested):
        raise SystemExit("isolated Docker test range conflicts with an existing route")
'
test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 || { echo 'Existing IPv4 forwarding is required; host setting is not changed' >&2; exit 1; }
sudo -n iptables -w -t nat -N "$chain"
nat_created=1
sudo -n iptables -w -t nat -A "$chain" -s 10.222.0.0/16 -j MASQUERADE
sudo -n iptables -w -t nat -A "$chain" -s 10.223.0.0/16 -j MASQUERADE
sudo -n iptables -w -t nat -I POSTROUTING 1 -j "$chain"
sudo -n iptables -w -N "$chain"
forward_created=1
for range in 10.222.0.0/16 10.223.0.0/16; do
  sudo -n iptables -w -A "$chain" -s "$range" -j ACCEPT
  sudo -n iptables -w -A "$chain" -d "$range" -j ACCEPT
done
sudo -n iptables -w -I FORWARD 1 -j "$chain"
sudo -n ip link add "$bridge" type bridge
bridge_created=1
sudo -n ip addr add 10.222.0.1/16 dev "$bridge"
sudo -n ip link set "$bridge" up
printf 'version = 3\n' > "$state/containerd.toml"
# The invoking user owns logs; containerd state and snapshots are private to this run.
# shellcheck disable=SC2024
sudo -n sh -c 'echo "$$" > "$1"; shift; exec "$@"' sh "$state/containerd.pid" \
  env TMPDIR="$state/tmp" XDG_RUNTIME_DIR="$runtime_state" containerd --config "$state/containerd.toml" --root "$state/containerd" \
  --state "$runtime_state/containerd" --address "$runtime_state/containerd.sock" \
  > "$state/containerd.log" 2>&1 &
container_launcher=$!
for attempt in {1..20}; do
  if [[ -S $runtime_state/containerd.sock ]]; then break; fi
  if ! kill -0 "$container_launcher" 2>/dev/null; then tail -30 "$state/containerd.log" >&2; exit 1; fi
  sleep 1
done
# The invoking user owns the state directory and intentionally owns this log.
# shellcheck disable=SC2024
sudo -n env TMPDIR="$state/tmp" XDG_RUNTIME_DIR="$runtime_state" dockerd --config-file "$state/daemon.json" --data-root "$state/data" \
  --exec-root "$state/exec" --host "$DOCKER_HOST" --pidfile "$state/daemon.pid" \
  --containerd "$runtime_state/containerd.sock" --containerd-namespace "devres-$$" \
  --containerd-plugins-namespace "devres-plugins-$$" \
  --iptables=false --ip6tables=false --ip-forward=false --ip-masq=false \
  --bridge "$bridge" --fixed-cidr 10.222.0.0/16 --default-address-pool base=10.223.0.0/16,size=24 \
  > "$state/daemon.log" 2>&1 &
launcher=$!
for attempt in {1..40}; do
  if docker info >/dev/null 2>&1; then break; fi
  if ! kill -0 "$launcher" 2>/dev/null; then echo 'Isolated daemon exited' >&2; exit 1; fi
  if (( attempt == 40 )); then echo 'Isolated Docker readiness timed out' >&2; exit 1; fi
  sleep 1
done
"$@"
