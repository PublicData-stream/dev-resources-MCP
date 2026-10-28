#!/usr/bin/env bash
# Best-effort, bounded storage counters only; never inspect fixture/request contents.
set -uo pipefail
phase=${1:-}
image=${2:-}
case "$phase" in
  before-artifact-load|after-artifact-load|artifact-load-failed|before-minikube-start|after-minikube-start|minikube-start-failed|after-minikube-import|minikube-import-failed) ;;
  *) echo 'Unsupported storage diagnostic phase' >&2; exit 2 ;;
esac
capture() {
  local name=$1 output status=0; shift
  output=$(timeout 15s "$@" 2>/dev/null | head -c 65536) || status=$?
  # Console output remains available even when the artifact filesystem is full.
  printf 'Storage %s/%s (status=%s):\n%s\n' "$phase" "$name" "$status" "$output" >&2
  if [[ -n ${DEVRES_E2E_DIAGNOSTICS_DIR:-} ]]; then
    if mkdir -p -- "$DEVRES_E2E_DIAGNOSTICS_DIR/storage" 2>/dev/null; then
      { printf '%s' "$output" > "$DEVRES_E2E_DIAGNOSTICS_DIR/storage/$phase-$name.txt"; } 2>/dev/null || true
    fi
  fi
}
# du never follows links. Only summarize existing, owned directories below /tmp;
# inspect no file names or contents and never traverse unrelated shared state.
mapfile -t roots < <(python3 - "${DEVRES_TMP_ROOT:-}" "${DEVRES_DOCKER_HOST:-}" "${3:-}" <<'PY'
import os
from pathlib import Path
import sys

state, daemon, scratch = sys.argv[1:]
paths = [state, scratch]
if daemon.startswith('unix:///tmp/'):
    paths.append(str(Path(daemon.removeprefix('unix://')).parent))
seen = set()
for candidate in paths:
    if not candidate:
        continue
    try:
        root = Path(candidate).resolve(strict=True)
        if (Path('/tmp') in root.parents and root.is_dir()
                and root.stat().st_uid == os.getuid() and root not in seen):
            seen.add(root)
            print(root)
    except OSError:
        pass
PY
)
capture space df -Pk /tmp "${roots[@]}"
capture inodes df -Pi /tmp "${roots[@]}"
if [[ -n $image ]]; then
  capture image-bytes docker image inspect --format '{{.Size}}' -- "$image"
fi
for index in "${!roots[@]}"; do
  capture "owned-kib-$index" du -skx -- "${roots[$index]}"
done
exit 0
