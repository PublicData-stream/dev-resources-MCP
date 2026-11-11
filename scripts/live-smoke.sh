#!/usr/bin/env bash
# Explicit opt-in only; URL and trust settings identify your local test service.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ ${1:-} != --live ]]; then
  echo 'usage: scripts/live-smoke.sh --live --url HTTPS_MCP_URL --ca CA_FILE [--cert CERT --key KEY]' >&2
  exit 2
fi
shift
if [[ ${1:-} == --wikipedia ]]; then
  shift
  if (( $# == 0 )); then
    root=$(mktemp -d /tmp/devres-wikipedia-live.XXXXXX)
    printf 'devres-wikipedia-live-v1\n' > "$root/owner-v1"
    chmod 600 "$root/owner-v1"
  elif (( $# == 1 )); then
    root=$1
  else
    echo 'usage: scripts/live-smoke.sh --live --wikipedia [OWNED_ROOT]' >&2
    exit 2
  fi
  printf 'Retained bounded Wikipedia evidence (reuse this root to resume): %s\n' "$root" >&2
  export CARGO_TARGET_DIR=/tmp/rust/target
  export TMPDIR=/tmp
  exec cargo run --locked -p devres-adapters --example wikipedia-live-probe -- --live "$root"
fi
if [[ ${1:-} == --html-transport ]]; then
  shift
  if (( $# == 0 )); then
    root=$(mktemp -d /tmp/devres-html-transport.XXXXXX)
    printf 'devres-html-transport-probe-v1\n' > "$root/owner-v1"
    chmod 600 "$root/owner-v1"
  elif (( $# == 1 )); then
    root=$1
  else
    echo 'usage: scripts/live-smoke.sh --live --html-transport [OWNED_ROOT]' >&2
    exit 2
  fi
  printf 'Retained bounded HTML comparison: %s\n' "$root" >&2
  exec cargo run --locked -p devres-adapters --example html-transport-probe -- --live "$root"
fi
if [[ ${1:-} == --attribution ]]; then
  shift
  test "$#" = 0 || { echo 'usage: scripts/live-smoke.sh --live --attribution' >&2; exit 2; }
  parent=$(mktemp -d /tmp/devres-attribution-live.XXXXXX)
  exec cargo run --locked -p devres-adapters --example attribution-live-probe -- --live "$parent/evidence"
fi
if [[ ${1:-} == --npm ]]; then
  shift
  test "$#" = 0 || { echo 'usage: scripts/live-smoke.sh --live --npm' >&2; exit 2; }
  root=$(mktemp -d /tmp/devres-npm-live.XXXXXX)
  printf 'devres-npm-live-v1\n' > "$root/owner-v1"
  chmod 600 "$root/owner-v1"
  printf 'Retained npm bounded evidence: %s\n' "$root" >&2
  exec cargo run --locked -p devres-adapters --example npm-live-probe -- --live "$root"
fi
if [[ ${1:-} == --chromium ]]; then
  shift
  test "$#" = 0 || { echo 'usage: scripts/live-smoke.sh --live --chromium' >&2; exit 2; }
  root=$(mktemp -d /tmp/devres-chromium-live.XXXXXX)
  printf 'devres-chromium-live-v1\n' > "$root/owner-v1"
  chmod 600 "$root/owner-v1"
  printf 'Retained Chromium bounded evidence: %s\n' "$root" >&2
  exec cargo run --locked -p devres-adapters --example chromium-live-probe -- --live "$root"
fi
if [[ ${1:-} == --w3c ]]; then
  shift
  test "$#" = 0 || { echo 'usage: scripts/live-smoke.sh --live --w3c' >&2; exit 2; }
  root=$(mktemp -d /tmp/devres-w3c-live.XXXXXX)
  printf 'devres-w3c-live-v1\n' > "$root/owner-v1"
  chmod 600 "$root/owner-v1"
  printf 'Retained W3C bounded evidence: %s\n' "$root" >&2
  exec cargo run --locked -p devres-adapters --example w3c-live-probe -- --live "$root"
fi
exec python3 scripts/mcp_smoke.py --live "$@"
