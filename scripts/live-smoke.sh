#!/usr/bin/env bash
# Explicit opt-in only; URL and trust settings identify your local test service.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ ${1:-} != --live ]]; then
  echo 'usage: scripts/live-smoke.sh --live --url HTTPS_MCP_URL --ca CA_FILE [--cert CERT --key KEY]' >&2
  exit 2
fi
shift
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
