#!/usr/bin/env bash
# Explicit opt-in only; URL and trust settings identify your local test service.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ ${1:-} != --live ]]; then
  echo 'usage: scripts/live-smoke.sh --live --url HTTPS_MCP_URL --ca CA_FILE [--cert CERT --key KEY]' >&2
  exit 2
fi
shift
exec python3 scripts/mcp_smoke.py --live "$@"
