#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
scratch=$(mktemp -d)
token=${scratch##*/}
owner="devres-image-check-$$-${token,,}"
image="$owner:local"
container="$owner"
cleanup() {
  if [[ $(docker inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$container" 2>/dev/null) == "$owner" ]]; then docker rm -fv "$container" >/dev/null 2>&1 || true; fi
  if [[ $(docker image inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$image" 2>/dev/null) == "$owner" ]]; then docker image rm "$image" >/dev/null 2>&1 || true; fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT
if docker image inspect "$image" >/dev/null 2>&1; then echo 'Refusing to replace an existing image tag' >&2; exit 1; fi
docker build --label "devres.test-owner=$owner" -t "$image" .
test "$(docker inspect --format '{{.Config.User}}' "$image")" = '65532:65532'
# A configuration-free invocation must fail promptly, with no implicit listener.
if timeout 10 docker run --rm --name "$container" --label "devres.test-owner=$owner" --network none --read-only --entrypoint /usr/local/bin/devres-server "$image" /missing.toml; then
  echo 'Server accepted a missing configuration' >&2; exit 1
else
  status=$?
  test "$status" -le 2
fi
echo 'Native runtime image build and fail-closed startup passed'
