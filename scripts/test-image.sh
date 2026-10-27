#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
platform=
target=runtime
external_image=
oci_output=
revision=
version=0.0.0
usage() {
  echo 'usage: scripts/test-image.sh [--platform linux/amd64|linux/arm64] [--target runtime|server|probe|audit-worker] [--image IMAGE] [--oci-output ABS_DIRECTORY] [--revision SHA] [--version VERSION]' >&2
  exit 2
}
while (( $# )); do
  test "$#" -ge 2 || usage
  case "$1" in
    --platform) platform=$2 ;;
    --target) target=$2 ;;
    --image) external_image=$2; test -n "$external_image" || usage ;;
    --oci-output) oci_output=$2; [[ $oci_output == /* ]] || usage ;;
    --revision) revision=$2 ;;
    --version) version=$2 ;;
    *) usage ;;
  esac
  shift 2
done
case "$target" in runtime|server|probe|audit-worker) ;; *) usage ;; esac
if [[ -z $revision && -z $external_image ]]; then revision=$(git rev-parse HEAD); fi
if [[ -n $revision ]]; then [[ $revision =~ ^[0-9a-f]{40}$ ]] || usage; fi
[[ -n $version && $version != *$'\n'* && $version != *$'\r'* ]] || usage
if [[ -z $platform ]]; then
  platform=$(docker info --format '{{.OSType}}/{{.Architecture}}')
  case "$platform" in linux/x86_64) platform=linux/amd64 ;; linux/aarch64) platform=linux/arm64 ;; esac
fi
case "$platform" in linux/amd64|linux/arm64) ;; *) usage ;; esac
if [[ -n $oci_output ]]; then
  test -z "$external_image" || { echo '--image is smoke-only and cannot be combined with --oci-output' >&2; exit 2; }
  command -v skopeo >/dev/null
  test ! -e "$oci_output" || { echo 'Refusing to replace an OCI output directory' >&2; exit 1; }
fi
scratch=$(mktemp -d)
token=${scratch##*/}
owner="devres-image-check-$$-${token,,}"
image=${external_image:-"$owner:local"}
container="$owner"
image_ref=
cleanup() {
  if [[ $(docker inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$container" 2>/dev/null) == "$owner" ]]; then docker rm -fv "$container" >/dev/null 2>&1 || true; fi
  if [[ -z $external_image ]] && [[ $(docker image inspect --format '{{index .Config.Labels "devres.test-owner"}}' "$image" 2>/dev/null) == "$owner" ]]; then docker image rm "$image" >/dev/null 2>&1 || true; fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -z $external_image ]]; then
  if docker image inspect "$image" >/dev/null 2>&1; then echo 'Refusing to replace an existing image tag' >&2; exit 1; fi
  build_flags=(--platform "$platform" --target "$target" --provenance=false --sbom=false --label "devres.test-owner=$owner"
    --label "org.opencontainers.image.revision=$revision" --label "org.opencontainers.image.version=$version" -t "$image")
  if [[ -n $oci_output ]]; then
    mkdir "$scratch/oci"
    # Export the canonical artifact first, then smoke exactly what Docker imports.
    docker buildx build "${build_flags[@]}" --output "type=oci,dest=$scratch/oci/image.oci.tar" .
    skopeo inspect --raw "oci-archive:$scratch/oci/image.oci.tar" > "$scratch/archive-manifest.json"
    docker load --input "$scratch/oci/image.oci.tar"
  else
    docker build "${build_flags[@]}" .
  fi
fi
docker image inspect "$image" > "$scratch/image.json"
image_ref=$(python3 scripts/image-fixture.py inspect "$scratch/image.json" "$platform" "$target")
if [[ -n $oci_output ]]; then
  # Bind the imported image to the canonical archive before executing a binary.
  python3 scripts/image-fixture.py metadata "$scratch/oci" "$scratch/archive-manifest.json" \
    "$scratch/image.json" "$platform" "$target"
fi
run_binary() {
  local binary=$1
  shift
  local status=0
  timeout 15 docker run --rm -i --platform "$platform" --name "$container" \
    --label "devres.test-owner=$owner" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --entrypoint "/usr/local/bin/$binary" "$image_ref" "$@" \
    > "$scratch/stdout" 2> "$scratch/stderr" || status=$?
  # Docker's invocation errors and timeout must never satisfy a negative test.
  if (( status > 2 )); then echo "Image executable failed to run: $binary (status $status)" >&2; exit 1; fi
  return "$status"
}
if [[ $target == runtime || $target == server ]]; then
  status=0
  run_binary devres-server /missing.toml </dev/null || status=$?
  test "$status" = 1 || { echo 'Server did not reject missing configuration' >&2; exit 1; }
  python3 scripts/image-fixture.py startup server "$scratch/stdout" "$scratch/stderr"
fi
if [[ $target == runtime || $target == probe ]]; then
  status=0
  run_binary devres-probe </dev/null || status=$?
  test "$status" = 1 || { echo 'Probe did not reject missing arguments' >&2; exit 1; }
  python3 scripts/image-fixture.py startup probe "$scratch/stdout" "$scratch/stderr"
fi
if [[ $target != probe ]]; then
  for mode in valid invalid npm-valid npm-invalid; do
    python3 scripts/image-fixture.py input "$mode" > "$scratch/input.json"
    run_binary devres-audit-worker < "$scratch/input.json"
    python3 scripts/image-fixture.py worker "$mode" "$scratch/stdout" "$scratch/stderr"
  done
fi
if [[ -n $oci_output ]]; then
  mkdir -p -- "$(dirname -- "$oci_output")"
  # Refuse a racing creator instead of merging with someone else's output.
  mkdir -- "$oci_output"
  mv -- "$scratch/oci/image.oci.tar" "$scratch/oci/metadata.json" "$oci_output/"
fi
echo "Image build/startup/fixture checks passed: target=$target platform=$platform (execution may be emulated)"
