#!/usr/bin/env bash
# Native CI build/consumer driver; all disposable runtime state belongs to this run.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
if [[ ${1:-} != --inside-state ]]; then
  case "${1:-}:$#" in build:3|test:4) ;; *) echo 'usage: ci-e2e.sh build PLATFORM DIRECTORY | test docker|minikube PLATFORM DIRECTORY' >&2; exit 2 ;; esac
  export DEVRES_TMP_ROOT
  DEVRES_TMP_ROOT=$(mktemp -d /tmp/devres-ci-e2e.XXXXXX)
  umask 022
  exec scripts/with-tmp-state.sh env CARGO_TARGET_DIR=/buildcache/rust/target \
    OXIBELT_TARGET_DIR=/buildcache/rust/target "$0" --inside-state "$@"
fi
shift
mode=$1
shift
scenario=
if [[ $mode == test ]]; then scenario=$1; shift; fi
platform=$1
artifact=$2
case "$platform" in
  linux/amd64) arch=amd64; checksum=b738496da01be06bbaf80c688f57ce25acd3849fbb518155f3a88e03ef555aa4 ;;
  linux/arm64) arch=arm64; checksum=202f331cb677761c5aec81c58472d16d65707358b9f66226210be3fe3275b1c3 ;;
  *) echo 'Unsupported native platform' >&2; exit 2 ;;
esac
case "$mode:$scenario" in build:|test:docker|test:minikube) ;; *) echo 'Unsupported CI scenario' >&2; exit 2 ;; esac
# Resolve paths before changing subprocess environments; artifact storage is runner-owned.
artifact=$(realpath -m -- "$artifact")
commit=${GITHUB_SHA:-$(git rev-parse HEAD)}
version=0.0.0
if [[ -n ${RELEASE_TAG:-} ]]; then
  if [[ $mode == build ]]; then
    scripts/verify-release-tag.sh "$RELEASE_TAG" "$commit"
    version=$(python3 scripts/release_contract.py stamp --tag "$RELEASE_TAG" --commit "$commit")
  else
    version=$(python3 scripts/release_contract.py validate --tag "$RELEASE_TAG" --commit "$commit")
  fi
fi
sudo -n apt-get update
sudo -n apt-get install -y build-essential clang cmake libclang-dev perl pkg-config \
  libssl-dev openssl curl ca-certificates git python3 iproute2 iptables conntrack
sudo -n mkdir -p /buildcache/rust/target
sudo -n chown "$(id -u):$(id -g)" /buildcache/rust/target
rustup toolchain install 1.99.1 --profile minimal
export RUSTUP_TOOLCHAIN=1.99.1
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
if [[ $scenario == minikube ]]; then
  mkdir -p "$DEVRES_TMP_ROOT/bin"
  curl --fail --location --silent --show-error \
    "https://github.com/kubernetes/minikube/releases/download/v1.39.0/minikube-linux-$arch" \
    -o "$DEVRES_TMP_ROOT/bin/minikube"
  printf '%s  %s\n' "$checksum" "$DEVRES_TMP_ROOT/bin/minikube" | sha256sum --check --strict
  chmod 755 "$DEVRES_TMP_ROOT/bin/minikube"
  export PATH="$DEVRES_TMP_ROOT/bin:$PATH"
  export DEVRES_KUBERNETES_VERSION=v1.37.0
fi
# Keep build, export/load, native guard and scenario in the same isolated daemon.
# Variables in this program are intentionally expanded by the child shell.
# shellcheck disable=SC2016
exec scripts/with-local-docker.sh bash -euo pipefail -c '
  scripts/check-native-platform.sh "$1"
  if [[ $2 == build ]]; then
    scratch=$(mktemp -d)
    image="devres-e2e-$6:$5"
    scripts/build-harness.sh "$scratch" "$image"
    python3 scripts/e2e-artifact.py export "$3" "$image" "$1" "$5" "$4"
  else
    scripts/e2e-storage.sh before-artifact-load "" "$3" || true
    image=$(python3 scripts/e2e-artifact.py verify "$3" "$1" "$5" "$4") || {
      status=$?
      scripts/e2e-storage.sh artifact-load-failed "" "$3" || true
      exit "$status"
    }
    scripts/e2e-storage.sh after-artifact-load "$image" "$3" || true
    case "$7" in
      docker) scripts/test-oxibelt.sh --image "$image" ;;
      minikube) scripts/test-minikube.sh --image "$image" ;;
    esac
  fi
' ci-e2e "$platform" "$mode" "$artifact" "$version" "$commit" "$arch" "$scenario"
