#!/usr/bin/env bash
# Native CI guard: host, Rust compiler and Docker daemon must agree.
set -euo pipefail
test "$#" = 1 || { echo 'usage: check-native-platform.sh linux/amd64|linux/arm64' >&2; exit 2; }
case "$1" in
  linux/amd64) machine=x86_64; rust_host=x86_64-unknown-linux-gnu ;;
  linux/arm64) machine=aarch64; rust_host=aarch64-unknown-linux-gnu ;;
  *) echo 'Unsupported native platform' >&2; exit 2 ;;
esac
test "$(uname -s)" = Linux
test "$(uname -m)" = "$machine" || { echo 'Host architecture differs from native CI platform' >&2; exit 1; }
compiler_host=$(rustc -vV | sed -n 's/^host: //p')
test "$compiler_host" = "$rust_host" || { echo 'Rust compiler host differs from native CI platform' >&2; exit 1; }
daemon=$(docker info --format '{{.OSType}}/{{.Architecture}}')
case "$daemon" in
  linux/x86_64) daemon=linux/amd64 ;;
  linux/aarch64) daemon=linux/arm64 ;;
esac
test "$daemon" = "$1" || { echo 'Docker daemon differs from native CI platform' >&2; exit 1; }
echo "Native host/compiler/daemon platform verified: $1"
