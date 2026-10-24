#!/usr/bin/env bash
# Generate synthetic two-day test identities; CA private keys never enter fixture/.
set -euo pipefail
test "$#" = 1 || { echo 'usage: make-fixture.sh SCRATCH' >&2; exit 2; }
scratch=$(realpath -- "$1")
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$scratch/fixture/cert" "$scratch/fixture/config"
for ca in ca client-ca wrong-ca; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -subj "/CN=devres-test-$ca" -keyout "$scratch/$ca-key.pem" \
    -out "$scratch/fixture/cert/$ca.pem" >/dev/null 2>&1
done
for name in edge backend wrong-backend edge-client wrong-client; do
  role=serverAuth
  ca=ca
  if [[ $name == *client ]]; then role=clientAuth; ca=client-ca; fi
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=$name" -keyout "$scratch/fixture/cert/$name-key.pem" \
    -out "$scratch/$name.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=%s\n' \
    "$name" "$role" > "$scratch/$name.ext"
  openssl x509 -req -in "$scratch/$name.csr" -CA "$scratch/fixture/cert/$ca.pem" \
    -CAkey "$scratch/$ca-key.pem" -CAcreateserial -days 2 -extfile "$scratch/$name.ext" \
    -out "$scratch/fixture/cert/$name.pem" >/dev/null 2>&1
done
chmod 644 "$scratch/fixture/cert/"*.pem
chmod 600 "$scratch/fixture/cert/"*-key.pem
cp "$repo/deploy/oxibelt/backend.toml" "$scratch/fixture/"
cp "$repo/deploy/oxibelt/oxibelt.toml" "$scratch/fixture/config/"
