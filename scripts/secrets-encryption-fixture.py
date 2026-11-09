#!/usr/bin/env python3
"""Configure and verify native Secrets encryption in an owned minikube profile."""
import base64
import json
from pathlib import Path
import secrets
import sys

SENTINEL = b'devres-synthetic-encryption-canary'


def prepare(minikube_home):
    root = Path(minikube_home).resolve(strict=True)
    if Path('/tmp') not in root.parents:
        raise ValueError('Encryption fixture requires MINIKUBE_HOME below /tmp')
    # MINIKUBE_HOME selects the parent of minikube's .minikube directory.
    # File sync reads its files/ subtree before kubeadm starts the API server.
    destination = root / '.minikube/files/var/lib/minikube/certs/devres-encryption.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    value = {'apiVersion': 'apiserver.config.k8s.io/v1', 'kind': 'EncryptionConfiguration',
             'resources': [{'resources': ['secrets'], 'providers': [
                 {'secretbox': {'keys': [{'name': 'devres-fixture',
                                         'secret': base64.b64encode(secrets.token_bytes(32)).decode()}]}},
                 {'identity': {}}]}]}
    destination.write_text(json.dumps(value))
    destination.chmod(0o600)


def verify(path):
    value = Path(path).read_bytes()
    if not value.startswith(b'k8s:enc:secretbox:v1:devres-fixture:') or SENTINEL in value:
        raise ValueError('Synthetic Secret was not encrypted by the configured provider')


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ('prepare', 'verify'):
        raise SystemExit('usage: secrets-encryption-fixture.py prepare /tmp/MINIKUBE_HOME | verify /tmp/ETCD_VALUE')
    (prepare if sys.argv[1] == 'prepare' else verify)(sys.argv[2])
