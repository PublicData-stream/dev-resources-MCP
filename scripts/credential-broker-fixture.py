#!/usr/bin/env python3
"""Generate private, synthetic broker acceptance inputs beneath /tmp.

The IAM facade is test-only; issued credentials are enforced by real RustFS.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sys

READONLY = '11111111-1111-4111-8111-111111111111'
READWRITE = '22222222-2222-4222-8222-222222222222'
ISSUER = '33333333-3333-4333-8333-333333333333'
PROJECT = '44444444-4444-4444-8444-444444444444'


def private(path, text):
    path.write_text(text)
    path.chmod(0o600)


def prepare(root, mode):
    root = Path(root).resolve(strict=True)
    if Path('/tmp') not in root.parents or mode not in ('docker', 'kubernetes'):
        raise ValueError('Expected a private /tmp fixture and docker|kubernetes mode')
    directory = root / 'fixture/broker'
    directory.mkdir(mode=0o700, exist_ok=True)
    issuer_secret = secrets.token_hex(32)
    root_access, root_secret = 'fixture' + secrets.token_hex(8), secrets.token_hex(32)
    existing = root / 'fixture/s3'
    if (existing / 'access-key').exists() and (existing / 'secret-key').exists():
        root_access = (existing / 'access-key').read_text().strip()
        root_secret = (existing / 'secret-key').read_text().strip()
    database_secret = secrets.token_hex(24)
    corpus_secret = secrets.token_hex(24)
    admin_secret = secrets.token_hex(24)
    private(directory / 'issuer-key', issuer_secret)
    private(directory / 'database-url', f'postgres://devres_broker:{database_secret}@postgres/devres_broker_test')
    private(directory / 'corpus-url', f'postgres://devres_corpus:{corpus_secret}@postgres/devres_corpus_test')
    private(directory / 'keyring.json', json.dumps({'active_key_id': 'initial', 'keys': {'initial': secrets.token_hex(32)}}))
    private(directory / 'rustfs.env', f'RUSTFS_ACCESS_KEY={root_access}\nRUSTFS_SECRET_KEY={root_secret}\n'
            'RUSTFS_CONSOLE_ENABLE=false\nRUSTFS_OBS_LOG_DIRECTORY=/data/logs\n')
    private(directory / 'postgres.env', f'POSTGRES_USER=devres_fixture_admin\nPOSTGRES_PASSWORD={admin_secret}\nPOSTGRES_DB=postgres\n')
    sql = (f"CREATE ROLE devres_broker LOGIN PASSWORD '{database_secret}';\n"
           f"CREATE ROLE devres_corpus LOGIN PASSWORD '{corpus_secret}';\n"
           'CREATE DATABASE devres_broker_test OWNER devres_broker;\n'
           'CREATE DATABASE devres_corpus_test OWNER devres_corpus;\n'
           'REVOKE CONNECT ON DATABASE devres_broker_test FROM PUBLIC;\n'
           'REVOKE CONNECT ON DATABASE devres_corpus_test FROM PUBLIC;\n'
           'GRANT CONNECT ON DATABASE devres_broker_test TO devres_broker;\n'
           'GRANT CONNECT ON DATABASE devres_corpus_test TO devres_corpus;\n')
    private(directory / 'database-init.sql', sql)
    private(directory / 'iam-fixture.json', json.dumps({'endpoint': 'http://objectstore:9000',
            'access_key': root_access, 'secret_key': root_secret, 'issuer_secret': issuer_secret,
            'issuer_access_key': 'fixture-issuer', 'bucket': 'devres-fixture', 'prefix': 'acceptance',
            'parent_secrets': {READONLY: secrets.token_hex(32), READWRITE: secrets.token_hex(32)},
            'state_file': '/fixture/broker/iam-state.json'}))
    kube_url = 'http://identity-fixture:8000' if mode == 'docker' else 'https://kubernetes.default.svc'
    kube_token = '/fixture/identity/api-token' if mode == 'docker' else '/run/kube-api/token'
    kube_ca = '' if mode == 'docker' else 'kube_ca_file = "/run/kube-api/ca.crt"\n'
    text = ('bind = "0.0.0.0:8444"\n'
            'tls_certificate_file = "/fixture/cert/credential-broker.pem"\n'
            'tls_private_key_file = "/fixture/cert/credential-broker-key.pem"\n'
            'database_url_file = "/fixture/broker/database-url"\n'
            'keyring_file = "/fixture/broker/keyring.json"\n'
            'issuer_key_file = "/fixture/broker/issuer-key"\n'
            'issuer_access_key = "fixture-issuer"\n'
            f'issuer_application_id = "{ISSUER}"\n'
            'acceptance_receipt_file = "/fixture/broker/receipt.json"\n'
            'iam_endpoint = "http://iam-fixture:8001"\nfixture_mode = true\n'
            'ttl_secs = 60\nrefresh_before_secs = 10\nmax_pods = 4\nmax_issued_keys = 16\nquota_reserve = 4\n'
            f'\n[authentication]\nkube_api_url = "{kube_url}"\nkube_token_file = "{kube_token}"\n'
            f'{kube_ca}audience = "devres-credential-broker"\nallow_http = {str(mode == "docker").lower()}\n')
    for app, account, role in ((READONLY, 'devres-serving', 'readonly'), (READWRITE, 'devres-writer', 'readwrite')):
        fingerprint = hashlib.sha256(f'fixture-policy:{app}:devres-fixture:acceptance:{role}'.encode()).hexdigest()
        text += ('\n[[profiles]]\nnamespace = "devres-acceptance"\n'
                 f'service_account = "{account}"\napplication_id = "{app}"\ndefault_project_id = "{PROJECT}"\n'
                 f'bucket = "devres-fixture"\nprefix = "acceptance"\nrole = "{role}"\n'
                 f'policy_fingerprint = "{fingerprint}"\n')
    private(directory / 'broker.toml', text)


def receipt(directory, fingerprints):
    directory = Path(directory)
    profiles = json.loads(Path(fingerprints).read_text())
    if set(profiles) != {READONLY, READWRITE} or any(len(value) != 64 for value in profiles.values()):
        raise ValueError('Unexpected synthetic profile fingerprints')
    now = datetime.now(timezone.utc)
    stamp = lambda value: value.isoformat(timespec='seconds').replace('+00:00', 'Z')
    issuer_fingerprint = (directory / 'issuer-fingerprint').read_text().strip()
    if len(issuer_fingerprint) != 64 or any(c not in '0123456789abcdef' for c in issuer_fingerprint):
        raise ValueError('Expected Rust-generated issuer secret fingerprint')
    private(directory / 'receipt.json', json.dumps({'issuer_access_key': 'fixture-issuer', 'issuer_application_id': ISSUER,
            'issuer_secret_fingerprint': issuer_fingerprint,
            'profile_fingerprints': profiles, 'confined_application_ids': sorted(profiles),
            'verified_at': stamp(now), 'expires_at': stamp(now + timedelta(hours=2)),
            'broker_key_budget': 20, 'ttl_secs': 60, 'unrelated_application_denied': True,
            'policy_management_denied': True, 'expiry_accepted': True, 'fixture': True}))


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] not in ('prepare', 'receipt'):
        raise SystemExit('usage: credential-broker-fixture.py prepare /tmp/ROOT docker|kubernetes | receipt DIRECTORY FINGERPRINTS.json')
    (prepare if sys.argv[1] == 'prepare' else receipt)(sys.argv[2], sys.argv[3])
