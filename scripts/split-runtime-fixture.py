#!/usr/bin/env python3
"""Prepare isolated reader/writer configuration; never copy provider credentials."""
from pathlib import Path
import re
import sys


def prepare(directory, engine):
    root = Path(directory).resolve(strict=True)
    if Path('/tmp') not in root.parents or engine not in ('docker', 'kubernetes'):
        raise ValueError('Expected an owned /tmp fixture and supported engine')
    backend = root / 'fixture/backend.toml'
    original = backend.read_text()
    writer = original.replace('postgres://devres:fixture-only@postgres/devres',
                              'postgres://devres_writer:writer-fixture-only@postgres/devres') + '''
[writer_listener]
bind = "0.0.0.0:9443"
certificate = "/fixture/cert/writer.pem"
private_key = "/fixture/cert/writer-key.pem"
allowed_clients = [{namespace = "devres-acceptance", service_account = "devres-serving"}]
[writer_listener.auth]
audience = "devres-writer"
'''
    if engine == 'kubernetes':
        writer += '''kube_api_url = "https://kubernetes.default.svc"
kube_token_file = "/run/devres-kube/token"
kube_ca_file = "/run/devres-kube/ca.crt"
'''
    else:
        writer += '''kube_api_url = "http://identity-fixture:8000"
kube_token_file = "/fixture/identity/api-token"
allow_http = true
'''
    (root / 'fixture/writer.toml').write_text(writer)
    reader = original.replace('postgres://devres:fixture-only@postgres/devres',
                              'postgres://devres_reader:reader-fixture-only@postgres/devres')
    reader, count = re.subn(r'(?m)^\[storage\]\s*$', '[storage]\nscratch_dir = "/tmp/devres-reader"', reader)
    if count != 1:
        raise ValueError('Expected one storage table')
    if re.search(r'(?m)^backend\s*=\s*"s3"', original):
        reader = reader.replace('blob_dir = "/data/blobs"', 'blob_dir = "/reader-cache"')
    reader += '''
[writer_client]
endpoint = "https://writer:9443/v1/acquire"
token_file = "/run/devres-writer-identity/token"
ca_file = "/fixture/cert/ca.pem"
'''
    if engine == 'docker':
        reader = reader.replace('/run/devres-writer-identity/token', '/fixture/identity/serving-token')
    backend.write_text(reader)
    for config in (backend, root / 'fixture/writer.toml'):
        config.chmod(0o600)
    (root / 'reader-role.sql').write_text('''
CREATE ROLE devres_reader LOGIN PASSWORD 'reader-fixture-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE devres_writer LOGIN PASSWORD 'writer-fixture-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
ALTER DATABASE devres OWNER TO devres_writer;
GRANT CONNECT ON DATABASE devres TO devres_reader;
GRANT USAGE ON SCHEMA public TO devres_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO devres_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE devres IN SCHEMA public GRANT SELECT ON TABLES TO devres_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE devres_writer IN SCHEMA public GRANT SELECT ON TABLES TO devres_reader;
''')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: split-runtime-fixture.py /tmp/FIXTURE docker|kubernetes')
    prepare(*sys.argv[1:])
