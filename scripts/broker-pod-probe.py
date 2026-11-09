#!/usr/bin/env python3
"""Verify actual workload tokens and S3 role enforcement inside disposable pods."""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import ssl
import sys
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler


def check(role):
    if role not in ('readonly', 'readwrite'):
        raise ValueError('Unknown fixture role')
    root = Path('/fixture')
    context = ssl.create_default_context(cafile=str(root / 'cert/ca.pem'))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    request = Request('https://credential-broker:8444/v1/credentials', headers={
        'Authorization': Path('/run/devres-broker-identity/token').read_text()})
    with opener.open(request, timeout=40) as response:
        assert response.status == 200 and response.headers.get('Cache-Control') == 'no-store'
        credential = json.loads(response.read(65537))
    assert set(credential) == {'AccessKeyId', 'SecretAccessKey', 'Expiration'}
    spec = importlib.util.spec_from_file_location('iam_fixture', Path(__file__).with_name('scaleway-iam-fixture.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    s3 = module.RustFS({'endpoint': 'http://objectstore:9000',
                       'access_key': credential['AccessKeyId'], 'secret_key': credential['SecretAccessKey']})
    assert s3.call('GET', '/devres-fixture/acceptance/store.json', raw=True)[0] == 200, 'prefix read'
    assert s3.call('GET', '/devres-fixture', query={'list-type': '2', 'prefix': 'acceptance/', 'max-keys': '1'}, raw=True)[0] == 200, 'prefix listing'
    assert s3.call('GET', '/devres-fixture/outside/private', raw=True)[0] == 403, 'outside prefix denied'
    assert s3.call('GET', '/rustfs/admin/v3/list-users', raw=True)[0] == 403, 'administration denied'
    path = '/devres-fixture/acceptance/.broker-acceptance/' + secrets.token_hex(12)
    if role == 'readonly':
        assert s3.call('PUT', path, {'synthetic': True}, raw=True)[0] == 403, 'reader write denied'
        assert s3.call('DELETE', path, raw=True)[0] == 403, 'reader delete denied'
    else:
        assert s3.call('PUT', path, {'synthetic': 'first'}, raw=True)[0] == 200, 'writer create'
        try:
            assert s3.call('PUT', path, {'synthetic': 'updated'}, raw=True)[0] == 200, 'writer update'
            assert s3.call('GET', path, raw=True)[0] == 200, 'writer read'
        finally:
            assert s3.call('DELETE', path, raw=True)[0] in (200, 204), 'writer delete'
    # Public identifiers are hashed for cross-pod/session comparison; secrets
    # remain only in this process and the broker's encrypted journal.
    return hashlib.sha256(credential['AccessKeyId'].encode()).hexdigest()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: broker-pod-probe.py readonly|readwrite')
    try:
        identity = check(sys.argv[1])
    except Exception:
        raise SystemExit('Workload credential role acceptance failed.') from None
    print(identity)
