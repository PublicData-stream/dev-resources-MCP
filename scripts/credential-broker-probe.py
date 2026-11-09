#!/usr/bin/env python3
"""Bounded synthetic broker acceptance against real RustFS authorization.

Outputs only fixed check names. Credentials stay in private fixture files/memory.
"""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time
import traceback
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, unquote
from urllib.request import Request, build_opener, ProxyHandler, HTTPSHandler

SPEC = importlib.util.spec_from_file_location('scaleway_iam_fixture', Path(__file__).with_name('scaleway-iam-fixture.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ROOT = Path('/fixture')
DIRECTORY = ROOT / 'broker'


def write(path, value):
    temporary = path.with_suffix('.stage')
    temporary.write_text(value)
    temporary.chmod(0o600)
    temporary.replace(path)


def broker(token_name, query='', origin=False):
    context = ssl.create_default_context(cafile=str(ROOT / 'cert/ca.pem'))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    headers = {} if token_name is None else {'Authorization': (ROOT / 'identity' / token_name).read_text()}
    if origin:
        headers['Origin'] = 'https://untrusted.invalid'
    request = Request('https://credential-broker:8444/v1/credentials' + query, headers=headers)
    try:
        with opener.open(request, timeout=40) as response:
            assert response.headers.get('Cache-Control') == 'no-store'
            value = json.loads(response.read(65537))
            assert set(value) == {'AccessKeyId', 'SecretAccessKey', 'Expiration'}
            return response.status, value
    except HTTPError as error:
        code = error.code
        error.close()
        return code, None


def get(token):
    for _ in range(50):
        try:
            status, value = broker(token)
            if status == 200:
                return value
            if status not in (429, 503):
                raise AssertionError('identity admission')
        except (URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(1)
    raise AssertionError('broker readiness deadline')


def client(credentials):
    return MODULE.RustFS({'endpoint': 'http://objectstore:9000',
                         'access_key': credentials['AccessKeyId'], 'secret_key': credentials['SecretAccessKey']})


def root_client():
    return MODULE.RustFS(json.loads((DIRECTORY / 'iam-fixture.json').read_text()))


def s3(credentials, method, path, value=None, query=None):
    return client(credentials).call(method, path, value=value, query=query, raw=True)


def pg(command, database='database-url', target=None, input_text=None):
    url = urlsplit((DIRECTORY / database).read_text())
    environment = dict(os.environ, PGHOST=url.hostname, PGPORT=str(url.port or 5432),
                       PGUSER=unquote(url.username), PGPASSWORD=unquote(url.password),
                       PGDATABASE=target or url.path.lstrip('/'))
    return subprocess.run(command, input=input_text, text=True, capture_output=True, env=environment, timeout=20)


def provider_ready():
    opener = build_opener(ProxyHandler({}))
    key = (DIRECTORY / 'issuer-key').read_text()
    for _ in range(40):
        try:
            request = Request('http://iam-fixture:8001/iam/v1alpha1/api-keys/fixture-issuer', headers={'X-Auth-Token': key})
            with opener.open(request, timeout=2) as response:
                if response.status == 200:
                    return
        except (URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(1)
    raise AssertionError('IAM fixture startup deadline')


def wait_ready():
    context = ssl.create_default_context(cafile=str(ROOT / 'cert/ca.pem'))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    for _ in range(50):
        try:
            with opener.open('https://credential-broker:8444/healthz', timeout=2) as response:
                if response.status == 204:
                    return
        except (URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(1)
    raise AssertionError('broker startup deadline')


def encrypted_database(state):
    dump = pg(['pg_dump', '--no-owner', '--no-privileges'])
    assert dump.returncode == 0, 'broker database dump'
    for credential in (state['reader'], state['writer']):
        assert credential['SecretAccessKey'] not in dump.stdout, 'plaintext credential in broker database'
    assert 'devres_credential_broker_keys' in dump.stdout
    corpus = pg(['pg_dump', '--no-owner', '--no-privileges'], database='corpus-url')
    assert corpus.returncode == 0 and 'devres_credential_broker_' not in corpus.stdout, 'broker data in corpus dump'
    assert pg(['psql', '-Atc', 'SELECT 1'], database='corpus-url', target='devres_broker_test').returncode != 0, 'corpus role accessed broker database'
    assert pg(['psql', '-Atc', 'SELECT 1'], target='devres_corpus_test').returncode != 0, 'broker role accessed corpus database'


def initial():
    root = root_client()
    assert root.call('PUT', '/devres-fixture', value=b'', raw=True)[0] == 200, 'bucket initialization'
    assert root.call('PUT', '/devres-fixture/acceptance/retained', value=b'synthetic-retained', raw=True)[0] == 200
    assert root.call('PUT', '/devres-fixture/outside/retained', value=b'outside', raw=True)[0] == 200
    reader, writer = get('serving-token'), get('writer-token')
    assert reader['AccessKeyId'] != writer['AccessKeyId'], 'distinct pod credentials'
    assert get('serving-token') == reader and get('writer-token') == writer, 'unnecessary credential issuance'
    assert s3(reader, 'GET', '/devres-fixture/acceptance/retained') == (200, b'synthetic-retained')
    assert s3(reader, 'HEAD', '/devres-fixture/acceptance/retained')[0] == 200
    assert s3(reader, 'GET', '/devres-fixture', query={'list-type': '2', 'prefix': 'acceptance/'})[0] == 200
    for credentials in (reader, writer):
        assert s3(credentials, 'GET', '/devres-fixture/outside/retained')[0] == 403
        assert s3(credentials, 'GET', '/devres-fixture', query={'list-type': '2'})[0] == 403
        assert s3(credentials, 'GET', '/rustfs/admin/v3/list-users')[0] == 403
    assert s3(reader, 'PUT', '/devres-fixture/acceptance/forbidden', value=b'forbidden')[0] == 403
    assert s3(reader, 'DELETE', '/devres-fixture/acceptance/retained')[0] == 403
    assert s3(writer, 'PUT', '/devres-fixture/acceptance/mutable', value=b'created')[0] == 200
    assert s3(writer, 'GET', '/devres-fixture/acceptance/mutable') == (200, b'created')
    assert s3(writer, 'PUT', '/devres-fixture/acceptance/mutable', value=b'updated')[0] == 200
    assert s3(writer, 'GET', '/devres-fixture/acceptance/mutable') == (200, b'updated')
    assert s3(writer, 'DELETE', '/devres-fixture/acceptance/mutable')[0] == 204
    for method in ('PUT', 'DELETE'):
        assert s3(writer, method, '/devres-fixture/outside/forbidden', value=b'blocked' if method == 'PUT' else None)[0] == 403
    assert broker(None)[0] == 401
    assert broker('serving-token', '?role=readwrite')[0] == 400
    assert broker('serving-token', origin=True)[0] == 400
    state = {'reader': reader, 'writer': writer}
    write(DIRECTORY / 'probe-state.json', json.dumps(state))
    encrypted_database(state)
    print('broker real-S3 role/prefix isolation, credential reuse, encrypted database and database-role isolation passed')


def provider_errors():
    wait_ready()
    # Empty journal: every attempted issuance must either be revoked or remain tracked.
    for mode in ('missing', 'null', 'invalid'):
        write(DIRECTORY / 'iam-next-expiry-mode', mode)
        status, value = broker('serving-token')
        assert status == 503 and value is None, 'malformed provider expiration returned credentials'
        state = json.loads((DIRECTORY / 'iam-state.json').read_text())
        assert not state['entries'], 'known owned malformed key was not revoked'
        rows = pg(['psql', '-Atc', "SELECT count(*) FROM devres_credential_broker_keys WHERE state <> 'revoked'"])
        assert rows.returncode == 0 and rows.stdout.strip() == '0', 'malformed provider key remained active'
    path = DIRECTORY / 'issuer-key'
    original = path.read_text()
    before = json.loads((DIRECTORY / 'iam-state.json').read_text())['counters'].copy()
    write(path, secrets.token_hex(32))
    assert broker('serving-token')[0] == 403, 'issuer key replacement bypassed receipt binding'
    assert json.loads((DIRECTORY / 'iam-state.json').read_text())['counters'] == before
    write(path, original)
    write(DIRECTORY / 'iam-hide-list', 'eventually-consistent')
    write(DIRECTORY / 'iam-drop-next-response', 'once')
    assert broker('serving-token')[0] == 503, 'ambiguous provider outcome returned credentials'
    lost = json.loads((DIRECTORY / 'iam-state.json').read_text())
    assert len(lost['entries']) == 1, 'provider must create exactly once before dropping reply'
    for _ in range(3):
        assert broker('serving-token')[0] == 503, 'unresolved issuance must remain fenced'
        assert json.loads((DIRECTORY / 'iam-state.json').read_text())['counters']['create'] == lost['counters']['create']
    (DIRECTORY / 'iam-hide-list').unlink()
    credential = get('serving-token')
    recovered = json.loads((DIRECTORY / 'iam-state.json').read_text())
    assert len(recovered['entries']) == 1 and credential['AccessKeyId'] in recovered['entries']
    assert recovered['counters']['create'] == lost['counters']['create'] + 1
    assert recovered['counters']['delete'] == lost['counters']['delete'] + 1
    print('broker revoked malformed-expiry keys, fenced issuer rotation, and reconciled one ambiguous create')


def recovered():
    state = json.loads((DIRECTORY / 'probe-state.json').read_text())
    assert get('serving-token') == state['reader'] and get('writer-token') == state['writer'], 'restart changed usable credentials'
    encrypted_database(state)
    print('broker restart recovered encrypted credentials without new issuance')


def refresh():
    state = json.loads((DIRECTORY / 'probe-state.json').read_text())
    expiry = datetime.fromisoformat(state['reader']['Expiration'].replace('Z', '+00:00')).timestamp()
    deadline = time.monotonic() + 65
    while time.time() < expiry - 9:
        assert time.monotonic() < deadline, 'bounded refresh wait'
        time.sleep(min(1, max(0.01, expiry - 9 - time.time())))
    config = DIRECTORY / 'broker.toml'
    original = config.read_text()
    write(config, original.replace('max_pods = 4', 'max_pods = 1').replace('max_issued_keys = 16', 'max_issued_keys = 2'))
    before = json.loads((DIRECTORY / 'iam-state.json').read_text())['counters']['create']
    status, _ = broker('serving-token')
    assert status == 429, 'quota must fail closed before minting another key'
    assert json.loads((DIRECTORY / 'iam-state.json').read_text())['counters']['create'] == before
    write(config, original)
    reader = get('serving-token')
    writer_expiry = datetime.fromisoformat(state['writer']['Expiration'].replace('Z', '+00:00')).timestamp()
    writer_deadline = time.monotonic() + 65
    while time.time() < writer_expiry - 9:
        assert time.monotonic() < writer_deadline, 'bounded writer refresh wait'
        time.sleep(min(1, max(0.01, writer_expiry - 9 - time.time())))
    writer = get('writer-token')
    assert reader['AccessKeyId'] != state['reader']['AccessKeyId'], 'reader refresh'
    assert writer['AccessKeyId'] != state['writer']['AccessKeyId'], 'writer refresh'
    state.update(reader=reader, writer=writer)
    write(DIRECTORY / 'probe-state.json', json.dumps(state))
    assert s3(reader, 'GET', '/devres-fixture/acceptance/retained')[0] == 200
    print('broker short TTL refresh and quota denial before issuance passed')


def rotate():
    path = DIRECTORY / 'keyring.json'
    keyring = json.loads(path.read_text())
    keyring['keys']['rotated'] = secrets.token_hex(32)
    keyring['active_key_id'] = 'rotated'
    write(path, json.dumps(keyring))
    state = json.loads((DIRECTORY / 'probe-state.json').read_text())
    assert get('serving-token') == state['reader']
    rows = pg(['psql', '-Atc', "SELECT DISTINCT encryption_key FROM devres_credential_broker_keys WHERE ciphertext IS NOT NULL"])
    assert rows.returncode == 0 and set(rows.stdout.split()) == {'rotated'}, 'active rows were not resealed'
    keyring['keys'] = {'rotated': keyring['keys']['rotated']}
    write(path, json.dumps(keyring))
    assert get('writer-token') == state['writer'], 'old encryption key removal broke recovery'
    print('broker encryption key rotation resealed rows and retired the old key')


def revoked():
    state = json.loads((DIRECTORY / 'probe-state.json').read_text())
    expiry = datetime.fromisoformat(state['reader']['Expiration'].replace('Z', '+00:00')).timestamp()
    before = json.loads((DIRECTORY / 'iam-state.json').read_text())['counters']['delete']
    write(ROOT / 'identity/deleted-pods.json', json.dumps(['backend']))
    assert broker('serving-token')[0] == 401, 'deleted pod obtained new credentials'
    for _ in range(45):
        if s3(state['reader'], 'GET', '/devres-fixture/acceptance/retained')[0] == 403:
            break
        time.sleep(1)
    else:
        raise AssertionError('deleted pod key remained active beyond revocation bound')
    assert time.time() < expiry, 'natural credential expiry is not evidence of pod revocation'
    for _ in range(20):
        provider = json.loads((DIRECTORY / 'iam-state.json').read_text())
        if state['reader']['AccessKeyId'] not in provider['entries'] and provider['counters']['delete'] > before:
            break
        time.sleep(0.1)
    else:
        raise AssertionError('provider did not delete the departed pod key')
    print('broker denied deleted pod identity and revoked its S3 key')


if __name__ == '__main__':
    checks = {'provider-ready': provider_ready, 'provider-errors': provider_errors, 'initial': initial, 'recovered': recovered, 'refresh': refresh, 'rotate': rotate, 'revoked': revoked}
    if len(sys.argv) != 2 or sys.argv[1] not in checks:
        raise SystemExit('usage: credential-broker-probe.py provider-errors|initial|recovered|refresh|rotate|revoked')
    try:
        checks[sys.argv[1]]()
    except Exception as error:
        # Exception text can originate in SDK/HTTP bodies; retain only fixed context.
        frames = traceback.extract_tb(error.__traceback__)
        location = next((frame.lineno for frame in reversed(frames) if Path(frame.filename).name == Path(__file__).name), 0)
        print('Credential broker fixture check failed: ' + sys.argv[1] + ' (' + type(error).__name__ + ', line ' + str(location) + ')', file=sys.stderr)
        raise SystemExit(1) from None
