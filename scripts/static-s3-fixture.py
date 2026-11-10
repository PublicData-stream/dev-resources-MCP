#!/usr/bin/env python3
"""Synthetic static S3 identities and bounded authorization probes for RustFS.

Administrative material is consumed only by fixture setup. Workload probes load
only their role's mounted files and sign requests directly to the object store.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import sys
import xml.etree.ElementTree as ET


def transport(config):
    spec = importlib.util.spec_from_file_location('static_iam_fixture',
        Path(__file__).with_name('scaleway-iam-fixture.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.RustFS(config)


def policy(bucket, prefix, write):
    actions = ['s3:GetObject']
    if write:
        actions += ['s3:PutObject', 's3:AbortMultipartUpload', 's3:ListMultipartUploadParts']
    statements = [
        {'Effect': 'Allow', 'Action': actions, 'Resource': [f'arn:aws:s3:::{bucket}/{prefix}/*']},
        {'Effect': 'Allow', 'Action': ['s3:ListBucket'] +
         (['s3:ListBucketMultipartUploads'] if write else []),
         'Resource': [f'arn:aws:s3:::{bucket}'],
         'Condition': {'StringLike': {'s3:prefix': [prefix + '/*']}}},
        {'Effect': 'Deny', 'Action': ['s3:DeleteObject', 's3:DeleteObjectVersion'],
         'Resource': [f'arn:aws:s3:::{bucket}/*']},
    ]
    return {'Version': '2012-10-17', 'Statement': statements}


def bootstrap(config_file):
    config = json.loads(Path(config_file).read_text())
    provider = transport(config)
    for identity in config.get('retired_identities', []):
        if provider.call('PUT', '/rustfs/admin/v3/add-user',
                {'secretKey': identity['secret_key'], 'status': 'disabled'},
                {'accessKey': identity['access_key']})[0] not in (200, 204):
            raise ValueError('Retired static fixture key revocation failed')
        retired = transport({**config, **identity})
        if retired.call('GET', f"/{config['bucket']}/{config['prefix']}/.static-fixture/read", raw=True)[0] != 403:
            raise ValueError('Retired static fixture key remains usable')
    for role in ('serving', 'writer'):
        identity = config['identities'][role]
        name = 'devres-static-' + role
        operations = (
            ('/rustfs/admin/v3/add-user', {'secretKey': identity['secret_key'], 'status': 'enabled'},
             {'accessKey': identity['access_key']}),
            ('/rustfs/admin/v3/add-canned-policy', policy(config['bucket'], config['prefix'], role == 'writer'),
             {'name': name}),
            ('/rustfs/admin/v3/set-user-or-group-policy', None,
             {'policyName': name, 'userOrGroup': identity['access_key'], 'isGroup': 'false'}),
        )
        for path, value, query in operations:
            if provider.call('PUT', path, value, query)[0] not in (200, 204):
                raise ValueError('Static S3 fixture identity setup failed')
    for path in (f"/{config['bucket']}/{config['prefix']}/.static-fixture/read",
                 f"/{config['bucket']}/outside/private"):
        if provider.call('PUT', path, b'synthetic retained fixture', raw=True)[0] != 200:
            raise ValueError('Static S3 fixture seed failed')
    if provider.call('PUT', '/devres-denied', b'', raw=True)[0] not in (200, 409):
        raise ValueError('Static S3 fixture isolation bucket setup failed')


def revoke_serving(config_file):
    config = json.loads(Path(config_file).read_text())
    identity = config['identities']['serving']
    provider = transport(config)
    if provider.call('PUT', '/rustfs/admin/v3/add-user',
            {'secretKey': identity['secret_key'], 'status': 'disabled'},
            {'accessKey': identity['access_key']})[0] not in (200, 204):
        raise ValueError('Static serving fixture key revocation failed')
    revoked = transport({**config, **identity})
    if revoked.call('GET', f"/{config['bucket']}/{config['prefix']}/.static-fixture/read", raw=True)[0] != 403:
        raise ValueError('Revoked static serving fixture key remains usable')


def conditional(provider, method, path, value, query=None):
    """Sign normal S3 requests; condition headers are valid unsigned headers."""
    previous = provider.opener

    class Conditional:
        def open(self, request, **kwargs):
            request.add_header('If-None-Match', '*')
            return previous.open(request, **kwargs)

    provider.opener = Conditional()
    try:
        return provider.call(method, path, value, query, raw=True)
    finally:
        provider.opener = previous


def upload_id(body):
    value = ET.fromstring(body)
    result = next((element.text for element in value.iter()
                   if element.tag.rsplit('}', 1)[-1] == 'UploadId'), None)
    if not result or len(result) > 4096:
        raise ValueError('Invalid fixture multipart identifier')
    return result


def check(role, config_file, directory):
    if role not in ('serving', 'writer'):
        raise ValueError('Unknown static fixture role')
    config = json.loads(Path(config_file).read_text())
    directory = Path(directory)
    access = (directory / 'access-key').read_text().strip()
    provider = transport({'endpoint': config['endpoint'], 'access_key': access,
                          'secret_key': (directory / 'secret-key').read_text().strip()})
    bucket, prefix = config['bucket'], config['prefix']
    path = f'/{bucket}/{prefix}/.static-fixture/' + secrets.token_hex(12)

    def expect(status, allowed, reason):
        if status not in allowed:
            raise ValueError(reason)

    expect(provider.call('GET', f'/{bucket}/{prefix}/.static-fixture/read', raw=True)[0], (200,), 'static read')
    expect(provider.call('HEAD', f'/{bucket}/{prefix}/.static-fixture/read', raw=True)[0], (200,), 'static head')
    expect(provider.call('GET', f'/{bucket}', query={'list-type': '2', 'prefix': prefix + '/', 'max-keys': '1'}, raw=True)[0], (200,), 'static list')
    expect(provider.call('GET', f'/{bucket}/outside/private', raw=True)[0], (403,), 'outside prefix denied')
    expect(provider.call('GET', '/devres-denied', query={'list-type': '2'}, raw=True)[0], (403,), 'other bucket denied')
    expect(provider.call('GET', '/rustfs/admin/v3/list-users', raw=True)[0], (403,), 'administration denied')
    expect(provider.call('DELETE', f'/{bucket}/{prefix}/.static-fixture/read', raw=True)[0], (403,), 'permanent deletion denied')
    expect(provider.call('DELETE', f'/{bucket}/{prefix}/.static-fixture/read', query={'versionId': 'synthetic'}, raw=True)[0], (403,), 'version deletion denied')
    if role == 'serving':
        expect(provider.call('PUT', path, b'synthetic', raw=True)[0], (403,), 'serving put denied')
        expect(provider.call('POST', path, b'', query={'uploads': ''}, raw=True)[0], (403,), 'serving multipart denied')
        expect(provider.call('DELETE', path, query={'uploadId': 'synthetic'}, raw=True)[0], (403,), 'serving abort denied')
    else:
        expect(conditional(provider, 'PUT', path, b'synthetic')[0], (200,), 'writer conditional put')
        expect(conditional(provider, 'PUT', path, b'overwrite forbidden')[0], (412,), 'conditional overwrite denied')
        status, body = provider.call('POST', path + '-complete', b'', query={'uploads': ''}, raw=True)
        expect(status, (200,), 'writer multipart create')
        identifier = upload_id(body)
        expect(provider.call('PUT', path + '-complete', b'one bounded part',
               query={'partNumber': '1', 'uploadId': identifier}, raw=True)[0], (200,), 'writer multipart part')
        status, body = provider.call('GET', path + '-complete', query={'uploadId': identifier}, raw=True)
        expect(status, (200,), 'writer multipart inspect')
        value = ET.fromstring(body)
        etag = next((element.text for element in value.iter() if element.tag.rsplit('}', 1)[-1] == 'ETag'), None)
        if not etag:
            raise ValueError('Missing fixture part identity')
        completion = ET.Element('CompleteMultipartUpload')
        part = ET.SubElement(completion, 'Part')
        ET.SubElement(part, 'ETag').text = etag
        ET.SubElement(part, 'PartNumber').text = '1'
        expect(conditional(provider, 'POST', path + '-complete', ET.tostring(completion),
               {'uploadId': identifier})[0], (200,), 'writer multipart completion')
        status, body = provider.call('POST', path + '-abort', b'', query={'uploads': ''}, raw=True)
        expect(status, (200,), 'writer interrupted multipart create')
        expect(provider.call('DELETE', path + '-abort', query={'uploadId': upload_id(body)}, raw=True)[0],
               (200, 204), 'writer interrupted multipart abort')
    return hashlib.sha256(access.encode()).hexdigest()


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] in ('bootstrap', 'revoke-serving'):
            (bootstrap if sys.argv[1] == 'bootstrap' else revoke_serving)(sys.argv[2])
        elif len(sys.argv) == 5 and sys.argv[1] == 'check':
            print(check(sys.argv[2], sys.argv[3], sys.argv[4]))
        else:
            raise ValueError('Unsupported static S3 fixture action')
    except Exception:
        raise SystemExit('Static S3 authorization fixture failed.') from None
