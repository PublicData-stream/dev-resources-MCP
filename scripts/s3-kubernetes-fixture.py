#!/usr/bin/env python3
"""Build private disposable S3 fixture configuration and initialization manifests."""
import json
from pathlib import Path
import re
import secrets
import sys


def prepare(scratch):
    root = Path(scratch).resolve(strict=True)
    if Path('/tmp') not in root.parents:
        raise ValueError('S3 fixtures require a private directory below /tmp')
    directory = root / 'fixture' / 's3'
    directory.mkdir(mode=0o700)
    access, secret = 'fixture-' + secrets.token_hex(12), secrets.token_hex(32)
    fields = (
        'endpoint = "http://objectstore:9000"\n'
        'bucket = "devres-fixture"\nregion = "us-east-1"\nprefix = "acceptance"\n'
        'path_style = true\nallow_http = true\ncache_max_bytes = 1073741824\n'
    )
    credentials = (
        'mode = "files"\naccess_key_file = "/fixture/s3/access-key"\n'
        'secret_key_file = "/fixture/s3/secret-key"\n'
    )
    files = {
        'access-key': access,
        'secret-key': secret,
        's3.toml': fields + '\n[credentials]\n' + credentials,
        'create-bucket.curl': (
            'url = "http://objectstore:9000/devres-fixture"\nrequest = "PUT"\n'
            'aws-sigv4 = "aws:amz:us-east-1:s3"\n'
            'user = ' + json.dumps(access + ':' + secret) + '\n'
            'data = ""\nsilent\nshow-error\nfail\noutput = "/dev/null"\n'
        ),
    }
    for name, body in files.items():
        path = directory / name
        path.write_text(body)
        path.chmod(0o600)
    identities = {}
    for role in ('serving', 'writer'):
        role_dir = root / 'fixture' / ('s3-' + role)
        role_dir.mkdir(mode=0o700)
        pair = {'access_key': 'static-' + secrets.token_hex(12), 'secret_key': secrets.token_hex(32)}
        identities[role] = pair
        for name, body in {'access-key': pair['access_key'], 'secret-key': pair['secret_key'],
                           's3.toml': fields + '\n[credentials]\n' + credentials}.items():
            path = role_dir / name
            path.write_text(body)
            path.chmod(0o600)
    setup = {'endpoint': 'http://objectstore:9000', 'access_key': access, 'secret_key': secret,
             'bucket': 'devres-fixture', 'prefix': 'acceptance', 'identities': identities}
    path = directory / 'static-fixture.json'
    path.write_text(json.dumps(setup))
    path.chmod(0o600)
    # Public coordinates only: workload probes never receive administrative keys.
    for role in ('serving', 'writer'):
        path = root / 'fixture' / ('s3-' + role) / 'probe.json'
        path.write_text(json.dumps({key: setup[key] for key in ('endpoint', 'bucket', 'prefix')}))
        path.chmod(0o600)
    config = root / 'fixture' / 'backend.toml'
    text = config.read_text()
    text, changes = re.subn(r'(?m)^\[storage\]\s*$', '[storage]\nbackend = "s3"', text)
    if changes != 1:
        raise ValueError('Expected one storage configuration')
    text += '\n[storage.s3]\n' + fields + '\n[storage.s3.credentials]\n' + credentials
    config.write_text(text)


def rotate(scratch):
    root = Path(scratch).resolve(strict=True)
    if Path('/tmp') not in root.parents:
        raise ValueError('S3 fixtures require a private directory below /tmp')
    setup_file = root / 'fixture/s3/static-fixture.json'
    setup = json.loads(setup_file.read_text())
    setup.setdefault('retired_identities', []).extend(setup['identities'].values())
    for role in ('serving', 'writer'):
        pair = {'access_key': 'static-' + secrets.token_hex(12), 'secret_key': secrets.token_hex(32)}
        setup['identities'][role] = pair
        for name, body in {'access-key': pair['access_key'], 'secret-key': pair['secret_key']}.items():
            path = root / 'fixture' / ('s3-' + role) / name
            path.write_text(body)
            path.chmod(0o600)
    setup_file.write_text(json.dumps(setup))
    setup_file.chmod(0o600)


def configure_static(scratch):
    root = Path(scratch).resolve(strict=True)
    if Path('/tmp') not in root.parents:
        raise ValueError('S3 fixtures require a private directory below /tmp')
    replacement = ('[storage.s3.credentials]\nmode = "files"\n'
                   'access_key_file = "/fixture/s3/access-key"\n'
                   'secret_key_file = "/fixture/s3/secret-key"\n\n')
    for name in ('backend', 'writer'):
        path = root / 'fixture' / (name + '.toml')
        text, count = re.subn(r'(?ms)^\[storage\.s3\.credentials\]\s*\n.*?(?=^\[|\Z)',
                              replacement, path.read_text())
        if count != 1:
            raise ValueError('Expected one S3 credential table')
        path.write_text(text)
        path.chmod(0o600)


def foundation(path):
    file = Path(path)
    text = file.read_text()
    text, count = re.subn(r'(name: backend\nspec:\n  replicas:) [01]\n', r'\1 0\n', text)
    if count != 1:
        raise ValueError('Expected one backend deployment')
    mount = '- {name: config, mountPath: /fixture/backend.toml, subPath: backend.toml, readOnly: true}'
    if text.count(mount) != 1:
        raise ValueError('Expected one backend configuration mount')
    text = text.replace(mount, mount + '\n            - {name: s3, mountPath: /fixture/s3, readOnly: true}')
    volume = 'secret: {secretName: devres-config}'
    if text.count(volume) != 1:
        raise ValueError('Expected one backend configuration volume')
    text = text.replace(volume, volume + '\n        - name: s3\n          secret: {secretName: devres-serving-s3, defaultMode: 0440}')
    file.write_text(text)


def writer(path):
    file = Path(path)
    text = file.read_text()
    mount = '- {name: data, mountPath: /data}'
    text = text.replace(mount, mount + '\n            - {name: s3, mountPath: /fixture/s3, readOnly: true}')
    volume = 'secret: {secretName: devres-writer-config}'
    text = text.replace(volume, volume + '\n        - name: s3\n          secret: {secretName: devres-writer-s3, defaultMode: 0440}')
    file.write_text(text)


def initializer(image):
    return {
        'apiVersion': 'batch/v1', 'kind': 'Job',
        'metadata': {'name': 'objectstore-init'},
        'spec': {'backoffLimit': 0, 'activeDeadlineSeconds': 90,
                 'template': {'metadata': {'labels': {'app': 'backend'}}, 'spec': {
                     'automountServiceAccountToken': False, 'restartPolicy': 'Never',
                     'securityContext': {'runAsUser': 65532, 'runAsGroup': 65532,
                                         'fsGroup': 65532, 'runAsNonRoot': True},
                     'containers': [{'name': 'initialize', 'image': image,
                                     'imagePullPolicy': 'Never',
                                     # DNS and Service health share one deadline; authenticated PUT runs once.
                                     'command': ['sh', '-ec',
                                         'deadline=$(($(date +%s)+60)); '
                                         'until getent ahostsv4 objectstore >/dev/null && '
                                         'curl --connect-timeout 1 --max-time 2 --fail --silent '
                                         '--output /dev/null http://objectstore:9000/health; do '
                                         'test "$(date +%s)" -lt "$deadline" || exit 1; '
                                         'sleep 1; done; '
                                         'curl --connect-timeout 5 --max-time 15 --retry 5 --retry-delay 1 --retry-max-time 20 '
                                         '--config /fixture/s3/create-bucket.curl; '
                                         'exec python3 -I -B /harness/static-s3-fixture.py '
                                         'bootstrap /fixture/s3/static-fixture.json'],
                                     'securityContext': {'allowPrivilegeEscalation': False,
                                                         'capabilities': {'drop': ['ALL']}},
                                     'volumeMounts': [{'name': 's3', 'mountPath': '/fixture/s3',
                                                      'readOnly': True}]}],
                     'volumes': [{'name': 's3', 'secret': {
                         'secretName': 'devres-s3-credentials', 'defaultMode': 0o440}}],
                 }}}
    }


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: s3-kubernetes-fixture.py prepare|rotate|configure-static|foundation|writer|initializer ARG')
    action, value = sys.argv[1:]
    if action == 'prepare':
        prepare(value)
    elif action == 'rotate':
        rotate(value)
    elif action == 'configure-static':
        configure_static(value)
    elif action == 'foundation':
        foundation(value)
    elif action == 'writer':
        writer(value)
    elif action == 'initializer':
        print(json.dumps(initializer(value)))
    else:
        raise SystemExit('Unsupported S3 fixture action')
