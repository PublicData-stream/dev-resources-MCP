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
    config = root / 'fixture' / 'backend.toml'
    text = config.read_text()
    text, changes = re.subn(r'(?m)^\[storage\]\s*$', '[storage]\nbackend = "s3"', text)
    if changes != 1:
        raise ValueError('Expected one storage configuration')
    text += '\n[storage.s3]\n' + fields + '\n[storage.s3.credentials]\n' + credentials
    config.write_text(text)


def foundation(path):
    file = Path(path)
    text = file.read_text()
    text, count = re.subn(r'(name: backend\nspec:\n  replicas:) 1\n', r'\1 0\n', text)
    if count != 1:
        raise ValueError('Expected one backend deployment')
    mount = '- {name: config, mountPath: /fixture/backend.toml, subPath: backend.toml, readOnly: true}'
    if text.count(mount) != 1:
        raise ValueError('Expected one backend configuration mount')
    text = text.replace(mount, mount + '\n            - {name: s3, mountPath: /fixture/s3, readOnly: true}')
    volume = 'secret: {secretName: devres-config}'
    if text.count(volume) != 1:
        raise ValueError('Expected one backend configuration volume')
    text = text.replace(volume, volume + '\n        - name: s3\n          secret: {secretName: devres-s3-credentials, defaultMode: 0440}')
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
                                     # DNS convergence is a prerequisite; the authenticated PUT runs once.
                                     'command': ['sh', '-ec',
                                         'attempt=0; until getent ahostsv4 objectstore >/dev/null; do '
                                         'attempt=$((attempt+1)); test "$attempt" -lt 60 || exit 1; '
                                         'sleep 1; done; '
                                         'exec curl --connect-timeout 5 --max-time 15 '
                                         '--config /fixture/s3/create-bucket.curl'],
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
        raise SystemExit('usage: s3-kubernetes-fixture.py prepare|foundation|initializer ARG')
    action, value = sys.argv[1:]
    if action == 'prepare':
        prepare(value)
    elif action == 'foundation':
        foundation(value)
    elif action == 'initializer':
        print(json.dumps(initializer(value)))
    else:
        raise SystemExit('Unsupported S3 fixture action')
