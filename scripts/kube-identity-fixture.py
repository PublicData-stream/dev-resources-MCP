#!/usr/bin/env python3
"""Offline Docker-only Kubernetes identity fixture, never a production verifier."""
import base64
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sys
import time


def prepare(root):
    root = Path(root).resolve(strict=True)
    if Path('/tmp') not in root.parents:
        raise ValueError('Identity fixtures must be generated below /tmp')
    directory = root / 'fixture/identity'
    directory.mkdir(mode=0o700)
    claims = base64.urlsafe_b64encode(json.dumps({'exp': int(time.time()) + 7200}).encode()).decode().rstrip('=')
    for name, value in {'api-token': secrets.token_hex(32),
                        'serving-token': 'fixture.' + claims + '.' + secrets.token_hex(16),
                        'writer-token': 'fixture.' + claims + '.' + secrets.token_hex(16)}.items():
        path = directory / name
        path.write_text(value)
        path.chmod(0o600)


def serve(directory):
    root = Path(directory)
    api_token = (root / 'api-token').read_text()
    identities = {
        (root / 'serving-token').read_text(): ('backend', 'devres-serving', 'fixture-serving-pod', 'fixture-serving-sa'),
        (root / 'writer-token').read_text(): ('writer', 'devres-writer', 'fixture-writer-pod', 'fixture-writer-sa'),
    }

    def deleted(name):
        marker = root / 'deleted-pods.json'
        return marker.exists() and name in json.loads(marker.read_text())

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def authorized(self):
            return hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + api_token)

        def do_POST(self):
            if not self.authorized() or self.path != '/apis/authentication.k8s.io/v1/tokenreviews':
                return self.reply(403, {})
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 65536:
                return self.reply(400, {})
            try:
                request = json.loads(self.rfile.read(length))
                spec = request['spec']
                identity = next((value for token, value in identities.items()
                                 if hmac.compare_digest(spec['token'], token)), None)
                allowed = identity is not None and not deleted(identity[0]) and spec['audiences'] in (['devres-writer'], ['devres-credential-broker'])
            except (ValueError, KeyError, TypeError):
                return self.reply(400, {})
            status = {'authenticated': allowed, 'audiences': spec['audiences'] if allowed else []}
            if allowed:
                name, account, pod_uid, account_uid = identity
                status['user'] = {'username': 'system:serviceaccount:devres-acceptance:' + account,
                                  'uid': account_uid, 'extra': {
                                      'authentication.kubernetes.io/pod-name': [name],
                                      'authentication.kubernetes.io/pod-uid': [pod_uid]}}
            self.reply(200, {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenReview', 'status': status})

        def do_GET(self):
            if not self.authorized():
                return self.reply(403, {})
            if self.path == '/api/v1/namespaces/kube-system':
                return self.reply(200, {'metadata': {'name': 'kube-system', 'uid': 'fixture-cluster-devres'}})
            prefix = '/api/v1/namespaces/devres-acceptance/'
            for name, account, pod_uid, account_uid in identities.values():
                if self.path == prefix + 'pods/' + name and not deleted(name):
                    return self.reply(200, {'metadata': {'name': name, 'namespace': 'devres-acceptance',
                                                       'uid': pod_uid}, 'spec': {'serviceAccountName': account}})
                if self.path == prefix + 'serviceaccounts/' + account:
                    return self.reply(200, {'metadata': {'name': account, 'namespace': 'devres-acceptance',
                                                       'uid': account_uid}})
            self.reply(404, {})

    ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ('prepare', 'serve'):
        raise SystemExit('usage: kube-identity-fixture.py prepare /tmp/ROOT | serve IDENTITY_DIRECTORY')
    (prepare if sys.argv[1] == 'prepare' else serve)(sys.argv[2])
