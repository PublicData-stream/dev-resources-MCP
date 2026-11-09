#!/usr/bin/env python3
"""Test-only Scaleway IAM facade backed by pinned RustFS authorization.

Only synthetic credentials are accepted. Workloads sign requests directly to
RustFS; this server does not proxy or authorize their S3 traffic.
"""
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sys
import threading
import xml.etree.ElementTree as ET
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import Request, build_opener, ProxyHandler

READONLY = '11111111-1111-4111-8111-111111111111'
READWRITE = '22222222-2222-4222-8222-222222222222'
ISSUER = '33333333-3333-4333-8333-333333333333'


def native_error_code(body):
    """Retain only the two static codes needed for missing-account recovery."""
    try:
        value = json.loads(body)
        code = value.get('Code', value.get('code')) if isinstance(value, dict) else None
    except (ValueError, TypeError):
        try:
            code = ET.fromstring(body).findtext('Code')
        except ET.ParseError:
            return None
    return code if code in ('InvalidRequest', 'NoSuchResource') else None


def delete_service_account(provider, access):
    """Normalize only a confirmed missing native account; preserve other failures."""
    try:
        status, error = provider.call('DELETE', '/rustfs/admin/v3/delete-service-account', query={'accessKey': access})
        print(f'rustfs-service-account-delete status={status}', flush=True)
        if status == 400 and error.get('Code') == 'InvalidRequest':
            info_status, info_error = provider.call('GET', '/rustfs/admin/v3/info-service-account', query={'accessKey': access})
            print(f'rustfs-service-account-info status={info_status}', flush=True)
            if info_status == 404 and info_error.get('Code') == 'NoSuchResource':
                return 404
        return status
    except (OSError, ValueError):
        print('rustfs-service-account-delete status=unavailable', flush=True)
        return 502


def policy(bucket, prefix, write):
    actions = ['s3:GetObject']
    if write:
        actions += ['s3:PutObject', 's3:DeleteObject', 's3:AbortMultipartUpload', 's3:ListMultipartUploadParts']
    listing = ['s3:ListBucket'] + (['s3:ListBucketMultipartUploads'] if write else [])
    return {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Action': actions, 'Resource': [f'arn:aws:s3:::{bucket}/{prefix}/*']},
        {'Effect': 'Allow', 'Action': listing, 'Resource': [f'arn:aws:s3:::{bucket}'],
         'Condition': {'StringLike': {'s3:prefix': [prefix + '/*']}}}]}


class RustFS:
    def __init__(self, config):
        self.endpoint = config['endpoint'].rstrip('/')
        self.access = config['access_key']
        self.secret = config['secret_key']
        self.opener = build_opener(ProxyHandler({}))

    def call(self, method, path, value=None, query=None, raw=False):
        body = value if isinstance(value, bytes) else b'' if value is None else json.dumps(value, separators=(',', ':')).encode()
        uri = self.endpoint + path
        query_string = urlencode(sorted((query or {}).items()), quote_via=quote, safe='')
        if query_string:
            uri += '?' + query_string
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        day = stamp[:8]
        authority = urlsplit(uri).netloc
        digest = hashlib.sha256(body).hexdigest()
        headers = {'host': authority, 'x-amz-content-sha256': digest, 'x-amz-date': stamp}
        names = ';'.join(sorted(headers))
        canonical = '\n'.join([method, quote(path, safe='/~'), query_string,
                               ''.join(k + ':' + headers[k] + '\n' for k in sorted(headers)), names, digest])
        scope = day + '/us-east-1/s3/aws4_request'
        message = '\n'.join(['AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
        signing = ('AWS4' + self.secret).encode()
        for part in (day, 'us-east-1', 's3', 'aws4_request'):
            signing = hmac.new(signing, part.encode(), hashlib.sha256).digest()
        headers['Authorization'] = ('AWS4-HMAC-SHA256 Credential=' + self.access + '/' + scope +
                                    ', SignedHeaders=' + names + ', Signature=' +
                                    hmac.new(signing, message.encode(), hashlib.sha256).hexdigest())
        headers['Content-Type'] = 'application/json'
        request = Request(uri, data=body if value is not None else None, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=10) as response:
                data = response.read(262145)
                if len(data) > 262144:
                    raise ValueError('fixture response bound')
                return response.status, data if raw else json.loads(data) if data else {}
        except HTTPError as error:
            try:
                data = error.read(262145)
                if len(data) > 262144:
                    raise ValueError('fixture response bound')
                code = native_error_code(data)
                return error.code, {'Code': code} if code else {}
            finally:
                error.close()


def serve(config_file):
    config = json.loads(Path(config_file).read_text())
    provider = RustFS(config)
    parents = {READONLY: 'devres-readonly-parent', READWRITE: 'devres-readwrite-parent'}
    # Workload keys never inherit root/admin authority, even in the fixture.
    for app, parent in parents.items():
        name = 'devres-readonly' if app == READONLY else 'devres-readwrite'
        parent_secret = config.get('parent_secrets', {}).get(app) or secrets.token_hex(32)
        operations = (
            ('/rustfs/admin/v3/add-user', {'secretKey': parent_secret, 'status': 'enabled'}, {'accessKey': parent}),
            ('/rustfs/admin/v3/add-canned-policy', policy(config['bucket'], config['prefix'], app == READWRITE), {'name': name}),
            ('/rustfs/admin/v3/set-user-or-group-policy', None, {'policyName': name, 'userOrGroup': parent, 'isGroup': 'false'}),
        )
        for path, body, query in operations:
            status, _ = provider.call('PUT', path, body, query)
            if status not in (200, 204):
                raise RuntimeError('RustFS fixture identity bootstrap failed')
    state_file = Path(config.get('state_file', '/fixture/broker/iam-state.json'))
    saved = json.loads(state_file.read_text()) if state_file.exists() else {}
    entries = saved.get('entries', {})
    counters = saved.get('counters', {'create': 0, 'delete': 0, 'list': 0})
    lock = threading.Lock()

    def persist():
        temporary = state_file.with_suffix('.stage')
        temporary.write_text(json.dumps({'entries': entries, 'counters': counters}))
        temporary.chmod(0o600)
        temporary.replace(state_file)

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
            return hmac.compare_digest(self.headers.get('X-Auth-Token', ''), config['issuer_secret'])

        def do_POST(self):
            if not self.authorized() or self.path != '/iam/v1alpha1/api-keys':
                return self.reply(403, {})
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 65536:
                return self.reply(400, {})
            try:
                request = json.loads(self.rfile.read(length))
                app = request['application_id']
                if app not in (READONLY, READWRITE):
                    return self.reply(403, {})
                expiry = datetime.fromisoformat(request['expires_at'].replace('Z', '+00:00'))
                if expiry <= datetime.now(timezone.utc):
                    return self.reply(400, {})
                access = 'devres' + secrets.token_hex(8)
                secret = secrets.token_hex(24)
                description = request['description']
                if not isinstance(description, str) or len(description) > 200:
                    return self.reply(400, {})
                status, _ = provider.call('PUT', '/rustfs/admin/v3/add-service-account', {
                    'targetUser': parents[app], 'accessKey': access, 'secretKey': secret,
                    'name': access, 'description': description, 'expiration': request['expires_at'],
                    'policy': policy(config['bucket'], config['prefix'], app == READWRITE)})
                if status != 200:
                    return self.reply(502, {})
                record = {'access_key': access, 'secret_key': None, 'application_id': app,
                          'description': description, 'expires_at': request['expires_at']}
                with lock:
                    entries[access] = record
                    counters['create'] += 1
                    persist()
                drop = state_file.parent / 'iam-drop-next-response'
                if drop.exists():
                    drop.unlink()
                    self.close_connection = True
                    return
                result = {**record, 'secret_key': secret}
                expiry_mode = state_file.parent / 'iam-next-expiry-mode'
                if expiry_mode.exists():
                    mode = expiry_mode.read_text().strip()
                    expiry_mode.unlink()
                    if mode == 'missing':
                        result.pop('expires_at')
                    elif mode == 'null':
                        result['expires_at'] = None
                    elif mode == 'invalid':
                        result['expires_at'] = 'invalid-expiration'
                self.reply(200, result)
            except (KeyError, ValueError, TypeError):
                self.reply(400, {})

        def do_GET(self):
            if not self.authorized():
                return self.reply(403, {})
            url = urlsplit(self.path)
            if url.path == '/iam/v1alpha1/api-keys/' + config['issuer_access_key']:
                return self.reply(200, {'access_key': config['issuer_access_key'], 'application_id': ISSUER,
                                       'secret_key': None, 'expires_at': None, 'description': 'fixture issuer'})
            with lock:
                if url.path == '/iam/v1alpha1/api-keys':
                    query = parse_qs(url.query, keep_blank_values=True)
                    organization = query.get('organization_id')
                    if organization != [config['organization_id']]:
                        reason = 'required' if organization in (None, ['']) else 'invalid'
                        return self.reply(400, {'type': 'invalid_arguments', 'details': [
                            {'argument_name': 'organization_id', 'help_message': '', 'reason': reason}]})
                    counters['list'] += 1
                    persist()
                    values = [row for row in entries.values()
                              if row['application_id'] == query.get('bearer_id', [''])[0]
                              and row['description'] == query.get('description', [''])[0]]
                    if (state_file.parent / 'iam-hide-list').exists():
                        values = []
                    return self.reply(200, {'api_keys': values, 'total_count': len(values)})
                row = entries.get(url.path.removeprefix('/iam/v1alpha1/api-keys/'))
                return self.reply(200 if row else 404, row or {})

        def do_DELETE(self):
            if not self.authorized() or not self.path.startswith('/iam/v1alpha1/api-keys/'):
                return self.reply(403, {})
            access = self.path.removeprefix('/iam/v1alpha1/api-keys/')
            with lock:
                if access not in entries:
                    return self.reply(404, {})
                status = delete_service_account(provider, access)
                if status not in (200, 204, 404):
                    return self.reply(502, {})
                del entries[access]
                counters['delete'] += 1
                persist()
            self.reply(204, {})

    class QuietServer(ThreadingHTTPServer):
        def handle_error(self, *_):
            # Never let HTTP/URL exceptions print request paths or credential values.
            print('iam-fixture-request failure', flush=True)

    QuietServer(('0.0.0.0', 8001), Handler).serve_forever()


def self_test():
    """Bounded regressions for delete recovery and organization-scoped listing."""
    import contextlib
    import io
    import queue
    import tempfile
    import unittest
    from unittest import mock

    class DeleteRecovery(unittest.TestCase):
        def run_case(self, replies, expected, calls):
            class Provider:
                def __init__(self):
                    self.methods = []

                def call(self, method, path, query):
                    self.methods.append((method, path, query))
                    value = replies[len(self.methods) - 1]
                    if isinstance(value, Exception):
                        raise value
                    return value

            provider = Provider()
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(delete_service_account(provider, 'synthetic-private-key'), expected)
            self.assertEqual(len(provider.methods), calls)
            self.assertNotIn('synthetic-private-key', output.getvalue())
            self.assertEqual(provider.methods[0][0:2], ('DELETE', '/rustfs/admin/v3/delete-service-account'))
            if calls == 2:
                self.assertEqual(provider.methods[1][0:2], ('GET', '/rustfs/admin/v3/info-service-account'))
                self.assertEqual(provider.methods[0][2], provider.methods[1][2])

        def test_lost_delete_reply_is_recoverable_only_after_proven_absence(self):
            self.run_case([(400, {'Code': 'InvalidRequest'}), (404, {'Code': 'NoSuchResource'})], 404, 2)

        def test_existing_account_is_not_forgotten(self):
            self.run_case([(400, {'Code': 'InvalidRequest'}), (200, {})], 400, 2)

        def test_unproven_or_unavailable_absence_stays_failure(self):
            for status, error in ((404, {}), (403, {'Code': 'NoSuchResource'}), (500, {})):
                with self.subTest(status=status):
                    self.run_case([(400, {'Code': 'InvalidRequest'}), (status, error)], 400, 2)

        def test_other_delete_errors_are_not_reinterpreted(self):
            for status, error in ((400, {}), (403, {}), (500, {})):
                with self.subTest(status=status):
                    self.run_case([(status, error)], status, 1)

        def test_transport_failure_remains_failure(self):
            self.run_case([OSError('private request detail')], 502, 1)

        def test_successful_and_missing_delete_need_no_lookup(self):
            for status in (200, 204, 404):
                with self.subTest(status=status):
                    self.run_case([(status, {})], status, 1)

        def test_only_static_native_codes_are_retained(self):
            self.assertEqual(native_error_code(b'<Error><Code>NoSuchResource</Code></Error>'), 'NoSuchResource')
            self.assertEqual(native_error_code(b'{"Code":"InvalidRequest","Message":"private"}'), 'InvalidRequest')
            self.assertIsNone(native_error_code(b'{"Code":"private"}'))
            self.assertIsNone(native_error_code(b'not structured'))

    class OrganizationListing(unittest.TestCase):
        def test_http_list_requires_exact_organization(self):
            organization = '55555555-5555-4555-8555-555555555555'
            servers = queue.Queue()

            class Provider:
                def __init__(self, _):
                    pass

                def call(self, *_):
                    return 200, {}

            class Server(ThreadingHTTPServer):
                def __init__(self, _, handler):
                    super().__init__(('127.0.0.1', 0), handler)
                    servers.put(self)

            with tempfile.TemporaryDirectory(dir='/tmp') as directory:
                root = Path(directory)
                config_file = root / 'config.json'
                config_file.write_text(json.dumps({'organization_id': organization,
                    'issuer_access_key': 'fixture-issuer', 'issuer_secret': 'synthetic-private-secret',
                    'bucket': 'fixture-bucket', 'prefix': 'acceptance', 'state_file': str(root / 'state.json')}))
                config_file.chmod(0o600)
                with mock.patch.object(sys.modules[__name__], 'RustFS', Provider), \
                     mock.patch.object(sys.modules[__name__], 'ThreadingHTTPServer', Server):
                    worker = threading.Thread(target=serve, args=(config_file,), daemon=True)
                    worker.start()
                    server = servers.get(timeout=5)
                    try:
                        opener = build_opener(ProxyHandler({}))
                        base = f'http://127.0.0.1:{server.server_port}/iam/v1alpha1/api-keys?'
                        cases = ((None, 'required'), ([''], 'required'),
                                 (['66666666-6666-4666-8666-666666666666'], 'invalid'),
                                 ([organization, organization], 'invalid'), ([organization], None))
                        for supplied, reason in cases:
                            with self.subTest(reason=reason, supplied=supplied):
                                query = {'bearer_id': READONLY, 'description': 'owned', 'page_size': '100', 'page': '1'}
                                if supplied is not None:
                                    query['organization_id'] = supplied
                                request = Request(base + urlencode(query, doseq=True),
                                                  headers={'X-Auth-Token': 'synthetic-private-secret'})
                                if reason is None:
                                    with opener.open(request, timeout=2) as response:
                                        self.assertEqual(response.status, 200)
                                        self.assertEqual(json.loads(response.read(65537)), {'api_keys': [], 'total_count': 0})
                                else:
                                    with self.assertRaises(HTTPError) as caught:
                                        opener.open(request, timeout=2)
                                    error = caught.exception
                                    try:
                                        self.assertEqual(error.code, 400)
                                        self.assertEqual(json.loads(error.read(65537)), {'type': 'invalid_arguments', 'details': [
                                            {'argument_name': 'organization_id', 'help_message': '', 'reason': reason}]})
                                    finally:
                                        error.close()
                        state = json.loads((root / 'state.json').read_text())
                        self.assertEqual(state['counters'], {'create': 0, 'delete': 0, 'list': 1})
                    finally:
                        server.shutdown()
                        server.server_close()
                        worker.join(timeout=5)
                    self.assertFalse(worker.is_alive())

    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                               for case in (DeleteRecovery, OrganizationListing))
    result = unittest.TextTestRunner().run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        self_test()
    if len(sys.argv) != 2:
        raise SystemExit('usage: scaleway-iam-fixture.py PRIVATE_CONFIG.json')
    try:
        serve(sys.argv[1])
    except Exception:
        raise SystemExit('IAM fixture failed') from None
