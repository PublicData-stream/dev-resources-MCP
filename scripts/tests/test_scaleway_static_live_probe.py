"""No-network fixtures for bounded live S3 scope, signing and durable intent."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from urllib.request import Request
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('scaleway_static_live_probe', ROOT / 'scripts/scaleway-static-live-probe.py')
probe_module = importlib.util.module_from_spec(SPEC)
# dataclasses consult the defining module during decoration.
import sys
sys.modules[SPEC.name] = probe_module
SPEC.loader.exec_module(probe_module)


def response(status=200, body=b'', headers=None):
    return probe_module.Response(status, headers or {}, body)


def denied(code='AccessDenied'):
    return response(403, ('<Error><Code>' + code + '</Code></Error>').encode())


class Store:
    def __init__(self):
        self.objects, self.uploads, self.calls = {}, {}, []
        self.revoked = False
        self.unexpected_reader_create = False
        self.uncertain_create = False
        self.before = None

    def client(self, role):
        owner = self

        class Client:
            def request(self, method, key=None, *, query=None, body=b'', headers=None, max_response=None):
                if owner.before:
                    owner.before(role, method, key, query or {})
                owner.calls.append((role, method, key, query or {}, len(body)))
                return owner.request(role, method, key, query or {}, body, headers or {})
        return Client()

    def request(self, role, method, key, query, body, headers):
        if self.revoked and role.startswith('test_'):
            return denied('InvalidAccessKeyId')
        if (key and key.startswith('outside/')) or query.get('prefix') == 'outside/':
            return denied()
        reader = role.endswith('reader')
        if reader and method not in ('GET', 'HEAD'):
            if self.unexpected_reader_create and method == 'POST' and 'uploads' in query:
                self.uploads['unexpected-reader-upload'] = {'key': key, 'body': b''}
                return response(body=b'<InitiateMultipartUploadResult><UploadId>unexpected-reader-upload</UploadId></InitiateMultipartUploadResult>')
            return denied()
        if key is None:
            keys = [value for value in sorted(self.objects) if value.startswith(query['prefix'])][:2]
            return response(body=('<ListBucketResult>' + ''.join('<Contents><Key>' + value + '</Key></Contents>'
                             for value in keys) + '</ListBucketResult>').encode())
        if method == 'POST' and 'uploads' in query:
            if self.uncertain_create:
                raise OSError('test-only-lost-initiation-response')
            identifier = 'upload-' + str(len(self.uploads))
            self.uploads[identifier] = {'key': key, 'body': b''}
            return response(body=('<InitiateMultipartUploadResult><UploadId>' + identifier + '</UploadId></InitiateMultipartUploadResult>').encode())
        if 'uploadId' in query:
            upload = self.uploads[query['uploadId']]
            if method == 'PUT':
                upload['body'] = body
                upload['etag'] = '"' + hashlib.md5(body).hexdigest() + '"'
                return response(headers={'etag': upload['etag']})
            if method == 'GET':
                return response(body=('<ListPartsResult><Part><ETag>' + upload['etag'] + '</ETag></Part></ListPartsResult>').encode())
            if method == 'POST':
                if key in self.objects:
                    return response(412, b'<Error><Code>PreconditionFailed</Code></Error>')
                self.objects[key] = upload['body']
                return response(body=b'<CompleteMultipartUploadResult><ETag>"completed"</ETag></CompleteMultipartUploadResult>')
            if method == 'DELETE':
                return response(204)
        if method == 'PUT':
            if key in self.objects:
                return response(412, b'<Error><Code>PreconditionFailed</Code></Error>')
            self.objects[key] = body
            return response(headers={'etag': '"small"'})
        if method == 'DELETE':
            return denied()
        metadata = {'x-amz-storage-class': 'ONEZONE_IA', 'content-length': str(len(self.objects[key]))}
        return response(body=self.objects[key] if method == 'GET' else b'', headers=metadata)


class StaticLiveProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.store = Store()
        self.probe = probe_module.Probe(self.parent / 'run', {role: self.store.client(role) for role in probe_module.ROLES})

    def test_complete_probe_uses_exactly_two_keys_and_less_than_twenty_mib(self):
        result = self.probe.run('credential-binding')
        allocated = {record['key'] for record in result['keys'].values()}
        mutated = {key for _, method, key, _, _ in self.store.calls if method not in ('GET', 'HEAD')}
        self.assertEqual(mutated, allocated)
        self.assertEqual(len(self.store.objects), 2)
        self.assertLess(result['bytes_sent'], probe_module.MAX_BYTES)
        self.assertEqual(sorted(upload['phase'] for upload in result['uploads']), ['aborted', 'completed'])
        self.assertFalse(result['checks']['version_deletion_denied']['passed'])
        self.assertFalse(result['checks']['foreign_bucket_denied']['passed'])
        self.assertFalse(result['checks']['administration_denied']['passed'])
        self.assertFalse(result['production_receipt_emitted'])

    def test_intent_and_spent_budget_are_on_disk_before_every_io(self):
        def before(role, method, key, query):
            state = self.probe.load()
            event = state['events'][-1]
            self.assertEqual(event['phase'], 'intent')
            self.assertEqual((event['role'], event['method'], event['key'], event['query']), (role, method, key, query))
            self.assertEqual(state['bytes_sent'], sum(item['request_bytes'] for item in state['events']))
        self.store.before = before
        self.probe.run('credential-binding')

    def test_unexpected_reader_allow_stops_and_preserves_new_upload_identifier(self):
        self.store.unexpected_reader_create = True
        with self.assertRaises(probe_module.ProbeError):
            self.probe.run('binding')
        state = self.probe.load()
        self.assertEqual(state['phase'], 'failed')
        self.assertIn('unexpected-reader-upload', [upload['upload_id'] for upload in state['uploads']])
        self.assertEqual(state['events'][-1]['label'], 'reader-init-denied')
        self.assertEqual(len(self.store.objects), 2)

    def test_ambiguous_create_cannot_resume_or_automatically_repeat(self):
        self.store.uncertain_create = True
        with self.assertRaises(OSError):
            self.probe.run('binding')
        state = self.probe.load()
        self.assertEqual(state['events'][-1]['phase'], 'uncertain')
        calls = len(self.store.calls)
        with self.assertRaisesRegex(probe_module.ProbeError, 'run_cannot_resume'):
            self.probe.run('binding')
        self.assertEqual(len(self.store.calls), calls)

    def test_request_payload_scope_and_actual_version_budgets_are_enforced_before_io(self):
        self.probe.start('binding')
        for kwargs in ({'outside': True, 'body': b'foreign'},
                       {'query': {'versionId': 'fabricated'}}, {'query': {'uploadId': 'unknown'}}):
            with self.subTest(kwargs=kwargs), self.assertRaises(probe_module.ProbeError):
                self.probe.io('invalid', 'test_writer', 'PUT', 'conditional', **kwargs)
        self.probe.state['bytes_sent'] = probe_module.MAX_BYTES
        with self.assertRaisesRegex(probe_module.ProbeError, 'run_budget_exhausted'):
            self.probe.io('oversized', 'test_writer', 'PUT', 'conditional', body=b'x')
        self.assertEqual(self.store.calls, [])

    def test_revocation_evidence_never_claims_operating_key_rotation(self):
        self.probe.run('binding')
        self.store.revoked = True
        result = self.probe.verify_revoked('binding')
        self.assertTrue(result['checks']['test_keys_denied_current_pairs_work']['passed'])
        self.assertFalse(result['checks']['rotation_revocation_verified']['passed'])
        self.assertFalse(result['production_receipt_emitted'])
        calls = len(self.store.calls)
        with self.assertRaises(probe_module.ProbeError):
            self.probe.verify_revoked('binding')
        self.assertEqual(len(self.store.calls), calls)

    def test_revocation_failure_or_changed_credentials_cannot_pass(self):
        self.probe.run('binding')
        with self.assertRaises(probe_module.ProbeError):
            self.probe.verify_revoked('changed')
        with self.assertRaises(probe_module.ProbeError):
            self.probe.verify_revoked('binding')
        self.assertNotIn('test_keys_denied_current_pairs_work', self.probe.load()['checks'])

    def test_failed_run_allows_only_readonly_revocation_verification_not_mutation_replay(self):
        self.store.uncertain_create = True
        with self.assertRaises(OSError):
            self.probe.run('binding')
        failed = self.probe.summary()
        self.assertEqual(failed['uncertain_intents'][0]['label'], 'multipart-init-complete')
        self.store.revoked = True
        mutations = len([call for call in self.store.calls if call[1] not in ('GET', 'HEAD')])
        result = self.probe.verify_revoked('binding')
        self.assertEqual(result['run_outcome'], 'failed')
        self.assertEqual(len([call for call in self.store.calls if call[1] not in ('GET', 'HEAD')]), mutations)

    def test_sigv4_signs_condition_and_storage_class_for_fixed_paris_endpoint(self):
        client = probe_module.S3('test-access', 'test-secret', now=lambda: datetime(2026, 11, 10, tzinfo=timezone.utc))
        request = client.signed_request('PUT', 'production/.acceptance/run/a b', body=b'fixture',
                                        query={'z': '/', 'a': '+'}, headers={'If-None-Match': '*', 'x-amz-storage-class': 'ONEZONE_IA'})
        self.assertEqual(request.full_url, probe_module.ENDPOINT + '/dev-resources-mcp/production/.acceptance/run/a%20b?a=%2B&z=%2F')
        authorization = request.get_header('Authorization')
        self.assertIn('/20261110/fr-par/s3/aws4_request', authorization)
        self.assertIn('if-none-match', authorization)
        self.assertIn('x-amz-storage-class', authorization)
        self.assertEqual(request.get_header('X-amz-content-sha256'), hashlib.sha256(b'fixture').hexdigest())
        with self.assertRaises(probe_module.ProbeError):
            client.signed_request('POST', None, query={'delete': ''})

    def test_redirect_refused_before_forwarding_authorization(self):
        with self.assertRaisesRegex(probe_module.ProbeError, 'redirect_refused'):
            probe_module.NoRedirect().redirect_request(Request(probe_module.ENDPOINT), None, 307, 'redirect', {}, 'https://untrusted.invalid')

    def test_private_files_symlinks_and_tampered_scope_refused(self):
        path = self.parent / 'private'
        path.write_text('test-only')
        path.chmod(0o644)
        with self.assertRaises(probe_module.ProbeError):
            probe_module.private_read(path)
        path.chmod(0o600)
        link = self.parent / 'link'
        link.symlink_to(path)
        with self.assertRaises(probe_module.ProbeError):
            probe_module.private_read(link)
        self.probe.start('binding')
        self.probe.state['keys']['conditional']['key'] = 'production/permanent-capture'
        self.probe.save()
        with self.assertRaisesRegex(probe_module.ProbeError, 'state_scope_invalid'):
            self.probe.load()

    def test_concurrent_operation_cannot_race_durable_attempt_accounting(self):
        self.probe.start('binding')
        with self.probe.exclusive():
            with self.assertRaisesRegex(probe_module.ProbeError, 'another_probe_operation_is_active'):
                with self.probe.exclusive():
                    self.fail('A second operation acquired the same run lock')
        self.assertEqual(self.store.calls, [])

    def test_transport_response_bound_and_uncertain_request_are_not_retried(self):
        class Reply:
            status = 200
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size): return b'oversized'[:size]

        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                return Reply()

        opener = Opener()
        client = probe_module.S3('test-access', 'test-secret', opener=opener)
        with self.assertRaisesRegex(probe_module.ProbeError, 'response_too_large'):
            client.request('GET', 'production/.acceptance/run/conditional', max_response=4)
        self.assertEqual(opener.calls, 1)
        with patch.object(opener, 'open', side_effect=TimeoutError('test-only-timeout')) as calls:
            with self.assertRaisesRegex(probe_module.ProbeError, 'request_uncertain'):
                client.request('GET', 'production/.acceptance/run/conditional')
            self.assertEqual(calls.call_count, 1)


if __name__ == '__main__':
    unittest.main()
