#!/usr/bin/env python3
"""Bounded, explicitly invoked Scaleway S3 evidence; never a production receipt.

Only two journaled disposable object keys are used. This helper creates/revokes
no IAM keys, performs no administrative cleanup, and never resumes a run.
"""
import argparse
import contextlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import fcntl
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import xml.etree.ElementTree as ET


ENDPOINT = 'https://s3.fr-par.scw.cloud'
REGION = 'fr-par'
BUCKET = 'dev-resources-mcp'
MAX_BYTES = 20 * 1024**2
MULTIPART_BYTES = 17 * 1024**2
MAX_XML = 65536
MAX_REQUESTS = 80
ROLES = ('test_reader', 'test_writer', 'current_reader', 'current_writer')
INPUT_FIELDS = {role + '_' + kind + '_file' for role in ROLES for kind in ('access_key', 'secret_key')}


class ProbeError(RuntimeError):
    """Only fixed, credential-free diagnostics leave the CLI."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProbeError('redirect_refused')


def private_read(path, limit=65536):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or any(item.is_symlink() for item in (path, *path.parents)):
        raise ProbeError('unsafe_private_path')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > limit):
            raise ProbeError('unsafe_private_file')
        value = os.read(descriptor, limit + 1)
        if len(value) > limit:
            raise ProbeError('private_file_too_large')
        return value
    finally:
        os.close(descriptor)


def atomic(path, value):
    encoded = json.dumps(value, sort_keys=True).encode()
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb', closefd=False) as output:
            output.write(encoded)
            output.flush()
            os.fsync(descriptor)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)


def xml_value(body, name):
    if len(body) > MAX_XML or b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():
        raise ProbeError('xml_response_invalid')
    try:
        root = ET.fromstring(body)
    except ET.ParseError as error:
        raise ProbeError('xml_response_invalid') from error
    values = [node.text for node in root.iter() if node.tag.rsplit('}', 1)[-1] == name]
    if len(values) != 1 or not isinstance(values[0], str) or not 1 <= len(values[0]) <= 4096:
        raise ProbeError('xml_response_field_invalid')
    if any(ord(char) < 32 or ord(char) == 127 for char in values[0]):
        raise ProbeError('xml_response_field_invalid')
    return values[0]


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes

    @property
    def code(self):
        if len(self.body) > MAX_XML or b'<Code>' not in self.body:
            return None
        value = xml_value(self.body, 'Code')
        return value if re.fullmatch('[A-Za-z][A-Za-z0-9]{0,63}', value) else None


class S3:
    """Fixed-endpoint SigV4 transport, also usable for separately authorized cleanup.

    Remote probes bypass proxy environment variables. Local operators can select
    use_environment_proxy=True; redirects stay disabled in either mode. No retry.
    """
    def __init__(self, access_key, secret_key, *, opener=None, use_environment_proxy=False, now=None):
        self.access_key, self.secret_key = access_key, secret_key
        self.opener = opener or build_opener(ProxyHandler() if use_environment_proxy else ProxyHandler({}), NoRedirect())
        self.now = now or (lambda: datetime.now(timezone.utc))

    def signed_request(self, method, key=None, *, query=None, body=b'', headers=None):
        if method not in ('GET', 'HEAD', 'PUT', 'POST', 'DELETE') or not isinstance(body, bytes) or len(body) > MAX_BYTES:
            raise ProbeError('request_scope_invalid')
        if key is None:
            if method != 'GET':
                raise ProbeError('bucket_mutation_refused')
            path = '/' + BUCKET
        else:
            if (not isinstance(key, str) or not key or len(key) > 1024 or key.startswith('/')
                    or any(part in ('', '.', '..') for part in key.split('/'))
                    or any(ord(char) < 32 or char in '\\*?' or ord(char) == 127 for char in key)):
                raise ProbeError('object_key_invalid')
            path = '/' + BUCKET + '/' + key
        query = query or {}
        if not isinstance(query, dict) or len(query) > 8:
            raise ProbeError('query_invalid')
        canonical_query = '&'.join(quote(str(name), safe='-_.~') + '=' + quote(str(value), safe='-_.~')
                                   for name, value in sorted(query.items()))
        if len(canonical_query) > 8192 or 'delete' in query:
            raise ProbeError('query_invalid')
        path = quote(path, safe='/-_.~')
        stamp = self.now().astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        fields = {'host': 's3.fr-par.scw.cloud', 'x-amz-date': stamp,
                  'x-amz-content-sha256': hashlib.sha256(body).hexdigest()}
        for name, value in (headers or {}).items():
            name = name.lower()
            if name in fields or name == 'authorization' or not re.fullmatch('[a-z0-9-]+', name):
                raise ProbeError('header_invalid')
            if not isinstance(value, str) or len(value) > 8192 or any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ProbeError('header_invalid')
            fields[name] = ' '.join(value.split())
        names = ';'.join(sorted(fields))
        canonical = '\n'.join((method, path, canonical_query,
                               ''.join(name + ':' + fields[name] + '\n' for name in sorted(fields)),
                               names, fields['x-amz-content-sha256']))
        scope = stamp[:8] + '/' + REGION + '/s3/aws4_request'
        message = '\n'.join(('AWS4-HMAC-SHA256', stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()))
        signing = ('AWS4' + self.secret_key).encode()
        for value in (stamp[:8], REGION, 's3', 'aws4_request'):
            signing = hmac.new(signing, value.encode(), hashlib.sha256).digest()
        fields['authorization'] = ('AWS4-HMAC-SHA256 Credential=' + self.access_key + '/' + scope +
                                   ', SignedHeaders=' + names + ', Signature=' +
                                   hmac.new(signing, message.encode(), hashlib.sha256).hexdigest())
        url = ENDPOINT + path + ('?' + canonical_query if canonical_query else '')
        return Request(url, data=body if method in ('PUT', 'POST') else None, headers=fields, method=method)

    def request(self, method, key=None, *, query=None, body=b'', headers=None, max_response=MAX_BYTES):
        request = self.signed_request(method, key, query=query, body=body, headers=headers)
        if not 0 <= max_response <= MAX_BYTES:
            raise ProbeError('response_bound_invalid')
        started = time.monotonic()
        try:
            try:
                response = self.opener.open(request, timeout=20)
            except HTTPError as error:
                response = error
            with response:
                data = bytearray()
                read = getattr(response, 'read1', response.read)
                while True:
                    if time.monotonic() - started > 45:
                        raise ProbeError('response_deadline_exceeded')
                    chunk = read(min(65536, max_response + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > max_response:
                        raise ProbeError('response_too_large')
                metadata = {name.lower(): value for name, value in response.headers.items()
                            if name.lower() in ('etag', 'x-amz-version-id', 'x-amz-storage-class', 'content-length',
                                                'x-amz-meta-devres-acceptance')}
                if any(len(value) > 8192 for value in metadata.values()):
                    raise ProbeError('response_header_too_large')
                return Response(response.status, metadata, bytes(data))
        except ProbeError:
            raise
        except (OSError, ValueError, HTTPException) as error:
            raise ProbeError('request_uncertain') from error


def load_inputs(path):
    config = json.loads(private_read(path))
    if not isinstance(config, dict) or set(config) != INPUT_FIELDS:
        raise ProbeError('input_paths_invalid')
    pairs = {}
    for role in ROLES:
        values = [private_read(config[role + '_' + kind + '_file']).decode().rstrip('\r\n')
                  for kind in ('access_key', 'secret_key')]
        if any(not value or not value.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in value) for value in values):
            raise ProbeError('credential_file_invalid')
        pairs[role] = values
    if len({values[0] for values in pairs.values()}) != 4:
        raise ProbeError('four_distinct_pairs_required')
    digest = hashlib.sha256(json.dumps(pairs, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return pairs, digest


class Probe:
    def __init__(self, root, clients=None):
        self.root = Path(root).absolute()
        self.clients = clients or {}
        if (Path('/tmp') not in self.root.parents or '..' in self.root.parts
                or any(path.is_symlink() for path in (self.root, *self.root.parents))):
            raise ProbeError('owned_tmp_root_required')

    def load(self):
        info = self.root.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ProbeError('unsafe_state_directory')
        state = json.loads(private_read(self.root / 'state.json', 1024**2))
        token = state.get('run_id', '')
        if (state.get('version') != 1 or not re.fullmatch('[0-9a-f]{24}', token)
                or state.get('prefix') != 'production/.acceptance/' + token
                or set(state.get('keys', {})) != {'conditional', 'multipart'}
                or not 0 <= state.get('bytes_sent', -1) <= MAX_BYTES
                or not isinstance(state.get('events'), list) or len(state['events']) > MAX_REQUESTS):
            raise ProbeError('state_scope_invalid')
        for name, record in state['keys'].items():
            if (record.get('key') != state['prefix'] + '/' + name
                    or not re.fullmatch('[0-9a-f]{64}', record.get('sha256', ''))
                    or not 0 < record.get('bytes', 0) <= MAX_BYTES):
                raise ProbeError('state_scope_invalid')
        for upload in state.get('uploads', []):
            if upload.get('key') not in {value['key'] for value in state['keys'].values()}:
                raise ProbeError('state_scope_invalid')
        return state

    def save(self):
        atomic(self.root / 'state.json', self.state)

    @contextlib.contextmanager
    def exclusive(self):
        info = self.root.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ProbeError('unsafe_state_directory')
        descriptor = os.open(self.root / '.probe.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            lock = os.fstat(descriptor)
            if not stat.S_ISREG(lock.st_mode) or lock.st_uid != os.geteuid() or lock.st_mode & 0o077 or lock.st_nlink != 1:
                raise ProbeError('unsafe_run_lock')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ProbeError('another_probe_operation_is_active') from error
            yield
        finally:
            os.close(descriptor)

    def start(self, credential_binding):
        if self.root.exists():
            raise ProbeError('run_cannot_resume')
        # Parent chain is private until the root-owned sticky /tmp boundary.
        for parent in self.root.parents:
            info = parent.stat()
            if parent == Path('/tmp'):
                if info.st_uid != 0 or not info.st_mode & stat.S_ISVTX:
                    raise ProbeError('unsafe_tmp_boundary')
                break
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ProbeError('unsafe_state_parent')
        self.root.mkdir(mode=0o700)
        token = secrets.token_hex(12)
        prefix = 'production/.acceptance/' + token
        small = ('devres-acceptance:' + token).encode()
        seed = ('multipart-acceptance:' + token).encode()
        large = (seed * (MULTIPART_BYTES // len(seed) + 1))[:MULTIPART_BYTES]
        self.payloads = {'conditional': small, 'multipart': large}
        self.state = {'version': 1, 'run_id': token, 'prefix': prefix, 'phase': 'running',
                      'created_at': datetime.now(timezone.utc).isoformat(), 'credential_binding': credential_binding,
                      'bytes_sent': 0, 'events': [], 'uploads': [], 'checks': {},
                      'keys': {name: {'key': prefix + '/' + name, 'sha256': hashlib.sha256(body).hexdigest(),
                                      'bytes': len(body), 'versions': []} for name, body in self.payloads.items()}}
        self.save()

    def io(self, label, role, method, name=None, *, query=None, body=b'', headers=None, outside=False):
        query = query or {}
        if len(self.state['events']) >= MAX_REQUESTS or self.state['bytes_sent'] + len(body) > MAX_BYTES:
            raise ProbeError('run_budget_exhausted')
        if self.state['phase'] == 'running':
            age = datetime.now(timezone.utc) - datetime.fromisoformat(self.state['created_at'])
            if age.total_seconds() > 8 * 60:
                raise ProbeError('run_deadline_exceeded')
        key = None if name is None else self.state['keys'][name]['key']
        if outside:
            if method != 'GET' or body:
                raise ProbeError('outside_mutation_refused')
            key = 'outside/.acceptance/' + self.state['run_id'] if name else None
        if key is None and (method != 'GET' or query.get('max-keys') != '2'):
            raise ProbeError('unbounded_listing_refused')
        if key is None and query != {'list-type': '2', 'prefix': 'outside/' if outside else self.state['prefix'] + '/', 'max-keys': '2'}:
            raise ProbeError('listing_scope_invalid')
        if 'uploadId' in query and not any(upload['upload_id'] == query['uploadId'] and upload['key'] == key
                                           for upload in self.state['uploads']):
            raise ProbeError('unknown_multipart_identifier')
        if 'versionId' in query and (name is None or query['versionId'] not in self.state['keys'][name]['versions']):
            raise ProbeError('unknown_object_version')
        if method == 'PUT' and 'uploadId' not in query and (headers or {}).get('If-None-Match') != '*':
            raise ProbeError('unconditional_object_put_refused')
        event = {'label': label, 'role': role, 'method': method, 'key': key, 'query': query,
                 'request_bytes': len(body), 'request_sha256': hashlib.sha256(body).hexdigest(), 'phase': 'intent'}
        self.state['events'].append(event)
        self.state['bytes_sent'] += len(body)
        self.save()  # Durable intent and spent budget always precede network I/O.
        try:
            response = self.clients[role].request(method, key, query=query, body=body, headers=headers,
                                                 max_response=MAX_BYTES if method == 'GET' and name and not outside else MAX_XML)
        except Exception:
            event['phase'] = 'uncertain'
            self.state['phase'] = 'failed'
            self.save()
            raise
        event.update(phase='response', status=response.status, headers=response.headers,
                     response_bytes=len(response.body), response_sha256=hashlib.sha256(response.body).hexdigest())
        self.save()
        if method == 'POST' and 'uploads' in query and response.status == 200:
            # Capture even an unexpectedly permitted reader initiation for cleanup.
            identifier = xml_value(response.body, 'UploadId')
            event['upload_id'] = identifier
            self.state['uploads'].append({'key': key, 'upload_id': identifier, 'phase': 'active'})
        version = response.headers.get('x-amz-version-id')
        if name and version and version != 'null' and version not in self.state['keys'][name]['versions']:
            self.state['keys'][name]['versions'].append(version)
        if method == 'DELETE' and 'uploadId' in query and response.status in (200, 204):
            self.upload_phase(query['uploadId'], 'aborted')
        self.save()
        return response

    def upload_phase(self, identifier, phase, **fields):
        for upload in self.state['uploads']:
            if upload['upload_id'] == identifier:
                upload['phase'] = phase
                upload.update(fields)

    def expect(self, response, statuses):
        if response.status not in statuses or (response.status < 300 and response.code is not None):
            raise ProbeError('unexpected_provider_result')
        if response.status == 403 and response.code != 'AccessDenied':
            raise ProbeError('permission_denial_not_established')
        return response

    def readback(self, role, name, label):
        response = self.expect(self.io(label, role, 'GET', name), (200,))
        expected = self.state['keys'][name]
        if len(response.body) != expected['bytes'] or hashlib.sha256(response.body).hexdigest() != expected['sha256']:
            raise ProbeError('object_readback_mismatch')

    def list(self, role, label, outside=False):
        query = {'list-type': '2', 'prefix': 'outside/' if outside else self.state['prefix'] + '/', 'max-keys': '2'}
        response = self.io(label, role, 'GET', query=query, outside=outside)
        if not outside and response.status == 200:
            if len(response.body) > MAX_XML or b'<!DOCTYPE' in response.body.upper() or b'<!ENTITY' in response.body.upper():
                raise ProbeError('listing_xml_invalid')
            try:
                root = ET.fromstring(response.body)
            except ET.ParseError as error:
                raise ProbeError('listing_xml_invalid') from error
            keys = [node.text for node in root.iter() if node.tag.rsplit('}', 1)[-1] == 'Key']
            allowed = {value['key'] for value in self.state['keys'].values()}
            if len(keys) > 2 or not set(keys) <= allowed or self.state['keys']['conditional']['key'] not in keys:
                raise ProbeError('listing_scope_mismatch')
        return response

    def run(self, binding):
        self.start(binding)
        with self.exclusive():
            try:
                self.run_operations()
                self.state['phase'] = 'run_complete'
                self.state['run_outcome'] = 'run_complete'
            except Exception:
                self.state['phase'] = 'failed'
                self.state['run_outcome'] = 'failed'
                self.save()
                raise
            self.save()
        return self.summary()

    def run_operations(self):
        create_headers = {'If-None-Match': '*', 'x-amz-storage-class': 'ONEZONE_IA',
                          'x-amz-meta-devres-acceptance': self.state['run_id']}
        small = self.payloads['conditional']
        self.expect(self.io('writer-conditional-create', 'test_writer', 'PUT', 'conditional', body=small, headers=create_headers), (200,))
        self.expect(self.io('writer-conditional-collision', 'test_writer', 'PUT', 'conditional', body=b'collision', headers=create_headers), (412,))
        self.readback('test_writer', 'conditional', 'writer-conditional-readback')
        head = self.expect(self.io('writer-head', 'test_writer', 'HEAD', 'conditional'), (200,))
        if head.headers.get('x-amz-storage-class') != 'ONEZONE_IA':
            raise ProbeError('storage_class_not_verified')
        self.expect(self.list('test_writer', 'writer-list'), (200,))
        self.state['checks']['writer_read_conditional_put'] = {'passed': True}
        # First owned MPU completes the 17 MiB object; a second uses the same key
        # to prove conditional completion collision and interrupted-upload abort.
        for iteration in ('complete', 'collision'):
            created = self.expect(self.io('multipart-init-' + iteration, 'test_writer', 'POST', 'multipart',
                                         query={'uploads': ''}, headers={key: value for key, value in create_headers.items() if key != 'If-None-Match'}), (200,))
            identifier = xml_value(created.body, 'UploadId')
            uploaded = self.expect(self.io('multipart-part-' + iteration, 'test_writer', 'PUT', 'multipart',
                                          query={'uploadId': identifier, 'partNumber': '1'},
                                          body=self.payloads['multipart'] if iteration == 'complete' else b'x'), (200,))
            etag = uploaded.headers.get('etag')
            if not etag:
                raise ProbeError('multipart_etag_missing')
            self.upload_phase(identifier, 'active', part_etags={'1': etag})
            self.save()
            inspected = self.expect(self.io('multipart-inspect-' + iteration, 'test_writer', 'GET', 'multipart',
                                           query={'uploadId': identifier}), (200,))
            if xml_value(inspected.body, 'ETag') != etag:
                raise ProbeError('multipart_part_identity_mismatch')
            completion = ET.Element('CompleteMultipartUpload')
            part = ET.SubElement(completion, 'Part')
            ET.SubElement(part, 'ETag').text = etag
            ET.SubElement(part, 'PartNumber').text = '1'
            body = ET.tostring(completion)
            if iteration == 'collision':
                self.reader_checks(identifier, body)
            response = self.io('multipart-finish-' + iteration, 'test_writer', 'POST', 'multipart',
                               query={'uploadId': identifier}, body=body, headers={'If-None-Match': '*', 'Content-Type': 'application/xml'})
            self.expect(response, (200,) if iteration == 'complete' else (412,))
            if iteration == 'complete':
                completed_etag = xml_value(response.body, 'ETag')
                self.upload_phase(identifier, 'completed', completed_etag=completed_etag)
                self.save()
                self.readback('test_writer', 'multipart', 'writer-multipart-readback')
                metadata = self.expect(self.io('multipart-storage-class', 'test_writer', 'HEAD', 'multipart'), (200,))
                if metadata.headers.get('x-amz-storage-class') != 'ONEZONE_IA':
                    raise ProbeError('multipart_storage_class_not_verified')
                self.state['checks']['storage_class_onezone_ia'] = {'passed': True}
            else:
                self.expect(self.io('multipart-abort', 'test_writer', 'DELETE', 'multipart', query={'uploadId': identifier}), (204, 200))
                self.readback('test_writer', 'multipart', 'writer-multipart-collision-unchanged')
        self.state['checks']['writer_multipart_complete_abort'] = {'passed': True}
        self.expect(self.io('writer-delete-denied', 'test_writer', 'DELETE', 'conditional'), (403,))
        self.state['checks']['object_deletion_denied'] = {'passed': True}
        versions = self.state['keys']['conditional']['versions']
        if versions:
            for role in ('test_reader', 'test_writer'):
                self.expect(self.io(role + '-version-delete-denied', role, 'DELETE', 'conditional', query={'versionId': versions[0]}), (403,))
            self.state['checks']['version_deletion_denied'] = {'passed': True}
        else:
            self.state['checks']['version_deletion_denied'] = {'passed': False, 'reason': 'no_actual_nonnull_version_id'}
        self.state['checks']['permanent_deletion_denied'] = {'passed': bool(versions),
            'object_deletion_denied': True, 'version_deletion_denied': bool(versions)}
        for role in ('test_reader', 'test_writer'):
            self.expect(self.io(role + '-outside-get', role, 'GET', 'conditional', outside=True), (403,))
            self.expect(self.list(role, role + '-outside-list', outside=True), (403,))
        self.state['checks']['other_prefix_denied'] = {'passed': True}
        self.state['checks']['foreign_bucket_denied'] = {'passed': False, 'reason': 'no_foreign_bucket_authorized'}
        self.state['checks']['administration_denied'] = {'passed': False, 'reason': 'independent_effective_iam_role_review_required'}
        self.state['checks']['source_ip_denial'] = {'passed': False, 'reason': 'no_alternate_egress_probe_authorized'}
        for role in ('current_reader', 'current_writer'):
            self.readback(role, 'conditional', role + '-replacement-read')
            self.expect(self.list(role, role + '-replacement-list'), (200,))
        self.state['checks']['current_pairs_read_list'] = {'passed': True}

    def reader_checks(self, identifier, completion):
        self.readback('test_reader', 'conditional', 'reader-get')
        self.expect(self.io('reader-head', 'test_reader', 'HEAD', 'conditional'), (200,))
        self.expect(self.list('test_reader', 'reader-list'), (200,))
        self.state['checks']['reader_read_list'] = {'passed': True}
        self.expect(self.io('reader-put-denied', 'test_reader', 'PUT', 'conditional', body=b'denied', headers={'If-None-Match': '*'}), (403,))
        self.expect(self.io('reader-delete-denied', 'test_reader', 'DELETE', 'conditional'), (403,))
        self.expect(self.io('reader-init-denied', 'test_reader', 'POST', 'multipart', query={'uploads': ''}), (403,))
        self.expect(self.io('reader-part-denied', 'test_reader', 'PUT', 'multipart',
                            query={'uploadId': identifier, 'partNumber': '2'}, body=b'denied'), (403,))
        self.expect(self.io('reader-complete-denied', 'test_reader', 'POST', 'multipart',
                            query={'uploadId': identifier}, body=completion, headers={'If-None-Match': '*'}), (403,))
        self.expect(self.io('reader-abort-denied', 'test_reader', 'DELETE', 'multipart', query={'uploadId': identifier}), (403,))
        self.state['checks']['reader_mutations_denied'] = {'passed': True}
        self.save()

    def verify_revoked(self, binding):
        with self.exclusive():
            return self._verify_revoked(binding)

    def _verify_revoked(self, binding):
        self.state = self.load()
        if self.state.get('credential_binding') != binding or self.state.get('phase') not in ('run_complete', 'failed'):
            raise ProbeError('finished_matching_run_required')
        if any(event.get('label', '').startswith('post-revoke-') for event in self.state['events']):
            raise ProbeError('revocation_verification_cannot_repeat')
        self.state['phase'] = 'verifying_revocation'
        self.save()
        try:
            for role in ('test_reader', 'test_writer'):
                response = self.io('post-revoke-' + role, role, 'GET', 'conditional')
                if response.status != 403 or response.code not in ('AccessDenied', 'InvalidAccessKeyId'):
                    raise ProbeError('test_key_denial_not_verified')
            for role in ('current_reader', 'current_writer'):
                self.readback(role, 'conditional', 'post-revoke-' + role + '-read')
                self.expect(self.list(role, 'post-revoke-' + role + '-list'), (200,))
            self.state['checks']['test_keys_denied_current_pairs_work'] = {'passed': True,
                'requires_parent_revocation_before_expiry_evidence': True}
            self.state['checks']['rotation_revocation_verified'] = {'passed': False,
                'reason': 'operational_pairs_not_rotated_parent_lifecycle_evidence_required'}
            self.state['phase'] = 'revocation_observed'
        except Exception:
            self.state['phase'] = 'revocation_verification_failed'
            self.save()
            raise
        self.save()
        return self.summary()

    def summary(self):
        return {'version': 1, 'phase': self.state['phase'], 'run_outcome': self.state.get('run_outcome'), 'prefix': self.state['prefix'],
                'keys': self.state['keys'], 'uploads': self.state['uploads'], 'checks': self.state['checks'],
                'uncertain_intents': [{key: event[key] for key in ('label', 'role', 'method', 'key', 'query', 'phase')}
                                      for event in self.state['events'] if event['phase'] in ('intent', 'uncertain')
                                      or (event['method'] == 'POST' and 'uploads' in event['query']
                                          and event.get('status') == 200 and 'upload_id' not in event)],
                'requests_spent': len(self.state['events']), 'bytes_sent': self.state['bytes_sent'],
                'production_receipt_emitted': False, 'cleanup_performed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-root', required=True, type=Path)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('operation', choices=('run', 'verify-revoked', 'status'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ProbeError('root_operator_required')
    probe = Probe(args.state_root)
    if args.operation == 'status':
        probe.state = probe.load()
        result = probe.summary()
    else:
        if args.inputs is None:
            parser.error('--inputs is required for provider requests')
        pairs, binding = load_inputs(args.inputs)
        probe.clients = {role: S3(*pair) for role, pair in pairs.items()}
        result = probe.run(binding) if args.operation == 'run' else probe.verify_revoked(binding)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ProbeError, OSError, ValueError, KeyError, TypeError, UnicodeError):
        print('Static S3 probe stopped; inspect its private journal before further action.', file=sys.stderr)
        raise SystemExit(1) from None
