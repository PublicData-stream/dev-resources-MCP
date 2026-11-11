#!/usr/bin/env python3
"""Verify an owned coordinated snapshot in isolated, disposable ZFS clones.

The caller holds the source snapshots while verification runs and uses the
maintenance lock for snapshot creation and marking only. The capacity guard stays
active during the drill. Only retained RFC/MDN data and attribution notices are read; no provider work occurs.
"""
import hashlib
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import tomllib

HERE = Path(__file__).resolve().parent
PRIVATE = Path('/etc/devres-staging')
DATASET = 'cachepool/devres-staging'
PG = 'postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a'
OLD_SERVER = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:02977361122a11d7f0a9eedea97437b15f2fccc17f82d2331f859d388359179e'
SERVER = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:b317a2c87ea6ce337f7c1a69213eb90c22fde469ac4c73d26d9d5a68e635fff5'
VERSION = '0.1.0-build.78c2e9c5'
# Ten is an offline migration profile; qualified serving/restore is eleven.
PROFILES = {9: (OLD_SERVER, '0.1.0-build.27d35cd6'), 10: (SERVER, VERSION), 11: (SERVER, VERSION)}
ATTRIBUTION = Path('/usr/local/libexec/devres-staging-attribution')
ATTRIBUTION_POLICY = 'devres-attribution-v1:exact-reacquisition:member-scopes:readable-notices'
SOURCE_PREFIX = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/'
COLLECTORS = ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'npm', 'wikipedia')
OWNER_KEY = 'org.publicdata:restore-owner'
LABEL_KEY = 'devres.restore-owner'
TOKEN_RE = re.compile(r'[0-9a-f]{24}\Z')
HASH_RE = re.compile(r'[0-9a-f]{64}\Z')
CONTENT_RE = re.compile(r'(?:blake3:)?[0-9a-f]{64}\Z')
OFFLINE_TIMEOUT_SECONDS = 7 * 24 * 60 * 60
OFFLINE_STOP_SECONDS = 120
OFFLINE_OPTIONS = {'workers': 8, 'payload_budget_mib': 64, 'graph_memory_budget_mib': 1024}
MAX_RESPONSE = 1024 * 1024
MAX_FIXED_BODY = 16 * 1024 * 1024
CLONE_QUOTAS = ('64G', '512G')
REHEARSAL_HEADROOM = 704 * 1024 * 1024 * 1024
# Resource admission is separate from schema/software restore identity. Scratch
# lives inside each worker's memory ceiling, never in addition to it.
RESOURCE_PROFILES = {
    'restore': {'worker_memory': '64g', 'postgres_memory': '2g', 'scratch': '32g',
                'worker_cpus': None, 'postgres_cpus': None, 'postgres_tuned': False,
                'host_memory_guard': False},
    'upgrade': {'worker_memory': '128g', 'postgres_memory': '32g', 'scratch': '32g',
                'worker_cpus': 37, 'postgres_cpus': 2, 'postgres_tuned': True,
                'host_memory_guard': True},
    'direct': {'worker_memory': '192g', 'postgres_memory': '16g', 'scratch': '64g',
               'worker_cpus': 37, 'postgres_cpus': 2, 'postgres_tuned': True,
               'host_memory_guard': True},
}
DIAGNOSTIC_ROOT = Path('/tmp/devres-offline-diagnostics')
DIAGNOSTIC_LOG_BYTES = 64 * 1024
DIAGNOSTIC_LOG_LINES = 64
DIAGNOSTIC_LOG_SECONDS = 3
DIAGNOSTIC_FILE_BYTES = 32 * 1024
DIAGNOSTIC_INSPECT_FORMAT = ('{"owner":{{json (index .Config.Labels "' + LABEL_KEY
    + '")}},"state":{"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}},'
    '"Running":{{json .State.Running}},"ErrorPresent":{{if .State.Error}}true{{else}}false{{end}}}}')
DIAGNOSTIC_PHASES = frozenset({
    'file_qualification', 'sql_qualification', 'capture_replay', 'verification',
    'file_inventory', 'files', 'complete', 'graph_rfc', 'graph_advisory',
    'graph_crate', 'graph_npm', 'graph_mdn', 'graph_whatwg', 'graph_w3c', 'graph_chromium',
    'graph_rfc_indexes', 'graph_npm_rows',
    'graph_crate_artifacts', 'graph_crate_observations', 'graph_crate_staging',
})
DIAGNOSTIC_ERROR_CODES = frozenset({'invalid_input', 'unavailable', 'not_found', 'capacity', 'integrity', 'cancelled'})
# Only exact source-authored reasons become enums. Unknown free-form messages are
# discarded even from private diagnostics; no body/configuration hashes are kept.
DIAGNOSTIC_REASONS = {
    'Durable storage unavailable': 'durable_storage_unavailable',
    'Ambiguous RFC migration identity.': 'rfc_identity_ambiguous',
    'Unresolved RFC migration reference.': 'rfc_reference_unresolved',
    'Unresolved RFC body reference.': 'rfc_body_reference_unresolved',
    'RFC graph migration canceled.': 'rfc_graph_cancelled',
    'RFC corpus representation exceeds limit': 'rfc_corpus_capacity',
    'RFC search index unavailable.': 'rfc_index_unavailable',
    'RFC search index integrity verification failed.': 'rfc_index_integrity',
    'RFC index file limit exceeded.': 'rfc_index_file_capacity',
    'RFC index size limit exceeded.': 'rfc_index_size_capacity',
    'RFC index writer is busy.': 'rfc_index_writer_busy',
    'RFC index document limit exceeded.': 'rfc_index_document_capacity',
    'RFC index manifest exceeds limit.': 'rfc_index_manifest_capacity',
    'RFC searchable text exceeds 16 MiB.': 'rfc_text_capacity',
    'Storage migration canceled.': 'storage_migration_cancelled',
    'Migration mapping integrity failed.': 'migration_mapping_integrity',
}
DIAGNOSTIC_PROGRESS_COUNTS = frozenset({
    'workers', 'payload_budget_bytes', 'admitted', 'completed', 'committed',
    'active_jobs', 'jobs_high_water', 'window_high_water', 'payload_bytes',
    'worker_wait_micros', 'publication_micros',
})
DIAGNOSTIC_GRAPH_COUNTS = frozenset({
    'graph_memory_budget_bytes', 'graph_admitted', 'graph_completed', 'graph_active_jobs',
    'graph_jobs_high_water', 'graph_memory_bytes', 'graph_memory_high_water',
})
DIAGNOSTIC_PROGRESS_TIMES = frozenset({'elapsed_secs', 'phase_elapsed_secs', 'records_per_second'})
RECORD_SQL = "SELECT id, body_hash FROM devres_captures WHERE source_url='https://www.rfc-editor.org/rfc/rfc9000.txt' AND media_type='text/plain' ORDER BY retrieved_at DESC,id LIMIT 1"


class RestoreError(RuntimeError):
    """Fixed diagnostic code; provider content and command stderr stay private."""


def attribution_assets():
    """Read only the parent's fixed, reviewed first-party helper and selector plan."""
    directory = ATTRIBUTION.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700):
        raise RestoreError('unsafe_attribution_directory')
    def read(name, mode, limit):
        descriptor = os.open(ATTRIBUTION / name, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != mode or before.st_size > limit):
                raise RestoreError('unsafe_attribution_asset')
            data = os.read(descriptor, limit + 1)
            after, linked = os.fstat(descriptor), (ATTRIBUTION / name).lstat()
            keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_gid', 'st_mode', 'st_nlink')
            if len(data) != before.st_size or any(getattr(before, key) != getattr(after, key)
                    or getattr(before, key) != getattr(linked, key) for key in keys):
                raise RestoreError('attribution_asset_changed')
            return data
        finally:
            os.close(descriptor)
    raw = read('manifest.json', 0o600, 16384)
    manifest = json.loads(raw)
    if (not isinstance(manifest, dict) or set(manifest) != {'version', 'release', 'server', 'binary_sha256', 'plan_sha256', 'live_acquisition',
                         'maximum_requests', 'retained_verifier_sha256', 'mdn_baseline_sha256'}
            or type(manifest['version']) is not int or manifest['version'] != 1
            or manifest['release'] != VERSION or manifest['server'] != SERVER
            or manifest['live_acquisition'] is not True
            or type(manifest['maximum_requests']) is not int or manifest['maximum_requests'] != 20
            or any(not isinstance(manifest[key], str) or not HASH_RE.fullmatch(manifest[key])
                   for key in ('binary_sha256', 'plan_sha256', 'retained_verifier_sha256', 'mdn_baseline_sha256'))):
        raise RestoreError('attribution_manifest_invalid')
    for name, mode, limit, key in (('repair', 0o755, 256 * 1024 * 1024, 'binary_sha256'),
                                  ('plan.json', 0o600, 512 * 1024, 'plan_sha256'),
                                  ('verify-retained.py', 0o600, 512 * 1024, 'retained_verifier_sha256'),
                                  ('mdn-baseline.json', 0o600, 512 * 1024, 'mdn_baseline_sha256')):
        data = read(name, mode, limit)
        if hashlib.sha256(data).hexdigest() != manifest[key]:
            raise RestoreError('attribution_asset_hash_changed')
    return {**manifest, 'manifest_sha256': hashlib.sha256(raw).hexdigest()}


def attribution_receipt(value, plan_sha256):
    fields = {'version', 'release', 'schema', 'integrity_active', 'scope', 'plan_sha256',
              'policy_epoch', 'policy_fingerprint', 'qualified_targets', 'providers', 'request_attempts',
              'maximum_requests', 'ready', 'notices_verified', 'attribution_storage_verified', 'target_set_digest'}
    if (not isinstance(value, dict) or set(value) != fields
            or type(value['version']) is not int or value['version'] != 1
            or value['release'] != VERSION or type(value['schema']) is not int or value['schema'] != 11
            or value['scope'] != 'fixed_retained_rfc_mdn' or value['plan_sha256'] != plan_sha256
            or type(value['policy_epoch']) is not int or value['policy_epoch'] != 1
            or value['policy_fingerprint'] != ATTRIBUTION_POLICY
            or value['providers'] != ['mdn', 'rfc']
            or type(value['qualified_targets']) is not int or not 2 <= value['qualified_targets'] <= 128
            or type(value['request_attempts']) is not int or not 0 <= value['request_attempts'] <= 20
            or type(value['maximum_requests']) is not int or value['maximum_requests'] != 20
            or any(value[key] is not True for key in ('integrity_active', 'ready', 'notices_verified', 'attribution_storage_verified'))
            or not isinstance(value['target_set_digest'], str)
            or not re.fullmatch(r'blake3:[0-9a-f]{64}', value['target_set_digest'])):
        raise RestoreError('attribution_qualification_receipt_invalid')
    return value


class OfflinePaused(RestoreError):
    """The worker is stopped; its caller must preserve and checkpoint the pair."""

    preserve_checkpoint = True

    def __init__(self, command, command_completed=False):
        super().__init__('offline_command_paused')
        self.command = command
        self.command_completed = command_completed


def execute(args):
    try:
        p = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                           timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RestoreError('restore_command_unavailable_or_timed_out') from error
    if p.returncode:
        raise RestoreError('restore_command_failed')
    if len(p.stdout) > MAX_RESPONSE:
        raise RestoreError('restore_command_output_exceeds_bound')
    return p.stdout.strip()


def bounded_diagnostic_output(arguments, byte_limit, *, timeout_seconds=None, input_data=None):
    """Bound pipe reads before buffering; never echo Docker or application text."""
    if input_data is not None and (not isinstance(input_data, bytes) or len(input_data) > 8192):
        raise RestoreError('invalid_private_helper_input')
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL if input_data is None else subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    captured = bytearray()
    truncated = timed_out = False
    deadline = time.monotonic() + (DIAGNOSTIC_LOG_SECONDS if timeout_seconds is None else timeout_seconds)
    try:
        if input_data is not None:
            process.stdin.write(input_data)
            process.stdin.close()
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not ready.select(remaining):
                    timed_out = True
                    break
                data = os.read(process.stdout.fileno(), min(8192, byte_limit + 1 - len(captured)))
                if not data:
                    break
                captured.extend(data)
                if len(captured) > byte_limit:
                    truncated = True
                    break
    finally:
        # No follow mode is used. Kill/reap only this newly owned Docker client
        # on a full pipe or timeout; worker removal remains the caller's finally.
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=1)
        finally:
            process.stdout.close()
    return {'data': bytes(captured[:byte_limit]),
            'truncated': truncated, 'timed_out': timed_out, 'returncode': process.returncode}


def verify_notice_roundtrip(attribution, read):
    """Read complete fixed notice resources with exact identity and byte offsets."""
    if (not isinstance(attribution, dict) or attribution.get('status') != 'ready'
            or type(attribution.get('policy_epoch')) is not int or attribution['policy_epoch'] != 1
            or attribution.get('policy_fingerprint') != ATTRIBUTION_POLICY):
        raise RestoreError('restored_attribution_missing')
    generations = attribution.get('generations')
    uris = attribution.get('resource_uris')
    if (not isinstance(generations, list) or not 1 <= len(generations) <= 128
            or not isinstance(uris, list) or len(uris) != len(generations)
            or any(not isinstance(uri, str) for uri in uris)
            or len(set(uris)) != len(uris) or attribution.get('resource_uri') != uris[0]):
        raise RestoreError('restored_attribution_identity_invalid')
    complete, seen = [], set()
    for generation, uri in zip(generations, uris):
        if (not isinstance(generation, dict) or not isinstance(uri, str)
                or not re.fullmatch(r'devres://attribution/blake3:[0-9a-f]{64}', uri)
                or generation.get('id') != uri.removeprefix('devres://attribution/')
                or not isinstance(generation.get('subject'), dict)
                or not isinstance(generation.get('notices'), list) or not generation['notices']):
            raise RestoreError('restored_attribution_identity_invalid')
        expected, local_seen = [], set()
        for notice in generation['notices']:
            if (not isinstance(notice, dict) or not isinstance(notice.get('source_url'), str)
                    or not isinstance(notice.get('text'), str) or not notice['text']):
                raise RestoreError('restored_attribution_notice_invalid')
            text = notice['source_url'] + '\n' + notice['text']
            if text not in local_seen:
                expected.append(text)
                local_seen.add(text)
            if text not in seen:
                complete.append(text)
                seen.add(text)
        expected_text = '\n\n'.join(expected)
        if len(expected_text.encode()) > 4 * 1024 * 1024:
            raise RestoreError('restored_attribution_notice_exceeds_bound')
        offset, chunks, total = 0, [], None
        for _ in range(129):
            result = read(uri + '?offset=' + str(offset) + '&limit=32768')
            items = result.get('contents')
            if not isinstance(items, list) or len(items) != 1:
                raise RestoreError('restored_attribution_readback_failed')
            item = items[0]
            metadata = item.get('_meta', {})
            identity = metadata.get('attribution', {})
            text, length, next_offset = item.get('text'), metadata.get('total_bytes'), metadata.get('next_offset')
            if (item.get('uri') != uri or item.get('mimeType') != 'text/plain'
                    or identity.get('id') != generation['id'] or identity.get('subject') != generation['subject']
                    or type(identity.get('policy_epoch')) is not int or identity['policy_epoch'] != 1
                    or type(metadata.get('offset')) is not int or metadata['offset'] != offset
                    or type(length) is not int or not 1 <= length <= 4 * 1024 * 1024
                    or (total is not None and total != length) or not isinstance(text, str) or not text
                    or len(text.encode()) > 32768):
                raise RestoreError('restored_attribution_readback_failed')
            total = length
            end = offset + len(text.encode())
            if end > total or (next_offset is None and end != total) or (next_offset is not None
                    and (type(next_offset) is not int or next_offset != end or not offset < next_offset < total)):
                raise RestoreError('restored_attribution_pagination_invalid')
            chunks.append(text)
            if next_offset is None:
                if ''.join(chunks) != expected_text:
                    raise RestoreError('restored_attribution_readback_failed')
                break
            offset = next_offset
        else:
            raise RestoreError('restored_attribution_notice_exceeds_bound')
    if attribution.get('readable_notice') != '\n\n'.join(complete):
        raise RestoreError('restored_attribution_readback_failed')
    return True


def diagnostic_container_name(name):
    if not re.fullmatch(r'devres-staging-restore-[0-9a-f]{24}-offline-[1-9][0-9]{0,7}', name):
        raise RestoreError('invalid_diagnostic_container')
    return name


def read_terminal_logs(name):
    return bounded_diagnostic_output(
        ['docker', 'logs', '--tail', str(DIAGNOSTIC_LOG_LINES), diagnostic_container_name(name)],
        DIAGNOSTIC_LOG_BYTES)


def inspect_offline_failure(name):
    # Select only ownership and fixed state fields. State.Error is never fetched
    # as text, and even this small response has an execution and pipe byte cap.
    result = bounded_diagnostic_output(
        ['docker', 'inspect', '--format', DIAGNOSTIC_INSPECT_FORMAT, diagnostic_container_name(name)], 4096)
    if result['truncated'] or result['timed_out']:
        raise RestoreError('offline_diagnostic_inspect_unavailable')
    return json.loads(result['data'])


def diagnostic_terminal(logs):
    """Keep typed progress and error enums only; free-form log bytes die here."""
    data = logs['data']
    if not isinstance(data, bytes) or len(data) > DIAGNOSTIC_LOG_BYTES:
        raise RestoreError('invalid_diagnostic_log_bound')
    events, dropped = [], 0
    lines = data.splitlines()[-DIAGNOSTIC_LOG_LINES:]
    progress_keys = {'event', 'phase'} | DIAGNOSTIC_PROGRESS_COUNTS | DIAGNOSTIC_PROGRESS_TIMES
    for raw in lines:
        line = raw.decode('utf-8', errors='replace')
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            value = None
        counts = DIAGNOSTIC_PROGRESS_COUNTS
        if isinstance(value, dict) and set(value) == progress_keys | DIAGNOSTIC_GRAPH_COUNTS:
            counts |= DIAGNOSTIC_GRAPH_COUNTS
        if (isinstance(value, dict) and set(value) == {'event', 'phase'} | counts | DIAGNOSTIC_PROGRESS_TIMES
                and value['event'] == 'offline_storage_progress'
                and type(value['phase']) is str and value['phase'] in DIAGNOSTIC_PHASES
                and all(type(value[key]) is int and 0 <= value[key] <= 2**64 - 1
                        for key in counts)
                and 1 <= value['workers'] <= 64 and value['payload_budget_bytes'] > 0
                and ('graph_memory_budget_bytes' not in value or value['graph_memory_budget_bytes'] > 0)
                and all(type(value[key]) in (int, float) and 0 <= value[key] <= 1e18
                        and math.isfinite(value[key]) for key in DIAGNOSTIC_PROGRESS_TIMES)):
            events.append(value)
            continue
        match = re.fullmatch(r'Error: Error \{ code: ("(?:[^"\\]|\\.)*"), message: ("(?:[^"\\]|\\.)*") \}', line)
        if match:
            try:
                code, message = (json.loads(part) for part in match.groups())
            except ValueError:
                code = message = None
            if code in DIAGNOSTIC_ERROR_CODES:
                events.append({'event': 'application_error', 'code': code,
                               'reason': DIAGNOSTIC_REASONS.get(message, 'unrecognized_message')})
                continue
        dropped += 1
    return {'captured_bytes': len(data), 'truncated': logs['truncated'] is True,
            'timed_out': logs['timed_out'] is True, 'dropped_lines': dropped,
            'raw_logs_retained': False, 'events': events[-16:]}


def write_private_diagnostic(root, filename, value, *, owner_uid=0):
    """Exclusive, bounded, root-private /tmp output; owner override is for fixtures."""
    root = Path(root)
    if (not root.is_absolute() or Path('/tmp') not in root.parents or '..' in root.parts
            or not re.fullmatch(r'[0-9a-f]{24}-offline-[1-9][0-9]{0,7}\.json', filename)
            or os.geteuid() != owner_uid):
        raise RestoreError('unsafe_diagnostic_destination')
    data = (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()
    if len(data) > DIAGNOSTIC_FILE_BYTES:
        raise RestoreError('diagnostic_artifact_exceeds_bound')
    directory = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in root.parts[2:]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid
                    or stat.S_IMODE(info.st_mode) != 0o700):
                os.close(child)
                raise RestoreError('unsafe_diagnostic_directory')
            os.close(directory)
            directory = child
        # Never delete prior diagnostics to make room for a new one.
        with os.scandir(directory) as entries:
            for count, _ in enumerate(entries, 1):
                if count >= 64:
                    raise RestoreError('diagnostic_directory_capacity')
        descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise RestoreError('unsafe_diagnostic_artifact')
            with os.fdopen(descriptor, 'wb', closefd=False) as output:
                output.write(data)
                output.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)
    finally:
        os.close(directory)


def validate_snapshot(value):
    spec = importlib.util.spec_from_file_location('devres_restore_maintenance', HERE / 'maintenance.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.snapshot_name(value)
    except module.MaintenanceError as error:
        raise RestoreError('invalid_snapshot_name') from error


def paused_config(text):
    """Change only the eight scheduling booleans; retain all runtime identity."""
    before = tomllib.loads(text)
    if before.get('storage', {}).get('backend', 'filesystem') != 'filesystem' or 's3' in before.get('storage', {}):
        raise RestoreError('filesystem_restore_does_not_support_s3')
    if any(not isinstance(before.get(c, {}).get('enabled'), bool) for c in COLLECTORS):
        raise RestoreError('explicit_collector_configuration_required')
    changed = text
    for collector in COLLECTORS:
        pattern = (r'(?ms)(^\[' + re.escape(collector) + r'\][ \t]*\n)'
                   r'((?:(?!^\[).)*?)(^enabled[ \t]*=[ \t]*)(?:true|false)([ \t]*(?:#.*)?$)')
        changed, count = re.subn(pattern, lambda m: m[1] + m[2] + m[3] + 'false' + m[4], changed)
        if count != 1:
            raise RestoreError('collector_configuration_layout_changed')
    after = tomllib.loads(changed)
    expected = json.loads(json.dumps(before))
    for c in COLLECTORS:
        expected[c]['enabled'] = False
    if after != expected:
        raise RestoreError('unexpected_restore_configuration_change')
    return changed


def blob_path(root, value):
    if not CONTENT_RE.fullmatch(value):
        raise RestoreError('invalid_capture_hash')
    root = Path(root)
    path = root / 'blake3' / value[7:] if value.startswith('blake3:') else root / value
    for parent in (root, path.parent):
        try:
            info = parent.lstat()
        except OSError as error:
            raise RestoreError('capture_blob_unavailable') from error
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RestoreError('capture_blob_unavailable')
    return path


def open_blob(root, value):
    path = blob_path(root, value)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise RestoreError('capture_blob_unavailable') from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RestoreError('capture_blob_not_regular')
        if not 0 < info.st_size <= MAX_FIXED_BODY:
            raise RestoreError('fixed_capture_size_exceeds_bound')
        return fd, info.st_size
    except BaseException:
        os.close(fd)
        raise


def hash_blob(root, value, *, integrity_verified=False):
    # Tagged BLAKE3 and legacy independent descriptors are verified by the exact
    # published target binary, avoiding a second cryptography implementation here.
    if value.startswith('blake3:') and not integrity_verified:
        raise RestoreError('independent_integrity_verification_required')
    fd, size = open_blob(root, value)
    try:
        if value.startswith('blake3:'):
            return size
        digest = hashlib.sha256()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            while part := stream.read(1024 * 1024):
                digest.update(part)
        if digest.hexdigest() != value:
            raise RestoreError('capture_blob_hash_mismatch')
        return size
    finally:
        os.close(fd)


def rpc(ip, method, params, private=PRIVATE):
    """One modern stateless RPC over the production backend mTLS contract."""
    context = ssl.create_default_context(cafile=Path(private) / 'backend-ca.pem')
    context.load_cert_chain(Path(private) / 'edge-client.pem', Path(private) / 'edge-client-key.pem')
    params = dict(params)
    params['_meta'] = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                       'io.modelcontextprotocol/clientInfo': {'name': 'devres-restore', 'version': '1'},
                       'io.modelcontextprotocol/clientCapabilities': {}}
    headers = {'Host': 'devres-k8s:30081', 'Content-Type': 'application/json',
               'Accept': 'application/json, text/event-stream',
               'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method}
    if 'name' in params:
        headers['Mcp-Name'] = params['name']
    elif 'uri' in params:
        headers['Mcp-Name'] = params['uri']
    connection = http.client.HTTPConnection('devres-k8s', 30081, timeout=10)
    try:
        connection.sock = context.wrap_socket(socket.create_connection((ip, 8080), timeout=10),
                                              server_hostname='devres-k8s')
        connection.request('POST', '/mcp', json.dumps({'jsonrpc': '2.0', 'id': 1,
                                                       'method': method, 'params': params}), headers)
        response = connection.getresponse()
        if response.status != 200:
            raise RestoreError('restored_rpc_http_failure')
        if response.getheader('content-type', '').startswith('text/event-stream'):
            remaining = MAX_RESPONSE
            value = None
            while remaining > 0:
                line = response.readline(remaining + 1)
                remaining -= len(line)
                if remaining < 0:
                    raise RestoreError('restored_rpc_output_exceeds_bound')
                if not line:
                    break
                if line.startswith(b'data:'):
                    candidate = json.loads(line[5:].strip())
                    if candidate.get('id') == 1:
                        value = candidate
                        break
        else:
            body = response.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise RestoreError('restored_rpc_output_exceeds_bound')
            value = json.loads(body)
        if not isinstance(value, dict) or 'error' in value or 'result' not in value:
            raise RestoreError('restored_rpc_rejected')
        return value['result']
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise RestoreError('restored_rpc_unavailable') from error
    finally:
        connection.close()


class Drill:
    def __init__(self, snapshot, run=execute, root=None, private=PRIVATE,
                 token=None, sleep=time.sleep, call=rpc, server=None, schema=None,
                 config_text=None, source_dataset=None, clone_quota='64G', resource_profile='restore',
                 diagnostic_root=DIAGNOSTIC_ROOT, log_reader=read_terminal_logs,
                 diagnostic_writer=write_private_diagnostic, diagnostic_inspector=inspect_offline_failure):
        if type(clone_quota) is not str or clone_quota not in CLONE_QUOTAS:
            raise RestoreError('invalid_restore_clone_quota')
        if type(resource_profile) is not str or resource_profile not in RESOURCE_PROFILES:
            raise RestoreError('invalid_restore_resource_profile')
        self.resource_profile = resource_profile
        self.diagnostic_root, self.log_reader = Path(diagnostic_root), log_reader
        self.diagnostic_writer, self.diagnostic_inspector = diagnostic_writer, diagnostic_inspector
        self.last_offline_diagnostic = None
        self.clone_quota = clone_quota
        self.snapshot = validate_snapshot(snapshot)
        if schema is not None and (type(schema) is not int or schema not in PROFILES):
            raise RestoreError('restored_schema_mismatch')
        if server is not None and server not in (OLD_SERVER, SERVER):
            raise RestoreError('unreviewed_restore_image')
        if server is not None and schema is not None and server != PROFILES[schema][0]:
            raise RestoreError('restore_profile_mismatch')
        self.server, self.schema, self.config_text = server, schema, config_text
        self.run, self.private, self.sleep, self.call = run, Path(private), sleep, call
        self.token = token or secrets.token_hex(12)
        if not TOKEN_RE.fullmatch(self.token):
            raise RestoreError('invalid_restore_token')
        self.name = 'devres-staging-restore-' + self.token
        self.dataset = 'cachepool/' + self.name
        self.source_dataset = DATASET if source_dataset is None else source_dataset
        if (self.source_dataset != DATASET
                and not re.fullmatch(r'cachepool/devres-staging-restore-[0-9a-f]{24}', self.source_dataset)):
            raise RestoreError('unsafe_restore_source_dataset')
        if self.source_dataset == self.dataset:
            raise RestoreError('restore_source_matches_destination')
        self.root = Path(root) if root is not None else Path('/tmp') / self.name
        if not self.root.is_absolute() or self.root == Path('/tmp') or Path('/tmp') not in self.root.parents:
            raise RestoreError('restore_path_must_be_below_tmp')
        self.datasets = []
        self.containers = []
        self.network = False
        self.runtime_owned = False
        self.postgres_started = False
        self.offline_sequence = 0
        self.offline_options = dict(OFFLINE_OPTIONS)
        self.backend_started = False

    def owned(self, dataset):
        if dataset not in (self.dataset, self.dataset + '/postgres', self.dataset + '/evidence'):
            raise RestoreError('unsafe_restore_dataset')
        if self.run(['zfs', 'get', '-H', '-o', 'value', OWNER_KEY, dataset]) != self.token:
            raise RestoreError('restore_dataset_ownership_changed')

    def prepare(self):
        # Validate the backend before creating any clone, network or directory.
        selected = self.config_text if self.config_text is not None else (self.private / 'backend.toml').read_text()
        parsed = tomllib.loads(selected)
        if parsed.get('storage', {}).get('backend', 'filesystem') != 'filesystem' or 's3' in parsed.get('storage', {}):
            raise RestoreError('filesystem_restore_does_not_support_s3')
        if self.clone_quota == '512G':
            # This finite profile belongs only to the main migration rehearsal.
            # Leave room for its ordinary nested restore and the existing pool
            # reserve before creating even the temporary runtime directory.
            available = self.run(['zpool', 'list', '-Hp', '-o', 'free',
                                  DATASET.split('/', 1)[0]])
            if (not isinstance(available, str)
                    or not re.fullmatch(r'[0-9]{1,20}', available.strip())):
                raise RestoreError('restore_clone_headroom_unavailable')
            free = int(available.strip())
            if free > 2**64 - 1:
                raise RestoreError('restore_clone_headroom_unavailable')
            if free < REHEARSAL_HEADROOM:
                raise RestoreError('restore_clone_headroom_insufficient')
        if self.source_dataset != DATASET:
            source_owner = self.source_dataset.rsplit('-', 1)[1]
            for child in ('', '/postgres', '/evidence'):
                if self.run(['zfs', 'get', '-H', '-o', 'value', OWNER_KEY,
                             self.source_dataset + child]).strip() != source_owner:
                    raise RestoreError('restore_source_ownership_changed')
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        marker = self.root / 'owner'
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write(self.token)
        self.runtime_owned = True
        self.datasets.append(self.dataset)
        self.run(['zfs', 'create', '-o', OWNER_KEY + '=' + self.token,
                  '-o', 'mountpoint=none', '-o', 'canmount=off', '-o', 'quota=' + self.clone_quota,
                  '-o', 'exec=off', '-o', 'setuid=off', '-o', 'devices=off', self.dataset])
        for child in ('postgres', 'evidence'):
            self.datasets.append(self.dataset + '/' + child)
            self.run(['zfs', 'clone', '-o', OWNER_KEY + '=' + self.token,
                      '-o', 'mountpoint=' + str(self.root / child), '-o', 'canmount=on',
                      self.source_dataset + '/' + child + '@' + self.snapshot, self.dataset + '/' + child])
        self.network = True
        self.run(['docker', 'network', 'create', '--internal', '--label', LABEL_KEY + '=' + self.token, self.name])
        for folder in ('config', 'tls'):
            path = self.root / folder
            path.mkdir(mode=0o750)
            os.chmod(path, 0o750)
            os.chown(path, 0, 65532)
        config = paused_config(self.config_text if self.config_text is not None
                               else (self.private / 'backend.toml').read_text())
        # Keep PostgreSQL alias/credentials and all transport identity unchanged.
        parsed = tomllib.loads(config)
        if not re.fullmatch(r'postgres://devres:[0-9a-f]+@postgres:5432/devres', parsed['storage']['database_url']):
            raise RestoreError('unexpected_private_database_authority')
        (self.root / 'config/backend.toml').write_text(config)
        os.chown(self.root / 'config/backend.toml', 0, 65532)
        os.chmod(self.root / 'config/backend.toml', 0o640)
        for name in ('backend.pem', 'backend-key.pem', 'client-ca.pem'):
            path = self.root / 'tls' / name
            shutil.copyfile(self.private / name, path)
            os.chown(path, 0, 65532)
            os.chmod(path, 0o640)

    def docker_run(self, role, image, args):
        name = self.name + '-' + role
        self.containers.append(name)
        self.run(['docker', 'run', '-d', '--name', name, '--label', LABEL_KEY + '=' + self.token,
                  '--network', self.name, '--network-alias', role, '--read-only',
                  '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128',
                  *args, image, *([] if role == 'postgres' else ['/etc/devres/config/backend.toml'])])
        return name

    def psql(self, query):
        return self.run(['docker', 'exec', self.name + '-postgres', 'psql', '-X', '-A', '-t',
                         '-F', '\t', '-h', '/tmp', '-U', 'devres_admin', '-d', 'devres', '-v', 'ON_ERROR_STOP=1', '-c', query])

    def start_postgres(self):
        if not self.runtime_owned or self.postgres_started:
            raise RestoreError('restore_postgres_state_invalid')
        resources = RESOURCE_PROFILES[self.resource_profile]
        if resources['host_memory_guard']:
            self.require_memory_headroom()
        pg = self.name + '-postgres'
        self.containers.append(pg)
        self.run(['docker', 'run', '-d', '--name', pg, '--label', LABEL_KEY + '=' + self.token,
                  '--network', self.name, '--network-alias', 'postgres', '--read-only',
                  '--user', '999:999', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                  '--pids-limit=128',
                  *(['--cpus=' + str(resources['postgres_cpus'])] if resources['postgres_cpus'] is not None else []),
                  '--memory=' + resources['postgres_memory'], '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,uid=999,gid=999',
                  '-v', str(self.root / 'postgres') + ':/var/lib/postgresql',
                  '--entrypoint', 'postgres', PG, '-D', '/var/lib/postgresql/18/docker',
                  '-c', 'listen_addresses=*', '-c', 'unix_socket_directories=/tmp',
                  *(['-c', 'shared_buffers=8GB', '-c', 'effective_cache_size=128GB',
                     '-c', 'maintenance_work_mem=2GB', '-c', 'max_wal_size=16GB',
                     '-c', 'checkpoint_timeout=15min', '-c', 'wal_compression=on',
                     '-c', 'fsync=on', '-c', 'full_page_writes=on', '-c', 'synchronous_commit=on']
                    if resources['postgres_tuned'] else [])])
        for attempt in range(60):
            try:
                self.run(['docker', 'exec', pg, 'pg_isready', '-h', '127.0.0.1', '-U', 'devres_admin', '-d', 'devres'])
                break
            except RestoreError:
                if attempt == 59:
                    raise RestoreError('restored_postgres_not_ready')
                self.sleep(1)
        self.postgres_started = True

    def backend_args(self, memory='16g', scratch='1g'):
        return ['--user', '65532:65532', '--memory=' + memory,
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=' + scratch + ',uid=65532,gid=65532',
                '-v', str(self.root / 'evidence') + ':/data',
                '-v', str(self.root / 'config') + ':/etc/devres/config:ro',
                '-v', str(self.root / 'tls') + ':/etc/devres/tls:ro']

    def capture_offline_failure(self, command, name, state, error):
        """Best effort only; never expose private paths or free-form failure text."""
        self.last_offline_diagnostic = 'unavailable'
        try:
            inspected = self.diagnostic_inspector(name)
            if not isinstance(inspected, dict) or inspected.get('owner') != self.token:
                return
            current = inspected.get('state')
            if not isinstance(current, dict):
                return
            exit_code = current.get('ExitCode')
            engine_error = state.get('Error') if isinstance(state, dict) else None
            engine_error = engine_error if isinstance(engine_error, str) else None
            failures = {'offline_command_failed', 'offline_command_timed_out',
                        'host_memory_headroom_insufficient', 'host_memory_headroom_unavailable',
                        'restore_command_failed', 'restore_command_unavailable_or_timed_out',
                        'restore_command_output_exceeds_bound'}
            failure = str(error) if isinstance(error, RestoreError) else None
            value = {'version': 1, 'command': command, 'server': SERVER,
                     'failure_code': failure if failure in failures else 'offline_execution_failed',
                     'resource_profile': self.resource_profile, 'owner_token': self.token,
                     'worker_sequence': self.offline_sequence,
                     'exit_code': exit_code if type(exit_code) is int and -2**31 <= exit_code < 2**31 else None,
                     'oom_killed': current.get('OOMKilled') if type(current.get('OOMKilled')) is bool else None,
                     'running': current.get('Running') if type(current.get('Running')) is bool else None,
                     'engine_error_present': current.get('ErrorPresent') if type(current.get('ErrorPresent')) is bool else None,
                     'engine_error_class': {'': 'none', 'context deadline exceeded': 'deadline_exceeded',
                                            'permission denied': 'permission_denied'}.get(engine_error,
                                                'unrecognized' if current.get('ErrorPresent') else 'none')}
            try:
                value['terminal'] = diagnostic_terminal(self.log_reader(name))
            except Exception:
                value['terminal'] = {'unavailable': True, 'raw_logs_retained': False}
            filename = self.token + '-offline-' + str(self.offline_sequence) + '.json'
            self.diagnostic_writer(self.diagnostic_root, filename, value)
            self.last_offline_diagnostic = 'saved'
        except Exception:
            # Diagnostics must not mask the original failure or suppress cleanup.
            pass

    def pause_offline(self, command, name, state):
        """Signal only the owned worker, then prove cooperative termination."""
        found = json.loads(self.run(['docker', 'inspect', name]))
        if (not isinstance(found, list) or len(found) != 1 or not isinstance(found[0], dict)
                or found[0].get('Config', {}).get('Labels', {}).get(LABEL_KEY) != self.token
                or not isinstance(found[0].get('Id'), str) or not HASH_RE.fullmatch(found[0]['Id'])
                or found[0].get('Name') != '/' + name):
            raise RestoreError('offline_worker_owner_changed')
        identifier = found[0]['Id']
        completed = state.get('Running') is False and state.get('ExitCode') == 0
        if state.get('Running') is True:
            try:
                self.run(['docker', 'kill', '--signal=SIGTERM', identifier])
            except Exception:
                # The worker may finish between inspection and signalling.
                # A successful stopped command remains a checkpoint boundary;
                # a failed or still-running command must retain normal failure.
                state = json.loads(self.run(['docker', 'inspect', '--format', '{{json .State}}', identifier]))
                if state.get('Running') is not False or state.get('ExitCode') != 0:
                    raise
                completed = True
            started = time.monotonic()
            for attempt in range(OFFLINE_STOP_SECONDS + 1):
                state = json.loads(self.run(['docker', 'inspect', '--format', '{{json .State}}', identifier]))
                if state.get('Running') is False:
                    break
                if time.monotonic() - started >= OFFLINE_STOP_SECONDS or attempt >= OFFLINE_STOP_SECONDS:
                    raise RestoreError('offline_cooperative_stop_unconfirmed')
                self.sleep(1)
        if (state.get('Running') is not False or state.get('OOMKilled') is True
                or type(state.get('ExitCode')) is not int or state['ExitCode'] not in (0, 1)
                or state.get('Error')):
            raise RestoreError('offline_cooperative_stop_unconfirmed')
        return completed, identifier

    def offline(self, command, target=SERVER, timeout=OFFLINE_TIMEOUT_SECONDS, control=None):
        """Run one reviewed offline command; stop/remove its writer on every exit."""
        if command not in ('migrate-storage', 'verify-storage', 'activate-storage') or target != SERVER:
            raise RestoreError('invalid_offline_command_or_image')
        if type(timeout) not in (int, float) or not 0 < timeout <= OFFLINE_TIMEOUT_SECONDS:
            raise RestoreError('invalid_offline_timeout')
        if control is not None and not callable(control):
            raise RestoreError('invalid_offline_control')
        if (not self.postgres_started or self.backend_started
                or any(name.startswith(self.name + '-offline-') for name in self.containers)):
            raise RestoreError('offline_writer_exclusion_required')
        resources = RESOURCE_PROFILES[self.resource_profile]
        if resources['host_memory_guard']:
            self.require_memory_headroom()
        self.offline_sequence += 1
        name = self.name + '-offline-' + str(self.offline_sequence)
        self.containers.append(name)
        args = [command, '/etc/devres/config/backend.toml']
        if command == 'migrate-storage':
            args.extend(['--to', 'blake3'])
        for option, value in self.offline_options.items():
            args.extend(['--' + option.replace('_', '-'), str(value)])
        state = None
        paused = False
        cleanup_allowed = True
        cleanup_target = name
        try:
            self.run(['docker', 'run', '-d', '--name', name, '--label', LABEL_KEY + '=' + self.token,
                      '--network', self.name, '--read-only', '--cap-drop=ALL',
                      '--security-opt=no-new-privileges', '--pids-limit=128',
                      *(['--cpus=' + str(resources['worker_cpus'])] if resources['worker_cpus'] is not None else []),
                      *self.backend_args(memory=resources['worker_memory'], scratch=resources['scratch']), '--entrypoint', '/usr/local/bin/devres-server', target, *args])
            # Count bounded polling intervals too, so injectable test clocks do
            # not turn a stalled command into an unbounded loop.
            started = time.monotonic()
            for attempt in range(int(timeout) + 1):
                if resources['host_memory_guard']:
                    self.require_memory_headroom()
                state = json.loads(self.run(['docker', 'inspect', '--format', '{{json .State}}', name]))
                if not state.get('Running') and state.get('ExitCode') != 0:
                    raise RestoreError('offline_command_failed')
                if control is not None and control(self, command, name) is True:
                    completed, cleanup_target = self.pause_offline(command, name, state)
                    paused = True
                    raise OfflinePaused(command, command_completed=completed)
                if not state.get('Running'):
                    return {'command': command, 'completed': True}
                if time.monotonic() - started >= timeout or attempt >= timeout:
                    raise RestoreError('offline_command_timed_out')
                self.sleep(min(1, timeout))
            raise RestoreError('offline_command_timed_out')
        except OfflinePaused:
            raise
        except Exception as error:
            if isinstance(error, RestoreError) and str(error) == 'offline_worker_owner_changed':
                # Latch writer exclusion until the owner mismatch is resolved;
                # even failure cleanup must not signal another owner's worker.
                cleanup_allowed = False
            self.capture_offline_failure(command, name, state, error)
            raise
        finally:
            # Docker removal waits for container termination before dropping the
            # writer; failed cleanup deliberately prevents the next command.
            if cleanup_allowed:
                self.run(['docker', 'rm', *([] if paused else ['-f']), cleanup_target])
                self.containers.remove(name)

    @staticmethod
    def require_memory_headroom():
        values = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, _, value = line.partition(':')
            if key == 'MemAvailable':
                fields = value.split()
                if len(fields) != 2 or fields[1] != 'kB' or not fields[0].isdigit():
                    raise RestoreError('host_memory_headroom_unavailable')
                values[key] = int(fields[0]) * 1024
        if values.get('MemAvailable', 0) < 32 * 1024**3:
            raise RestoreError('host_memory_headroom_insufficient')

    def select_profile(self, schema):
        server, version = PROFILES[schema]
        if self.server is not None and self.server != server:
            raise RestoreError('restore_profile_mismatch')
        source = SOURCE_PREFIX + version + '/source.tar.gz'
        path = self.root / 'config/backend.toml'
        text = path.read_text()
        before = tomllib.loads(text)
        pattern = r'(?ms)(^\[source\][ \t]*\n)((?:(?!^\[).)*?)(^url[ \t]*=[ \t]*)[^\n]*$'
        changed, count = re.subn(pattern, lambda m: m[1] + m[2] + m[3] + json.dumps(source), text)
        after = tomllib.loads(changed)
        before.setdefault('source', {})['url'] = source
        if count != 1 or before != after:
            raise RestoreError('restore_source_configuration_invalid')
        path.write_text(changed)
        return server, version, source

    def check(self, prepared=False, timeout=OFFLINE_TIMEOUT_SECONDS):
        if not prepared:
            self.prepare()
            self.start_postgres()
        elif not self.postgres_started:
            raise RestoreError('restore_postgres_state_invalid')
        actual = self.psql('SELECT version FROM devres_schema WHERE singleton')
        expected = 11 if self.schema == 10 else self.schema
        if actual not in ('9', '11') or (expected is not None and str(expected) != actual):
            raise RestoreError('restored_schema_mismatch')
        schema = int(actual)
        server, version, source = self.select_profile(schema)
        if schema == 11:
            if self.psql('SELECT active FROM devres_integrity_control WHERE singleton') != 't':
                raise RestoreError('restored_integrity_not_active')
            self.offline('verify-storage', timeout=timeout)
        count = self.psql('SELECT count(*) FROM devres_captures')
        if not count.isdigit() or int(count) < 1:
            raise RestoreError('real_capture_required')
        row = self.psql(RECORD_SQL).split('\t')
        identity_pattern = HASH_RE if schema == 9 else CONTENT_RE
        if len(row) != 2 or not all(identity_pattern.fullmatch(v) for v in row):
            raise RestoreError('retained_fixed_rfc_required')
        capture, body_hash = row
        blob_root = self.root / 'evidence/blobs'
        size = hash_blob(blob_root, body_hash, integrity_verified=schema == 11)
        backend = self.docker_run('backend', server, self.backend_args('4g'))
        self.backend_started = True
        info = json.loads(self.run(['docker', 'inspect', backend]))[0]
        ip = info['NetworkSettings']['Networks'][self.name]['IPAddress']
        for attempt in range(60):
            try:
                result = self.call(ip, 'tools/call', {'name': 'server.info', 'arguments': {}}, self.private)
                identity = result.get('structuredContent', {})
                if (result.get('isError') or identity.get('product') != 'dev-resources-MCP'
                        or identity.get('version') != version or identity.get('sourceUrl') != source):
                    raise RestoreError('restored_identity_mismatch')
                break
            except RestoreError:
                if attempt == 59:
                    raise RestoreError('restored_backend_not_ready')
                self.sleep(1)
        resource = self.call(ip, 'resources/read', {'uri': 'devres://capture/' + capture}, self.private)
        contents = resource.get('contents', [])
        if not contents or not isinstance(contents[0].get('text'), str) or not contents[0]['text']:
            raise RestoreError('restored_capture_read_failed')
        page = contents[0]['text'].encode('utf-8')
        if len(page) > 32768:
            raise RestoreError('restored_capture_page_exceeds_bound')
        fd, _ = open_blob(blob_root, body_hash)
        with os.fdopen(fd, 'rb') as stream:
            if stream.read(len(page)) != page:
                raise RestoreError('restored_capture_page_mismatch')
        if schema == 11:
            attribution = resource.get('attribution', {})
            uri = attribution.get('resource_uri')
            verify_notice_roundtrip(attribution, lambda selected:
                                   self.call(ip, 'resources/read', {'uri': selected}, self.private))
            if not any(item.get('uri') == uri and item.get('text') == attribution['readable_notice'] for item in contents[1:]):
                raise RestoreError('restored_attribution_readback_failed')
            self.verify_retained_mdn(ip)
        return {'snapshot': self.snapshot, 'schema': schema, 'server': server,
                'version': version, 'source_url': source, 'captures': int(count),
                'verified_capture_id': capture,
                'verified_body_hash': body_hash, 'verified_body_bytes': size,
                'verified_resource_bytes': len(page)}

    def verify_retained_mdn(self, ip):
        if (self.psql('SELECT version FROM devres_schema WHERE singleton') != '11'
                or self.psql('SELECT active FROM devres_integrity_control WHERE singleton') != 't'):
            raise RestoreError('restored_mdn_schema_or_activation_invalid')
        assets = attribution_assets()
        aliases = {}
        for namespace, legacy in (('mdn:snapshots', '10b23b616473f7534f3ba617c16453f88f5934eaa4d6e18b94b1a6a71e501f8a'),
                                  ('mdn:projections', '45ad5da63ff8bb663ee90a03468e7803763e75c79c9bf2ee7baa76b095da1f78')):
            value = self.psql("SELECT canonical FROM devres_content_aliases WHERE namespace='" + namespace + "' AND legacy='" + legacy + "'")
            if not re.fullmatch('blake3:[0-9a-f]{64}', value):
                raise RestoreError('restored_mdn_alias_unavailable')
            aliases[namespace] = value
        context = {'ip': ip, 'private_dir': str(self.private), 'release': VERSION,
                   'baseline_sha256': assets['mdn_baseline_sha256'], 'mdn_aliases': aliases}
        result = bounded_diagnostic_output(['/usr/bin/python3', '-I', '-B', str(ATTRIBUTION / 'verify-retained.py')],
                                           16384, timeout_seconds=180,
                                           input_data=json.dumps(context, sort_keys=True).encode())
        if result['truncated'] or result['timed_out'] or result['returncode'] != 0:
            raise RestoreError('restored_retained_verifier_failed')
        value = json.loads(result['data'])
        expected = {'version': 1, 'release': VERSION, 'schema': 11,
                    'retained_mdn': True, 'notices_verified': True, 'no_acquisition': True,
                    'mdn_baseline_sha256': assets['mdn_baseline_sha256']}
        if (value != expected or type(value.get('version')) is not int or type(value.get('schema')) is not int
                or any(value.get(key) is not True for key in ('retained_mdn', 'notices_verified', 'no_acquisition'))
                or attribution_assets() != assets):
            raise RestoreError('restored_retained_verifier_receipt_invalid')
        return True

    def cleanup(self):
        # Stop every clone writer before unmounting/destroying its storage.
        for name in reversed(self.containers):
            found = self.run(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'])
            if not found:
                continue
            if found != name:
                raise RestoreError('restore_container_inventory_changed')
            info = json.loads(self.run(['docker', 'inspect', name]))[0]
            if info.get('Config', {}).get('Labels', {}).get(LABEL_KEY) != self.token:
                raise RestoreError('restore_container_ownership_changed')
            self.run(['docker', 'rm', '-f', name])
        if self.network:
            found = self.run(['docker', 'network', 'ls', '--filter', 'name=^' + self.name + '$', '--format', '{{.Name}}'])
            if found and found != self.name:
                raise RestoreError('restore_network_inventory_changed')
            if found:
                info = json.loads(self.run(['docker', 'network', 'inspect', self.name]))[0]
                if info.get('Labels', {}).get(LABEL_KEY) != self.token:
                    raise RestoreError('restore_network_ownership_changed')
                self.run(['docker', 'network', 'rm', self.name])
        if self.datasets:
            inventory = self.run(['zfs', 'list', '-H', '-o', 'name']).splitlines()
            listed = [v for v in inventory if v == self.dataset or v.startswith(self.dataset + '/')]
            if not set(listed).issubset(set(self.datasets)):
                raise RestoreError('restore_dataset_tree_changed')
        for dataset in reversed(self.datasets):
            if dataset not in listed:
                continue
            self.owned(dataset)
            self.run(['zfs', 'destroy', dataset])
        if self.runtime_owned:
            if self.root.is_symlink() or (self.root / 'owner').read_text() != self.token:
                raise RestoreError('restore_runtime_ownership_changed')
            shutil.rmtree(self.root)


def verify(snapshot, *, timeout=OFFLINE_TIMEOUT_SECONDS, on_drill=None, **kwargs):
    """Return bounded metadata only after real capture recovery and cleanup pass."""
    drill = Drill(snapshot, **kwargs)
    try:
        if on_drill is not None:
            on_drill(drill)
        return drill.check(timeout=timeout)
    finally:
        drill.cleanup()
