"""Bounded private artifacts and closed, payload-free diagnostic events."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import time


class EvidenceError(RuntimeError):
    """Closed failure: callers must not persist exception text."""


def private_root(path: Path) -> int:
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path == Path('/tmp') or Path('/tmp') not in path.parents:
        raise EvidenceError('private_tmp_required')
    fd = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.relative_to('/tmp').parts:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise EvidenceError('private_owned_directory_required')
        return fd
    except BaseException:
        os.close(fd)
        raise


class EvidenceSink:
    """Only use trusted first-party, payload-free child stdout/stderr as artifacts."""

    def __init__(self, root: Path):
        self.fd = private_root(root)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def write(self, name: str, body: bytes):
        if name not in {'stdout.log', 'stderr.log', 'outcome.json'} or len(body) > 4 * 1024**2:
            raise EvidenceError('artifact_refused')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.fd)


METHODS = {'server/discover', 'initialize', 'tools/list', 'tools/call'}
TOOLS = {'server.info', 'none'}
STAGES = {'start', 'response', 'decode', 'assertion', 'receipt', 'failure'}
CODES = {'ok', 'transport', 'http_status', 'decode', 'assertion', 'response_bound', 'cancelled', 'trace'}


def validate_trace(value: dict):
    if set(value) != {'family', 'revision', 'operation', 'method', 'tool', 'stage', 'code', 'status', 'elapsed_ns'}:
        raise EvidenceError('trace_fields_refused')
    if value['family'] != 'ipv4' or value['revision'] not in {'2025-11-25', '2026-07-28'}:
        raise EvidenceError('trace_identity_refused')
    if value['operation'] not in {'discover', 'initialize', 'list_tools', 'server_info'} or value['method'] not in METHODS or value['tool'] not in TOOLS or value['stage'] not in STAGES or value['code'] not in CODES:
        raise EvidenceError('trace_value_refused')
    if type(value['elapsed_ns']) is not int or not 0 <= value['elapsed_ns'] < 2**63:
        raise EvidenceError('trace_timing_refused')
    if value['status'] is not None and (type(value['status']) is not int or not 100 <= value['status'] <= 599):
        raise EvidenceError('trace_status_refused')


def validate_runtime(kind: str, value: dict):
    schemas = {
        'pod': {'role', 'ready', 'restarts'},
        'resource': {'role', 'rss_bytes', 'cpu_millicores'},
        'application': {'role', 'code'},
        'edge': {'code'},
    }
    if kind not in schemas or set(value) != schemas[kind]:
        raise EvidenceError('runtime_fields_refused')
    if 'role' in value and value['role'] not in {'backend', 'writer', 'postgres'}:
        raise EvidenceError('runtime_role_refused')
    if 'code' in value and value['code'] not in {'started', 'ready', 'timeout', 'closed', 'cancelled', 'capacity', 'integrity', 'unknown'}:
        raise EvidenceError('runtime_code_refused')
    if 'ready' in value and type(value['ready']) is not bool:
        raise EvidenceError('runtime_ready_refused')
    for key in {'restarts', 'rss_bytes', 'cpu_millicores'} & value.keys():
        if type(value[key]) is not int or not 0 <= value[key] < 2**63:
            raise EvidenceError('runtime_number_refused')


class EventRecorder:
    """Append-only bounded closed events, anchored to a private directory FD."""

    def __init__(self, root: Path, kind: str, limit: int = 2 * 1024**2):
        if kind not in {'runtime', 'http'} or not 1 <= limit <= 2 * 1024**2:
            raise EvidenceError('recorder_refused')
        self.root = private_root(root)
        try:
            self.fd = os.open(kind + '.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.root)
        except BaseException:
            os.close(self.root)
            raise
        self.kind, self.limit, self.written = kind, limit, 0
        self.failed = False

    def record(self, kind: str, value: dict):
        if self.failed:
            raise EvidenceError('event_sink_failed')
        if self.kind == 'http':
            if kind != 'http':
                raise EvidenceError('event_kind_refused')
            validate_trace(value)
            row = value
        else:
            validate_runtime(kind, value)
            row = {'kind': kind, 'elapsed_ns': time.monotonic_ns(), **value}
        body = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
        if self.written + len(body) > self.limit:
            raise EvidenceError('event_bound')
        # Charge the attempt before I/O: a partially written or unsynced row
        # cannot be retried to bypass the byte cap. Failed sinks stay poisoned.
        self.written += len(body)
        try:
            with os.fdopen(os.dup(self.fd), 'ab') as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            self.failed = True
            raise EvidenceError('event_sink_failed') from None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            os.close(self.root)
            self.fd = None
