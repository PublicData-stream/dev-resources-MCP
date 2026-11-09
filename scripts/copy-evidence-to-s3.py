#!/usr/bin/env python3
"""Copy a held public-evidence snapshot to the explicitly authorized bucket root.

This private operator reads no PostgreSQL data and never activates a backend. It
retains source snapshots, completed objects, and durable per-file checkpoints.
Only this job's journaled incomplete multipart upload may be aborted.
"""
import argparse
import base64
import contextlib
import errno
import concurrent.futures
import fcntl
import hashlib
import io
import json
import math
import os
from pathlib import Path
import pwd
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

DEADLINE = 1794344340
DATASET = 'cachepool/devres-staging/evidence'
BUCKET = 'dev-resources-mcp'
ENDPOINT = 'https://s3.fr-par.scw.cloud'
REGION = 'fr-par'
CONTROL = '_devres-copy/'
STORAGE_CLASS = 'ONEZONE_IA'
MAX_SINGLE_COPY = 5_000_000_000
JOURNAL = Path('/var/lib/devres-staging/upgrade/state.json')
PLAN_FIELDS = {'version', 'source_dataset', 'source_dataset_guid', 'source_snapshot',
               'source_snapshot_guid', 'source_root', 'hold', 'bucket', 'endpoint',
               'region', 'prefix', 'profile', 'credential_user', 'deadline_at',
               'migration_proof_id', 'state_dir'}
CHUNK = 1024 * 1024
RATE = 16 * CHUNK
MIN_PART = 16 * CHUNK
INVENTORY_BATCH = 256
HASH_WORKERS, HASH_PENDING = 16, 32
COPY_WORKERS, COPY_PENDING = 128, 256
PART_WORKERS, PART_PENDING = 16, 32
MAX_CONNECTIONS = 160
MAX_PART = 5_000_000_000
MAX_OBJECT = MAX_PART * 1000
PHASES = {'running_migrate_storage', 'running_verify_storage', 'running_activate_storage',
          'offline_boundary', 'checkpoint_resuming', 'qualifying_attribution',
          'starting_candidate', 'awaiting_acceptance', 'complete'}
STOPPED = False


class CopyError(RuntimeError):
    """Only fixed, non-sensitive diagnostic codes cross the CLI boundary."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_dir(path):
    value = Path(path).lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
        raise CopyError('unsafe_private_directory')


def private_read(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > limit):
            raise CopyError('unsafe_private_file')
        data = os.read(fd, limit + 1)
        after, linked = os.fstat(fd), Path(path).lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_nlink')
        if len(data) != before.st_size or any(getattr(before, k) != getattr(after, k)
                or getattr(before, k) != getattr(linked, k) for k in fields):
            raise CopyError('private_file_changed')
        return data
    finally:
        os.close(fd)


def atomic_private(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.close(fd)
        if temporary.exists():
            temporary.unlink()


def read_plan(path):
    path = Path(path)
    if not path.is_absolute():
        raise CopyError('absolute_plan_required')
    private_dir(path.parent)
    raw = private_read(path)
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != PLAN_FIELDS:
        raise CopyError('invalid_plan_fields')
    if (type(value['version']) is not int or value['version'] != 1
            or value['source_dataset'] != DATASET or value['bucket'] != BUCKET
            or value['endpoint'] != ENDPOINT or value['region'] != REGION
            or value['prefix'] != '' or value['profile'] != 'newprofile'
            or value['credential_user'] != 'codex' or type(value['deadline_at']) is not int
            or value['deadline_at'] != DEADLINE
            or any(not isinstance(value[k], str) or not re.fullmatch('[0-9]+', value[k])
                   for k in ('source_dataset_guid', 'source_snapshot_guid'))
            or not isinstance(value['migration_proof_id'], str)
            or not re.fullmatch('[0-9a-f]{64}', value['migration_proof_id'])
            or not isinstance(value['source_snapshot'], str)
            or not re.fullmatch(re.escape(DATASET) + r'@[A-Za-z0-9][A-Za-z0-9_.:-]{0,200}', value['source_snapshot'])
            or not isinstance(value['hold'], str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,100}', value['hold'])
            or any(not isinstance(value[k], str) or not Path(value[k]).is_absolute()
                   or '..' in Path(value[k]).parts for k in ('source_root', 'state_dir'))
            or Path(value['state_dir']) == Path(value['source_root'])
            or Path(value['source_root']) in Path(value['state_dir']).parents):
        raise CopyError('invalid_plan')
    private_dir(value['state_dir'])
    return value, digest(raw)


def command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=30, check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise CopyError('source_probe_failed')
    return result.stdout.decode('utf-8', 'strict').strip()


def mount_paths():
    result = []
    for line in Path('/proc/self/mountinfo').read_bytes().splitlines():
        fields = line.split()
        if len(fields) < 6:
            raise CopyError('invalid_mount_inventory')
        raw = re.sub(rb'\\([0-7]{3})', lambda m: bytes([int(m[1], 8)]), fields[4])
        result.append(os.path.normpath(os.fsdecode(raw)))
    return result


class Guard:
    def __init__(self, plan, plan_path, plan_hash, run=command, clock=time.time):
        self.plan, self.path, self.hash, self.run, self.clock = plan, Path(plan_path), plan_hash, run, clock
        self.last = -math.inf
        self.device = None
        self.lock = threading.Lock()
        self.failure = None

    def check(self, force=False):
        with self.lock:
            if self.failure is not None:
                raise CopyError(self.failure)
            try:
                self._check(force)
                if STOPPED:
                    raise CopyError('copy_interrupted')
                if self.clock() >= self.plan['deadline_at']:
                    raise CopyError('copy_deadline_exceeded')
            except Exception as error:
                self.failure = str(error) if isinstance(error, CopyError) else 'source_guard_failed'
                raise

    def _check(self, force=False):
        if STOPPED:
            raise CopyError('copy_interrupted')
        if self.clock() >= self.plan['deadline_at']:
            raise CopyError('copy_deadline_exceeded')
        if not force and time.monotonic() - self.last < 10:
            return
        p = self.plan
        if digest(private_read(self.path)) != self.hash:
            raise CopyError('plan_changed')
        for attempt in range(3):
            try:
                record = json.loads(private_read(JOURNAL, 1024 * 1024))
                break
            except CopyError as error:
                if str(error) != 'private_file_changed' or attempt == 2:
                    raise
                # The live operator atomically replaces its journal. Retry only
                # that read race, never an unsafe owner, phase, or source check.
                time.sleep(0.05)
        token = record.get('token')
        if (not isinstance(token, str) or not re.fullmatch('[0-9a-f]{24}', token)
                or digest(b'devres-nodeport-proof-v1\0' + token.encode('ascii')) != p['migration_proof_id']
                or record.get('mode') != 'direct' or record.get('deadline_at') != p['deadline_at']
                or record.get('phase') not in PHASES):
            raise CopyError('migration_owner_or_phase_changed')
        for name, expected in ((p['source_dataset'], p['source_dataset_guid']),
                               (p['source_snapshot'], p['source_snapshot_guid'])):
            if self.run(['zfs', 'get', '-Hp', '-o', 'value', 'guid', name]) != expected:
                raise CopyError('source_identity_changed')
        descendants = self.run(['zfs', 'list', '-Hp', '-o', 'name', '-t', 'filesystem', '-r', p['source_dataset']]).splitlines()
        if descendants != [p['source_dataset']]:
            raise CopyError('source_child_dataset')
        mountpoint = self.run(['zfs', 'get', '-Hp', '-o', 'value', 'mountpoint', p['source_dataset']])
        expected_root = mountpoint + '/.zfs/snapshot/' + p['source_snapshot'].split('@', 1)[1]
        if p['source_root'] != expected_root:
            raise CopyError('source_snapshot_root_changed')
        holds = self.run(['zfs', 'holds', '-H', p['source_snapshot']]).splitlines()
        if not any(len(line.split('\t')) >= 2 and line.split('\t')[:2] == [p['source_snapshot'], p['hold']] for line in holds):
            raise CopyError('source_hold_missing')
        root = Path(p['source_root'])
        st = root.lstat()
        if not stat.S_ISDIR(st.st_mode) or not os.statvfs(root).f_flag & os.ST_RDONLY:
            raise CopyError('source_snapshot_not_readonly')
        if self.device is not None and self.device != st.st_dev:
            raise CopyError('source_device_changed')
        self.device = st.st_dev
        if any(name != str(root) and root in Path(name).parents for name in mount_paths()):
            raise CopyError('source_child_mount')
        self.last = time.monotonic()
        if self.clock() >= p['deadline_at']:
            raise CopyError('copy_deadline_exceeded')


class Limiter:
    """One thread-safe counter and optional aggregate bandwidth budget."""
    def __init__(self, guard, rate=RATE, cancelled=None):
        self.guard, self.rate, self.next = guard, rate, time.monotonic()
        self.lock, self._bytes = threading.Lock(), 0
        self.cancelled = cancelled

    @property
    def bytes(self):
        with self.lock:
            return self._bytes

    def check(self):
        if self.cancelled is not None and self.cancelled.is_set():
            raise CopyError('copy_worker_cancelled')
        self.guard.check()

    def consume(self, amount):
        self.check()
        with self.lock:
            self._bytes += amount
            if self.rate is None:
                return
            self.next = max(self.next, time.monotonic()) + amount / self.rate
            target = self.next
        while True:
            self.check()
            delay = target - time.monotonic()
            if delay <= 0:
                break
            time.sleep(min(0.2, delay))


@contextlib.contextmanager
def parallel_results(function, items, workers, outstanding, cancelled, check):
    """Bound submissions, preserve the first failure, and drain before returning.

    The consumer alone touches SQLite. Running jobs observe cancellation at their
    next source/network boundary; pending jobs are cancelled and no pool outlives
    the database, source descriptor, or multipart-upload owner.
    """
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    pending, failures, failure_lock = set(), [], threading.Lock()
    def fail(error):
        with failure_lock:
            if not failures:
                failures.append(error)
        cancelled.set()
    def invoke(item):
        try:
            check()
            return function(item)
        except BaseException as error:
            fail(error)
            raise
    def results():
        iterator, exhausted = iter(items), False
        while pending or not exhausted:
            while not exhausted and len(pending) < outstanding:
                check()
                try:
                    item = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                check()
                pending.add(pool.submit(invoke, item))
            if not pending:
                break
            done, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                pending.remove(future)
                yield future.result()
    try:
        yield results()
    except BaseException as error:
        fail(error)
        for future in pending:
            future.cancel()
        # Shutdown waits for every running reader/writer before abort/DB close.
        pool.shutdown(wait=True, cancel_futures=True)
        raise failures[0]
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


def identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid, st.st_gid)


def object_key(raw):
    try:
        key = raw.decode('utf-8', 'strict')
    except UnicodeError:
        key = None
    if key is not None and len(raw) <= 1024:
        return key
    return CONTROL + 'mapped/' + digest(raw)


def walk(root, guard):
    """Open every path relative to no-follow directory descriptors, including dots."""
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root_dev = os.fstat(root_fd).st_dev
    def descend(fd, rel):
        with os.scandir(fd) as entries:
            for entry in entries:
                name = entry.name
                raw = os.fsencode(name)
                if not rel and raw == b'.zfs':
                    continue
                if not rel and raw == b'_devres-copy':
                    raise CopyError('reserved_source_path')
                path = rel + (b'/' if rel else b'') + raw
                guard.check()
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if st.st_dev != root_dev:
                    raise CopyError('source_child_mount')
                if stat.S_ISDIR(st.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        if identity(st) != identity(os.fstat(child)):
                            raise CopyError('source_entry_changed')
                        yield path, 'directory', st
                        yield from descend(child, path)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(st.st_mode):
                    yield path, 'file', st
                else:
                    raise CopyError('source_special_or_symlink')
    try:
        yield b'', 'directory', os.fstat(root_fd)
        yield from descend(root_fd, b'')
    finally:
        os.close(root_fd)


@contextlib.contextmanager
def open_source(root, raw, expected):
    parts = raw.split(b'/')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in parts[:-1]:
            new = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            if identity(os.fstat(leaf)) != tuple(expected):
                raise CopyError('source_file_changed')
            with os.fdopen(leaf, 'rb', closefd=False) as stream:
                yield stream
            if identity(os.fstat(leaf)) != tuple(expected):
                raise CopyError('source_file_changed')
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


def hash_stream(stream, limiter):
    hasher, size = hashlib.sha256(), 0
    while True:
        data = stream.read(CHUNK)
        if not data:
            return hasher.hexdigest(), size
        limiter.consume(len(data))
        hasher.update(data)
        size += len(data)


def part_size(size):
    if type(size) is not int or size < 0 or size > MAX_OBJECT:
        raise CopyError('unsupported_object_size')
    value = max(MIN_PART, (size + 999) // 1000)
    value = min(MAX_PART, ((value + CHUNK - 1) // CHUNK) * CHUNK)
    if value > MAX_PART or (size + value - 1) // value > 1000:
        raise CopyError('multipart_part_limit')
    return value


class PartBody(io.RawIOBase):
    """Seekable bounded view; no part-sized allocation, including very large files."""
    def __init__(self, stream, start, length, limiter, independent=False):
        self.stream, self.start, self.length, self.limiter = stream, start, length, limiter
        self.independent = independent
        self.position = 0
        self.seek(0)
    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position
    def seek(self, offset, whence=0):
        at = offset if whence == 0 else self.position + offset if whence == 1 else self.length + offset
        if at < 0 or at > self.length:
            raise CopyError('invalid_part_seek')
        if not self.independent:
            self.stream.seek(self.start + at)
        self.position = at
        return at
    def read(self, size=-1):
        count = min(CHUNK, self.length - self.position, size if size >= 0 else CHUNK)
        if count <= 0:
            return b''
        data = (os.pread(self.stream.fileno(), count, self.start + self.position)
                if self.independent else self.stream.read(count))
        if len(data) != count:
            raise CopyError('source_short_read')
        self.limiter.consume(len(data))
        self.position += len(data)
        return data


def error_code(error):
    # Some S3-compatible errors carry a null/non-mapping Error (or response).
    # Classification must never replace the original failure with a parser error
    # or stringify an arbitrary provider value.
    try:
        response = getattr(error, 'response', None)
    except Exception:
        return ''
    if not isinstance(response, dict):
        return ''
    detail = dict.get(response, 'Error')
    if not isinstance(detail, dict):
        return ''
    code = dict.get(detail, 'Code')
    if type(code) is str:
        return code
    if type(code) is int and 0 <= code <= 999:
        return str(code)
    return ''


def missing(error):
    return error_code(error) in ('404', 'NoSuchKey', 'NotFound')


def http_status(error):
    try:
        response = getattr(error, 'response', None)
    except Exception:
        return None
    if not isinstance(response, dict):
        return None
    metadata = dict.get(response, 'ResponseMetadata')
    if not isinstance(metadata, dict):
        return None
    status = dict.get(metadata, 'HTTPStatusCode')
    return status if type(status) is int and 100 <= status <= 599 else None


def transient_s3(error):
    if isinstance(error, CopyError):
        return getattr(error, '_s3_transient', False) is True
    status = http_status(error)
    if status is not None:
        return status in (408, 429, 500, 502, 503, 504)
    if isinstance(error, OSError):
        try:
            number = getattr(error, 'errno', None)
        except Exception:
            return False
        if type(number) is int and number in (
                errno.ECONNRESET, errno.ECONNABORTED, errno.ETIMEDOUT, errno.EPIPE,
                errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN):
            return True
    sdk = sys.modules.get('botocore.exceptions')
    classes = tuple(value for name in ('EndpointConnectionError', 'ReadTimeoutError',
        'ConnectTimeoutError', 'ConnectionClosedError',
        'IncompleteReadError', 'ResponseStreamingError')
        if isinstance(value := getattr(sdk, name, None), type))
    return isinstance(error, classes)


def s3_failure(error):
    failure = CopyError('s3_request_failed')
    name = type(error).__name__
    failure.s3_exception_type = name if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}', name) else 'UnknownS3Error'
    failure.s3_http_status = http_status(error)
    failure._s3_transient = transient_s3(error)
    return failure


def make_client(plan, max_speed=False):
    try:
        account = pwd.getpwnam('codex')
    except KeyError:
        raise CopyError('credential_account_invalid') from None
    if (account.pw_name != 'codex' or type(account.pw_uid) is not int or account.pw_uid <= 0
            or type(account.pw_gid) is not int or account.pw_gid <= 0
            or not isinstance(account.pw_dir, str) or not Path(account.pw_dir).is_absolute()
            or '..' in Path(account.pw_dir).parts):
        raise CopyError('credential_account_invalid')
    args = ['/usr/local/bin/scw', '-p', 'newprofile', '-o', 'json',
            'config', 'get', 'access-key', 'secret-key', 'default-region']
    # Root drops only this child's identity. No sudo/elevation or supplementary
    # groups are needed, including under the service's NoNewPrivileges fence.
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=30, check=False,
            user=account.pw_uid, group=account.pw_gid, extra_groups=[],
            env={'HOME': account.pw_dir, 'USER': 'codex', 'LOGNAME': 'codex',
                 'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C'})
    except (OSError, subprocess.SubprocessError):
        raise CopyError('credential_selection_failed') from None
    if result.returncode or len(result.stdout) > 65536:
        raise CopyError('credential_selection_failed')
    keys = json.loads(result.stdout)
    if (not isinstance(keys, list) or len(keys) != 3 or any(not isinstance(x, str) or not x for x in keys)
            or keys[2] != REGION):
        raise CopyError('credential_profile_invalid')
    import boto3
    from botocore.config import Config
    session = boto3.Session(aws_access_key_id=keys[0], aws_secret_access_key=keys[1], region_name=REGION)
    session._session.set_config_variable('config_file', '/dev/null')
    session._session.set_config_variable('credentials_file', '/dev/null')
    session._session.set_config_variable('profile', None)
    client = session.client('s3', endpoint_url=ENDPOINT, region_name=REGION, verify=True,
        config=Config(signature_version='s3v4', connect_timeout=10, read_timeout=30,
                      retries={'mode': 'standard', 'total_max_attempts': 1}, max_pool_connections=MAX_CONNECTIONS if max_speed else 2,
                      s3={'addressing_style': 'path'}, proxies={'http': None, 'https': None},
                      request_checksum_calculation='when_required', response_checksum_validation='when_required'))
    for operation in ('PutObject', 'CompleteMultipartUpload'):
        if 'IfNoneMatch' not in client.meta.service_model.operation_model(operation).input_shape.members:
            raise CopyError('conditional_s3_sdk_required')
    def destination(request, **_kwargs):
        url = urllib.parse.urlsplit(request.url)
        if url.scheme != 'https' or url.hostname != 's3.fr-par.scw.cloud':
            raise CopyError('unexpected_s3_destination')
    client.meta.events.register('before-send.s3', destination)
    return client


class Copier:
    def __init__(self, plan, plan_hash, guard, client, limiter=None, *, max_speed=False):
        self.p, self.plan_hash, self.guard, self.s3 = plan, plan_hash, guard, client
        self.state = Path(plan['state_dir'])
        self.max_speed, self.cancelled = max_speed, threading.Event()
        self.limiter = limiter or Limiter(guard, rate=None if max_speed else RATE, cancelled=self.cancelled)
        self.db = None
        self.epoch = uuid.uuid4().hex
        self.last_progress = 0
        self.manifest_hash = None
        self.fresh_root = False
        self.admitted = False

    def check_active(self):
        if self.cancelled.is_set():
            raise CopyError('copy_worker_cancelled')
        self.guard.check()
        if self.cancelled.is_set():
            raise CopyError('copy_worker_cancelled')

    def retry_wait(self, delay):
        target = time.monotonic() + delay
        while True:
            self.check_active()
            remaining = target - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.05, remaining))

    def call(self, method, *, _attempts=None, **kwargs):
        # There is one explicit retry owner. SDK attempts remain one. A whole
        # streaming GET below supplies _attempts=1 and owns its total budget.
        safe = method in ('get_object', 'get_bucket_versioning', 'get_bucket_acl', 'list_objects_v2')
        safe |= method == 'put_object' and kwargs.get('IfNoneMatch') == '*'
        safe |= (method == 'upload_part' and isinstance(kwargs.get('UploadId'), str)
                 and bool(kwargs['UploadId']) and type(kwargs.get('PartNumber')) is int
                 and 1 <= kwargs['PartNumber'] <= 1000)
        attempts = min(4, _attempts) if safe and _attempts is not None else 4 if safe else 1
        body = kwargs.get('Body')
        origin = None
        if body is not None and not isinstance(body, (bytes, bytearray, memoryview)):
            try:
                origin = body.tell()
                if not body.seekable():
                    attempts = 1
            except Exception:
                attempts = 1
        for attempt in range(attempts):
            self.check_active()
            try:
                return getattr(self.s3, method)(Bucket=BUCKET, **kwargs)
            except CopyError:
                raise
            except Exception as error:
                if missing(error) or error_code(error) in ('PreconditionFailed', '412', 'NoSuchUpload'):
                    raise
                if attempt + 1 == attempts or not transient_s3(error):
                    raise s3_failure(error) from None
                if origin is not None:
                    try:
                        body.seek(origin)
                    except Exception:
                        raise s3_failure(error) from None
                self.retry_wait((0.25, 0.5, 1.0)[attempt])

    def bucket_check(self):
        versioning = self.call('get_bucket_versioning')
        # Scaleway returns an empty Status for a never-versioned bucket.
        if versioning.get('Status') not in (None, '', 'Suspended'):
            raise CopyError('unexpected_bucket_versioning')
        acl = self.call('get_bucket_acl')
        owner = acl.get('Owner', {}).get('ID')
        grants = acl.get('Grants', [])
        if not owner or not grants or any(g.get('Grantee', {}).get('Type') != 'CanonicalUser'
                or g.get('Grantee', {}).get('ID') != owner or g.get('Permission') != 'FULL_CONTROL' for g in grants):
            raise CopyError('bucket_acl_not_owner_only')

    def read_existing(self, key, metadata, expected_hash, expected_size, maximum):
        try:
            value = self.call('get_object', Key=key, _attempts=1)
        except Exception as error:
            if missing(error): return None
            raise
        body = value['Body']
        try:
            if metadata is not None and value.get('Metadata') != metadata:
                raise CopyError('object_owner_metadata_collision')
            hasher, length, output = hashlib.sha256(), 0, bytearray()
            while True:
                self.check_active()
                chunk = body.read(CHUNK)
                if not chunk: break
                self.limiter.consume(len(chunk))
                length += len(chunk)
                if (expected_size is not None and length > expected_size) or (maximum is not None and length > maximum):
                    raise CopyError('object_size_collision')
                hasher.update(chunk)
                if maximum is not None: output.extend(chunk)
            if ((expected_size is not None and length != expected_size)
                    or (expected_hash is not None and hasher.hexdigest() != expected_hash)):
                raise CopyError('object_content_collision')
            result = bytes(output) if maximum is not None else True
        finally:
            body.close()
        return value, result, length

    def existing(self, key, metadata=None, expected_hash=None, expected_size=None, maximum=None, *, allow_conversion=True):
        # At most three complete GET requests per proof, including request-level
        # failures. Every retry discards the old hasher/body and closes the body.
        for attempt in range(3):
            try:
                read = self.read_existing(key, metadata, expected_hash, expected_size, maximum)
                if read is None:
                    return None
                value, result, length = read
                break
            except Exception as error:
                if not transient_s3(error):
                    raise
                if attempt == 2:
                    if isinstance(error, CopyError):
                        raise
                    raise s3_failure(error) from None
                self.retry_wait((0.25, 0.5)[attempt])
        if self.admitted and metadata is not None and expected_hash is not None and expected_size is not None:
            storage_class = value.get('StorageClass', 'STANDARD')
            if storage_class != STORAGE_CLASS:
                if storage_class != 'STANDARD' or not allow_conversion:
                    raise CopyError('object_storage_class_mismatch')
                if length > MAX_SINGLE_COPY:
                    raise CopyError('legacy_storage_class_copy_too_large')
                etag = value.get('ETag')
                if not isinstance(etag, str) or not re.fullmatch(r'"[0-9A-Za-z._:/+=-]{1,200}"', etag):
                    raise CopyError('object_storage_class_etag_invalid')
                # Only this admitted namespace's fully read/hash-verified object
                # may change class. The same-key source CAS preserves its bytes
                # and user metadata; neither delete nor re-upload is permitted.
                try:
                    self.call('copy_object', Key=key, CopySource={'Bucket': BUCKET, 'Key': key},
                              CopySourceIfMatch=etag, MetadataDirective='COPY', StorageClass=STORAGE_CLASS)
                except Exception as error:
                    # A prior acknowledged-lost conversion may have changed its
                    # ETag. Never repeat CopyObject: prove the target class and
                    # unchanged content with a fresh complete GET instead.
                    if error_code(error) not in ('PreconditionFailed', '412') and not transient_s3(error):
                        raise
                verified = self.existing(key, metadata, expected_hash, expected_size, maximum,
                                         allow_conversion=False)
                if verified is None:
                    raise CopyError('storage_class_converted_object_missing')
                return verified
        return result

    def owner(self):
        return {'version': 1, 'plan_sha256': self.plan_hash, 'manifest_sha256': self.manifest_hash,
                'source_dataset_guid': self.p['source_dataset_guid'],
                'source_snapshot': self.p['source_snapshot'],
                'source_snapshot_guid': self.p['source_snapshot_guid'],
                'migration_proof_id': self.p['migration_proof_id']}

    def control_metadata(self, sha):
        return {'copy-plan-sha256': self.plan_hash, 'copy-manifest-sha256': self.manifest_hash,
                'sha256': sha}

    def conditional_bytes(self, key, data):
        sha = digest(data)
        metadata = self.control_metadata(sha)
        existing = self.existing(key, metadata, sha, len(data), maximum=max(len(data), 1))
        if existing is not None:
            if existing != data: raise CopyError('control_collision')
            return False
        created = False
        try:
            self.call('put_object', Key=key, Body=data, ContentLength=len(data), Metadata=metadata, StorageClass=STORAGE_CLASS, IfNoneMatch='*')
            created = True
        except Exception as error:
            if error_code(error) not in ('PreconditionFailed', '412'): raise
        self.existing(key, metadata, sha, len(data)) or self.fail('conditional_object_missing')
        return created

    @staticmethod
    def fail(code):
        raise CopyError(code)

    def database(self):
        path = self.state / 'copy.sqlite3'
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        self.validate_db_file(path)
        self.db = sqlite3.connect(path)
        path.chmod(0o600)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS entries (path BLOB PRIMARY KEY, kind TEXT NOT NULL, identity TEXT NOT NULL, sha TEXT, object_key TEXT UNIQUE, verified TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS multipart (singleton INTEGER PRIMARY KEY CHECK(singleton=1), object_key TEXT NOT NULL, upload_id TEXT, metadata TEXT NOT NULL)')
        row = self.db.execute("SELECT value FROM metadata WHERE key='plan'").fetchone()
        if row and row[0] != self.plan_hash: raise CopyError('local_state_plan_collision')
        self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('plan', ?)", (self.plan_hash,))
        self.db.commit()

    @staticmethod
    def validate_db_file(path):
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1:
            raise CopyError('unsafe_checkpoint_database')

    def inventory_entry(self, entry):
        raw, kind, st = entry
        self.check_active()
        sha, key = None, None
        if kind == 'file':
            part_size(st.st_size)
            with open_source(self.p['source_root'], raw, identity(st)) as stream:
                sha, size = hash_stream(stream, self.limiter)
            if size != st.st_size:
                raise CopyError('source_short_read')
            key = object_key(raw)
        self.check_active()
        return raw, kind, json.dumps(identity(st)), sha, key

    def inventory(self):
        complete = self.db.execute("SELECT value FROM metadata WHERE key='inventory_complete'").fetchone()
        if not complete:
            self.db.execute('DELETE FROM entries')
            self.db.commit()
            entries = walk(self.p['source_root'], self.guard)
            work = (parallel_results(self.inventory_entry, entries, HASH_WORKERS, HASH_PENDING,
                                     self.cancelled, self.check_active) if self.max_speed else
                    contextlib.nullcontext(map(self.inventory_entry, entries)))
            pending = 0
            with contextlib.closing(entries), work as results:
                for entry in results:
                    self.db.execute('INSERT INTO entries VALUES (?,?,?,?,?,NULL)', entry)
                    pending += 1
                    if pending == INVENTORY_BATCH:
                        self.db.commit()
                        pending = 0
                    self.progress('inventory')
            # All hash workers have joined before final rows/completion become
            # durable and before any manifest or remote owner can be published.
            self.db.execute("INSERT OR REPLACE INTO metadata VALUES ('inventory_complete','true')")
            self.db.commit()
        manifest = self.state / 'manifest.jsonl'
        temporary = self.state / ('manifest.tmp-' + self.epoch)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        hasher, length = hashlib.sha256(), 0
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                for raw, kind, ident, sha, key in self.db.execute('SELECT path,kind,identity,sha,object_key FROM entries ORDER BY path'):
                    st = json.loads(ident)
                    record = {'version': 1, 'path_bytes_base64': base64.b64encode(raw).decode(), 'kind': kind,
                              'size': st[2], 'mtime_ns': st[3], 'mode': stat.S_IMODE(st[4]), 'uid': st[5], 'gid': st[6],
                              'sha256': sha, 'object_key': key}
                    data = canonical(record)
                    stream.write(data); hasher.update(data); length += len(data)
                    self.guard.check()
                stream.flush(); os.fsync(fd)
            os.replace(temporary, manifest)
        finally:
            os.close(fd)
            if temporary.exists(): temporary.unlink()
        self.manifest_hash, self.manifest_size = hasher.hexdigest(), length
        self.guard.check(force=True)

    def verify_bucket_keys(self):
        token = None
        while True:
            args = {'MaxKeys': 1000}
            if token is not None: args['ContinuationToken'] = token
            page = self.call('list_objects_v2', **args)
            for entry in page.get('Contents', []):
                key = entry.get('Key')
                if key not in {CONTROL + 'owner.json', CONTROL + 'manifest.jsonl', CONTROL + 'COMPLETE.json'}:
                    if not self.db.execute('SELECT 1 FROM entries WHERE object_key=?', (key,)).fetchone():
                        raise CopyError('unexpected_existing_bucket_object')
            if not page.get('IsTruncated'): return
            next_token = page.get('NextContinuationToken')
            if not isinstance(next_token, str) or not next_token or next_token == token:
                raise CopyError('invalid_bucket_listing')
            token = next_token

    def claim_root(self):
        expected = canonical(self.owner())
        existing = self.existing(CONTROL + 'owner.json', maximum=8192)
        if existing is None:
            if self.call('list_objects_v2', MaxKeys=1).get('Contents'):
                raise CopyError('bucket_root_not_empty')
        elif existing != expected:
            raise CopyError('bucket_root_owner_collision')
        created = self.conditional_bytes(CONTROL + 'owner.json', expected)
        self.verify_bucket_keys()
        self.fresh_root = existing is None and created
        self.admitted = True
        self.existing(CONTROL + 'owner.json', self.control_metadata(digest(expected)),
                      digest(expected), len(expected)) or self.fail('admitted_owner_missing')

    def abort_pending(self):
        row = self.db.execute('SELECT object_key,upload_id,metadata FROM multipart WHERE singleton=1').fetchone()
        if row:
            key, upload_id, metadata = row
            bound = self.db.execute('SELECT sha FROM entries WHERE object_key=?', (key,)).fetchone()
            if upload_id is None:
                raise CopyError('multipart_creation_uncertain')
            sha = self.manifest_hash if key == CONTROL + 'manifest.jsonl' else bound[0] if bound else None
            if not sha or json.loads(metadata) != self.control_metadata(sha):
                raise CopyError('multipart_owner_changed')
            # Already completed objects are never deleted. Abort affects only
            # this durably recorded incomplete upload, never a bucket listing.
            try:
                self.s3.abort_multipart_upload(Bucket=BUCKET, Key=key, UploadId=upload_id)
            except Exception as error:
                if error_code(error) != 'NoSuchUpload': raise CopyError('multipart_abort_failed') from None
            self.db.execute('DELETE FROM multipart WHERE singleton=1'); self.db.commit()

    def upload(self, key, stream, size, sha):
        metadata = self.control_metadata(sha)
        if size <= MIN_PART:
            body = PartBody(stream, 0, size, self.limiter)
            try:
                self.call('put_object', Key=key, Body=body, ContentLength=size, Metadata=metadata, StorageClass=STORAGE_CLASS, IfNoneMatch='*')
            except Exception as error:
                if error_code(error) not in ('PreconditionFailed', '412'): raise
            return
        self.db.execute('INSERT INTO multipart VALUES (1,?,NULL,?)', (key, json.dumps(metadata, sort_keys=True)))
        self.db.commit()
        result = self.call('create_multipart_upload', Key=key, Metadata=metadata, StorageClass=STORAGE_CLASS)
        upload_id = result.get('UploadId')
        if not isinstance(upload_id, str) or not upload_id or len(upload_id) > 4096:
            raise CopyError('invalid_multipart_identity')
        self.db.execute('UPDATE multipart SET upload_id=? WHERE singleton=1', (upload_id,))
        self.db.commit()
        parts, width = [], part_size(size)
        def part(item):
            number, start = item
            length = min(width, size-start)
            result = self.call('upload_part', Key=key, UploadId=upload_id, PartNumber=number,
                               Body=PartBody(stream, start, length, self.limiter, independent=self.max_speed),
                               ContentLength=length)
            etag = result.get('ETag')
            if not isinstance(etag, str) or not etag:
                raise CopyError('invalid_multipart_part')
            return {'PartNumber': number, 'ETag': etag}
        items = enumerate(range(0, size, width), 1)
        work = (parallel_results(part, items, PART_WORKERS, PART_PENDING, self.cancelled, self.check_active)
                if self.max_speed else contextlib.nullcontext(map(part, items)))
        with work as results:
            parts.extend(results)
        parts.sort(key=lambda value: value['PartNumber'])
        try:
            self.call('complete_multipart_upload', Key=key, UploadId=upload_id,
                      MultipartUpload={'Parts': parts}, IfNoneMatch='*')
        except Exception as error:
            if error_code(error) not in ('PreconditionFailed', '412'): raise
        self.abort_pending()

    def copy_file(self, entry):
        raw, ident, sha, key = entry
        st = json.loads(ident)
        fresh_small = self.fresh_root and st[2] <= MIN_PART
        if fresh_small or self.existing(key, self.control_metadata(sha), sha, st[2]) is None:
            with open_source(self.p['source_root'], raw, st) as stream:
                self.upload(key, stream, st[2], sha)
            self.existing(key, self.control_metadata(sha), sha, st[2]) or self.fail('uploaded_object_missing')
        return raw

    def copy_files(self):
        rows = iter(self.db.execute("SELECT path,identity,sha,object_key FROM entries WHERE kind='file' ORDER BY path"))
        try:
            pending = 0
            def verified(raw):
                nonlocal pending
                self.db.execute('UPDATE entries SET verified=? WHERE path=?', (self.epoch, raw))
                pending += 1
                if not self.max_speed or pending == INVENTORY_BATCH:
                    self.db.commit()
                    pending = 0
                self.progress('copying')
            if not self.max_speed:
                for row in rows:
                    verified(self.copy_file(row))
                return
            # Each small-file segment is streamed through a bounded pool. A large
            # file is a barrier: drain small jobs, then let the main thread own one
            # MPU journal and its bounded part pool before admitting more files.
            while True:
                boundary = []
                def segment():
                    for row in rows:
                        if json.loads(row[1])[2] > MIN_PART:
                            boundary.append(row)
                            return
                        yield row
                with parallel_results(self.copy_file, segment(), COPY_WORKERS, COPY_PENDING,
                                      self.cancelled, self.check_active) as results:
                    for raw in results:
                        verified(raw)
                self.db.commit()
                pending = 0
                if not boundary:
                    break
                verified(self.copy_file(boundary[0]))
            self.db.commit()
        finally:
            rows.close()

    def progress(self, phase, force=False):
        if not force and time.monotonic() - self.last_progress < 30: return
        counts = self.db.execute("SELECT COUNT(*),COALESCE(SUM(json_extract(identity,'$[2]')),0) FROM entries WHERE kind='file'").fetchone()
        verified = self.db.execute("SELECT COUNT(*),COALESCE(SUM(json_extract(identity,'$[2]')),0) FROM entries WHERE kind='file' AND verified=?", (self.epoch,)).fetchone()
        atomic_private(self.state / 'progress.json', canonical({'version': 1, 'plan_sha256': self.plan_hash,
            'phase': phase, 'files_total': counts[0], 'bytes_total': counts[1], 'files_verified': verified[0],
            'bytes_verified': verified[1], 'io_bytes': self.limiter.bytes, 'deadline_at': self.p['deadline_at']}))
        self.last_progress = time.monotonic()

    def run(self):
        self.bucket_check()
        self.database()
        try:
            self.inventory()
            self.claim_root()
            self.abort_pending()
            path = self.state / 'manifest.jsonl'
            with path.open('rb') as stream:
                if self.existing(CONTROL + 'manifest.jsonl', self.control_metadata(self.manifest_hash),
                                 self.manifest_hash, self.manifest_size) is None:
                    self.upload(CONTROL + 'manifest.jsonl', stream, self.manifest_size, self.manifest_hash)
                    self.existing(CONTROL + 'manifest.jsonl', self.control_metadata(self.manifest_hash),
                                  self.manifest_hash, self.manifest_size) or self.fail('manifest_missing')
            self.copy_files()
            if self.db.execute("SELECT COUNT(*) FROM entries WHERE kind='file' AND (verified IS NULL OR verified!=?)", (self.epoch,)).fetchone()[0]:
                raise CopyError('incomplete_verification')
            self.guard.check(force=True)
            self.bucket_check()
            self.verify_bucket_keys()
            counts = self.db.execute("SELECT COUNT(*),COALESCE(SUM(json_extract(identity,'$[2]')),0) FROM entries WHERE kind='file'").fetchone()
            self.guard.check(force=True)
            self.conditional_bytes(CONTROL + 'COMPLETE.json', canonical({**self.owner(), 'complete': True,
                'files': counts[0], 'bytes': counts[1], 'all_objects_get_sha256_verified': True}))
            self.guard.check(force=True)
            self.progress('complete', force=True)
            return {'complete': True, 'files': counts[0], 'bytes': counts[1], 'plan_sha256': self.plan_hash,
                    'manifest_sha256': self.manifest_hash, 'all_objects_get_sha256_verified': True}
        finally:
            # Even after deadline/SIGTERM only our recorded MPU may be aborted;
            # this neither publishes an object nor changes the source/other jobs.
            if self.db is not None:
                try: self.abort_pending()
                finally: self.db.close(); self.db = None

    def check(self):
        self.guard.check(force=True)
        files, size, directories = 0, 0, 0
        for _raw, kind, st in walk(self.p['source_root'], self.guard):
            if kind == 'file':
                part_size(st.st_size); files += 1; size += st.st_size
            else: directories += 1
        self.bucket_check()
        owner = self.existing(CONTROL + 'owner.json', maximum=8192)
        if owner is None:
            if self.call('list_objects_v2', MaxKeys=1).get('Contents'):
                raise CopyError('bucket_root_not_empty')
        else:
            value = json.loads(owner)
            expected = {'version', 'plan_sha256', 'manifest_sha256', 'source_dataset_guid',
                        'source_snapshot', 'source_snapshot_guid', 'migration_proof_id'}
            if (not isinstance(value, dict) or set(value) != expected or value['version'] != 1
                    or value['plan_sha256'] != self.plan_hash
                    or any(value[k] != self.p[k] for k in ('source_dataset_guid', 'source_snapshot',
                            'source_snapshot_guid', 'migration_proof_id'))
                    or not re.fullmatch('[0-9a-f]{64}', value['manifest_sha256'])):
                raise CopyError('bucket_root_owner_collision')
        self.guard.check(force=True)
        return {'check_passed': True, 'files': files, 'bytes': size, 'directories': directories,
                'resume_owner_present': owner is not None, 'remote_writes': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--max-speed', action='store_true', help='unthrottled bounded parallel hashing and transfers')
    args = parser.parse_args(argv)
    if os.geteuid() != 0: raise CopyError('root_required')
    os.umask(0o077)
    plan, plan_hash = read_plan(args.plan)
    guard = Guard(plan, args.plan, plan_hash)
    guard.check(force=True)
    def stop(_number, _frame):
        global STOPPED
        STOPPED = True
    for number in (signal.SIGTERM, signal.SIGINT): signal.signal(number, stop)
    client = make_client(plan, max_speed=args.max_speed)
    copier = Copier(plan, plan_hash, guard, client, max_speed=args.max_speed)
    if args.check:
        result = copier.check()
    else:
        lock_path = Path(plan['state_dir']) / 'copy.lock'
        lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(lock).st_uid != os.geteuid() or os.fstat(lock).st_nlink != 1:
                raise CopyError('unsafe_copy_lock')
            try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise CopyError('copy_already_running') from None
            result = copier.run()
        finally:
            os.close(lock)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = str(error) if isinstance(error, CopyError) else 'copy_failed'
        print(json.dumps({'ok': False, 'code': code}), file=sys.stderr)
        sys.exit(1)
