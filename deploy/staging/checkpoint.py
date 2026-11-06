#!/usr/bin/env python3
"""Private, token-scoped offline checkpoints. Never execute imported receipts."""
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import tomllib

COMMANDS = ('migrate-storage', 'verify-storage', 'activate-storage')
PAUSED = {'rehearsal_paused', 'upgrade_paused'}
PRESERVED = PAUSED | {'rehearsal_preserved_failed', 'upgrade_preserved_failed'}
HEX = re.compile(r'[0-9a-f]{64}\Z')
TOKEN = re.compile(r'[0-9a-f]{24}\Z')
CAPSULE_FILES = ('config/backend.toml', 'tls/backend.pem', 'tls/backend-key.pem',
                 'tls/client-ca.pem', 'original-config.toml')
LEGACY_SERVER = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:491ba0afe42ebc564e1d40ddf1c884f0aaa34cc75517f1eeabb853d8e21f6c70'
LEGACY_VERSION = '0.1.0-build.b91929db'
LEGACY_FILES = {'owner', *CAPSULE_FILES, 'RESUME.txt', 'journal-before-pause.json',
                'pause-helper.py', 'resume-controller.py', 'current-resume-receipt.json',
                'previous-pause-receipt.json', 'previous-resume-receipt.json'}


class CheckpointError(RuntimeError):
    """Fixed error only; private data and external stderr must not escape."""


class Paused(Exception):
    preserve_checkpoint = True


def unsafe_owner(reason):
    error = CheckpointError(reason)
    error.unsafe_cleanup = True
    return error


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise CheckpointError('unsafe_checkpoint_directory')
    return path


def read_bytes(path, limit=1024 * 1024, private=True):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise CheckpointError('unsafe_checkpoint_parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_size > limit
                or info.st_mode & 0o022 or (private and info.st_mode & 0o077)
                or (not private and info.st_gid not in (os.getegid(), 65532))):
            raise CheckpointError('unsafe_checkpoint_file')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise CheckpointError('checkpoint_file_exceeds_bound')
        return data
    finally:
        os.close(fd)


def read_json(path):
    try:
        value = json.loads(read_bytes(path))
    except (ValueError, UnicodeError) as error:
        raise CheckpointError('invalid_checkpoint_json') from error
    if not isinstance(value, dict):
        raise CheckpointError('invalid_checkpoint_json')
    return value


def digest(path, private=True):
    return hashlib.sha256(read_bytes(path, private=private)).hexdigest()


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value):
        raise CheckpointError('boot_identity_unavailable')
    return value


@contextlib.contextmanager
def control_lock(root):
    private_directory(root)
    fd = os.open(root / 'checkpoint-control.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise CheckpointError('unsafe_checkpoint_lock')
        for attempt in range(101):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as error:
                if attempt == 100:
                    raise CheckpointError('checkpoint_control_busy') from error
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


class Lifecycle:
    def __init__(self, upgrade):
        self.u = upgrade
        self.restore = upgrade.restore_module
        self.root = upgrade.root

    def record(self, token):
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            raise CheckpointError('invalid_checkpoint_token')
        value = self.u.read_record()
        if not value or value['token'] != token:
            raise CheckpointError('checkpoint_token_mismatch')
        return value

    @staticmethod
    def permanent(record):
        return record.get('live_kind') == 'permanent' or record.get('checkpoint_kind') == 'permanent'

    def eligible(self, record):
        command = record.get('offline_command')
        if command not in COMMANDS:
            raise CheckpointError('offline_checkpoint_phase_required')
        if self.permanent(record) and record.get('pause_scope', 'rehearsal') != 'all':
            raise CheckpointError('permanent_checkpoint_not_enabled')
        if record['phase'] not in {*(('running_' + c.replace('-', '_')) for c in COMMANDS),
                                  'rehearsal_running', *PAUSED, 'checkpoint_pausing'}:
            raise CheckpointError('offline_checkpoint_phase_required')

    def status(self, token):
        record = self.record(token)
        # Deliberately exclude owner tokens, paths, config hashes and source bodies.
        result = {'phase': record['phase'], 'paused': record['phase'] in PAUSED,
                  'permanent': self.permanent(record),
                  'timing_qualified': bool(record.get('timing_qualified', False)),
                  'pause_scope': record.get('pause_scope', 'rehearsal')}
        for key in ('offline_command', 'deadline_at'):
            if key in record:
                result[key] = record[key]
        return result

    def pause(self, token, wait_seconds=180, sleep=time.sleep):
        with control_lock(self.root):
            record = self.record(token)
            self.eligible(record)
            if self.permanent(record) and self.u.deadline_due(record, time.time):
                return {'paused': False, **self.u.expire(token)}
            if record['phase'] in PAUSED:
                self.validate_paused(record)
                return {'paused': True, 'already_paused': True}
            request = {'version': 1, 'token': token, 'live_token': record.get('live_token'),
                       'command': record['offline_command'], 'requested_at': time.time()}
            self.u.write(self.root / 'pause-request.json', json.dumps(request, sort_keys=True) + '\n')
        started = time.monotonic()
        for _ in range(max(1, math.ceil(wait_seconds))):
            current = self.record(token)
            if current['phase'] in PAUSED:
                self.validate_paused(current)
                return {'paused': True}
            if current['phase'] not in ('checkpoint_pausing', 'rehearsal_running') and not current['phase'].startswith('running_'):
                raise CheckpointError('checkpoint_pause_not_acknowledged')
            if time.monotonic() - started >= wait_seconds:
                break
            sleep(1)
        raise CheckpointError('checkpoint_pause_pending')

    def control(self, drill, command, worker):
        if self.permanent(self.u.record):
            self.u.wall_remaining()
        else:
            self.u.safe()
        path = self.root / 'pause-request.json'
        if not path.exists():
            return False
        request = read_json(path)
        record = self.u.record
        if (request.get('version') != 1 or request.get('token') != record['token']
                or request.get('live_token') != record.get('live_token')
                or request.get('command') != command):
            raise CheckpointError('checkpoint_request_identity_changed')
        self.eligible(record)
        if worker != drill.name + '-offline-' + str(drill.offline_sequence):
            raise CheckpointError('checkpoint_worker_identity_changed')
        return True

    def offline(self, drill, command, timeout=None):
        if command not in COMMANDS:
            raise CheckpointError('invalid_checkpoint_command')
        permanent = self.permanent(self.u.record)
        identity = self.u.identity()
        if self.u.record.get('target_identity') and self.u.record['target_identity'] != identity:
            raise CheckpointError('checkpoint_target_identity_changed')
        dataset = self.u.dataset if permanent else drill.dataset
        guids = self.pair_guids(dataset)
        previous_guids = self.u.record.get('live_dataset_guids')
        if (self.u.record.get('live_token') == drill.token and previous_guids
                and guids != previous_guids):
            raise CheckpointError('checkpoint_dataset_identity_changed')
        with control_lock(self.root):
            self.u.save('running_' + command.replace('-', '_') if permanent else 'rehearsal_running',
                        offline_command=command, checkpoint_kind='permanent' if permanent else 'rehearsal',
                        live_token=drill.token, live_kind='permanent' if permanent else 'restore',
                        live_snapshot=drill.snapshot,
                        resource_profile=drill.resource_profile,
                        live_dataset_guids=guids,
                        target_identity=identity)
        kwargs = {'control': self.control}
        if timeout is not None:
            kwargs['timeout'] = timeout
        started = time.monotonic()
        try:
            drill.offline(command, **kwargs)
            # Serialize the successful-command boundary with request admission.
            # A request arriving after the final worker poll is acknowledged
            # here before a new phase can replace its command identity.
            with control_lock(self.root):
                path = self.root / 'pause-request.json'
                if path.exists():
                    request = read_json(path)
                    if (request.get('token') != self.u.record['token']
                            or request.get('live_token') != drill.token
                            or request.get('command') != command):
                        raise CheckpointError('checkpoint_request_identity_changed')
                    self.checkpoint(drill, command, completed=True)
                    raise Paused()
                self.note_elapsed(command, started)
                self.u.save('offline_boundary', offline_command=None)
        except self.restore.OfflinePaused as error:
            self.note_elapsed(command, started)
            try:
                self.checkpoint(drill, command, bool(error.command_completed))
            except Exception as failure:
                self.preserve_failure(drill, allow_stop=not getattr(failure, 'unsafe_cleanup', False))
                raise
            raise Paused() from None
        except Exception as failure:
            if (getattr(failure, 'unsafe_cleanup', False)
                    or self.u.record.get('phase') == 'checkpoint_pausing'):
                self.preserve_failure(drill, allow_stop=not getattr(failure, 'unsafe_cleanup', False))
            raise

    def note_elapsed(self, command, started):
        if 'resume_started_epoch' in self.u.record:
            phases = dict(self.u.record.get('resume_phase_seconds', {}))
            phases[command] = phases.get(command, 0) + max(0, time.monotonic() - started)
            self.u.save(resume_phase_seconds=phases)

    def pair_guids(self, dataset):
        result = {}
        for child in ('', '/postgres', '/evidence'):
            value = self.u.run(['zfs', 'get', '-H', '-o', 'value', 'guid', dataset + child]).strip()
            if not value.isdigit():
                raise CheckpointError('checkpoint_dataset_identity_invalid')
            result[dataset + child] = value
        return result

    def checkpoint(self, drill, command, completed=False, provenance=None):
        permanent = self.permanent(self.u.record)
        identity = self.u.identity()
        if ((provenance is None and self.u.record.get('target_identity') != identity)
                or (provenance is not None and provenance.get('to_bundle_sha256') != identity['bundle_sha256'])):
            raise CheckpointError('checkpoint_target_identity_changed')
        self.u.save('checkpoint_pausing', command_completed=completed)
        if getattr(drill, 'backend_started', False):
            raise CheckpointError('public_candidate_cannot_pause')
        if permanent:
            self.u.wall_remaining()
        self.stop_postgres(drill)
        drill.postgres_started = False
        self.clean_postgres(drill.root / 'postgres')
        dataset = self.u.dataset if permanent else drill.dataset
        checkpoint = self.u.snapshot_name('offline-pause')
        with self.u.maintenance_state.locked():
            self.u.safe_unlocked()
            self.u.run(['zfs', 'snapshot', '-r', dataset + '@' + checkpoint])
            self.u.run(['zfs', 'hold', '-r', self.u.hold, dataset + '@' + checkpoint])
        capsule = self.root / 'pause' / self.u.record['token'] / checkpoint
        self.write_capsule(capsule, drill)
        guids = self.pair_guids(dataset)
        snapshots = {name: self.u.run(['zfs', 'get', '-H', '-o', 'value', 'guid', name + '@' + checkpoint]).strip()
                     for name in guids}
        if any(not value.isdigit() for value in snapshots.values()):
            raise CheckpointError('checkpoint_snapshot_identity_invalid')
        receipt = {'version': 2, 'token': self.u.record['token'], 'live_token': drill.token,
                   'dataset': dataset, 'dataset_guids': guids, 'checkpoint': checkpoint,
                   'checkpoint_guids': snapshots, 'checkpoint_hold': self.u.hold,
                   'command': command, 'command_completed': completed,
                   'capsule': str(capsule), 'target_identity': identity,
                   'resource_profile': drill.resource_profile,
                   'paused_at_epoch': time.time(), 'boot_id': boot_id(),
                   'timing_qualified': False}
        if permanent:
            self.u.wall_remaining()
            receipt['deadline_at'] = self.u.record['deadline_at']
        if provenance is not None:
            receipt['bundle_transition'] = provenance
        receipt_path = capsule / 'receipt.json'
        self.u.write(receipt_path, json.dumps(receipt, sort_keys=True) + '\n')
        if self.u.identity() != identity:
            raise CheckpointError('checkpoint_target_identity_changed')
        updates = {'pause_receipt': str(receipt_path), 'pause_checkpoint': checkpoint,
                   'timing_qualified': False, 'driver_stopped': True}
        if provenance is not None:
            updates['target_identity'] = identity
            updates['bundle_transitions'] = [*self.u.record.get('bundle_transitions', []), provenance]
        self.u.save('upgrade_paused' if permanent else 'rehearsal_paused', **updates)
        (self.root / 'pause-request.json').unlink(missing_ok=True)

    def stop_postgres(self, drill):
        try:
            self.stop_postgres_owned(drill)
        except Exception as error:
            if getattr(error, 'unsafe_cleanup', False):
                raise
            raise unsafe_owner('checkpoint_postgres_identity_unavailable') from None

    def stop_postgres_owned(self, drill):
        name = drill.name + '-postgres'
        if not drill.postgres_started:
            names = self.u.run(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$',
                                '--format', '{{.Names}}']).splitlines()
            if name not in names:
                return
        info = json.loads(self.u.run(['docker', 'inspect', name]))[0]
        identifier = info.get('Id')
        try:
            if (not isinstance(identifier, str) or not HEX.fullmatch(identifier)
                    or info.get('Config', {}).get('Image') != self.restore.PG
                    or info.get('Config', {}).get('Labels', {}).get(self.restore.LABEL_KEY) != drill.token
                    or set(info.get('NetworkSettings', {}).get('Networks', {})) != {drill.name}
                    or info.get('HostConfig', {}).get('PortBindings')
                    or info.get('HostConfig', {}).get('RestartPolicy', {}).get('Name', 'no') not in ('', 'no')):
                raise CheckpointError('checkpoint_postgres_identity_changed')
            self.validate_container_mounts(info, drill.root, True, self.permanent(self.u.record))
        except CheckpointError as error:
            raise unsafe_owner(str(error)) from None
        self.u.run(['docker', 'stop', '--time=120', identifier])
        stopped = json.loads(self.u.run(['docker', 'inspect', identifier]))[0]
        if (stopped.get('Id') != identifier or stopped.get('State', {}).get('Running') is not False
                or stopped.get('Config', {}).get('Labels', {}).get(self.restore.LABEL_KEY) != drill.token):
            raise unsafe_owner('checkpoint_postgres_stop_uncertain')

    def clean_postgres(self, path):
        output = self.u.run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                             '--user', '999:999', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                             '-e', 'LC_ALL=C', '--entrypoint', 'pg_controldata', '-v',
                             str(path) + ':/pgdata:ro', self.restore.PG, '/pgdata/18/docker'])
        states = [line.partition(':')[2].strip() for line in output.splitlines()
                  if line.startswith('Database cluster state:')]
        if states != ['shut down']:
            raise CheckpointError('checkpoint_postgres_not_clean')

    def write_capsule(self, path, drill):
        path.parent.parent.mkdir(mode=0o700, exist_ok=True)
        path.parent.mkdir(mode=0o700, exist_ok=True)
        private_directory(path.parent.parent)
        private_directory(path.parent)
        path.mkdir(mode=0o700, exist_ok=False)
        private_directory(path)
        hashes = {}
        for relative in CAPSULE_FILES:
            source = (self.root / 'original-config.toml' if relative == 'original-config.toml'
                      else drill.root / relative)
            data = read_bytes(source, private=relative == 'original-config.toml')
            destination = path / relative
            destination.parent.mkdir(mode=0o700, exist_ok=True)
            private_directory(destination.parent)
            self.u.write(destination, data.decode('utf-8'))
            hashes[relative] = hashlib.sha256(data).hexdigest()
        self.u.write(path / 'manifest.json', json.dumps({'version': 1, 'files': hashes}, sort_keys=True) + '\n')
        for parent in (path, path.parent, path.parent.parent, self.root):
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def verify_capsule(self, capsule):
        private_directory(capsule)
        manifest = read_json(capsule / 'manifest.json')
        if manifest.get('version') != 1 or set(manifest.get('files', {})) != set(CAPSULE_FILES):
            raise CheckpointError('checkpoint_capsule_manifest_invalid')
        for relative, expected in manifest['files'].items():
            private_directory((capsule / relative).parent)
            if not isinstance(expected, str) or not HEX.fullmatch(expected) or digest(capsule / relative) != expected:
                raise CheckpointError('checkpoint_capsule_integrity_changed')
        return manifest

    def validate_serving_pair(self, record, original):
        permanent = self.permanent(record)
        expected_replicas = 0 if permanent else 1
        if any(self.u.tool.replicas(name) != expected_replicas for name in ('backend', 'postgres')):
            raise CheckpointError('checkpoint_serving_replica_state_changed')
        image = self.u.tool.k('get', 'deployment', 'backend', '-o',
                              'jsonpath={.spec.template.spec.containers[0].image}').strip()
        if image != self.restore.OLD_SERVER:
            raise CheckpointError('checkpoint_serving_image_changed')
        expected = self.restore.paused_config(original) if permanent else original
        if read_bytes(self.u.private / 'backend.toml').decode() != expected:
            raise CheckpointError('checkpoint_serving_configuration_changed')
        if not permanent:
            schema = self.u.tool.k('exec', 'deployment/postgres', '--', 'psql', '-X', '-U',
                                   'devres_admin', '-d', 'devres', '-Atc',
                                   'SELECT version FROM devres_schema WHERE singleton').strip()
            if schema != '9':
                raise CheckpointError('checkpoint_serving_schema_changed')

    def validate_paused(self, record):
        if record['phase'] not in PAUSED:
            raise CheckpointError('paused_checkpoint_required')
        receipt_path = Path(record.get('pause_receipt', ''))
        expected = self.root / 'pause' / record['token'] / record.get('pause_checkpoint', '')
        if receipt_path != expected / 'receipt.json':
            raise CheckpointError('formal_checkpoint_adoption_required')
        receipt = read_json(receipt_path)
        if (receipt.get('version') != 2 or receipt.get('token') != record['token']
                or receipt.get('live_token') != record.get('live_token')
                or receipt.get('checkpoint') != record.get('pause_checkpoint')
                or receipt.get('capsule') != str(receipt_path.parent)
                or receipt.get('command') != record.get('offline_command')
                or receipt.get('resource_profile') != ('direct' if record.get('mode') == 'direct' else 'upgrade')
                or receipt.get('resource_profile') != record.get('resource_profile')
                or receipt.get('target_identity') != record.get('target_identity')
                or (self.permanent(record) and receipt.get('deadline_at') != record.get('deadline_at'))
                or receipt.get('timing_qualified') is not False):
            raise CheckpointError('checkpoint_receipt_identity_changed')
        self.verify_capsule(receipt_path.parent)
        self.validate_storage(record, receipt)
        self.clean_postgres((Path('/mnt/devres-staging') if self.permanent(record)
                             else Path('/tmp') / ('devres-staging-restore-' + record['live_token'])) / 'postgres')
        return receipt

    def validate_storage(self, record, receipt, checkpoint_required=True):
        permanent = self.permanent(record)
        token = record['live_token']
        expected = self.u.dataset if permanent else 'cachepool/devres-staging-restore-' + token
        if receipt.get('dataset') != expected:
            raise CheckpointError('checkpoint_dataset_changed')
        if self.pair_guids(expected) != receipt.get('dataset_guids'):
            raise CheckpointError('checkpoint_dataset_identity_changed')
        checkpoint = receipt.get('checkpoint')
        if checkpoint_required:
            if receipt.get('legacy'):
                if checkpoint != 'devres-pause2-' + record['token']:
                    raise CheckpointError('checkpoint_snapshot_name_invalid')
            else:
                self.restore.validate_snapshot(checkpoint)
        self.validate_dataset_tree(record, receipt)
        for name in receipt['dataset_guids']:
            if not permanent and self.u.run(['zfs', 'get', '-H', '-o', 'value', self.restore.OWNER_KEY, name]).strip() != token:
                raise CheckpointError('checkpoint_dataset_owner_changed')
            if not checkpoint_required:
                continue
            snapshot = name + '@' + checkpoint
            if self.u.run(['zfs', 'get', '-H', '-o', 'value', 'guid', snapshot]).strip() != receipt['checkpoint_guids'].get(name):
                raise CheckpointError('checkpoint_snapshot_identity_changed')
            holds = self.u.run(['zfs', 'holds', '-H', snapshot]).splitlines()
            if not any(len(line.split('\t')) >= 2 and line.split('\t')[1] == receipt['checkpoint_hold'] for line in holds):
                raise CheckpointError('checkpoint_hold_missing')
        runtime = Path('/tmp') / ('devres-staging-restore-' + token)
        if runtime.exists():
            info = runtime.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o022):
                raise CheckpointError('checkpoint_runtime_owner_changed')
            marker = runtime / 'owner'
            if marker.exists() and read_bytes(marker).decode() != token:
                raise CheckpointError('checkpoint_runtime_owner_changed')
        name = runtime.name
        net = json.loads(self.u.run(['docker', 'network', 'inspect', name]))
        if (len(net) != 1 or net[0].get('Internal') is not True
                or net[0].get('Labels', {}).get(self.restore.LABEL_KEY) != token):
            raise CheckpointError('checkpoint_network_changed')
        names = set()
        for selector in ('label=' + self.restore.LABEL_KEY + '=' + token, 'name=^/' + name + '-'):
            names.update(self.u.run(['docker', 'ps', '-a', '--filter', selector,
                                    '--format', '{{.Names}}']).splitlines())
        endpoints = set(net[0].get('Containers', {}))
        identifiers = set()
        identities = {}
        for container in names:
            if not re.fullmatch(re.escape(name) + r'-(?:postgres|offline-[1-9][0-9]*)', container):
                raise CheckpointError('checkpoint_container_inventory_changed')
            info = json.loads(self.u.run(['docker', 'inspect', container]))[0]
            identities[container] = info.get('Id')
            identifiers.add(info.get('Id'))
            if (info.get('State', {}).get('Running') is not False
                    or info.get('Config', {}).get('Labels', {}).get(self.restore.LABEL_KEY) != token
                    or info.get('HostConfig', {}).get('RestartPolicy', {}).get('Name', 'no') not in ('', 'no')):
                raise CheckpointError('checkpoint_writer_not_stopped')
            expected_image = self.restore.PG if container.endswith('-postgres') else receipt['target_identity']['server']
            if info['Config'].get('Image') != expected_image:
                raise CheckpointError('checkpoint_container_image_changed')
            self.validate_container_mounts(info, runtime, container.endswith('-postgres'), permanent)
            networks = info.get('NetworkSettings', {}).get('Networks', {})
            if set(networks) != {name} or info.get('HostConfig', {}).get('PortBindings') or info.get('NetworkSettings', {}).get('Ports'):
                raise CheckpointError('checkpoint_container_network_changed')
        if not endpoints.issubset(identifiers) or net[0].get('EnableIPv6', False):
            raise CheckpointError('checkpoint_network_endpoints_changed')
        return runtime, identities

    def adopt(self, token, receipt_path, check_only=False, from_bundle_sha256=None):
        """Import only the known R3 v1 paused shape; helper files remain inert."""
        with self.u.state.locked():
            self.u.record = self.record(token)
            record = self.u.record
            if from_bundle_sha256 is not None:
                return self.transition_bundle(receipt_path, from_bundle_sha256, check_only)
            if record['phase'] != 'rehearsal_paused' or self.permanent(record):
                raise CheckpointError('legacy_paused_rehearsal_required')
            path = Path(receipt_path)
            if record.get('legacy_provenance'):
                self.validate_paused(record)
                if digest(path) != record['legacy_provenance']['receipt_sha256']:
                    raise CheckpointError('legacy_adoption_receipt_changed')
                return {'adopted': True, 'already_adopted': True, 'paused': True}
            basename = record.get('pause_receipt', '')
            if (not isinstance(basename, str) or not re.fullmatch(r'rehearsal-pause-[1-9][0-9]*\.json', basename)
                    or not path.is_absolute() or path != self.root / basename):
                raise CheckpointError('legacy_receipt_path_changed')
            legacy = read_json(path)
            if (legacy.get('version') != 1 or legacy.get('phase') != 'paused'
                    or legacy.get('token') != token or legacy.get('live_token') != record.get('live_token')
                    or legacy.get('server') != LEGACY_SERVER or legacy.get('postgres_image') != self.restore.PG
                    or legacy.get('schema') != 10 or legacy.get('integrity_active') is not False
                    or legacy.get('interrupted_timing_qualified') is not False
                    or legacy.get('resume_automatically') is not False
                    or legacy.get('source_snapshot') != record.get('snapshot')
                    or legacy.get('original_timers') != record.get('timers')
                    or not isinstance(legacy.get('operator_bundle'), str)
                    or not HEX.fullmatch(legacy['operator_bundle'])):
                raise CheckpointError('legacy_pause_receipt_invalid')
            if (set(record.get('timers', {})) != {'devres-staging-backup.timer'}
                    or any(v not in ('active', 'inactive') for v in record['timers'].values())):
                raise CheckpointError('legacy_timer_intent_invalid')
            live = record['live_token']
            if not isinstance(live, str) or not TOKEN.fullmatch(live):
                raise CheckpointError('legacy_clone_token_invalid')
            dataset = 'cachepool/devres-staging-restore-' + live
            runtime = Path('/tmp') / ('devres-staging-restore-' + live)
            context = runtime / 'postgres/.devres-rehearsal-resume-context-2'
            private_directory(context)
            manifest = read_json(context / 'manifest.json')
            if (manifest.get('version') != 1 or manifest.get('token') != token
                    or manifest.get('live_token') != live or set(manifest.get('files', {})) != LEGACY_FILES):
                raise CheckpointError('legacy_capsule_manifest_invalid')
            for relative, metadata in manifest['files'].items():
                data = read_bytes(context / relative)
                expected_mode, expected_gid = ((0o640, 65532) if relative.startswith(('config/', 'tls/'))
                                               else (0o700, 0) if relative in ('pause-helper.py', 'resume-controller.py')
                                               else (0o600, 0))
                if (not isinstance(metadata, dict) or metadata.get('uid') != 0
                        or metadata.get('gid') != expected_gid
                        or metadata.get('mode') != expected_mode
                        or metadata.get('bytes') != len(data)
                        or metadata.get('sha256') != hashlib.sha256(data).hexdigest()):
                    raise CheckpointError('legacy_capsule_integrity_changed')
            if read_bytes(context / 'owner').decode() != live:
                raise CheckpointError('legacy_capsule_owner_changed')
            links = {'previous_pause_receipt_sha256': 'previous-pause-receipt.json',
                     'resume_controller_sha256': 'resume-controller.py',
                     'resume_receipt_sha256': 'current-resume-receipt.json'}
            for key, relative in links.items():
                if legacy.get(key) != digest(context / relative):
                    raise CheckpointError('legacy_receipt_chain_changed')
            previous = read_json(context / 'previous-pause-receipt.json')
            if previous.get('token') != token or previous.get('live_token') != live:
                raise CheckpointError('legacy_previous_receipt_identity_changed')
            current_resume = read_json(context / 'current-resume-receipt.json')
            if (current_resume.get('previous_attempt_receipt_sha256') != digest(context / 'previous-resume-receipt.json')
                    or current_resume.get('controller_sha256') != digest(context / 'resume-controller.py')):
                raise CheckpointError('legacy_previous_receipt_chain_changed')
            before = read_json(context / 'journal-before-pause.json')
            if before.get('token') != token or before.get('live_token') != live or before.get('snapshot') != record['snapshot']:
                raise CheckpointError('legacy_capsule_journal_changed')
            slots = {'parent': dataset, '/postgres': dataset + '/postgres', '/evidence': dataset + '/evidence'}
            def guids(key, value):
                mapping = value.get(key)
                if not isinstance(mapping, dict) or set(mapping) != set(slots) or any(
                        not isinstance(v, str) or not v.isdigit() for v in mapping.values()):
                    raise CheckpointError('legacy_guid_map_invalid')
                return {slots[k]: v for k, v in mapping.items()}
            imported = {'version': 2, 'legacy': True, 'token': token, 'live_token': live,
                        'dataset': dataset, 'dataset_guids': guids('dataset_guids', legacy),
                        'checkpoint': legacy['checkpoint'], 'checkpoint_guids': guids('checkpoint_guids', legacy),
                        'checkpoint_hold': legacy['checkpoint_hold'],
                        'target_identity': {'server': LEGACY_SERVER}}
            if legacy['checkpoint_hold'] != 'devres-rehearsal-paused':
                raise CheckpointError('legacy_checkpoint_hold_invalid')
            _, legacy_containers = self.validate_storage(record, imported)
            self.clean_postgres(runtime / 'postgres')
            for child in ('', '/postgres', '/evidence'):
                source = self.u.dataset + child + '@' + record['snapshot']
                holds = self.u.run(['zfs', 'holds', '-H', source]).splitlines()
                if not any(len(row.split('\t')) >= 2 and row.split('\t')[1] == self.u.hold for row in holds):
                    raise CheckpointError('legacy_source_hold_missing')
            candidate = read_bytes(context / 'config/backend.toml').decode()
            parsed = tomllib.loads(candidate)
            old_url = self.u.source_prefix + LEGACY_VERSION + '/source.tar.gz'
            if parsed.get('source', {}).get('url') != old_url or any(parsed[c].get('enabled') is not False for c in self.restore.COLLECTORS):
                raise CheckpointError('legacy_candidate_configuration_changed')
            candidate = candidate.replace(old_url, self.u.source_prefix + self.u.target_version + '/source.tar.gz')
            parsed['source']['url'] = self.u.source_prefix + self.u.target_version + '/source.tar.gz'
            if tomllib.loads(candidate) != parsed:
                raise CheckpointError('legacy_source_configuration_change_invalid')
            original = read_bytes(context / 'original-config.toml')
            if (original != read_bytes(self.root / 'original-config.toml')
                    or original != read_bytes(self.u.private / 'backend.toml')):
                raise CheckpointError('legacy_original_configuration_changed')
            expected_candidate = tomllib.loads(self.restore.paused_config(original.decode()))
            expected_candidate['source']['url'] = self.u.source_prefix + self.u.target_version + '/source.tar.gz'
            if tomllib.loads(candidate) != expected_candidate:
                raise CheckpointError('legacy_candidate_configuration_changed')
            self.validate_serving_pair(record, original.decode())
            self.u.safe()
            # The daily timer may have reactivated on reboot. Stop only the
            # timer after excluding an in-flight backup, retaining recorded intent.
            service = ['systemctl', 'show', '-p', 'ActiveState', '--value', 'devres-staging-backup.service']
            if self.u.run(service).strip() not in ('inactive', 'failed'):
                raise CheckpointError('backup_already_running')
            if check_only:
                return {'adopted': False, 'check_passed': True, 'timing_qualified': False}
            self.u.run(['systemctl', 'stop', 'devres-staging-backup.timer'])
            if self.u.run(service).strip() not in ('inactive', 'failed'):
                raise CheckpointError('backup_started_during_checkpoint_admission')
            # Preserve the exact legacy pair before any runtime/config change.
            pre = self.u.snapshot_name('pre-adoption')
            with self.u.maintenance_state.locked():
                self.u.safe_unlocked()
                if self.u.run(service).strip() not in ('inactive', 'failed'):
                    raise CheckpointError('backup_started_during_checkpoint_admission')
                self.validate_storage(record, imported)
                self.clean_postgres(runtime / 'postgres')
                self.u.run(['zfs', 'snapshot', '-r', dataset + '@' + pre])
                self.u.run(['zfs', 'hold', '-r', self.u.hold, dataset + '@' + pre])
            archive = self.root / ('legacy-' + token + '.json')
            if archive.exists():
                raise CheckpointError('legacy_adoption_already_recorded')
            self.u.write(archive, json.dumps({'journal': record, 'receipt': legacy,
                                           'manifest': manifest}, sort_keys=True) + '\n')
            for name, identifier in legacy_containers.items():
                if name.endswith('-postgres'):
                    continue
                current = json.loads(self.u.run(['docker', 'inspect', name]))[0]
                if current.get('Id') != identifier or current.get('State', {}).get('Running') is not False:
                    raise CheckpointError('checkpoint_container_identity_changed')
                self.u.run(['docker', 'rm', identifier])
            runtime.mkdir(mode=0o700, exist_ok=True)
            os.chmod(runtime, 0o700)
            self.u.write(runtime / 'owner', live)
            for folder in ('config', 'tls'):
                destination = runtime / folder
                destination.mkdir(mode=0o750, exist_ok=True)
                info = destination.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o027:
                    raise CheckpointError('legacy_runtime_directory_changed')
                os.chown(destination, os.geteuid(), 65532)
                os.chmod(destination, 0o750)
            for relative in CAPSULE_FILES:
                if relative == 'original-config.toml':
                    continue
                data = candidate if relative == 'config/backend.toml' else read_bytes(context / relative).decode()
                destination = runtime / relative
                if destination.exists() and read_bytes(destination, private=False) != read_bytes(context / relative):
                    raise CheckpointError('legacy_runtime_content_changed')
                self.u.write(destination, data, mode=0o640)
                os.chown(destination, os.geteuid(), 65532)
            drill = self.u.drill(record['snapshot'], schema=10, private=self.u.private,
                                 token=live, config_text=candidate, clone_quota='512G',
                                 resource_profile='upgrade')
            drill.root = runtime
            drill.postgres_started = False
            drill.backend_started = False
            self.u.save(offline_command='migrate-storage', checkpoint_kind='rehearsal',
                        live_kind='restore', pause_scope='rehearsal',
                        resource_profile='upgrade',
                        legacy_provenance={'receipt_sha256': digest(path),
                                           'bundle_sha256': legacy['operator_bundle'],
                                           'server': LEGACY_SERVER, 'pre_adoption_snapshot': pre},
                        target_identity=self.u.identity())
            # checkpoint() needs no running PG: stop is idempotent for the exact
            # legacy PostgreSQL container, or use an already-clean stopped pair.
            self.checkpoint(drill, 'migrate-storage')
            return {'adopted': True, 'paused': True, 'timing_qualified': False}

    def transition_bundle(self, receipt_path, from_bundle_sha256, check_only):
        """Rebind one clean formal rehearsal to reviewed same-image code only."""
        record = self.u.record
        if (record['phase'] != 'rehearsal_paused' or self.permanent(record)
                or record.get('timing_qualified') is not False):
            raise CheckpointError('formal_paused_rehearsal_required')
        if not isinstance(from_bundle_sha256, str) or not HEX.fullmatch(from_bundle_sha256):
            raise CheckpointError('invalid_previous_bundle_digest')
        current = self.u.identity()
        path = Path(receipt_path)
        receipt = self.validate_paused(record)
        old = receipt['target_identity']
        history = record.get('bundle_transitions', [])
        if not isinstance(history, list):
            raise CheckpointError('invalid_bundle_transition_history')
        already = False
        if old.get('bundle_sha256') == current.get('bundle_sha256'):
            if not history or not isinstance(history[-1], dict):
                raise CheckpointError('previous_bundle_digest_mismatch')
            previous = history[-1]
            if (previous.get('from_bundle_sha256') != from_bundle_sha256
                    or previous.get('to_bundle_sha256') != current['bundle_sha256']
                    or str(path) != previous.get('from_receipt')
                    or digest(path) != previous.get('from_receipt_sha256')
                    or receipt.get('bundle_transition') != previous):
                raise CheckpointError('previous_bundle_transition_mismatch')
            already = True
        elif (old.get('bundle_sha256') != from_bundle_sha256
              or not path.is_absolute() or path != Path(record['pause_receipt'])):
            raise CheckpointError('previous_bundle_digest_mismatch')
        if ({key: value for key, value in old.items() if key != 'bundle_sha256'} !=
                {key: value for key, value in current.items() if key != 'bundle_sha256'}):
            raise CheckpointError('bundle_transition_contract_changed')
        capsule = Path(receipt['capsule'])
        original = read_bytes(capsule / 'original-config.toml')
        if original != read_bytes(self.root / 'original-config.toml'):
            raise CheckpointError('checkpoint_original_configuration_changed')
        self.validate_serving_pair(record, original.decode())
        runtime = Path('/tmp') / ('devres-staging-restore-' + record['live_token'])
        candidate = read_bytes(capsule / 'config/backend.toml')
        expected = tomllib.loads(self.restore.paused_config(original.decode()))
        expected['source']['url'] = current['source_url']
        if tomllib.loads(candidate.decode()) != expected:
            raise CheckpointError('bundle_transition_configuration_changed')
        for relative in CAPSULE_FILES:
            if relative == 'original-config.toml':
                continue
            if read_bytes(runtime / relative, private=False) != read_bytes(capsule / relative):
                raise CheckpointError('checkpoint_runtime_content_changed')
            if relative.startswith('tls/') and read_bytes(runtime / relative, private=False) != read_bytes(
                    self.u.private / Path(relative).name, private=False):
                raise CheckpointError('checkpoint_transport_identity_changed')
        self.u.safe()
        service = ['systemctl', 'show', '-p', 'ActiveState', '--value', 'devres-staging-backup.service']
        if self.u.run(service).strip() not in ('inactive', 'failed'):
            raise CheckpointError('backup_already_running')
        if already or check_only:
            return {'adopted': already, 'already_adopted': already, 'check_passed': True,
                    'paused': True, 'timing_qualified': False}
        self.u.run(['systemctl', 'stop', 'devres-staging-backup.timer'])
        if self.u.run(service).strip() not in ('inactive', 'failed'):
            raise CheckpointError('backup_started_during_checkpoint_admission')
        provenance = {'from_bundle_sha256': from_bundle_sha256,
                      'to_bundle_sha256': current['bundle_sha256'],
                      'from_receipt': str(path), 'from_receipt_sha256': digest(path),
                      'from_checkpoint': receipt['checkpoint']}
        archive = self.root / ('bundle-transition-' + receipt['checkpoint'] + '-' + current['bundle_sha256'][:12] + '.json')
        if archive.exists():
            raise CheckpointError('bundle_transition_archive_exists')
        self.u.write(archive, json.dumps({'version': 1, 'journal': record,
                                        'receipt': receipt, 'provenance': provenance}, sort_keys=True) + '\n')
        drill = self.u.drill(record['snapshot'], schema=10, private=self.u.private,
                             token=record['live_token'], config_text=candidate.decode(),
                             clone_quota='512G', resource_profile=receipt['resource_profile'])
        drill.root, drill.postgres_started, drill.backend_started = runtime, False, False
        try:
            self.checkpoint(drill, receipt['command'], completed=receipt['command_completed'],
                            provenance=provenance)
        except Exception:
            self.u.save('rehearsal_preserved_failed', timing_qualified=False)
            raise
        return {'adopted': True, 'bundle_transition': True, 'paused': True, 'timing_qualified': False}

    def retirement_inventory(self, record):
        """Prove one clean rehearsal and retain every existing recovery object."""
        if (record.get('phase') != 'rehearsal_paused' or self.permanent(record)
                or record.get('checkpoint_kind') != 'rehearsal'
                or record.get('resource_profile') != 'upgrade'
                or record.get('timing_qualified') is not False
                or any(key in record for key in ('deadline_at', 'watchdog_timer', 'mode'))):
            raise CheckpointError('formal_paused_rehearsal_required')
        if record.get('target_identity') != self.u.identity():
            raise CheckpointError('checkpoint_target_identity_changed')
        if (not isinstance(record.get('timers'), dict)
                or set(record['timers']) != {'devres-staging-backup.timer'}
                or any(value not in ('active', 'inactive') for value in record['timers'].values())):
            raise CheckpointError('retirement_timer_intent_invalid')
        receipt = self.validate_paused(record)
        original = read_bytes(Path(receipt['capsule']) / 'original-config.toml')
        if original != read_bytes(self.root / 'original-config.toml'):
            raise CheckpointError('checkpoint_original_configuration_changed')
        self.validate_serving_pair(record, original.decode())
        runtime = Path('/tmp') / ('devres-staging-restore-' + record['live_token'])
        candidate = read_bytes(Path(receipt['capsule']) / 'config/backend.toml')
        expected = tomllib.loads(self.restore.paused_config(original.decode()))
        expected['source']['url'] = self.u.identity()['source_url']
        if tomllib.loads(candidate.decode()) != expected:
            raise CheckpointError('retirement_configuration_changed')
        for relative in CAPSULE_FILES:
            if relative == 'original-config.toml':
                continue
            if read_bytes(runtime / relative, private=False) != read_bytes(Path(receipt['capsule']) / relative):
                raise CheckpointError('checkpoint_runtime_content_changed')
            if relative.startswith('tls/') and read_bytes(runtime / relative, private=False) != read_bytes(
                    self.u.private / Path(relative).name, private=False):
                raise CheckpointError('checkpoint_transport_identity_changed')
        self.restore.validate_snapshot(record['snapshot'])
        source_guids = {}
        for child in ('', '/postgres', '/evidence'):
            snapshot = self.u.dataset + child + '@' + record['snapshot']
            guid = self.u.run(['zfs', 'get', '-H', '-o', 'value', 'guid', snapshot]).strip()
            holds = self.u.run(['zfs', 'holds', '-H', snapshot]).splitlines()
            if (not guid.isdigit() or not any(len(row.split('\t')) >= 2 and row.split('\t')[1] == self.u.hold
                                            for row in holds)):
                raise CheckpointError('retirement_source_snapshot_changed')
            source_guids[snapshot] = guid
        self.u.safe_unlocked()
        return receipt, {'dataset': receipt['dataset'], 'dataset_guids': receipt['dataset_guids'],
                         'checkpoint': receipt['checkpoint'], 'checkpoint_guids': receipt['checkpoint_guids'],
                         'checkpoint_hold': receipt['checkpoint_hold'], 'capsule': receipt['capsule'],
                         'source_snapshot_guids': source_guids, 'source_hold': self.u.hold}

    def retire(self, token):
        """Release the operation fence without discarding paused rehearsal data."""
        with self.u.state.locked():
            self.u.record = self.record(token)
            record = self.u.record
            archive_path = self.root / ('retired-' + token + '.json')
            already = record.get('phase') == 'rehearsal_retired'
            if already:
                retirement = record.get('retirement')
                if (not isinstance(retirement, dict) or retirement.get('archive') != str(archive_path)
                        or retirement.get('sha256') != digest(archive_path)):
                    raise CheckpointError('retirement_archive_changed')
                archive = read_json(archive_path)
                paused_record = archive.get('record')
                if not isinstance(paused_record, dict) or paused_record.get('token') != token:
                    raise CheckpointError('retirement_archive_changed')
                expected = {**paused_record, 'phase': 'rehearsal_retired', 'timing_qualified': False,
                            'retirement': retirement,
                            'retirement_timer_restore_pending': record.get('retirement_timer_restore_pending')}
                if record != expected or type(record.get('retirement_timer_restore_pending')) is not bool:
                    raise CheckpointError('retired_rehearsal_identity_changed')
            else:
                paused_record = record
                archive = read_json(archive_path) if archive_path.exists() or archive_path.is_symlink() else None
            # Follow the upgrade -> maintenance lock order used by snapshots.
            with self.u.maintenance_state.locked():
                receipt, inventory = self.retirement_inventory(paused_record)
                payload = {'version': 1, 'token': token, 'record': paused_record,
                           'receipt': receipt, 'receipt_sha256': digest(Path(paused_record['pause_receipt'])),
                           'retained_resources': inventory, 'timing_qualified': False}
                if archive is not None and archive != payload:
                    raise CheckpointError('retirement_archive_changed')
                if archive is None:
                    self.u.write(archive_path, json.dumps(payload, sort_keys=True) + '\n')
                if not already:
                    self.u.save('rehearsal_retired', timing_qualified=False,
                                retirement={'archive': str(archive_path), 'sha256': digest(archive_path)},
                                retirement_timer_restore_pending=True)
            if self.u.record['retirement_timer_restore_pending']:
                self.u.restore_timers()
                self.u.save(retirement_timer_restore_pending=False)
            return {'retired': True, 'already_retired': already, 'retained_pair': True,
                    'timing_qualified': False, 'timers_restored': True, 'serving_changed': False}

    def validate_dataset_tree(self, record, receipt):
        root = receipt['dataset']
        rows = self.u.run(['zfs', 'list', '-Hp', '-r', '-t', 'filesystem', '-o',
                           'name,guid,origin,mountpoint,canmount,quota,' + self.restore.OWNER_KEY, root]).splitlines()
        tree = {}
        for line in rows:
            fields = line.split('\t')
            if len(fields) != 7 or fields[0] in tree:
                raise CheckpointError('checkpoint_dataset_tree_invalid')
            tree[fields[0]] = fields[1:]
        if set(tree) != set(receipt['dataset_guids']):
            raise CheckpointError('checkpoint_dataset_tree_changed')
        if self.permanent(record):
            self.u.tool.metrics()  # Existing strict permanent quota/layout contract.
            for child in ('postgres', 'evidence'):
                if tree[root + '/' + child][2:4] != ['/mnt/devres-staging/' + child, 'on']:
                    raise CheckpointError('checkpoint_permanent_mount_changed')
            return
        runtime = Path('/tmp') / ('devres-staging-restore-' + record['live_token'])
        if tree[root][1:5] != ['-', 'none', 'off', str(512 * 1024**3)]:
            raise CheckpointError('checkpoint_clone_profile_changed')
        for child in ('postgres', 'evidence'):
            fields = tree[root + '/' + child]
            if (fields[1:4] != [self.u.dataset + '/' + child + '@' + record['snapshot'], str(runtime / child), 'on']
                    or fields[-1] != record['live_token']):
                raise CheckpointError('checkpoint_clone_origin_changed')

    def validate_container_mounts(self, info, runtime, postgres, permanent):
        expected = ({'/var/lib/postgresql': ('postgres', True)} if postgres else {
            '/data': ('evidence', True), '/etc/devres/config': ('config', False),
            '/etc/devres/tls': ('tls', False)})
        found = {}
        for mount in info.get('Mounts', []):
            if mount.get('Type') == 'tmpfs' and mount.get('Destination') == '/tmp':
                continue
            destination = mount.get('Destination')
            if destination not in expected or destination in found or mount.get('Type') != 'bind':
                raise CheckpointError('checkpoint_container_mount_changed')
            relative, writable = expected[destination]
            allowed = {str(runtime / relative)}
            if permanent and relative in ('postgres', 'evidence'):
                allowed.add('/mnt/devres-staging/' + relative)
            if mount.get('Source') not in allowed or mount.get('RW') is not writable:
                raise CheckpointError('checkpoint_container_mount_changed')
            found[destination] = True
        if set(found) != set(expected):
            raise CheckpointError('checkpoint_container_mount_changed')

    def attach(self, record, receipt):
        runtime, containers = self.validate_storage(record, receipt)
        capsule = Path(receipt['capsule'])
        self.verify_capsule(capsule)
        if not runtime.exists():
            runtime.mkdir(mode=0o700)
        os.chmod(runtime, 0o700)
        if not (runtime / 'owner').exists():
            self.u.write(runtime / 'owner', record['live_token'])
        for folder in ('config', 'tls'):
            destination = runtime / folder
            destination.mkdir(mode=0o750, exist_ok=True)
            info = destination.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o027:
                raise CheckpointError('checkpoint_runtime_directory_changed')
            os.chown(destination, os.geteuid(), 65532)
            os.chmod(destination, 0o750)
        for relative in CAPSULE_FILES:
            if relative == 'original-config.toml':
                continue
            destination = runtime / relative
            if destination.exists() and read_bytes(destination, private=False) != read_bytes(capsule / relative):
                raise CheckpointError('checkpoint_runtime_content_changed')
            self.u.write(destination, read_bytes(capsule / relative).decode('utf-8'), mode=0o640)
            os.chown(destination, os.geteuid(), 65532)
        for name, identifier in containers.items():
            current = json.loads(self.u.run(['docker', 'inspect', name]))[0]
            if current.get('Id') != identifier or current.get('State', {}).get('Running') is not False:
                raise CheckpointError('checkpoint_container_identity_changed')
            self.u.run(['docker', 'rm', identifier])
        for child in ('postgres', 'evidence'):
            destination = runtime / child
            if self.permanent(record):
                if not destination.exists() and not destination.is_symlink():
                    destination.symlink_to(Path('/mnt/devres-staging') / child, target_is_directory=True)
                if not destination.is_symlink() or os.readlink(destination) != '/mnt/devres-staging/' + child:
                    raise CheckpointError('checkpoint_permanent_mount_changed')
            else:
                dataset = receipt['dataset'] + '/' + child
                mountpoint = self.u.run(['zfs', 'get', '-H', '-o', 'value', 'mountpoint', dataset]).strip()
                if mountpoint != str(destination):
                    raise CheckpointError('checkpoint_mountpoint_changed')
                self.u.run(['zfs', 'mount', dataset]) if not destination.exists() else None
        cls = self.u.live if self.permanent(record) else self.u.drill
        drill = cls(record['snapshot'], schema=10, private=self.u.private, token=record['live_token'],
                    config_text=read_bytes(capsule / 'config/backend.toml').decode(),
                    resource_profile=receipt['resource_profile'],
                    **({} if self.permanent(record) else {'clone_quota': '512G'}))
        drill.root = runtime
        drill.runtime_owned = True
        drill.network = True
        drill.containers = []
        drill.datasets = [] if self.permanent(record) else list(receipt['dataset_guids'])
        return drill

    def resume(self, token):
        with self.u.state.locked():
            self.u.record = self.record(token)
            record = self.u.record
            if self.permanent(record) and self.u.deadline_due(record, time.time):
                return self.u._rollback()
            if record['phase'] in PRESERVED - PAUSED:
                self.qualify_failed(record)
                record = self.u.record
            self.eligible(record)
            permanent = self.permanent(record)
            if permanent and self.u.deadline_due(record, time.time):
                return self.u._rollback()
            receipt = self.validate_paused(record)
            if receipt['target_identity'] != self.u.identity():
                raise CheckpointError('checkpoint_target_identity_changed')
            self.validate_serving_pair(record, read_bytes(Path(receipt['capsule']) / 'original-config.toml').decode())
            self.u.safe()
            if permanent:
                self.u.arm_watchdog()
            self.u.record_driver()
            with control_lock(self.root):
                self.u.save('checkpoint_resuming', resume_started_epoch=time.time(),
                            timing_qualified=False, driver_stopped=False)
            drill = None
            try:
                drill = self.attach(record, receipt)
                drill.start_postgres()
                active = drill.psql('SELECT active FROM devres_integrity_control WHERE singleton')
                if active not in ('t', 'f'):
                    raise CheckpointError('checkpoint_integrity_state_invalid')
                command = receipt['command']
                start = COMMANDS.index(command)
                # Activation may have committed immediately before cancellation.
                # Verify the active pair instead of attempting to migrate it again.
                if active == 't':
                    self.offline(drill, 'verify-storage', self.u.wall_remaining() if permanent else None)
                else:
                    pending = list(COMMANDS[start:])
                    if command == 'activate-storage':
                        pending.insert(0, 'verify-storage')
                    for current in pending:
                        self.offline(drill, current, self.u.wall_remaining() if permanent else None)
                if permanent:
                    self.u.clean_stop(drill)
                    drill.cleanup()
                    self.u.start_candidate()
                    return {'candidate_ready': True, 'collectors_paused': True}
                return self.u.complete_resumed_rehearsal(drill)
            except Paused:
                return {'paused': True}
            except Exception as failure:
                if permanent:
                    self.u._rollback()
                elif drill is not None:
                    self.preserve_failure(drill, allow_stop=not getattr(failure, 'unsafe_cleanup', False))
                else:
                    self.u.save('rehearsal_preserved_failed', timing_qualified=False)
                raise

    def qualify_failed(self, record):
        """An explicit retry may checkpoint only an already-clean exact pair."""
        permanent = self.permanent(record)
        if permanent and self.u.deadline_due(record, time.time):
            raise CheckpointError('upgrade_deadline_exceeded')
        guids = record.get('live_dataset_guids')
        if (not isinstance(guids, dict) or record.get('target_identity') != self.u.identity()
                or record.get('resource_profile') != ('direct' if record.get('mode') == 'direct' else 'upgrade')):
            raise CheckpointError('failed_checkpoint_identity_unavailable')
        original = read_bytes(self.root / 'original-config.toml').decode()
        self.validate_serving_pair(record, original)
        dataset = self.u.dataset if permanent else 'cachepool/devres-staging-restore-' + record['live_token']
        expected = {'dataset': dataset, 'dataset_guids': guids,
                    'target_identity': record['target_identity']}
        runtime, _ = self.validate_storage(record, expected, checkpoint_required=False)
        candidate = read_bytes(runtime / 'config/backend.toml', private=False).decode()
        parsed = tomllib.loads(self.restore.paused_config(original))
        parsed['source']['url'] = self.u.source_prefix + self.u.target_version + '/source.tar.gz'
        if tomllib.loads(candidate) != parsed:
            raise CheckpointError('failed_checkpoint_configuration_changed')
        for relative in CAPSULE_FILES:
            if not relative.startswith('tls/'):
                continue
            if read_bytes(runtime / relative, private=False) != read_bytes(self.u.private / Path(relative).name, private=False):
                raise CheckpointError('failed_checkpoint_transport_identity_changed')
        self.clean_postgres(runtime / 'postgres')
        self.u.safe()
        if permanent:
            self.u.arm_watchdog()
        cls = self.u.live if permanent else self.u.drill
        drill = cls(record['snapshot'], schema=10, private=self.u.private,
                    token=record['live_token'], config_text=candidate,
                    resource_profile=record['resource_profile'],
                    **({} if permanent else {'clone_quota': '512G'}))
        drill.root, drill.postgres_started, drill.backend_started = runtime, False, False
        command = record.get('offline_command') or 'activate-storage'
        self.u.save(offline_command=command)
        try:
            self.checkpoint(drill, command)
        except Exception:
            self.u.save('upgrade_preserved_failed' if permanent else 'rehearsal_preserved_failed')
            raise

    def preserve_failure(self, drill, allow_stop=True):
        # No destructive cleanup; unknown ownership is never a deletion license.
        try:
            if allow_stop:
                self.u.clean_stop(drill)
        finally:
            self.u.save('upgrade_preserved_failed' if self.permanent(self.u.record) else 'rehearsal_preserved_failed',
                        timing_qualified=False)
