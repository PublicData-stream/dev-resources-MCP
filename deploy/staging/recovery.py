#!/usr/bin/env python3
"""Token-bound recovery of an orphaned, disposable staging rehearsal only.

This does not roll back a real cutover, change serving, release snapshot holds, or
delete permanent evidence. Ambiguous ownership leaves recovery incomplete.
"""
import contextlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import time


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('devres_recovery_upgrade', HERE / 'upgrade.py')
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)
op, restore, maintenance = upgrade.op, upgrade.restore, upgrade.m
OLD_REHEARSAL_SERVER = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:0c8592f7323ece2c11d4b9dcc4f5cae48d681c6305d5c2575a09e805b47a6997'
HEX = re.compile(r'[0-9a-f]{64}\Z')


class RecoveryError(RuntimeError):
    """Fixed codes only; inspected process/configuration contents stay private."""


def private_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 1024 * 1024):
        os.close(fd)
        raise RecoveryError('unsafe_recovery_file')
    return fd


class Processes:
    """Linux PID identity plus pidfds, so PID reuse cannot redirect a signal."""

    def holders(self, lock):
        info = lock.stat()
        key = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
        found = []
        for line in Path('/proc/locks').read_text().splitlines():
            fields = line.split()
            if len(fields) != 8 or fields[1:4] != ['FLOCK', 'ADVISORY', 'WRITE']:
                continue
            device = fields[5].split(':')
            if len(device) == 3 and (int(device[0], 16), int(device[1], 16), int(device[2])) == key:
                found.append(int(fields[4]))
        return found

    def identity(self, pid):
        root = Path('/proc') / str(pid)
        try:
            fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
            uid = next(line.split()[1:] for line in (root / 'status').read_text().splitlines()
                       if line.startswith('Uid:'))
            argv = (root / 'cmdline').read_bytes().split(b'\0')
            return {'pid': pid, 'start': fields[19], 'ppid': int(fields[1]),
                    'uid': [int(value) for value in uid],
                    'argv': [value.decode('utf-8') for value in argv if value],
                    'exe': os.readlink(root / 'exe')}
        except FileNotFoundError:
            return None
        except (OSError, ValueError, IndexError, StopIteration, UnicodeError) as error:
            raise RecoveryError('rehearsal_process_identity_unavailable') from error

    def open(self, pid):
        try:
            return os.pidfd_open(pid)
        except (OSError, AttributeError) as error:
            raise RecoveryError('rehearsal_pidfd_unavailable') from error

    def send(self, fd, sig):
        try:
            signal.pidfd_send_signal(fd, sig)
        except ProcessLookupError:
            pass
        except (OSError, AttributeError) as error:
            raise RecoveryError('rehearsal_signal_failed') from error

    def close(self, fd):
        os.close(fd)


class Recovery:
    def __init__(self, run=None, state_root=None, tmp_root='/tmp', processes=None,
                 clock=time.monotonic, sleep=time.sleep, lock_timeout=10):
        self.run = run or op.run
        self.state_root = Path(state_root if state_root is not None else op.STATE)
        self.root = self.state_root / 'upgrade'
        self.receipt_path = self.root / 'rehearsal-abort.json'
        self.tmp_root = Path(tmp_root)
        self.processes = processes or Processes()
        self.clock, self.sleep, self.lock_timeout = clock, sleep, lock_timeout
        self.receipt = None

    def save_receipt(self, **updates):
        self.receipt.update(updates)
        op.write(self.receipt_path, json.dumps(self.receipt, sort_keys=True) + '\n')

    def load_receipt(self):
        try:
            fd = private_file(self.receipt_path)
        except FileNotFoundError:
            return None
        with os.fdopen(fd) as stream:
            try:
                value = json.load(stream)
            except (ValueError, TypeError) as error:
                raise RecoveryError('invalid_rehearsal_abort_receipt') from error
        if not isinstance(value, dict) or value.get('version') != 1:
            raise RecoveryError('invalid_rehearsal_abort_receipt')
        return value

    @contextlib.contextmanager
    def lock(self, name, wait=False):
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RecoveryError('unsafe_recovery_directory')
        fd = os.open(self.root / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise RecoveryError('unsafe_recovery_lock')
            started = self.clock()
            for attempt in range(101):
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as error:
                    if not wait or self.clock() - started >= self.lock_timeout or attempt == 100:
                        raise RecoveryError('rehearsal_recovery_lock_busy') from error
                    self.sleep(0.1)
            yield
        finally:
            os.close(fd)

    def record(self, token):
        value = upgrade.read_record(self.state_root)
        if not value or value['token'] != token:
            raise RecoveryError('rehearsal_token_mismatch')
        if (value['phase'] not in ('rehearsing', 'rehearsal_failed')
                or value.get('backend_drained') or value.get('dataset_guids')
                or value.get('watchdog_timer')):
            raise RecoveryError('disposable_rehearsal_required')
        live = value.get('live_token')
        if not isinstance(live, str) or not upgrade.TOKEN.fullmatch(live):
            if not (self.receipt and self.receipt.get('cleaned') and live is None):
                raise RecoveryError('rehearsal_clone_token_required')
            live = self.receipt['live_token']
        if (not isinstance(value.get('timers'), dict)
                or set(value['timers']) != set(upgrade.TIMERS)
                or any(state not in ('active', 'inactive') for state in value['timers'].values())):
            raise RecoveryError('recorded_rehearsal_timers_required')
        restore.validate_snapshot(value.get('snapshot'))
        return value, live

    def process(self):
        lock = self.root / 'maintenance.lock'
        with os.fdopen(private_file(lock)):
            holders = self.processes.holders(lock)
        if not holders:
            return None
        if len(holders) != 1:
            raise RecoveryError('rehearsal_lock_owner_uncertain')
        identity = self.processes.identity(holders[0])
        arguments = identity.get('argv', []) if identity else []
        allowed = ([str(HERE / 'staging.py'), 'upgrade-rehearse'],
                   ['-I', '-B', str(HERE / 'staging.py'), 'upgrade-rehearse'])
        if (not identity or identity['ppid'] != 1 or identity['uid'] != [0, 0, 0, 0]
                or not arguments or arguments[1:] not in allowed
                or arguments[0] not in ('python3', '/usr/bin/python3')
                or not re.fullmatch(r'/usr/bin/python3(?:\.[0-9]+)?', identity['exe'])
                or not identity['start'].isdigit()):
            raise RecoveryError('orphan_rehearsal_process_required')
        return identity

    def stop_process(self, identity):
        if identity is None:
            return
        fd = self.processes.open(identity['pid'])
        try:
            if self.process() != identity:
                raise RecoveryError('rehearsal_process_identity_changed')
            for sig, seconds in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                current = self.processes.identity(identity['pid'])
                if current is None or current['start'] != identity['start']:
                    return
                if current != identity or self.process() != identity:
                    raise RecoveryError('rehearsal_process_identity_changed')
                self.processes.send(fd, sig)
                started = self.clock()
                for _ in range(seconds * 10):
                    current = self.processes.identity(identity['pid'])
                    if current is None or current['start'] != identity['start']:
                        return
                    if self.clock() - started >= seconds:
                        break
                    self.sleep(0.1)
            raise RecoveryError('rehearsal_process_did_not_exit')
        finally:
            self.processes.close(fd)

    def protected_snapshot(self, record):
        snapshot = maintenance.DATASET + '@' + record['snapshot']
        guid = self.run(['zfs', 'get', '-Hp', '-o', 'value', 'guid', snapshot]).strip()
        holds = self.run(['zfs', 'holds', '-H', snapshot]).splitlines()
        if not guid.isdigit() or not any(row.split('\t')[1:2] == [upgrade.HOLD] for row in holds):
            raise RecoveryError('protected_rehearsal_snapshot_required')
        return guid

    def runtime(self, live):
        name = 'devres-staging-restore-' + live
        root = self.tmp_root / name
        if (not self.tmp_root.is_absolute() or self.tmp_root.resolve() != self.tmp_root
                or Path('/tmp') not in (self.tmp_root, *self.tmp_root.parents)):
            raise RecoveryError('rehearsal_runtime_must_be_below_tmp')
        if root.exists() or root.is_symlink():
            info = root.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise RecoveryError('rehearsal_runtime_ownership_changed')
            with os.fdopen(private_file(root / 'owner')) as stream:
                if stream.read() != live:
                    raise RecoveryError('rehearsal_runtime_ownership_changed')
            if any((root / child).is_symlink() for child in ('postgres', 'evidence', 'config', 'tls')):
                raise RecoveryError('rehearsal_runtime_symlink')
        return name, root

    def datasets(self, name, root, record, live):
        parent = 'cachepool/' + name
        rows = self.run(['zfs', 'list', '-Hp', '-t', 'filesystem,snapshot', '-o',
                         'name,guid,origin,mountpoint,canmount,' + restore.OWNER_KEY]).splitlines()
        found = {}
        for line in rows:
            row = line.split('\t')
            if len(row) != 6:
                raise RecoveryError('rehearsal_dataset_inventory_invalid')
            dataset, guid, origin, mountpoint, canmount, owner = row
            if dataset != parent and not dataset.startswith((parent + '/', parent + '@')):
                continue
            if dataset not in (parent, parent + '/postgres', parent + '/evidence'):
                raise RecoveryError('rehearsal_dataset_tree_changed')
            if owner != live or not guid.isdigit():
                raise RecoveryError('rehearsal_dataset_ownership_changed')
            child = dataset.removeprefix(parent + '/')
            expected = ('-', 'none', 'off') if dataset == parent else (
                maintenance.DATASET + '/' + child + '@' + record['snapshot'], str(root / child), 'on')
            if (origin, mountpoint, canmount) != expected:
                raise RecoveryError('rehearsal_dataset_origin_or_mount_changed')
            found[dataset] = guid
        if found and not root.is_dir():
            raise RecoveryError('rehearsal_runtime_required')
        return found

    def container(self, info, name, root, live):
        identifier = info.get('Id', '')
        role = info.get('Name', '').removeprefix('/').removeprefix(name + '-')
        config, host = info.get('Config', {}), info.get('HostConfig', {})
        if (not HEX.fullmatch(identifier) or info.get('Name') != '/' + name + '-' + role
                or not re.fullmatch(r'postgres|backend|offline-[1-9][0-9]*', role)
                or config.get('Labels', {}).get(restore.LABEL_KEY) != live
                or host.get('NetworkMode') != name or host.get('PortBindings')):
            raise RecoveryError('rehearsal_container_ownership_changed')
        expected = {'/var/lib/postgresql': (str(root / 'postgres'), True)} if role == 'postgres' else {
            '/data': (str(root / 'evidence'), True),
            '/etc/devres/config': (str(root / 'config'), False),
            '/etc/devres/tls': (str(root / 'tls'), False)}
        actual = {}
        for mount in info.get('Mounts', []):
            if mount.get('Type') == 'tmpfs' and mount.get('Destination') == '/tmp':
                continue
            if mount.get('Type') != 'bind' or mount.get('Destination') in actual:
                raise RecoveryError('rehearsal_container_mount_changed')
            actual[mount.get('Destination')] = (mount.get('Source'), mount.get('RW'))
        if actual != expected:
            raise RecoveryError('rehearsal_container_mount_changed')
        image = config.get('Image')
        if image != (restore.PG if role == 'postgres' else OLD_REHEARSAL_SERVER):
            raise RecoveryError('rehearsal_container_image_changed')
        return identifier, role

    def resources(self, record, live):
        name, root = self.runtime(live)
        datasets = self.datasets(name, root, record, live)
        identifiers = set()
        for filt in ('label=' + restore.LABEL_KEY + '=' + live, 'name=^/' + name + '-'):
            identifiers.update(self.run(['docker', 'ps', '-a', '--no-trunc', '--filter', filt,
                                         '--format', '{{.ID}}']).splitlines())
        if len(identifiers) > 8 or any(not HEX.fullmatch(value) for value in identifiers):
            raise RecoveryError('rehearsal_container_inventory_invalid')
        containers = {}
        if identifiers:
            for info in json.loads(self.run(['docker', 'inspect', '--type', 'container', *sorted(identifiers)])):
                identifier, role = self.container(info, name, root, live)
                containers[identifier] = role
            if set(containers) != identifiers or not datasets or not root.is_dir():
                raise RecoveryError('rehearsal_container_inventory_changed')
        network = None
        found = self.run(['docker', 'network', 'ls', '--filter', 'name=^' + name + '$',
                          '--format', '{{.Name}}']).strip()
        if found:
            if found != name:
                raise RecoveryError('rehearsal_network_inventory_changed')
            info = json.loads(self.run(['docker', 'network', 'inspect', name]))[0]
            if (info.get('Name') != name or not info.get('Internal')
                    or info.get('Labels', {}).get(restore.LABEL_KEY) != live
                    or not HEX.fullmatch(info.get('Id', ''))
                    or not set(info.get('Containers', {})).issubset(containers)):
                raise RecoveryError('rehearsal_network_ownership_changed')
            network = info['Id']
        if containers and not network:
            raise RecoveryError('rehearsal_network_required')
        return {'datasets': datasets, 'containers': containers, 'network': network}

    def compatible(self, current):
        original = self.receipt['resources']
        if (any(original['datasets'].get(key) != value for key, value in current['datasets'].items())
                or any(original['containers'].get(key) != value for key, value in current['containers'].items())
                or (current['network'] is not None and current['network'] != original['network'])):
            raise RecoveryError('rehearsal_abort_inventory_changed')

    def cleanup(self, record, live):
        current = self.resources(record, live)
        self.compatible(current)
        name, root = self.runtime(live)
        for identifier, role in sorted(current['containers'].items(),
                                       key=lambda item: (item[1] == 'postgres', item[1] == 'backend')):
            info = json.loads(self.run(['docker', 'inspect', '--type', 'container', identifier]))[0]
            self.container(info, name, root, live)
            self.run(['docker', 'stop', '--time=' + ('120' if role == 'postgres' else '15'), identifier])
            self.run(['docker', 'rm', identifier])
        current = self.resources(record, live)
        self.compatible(current)
        if current['containers']:
            raise RecoveryError('rehearsal_writers_remain')
        if current['network']:
            self.run(['docker', 'network', 'rm', current['network']])
        for dataset in sorted(current['datasets'], key=lambda value: value.count('/'), reverse=True):
            remaining = self.resources(record, live)
            self.compatible(remaining)
            if remaining['datasets'].get(dataset) != current['datasets'][dataset]:
                raise RecoveryError('rehearsal_dataset_identity_changed')
            self.run(['zfs', 'destroy', dataset])
        remaining = self.resources(record, live)
        if remaining != {'datasets': {}, 'containers': {}, 'network': None}:
            raise RecoveryError('rehearsal_cleanup_incomplete')
        if root.exists():
            self.runtime(live)
            for line in Path('/proc/self/mountinfo').read_text().splitlines():
                fields = line.split()
                if len(fields) < 5:
                    raise RecoveryError('rehearsal_mount_inventory_invalid')
                mounted = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4]))
                if mounted == root or root in mounted.parents:
                    raise RecoveryError('rehearsal_runtime_mount_remains')
            shutil.rmtree(root)

    def abort_rehearsal(self, token):
        if not isinstance(token, str) or not upgrade.TOKEN.fullmatch(token):
            raise RecoveryError('invalid_rehearsal_token')
        with self.lock('rehearsal-abort.lock'):
            self.receipt = self.load_receipt()
            if self.receipt and self.receipt.get('token') != token:
                raise RecoveryError('rehearsal_abort_token_mismatch')
            record, live = self.record(token)
            snapshot_guid = self.protected_snapshot(record)
            identity = self.process()
            resources = self.resources(record, live)
            if self.receipt:
                if (self.receipt.get('live_token') != live
                        or self.receipt.get('snapshot_guid') != snapshot_guid
                        or self.receipt.get('timers') != record['timers']):
                    raise RecoveryError('rehearsal_abort_identity_changed')
                self.compatible(resources)
                if identity is not None and identity != self.receipt.get('process'):
                    raise RecoveryError('rehearsal_process_identity_changed')
            else:
                if record['phase'] != 'rehearsing':
                    raise RecoveryError('active_rehearsal_required')
                self.receipt = {'version': 1, 'token': token, 'live_token': live,
                                'snapshot_guid': snapshot_guid, 'process': identity,
                                'resources': resources, 'timers': dict(record['timers']),
                                'cleaned': False, 'complete': False}
                self.save_receipt()
            self.stop_process(identity)
            with self.lock('maintenance.lock', wait=True):
                current, current_live = self.record(token)
                if (current_live != live or current.get('snapshot') != record.get('snapshot')
                        or current['timers'] != self.receipt['timers']):
                    raise RecoveryError('rehearsal_journal_changed')
                self.cleanup(current, live)
                if self.protected_snapshot(current) != snapshot_guid:
                    raise RecoveryError('protected_rehearsal_snapshot_changed')
                self.save_receipt(cleaned=True)
                current.update(phase='rehearsal_failed', live_token=None,
                               rehearsal_abort_token=token)
                maintenance.State(self.root).save(current)
                for timer, state in current['timers'].items():
                    self.run(['systemctl', 'start' if state == 'active' else 'stop', timer])
                self.save_receipt(complete=True)
        return {'rehearsal_aborted': True, 'token': token, 'snapshot_preserved': True,
                'timers_restored': True}


def abort_rehearsal(token):
    if os.geteuid() != 0:
        raise RecoveryError('root_required')
    try:
        return Recovery().abort_rehearsal(token)
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        raise RecoveryError('rehearsal_recovery_state_unavailable') from error
