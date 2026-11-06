#!/usr/bin/env python3
"""Private, owner-scoped schema-nine to schema-ten staging upgrade.

No provider calls or shared-edge changes occur here. Public acceptance is a
separate operator gate before ``finalize`` restores the original schedules.
"""
import contextlib
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import stat
import time
import tomllib


HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location('devres_upgrade_' + name, HERE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


op = module('staging')
restore = module('restore')
m = module('maintenance')
checkpoint = module('checkpoint')
VERSION = '0.1.0-build.d373818b'
OLD_VERSION = '0.1.0-build.27d35cd6'
SOURCE = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/'
TERMINAL = {'rehearsed', 'rehearsed_unqualified', 'rehearsal_failed', 'rehearsal_retired', 'complete', 'rolled_back'}
TIMERS = ('devres-staging-backup.timer',)
HOLD = 'devres-upgrade-protected'
TOKEN = re.compile(r'[0-9a-f]{24}\Z')
WATCHDOG = 'devres-staging-upgrade-expire@'
BUNDLE_FILES = ('staging.py', 'restore.py', 'upgrade.py', 'maintenance.py', 'recovery.py', 'checkpoint.py')
SAFETY_LOCK_WAIT_SECONDS = 10
SAFETY_LOCK_POLL_SECONDS = 0.1


class UpgradeError(RuntimeError):
    """Fixed diagnostic codes only; command output and configuration stay private."""


def rehearsal_identity():
    """Bind measured timing to the exact reviewed executable bundle and profile."""
    hashes = {}
    for name in BUNDLE_FILES:
        descriptor = os.open(HERE / name, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise UpgradeError('unsafe_upgrade_bundle')
            with os.fdopen(descriptor, 'rb', closefd=False) as source:
                data = source.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise UpgradeError('unsafe_upgrade_bundle')
            hashes[name] = hashlib.sha256(data).hexdigest()
        finally:
            os.close(descriptor)
    bundle = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    return {'server': restore.SERVER, 'version': VERSION,
            'source_url': SOURCE + VERSION + '/source.tar.gz',
            'bundle_sha256': bundle,
            'resource_profile': {'name': 'upgrade', **restore.RESOURCE_PROFILES['upgrade']},
            'offline_options': dict(restore.OFFLINE_OPTIONS)}


def journal_root(state_root=None):
    return Path(state_root if state_root is not None else op.STATE) / 'upgrade'


def read_record(state_root=None):
    path = journal_root(state_root) / 'state.json'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 1024 * 1024:
            raise UpgradeError('unsafe_upgrade_journal')
        with os.fdopen(fd, closefd=False) as stream:
            value = json.load(stream)
        if value.get('version') != 1 or not TOKEN.fullmatch(value.get('token', '')) or not isinstance(value.get('phase'), str):
            raise UpgradeError('invalid_upgrade_journal')
        return value
    except (ValueError, TypeError) as error:
        raise UpgradeError('invalid_upgrade_journal') from error
    finally:
        os.close(fd)


def acceptance(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 16384:
            raise UpgradeError('unsafe_acceptance_receipt')
        with os.fdopen(fd, closefd=False) as stream:
            return json.load(stream)
    finally:
        os.close(fd)


def active(state_root=None):
    value = read_record(state_root)
    return bool(value and value['phase'] not in TERMINAL)


def owned_containers(state_root=None):
    value = read_record(state_root)
    token = value.get('live_token') if value else None
    if token is None:
        return None
    if not TOKEN.fullmatch(token):
        raise UpgradeError('invalid_upgrade_container_owner')
    return {'token': token, 'label': restore.LABEL_KEY,
            'prefix': 'devres-staging-restore-' + token}


def target_config(text, paused=False):
    before = tomllib.loads(text)
    old = SOURCE + OLD_VERSION + '/source.tar.gz'
    new = SOURCE + VERSION + '/source.tar.gz'
    if before.get('source', {}).get('url') not in (old, new):
        raise UpgradeError('unexpected_corresponding_source')
    result = text.replace(old, new)
    expected = json.loads(json.dumps(before))
    expected['source']['url'] = new
    if tomllib.loads(result) != expected:
        raise UpgradeError('unexpected_source_configuration_change')
    return restore.paused_config(result) if paused else result


def process_start(pid):
    """Linux process birth identity; a reused PID must never receive a signal."""
    if type(pid) is not int or pid < 2:
        raise UpgradeError('invalid_upgrade_driver_identity')
    try:
        value = (Path('/proc') / str(pid) / 'stat').read_text()
    except FileNotFoundError:
        return None
    fields = value.rsplit(') ', 1)[-1].split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise UpgradeError('invalid_upgrade_driver_identity')
    return fields[19]


def terminate_driver(record, lock_path=None):
    """Stop only the overdue direct driver's exact Linux process instance."""
    pid, born = record.get('driver_pid'), record.get('driver_start')
    if record.get('driver_boot_id') and record['driver_boot_id'] != checkpoint.boot_id():
        return
    if (type(pid) is not int or pid < 2 or not isinstance(born, str)
            or not born.isdigit() or pid == os.getpid()):
        raise UpgradeError('invalid_upgrade_driver_identity')
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        current = process_start(pid)
        if current is None:
            return
        if current != born:
            raise UpgradeError('upgrade_driver_identity_changed')
        if lock_path is not None:
            info = Path(lock_path).stat()
            key = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
            holders = []
            for line in Path('/proc/locks').read_text().splitlines():
                fields = line.split()
                if len(fields) != 8 or fields[1:4] != ['FLOCK', 'ADVISORY', 'WRITE']:
                    continue
                device = fields[5].split(':')
                if len(device) == 3 and (int(device[0], 16), int(device[1], 16), int(device[2])) == key:
                    holders.append(int(fields[4]))
            if holders != [pid]:
                raise UpgradeError('upgrade_driver_lock_owner_changed')
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        if not select.select([descriptor], [], [], 5)[0]:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            if not select.select([descriptor], [], [], 5)[0]:
                raise UpgradeError('upgrade_driver_did_not_stop')
    except ProcessLookupError:
        pass
    finally:
        os.close(descriptor)


class LiveDrill(restore.Drill):
    """Reuse isolated command execution while never owning permanent datasets."""

    def prepare(self):
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        op.write(self.root / 'owner', self.token, mode=0o600)
        self.runtime_owned = True
        for child in ('postgres', 'evidence'):
            (self.root / child).symlink_to(Path('/mnt/devres-staging') / child, target_is_directory=True)
        self.network = True
        self.run(['docker', 'network', 'create', '--internal', '--label',
                  restore.LABEL_KEY + '=' + self.token, self.name])
        for folder in ('config', 'tls'):
            path = self.root / folder
            path.mkdir(mode=0o750)
            os.chmod(path, 0o750)
            os.chown(path, 0, 65532)
        config = restore.paused_config(self.config_text)
        parsed = tomllib.loads(config)
        if not re.fullmatch(r'postgres://devres:[0-9a-f]+@postgres:5432/devres', parsed['storage']['database_url']):
            raise UpgradeError('unexpected_private_database_authority')
        destination = self.root / 'config/backend.toml'
        destination.write_text(config)
        os.chown(destination, 0, 65532)
        os.chmod(destination, 0o640)
        for name in ('backend.pem', 'backend-key.pem', 'client-ca.pem'):
            destination = self.root / 'tls' / name
            shutil.copyfile(self.private / name, destination)
            os.chown(destination, 0, 65532)
            os.chmod(destination, 0o640)


class Upgrade:
    def __init__(self, run=None, state_root=None, private=None, clock=time.monotonic,
                 drill=restore.Drill, live=LiveDrill, verify=restore.verify):
        self.run = run or op.run
        self.root = journal_root(state_root)
        self.state = m.State(self.root)
        self.maintenance_state = m.State(state_root if state_root is not None else op.STATE)
        self.tool = m.Maintenance(self.maintenance_state, run=lambda args: self.run(args).strip())
        self.private = Path(private if private is not None else op.PRIVATE)
        self.clock, self.drill, self.live, self.verify = clock, drill, live, verify
        self.record = None
        self.restore_module = restore
        self.dataset, self.hold = m.DATASET, HOLD
        self.source_prefix, self.target_version = SOURCE, VERSION
        self.write = op.write

    def read_record(self):
        return read_record(self.root.parent)

    def identity(self):
        result = rehearsal_identity()
        record = self.record or {}
        profile = record.get('resource_profile', 'direct' if record.get('mode') == 'direct' else 'upgrade')
        if profile not in ('upgrade', 'direct'):
            raise UpgradeError('invalid_upgrade_resource_profile')
        result['resource_profile'] = {'name': profile, **restore.RESOURCE_PROFILES[profile]}
        result['pause_scope'] = record.get('pause_scope', 'rehearsal')
        return result

    def snapshot_name(self, label):
        return 'devres-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + label + '-' + secrets.token_hex(3)

    @staticmethod
    def validate_pause_scope(scope):
        if scope not in ('rehearsal', 'all'):
            raise UpgradeError('invalid_pause_scope')

    def safe_unlocked(self):
        value = self.maintenance_state.load()
        if value.get('fence') or value.get('operation') or self.tool.capacity_reason(self.tool.metrics()):
            raise UpgradeError('upgrade_capacity_or_maintenance_fenced')

    def save(self, phase=None, **updates):
        if phase is not None:
            self.record['phase'] = phase
            if phase in TERMINAL and 'watchdog_timer' in self.record:
                updates.setdefault('watchdog_cleanup_pending', True)
        self.record.update(updates)
        self.state.save(self.record)

    def safe(self, *, deadline_at=None):
        """Wait briefly for the periodic guard, then perform every safety check.

        Only lock acquisition contention is retryable. A failed check, metric,
        or persistent lock remains fatal; recovery callers can omit the already
        expired cutover deadline while retaining the same bounded lock wait.
        """
        def deadline_remaining():
            if deadline_at is None:
                return math.inf
            now = time.time()
            if self.deadline_due({'deadline_at': deadline_at}, lambda: now):
                raise UpgradeError('upgrade_deadline_exceeded')
            return deadline_at - now

        started, contended = time.monotonic(), False
        with contextlib.ExitStack() as acquired:
            while True:
                deadline_remaining()
                if contended and time.monotonic() - started >= SAFETY_LOCK_WAIT_SECONDS:
                    raise m.MaintenanceError('maintenance_busy')
                try:
                    acquired.enter_context(self.maintenance_state.locked())
                except m.MaintenanceError as error:
                    if str(error) != 'maintenance_busy':
                        raise
                    contended = True
                    remaining = min(SAFETY_LOCK_WAIT_SECONDS - (time.monotonic() - started),
                                    deadline_remaining())
                    if remaining <= 0:
                        raise
                    time.sleep(min(SAFETY_LOCK_POLL_SECONDS, remaining))
                else:
                    break
            deadline_remaining()
            self.safe_unlocked()
            deadline_remaining()

    def begin(self, phase):
        previous = read_record(self.root.parent)
        if previous and previous['phase'] not in TERMINAL:
            raise UpgradeError('upgrade_already_active')
        if previous and previous.get('retirement_timer_restore_pending'):
            raise UpgradeError('retirement_timer_restore_required')
        self.safe()
        # No mutation before confirming the exact serving image and schema-nine source.
        image = self.tool.k('get', 'deployment', 'backend', '-o', 'jsonpath={.spec.template.spec.containers[0].image}').strip()
        if image != restore.OLD_SERVER:
            raise UpgradeError('unexpected_existing_server_image')
        text = (self.private / 'backend.toml').read_text()
        if tomllib.loads(text).get('source', {}).get('url') != SOURCE + OLD_VERSION + '/source.tar.gz':
            raise UpgradeError('unexpected_existing_source')
        if self.tool.replicas('backend') != 1 or self.tool.replicas('postgres') != 1:
            raise UpgradeError('expected_running_staging_pair')
        schema = self.tool.k('exec', 'deployment/postgres', '--', 'psql', '-X', '-U',
                             'devres_admin', '-d', 'devres', '-Atc',
                             'SELECT version FROM devres_schema WHERE singleton').strip()
        if schema != '9':
            raise UpgradeError('expected_schema_nine')
        timer_state = {}
        for timer in TIMERS:
            state = self.run(['systemctl', 'show', '-p', 'ActiveState', '--value', timer]).strip()
            if state not in ('active', 'inactive'):
                raise UpgradeError('backup_timer_state_uncertain')
            timer_state[timer] = state
        if self.run(['systemctl', 'show', '-p', 'ActiveState', '--value', 'devres-staging-backup.service']).strip() not in ('inactive', 'failed'):
            raise UpgradeError('backup_already_running')
        token = secrets.token_hex(12)
        self.record = {'version': 1, 'fence': None, 'operation': None, 'verified': [],
                       'phase': phase, 'token': token, 'timers': timer_state,
                       'old_server': image, 'old_version': OLD_VERSION}
        self.save()
        with checkpoint.control_lock(self.root):
            request = self.root / 'pause-request.json'
            if request.exists():
                checkpoint.read_json(request)
                request.unlink()
        (self.root / 'acceptance.json').unlink(missing_ok=True)
        op.write(self.root / 'original-config.toml', text)
        self.run(['systemctl', 'stop', *TIMERS])
        # Recheck after stopping the timer; never kill an in-flight backup service.
        if self.run(['systemctl', 'show', '-p', 'ActiveState', '--value', 'devres-staging-backup.service']).strip() not in ('inactive', 'failed'):
            raise UpgradeError('backup_started_during_upgrade_admission')
        return text

    def restore_timers(self):
        for timer, state in self.record['timers'].items():
            self.run(['systemctl', 'start' if state == 'active' else 'stop', timer])
        self.disarm_watchdog()

    def watchdog_timer(self):
        token = self.record['token']
        if not TOKEN.fullmatch(token):
            raise UpgradeError('invalid_upgrade_watch_token')
        timer = WATCHDOG + token + '.timer'
        if self.record.get('watchdog_timer', timer) != timer:
            raise UpgradeError('upgrade_watchdog_identity_changed')
        return timer

    def arm_watchdog(self):
        timer = self.watchdog_timer()
        # Persist ownership before enabling: partial systemctl failure must still
        # permit safe cleanup of this token's timer during admission recovery.
        self.save(watchdog_timer=timer, watchdog_cleanup_pending=True)
        self.run(['systemctl', 'enable', '--now', timer])
        active = self.run(['systemctl', 'show', '-p', 'ActiveState', '--value', timer]).strip()
        enabled = self.run(['systemctl', 'show', '-p', 'UnitFileState', '--value', timer]).strip()
        if active != 'active' or enabled != 'enabled':
            raise UpgradeError('upgrade_watchdog_not_armed')
        self.save(watchdog_cleanup_pending=False)

    def disarm_watchdog(self):
        if 'watchdog_timer' not in self.record:
            return True
        timer = self.watchdog_timer()
        try:
            # Never stop the service: it may be executing this very rollback.
            self.run(['systemctl', 'disable', '--now', timer])
            active = self.run(['systemctl', 'show', '-p', 'ActiveState', '--value', timer]).strip()
            enabled = self.run(['systemctl', 'show', '-p', 'UnitFileState', '--value', timer]).strip()
            if active != 'inactive' or enabled != 'disabled':
                raise UpgradeError('upgrade_watchdog_still_active')
        except Exception:
            # A terminal journal prevents stale timer invocations from touching
            # workloads. Retry its cleanup separately, never roll back a fully
            # accepted candidate merely because timer removal failed.
            self.save(watchdog_cleanup_pending=True)
            return False
        self.save(watchdog_cleanup_pending=False)
        return True

    def snapshot(self, label, paused=False):
        self.safe()
        with self.maintenance_state.locked():
            result = self.tool.snapshot(label, upgrade=True)
            name = result['snapshot']
            self.run(['zfs', 'hold', '-r', HOLD, m.DATASET + '@' + name])
        if paused:
            self.tool.scale('backend', 0)
            self.tool.stopped('backend')
        return name

    def clean_stop(self, drill):
        if getattr(drill, 'backend_started', False):
            self.run(['docker', 'stop', '--time=120', drill.name + '-backend'])
        if drill.postgres_started:
            self.run(['docker', 'stop', '--time=120', drill.name + '-postgres'])

    def rehearsal(self, pause_scope='rehearsal'):
        self.validate_pause_scope(pause_scope)
        with self.state.locked():
            started = self.clock()
            identity = rehearsal_identity()
            phases = {}
            phase_started = time.monotonic()
            admitted = False
            try:
                original = self.begin('rehearsing')
                self.save(pause_scope=pause_scope, timing_qualified=True)
                self.record_driver()
                admitted = True
                snapshot = self.snapshot('upgrade-rehearsal')
                self.save(snapshot=snapshot)
                phases['snapshot'] = time.monotonic() - phase_started
                phase_started = time.monotonic()
                self.verify(snapshot, schema=9, server=restore.OLD_SERVER, private=self.private,
                            config_text=original)
                phases['old_restore'] = time.monotonic() - phase_started
                drill = self.drill(snapshot, schema=10, private=self.private,
                                   config_text=target_config(original, paused=True),
                                   clone_quota='512G', resource_profile='upgrade')
                self.save(live_token=drill.token)
                canonical_snapshot = snapshot + '-canonical'
                m.snapshot_name(canonical_snapshot)
                canonical_created = False
                try:
                    drill.prepare()
                    drill.start_postgres()
                    for command in ('migrate-storage', 'verify-storage', 'activate-storage'):
                        self.safe()
                        phase_started = time.monotonic()
                        checkpoint.Lifecycle(self).offline(drill, command)
                        phases[command] = time.monotonic() - phase_started
                    phase_started = time.monotonic()
                    receipt = drill.check(prepared=True)
                    phases['candidate_read'] = time.monotonic() - phase_started
                    self.clean_stop(drill)
                    control = self.run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                                        '--user', '999:999', '--cap-drop=ALL',
                                        '--security-opt=no-new-privileges', '-e', 'LC_ALL=C',
                                        '--entrypoint', 'pg_controldata', '-v',
                                        str(drill.root / 'postgres') + ':/pgdata:ro', restore.PG,
                                        '/pgdata/18/docker'])
                    states = [line.partition(':')[2].strip() for line in control.splitlines()
                              if line.startswith('Database cluster state:')]
                    if states != ['shut down']:
                        raise UpgradeError('rehearsal_postgres_shutdown_unconfirmed')
                    self.run(['zfs', 'snapshot', '-r', drill.dataset + '@' + canonical_snapshot])
                    canonical_created = True
                    phase_started = time.monotonic()
                    canonical_receipt = self.verify(canonical_snapshot, schema=10, server=restore.SERVER,
                                                    source_dataset=drill.dataset, private=self.private,
                                                    config_text=target_config(original, paused=True))
                    phases['schema10_restore'] = time.monotonic() - phase_started
                    # Prove the matching old pair remains independently restorable.
                    phase_started = time.monotonic()
                    rollback_receipt = self.verify(snapshot, schema=9, server=restore.OLD_SERVER,
                                                   private=self.private, config_text=original)
                    phases['rollback_restore'] = time.monotonic() - phase_started
                    self.save(rehearsal_schema10_restore=canonical_receipt,
                              rehearsal_rollback_restore=rollback_receipt)
                except checkpoint.Paused:
                    raise
                except Exception as failure:
                    if getattr(drill, 'runtime_owned', True):
                        checkpoint.Lifecycle(self).preserve_failure(
                            drill, allow_stop=not getattr(failure, 'unsafe_cleanup', False))
                    raise
                finally:
                    preserved = self.record.get('phase') in checkpoint.PRESERVED
                    try:
                        if not preserved:
                            self.clean_stop(drill)
                    finally:
                        if canonical_created and not preserved:
                            # This source is the token-owned disposable clone,
                            # never the permanent staging subtree. Nested clone
                            # cleanup must have completed before removal succeeds.
                            drill.owned(drill.dataset)
                            self.run(['zfs', 'destroy', '-r', drill.dataset + '@' + canonical_snapshot])
                        if not preserved:
                            drill.cleanup()
                            self.save(live_token=None)
                if rehearsal_identity() != identity:
                    raise UpgradeError('rehearsal_identity_changed')
                elapsed = max(1, math.ceil(self.clock() - started))
                self.save('rehearsed', rehearsal_seconds=elapsed,
                          deadline_seconds=max(1800, elapsed * 2), receipt=receipt,
                          rehearsal_identity=identity, phase_seconds=phases)
                self.restore_timers()
                return {'rehearsed': True, 'seconds': elapsed,
                        'deadline_seconds': self.record['deadline_seconds'], 'snapshot': snapshot,
                        'rehearsal_identity': identity, 'phase_seconds': phases}
            except checkpoint.Paused:
                return {'paused': True, 'timing_qualified': False}
            except Exception:
                if (admitted or self.record) and self.record.get('phase') not in checkpoint.PRESERVED:
                    self.save('rehearsal_failed')
                    self.restore_timers()
                raise

    def remaining(self):
        return self.wall_remaining()

    def apply(self, pause_scope='rehearsal'):
        return self._apply(pause_scope=pause_scope)

    def apply_direct(self, deadline_at, pause_scope='rehearsal'):
        if (isinstance(deadline_at, bool) or not isinstance(deadline_at, (int, float))
                or not math.isfinite(deadline_at) or deadline_at <= time.time()):
            raise UpgradeError('invalid_upgrade_deadline')
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
            raise UpgradeError('upgrade_driver_supervision_unavailable')
        return self._apply(deadline_at=deadline_at, pause_scope=pause_scope)

    def record_driver(self):
        pid = os.getpid()
        born = process_start(pid)
        if born is None:
            raise UpgradeError('upgrade_driver_supervision_unavailable')
        self.save(driver_pid=pid, driver_start=born, driver_boot_id=checkpoint.boot_id())

    def verify_direct(self, snapshot, **kwargs):
        """Expose the isolated restore owner before it can start any writer."""
        def owner(drill):
            self.save(live_token=drill.token, live_kind='restore', live_snapshot=snapshot,
                      live_schema=kwargs['schema'])
        result = self.verify(snapshot, private=self.private, timeout=self.wall_remaining(),
                             on_drill=owner, **kwargs)
        self.save(live_token=None, live_kind=None)
        return result

    def recover_original(self):
        """Before migration, restore the unchanged old pair only if drain is certain."""
        self.save('recovering_original')
        self.stop_owned()
        self.safe()
        if self.record.get('drain_started') or self.record.get('backend_drained'):
            self.tool.scale('backend', 0)
            self.tool.stopped('backend')
            original = (self.root / 'original-config.toml').read_text()
            op.write(self.private / 'backend.toml', original)
            op.config_secret()
            self.tool.start('postgres', 1)
            self.tool.start('backend', 1)
        self.save('rolled_back')
        self.restore_timers()
        return {'rolled_back': True, 'version': OLD_VERSION,
                'watchdog_disarmed': not self.record.get('watchdog_cleanup_pending', False)}

    def _apply(self, deadline_at=None, pause_scope='rehearsal'):
        self.validate_pause_scope(pause_scope)
        with self.state.locked():
            direct = deadline_at is not None
            if not direct:
                rehearsal = read_record(self.root.parent)
                if not rehearsal or rehearsal['phase'] != 'rehearsed' or not isinstance(rehearsal.get('deadline_seconds'), int):
                    raise UpgradeError('successful_rehearsal_required')
                if rehearsal.get('rehearsal_identity') != rehearsal_identity():
                    raise UpgradeError('matching_rehearsal_identity_required')
                if rehearsal.get('timing_qualified', True) is not True:
                    raise UpgradeError('uninterrupted_rehearsal_required')
                if rehearsal.get('pause_scope', 'rehearsal') != pause_scope:
                    raise UpgradeError('matching_rehearsal_policy_required')
            mutated = False
            drain_attempted = False
            original = None
            try:
                original = self.begin('preparing_upgrade')
                self.save(pause_scope=pause_scope)
                if direct:
                    self.save(mode='direct', deadline_seconds=deadline_at - time.time(),
                              deadline_at=deadline_at)
                    self.record_driver()
                else:
                    self.save(deadline_seconds=rehearsal['deadline_seconds'],
                              deadline_at=time.time() + rehearsal['deadline_seconds'],
                              rehearsal_snapshot=rehearsal['snapshot'])
                self.started = self.clock()
                self.record_driver()
                paused = restore.paused_config(original)
                self.remaining()
                self.arm_watchdog()
                drain_attempted = True
                if direct:
                    self.save(drain_started=True)
                self.tool.scale('backend', 0)
                self.tool.stopped('backend')
                self.save(backend_drained=True)
                op.write(self.private / 'backend.toml', paused)
                op.config_secret()
                # snapshot() preserves zero backend replicas and returns PG to one.
                snapshot = self.snapshot('pre-blake3', paused=True)
                self.save('pre_upgrade_restore', snapshot=snapshot)
                if direct:
                    # Keep the exact source pair frozen throughout restore proof
                    # and migration; no later-history merge or snapshot reuse.
                    self.tool.scale('postgres', 0)
                    self.tool.stopped('postgres')
                    self.tool.postgres_shut_down()
                    started = self.clock()
                    old_receipt = self.verify_direct(snapshot, schema=9, server=restore.OLD_SERVER,
                                                     config_text=original)
                    self.save(old_restore=old_receipt,
                              old_restore_seconds=max(0, self.clock() - started))
                else:
                    old_receipt = self.verify(snapshot, schema=9, server=restore.OLD_SERVER,
                                              private=self.private, config_text=original)
                    self.save(old_restore=old_receipt)
                self.remaining()
                self.tool.scale('postgres', 0)
                self.tool.stopped('postgres')
                self.tool.postgres_shut_down()
                guids = {child: self.run(['zfs', 'get', '-H', '-o', 'value', 'guid',
                                         m.DATASET + '/' + child]).strip()
                         for child in ('postgres', 'evidence')}
                if any(not value.isdigit() for value in guids.values()):
                    raise UpgradeError('invalid_dataset_identity')
                self.save('migrating', dataset_guids=guids, live_token=secrets.token_hex(12),
                          live_kind='permanent', checkpoint_kind='permanent')
                mutated = True
                drill = self.live(snapshot, schema=10, private=self.private,
                                  token=self.record['live_token'],
                                  config_text=target_config(original, paused=True),
                                  resource_profile='direct' if direct else 'upgrade')
                try:
                    drill.prepare()
                    drill.start_postgres()
                    for command in ('migrate-storage', 'verify-storage', 'activate-storage'):
                        self.save('running_' + command.replace('-', '_'))
                        checkpoint.Lifecycle(self).offline(drill, command, timeout=self.remaining())
                finally:
                    try:
                        if self.record.get('phase') not in checkpoint.PRESERVED:
                            self.clean_stop(drill)
                    finally:
                        if self.record.get('phase') not in checkpoint.PRESERVED:
                            drill.cleanup()
                self.start_candidate()
                return {'candidate_ready': True, 'collectors_paused': True,
                        'snapshot': snapshot, 'version': VERSION,
                        **({'old_restore_seconds': self.record['old_restore_seconds']} if direct else {})}
            except checkpoint.Paused:
                return {'paused': True, 'deadline_at': self.record['deadline_at']}
            except Exception:
                if mutated:
                    self._rollback()
                elif direct and self.record:
                    self.recover_original()
                elif self.record and original is not None and self.record.get('backend_drained'):
                    # Refuse uncertain partial snapshot drains; the original
                    # maintenance recovery fence must remain visible.
                    self.safe()
                    self.tool.stopped('backend')
                    op.write(self.private / 'backend.toml', original)
                    op.config_secret()
                    self.tool.start('postgres', 1)
                    self.tool.start('backend', 1)
                    self.save('rolled_back')
                    self.restore_timers()
                elif self.record and not drain_attempted:
                    # begin() cannot touch serving or its configuration. A timer
                    # admission failure can therefore be unwound independently.
                    self.save('rolled_back')
                    self.restore_timers()
                raise

    def stop_owned(self):
        owner = owned_containers(self.root.parent)
        if not owner:
            return
        if self.record.get('live_kind') in ('restore', 'permanent'):
            self.cleanup_owned_resources(owner)
            self.save(live_token=None, live_kind=None)
            return
        names = self.run(['docker', 'ps', '-a', '--filter', 'label=' + owner['label'] + '=' + owner['token'],
                          '--format', '{{.Names}}']).splitlines()
        for name in names:
            if name != owner['prefix'] + '-postgres' and not re.fullmatch(re.escape(owner['prefix']) + r'-offline-[0-9]+', name):
                raise UpgradeError('upgrade_container_inventory_changed')
            identity = json.loads(self.run(['docker', 'inspect', name]))[0]
            if identity['Config'].get('Labels', {}).get(owner['label']) != owner['token']:
                raise UpgradeError('upgrade_container_owner_changed')
            self.run(['docker', 'stop', '--time=120', name])
            self.run(['docker', 'rm', name])
        self.save(live_token=None, live_kind=None)

    def owned_inventory(self, owner):
        """Validate the whole detached inventory before the first cleanup mutation."""
        token, name = owner['token'], owner['prefix']
        kind = self.record.get('live_kind')
        if kind not in ('restore', 'permanent'):
            raise UpgradeError('invalid_upgrade_resource_kind')
        runtime = Path('/tmp') / name
        missing_links = False
        if runtime.is_symlink():
            raise UpgradeError('restore_runtime_ownership_changed')
        if runtime.exists():
            info = runtime.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise UpgradeError('restore_runtime_ownership_changed')
            fd = os.open(runtime / 'owner', os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                marker = os.read(fd, 128).decode('ascii')
            finally:
                os.close(fd)
            if (marker != token or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise UpgradeError('restore_runtime_ownership_changed')
            for child in ('config', 'tls'):
                if (runtime / child).is_symlink():
                    raise UpgradeError('restore_runtime_ownership_changed')
            for child in ('postgres', 'evidence'):
                path = runtime / child
                if kind == 'restore' and path.is_symlink():
                    raise UpgradeError('restore_runtime_ownership_changed')
                if kind == 'permanent':
                    if not path.exists() and not path.is_symlink():
                        missing_links = True
                    elif not path.is_symlink() or os.readlink(path) != '/mnt/devres-staging/' + child:
                        raise UpgradeError('upgrade_permanent_mount_changed')
        dataset = 'cachepool/' + name
        datasets = {}
        rows = self.run(['zfs', 'list', '-Hp', '-t', 'filesystem,snapshot', '-o',
                         'name,guid,origin,mountpoint,canmount,' + restore.OWNER_KEY]).splitlines()
        for line in rows:
            row = line.split('\t')
            child = row[0]
            if child != dataset and not child.startswith((dataset + '/', dataset + '@')):
                continue
            if (len(row) != 6 or kind != 'restore'
                    or child not in (dataset, dataset + '/postgres', dataset + '/evidence')):
                raise UpgradeError('restore_dataset_tree_changed')
            _, guid, origin, mountpoint, canmount, claimed = row
            leaf = child.removeprefix(dataset + '/')
            expected = ('-', 'none', 'off') if child == dataset else (
                m.DATASET + '/' + leaf + '@' + self.record['live_snapshot'], str(runtime / leaf), 'on')
            if claimed != token or not guid.isdigit() or (origin, mountpoint, canmount) != expected:
                raise UpgradeError('restore_dataset_ownership_changed')
            datasets[child] = guid
        identifiers = set()
        for filt in ('label=' + restore.LABEL_KEY + '=' + token, 'name=^/' + name + '-'):
            identifiers.update(self.run(['docker', 'ps', '-a', '--no-trunc', '--filter', filt,
                                         '--format', '{{.ID}}']).splitlines())
        if len(identifiers) > 8 or any(not re.fullmatch(r'[0-9a-f]{64}', value) for value in identifiers):
            raise UpgradeError('upgrade_container_inventory_changed')
        containers = {}
        for identifier in sorted(identifiers):
            info = json.loads(self.run(['docker', 'inspect', '--type', 'container', identifier]))[0]
            role = self.owned_container(info, owner, runtime)
            if info.get('Id') != identifier:
                raise UpgradeError('upgrade_container_inventory_changed')
            containers[identifier] = role
        network = self.run(['docker', 'network', 'ls', '--filter', 'name=^' + name + '$',
                            '--format', '{{.Name}}']).strip()
        network_id = None
        if network:
            if network != name:
                raise UpgradeError('restore_network_inventory_changed')
            info = json.loads(self.run(['docker', 'network', 'inspect', name]))[0]
            if (info.get('Name') != name or not info.get('Internal')
                    or info.get('Labels', {}).get(restore.LABEL_KEY) != token
                    or not re.fullmatch(r'[0-9a-f]{64}', info.get('Id', ''))
                    or not set(info.get('Containers', {})).issubset(identifiers)):
                raise UpgradeError('restore_network_ownership_changed')
            network_id = info['Id']
        if (datasets or containers or network) and not runtime.is_dir():
            raise UpgradeError('restore_runtime_required')
        if containers and (not network or (kind == 'restore' and not datasets)):
            raise UpgradeError('restore_container_storage_or_network_missing')
        if containers and missing_links:
            raise UpgradeError('upgrade_permanent_mount_changed')
        return {'datasets': datasets, 'containers': containers, 'network': network_id}

    def owned_container(self, info, owner, runtime):
        name, token = owner['prefix'], owner['token']
        role = info.get('Name', '').removeprefix('/').removeprefix(name + '-')
        config, host = info.get('Config', {}), info.get('HostConfig', {})
        if (info.get('Name') != '/' + name + '-' + role
                or not re.fullmatch(r'postgres|backend|offline-[1-9][0-9]*', role)
                or config.get('Labels', {}).get(restore.LABEL_KEY) != token
                or host.get('NetworkMode') != name or host.get('PortBindings')):
            raise UpgradeError('upgrade_container_inventory_changed')
        server = (restore.OLD_SERVER if self.record.get('live_kind') == 'restore'
                  and self.record.get('live_schema') == 9 else restore.SERVER)
        if config.get('Image') != (restore.PG if role == 'postgres' else server):
            raise UpgradeError('upgrade_container_image_changed')
        expected = {'/var/lib/postgresql': (str(runtime / 'postgres'), True)} if role == 'postgres' else {
            '/data': (str(runtime / 'evidence'), True),
            '/etc/devres/config': (str(runtime / 'config'), False),
            '/etc/devres/tls': (str(runtime / 'tls'), False)}
        actual = {}
        for mount in info.get('Mounts', []):
            if mount.get('Type') == 'tmpfs' and mount.get('Destination') == '/tmp':
                continue
            destination = mount.get('Destination')
            if mount.get('Type') != 'bind' or destination in actual:
                raise UpgradeError('upgrade_container_mount_changed')
            source = mount.get('Source')
            if self.record.get('live_kind') == 'permanent':
                for child in ('postgres', 'evidence'):
                    if source == '/mnt/devres-staging/' + child:
                        source = str(runtime / child)
            actual[destination] = (source, mount.get('RW'))
        if actual != expected:
            raise UpgradeError('upgrade_container_mount_changed')
        return role

    def cleanup_owned_resources(self, owner):
        """Remove only the preflighted token-owned detached direct resources."""
        original = self.owned_inventory(owner)
        runtime = Path('/tmp') / owner['prefix']
        for identifier, role in sorted(original['containers'].items(),
                                       key=lambda item: (item[1] == 'postgres', item[1] == 'backend')):
            current = self.owned_inventory(owner)
            if current['containers'].get(identifier) != role:
                raise UpgradeError('upgrade_container_inventory_changed')
            self.run(['docker', 'stop', '--time=' + ('120' if role == 'postgres' else '15'), identifier])
            self.run(['docker', 'rm', identifier])
        current = self.owned_inventory(owner)
        if current['containers']:
            raise UpgradeError('upgrade_writers_remain')
        if current['network']:
            if current['network'] != original['network']:
                raise UpgradeError('restore_network_ownership_changed')
            self.run(['docker', 'network', 'rm', current['network']])
        for dataset in sorted(original['datasets'], key=len, reverse=True):
            current = self.owned_inventory(owner)
            if current['datasets'].get(dataset) != original['datasets'][dataset]:
                raise UpgradeError('restore_dataset_ownership_changed')
            self.run(['zfs', 'destroy', dataset])
        remaining = self.owned_inventory(owner)
        if remaining != {'datasets': {}, 'containers': {}, 'network': None}:
            raise UpgradeError('restore_cleanup_incomplete')
        if runtime.exists():
            for line in Path('/proc/self/mountinfo').read_text().splitlines():
                fields = line.split()
                if len(fields) < 5:
                    raise UpgradeError('restore_mount_inventory_invalid')
                mounted = Path(re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4]))
                if mounted == runtime or runtime in mounted.parents:
                    raise UpgradeError('restore_runtime_mount_remains')
            shutil.rmtree(runtime)

    def _rollback(self):
        if not self.record.get('snapshot') or not self.record.get('dataset_guids'):
            raise UpgradeError('no_upgrade_pair_to_restore')
        self.save('rolling_back')
        self.tool.scale('backend', 0)
        self.tool.stopped('backend')
        self.tool.scale('postgres', 0)
        self.tool.stopped('postgres')
        self.stop_owned()
        try:
            self.tool.postgres_shut_down()
            self.save(failed_pair_clean_shutdown=True)
        except m.MaintenanceError:
            # An interrupted migration may leave crash-recovery state. Preserve
            # that exact pair offline; only the known clean pre-upgrade pair is
            # restarted. No failed-pair file is discarded or rewritten.
            self.save(failed_pair_clean_shutdown=False)
        token = self.record['token']
        preserved = {child: 'cachepool/devres-staging-preserved-' + token + '-' + child
                     for child in ('postgres', 'evidence')}
        self.save(preserved=preserved)
        # Hold the maintenance lock only for the short dataset swap. Guard remains
        # live during migration and cannot mistake the swap's partial layout for loss.
        with self.maintenance_state.locked():
            inventory = set(self.run(['zfs', 'list', '-H', '-o', 'name']).splitlines())
            for child in ('postgres', 'evidence'):
                canonical = m.DATASET + '/' + child
                kept = preserved[child]
                if canonical in inventory:
                    guid = self.run(['zfs', 'get', '-H', '-o', 'value', 'guid', canonical]).strip()
                    if guid == self.record['dataset_guids'][child]:
                        if kept in inventory:
                            raise UpgradeError('preserved_dataset_conflict')
                        self.run(['zfs', 'unmount', canonical])
                        self.run(['zfs', 'set', 'mountpoint=none', canonical])
                        self.run(['zfs', 'rename', canonical, kept])
                        inventory.remove(canonical)
                        inventory.add(kept)
                    elif self.run(['zfs', 'get', '-H', '-o', 'value', 'origin', canonical]).strip() != kept + '@' + self.record['snapshot']:
                        raise UpgradeError('rollback_dataset_identity_changed')
                if canonical not in inventory:
                    if kept not in inventory or self.run(['zfs', 'get', '-H', '-o', 'value', 'guid', kept]).strip() != self.record['dataset_guids'][child]:
                        raise UpgradeError('preserved_dataset_identity_changed')
                    quota = '256G' if child == 'postgres' else '768G'
                    self.run(['zfs', 'clone', '-o', 'mountpoint=/mnt/devres-staging/' + child,
                              '-o', 'canmount=on', '-o', 'refquota=' + quota,
                              kept + '@' + self.record['snapshot'], canonical])
        op.write(self.private / 'backend.toml', (self.root / 'original-config.toml').read_text())
        op.config_secret()
        self.tool.k('set', 'image', 'deployment/backend', 'backend=' + restore.OLD_SERVER)
        self.safe()
        self.tool.start('postgres', 1)
        self.tool.start('backend', 1)
        self.save('rolled_back', restored_version=OLD_VERSION)
        self.restore_timers()
        return {'rolled_back': True, 'preserved': preserved, 'version': OLD_VERSION,
                'watchdog_disarmed': not self.record.get('watchdog_cleanup_pending', False)}

    def rollback(self):
        with self.state.locked():
            self.record = read_record(self.root.parent)
            if not self.record or self.record['phase'] in TERMINAL:
                raise UpgradeError('no_active_upgrade')
            return self._rollback()

    def expire(self, expected_token, wall_clock=time.time):
        if not isinstance(expected_token, str) or not TOKEN.fullmatch(expected_token):
            raise UpgradeError('invalid_upgrade_watch_token')
        # Do not enter through the capacity guard's maintenance lock. Both this
        # path and finish/apply serialize on upgrade first, then maintenance.
        entered = False
        try:
            with self.state.locked():
                entered = True
                return self.expire_locked(expected_token, wall_clock)
        except m.MaintenanceError as error:
            if entered or str(error) != 'maintenance_busy':
                raise
            # A long-running direct command holds this lock. An independent
            # root timer must be able to terminate that exact driver rather
            # than retry the same busy lock forever. Detached containers are
            # stopped only after the timer acquires the released lock.
            record = read_record(self.root.parent)
            if (not record or record['token'] != expected_token
                    or 'deadline_at' not in record
                    or record['phase'] in TERMINAL | {'rolling_back', 'recovering_original'}
                    or not self.deadline_due(record, wall_clock)):
                raise
            terminate_driver(record, self.root / 'maintenance.lock')
            with self.state.locked():
                return self.expire_locked(expected_token, wall_clock)

    @staticmethod
    def deadline_due(record, wall_clock):
        deadline = record.get('deadline_at')
        if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
                or not math.isfinite(deadline) or deadline <= 0):
            raise UpgradeError('invalid_upgrade_deadline')
        now = wall_clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise UpgradeError('invalid_upgrade_wall_clock')
        return now >= deadline

    def expire_locked(self, expected_token, wall_clock):
        self.record = read_record(self.root.parent)
        if not self.record or self.record['token'] != expected_token:
            return {'expired': False}
        if self.record['phase'] in TERMINAL:
            if self.record.get('watchdog_cleanup_pending'):
                if self.record.get('mode') == 'direct':
                    self.restore_timers()
                else:
                    self.disarm_watchdog()
            return {'expired': False}
        direct = self.record.get('mode') == 'direct'
        if 'deadline_at' not in self.record:
            return {'expired': False}
        if not self.deadline_due(self.record, wall_clock):
            return {'expired': False}
        # A terminated pre-migration restore has never changed the permanent
        # pair. Once migration may have started, use the preserving pair swap.
        if not self.record.get('dataset_guids'):
            result = self.recover_original()
        else:
            result = self._rollback()
        return {'expired': True, **result}

    def finish(self):
        with self.state.locked():
            self.record = read_record(self.root.parent)
            if not self.record or self.record['phase'] != 'awaiting_acceptance':
                raise UpgradeError('candidate_acceptance_required')
            self.record_driver()
            if time.time() >= self.record['deadline_at']:
                self._rollback()
                raise UpgradeError('upgrade_acceptance_deadline_exceeded')
            receipt = acceptance(self.root / 'acceptance.json')
            expected = {'version': VERSION, 'token': self.record['token'], 'http': True, 'webtransport': True,
                        'revisions': ['2025-11-25', '2026-07-28'], 'retained': True,
                        'isolation': True, 'shared_services': True}
            if receipt != expected:
                raise UpgradeError('candidate_acceptance_receipt_mismatch')
            try:
                self.wall_remaining()
                snapshot = self.snapshot('post-blake3')
                if self.record.get('mode') == 'direct':
                    self.verify_direct(snapshot, schema=10, server=restore.SERVER,
                                       config_text=(self.private / 'backend.toml').read_text())
                else:
                    self.verify(snapshot, schema=10, server=restore.SERVER, private=self.private,
                                config_text=(self.private / 'backend.toml').read_text(),
                                timeout=self.wall_remaining())
                self.wall_remaining()
                with self.maintenance_state.locked():
                    self.tool.mark_verified(snapshot)
                    self.run(['zfs', 'release', '-r', HOLD, m.DATASET + '@' + snapshot])
                self.tool.scale('backend', 0)
                self.tool.stopped('backend')
                original = (self.root / 'original-config.toml').read_text()
                op.write(self.private / 'backend.toml', target_config(original))
                op.config_secret()
                self.wall_remaining()
                self.tool.start('backend', 1)
                self.wall_remaining()
                self.save('complete', verified_schema10_snapshot=snapshot)
                self.restore_timers()
                return {'complete': True, 'version': VERSION, 'snapshot': snapshot,
                        'original_collectors_restored': True,
                        'watchdog_disarmed': not self.record.get('watchdog_cleanup_pending', False)}
            except Exception:
                self._rollback()
                raise

    def wall_remaining(self):
        if self.deadline_due(self.record, time.time):
            raise UpgradeError('upgrade_deadline_exceeded')
        self.safe(deadline_at=self.record['deadline_at'])
        # Guard contention and metrics consume the same absolute budget. Never
        # return a timeout computed before acquiring the maintenance lock.
        now = time.time()
        if self.deadline_due(self.record, lambda: now):
            raise UpgradeError('upgrade_deadline_exceeded')
        remaining = self.record['deadline_at'] - now
        return min(restore.OFFLINE_TIMEOUT_SECONDS, remaining)

    def start_candidate(self):
        self.save('starting_candidate', live_token=None, live_kind=None, offline_command=None)
        self.tool.postgres_shut_down()
        original = (self.root / 'original-config.toml').read_text()
        op.write(self.private / 'backend.toml', target_config(original, paused=True))
        op.config_secret()
        self.tool.k('set', 'image', 'deployment/backend', 'backend=' + restore.SERVER)
        self.wall_remaining()
        self.tool.start('postgres', 1)
        self.tool.start('backend', 1)
        self.wall_remaining()
        self.save('awaiting_acceptance')

    def complete_resumed_rehearsal(self, drill):
        self.save('rehearsal_restore_checks', offline_command=None)
        started = time.monotonic()
        receipt = drill.check(prepared=True)
        phases = dict(self.record.get('resume_phase_seconds', {}))
        phases['candidate_read'] = time.monotonic() - started
        self.clean_stop(drill)
        drill.postgres_started = False
        lifecycle = checkpoint.Lifecycle(self)
        lifecycle.clean_postgres(drill.root / 'postgres')
        name = self.snapshot_name('resumed-canonical')
        self.run(['zfs', 'snapshot', '-r', drill.dataset + '@' + name])
        self.run(['zfs', 'hold', '-r', HOLD, drill.dataset + '@' + name])
        config = (drill.root / 'config/backend.toml').read_text()
        started = time.monotonic()
        canonical = self.verify(name, schema=10, server=restore.SERVER,
                                source_dataset=drill.dataset, private=self.private,
                                config_text=config)
        phases['schema10_restore'] = time.monotonic() - started
        original = (self.root / 'original-config.toml').read_text()
        started = time.monotonic()
        rollback = self.verify(self.record['snapshot'], schema=9, server=restore.OLD_SERVER,
                               private=self.private, config_text=original)
        phases['rollback_restore'] = time.monotonic() - started
        self.save('rehearsed_unqualified', timing_qualified=False, receipt=receipt,
                  rehearsal_schema10_restore=canonical, rehearsal_rollback_restore=rollback,
                  retained_candidate_snapshot=name,
                  resume_phase_seconds=phases, resume_completed_epoch=time.time(),
                  completed_target_identity=self.identity())
        # Keep the exact pair and holds; terminal journal is archived before a
        # later operation can replace its ownership/provenance inventory.
        op.write(self.root / ('retained-' + self.record['token'] + '.json'),
                 json.dumps(self.record, sort_keys=True) + '\n')
        self.restore_timers()
        return {'rehearsed': True, 'timing_qualified': False, 'retained_candidate': True,
                'phase_seconds': phases}

    def checkpoint_status(self, token):
        return checkpoint.Lifecycle(self).status(token)

    def checkpoint_pause(self, token):
        return checkpoint.Lifecycle(self).pause(token)

    def checkpoint_resume(self, token):
        return checkpoint.Lifecycle(self).resume(token)

    def checkpoint_adopt(self, token, receipt, check_only=False, from_bundle_sha256=None):
        return checkpoint.Lifecycle(self).adopt(token, receipt, check_only=check_only,
                                               from_bundle_sha256=from_bundle_sha256)

    def checkpoint_retire(self, token):
        return checkpoint.Lifecycle(self).retire(token)

    def refresh_paused(self, token, refresh):
        with self.state.locked():
            self.record = checkpoint.Lifecycle(self).record(token)
            if self.record['phase'] != 'rehearsal_paused':
                raise UpgradeError('stopped_rehearsal_required')
            checkpoint.Lifecycle(self).validate_paused(self.record)
            refresh()


def rehearse(pause_scope='rehearsal'):
    print(json.dumps(Upgrade().rehearsal(pause_scope=pause_scope), sort_keys=True))


def upgrade(pause_scope='rehearsal'):
    print(json.dumps(Upgrade().apply(pause_scope=pause_scope), sort_keys=True))


def upgrade_direct(deadline_at, pause_scope='rehearsal'):
    print(json.dumps(Upgrade().apply_direct(deadline_at, pause_scope=pause_scope), sort_keys=True))


def rollback():
    print(json.dumps(Upgrade().rollback(), sort_keys=True))


def finalize():
    print(json.dumps(Upgrade().finish(), sort_keys=True))


def expire(token):
    try:
        print(json.dumps(Upgrade().expire(token), sort_keys=True))
    except m.MaintenanceError as error:
        if str(error) == 'maintenance_busy':
            raise SystemExit(75) from None
        raise
