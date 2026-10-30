#!/usr/bin/env python3
"""Private, owner-scoped schema-nine to schema-ten staging upgrade.

No provider calls or shared-edge changes occur here. Public acceptance is a
separate operator gate before ``finalize`` restores the original schedules.
"""
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
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
VERSION = '0.1.0-build.fc7d9856'
OLD_VERSION = '0.1.0-build.27d35cd6'
SOURCE = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/'
TERMINAL = {'rehearsed', 'rehearsal_failed', 'complete', 'rolled_back'}
TIMERS = ('devres-staging-backup.timer',)
HOLD = 'devres-upgrade-protected'
TOKEN = re.compile(r'[0-9a-f]{24}\Z')


class UpgradeError(RuntimeError):
    """Fixed diagnostic codes only; command output and configuration stay private."""


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


class LiveDrill(restore.Drill):
    """Reuse isolated command execution while never owning permanent datasets."""

    def prepare(self):
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        (self.root / 'owner').write_text(self.token)
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

    def save(self, phase=None, **updates):
        if phase is not None:
            self.record['phase'] = phase
        self.record.update(updates)
        self.state.save(self.record)

    def safe(self):
        with self.maintenance_state.locked():
            value = self.maintenance_state.load()
            if value.get('fence') or value.get('operation') or self.tool.capacity_reason(self.tool.metrics()):
                raise UpgradeError('upgrade_capacity_or_maintenance_fenced')

    def begin(self, phase):
        previous = read_record(self.root.parent)
        if previous and previous['phase'] not in TERMINAL:
            raise UpgradeError('upgrade_already_active')
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

    def rehearsal(self):
        with self.state.locked():
            started = self.clock()
            admitted = False
            try:
                original = self.begin('rehearsing')
                admitted = True
                snapshot = self.snapshot('upgrade-rehearsal')
                self.save(snapshot=snapshot)
                self.verify(snapshot, schema=9, server=restore.OLD_SERVER, private=self.private,
                            config_text=original)
                drill = self.drill(snapshot, schema=10, private=self.private,
                                   config_text=target_config(original, paused=True))
                self.save(live_token=drill.token)
                canonical_snapshot = snapshot + '-canonical'
                m.snapshot_name(canonical_snapshot)
                canonical_created = False
                try:
                    drill.prepare()
                    drill.start_postgres()
                    for command in ('migrate-storage', 'verify-storage', 'activate-storage'):
                        self.safe()
                        drill.offline(command)
                    receipt = drill.check(prepared=True)
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
                    canonical_receipt = self.verify(canonical_snapshot, schema=10, server=restore.SERVER,
                                                    source_dataset=drill.dataset, private=self.private,
                                                    config_text=target_config(original, paused=True))
                    # Prove the matching old pair remains independently restorable.
                    rollback_receipt = self.verify(snapshot, schema=9, server=restore.OLD_SERVER,
                                                   private=self.private, config_text=original)
                    self.save(rehearsal_schema10_restore=canonical_receipt,
                              rehearsal_rollback_restore=rollback_receipt)
                finally:
                    try:
                        self.clean_stop(drill)
                    finally:
                        if canonical_created:
                            # This source is the token-owned disposable clone,
                            # never the permanent staging subtree. Nested clone
                            # cleanup must have completed before removal succeeds.
                            drill.owned(drill.dataset)
                            self.run(['zfs', 'destroy', '-r', drill.dataset + '@' + canonical_snapshot])
                        drill.cleanup()
                        self.save(live_token=None)
                elapsed = max(1, math.ceil(self.clock() - started))
                self.save('rehearsed', rehearsal_seconds=elapsed,
                          deadline_seconds=max(1800, elapsed * 2), receipt=receipt)
                self.restore_timers()
                return {'rehearsed': True, 'seconds': elapsed,
                        'deadline_seconds': self.record['deadline_seconds'], 'snapshot': snapshot}
            except Exception:
                if admitted or self.record:
                    self.save('rehearsal_failed')
                    self.restore_timers()
                raise

    def remaining(self):
        remaining = self.record['deadline_seconds'] - (self.clock() - self.started)
        if remaining <= 0:
            raise UpgradeError('upgrade_deadline_exceeded')
        self.safe()
        return min(86400, remaining)

    def apply(self):
        with self.state.locked():
            rehearsal = read_record(self.root.parent)
            if not rehearsal or rehearsal['phase'] != 'rehearsed' or not isinstance(rehearsal.get('deadline_seconds'), int):
                raise UpgradeError('successful_rehearsal_required')
            mutated = False
            original = None
            try:
                original = self.begin('preparing_upgrade')
                self.save(deadline_seconds=rehearsal['deadline_seconds'],
                          deadline_at=time.time() + rehearsal['deadline_seconds'],
                          rehearsal_snapshot=rehearsal['snapshot'])
                self.started = self.clock()
                paused = restore.paused_config(original)
                self.tool.scale('backend', 0)
                self.tool.stopped('backend')
                self.save(backend_drained=True)
                op.write(self.private / 'backend.toml', paused)
                op.config_secret()
                # snapshot() preserves zero backend replicas and returns PG to one.
                snapshot = self.snapshot('pre-blake3', paused=True)
                self.save('pre_upgrade_restore', snapshot=snapshot)
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
                self.save('migrating', dataset_guids=guids, live_token=secrets.token_hex(12))
                mutated = True
                drill = self.live(snapshot, schema=10, private=self.private,
                                  token=self.record['live_token'],
                                  config_text=target_config(original, paused=True))
                try:
                    drill.prepare()
                    drill.start_postgres()
                    for command in ('migrate-storage', 'verify-storage', 'activate-storage'):
                        self.save('running_' + command.replace('-', '_'))
                        drill.offline(command, timeout=self.remaining())
                finally:
                    try:
                        self.clean_stop(drill)
                    finally:
                        drill.cleanup()
                self.save('starting_candidate', live_token=None)
                self.tool.postgres_shut_down()
                op.write(self.private / 'backend.toml', target_config(original, paused=True))
                op.config_secret()
                self.tool.k('set', 'image', 'deployment/backend', 'backend=' + restore.SERVER)
                self.remaining()
                self.tool.start('postgres', 1)
                self.tool.start('backend', 1)
                self.remaining()
                self.save('awaiting_acceptance')
                return {'candidate_ready': True, 'collectors_paused': True,
                        'snapshot': snapshot, 'version': VERSION}
            except Exception:
                if mutated:
                    self._rollback()
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
                elif self.record and original is None:
                    # begin() cannot touch serving or its configuration. A timer
                    # admission failure can therefore be unwound independently.
                    self.save('rolled_back')
                    self.restore_timers()
                raise

    def stop_owned(self):
        owner = owned_containers(self.root.parent)
        if not owner:
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
        self.save(live_token=None)

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
        return {'rolled_back': True, 'preserved': preserved, 'version': OLD_VERSION}

    def rollback(self):
        with self.state.locked():
            self.record = read_record(self.root.parent)
            if not self.record or self.record['phase'] in TERMINAL:
                raise UpgradeError('no_active_upgrade')
            return self._rollback()

    def finish(self):
        with self.state.locked():
            self.record = read_record(self.root.parent)
            if not self.record or self.record['phase'] != 'awaiting_acceptance':
                raise UpgradeError('candidate_acceptance_required')
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
                self.save('complete', verified_schema10_snapshot=snapshot)
                self.restore_timers()
                return {'complete': True, 'version': VERSION, 'snapshot': snapshot,
                        'original_collectors_restored': True}
            except Exception:
                self._rollback()
                raise

    def wall_remaining(self):
        remaining = self.record['deadline_at'] - time.time()
        if remaining <= 0:
            raise UpgradeError('upgrade_deadline_exceeded')
        self.safe()
        return min(86400, remaining)


def rehearse():
    print(json.dumps(Upgrade().rehearsal(), sort_keys=True))


def upgrade():
    print(json.dumps(Upgrade().apply(), sort_keys=True))


def rollback():
    print(json.dumps(Upgrade().rollback(), sort_keys=True))


def finalize():
    print(json.dumps(Upgrade().finish(), sort_keys=True))
