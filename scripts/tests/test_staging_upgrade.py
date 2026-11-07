import contextlib
import importlib.util
import json
import os
from pathlib import Path
import select
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('staging_upgrade', ROOT / 'deploy/staging/upgrade.py')
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)
SNAPSHOT = 'devres-20261030T120000Z-pre-blake3'
CONFIG = (ROOT / 'deploy/staging/backend.toml.example').read_text().replace(
    upgrade.VERSION, upgrade.OLD_VERSION).replace('REPLACE_WITH_PRIVATE_POSTGRES_URL',
    'postgres://devres:' + 'a' * 64 + '@postgres:5432/devres').replace('0.1.0-build.d373818b', upgrade.OLD_VERSION)


class FakeTool:
    def __init__(self):
        self.commands = []
        self.counts = {'backend': 1, 'postgres': 1}
        self.fail_drain = False
        self.snapshot_failure = False

    def k(self, *args):
        self.commands.append(args)
        if args[:2] == ('get', 'deployment'):
            return upgrade.restore.OLD_SERVER
        if args[:2] == ('exec', 'deployment/postgres'):
            return '9'
        return ''

    def metrics(self):
        return {}

    def capacity_reason(self, metrics):
        return None

    def replicas(self, name):
        return self.counts[name]

    def scale(self, name, count):
        self.commands.append(('scale', name, count))
        self.counts[name] = count

    def stopped(self, name):
        self.commands.append(('stopped', name))
        if self.fail_drain and name == 'backend':
            raise upgrade.UpgradeError('drain_uncertain')

    def start(self, name, count):
        self.commands.append(('start', name, count))
        self.counts[name] = count

    def snapshot(self, label, upgrade=False):
        self.commands.append(('snapshot', label, upgrade))
        if self.snapshot_failure:
            raise RuntimeError('snapshot failed')
        return {'snapshot': SNAPSHOT}

    def postgres_shut_down(self):
        self.commands.append(('clean_postgres',))

    def mark_verified(self, value):
        self.commands.append(('mark_verified', value))


class FakeDrill:
    events = []
    initializations = []
    fail_command = None

    def __init__(self, *args, **kwargs):
        self.initializations.append(dict(kwargs))
        self.name = 'fake'
        self.token = 'b' * 24
        self.dataset = 'cachepool/devres-staging-restore-' + self.token
        self.root = Path('/tmp/fake-owned-restore')
        self.postgres_started = False
        self.snapshot = args[0] if args else SNAPSHOT
        self.resource_profile = kwargs.get('resource_profile', 'restore')
        self.offline_sequence = 0

    def prepare(self):
        self.events.append('prepare')

    def start_postgres(self):
        self.events.append('start_postgres')
        self.postgres_started = True

    def offline(self, command, **kwargs):
        self.events.append(command)
        if command == self.fail_command:
            raise upgrade.UpgradeError('offline_command_failed')

    def check(self, prepared=False):
        self.events.append('check')
        return {'schema': 11}

    def cleanup(self):
        self.events.append('cleanup')

    def owned(self, dataset):
        self.events.append('owned')


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='devres-upgrade-test-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = self.root / 'private'
        self.private.mkdir()
        (self.root / 'state').mkdir(mode=0o700)
        (self.private / 'backend.toml').write_text(CONFIG)
        self.commands = []
        self.watch_timers = {}
        self.inventory = {upgrade.m.DATASET + '/' + c for c in ('postgres', 'evidence')}
        self.guids = {upgrade.m.DATASET + '/postgres': '1', upgrade.m.DATASET + '/evidence': '2'}
        self.origins = {}
        self.instance = upgrade.Upgrade(run=self.fake_run, state_root=self.root / 'state', private=self.private,
                                        drill=FakeDrill, live=FakeDrill, verify=lambda *a, **k: {'schema': k['schema']})
        self.tool = FakeTool()
        self.instance.tool = self.tool
        self.qualifier = patch.object(self.instance, 'qualify_attribution')
        self.qualifier.start()
        self.addCleanup(self.qualifier.stop)
        self.writer = patch.object(upgrade.op, 'config_secret')
        self.writer.start()
        self.addCleanup(self.writer.stop)
        self.phase_record('rehearsed', deadline_seconds=1800, snapshot=SNAPSHOT)
        FakeDrill.events = []
        FakeDrill.initializations = []
        FakeDrill.fail_command = None

    def phase_record(self, phase, **updates):
        if phase == 'rehearsed':
            updates.setdefault('rehearsal_identity', upgrade.rehearsal_identity())
        record = {'version': 1, 'fence': None, 'operation': None, 'verified': [],
                  'phase': phase, 'token': 'a' * 24,
                  'timers': {'devres-staging-backup.timer': 'active'}, **updates}
        with self.instance.state.locked():
            self.instance.state.save(record)
        return record

    def fake_run(self, args, **kwargs):
        args = [str(v) for v in args]
        self.commands.append(args)
        if args[:2] == ['systemctl', 'enable'] and args[-1].startswith(upgrade.WATCHDOG):
            self.watch_timers[args[-1]] = True
        if args[:2] == ['systemctl', 'disable'] and args[-1].startswith(upgrade.WATCHDOG):
            self.watch_timers[args[-1]] = False
        if args[:2] == ['systemctl', 'show']:
            if args[-1].startswith(upgrade.WATCHDOG):
                enabled = self.watch_timers.get(args[-1], False)
                if args[3] == 'UnitFileState':
                    return 'enabled' if enabled else 'disabled'
                return 'active' if enabled else 'inactive'
            return 'inactive' if args[-1].endswith('.service') else 'active'
        if 'pg_controldata' in args:
            return 'Database cluster state: shut down'
        if args[:2] == ['zfs', 'get']:
            if args[-2] == 'guid':
                if args[-1].startswith('cachepool/devres-staging-restore-') or args[-1] == upgrade.m.DATASET:
                    return self.guids.get(args[-1], '3')
                return self.guids[args[-1]]
            return self.origins.get(args[-1], '-')
        if args[:2] == ['zfs', 'list']:
            return '\n'.join(sorted(self.inventory))
        if args[:2] == ['zfs', 'rename']:
            old, new = args[-2:]
            self.inventory.remove(old)
            self.inventory.add(new)
            self.guids[new] = self.guids.pop(old)
        if args[:2] == ['zfs', 'clone']:
            source, destination = args[-2:]
            self.inventory.add(destination)
            self.guids[destination] = '100' + self.guids[source.split('@')[0]]
            self.origins[destination] = source
        return ''

    def test_extended_command_budget_preserves_tighter_remaining_and_expiry(self):
        self.instance.record = {'deadline_seconds': 900000, 'deadline_at': 900000}
        self.instance.started = 0
        self.instance.clock = lambda: 10
        with patch.object(upgrade.time, 'time', return_value=10):
            self.assertEqual(self.instance.remaining(), 604800)
            self.assertEqual(self.instance.wall_remaining(), 604800)
            self.instance.record.update(deadline_seconds=100000, deadline_at=100000)
            self.assertEqual(self.instance.remaining(), 99990)
            self.assertEqual(self.instance.wall_remaining(), 99990)
            self.instance.record.update(mode='direct', deadline_at=50)
            self.assertEqual(self.instance.remaining(), 40)
            self.instance.record.update(deadline_at=10)
            with self.assertRaisesRegex(upgrade.UpgradeError, 'deadline_exceeded'):
                self.instance.wall_remaining()
            with self.assertRaisesRegex(upgrade.UpgradeError, 'deadline_exceeded'):
                self.instance.remaining()
            self.instance.record.pop('mode')
            self.instance.record['deadline_seconds'] = 10
            with self.assertRaisesRegex(upgrade.UpgradeError, 'deadline_exceeded'):
                self.instance.remaining()

    def hold_maintenance_lock(self):
        self.instance.maintenance_state.prepare()
        script = '''import fcntl,os,sys
fd=os.open(sys.argv[1],os.O_CREAT|os.O_RDWR,0o600)
fcntl.flock(fd,fcntl.LOCK_EX)
print('locked',flush=True)
sys.stdin.buffer.read(1)
os.close(fd)
'''
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', script,
                                  str(self.instance.maintenance_state.root / 'maintenance.lock')],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()
        self.addCleanup(cleanup)
        self.assertTrue(select.select([child.stdout], [], [], 10)[0], 'child did not acquire maintenance lock')
        self.assertEqual(child.stdout.readline().strip(), b'locked')
        return child

    def release_maintenance_lock(self, child, after=0.12):
        def release():
            child.stdin.write(b'x')
            child.stdin.flush()
        timer = threading.Timer(after, release)
        timer.start()
        self.addCleanup(timer.join, 2)
        self.addCleanup(timer.cancel)

    def test_safety_waits_for_real_short_guard_lock_without_holding_it_during_sleep(self):
        child = self.hold_maintenance_lock()
        self.release_maintenance_lock(child)
        checked = []
        original = self.instance.safe_unlocked
        def check():
            self.assertIsNotNone(child.poll())
            # The safety check itself must own the actual maintenance lock.
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, 'maintenance_busy'):
                with self.instance.maintenance_state.locked():
                    self.fail('safety check did not retain its maintenance lock')
            checked.append(True)
            original()
        with patch.object(self.instance, 'safe_unlocked', side_effect=check):
            self.instance.safe()
        self.assertEqual(checked, [True])
        with self.instance.maintenance_state.locked():
            pass

    def test_safety_persistent_real_lock_fails_within_bound_without_checks(self):
        self.hold_maintenance_lock()
        started = time.monotonic()
        with patch.object(upgrade, 'SAFETY_LOCK_WAIT_SECONDS', 0.15), \
                patch.object(self.instance, 'safe_unlocked') as check:
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, '^maintenance_busy$'):
                self.instance.safe()
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.12)
        self.assertLess(elapsed, 1)
        check.assert_not_called()

    def test_safety_short_guard_release_still_rejects_fence_operation_and_capacity(self):
        for failure in ('fence', 'operation', 'capacity'):
            with self.subTest(failure=failure):
                value = {'version': 1, 'fence': None, 'operation': None, 'verified': []}
                if failure != 'capacity':
                    value[failure] = {'phase': 'fenced'}
                self.instance.maintenance_state.save(value)
                child = self.hold_maintenance_lock()
                self.release_maintenance_lock(child)
                with patch.object(self.tool, 'capacity_reason', return_value='pool_low_free' if failure == 'capacity' else None), \
                        patch.object(self.instance, 'safe_unlocked', wraps=self.instance.safe_unlocked) as check:
                    with self.assertRaisesRegex(upgrade.UpgradeError, 'upgrade_capacity_or_maintenance_fenced'):
                        self.instance.safe()
                self.assertEqual(check.call_count, 1)
                child.wait(timeout=5)
                with self.instance.maintenance_state.locked():
                    pass

    def test_safety_body_busy_and_other_lock_errors_are_never_retried(self):
        with patch.object(self.instance, 'safe_unlocked', side_effect=upgrade.m.MaintenanceError('maintenance_busy')) as check, \
                patch.object(upgrade.time, 'sleep') as sleep:
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, '^maintenance_busy$'):
                self.instance.safe()
        self.assertEqual(check.call_count, 1)
        sleep.assert_not_called()
        with self.instance.maintenance_state.locked():
            pass
        with patch.object(self.instance.maintenance_state, 'locked', side_effect=upgrade.m.MaintenanceError('unsafe_lock_file')) as lock, \
                patch.object(upgrade.time, 'sleep') as sleep:
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, 'unsafe_lock_file'):
                self.instance.safe()
        self.assertEqual(lock.call_count, 1)
        sleep.assert_not_called()

    def test_safety_metrics_failure_is_checked_once_and_releases_lock(self):
        with patch.object(self.tool, 'metrics', side_effect=upgrade.m.MaintenanceError('command_failed')) as metrics, \
                patch.object(upgrade.time, 'sleep') as sleep:
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, 'command_failed'):
                self.instance.safe()
        self.assertEqual(metrics.call_count, 1)
        sleep.assert_not_called()
        with self.instance.maintenance_state.locked():
            pass

    def test_safety_absolute_deadline_clips_real_lock_wait_and_never_checks_after_expiry(self):
        self.hold_maintenance_lock()
        started = time.monotonic()
        with patch.object(self.instance, 'safe_unlocked') as check:
            with self.assertRaisesRegex(upgrade.UpgradeError, 'upgrade_deadline_exceeded'):
                self.instance.safe(deadline_at=time.time() + 0.12)
        self.assertLess(time.monotonic() - started, 1)
        check.assert_not_called()

    def test_safety_deadline_is_checked_after_acquisition_and_after_body(self):
        for times, body_called in (([99, 100], False), ([99, 99, 100], True)):
            with self.subTest(body_called=body_called):
                with patch.object(upgrade.time, 'time', side_effect=times), \
                        patch.object(self.instance, 'safe_unlocked') as check:
                    with self.assertRaisesRegex(upgrade.UpgradeError, 'upgrade_deadline_exceeded'):
                        self.instance.safe(deadline_at=100)
                self.assertEqual(check.call_count, int(body_called))
                with self.instance.maintenance_state.locked():
                    pass

    def test_wall_and_command_budget_recompute_after_wait_and_recovery_can_ignore_expired_cutoff(self):
        for budget in (self.instance.wall_remaining, self.instance.remaining):
            with self.subTest(budget=budget.__name__):
                self.instance.record = {'deadline_at': 100, 'mode': 'direct'}
                with patch.object(upgrade.time, 'time', side_effect=[90, 95]), \
                        patch.object(self.instance, 'safe') as check:
                    self.assertEqual(budget(), 5)
                check.assert_called_once_with(deadline_at=100)
        # The preserving recovery paths call safe() without an absolute deadline.
        # Their lock grace remains usable after the failed attempt's cutoff.
        with patch.object(upgrade.time, 'time', return_value=101):
            self.instance.safe()

    def test_config_changes_only_source_and_requested_scheduling_booleans(self):
        original = upgrade.tomllib.loads(CONFIG)
        original['rfc']['enabled'] = True
        text = CONFIG.replace('[rfc]\nenabled = false', '[rfc]\nenabled = true')
        changed = upgrade.tomllib.loads(upgrade.target_config(text))
        self.assertTrue(changed['rfc']['enabled'])
        changed['source'] = original['source']
        self.assertEqual(changed, original)
        paused = upgrade.tomllib.loads(upgrade.target_config(text, paused=True))
        self.assertTrue(all(not paused[c]['enabled'] for c in upgrade.restore.COLLECTORS))

    def test_journal_active_and_owned_containers_are_fail_closed(self):
        self.assertFalse(upgrade.active(self.root / 'state'))
        self.phase_record('running_migrate_storage', live_token='b' * 24)
        self.assertTrue(upgrade.active(self.root / 'state'))
        self.assertEqual(upgrade.owned_containers(self.root / 'state')['prefix'],
                         'devres-staging-restore-' + 'b' * 24)
        (self.instance.root / 'state.json').write_text('{}')
        with self.assertRaises(upgrade.UpgradeError):
            upgrade.active(self.root / 'state')

    def test_successful_upgrade_orders_offline_stages_and_leaves_collectors_paused(self):
        result = self.instance.apply()
        self.assertTrue(result['candidate_ready'])
        self.assertEqual(FakeDrill.initializations[-1]['resource_profile'], 'upgrade')
        self.assertEqual(FakeDrill.events, ['prepare', 'start_postgres', 'migrate-storage',
                         'verify-storage', 'activate-storage', 'cleanup'])
        record = upgrade.read_record(self.root / 'state')
        self.assertEqual(record['phase'], 'awaiting_acceptance')
        self.assertNotIn(['systemctl', 'start', 'devres-staging-backup.timer'], self.commands)
        self.assertIn(('snapshot', 'pre-blake3', True), self.tool.commands)
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        parsed = upgrade.tomllib.loads((self.private / 'backend.toml').read_text())
        self.assertTrue(all(not parsed[c]['enabled'] for c in upgrade.restore.COLLECTORS))
        self.assertFalse(any(kwargs.get('clone_quota') == '512G' for kwargs in FakeDrill.initializations))

    def test_watchdog_is_enabled_and_verified_before_first_backend_drain(self):
        scale = self.tool.scale
        def checked_scale(name, count):
            if name == 'backend' and count == 0:
                timer = self.instance.watchdog_timer()
                self.assertTrue(self.watch_timers.get(timer))
                self.assertIn(['systemctl', 'show', '-p', 'UnitFileState', '--value', timer], self.commands)
            return scale(name, count)
        self.tool.scale = checked_scale
        self.instance.apply()
        record = upgrade.read_record(self.root / 'state')
        self.assertEqual(record['watchdog_timer'], upgrade.WATCHDOG + record['token'] + '.timer')
        self.assertFalse(record['watchdog_cleanup_pending'])

    def test_partly_enabled_watchdog_failure_restores_timer_without_draining(self):
        run = self.instance.run
        def fail(args, **kwargs):
            result = run(args, **kwargs)
            if args[:2] == ['systemctl', 'enable']:
                raise RuntimeError('arming interrupted')
            return result
        self.instance.run = fail
        with self.assertRaisesRegex(RuntimeError, 'arming interrupted'):
            self.instance.apply()
        self.assertFalse(any(c[0] == 'scale' for c in self.tool.commands))
        self.assertEqual((self.private / 'backend.toml').read_text(), CONFIG)
        record = upgrade.read_record(self.root / 'state')
        self.assertEqual(record['phase'], 'rolled_back')
        self.assertFalse(self.watch_timers[record['watchdog_timer']])
        self.assertIn(['systemctl', 'start', 'devres-staging-backup.timer'], self.commands)

    def test_watchdog_must_be_persistently_enabled_not_merely_active(self):
        run = self.instance.run
        def disabled(args, **kwargs):
            if args[:4] == ['systemctl', 'show', '-p', 'UnitFileState']:
                return 'disabled'
            return run(args, **kwargs)
        self.instance.run = disabled
        with self.assertRaisesRegex(upgrade.UpgradeError, 'watchdog_not_armed'):
            self.instance.apply()
        self.assertFalse(any(c[0] == 'scale' for c in self.tool.commands))
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rolled_back')

    def test_rehearsal_restores_canonical_snapshot_and_old_pair_before_reporting_time(self):
        calls = []
        def verify(snapshot, **kwargs):
            calls.append((snapshot, kwargs))
            return {'schema': kwargs['schema']}
        self.instance.verify = verify
        clock = iter((0, 901))
        self.instance.clock = lambda: next(clock)
        result = self.instance.rehearsal()
        self.assertEqual(result['deadline_seconds'], 1802)
        self.assertEqual(FakeDrill.initializations[0]['resource_profile'], 'upgrade')
        self.assertEqual(result['rehearsal_identity'], upgrade.rehearsal_identity())
        self.assertTrue(all(value >= 0 for value in result['phase_seconds'].values()))
        self.assertEqual(set(result['phase_seconds']), {'snapshot', 'old_restore', 'migrate-storage',
                         'verify-storage', 'activate-storage', 'candidate_read', 'schema11_restore', 'rollback_restore'})
        self.assertEqual([kwargs['schema'] for _, kwargs in calls], [9, 11, 9])
        self.assertEqual([kwargs.get('clone_quota') for kwargs in FakeDrill.initializations], ['512G'])
        self.assertTrue(all('clone_quota' not in kwargs for _, kwargs in calls))
        self.assertEqual(calls[1][1]['source_dataset'],
                         'cachepool/devres-staging-restore-' + 'b' * 24)
        source = 'cachepool/devres-staging-restore-' + 'b' * 24 + '@' + SNAPSHOT + '-canonical'
        self.assertIn(['zfs', 'snapshot', '-r', source], self.commands)
        self.assertIn(['zfs', 'destroy', '-r', source], self.commands)
        self.assertFalse(any(c[:2] == ['zfs', 'destroy'] and c[-1].startswith(upgrade.m.DATASET + '@')
                             for c in self.commands))
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rehearsed')
        self.assertFalse(any(any(str(arg).startswith(upgrade.WATCHDOG) for arg in command)
                             for command in self.commands))

    def test_old_or_changed_rehearsal_identity_cannot_drain_or_replace_journal(self):
        identity = upgrade.rehearsal_identity()
        changed = [None]
        for key in ('server', 'version', 'source_url', 'bundle_sha256', 'resource_profile'):
            value = dict(identity)
            value[key] = 'changed'
            changed.append(value)
        for value in changed:
            with self.subTest(identity=value):
                before = self.phase_record('rehearsed', deadline_seconds=1800,
                                           snapshot=SNAPSHOT, rehearsal_identity=value)
                with self.assertRaisesRegex(upgrade.UpgradeError, 'matching_rehearsal_identity_required'):
                    self.instance.apply()
                self.assertEqual(upgrade.read_record(self.root / 'state'), before)
                self.assertFalse(self.tool.commands)
                self.assertFalse(self.commands)
                self.assertEqual((self.private / 'backend.toml').read_text(), CONFIG)

    def test_bundle_content_changes_rehearsal_identity(self):
        directory = self.root / 'bundle'
        directory.mkdir()
        for name in upgrade.BUNDLE_FILES:
            (directory / name).write_bytes((upgrade.HERE / name).read_bytes())
        with patch.object(upgrade, 'HERE', directory):
            before = upgrade.rehearsal_identity()
            with (directory / 'recovery.py').open('a') as output:
                output.write('\n# changed reviewed bundle\n')
            after = upgrade.rehearsal_identity()
        self.assertNotEqual(before['bundle_sha256'], after['bundle_sha256'])
        self.assertEqual(before['resource_profile'], after['resource_profile'])

    def test_resource_changes_change_rehearsal_identity(self):
        before = upgrade.rehearsal_identity()
        with patch.dict(upgrade.restore.RESOURCE_PROFILES['upgrade'], worker_memory='129g'):
            after = upgrade.rehearsal_identity()
        self.assertNotEqual(before['resource_profile'], after['resource_profile'])

    def test_bundle_changed_during_rehearsal_cannot_publish_measured_receipt(self):
        before = upgrade.rehearsal_identity()
        after = {**before, 'bundle_sha256': 'changed'}
        with patch.object(upgrade, 'rehearsal_identity', side_effect=[before, before, before, before, after]):
            with self.assertRaisesRegex(upgrade.UpgradeError, 'rehearsal_identity_changed'):
                self.instance.rehearsal()
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rehearsal_failed')
        self.assertEqual(FakeDrill.events[-1], 'cleanup')
        self.assertIn(['systemctl', 'start', 'devres-staging-backup.timer'], self.commands)

    def test_wrong_existing_image_does_not_stop_workloads_or_attempt_rollback(self):
        with patch.object(self.tool, 'k', return_value='unexpected'), patch.object(self.instance, '_rollback') as rollback:
            with self.assertRaisesRegex(upgrade.UpgradeError, 'unexpected_existing'):
                self.instance.apply()
        rollback.assert_not_called()
        self.assertFalse(any(c[0] == 'scale' for c in self.tool.commands))

    def test_failed_drain_never_restores_uncertain_writer_or_changes_config(self):
        self.tool.fail_drain = True
        with self.assertRaisesRegex(upgrade.UpgradeError, 'drain_uncertain'):
            self.instance.apply()
        self.assertEqual((self.private / 'backend.toml').read_text(), CONFIG)
        self.assertFalse(any(c[0] == 'start' for c in self.tool.commands))
        self.assertTrue(upgrade.active(self.root / 'state'))

    def test_early_secret_failure_restores_old_config_pair_and_timer(self):
        with patch.object(upgrade.op, 'config_secret', side_effect=[RuntimeError('secret failure'), None]):
            with self.assertRaisesRegex(RuntimeError, 'secret failure'):
                self.instance.apply()
        self.assertEqual((self.private / 'backend.toml').read_text(), CONFIG)
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rolled_back')
        self.assertIn(['systemctl', 'start', 'devres-staging-backup.timer'], self.commands)

    def test_early_write_failure_recovers_only_after_confirmed_drain(self):
        real_write = upgrade.op.write
        failed = False
        def write(path, content, *args):
            nonlocal failed
            if Path(path) == self.private / 'backend.toml' and not failed:
                failed = True
                raise OSError('injected')
            return real_write(path, content, *args)
        with patch.object(upgrade.op, 'write', side_effect=write):
            with self.assertRaises(OSError):
                self.instance.apply()
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rolled_back')

    def test_early_snapshot_failure_recovers_when_maintenance_fence_clear(self):
        self.tool.snapshot_failure = True
        with self.assertRaisesRegex(RuntimeError, 'snapshot failed'):
            self.instance.apply()
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        self.assertEqual((self.private / 'backend.toml').read_text(), CONFIG)

    def test_failed_migration_attempts_preserving_rollback_and_no_later_commands(self):
        FakeDrill.fail_command = 'migrate-storage'
        with patch.object(self.instance, '_rollback') as rollback:
            with self.assertRaisesRegex(upgrade.UpgradeError, 'offline_command_failed'):
                self.instance.apply()
        rollback.assert_called_once()
        self.assertEqual(FakeDrill.events[-1], 'cleanup')
        self.assertNotIn('activate-storage', FakeDrill.events)

    def test_rollback_renames_both_failed_datasets_and_clones_matching_original_pair(self):
        self.instance.apply()
        result = self.instance.rollback()
        self.assertTrue(result['rolled_back'])
        mutations = [c for c in self.commands if c[:2] in (['zfs', 'rename'], ['zfs', 'clone'])]
        self.assertEqual([c[1] for c in mutations], ['rename', 'clone', 'rename', 'clone'])
        self.assertTrue(all(name in self.inventory for name in result['preserved'].values()))
        self.assertFalse(any(c[:2] in (['zfs', 'destroy'], ['zfs', 'rollback']) for c in self.commands))
        self.assertEqual((self.private / 'backend.toml').read_text(), CONFIG)
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})

    def test_partial_rollback_can_resume_without_overwriting_preserved_pair(self):
        self.instance.apply()
        run = self.instance.run
        def fail_once(args, **kwargs):
            if args[:2] == ['zfs', 'clone'] and args[-1].endswith('/evidence'):
                raise RuntimeError('clone interrupted')
            return run(args, **kwargs)
        self.instance.run = fail_once
        with self.assertRaisesRegex(RuntimeError, 'clone interrupted'):
            self.instance.rollback()
        self.instance.run = run
        self.assertTrue(self.instance.rollback()['rolled_back'])

    def test_finish_requires_exact_independent_acceptance_receipt(self):
        self.instance.apply()
        upgrade.op.write(self.instance.root / 'acceptance.json', '{}')
        with self.assertRaisesRegex(upgrade.UpgradeError, 'receipt_mismatch'):
            self.instance.finish()
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'awaiting_acceptance')

    def test_finish_verifies_new_snapshot_before_restoring_original_collectors(self):
        self.instance.apply()
        receipt = {'version': upgrade.VERSION, 'token': upgrade.read_record(self.root / 'state')['token'], 'http': True, 'webtransport': True,
                   'revisions': ['2025-11-25', '2026-07-28'], 'retained': True,
                   'isolation': True, 'shared_services': True}
        upgrade.op.write(self.instance.root / 'acceptance.json', json.dumps(receipt))
        result = self.instance.finish()
        self.assertTrue(result['complete'])
        self.assertIn(('mark_verified', SNAPSHOT), self.tool.commands)
        self.assertIn(['zfs', 'release', '-r', upgrade.HOLD,
                       upgrade.m.DATASET + '@' + SNAPSHOT], self.commands)
        self.assertEqual(upgrade.tomllib.loads((self.private / 'backend.toml').read_text()),
                         upgrade.tomllib.loads(upgrade.target_config(CONFIG)))

    def test_expired_acceptance_rolls_back_preserving_candidate(self):
        self.instance.apply()
        record = upgrade.read_record(self.root / 'state')
        record['deadline_at'] = time.time() - 1
        self.instance.state.save(record)
        with self.assertRaisesRegex(upgrade.UpgradeError, 'deadline_exceeded'):
            self.instance.finish()
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rolled_back')

    def test_watchdog_expires_without_finish_and_preserves_matching_pair(self):
        self.instance.apply()
        record = upgrade.read_record(self.root / 'state')
        result = self.instance.expire(record['token'], wall_clock=lambda: record['deadline_at'])
        self.assertTrue(result['expired'])
        self.assertTrue(result['rolled_back'])
        self.assertTrue(result['watchdog_disarmed'])
        self.assertTrue(all(name in self.inventory for name in result['preserved'].values()))
        self.assertEqual((self.private / 'backend.toml').read_text(), CONFIG)
        self.assertFalse(any(c[:2] in (['zfs', 'destroy'], ['zfs', 'rollback']) for c in self.commands))
        mutations = [c[1] for c in self.commands if c[:2] in (['zfs', 'rename'], ['zfs', 'clone'])]
        self.assertEqual(mutations, ['rename', 'clone', 'rename', 'clone'])
        self.assertFalse(self.instance.expire(record['token'], wall_clock=lambda: float('inf'))['expired'])

    def test_watchdog_ignores_not_due_and_stale_tokens(self):
        self.instance.apply()
        record = upgrade.read_record(self.root / 'state')
        commands = list(self.commands)
        self.assertFalse(self.instance.expire(record['token'], wall_clock=lambda: record['deadline_at'] - 1)['expired'])
        self.assertFalse(self.instance.expire('f' * 24, wall_clock=lambda: record['deadline_at'] + 1)['expired'])
        self.assertEqual(self.commands, commands)

    def test_watchdog_resumes_after_capacity_lock_contention_during_dataset_swap(self):
        self.instance.apply()
        record = upgrade.read_record(self.root / 'state')
        due = lambda: record['deadline_at'] + 1
        with self.instance.maintenance_state.locked():
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, 'maintenance_busy'):
                self.instance.expire(record['token'], wall_clock=due)
        interrupted = upgrade.read_record(self.root / 'state')
        self.assertEqual(interrupted['phase'], 'rolling_back')
        self.assertEqual(self.tool.counts, {'backend': 0, 'postgres': 0})
        self.assertFalse(any(c[:2] == ['zfs', 'rename'] for c in self.commands))
        commands = list(self.commands)
        self.assertFalse(self.instance.expire(record['token'],
                         wall_clock=lambda: record['deadline_at'] - 1)['expired'])
        self.assertFalse(self.instance.expire('f' * 24, wall_clock=due)['expired'])
        self.assertEqual(self.commands, commands)
        result = self.instance.expire(record['token'], wall_clock=due)
        self.assertTrue(result['rolled_back'])
        self.assertTrue(all(name in self.inventory for name in result['preserved'].values()))
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rolled_back')

    def test_watchdog_resumes_partial_preserving_clone_failure(self):
        self.instance.apply()
        record = upgrade.read_record(self.root / 'state')
        due = lambda: record['deadline_at'] + 1
        run = self.instance.run
        def fail_clone(args, **kwargs):
            if args[:2] == ['zfs', 'clone'] and args[-1].endswith('/evidence'):
                raise RuntimeError('clone interrupted')
            return run(args, **kwargs)
        self.instance.run = fail_clone
        with self.assertRaisesRegex(RuntimeError, 'clone interrupted'):
            self.instance.expire(record['token'], wall_clock=due)
        interrupted = upgrade.read_record(self.root / 'state')
        self.assertEqual(interrupted['phase'], 'rolling_back')
        self.assertEqual(self.tool.counts, {'backend': 0, 'postgres': 0})
        self.assertTrue(all(name in self.inventory for name in interrupted['preserved'].values()))
        preserved_guids = {name: self.guids[name] for name in interrupted['preserved'].values()}
        self.instance.run = run
        result = self.instance.expire(record['token'], wall_clock=due)
        self.assertTrue(result['rolled_back'])
        self.assertEqual({name: self.guids[name] for name in result['preserved'].values()}, preserved_guids)
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        mutations = [c[1] for c in self.commands if c[:2] in (['zfs', 'rename'], ['zfs', 'clone'])]
        self.assertEqual(mutations, ['rename', 'clone', 'rename', 'clone'])
        self.assertFalse(any(c[:2] in (['zfs', 'destroy'], ['zfs', 'rollback']) for c in self.commands))

    def test_watchdog_ignores_absent_rehearsal_terminal_and_running_journals(self):
        for phase in [None, 'rehearsing', 'rehearsed', 'rehearsal_failed', 'complete',
                      'rolled_back', 'running_migrate_storage', 'starting_candidate']:
            with self.subTest(phase=phase):
                if phase is None:
                    (self.instance.root / 'state.json').unlink(missing_ok=True)
                else:
                    self.phase_record(phase)
                commands = list(self.commands)
                self.assertFalse(self.instance.expire('a' * 24)['expired'])
                self.assertEqual(self.commands, commands)

    def test_watchdog_rejects_invalid_tokens_and_deadlines_without_rollback(self):
        for token in (None, '', '../bad', 'g' * 24):
            with self.subTest(token=token), self.assertRaisesRegex(upgrade.UpgradeError, 'watch_token'):
                self.instance.expire(token)
        for deadline in (None, True, '100', 0, -1, float('nan'), float('inf'), float('-inf')):
            with self.subTest(deadline=deadline):
                self.phase_record('awaiting_acceptance', deadline_at=deadline)
                with patch.object(self.instance, '_rollback') as rollback:
                    with self.assertRaisesRegex(upgrade.UpgradeError, 'invalid_upgrade_deadline'):
                        self.instance.expire('a' * 24)
                    rollback.assert_not_called()

    def test_watchdog_busy_lock_retries_and_cli_returns_temporary_status(self):
        self.instance.apply()
        token = upgrade.read_record(self.root / 'state')['token']
        with self.instance.state.locked():
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, 'maintenance_busy'):
                self.instance.expire(token)
            with patch.object(upgrade, 'Upgrade', return_value=self.instance):
                with self.assertRaises(SystemExit) as stopped:
                    upgrade.expire(token)
                self.assertEqual(stopped.exception.code, 75)

    def test_watchdog_rejects_unusable_wall_clock_before_any_recovery(self):
        self.phase_record('awaiting_acceptance', deadline_at=1000)
        for now in (True, '1001', float('nan'), float('inf')):
            with self.subTest(now=now), patch.object(self.instance, '_rollback') as rollback:
                with self.assertRaisesRegex(upgrade.UpgradeError, 'invalid_upgrade_wall_clock'):
                    self.instance.expire('a' * 24, wall_clock=lambda: now)
                rollback.assert_not_called()

    def test_expiry_holds_upgrade_lock_through_preserving_recovery(self):
        self.instance.apply()
        record = upgrade.read_record(self.root / 'state')
        rollback = self.instance._rollback
        def checked_rollback():
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, 'maintenance_busy'):
                self.instance.finish()
            return rollback()
        with patch.object(self.instance, '_rollback', side_effect=checked_rollback):
            self.assertTrue(self.instance.expire(record['token'],
                            wall_clock=lambda: record['deadline_at'])['rolled_back'])

    def test_finish_holds_lock_against_expiry_and_terminal_state_is_not_rolled_back(self):
        self.instance.apply()
        token = upgrade.read_record(self.root / 'state')['token']
        receipt = {'version': upgrade.VERSION, 'token': token, 'http': True, 'webtransport': True,
                   'revisions': ['2025-11-25', '2026-07-28'], 'retained': True,
                   'isolation': True, 'shared_services': True}
        upgrade.op.write(self.instance.root / 'acceptance.json', json.dumps(receipt))
        def verify(*args, **kwargs):
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, 'maintenance_busy'):
                self.instance.expire(token, wall_clock=lambda: time.time())
            return {'schema': 10}
        self.instance.verify = verify
        self.assertTrue(self.instance.finish()['complete'])
        with patch.object(self.instance, '_rollback') as rollback:
            self.assertFalse(self.instance.expire(token)['expired'])
            rollback.assert_not_called()

    def test_watchdog_cleanup_failure_does_not_rollback_accepted_candidate(self):
        self.instance.apply()
        token = upgrade.read_record(self.root / 'state')['token']
        receipt = {'version': upgrade.VERSION, 'token': token, 'http': True, 'webtransport': True,
                   'revisions': ['2025-11-25', '2026-07-28'], 'retained': True,
                   'isolation': True, 'shared_services': True}
        upgrade.op.write(self.instance.root / 'acceptance.json', json.dumps(receipt))
        run = self.instance.run
        def fail(args, **kwargs):
            if args[:2] == ['systemctl', 'disable']:
                raise RuntimeError('timer cleanup unavailable')
            return run(args, **kwargs)
        self.instance.run = fail
        with patch.object(self.instance, '_rollback') as rollback:
            result = self.instance.finish()
            rollback.assert_not_called()
        self.assertTrue(result['complete'])
        self.assertFalse(result['watchdog_disarmed'])
        self.assertTrue(upgrade.read_record(self.root / 'state')['watchdog_cleanup_pending'])
        self.instance.run = run
        self.assertFalse(self.instance.expire(token)['expired'])
        self.assertFalse(upgrade.read_record(self.root / 'state')['watchdog_cleanup_pending'])
        self.assertFalse(any(c[:2] == ['systemctl', 'stop'] and c[-1].endswith('.service') for c in self.commands))

    def test_watchdog_cleanup_verifies_reboot_enablement_was_removed(self):
        self.instance.apply()
        token = upgrade.read_record(self.root / 'state')['token']
        receipt = {'version': upgrade.VERSION, 'token': token, 'http': True, 'webtransport': True,
                   'revisions': ['2025-11-25', '2026-07-28'], 'retained': True,
                   'isolation': True, 'shared_services': True}
        upgrade.op.write(self.instance.root / 'acceptance.json', json.dumps(receipt))
        run = self.instance.run
        def still_enabled(args, **kwargs):
            if (args[:4] == ['systemctl', 'show', '-p', 'UnitFileState']
                    and not self.watch_timers.get(args[-1], False)):
                return 'enabled'
            return run(args, **kwargs)
        self.instance.run = still_enabled
        with patch.object(self.instance, '_rollback') as rollback:
            result = self.instance.finish()
            rollback.assert_not_called()
        self.assertTrue(result['complete'])
        self.assertFalse(result['watchdog_disarmed'])
        self.assertTrue(upgrade.read_record(self.root / 'state')['watchdog_cleanup_pending'])

    def test_failed_new_snapshot_verification_preserves_candidate_then_rolls_back(self):
        self.instance.apply()
        receipt = {'version': upgrade.VERSION, 'token': upgrade.read_record(self.root / 'state')['token'],
                   'http': True, 'webtransport': True,
                   'revisions': ['2025-11-25', '2026-07-28'], 'retained': True,
                   'isolation': True, 'shared_services': True}
        upgrade.op.write(self.instance.root / 'acceptance.json', json.dumps(receipt))
        self.instance.verify = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('bad restore'))
        with self.assertRaisesRegex(RuntimeError, 'bad restore'):
            self.instance.finish()
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rolled_back')
        self.assertTrue(any('preserved-' in value for value in self.inventory))

    def test_stale_acceptance_is_removed_when_new_upgrade_is_admitted(self):
        upgrade.op.write(self.instance.root / 'acceptance.json', '{}')
        self.instance.apply()
        self.assertFalse((self.instance.root / 'acceptance.json').exists())

    def test_receipt_symlink_cannot_be_used(self):
        self.instance.apply()
        outside = self.root / 'untrusted'
        outside.write_text('{}')
        (self.instance.root / 'acceptance.json').symlink_to(outside)
        with self.assertRaises(OSError):
            self.instance.finish()
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'awaiting_acceptance')

    def test_rehearsal_timer_admission_failure_restores_original_timer(self):
        run = self.instance.run
        once = False
        def fail(args, **kwargs):
            nonlocal once
            if args[:2] == ['systemctl', 'stop'] and not once:
                once = True
                raise RuntimeError('timer failure')
            return run(args, **kwargs)
        self.instance.run = fail
        with self.assertRaisesRegex(RuntimeError, 'timer failure'):
            self.instance.rehearsal()
        self.assertIn(['systemctl', 'start', 'devres-staging-backup.timer'], self.commands)
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rehearsal_failed')

    def test_snapshot_uncertainty_keeps_existing_maintenance_fence_and_writer_stopped(self):
        # snapshot() already holds this lock; inject the resulting persisted
        # uncertainty without reacquiring it.
        def uncertain(label, upgrade=False):
            value = self.instance.maintenance_state.load()
            value['operation'] = {'phase': 'draining_postgres'}
            self.instance.maintenance_state.save(value)
            raise RuntimeError('uncertain snapshot')
        self.tool.snapshot = uncertain
        with self.assertRaisesRegex(upgrade.UpgradeError, 'maintenance_fenced'):
            self.instance.apply()
        self.assertFalse(any(c[0] == 'start' for c in self.tool.commands))
        self.assertTrue(upgrade.active(self.root / 'state'))

    def direct(self, seconds=1800):
        return self.instance.apply_direct(time.time() + seconds)

    def test_direct_requires_finite_future_absolute_deadline_before_admission(self):
        for deadline in (None, True, '1000', 0, time.time() - 1, float('nan'), float('inf')):
            with self.subTest(deadline=deadline):
                before = list(self.commands)
                with self.assertRaisesRegex(upgrade.UpgradeError, 'invalid_upgrade_deadline'):
                    self.instance.apply_direct(deadline)
                self.assertEqual(before, self.commands)

    def test_attribution_failure_preserves_pair_and_rolls_back_before_candidate_start(self):
        with patch.object(self.instance, 'qualify_attribution', side_effect=upgrade.UpgradeError('attribution_qualification_failed')), \
                patch.object(self.instance, 'start_candidate') as candidate:
            with self.assertRaisesRegex(upgrade.UpgradeError, 'attribution_qualification_failed'):
                self.direct()
        candidate.assert_not_called()
        record = upgrade.read_record(self.root / 'state')
        self.assertEqual(record['phase'], 'rolled_back')
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        self.assertTrue(all(name in self.inventory for name in record['preserved'].values()))

    def test_direct_uses_one_fresh_frozen_pair_without_rehearsal(self):
        (self.instance.root / 'state.json').unlink()
        seen = []
        def verify(snapshot, **kwargs):
            self.assertEqual(self.tool.counts, {'backend': 0, 'postgres': 0})
            self.assertGreater(kwargs['timeout'], 0)
            self.assertLessEqual(kwargs['timeout'], 1800)
            kwargs['on_drill'](FakeDrill())
            record = upgrade.read_record(self.root / 'state')
            self.assertEqual(record['live_kind'], 'restore')
            self.assertEqual(record['live_token'], 'b' * 24)
            self.assertNotIn('dataset_guids', record)
            seen.append((snapshot, kwargs['schema'], kwargs['server']))
            return {'schema': 9}
        self.instance.verify = verify
        result = self.direct()
        record = upgrade.read_record(self.root / 'state')
        self.assertEqual(record['mode'], 'direct')
        self.assertEqual(FakeDrill.initializations[-1]['resource_profile'], 'direct')
        self.assertNotIn('rehearsal_snapshot', record)
        self.assertEqual(record['phase'], 'awaiting_acceptance')
        self.assertEqual(seen, [(SNAPSHOT, 9, upgrade.restore.OLD_SERVER)])
        self.assertEqual(FakeDrill.events.count('migrate-storage'), 1)
        self.assertEqual(FakeDrill.events.count('verify-storage'), 1)
        self.assertEqual(FakeDrill.events.count('activate-storage'), 1)
        self.assertTrue(result['candidate_ready'])
        self.assertGreaterEqual(result['old_restore_seconds'], 0)

    def test_direct_failed_old_restore_recovers_unmodified_pair_without_migration(self):
        def fail(snapshot, **kwargs):
            kwargs['on_drill'](FakeDrill())
            raise RuntimeError('old restore failed')
        self.instance.verify = fail
        with self.assertRaisesRegex(RuntimeError, 'old restore failed'):
            self.direct()
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        self.assertEqual((self.private / 'backend.toml').read_text(), CONFIG)
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rolled_back')
        self.assertNotIn('migrate-storage', FakeDrill.events)
        self.assertFalse(any(c[:2] == ['zfs', 'rename'] for c in self.commands))

    def test_direct_migration_failure_preserves_pair_and_restores_original(self):
        for command in ('migrate-storage', 'verify-storage', 'activate-storage'):
            with self.subTest(command=command):
                FakeDrill.events = []
                FakeDrill.fail_command = command
                with self.assertRaisesRegex(upgrade.UpgradeError, 'offline_command_failed'):
                    self.direct()
                self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rolled_back')
                self.assertEqual((self.private / 'backend.toml').read_text(), CONFIG)
                self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
                self.assertNotIn('check', FakeDrill.events)
                # Each attempt must start from a fresh canonical old pair.
                self.inventory = {upgrade.m.DATASET + '/' + c for c in ('postgres', 'evidence')}
                self.guids = {upgrade.m.DATASET + '/postgres': '1', upgrade.m.DATASET + '/evidence': '2'}
                self.origins = {}

    def test_direct_restore_cannot_run_past_cutoff_and_start_migration(self):
        now = time.time()
        def verify(snapshot, **kwargs):
            kwargs['on_drill'](FakeDrill())
            return {'schema': 9}
        self.instance.verify = verify
        with patch.object(upgrade.time, 'time', side_effect=lambda: now):
            def elapsed_verify(snapshot, **kwargs):
                nonlocal now
                result = verify(snapshot, **kwargs)
                now += 1801
                return result
            self.instance.verify = elapsed_verify
            with self.assertRaisesRegex(upgrade.UpgradeError, 'deadline_exceeded'):
                self.direct()
        self.assertNotIn('migrate-storage', FakeDrill.events)
        self.assertEqual(upgrade.read_record(self.root / 'state')['phase'], 'rolled_back')

    def test_direct_expiry_before_migration_restores_original_without_dataset_swap(self):
        upgrade.op.write(self.instance.root / 'original-config.toml', CONFIG)
        self.phase_record('pre_upgrade_restore', mode='direct', deadline_at=1000,
                          drain_started=True, backend_drained=True, snapshot=SNAPSHOT)
        self.tool.counts = {'backend': 0, 'postgres': 0}
        self.assertTrue(self.instance.expire('a' * 24, wall_clock=lambda: 1000)['rolled_back'])
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        self.assertFalse(any(c[:2] == ['zfs', 'rename'] for c in self.commands))

    def test_direct_expiry_keeps_uncertain_snapshot_drain_fenced(self):
        upgrade.op.write(self.instance.root / 'original-config.toml', CONFIG)
        self.phase_record('pre_upgrade_restore', mode='direct', deadline_at=1000,
                          drain_started=True, backend_drained=True)
        self.tool.counts = {'backend': 0, 'postgres': 0}
        with self.instance.maintenance_state.locked():
            self.instance.maintenance_state.save({'version': 1, 'fence': None,
                                                  'operation': {'phase': 'snapshotting'}, 'verified': []})
        with self.assertRaisesRegex(upgrade.UpgradeError, 'maintenance_fenced'):
            self.instance.expire('a' * 24, wall_clock=lambda: 1000)
        self.assertEqual(self.tool.counts, {'backend': 0, 'postgres': 0})
        self.assertTrue(upgrade.active(self.root / 'state'))

    def test_direct_watchdog_stops_exact_driver_holding_migration_lock(self):
        self.direct()
        record = upgrade.read_record(self.root / 'state')
        script = '''import importlib.util,os,pathlib,signal,sys
spec=importlib.util.spec_from_file_location('owned_upgrade',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
state=module.m.State(pathlib.Path(sys.argv[2]))
with state.locked():
    record=module.read_record(pathlib.Path(sys.argv[2]).parent)
    record.update(phase='running_migrate_storage',driver_pid=os.getpid(),driver_start=module.process_start(os.getpid()))
    state.save(record)
    print('locked',flush=True)
    signal.pause()
'''
        child = subprocess.Popen([sys.executable, '-c', script, str(ROOT / 'deploy/staging/upgrade.py'),
                                  str(self.instance.root)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        self.addCleanup(child.stdout.close)
        self.assertTrue(select.select([child.stdout], [], [], 10)[0], 'child did not acquire upgrade lock')
        self.assertEqual(child.stdout.readline().strip(), 'locked')
        result = self.instance.expire(record['token'], wall_clock=lambda: record['deadline_at'])
        self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)
        self.assertTrue(result['rolled_back'])
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        self.assertTrue(all(name in self.inventory for name in result['preserved'].values()))

    def test_direct_watchdog_does_not_terminate_running_driver_before_deadline(self):
        self.direct()
        record = upgrade.read_record(self.root / 'state')
        with self.instance.state.locked(), patch.object(upgrade, 'terminate_driver') as terminate:
            with self.assertRaisesRegex(upgrade.m.MaintenanceError, 'maintenance_busy'):
                self.instance.expire(record['token'], wall_clock=lambda: record['deadline_at'] - 1)
            terminate.assert_not_called()

    def test_direct_finish_journals_restore_owner_and_retains_absolute_cutoff(self):
        self.direct()
        record = upgrade.read_record(self.root / 'state')
        receipt = {'version': upgrade.VERSION, 'token': record['token'], 'http': True, 'webtransport': True,
                   'revisions': ['2025-11-25', '2026-07-28'], 'retained': True,
                   'isolation': True, 'shared_services': True}
        upgrade.op.write(self.instance.root / 'acceptance.json', json.dumps(receipt))
        def verify(snapshot, **kwargs):
            self.assertEqual(kwargs['schema'], 11)
            self.assertLessEqual(kwargs['timeout'], 1800)
            kwargs['on_drill'](FakeDrill())
            self.assertEqual(upgrade.read_record(self.root / 'state')['live_kind'], 'restore')
            return {'schema': 10}
        self.instance.verify = verify
        self.assertTrue(self.instance.finish()['complete'])
        final = upgrade.read_record(self.root / 'state')
        self.assertEqual(final['deadline_at'], record['deadline_at'])
        self.assertIsNone(final['live_token'])

    def test_pidfd_supervision_rejects_reused_process_before_signalling(self):
        record = {'driver_pid': os.getpid() + 1000000, 'driver_start': '123'}
        with patch.object(upgrade.os, 'pidfd_open', return_value=123), \
                patch.object(upgrade.os, 'close'), \
                patch.object(upgrade, 'process_start', return_value='124'), \
                patch.object(upgrade.signal, 'pidfd_send_signal') as send:
            with self.assertRaisesRegex(upgrade.UpgradeError, 'identity_changed'):
                upgrade.terminate_driver(record)
            send.assert_not_called()

    def detached_resources(self, kind='restore'):
        token = upgrade.secrets.token_hex(12)
        name = 'devres-staging-restore-' + token
        runtime = Path('/tmp') / name
        runtime.mkdir(mode=0o700)
        self.addCleanup(lambda: runtime.exists() and upgrade.shutil.rmtree(runtime))
        upgrade.op.write(runtime / 'owner', token)
        for child in ('config', 'tls'):
            (runtime / child).mkdir()
        for child in ('postgres', 'evidence'):
            if kind == 'permanent':
                (runtime / child).symlink_to('/mnt/devres-staging/' + child)
            else:
                (runtime / child).mkdir()
        dataset = 'cachepool/' + name
        rows = {} if kind == 'permanent' else {
            dataset: [dataset, '10', '-', 'none', 'off', token],
            **{dataset + '/' + child: [dataset + '/' + child, str(index),
                upgrade.m.DATASET + '/' + child + '@' + SNAPSHOT,
                str(runtime / child), 'on', token] for index, child in enumerate(('postgres', 'evidence'), 11)}}
        server = upgrade.restore.OLD_SERVER if kind == 'restore' else upgrade.restore.SERVER
        container_id = 'c' * 64
        mounts = {'/data': ('/mnt/devres-staging/evidence' if kind == 'permanent' else str(runtime / 'evidence'), True),
                  '/etc/devres/config': (str(runtime / 'config'), False),
                  '/etc/devres/tls': (str(runtime / 'tls'), False)}
        container = {'Id': container_id, 'Name': '/' + name + '-backend',
                     'Config': {'Image': server, 'Labels': {upgrade.restore.LABEL_KEY: token}},
                     'HostConfig': {'NetworkMode': name, 'PortBindings': {}},
                     'Mounts': [{'Type': 'bind', 'Destination': key, 'Source': value[0], 'RW': value[1]}
                                for key, value in mounts.items()]}
        objects = {'rows': rows, 'containers': {container_id: container},
                   'network': {'Id': 'd' * 64, 'Name': name, 'Internal': True,
                               'Labels': {upgrade.restore.LABEL_KEY: token},
                               'Containers': {container_id: {}}}}
        self.phase_record('pre_upgrade_restore' if kind == 'restore' else 'running_migrate_storage',
                          mode='direct', live_kind=kind, live_schema=9 if kind == 'restore' else 10,
                          live_token=token, live_snapshot=SNAPSHOT)
        self.instance.record = upgrade.read_record(self.root / 'state')
        def run(args, **kwargs):
            self.commands.append(list(args))
            if args[:2] == ['zfs', 'list']:
                return '\n'.join('\t'.join(row) for row in objects['rows'].values())
            if args[:2] == ['zfs', 'destroy']:
                del objects['rows'][args[-1]]
            if args[:2] == ['docker', 'ps']:
                return '\n'.join(objects['containers'])
            if args[:2] == ['docker', 'inspect']:
                return json.dumps([objects['containers'][args[-1]]])
            if args[:2] == ['docker', 'rm']:
                del objects['containers'][args[-1]]
                objects['network']['Containers'].pop(args[-1], None)
            if args[:3] == ['docker', 'network', 'ls']:
                return name if objects['network'] else ''
            if args[:3] == ['docker', 'network', 'inspect']:
                return json.dumps([objects['network']])
            if args[:3] == ['docker', 'network', 'rm']:
                objects['network'] = None
            return ''
        self.instance.run = run
        return runtime, upgrade.owned_containers(self.root / 'state'), objects

    def test_direct_cleanup_preflights_mounts_before_stopping_any_container(self):
        runtime, owner, objects = self.detached_resources()
        objects['containers']['c' * 64]['Mounts'][0]['Source'] = '/mnt/foreign-permanent-data'
        before = len(self.commands)
        with self.assertRaisesRegex(upgrade.UpgradeError, 'container_mount_changed'):
            self.instance.cleanup_owned_resources(owner)
        self.assertFalse(any(args[:2] == ['docker', 'stop'] or args[:2] == ['zfs', 'destroy']
                             for args in self.commands[before:]))
        self.assertTrue(runtime.exists())

    def test_direct_cleanup_rejects_changed_clone_origin_without_mutation(self):
        _, owner, objects = self.detached_resources()
        child = 'cachepool/' + owner['prefix'] + '/evidence'
        objects['rows'][child][2] = upgrade.m.DATASET + '/evidence@unrelated'
        before = len(self.commands)
        with self.assertRaisesRegex(upgrade.UpgradeError, 'dataset_ownership_changed'):
            self.instance.cleanup_owned_resources(owner)
        self.assertFalse(any(args[:2] == ['docker', 'stop'] or args[:2] == ['zfs', 'destroy']
                             for args in self.commands[before:]))

    def test_direct_cleanup_removes_only_verified_disposable_objects(self):
        runtime, owner, objects = self.detached_resources()
        self.instance.stop_owned()
        self.assertEqual(objects, {'rows': {}, 'containers': {}, 'network': None})
        self.assertFalse(runtime.exists())
        self.assertIsNone(upgrade.read_record(self.root / 'state')['live_token'])
        self.assertTrue(all(args[-1].startswith('cachepool/' + owner['prefix'])
                            for args in self.commands if args[:2] == ['zfs', 'destroy']))

    def test_direct_cleanup_handles_permanent_binds_without_deleting_permanent_data(self):
        runtime, owner, objects = self.detached_resources(kind='permanent')
        self.instance.stop_owned()
        self.assertFalse(runtime.exists())
        self.assertEqual(objects, {'rows': {}, 'containers': {}, 'network': None})
        self.assertFalse(any(args[:2] == ['zfs', 'destroy'] for args in self.commands))

    def test_direct_cleanup_recovers_partial_prepare_before_container_creation(self):
        runtime, owner, objects = self.detached_resources(kind='permanent')
        (runtime / 'evidence').unlink()
        objects['containers'] = {}
        objects['network']['Containers'] = {}
        self.instance.stop_owned()
        self.assertFalse(runtime.exists())
        self.assertFalse(any(args[:2] == ['zfs', 'destroy'] for args in self.commands))

    def test_direct_cleanup_rejects_missing_permanent_link_with_detached_writer(self):
        runtime, owner, objects = self.detached_resources(kind='permanent')
        (runtime / 'evidence').unlink()
        with self.assertRaisesRegex(upgrade.UpgradeError, 'permanent_mount_changed'):
            self.instance.cleanup_owned_resources(owner)
        self.assertFalse(any(args[:2] == ['docker', 'stop'] for args in self.commands))


class AttributionQualifierTests(unittest.TestCase):
    def setUp(self):
        self.helper = UpgradeTests()
        self.helper.setUp()
        self.addCleanup(self.helper.doCleanups)
        self.helper.qualifier.stop()
        self.u, self.root = self.helper.instance, self.helper.root
        self.assets = self.root / 'attribution'
        self.assets.mkdir(mode=0o700)
        (self.assets / 'repair').write_bytes(b'first party executable fixture')
        (self.assets / 'repair').chmod(0o755)
        (self.assets / 'plan.json').write_text('{"fixed":"rfc-mdn"}')
        (self.assets / 'plan.json').chmod(0o600)
        for name in ('verify-retained.py', 'mdn-baseline.json'):
            upgrade.op.write(self.assets / name, 'reviewed fixture ' + name)
        self.plan_sha = upgrade.hashlib.sha256((self.assets / 'plan.json').read_bytes()).hexdigest()
        manifest = {'version': 1, 'release': upgrade.VERSION, 'server': upgrade.restore.SERVER,
                    'binary_sha256': upgrade.hashlib.sha256((self.assets / 'repair').read_bytes()).hexdigest(),
                    'plan_sha256': self.plan_sha, 'live_acquisition': True, 'maximum_requests': 20,
                    'retained_verifier_sha256': upgrade.hashlib.sha256((self.assets / 'verify-retained.py').read_bytes()).hexdigest(),
                    'mdn_baseline_sha256': upgrade.hashlib.sha256((self.assets / 'mdn-baseline.json').read_bytes()).hexdigest()}
        upgrade.op.write(self.assets / 'manifest.json', json.dumps(manifest))
        item = patch.object(upgrade.restore, 'ATTRIBUTION', self.assets)
        item.start(); self.addCleanup(item.stop)
        self.live = secrets.token_hex(12)
        runtime = self.root / 'runtime'
        runtime.mkdir(mode=0o700)
        for name in ('postgres', 'evidence', 'config'):
            (runtime / name).mkdir(mode=0o750)
        upgrade.op.write(runtime / 'config/backend.toml', upgrade.target_config(CONFIG, paused=True), mode=0o640)
        self.drill = SimpleNamespace(token=self.live, name='devres-staging-restore-' + self.live,
                                    root=runtime, postgres_started=True, backend_started=False,
                                    psql=lambda sql: '11' if 'version' in sql else 't')
        self.u.record = self.helper.phase_record('running_activate_storage', mode='direct',
            resource_profile='direct', live_token=self.live, live_kind='permanent',
            deadline_at=upgrade.SUPERSESSION_DEADLINE)
        self.u.record['target_identity'] = self.u.identity()
        self.u.save()
        self.commands, self.container, self.create_failure, self.start_failure = [], None, False, False
        self.u.run = self.host_run
        original_lstat = Path.lstat
        def metadata(path):
            info = original_lstat(path)
            if path == runtime / 'config/attribution-plan.json':
                values = list(info)
                values[5] = 65532  # model the successful root-only fchown in this unprivileged fixture
                return os.stat_result(values)
            return info
        for item in (patch.object(upgrade.os, 'chown'), patch.object(Path, 'lstat', metadata),
                     patch.object(upgrade.restore, 'bounded_diagnostic_output', side_effect=lambda *args:
                        {'data': json.dumps(self.receipt()).encode(), 'truncated': False, 'timed_out': False})):
            item.start(); self.addCleanup(item.stop)

    def receipt(self, **changes):
        return {'version': 1, 'release': upgrade.VERSION, 'schema': 11, 'integrity_active': True,
                'scope': 'fixed_retained_rfc_mdn', 'plan_sha256': self.plan_sha, 'policy_epoch': 1,
                'policy_fingerprint': upgrade.restore.ATTRIBUTION_POLICY, 'qualified_targets': 2,
                'providers': ['mdn', 'rfc'], 'request_attempts': 20, 'maximum_requests': 20,
                'ready': True, 'notices_verified': True, 'attribution_storage_verified': True,
                'target_set_digest': 'blake3:' + 'f' * 64, **changes}

    def host_run(self, argv):
        args = [str(value) for value in argv]
        self.commands.append(args)
        if args[:2] == ['docker', 'create']:
            self.assertIsNone(self.u.record['attribution_qualifier']['container_id'])
            mounts = {'/data': (self.drill.root / 'evidence', True),
                      '/etc/devres/config': (self.drill.root / 'config', False),
                      '/operator/repair': (self.assets / 'repair', False),
                      '/operator/plan.json': (self.drill.root / 'config/attribution-plan.json', False)}
            self.container = {'Id': 'a' * 64, 'Name': '/' + self.drill.name + '-attribution',
                'Config': {'Image': upgrade.restore.SERVER, 'Labels': {upgrade.restore.LABEL_KEY: self.live},
                    'User': '65532:65532', 'Entrypoint': ['/operator/repair'],
                    'Cmd': ['/etc/devres/config/backend.toml', '/operator/plan.json']},
                'HostConfig': {'NetworkMode': 'host', 'PortBindings': {}, 'ExtraHosts': ['postgres:172.28.0.2'],
                    'Memory': 16 * 1024**3, 'MemorySwap': 16 * 1024**3, 'NanoCpus': 2 * 10**9,
                    'PidsLimit': 128, 'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
                    'SecurityOpt': ['no-new-privileges'], 'Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=16g'}},
                'State': {'Running': False, 'ExitCode': 0, 'OOMKilled': False, 'Error': ''},
                'Mounts': [{'Type': 'bind', 'Source': str(source), 'Destination': target, 'RW': rw}
                           for target, (source, rw) in mounts.items()]}
            if self.create_failure:
                raise upgrade.UpgradeError('create_response_lost')
            return self.container['Id']
        if args[:2] == ['docker', 'inspect']:
            if args[-1].endswith('-postgres'):
                return json.dumps([{'Id': 'b' * 64, 'Config': {'Image': upgrade.restore.PG,
                    'Labels': {upgrade.restore.LABEL_KEY: self.live}}, 'State': {'Running': True},
                    'NetworkSettings': {'Networks': {self.drill.name: {'IPAddress': '172.28.0.2'}}},
                    'Mounts': [{'Type': 'bind', 'Source': str(self.drill.root / 'postgres'),
                                'Destination': '/var/lib/postgresql', 'RW': True}]}])
            return json.dumps([self.container])
        if args[:2] == ['docker', 'start']:
            self.assertEqual(self.u.record['attribution_qualifier']['container_id'], args[-1])
            self.assertEqual(self.u.record['attribution_attempt']['plan_sha256'], self.plan_sha)
            if self.start_failure:
                raise upgrade.UpgradeError('start_response_lost')
            return ''
        if args[:2] == ['docker', 'rm']:
            self.container = None
            return ''
        raise AssertionError(args)

    def test_single_stopped_owned_writer_records_id_before_start_and_reuses_verified_receipt(self):
        self.u.qualify_attribution(self.drill)
        state = upgrade.read_record(self.u.root.parent)
        self.assertEqual(state['qualified_schema'], 11)
        self.assertIsNone(state['attribution_qualifier'])
        self.assertIsNone(self.container)
        count = len(self.commands)
        self.u.qualify_attribution(self.drill)
        self.assertEqual(len(self.commands), count)
        creates = [args for args in self.commands if args[:2] == ['docker', 'create']]
        self.assertEqual(len(creates), 1)
        self.assertIn('--network', creates[0])
        self.assertNotIn('/etc/devres/tls', ' '.join(creates[0]))

    def test_create_response_loss_cannot_restart_or_issue_a_new_request_budget(self):
        self.create_failure = True
        with self.assertRaisesRegex(upgrade.UpgradeError, 'create_response_lost'):
            self.u.qualify_attribution(self.drill)
        self.assertFalse(self.container['State']['Running'])
        self.assertIsNone(self.u.record['attribution_qualifier']['container_id'])
        self.create_failure = False
        with self.assertRaisesRegex(upgrade.UpgradeError, 'already_attempted'):
            self.u.qualify_attribution(self.drill)
        self.assertEqual(len([a for a in self.commands if a[:2] == ['docker', 'create']]), 1)
        self.assertFalse(any(a[:2] == ['docker', 'start'] for a in self.commands))
        self.u.owned_container(self.container, {'token': self.live, 'prefix': self.drill.name}, self.drill.root)

    def test_start_response_loss_can_only_reconcile_stopped_strict_receipt_not_start_again(self):
        self.start_failure = True
        with self.assertRaisesRegex(upgrade.UpgradeError, 'start_response_lost'):
            self.u.qualify_attribution(self.drill)
        self.start_failure = False
        self.u.qualify_attribution(self.drill)
        self.assertEqual(len([a for a in self.commands if a[:2] == ['docker', 'start']]), 1)

    def test_receipt_budget_policy_and_unknown_fields_are_strict(self):
        for changed in ({'request_attempts': 21}, {'ready': False}, {'schema': 10},
                        {'plan_sha256': '0' * 64}, {'untrusted': 'private'}, {'qualified_targets': True}):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(upgrade.restore.RestoreError, 'receipt_invalid'):
                    upgrade.restore.attribution_receipt(self.receipt(**changed), self.plan_sha)

    def test_opt_in_manifest_and_asset_hashes_fail_before_any_container_creation(self):
        path = self.assets / 'manifest.json'
        original = path.read_text()
        for changes in ({'live_acquisition': False}, {'maximum_requests': 21},
                        {'server': upgrade.PREVIOUS_SERVER}, {'extra': 'untrusted'}):
            value = json.loads(original)
            value.update(changes)
            upgrade.op.write(path, json.dumps(value))
            with self.assertRaisesRegex(upgrade.restore.RestoreError, 'manifest_invalid'):
                self.u.qualify_attribution(self.drill)
        upgrade.op.write(path, original)
        (self.assets / 'repair').write_bytes(b'changed binary')
        with self.assertRaisesRegex(upgrade.restore.RestoreError, 'asset_hash_changed'):
            self.u.qualify_attribution(self.drill)
        self.assertFalse(self.commands)

    def test_hostnetwork_or_extra_mounts_are_not_general_worker_permissions(self):
        self.start_failure = True
        with self.assertRaises(upgrade.UpgradeError):
            self.u.qualify_attribution(self.drill)
        owner = {'token': self.live, 'prefix': self.drill.name}
        self.container['HostConfig']['ExtraHosts'] = ['postgres:1.1.1.1']
        with self.assertRaisesRegex(upgrade.UpgradeError, 'descriptor_changed'):
            self.u.owned_container(self.container, owner, self.drill.root)
        self.container['HostConfig']['ExtraHosts'] = ['postgres:172.28.0.2']
        self.container['Mounts'].append({'Type': 'bind', 'Source': '/private', 'Destination': '/extra', 'RW': True})
        with self.assertRaisesRegex(upgrade.UpgradeError, 'mount_changed'):
            self.u.owned_container(self.container, owner, self.drill.root)


class SupersessionTests(unittest.TestCase):
    def setUp(self):
        self.helper = UpgradeTests()
        self.helper.setUp()
        self.addCleanup(self.helper.doCleanups)
        self.u, self.root = self.helper.instance, self.helper.root
        (self.u.private / 'backend.toml').chmod(0o600)
        self.u.live = upgrade.LiveDrill
        self.original_run = self.u.run
        self.u.run = self.host_run
        self.installed = self.root / 'devres-staging'
        self.installed.mkdir(mode=0o700)
        for name in upgrade.BUNDLE_FILES:
            shutil.copyfile(ROOT / 'deploy/staging' / name, self.installed / name)
            (self.installed / name).chmod(0o600)
            with (self.installed / name).open('a') as stream:
                stream.write('\n# Inert previous operator fixture.\n')
        self.old_bundle = upgrade.bundle_at(self.installed)[0]
        temporary = self.root / 'next'
        temporary.mkdir(mode=0o700)
        for name in upgrade.STAGING_ASSETS:
            shutil.copyfile(ROOT / 'deploy/staging' / name, temporary / name)
            (temporary / name).chmod(0o600)
        self.new_bundle = upgrade.bundle_at(temporary)[0]
        self.stage = self.root / ('devres-staging-next-' + self.new_bundle)
        temporary.rename(self.stage)
        for name, value in (('INSTALLED', self.installed), ('HERE', self.stage), ('PREVIOUS_BUNDLE', self.old_bundle)):
            item = patch.object(upgrade, name, value)
            item.start()
            self.addCleanup(item.stop)
        self.token, self.live = secrets.token_hex(12), secrets.token_hex(12)
        self.runtime = Path('/tmp') / ('devres-staging-restore-' + self.live)
        self.runtime.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.runtime, True)
        for name in ('config', 'tls'):
            (self.runtime / name).mkdir(mode=0o750)
        for child in ('postgres', 'evidence'):
            (self.runtime / child).symlink_to('/mnt/devres-staging/' + child)
        upgrade.op.write(self.runtime / 'owner', self.live)
        upgrade.op.write(self.u.root / 'original-config.toml', CONFIG)
        upgrade.op.write(self.runtime / 'config/backend.toml', upgrade.target_config(CONFIG, paused=True).replace(
            upgrade.VERSION, upgrade.PREVIOUS_VERSION), mode=0o640)
        for name in ('backend.pem', 'backend-key.pem', 'client-ca.pem'):
            upgrade.op.write(self.runtime / 'tls' / name, 'fixture tls', mode=0o640)
            upgrade.op.write(self.u.private / name, 'fixture tls')
        self.helper.tool.counts = {'backend': 0, 'postgres': 0}
        self.helper.guids[upgrade.m.DATASET] = '3'
        old = self.u.identity()
        old.update(version=upgrade.PREVIOUS_VERSION, server=upgrade.PREVIOUS_SERVER,
                   source_url=upgrade.SOURCE + upgrade.PREVIOUS_VERSION + '/source.tar.gz', bundle_sha256=self.old_bundle)
        self.helper.phase_record('running_migrate_storage', token=self.token, live_token=self.live,
            live_kind='permanent', checkpoint_kind='permanent', mode='direct', pause_scope='rehearsal',
            resource_profile='direct', offline_command='migrate-storage', snapshot=SNAPSHOT,
            deadline_at=upgrade.SUPERSESSION_DEADLINE,
            dataset_guids={'postgres': '1', 'evidence': '2'},
            live_dataset_guids={upgrade.m.DATASET: '3', upgrade.m.DATASET + '/postgres': '1', upgrade.m.DATASET + '/evidence': '2'},
            target_identity=old, old_server=upgrade.restore.OLD_SERVER, old_version=upgrade.OLD_VERSION,
            watchdog_timer=upgrade.WATCHDOG + self.token + '.timer', watchdog_cleanup_pending=False)
        self.helper.watch_timers[upgrade.WATCHDOG + self.token + '.timer'] = True
        self.containers = {}
        for role, identifier, image in (('offline-1', 'a' * 64, upgrade.PREVIOUS_SERVER),
                                        ('postgres', 'b' * 64, upgrade.restore.PG)):
            mounts = {'/var/lib/postgresql': ('postgres', True)} if role == 'postgres' else {
                '/data': ('evidence', True), '/etc/devres/config': ('config', False), '/etc/devres/tls': ('tls', False)}
            self.containers[identifier] = {'Id': identifier, 'Name': '/' + self.runtime.name + '-' + role,
                'Config': {'Image': image, 'Labels': {upgrade.restore.LABEL_KEY: self.live}},
                'HostConfig': {'NetworkMode': self.runtime.name, 'PortBindings': {}, 'RestartPolicy': {'Name': 'no'}},
                'State': {'Running': True, 'ExitCode': 0, 'OOMKilled': False, 'Error': ''},
                'Mounts': [{'Type': 'bind', 'Destination': target, 'Source': str(self.runtime / source), 'RW': rw}
                           for target, (source, rw) in mounts.items()],
                'NetworkSettings': {'Networks': {self.runtime.name: {'IPAddress': '172.28.0.2'}}, 'Ports': {}}}
        self.calls, self.ignore_worker, self.dirty_pg = [], False, False
        self.network_exists = True
        script = r'''import fcntl,json,os,pathlib,signal,sys
root=pathlib.Path(sys.argv[1]);fd=os.open(root/'maintenance.lock',os.O_CREAT|os.O_RDWR,0o600)
fcntl.flock(fd,fcntl.LOCK_EX)
path=root/'state.json';value=json.loads(path.read_text())
value.update(driver_pid=os.getpid(),driver_start=pathlib.Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()[19],driver_boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
path.write_text(json.dumps(value,sort_keys=True)+'\n');print('locked',flush=True);signal.pause()
'''
        self.driver = subprocess.Popen([sys.executable, '-I', '-B', '-c', script, str(self.u.root)], stdout=subprocess.PIPE)
        def cleanup():
            if self.driver.poll() is None:
                self.driver.kill()
            self.driver.wait(timeout=5)
            self.driver.stdout.close()
        self.addCleanup(cleanup)
        self.assertTrue(select.select([self.driver.stdout], [], [], 10)[0])
        self.assertEqual(self.driver.stdout.readline().strip(), b'locked')
        self.before = (self.u.root / 'state.json').read_bytes()

    def host_run(self, arguments):
        args = [str(value) for value in arguments]
        self.calls.append(args)
        if args[:2] == ['zfs', 'get'] and args[-2] == 'guid':
            return self.helper.guids.get(args[-1].split('@')[0], '3') + ('0' if '@' in args[-1] else '')
        if args[:2] == ['zfs', 'holds']:
            return args[-1] + '\t' + upgrade.HOLD + '\tfixture'
        if args == ['zfs', 'list', '-H', '-o', 'name']:
            return '\n'.join(sorted(self.helper.inventory))
        if args[:2] == ['zfs', 'list']:
            rows = []
            for suffix, guid in (('', '3'), ('/postgres', '1'), ('/evidence', '2')):
                fields = [upgrade.m.DATASET + suffix, guid, '-', '/mnt/devres-staging' + suffix if suffix else 'none',
                          'on' if suffix else 'off']
                if any('quota,' in value for value in args):
                    fields.append('0')
                fields.append('devres-staging-v1')
                rows.append('\t'.join(fields))
            return '\n'.join(rows)
        if args[:2] == ['docker', 'ps']:
            return '\n'.join(self.containers) if '--no-trunc' in args else '\n'.join(
                value['Name'][1:] for value in self.containers.values())
        if args[:3] == ['docker', 'network', 'ls']:
            return self.runtime.name if self.network_exists else ''
        if args[:3] == ['docker', 'network', 'rm']:
            self.network_exists = False
            return ''
        if args[:3] == ['docker', 'network', 'inspect']:
            return json.dumps([{'Id': 'c' * 64, 'Name': self.runtime.name, 'Internal': True, 'EnableIPv6': False,
                'Labels': {upgrade.restore.LABEL_KEY: self.live}, 'Containers': {key: {} for key in self.containers}}])
        if args[:2] == ['docker', 'inspect']:
            selected = next(value for key, value in self.containers.items()
                            if args[-1] in (key, value['Name'][1:]))
            return json.dumps(selected['State']) if '--format' in args else json.dumps([selected])
        if args[:3] == ['docker', 'kill', '--signal=SIGTERM']:
            value = self.containers[args[-1]]
            if self.ignore_worker and value['Name'].endswith('offline-1'):
                return ''
            value['State'].update(Running=False, ExitCode=0 if value['Name'].endswith('postgres') else 1)
            return ''
        if args[:2] == ['docker', 'stop']:
            self.containers[args[-1]]['State'].update(Running=False, ExitCode=0)
            return ''
        if args[:2] == ['docker', 'rm']:
            self.containers.pop(args[-1])
            return ''
        if 'pg_controldata' in args and self.dirty_pg:
            return 'Database cluster state: in production'
        return self.original_run(args)

    def supersede(self, **kwargs):
        return self.u.supersede_target(self.token, self.old_bundle, upgrade.PREVIOUS_VERSION,
                                      upgrade.PREVIOUS_SERVER, self.new_bundle, **kwargs)

    def test_preflight_is_inert_and_full_transition_archives_then_exchanges_without_resume(self):
        self.assertTrue(self.supersede(check_only=True)['check_passed'])
        self.assertIsNone(self.driver.poll())
        self.assertEqual((self.u.root / 'state.json').read_bytes(), self.before)
        self.assertFalse(any(call[:2] in (['docker', 'kill'], ['docker', 'rm'], ['zfs', 'snapshot']) for call in self.calls))
        result = self.supersede()
        self.assertTrue(result['paired_progress_retained'])
        self.assertEqual(self.driver.wait(timeout=5), -signal.SIGTERM)
        record = upgrade.read_record(self.u.root.parent)
        self.assertEqual(record['phase'], upgrade.checkpoint.SUPERSEDED)
        self.assertEqual(record['pause_scope'], 'rehearsal')
        self.assertEqual(record['deadline_at'], upgrade.SUPERSESSION_DEADLINE)
        self.assertEqual(record['target_identity']['bundle_sha256'], self.new_bundle)
        self.assertEqual((self.u.root / ('supersession-' + self.token) / 'source-state.json').read_bytes(), self.before)
        self.assertEqual(upgrade.bundle_at(self.installed)[0], self.new_bundle)
        self.assertEqual(upgrade.bundle_at(self.stage)[0], self.old_bundle)
        self.assertNotIn('a' * 64, self.containers)
        self.assertFalse(self.containers['b' * 64]['State']['Running'])
        self.assertFalse(any(call[:2] == ['zfs', 'destroy'] or '-f' in call for call in self.calls))
        self.assertTrue(self.helper.watch_timers[upgrade.WATCHDOG + self.token + '.timer'])
        with patch.object(upgrade, 'HERE', self.installed):
            self.u.validate_installed_supersession(record['target_supersession'])
            self.assertTrue(self.supersede(check_only=True)['already_superseded'])

    def test_wrong_tuple_or_staged_bundle_refuses_before_driver_or_worker_signal(self):
        with self.assertRaisesRegex(upgrade.UpgradeError, 'previous_target_mismatch'):
            self.u.supersede_target(self.token, '0' * 64, upgrade.PREVIOUS_VERSION,
                                    upgrade.PREVIOUS_SERVER, self.new_bundle)
        (self.stage / 'upgrade.py').write_text('changed')
        with self.assertRaisesRegex(upgrade.UpgradeError, 'bundle_mismatch'):
            self.supersede()
        self.assertIsNone(self.driver.poll())
        self.assertFalse(any(call[:2] == ['docker', 'kill'] for call in self.calls))

    def test_clean_pg_failure_keeps_old_bundle_snapshot_and_archive_and_never_starts_new_writer(self):
        self.dirty_pg = True
        with self.assertRaisesRegex(upgrade.checkpoint.CheckpointError, 'postgres_not_clean'):
            self.supersede()
        self.assertEqual(upgrade.bundle_at(self.installed)[0], self.old_bundle)
        self.assertTrue((self.u.root / ('supersession-' + self.token) / 'source-state.json').exists())
        self.assertFalse(any(call[:2] in (['docker', 'start'], ['zfs', 'destroy']) for call in self.calls))
        self.assertEqual(upgrade.read_record(self.u.root.parent)['phase'], 'target_supersession_stopping')

    def test_snapshot_boundary_waits_for_real_short_guard_lock_and_runs_body_once(self):
        original = self.u.maintenance_locked
        entered = []
        @contextlib.contextmanager
        def contended(**kwargs):
            entered.append(kwargs)
            child = self.helper.hold_maintenance_lock()
            self.helper.release_maintenance_lock(child)
            with original(**kwargs):
                yield
        with patch.object(self.u, 'safe'), patch.object(self.u, 'maintenance_locked', side_effect=contended), \
                patch.object(self.u, 'safe_unlocked', wraps=self.u.safe_unlocked) as check:
            self.assertTrue(self.supersede()['paired_progress_retained'])
        self.assertEqual(entered, [{'deadline_at': upgrade.SUPERSESSION_DEADLINE}])
        self.assertEqual(check.call_count, 1)
        self.assertEqual(len([call for call in self.calls if call[:2] == ['zfs', 'snapshot']]), 1)

    def test_preformal_handoff_failure_can_canonically_rollback_preserving_failed_pair(self):
        self.dirty_pg = True
        with self.assertRaisesRegex(upgrade.checkpoint.CheckpointError, 'postgres_not_clean'):
            self.supersede()
        with self.assertRaisesRegex(upgrade.UpgradeError, 'supersession_source_state_changed'):
            self.supersede()
        with patch.object(self.helper.tool, 'postgres_shut_down',
                          side_effect=upgrade.m.MaintenanceError('postgres_not_clean')):
            result = self.u.rollback()
        record = upgrade.read_record(self.u.root.parent)
        self.assertTrue(result['rolled_back'])
        self.assertEqual(record['phase'], 'rolled_back')
        self.assertFalse(record['failed_pair_clean_shutdown'])
        for child, guid in (('postgres', '1'), ('evidence', '2')):
            kept = result['preserved'][child]
            self.assertIn(kept, self.helper.inventory)
            self.assertEqual(self.helper.guids[kept], guid)
            self.assertEqual(self.helper.origins[upgrade.m.DATASET + '/' + child], kept + '@' + SNAPSHOT)
        self.assertEqual((self.u.root / ('supersession-' + self.token) / 'source-state.json').read_bytes(), self.before)
        self.assertEqual(upgrade.bundle_at(self.installed)[0], self.old_bundle)
        self.assertFalse(any(call[:2] in (['docker', 'start'], ['zfs', 'destroy']) for call in self.calls))
        self.assertEqual(self.helper.tool.counts, {'backend': 1, 'postgres': 1})

    def test_exchange_failure_leaves_formal_paused_pair_and_can_retry_only_install(self):
        with patch.object(upgrade, 'exchange_bundles', side_effect=upgrade.UpgradeError('atomic_bundle_exchange_failed')):
            with self.assertRaisesRegex(upgrade.UpgradeError, 'atomic_bundle_exchange_failed'):
                self.supersede()
        record = upgrade.read_record(self.u.root.parent)
        self.assertEqual(record['phase'], upgrade.checkpoint.SUPERSEDED)
        before = len([call for call in self.calls if call[:2] == ['zfs', 'snapshot']])
        self.assertTrue(self.supersede()['superseded'])
        self.assertEqual(before, len([call for call in self.calls if call[:2] == ['zfs', 'snapshot']]))

    def test_permanent_pause_policy_remains_rehearsal_only_except_exact_sealed_resume(self):
        self.supersede()
        record = upgrade.read_record(self.u.root.parent)
        lifecycle = upgrade.checkpoint.Lifecycle(self.u)
        lifecycle.eligible(record)
        for changed in ({'phase': 'running_migrate_storage'}, {'supersession_resume_pending': False}):
            with self.assertRaisesRegex(upgrade.checkpoint.CheckpointError, 'not_enabled'):
                lifecycle.eligible({**record, **changed})
        archived = Path(record['target_supersession']['source_record'])
        archived.write_text('{}')
        with self.assertRaisesRegex(upgrade.checkpoint.CheckpointError, 'provenance_changed'):
            lifecycle.eligible(record)

    def test_expiry_and_wrong_image_fail_before_any_driver_or_container_signal(self):
        with patch.object(upgrade.time, 'time', return_value=upgrade.SUPERSESSION_DEADLINE):
            with self.assertRaisesRegex(upgrade.UpgradeError, 'direct_owner_required'):
                self.supersede()
        self.containers['a' * 64]['Config']['Image'] = 'unreviewed:image'
        with self.assertRaisesRegex(upgrade.UpgradeError, 'container_image_changed'):
            self.supersede()
        self.assertIsNone(self.driver.poll())
        self.assertFalse(any(call[:2] == ['docker', 'kill'] for call in self.calls))

    def test_runtime_source_and_transport_drift_are_rejected_by_read_only_preflight(self):
        path = self.runtime / 'config/backend.toml'
        original = path.read_text()
        upgrade.op.write(path, original.replace(upgrade.PREVIOUS_VERSION, '0.1.0-build.unreviewed'), mode=0o640)
        with self.assertRaisesRegex(upgrade.UpgradeError, 'source_config_changed'):
            self.supersede(check_only=True)
        upgrade.op.write(path, original, mode=0o640)
        upgrade.op.write(self.runtime / 'tls/backend.pem', 'drift', mode=0o640)
        with self.assertRaisesRegex(upgrade.UpgradeError, 'transport_identity_changed'):
            self.supersede(check_only=True)
        self.assertIsNone(self.driver.poll())
        self.assertEqual((self.u.root / 'state.json').read_bytes(), self.before)

    def test_unresponsive_worker_is_not_force_killed_or_claimed_clean(self):
        self.ignore_worker = True
        with patch.object(upgrade.restore, 'OFFLINE_STOP_SECONDS', 0):
            with self.assertRaisesRegex(upgrade.restore.RestoreError, 'cooperative_stop_unconfirmed'):
                self.supersede()
        self.assertTrue(self.containers['a' * 64]['State']['Running'])
        self.assertTrue(self.containers['b' * 64]['State']['Running'])
        self.assertFalse(any('SIGKILL' in call or '-f' in call or call[:2] == ['zfs', 'snapshot'] for call in self.calls))
        self.assertEqual(upgrade.bundle_at(self.installed)[0], self.old_bundle)


if __name__ == '__main__':
    unittest.main()
