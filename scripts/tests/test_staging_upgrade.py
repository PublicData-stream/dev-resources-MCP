import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('staging_upgrade', ROOT / 'deploy/staging/upgrade.py')
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)
SNAPSHOT = 'devres-20261030T120000Z-pre-blake3'
CONFIG = (ROOT / 'deploy/staging/backend.toml.example').read_text().replace(
    upgrade.VERSION, upgrade.OLD_VERSION).replace('REPLACE_WITH_PRIVATE_POSTGRES_URL',
    'postgres://devres:' + 'a' * 64 + '@postgres:5432/devres')


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
    fail_command = None

    def __init__(self, *args, **kwargs):
        self.name = 'fake'
        self.token = 'b' * 24
        self.dataset = 'cachepool/devres-staging-restore-' + self.token
        self.root = Path('/tmp/fake-owned-restore')
        self.postgres_started = False

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
        return {'schema': 10}

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
        self.writer = patch.object(upgrade.op, 'config_secret')
        self.writer.start()
        self.addCleanup(self.writer.stop)
        self.phase_record('rehearsed', deadline_seconds=1800, snapshot=SNAPSHOT)
        FakeDrill.events = []
        FakeDrill.fail_command = None

    def phase_record(self, phase, **updates):
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
            return self.guids[args[-1]] if args[-2] == 'guid' else self.origins.get(args[-1], '-')
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
        self.assertEqual(FakeDrill.events, ['prepare', 'start_postgres', 'migrate-storage',
                         'verify-storage', 'activate-storage', 'cleanup'])
        record = upgrade.read_record(self.root / 'state')
        self.assertEqual(record['phase'], 'awaiting_acceptance')
        self.assertNotIn(['systemctl', 'start', 'devres-staging-backup.timer'], self.commands)
        self.assertIn(('snapshot', 'pre-blake3', True), self.tool.commands)
        self.assertEqual(self.tool.counts, {'backend': 1, 'postgres': 1})
        parsed = upgrade.tomllib.loads((self.private / 'backend.toml').read_text())
        self.assertTrue(all(not parsed[c]['enabled'] for c in upgrade.restore.COLLECTORS))

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
        self.assertEqual([kwargs['schema'] for _, kwargs in calls], [9, 10, 9])
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
                self.instance.expire(token, wall_clock=lambda: float('inf'))
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


if __name__ == '__main__':
    unittest.main()
