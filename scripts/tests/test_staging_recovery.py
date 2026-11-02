import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('staging_recovery', ROOT / 'deploy/staging/recovery.py')
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
TOKEN, LIVE = 'a' * 24, 'b' * 24
SNAPSHOT = 'devres-20261102T120000Z-upgrade-rehearsal'
CONTAINER, NETWORK = 'c' * 64, 'd' * 64


class FakeProcesses:
    def __init__(self):
        self.value = {'pid': 3817748, 'start': '123456', 'ppid': 1,
                      'uid': [0, 0, 0, 0], 'exe': '/usr/bin/python3.12',
                      'argv': ['python3', str(recovery.HERE / 'staging.py'), 'upgrade-rehearse']}
        self.signals = []
        self.changed_on_open = False
        self.ignore_signals = False

    def holders(self, lock):
        return [self.value['pid']] if self.value else []

    def identity(self, pid):
        return copy.deepcopy(self.value)

    def open(self, pid):
        if self.changed_on_open:
            self.value['start'] = '999999'
        return 72

    def send(self, fd, sig):
        self.signals.append(sig)
        if not self.ignore_signals:
            self.value = None

    def close(self, fd):
        pass


class Host:
    def __init__(self, root):
        self.root, self.name = root, root.name
        self.parent = 'cachepool/' + self.name
        self.datasets = {self.parent: ['100', '-', 'none', 'off', LIVE]}
        for index, child in enumerate(('postgres', 'evidence')):
            self.datasets[self.parent + '/' + child] = [str(101 + index),
                recovery.maintenance.DATASET + '/' + child + '@' + SNAPSHOT,
                str(root / child), 'on', LIVE]
        self.containers = {}
        self.add_container(CONTAINER, 'offline-1')
        self.add_container('e' * 64, 'postgres')
        self.network = {'Name': self.name, 'Id': NETWORK, 'Internal': True,
                        'Labels': {recovery.restore.LABEL_KEY: LIVE}, 'Containers': {}}
        self.commands = []
        self.fail_remove = False
        self.fail_timer = False
        self.hold = True

    def add_container(self, identifier, role):
        mounts = ([('postgres', '/var/lib/postgresql', True)] if role == 'postgres' else
                  [('evidence', '/data', True), ('config', '/etc/devres/config', False),
                   ('tls', '/etc/devres/tls', False)])
        self.containers[identifier] = {'Id': identifier, 'Name': '/' + self.name + '-' + role,
            'Config': {'Labels': {recovery.restore.LABEL_KEY: LIVE},
                       'Image': recovery.restore.PG if role == 'postgres' else recovery.OLD_REHEARSAL_SERVER},
            'HostConfig': {'NetworkMode': self.name, 'PortBindings': {}},
            'Mounts': [{'Type': 'bind', 'Source': str(self.root / source),
                        'Destination': dest, 'RW': rw} for source, dest, rw in mounts]}

    def run(self, args):
        args = [str(value) for value in args]
        self.commands.append(args)
        if args[:2] == ['zfs', 'get']:
            return '200'
        if args[:2] == ['zfs', 'holds']:
            return args[-1] + '\tdevres-upgrade-protected\t0\n' if self.hold else ''
        if args[:2] == ['zfs', 'list']:
            return '\n'.join('\t'.join([key, *value]) for key, value in self.datasets.items())
        if args[:2] == ['zfs', 'destroy']:
            del self.datasets[args[-1]]
            return ''
        if args[:2] == ['docker', 'ps']:
            return '\n'.join(self.containers)
        if args[:2] == ['docker', 'inspect']:
            return json.dumps([self.containers[key] for key in args[4:]])
        if args[:2] == ['docker', 'stop']:
            return args[-1]
        if args[:2] == ['docker', 'rm']:
            if self.fail_remove:
                self.fail_remove = False
                raise recovery.RecoveryError('injected_container_remove_failure')
            del self.containers[args[-1]]
            return ''
        if args[:3] == ['docker', 'network', 'ls']:
            return self.name if self.network else ''
        if args[:3] == ['docker', 'network', 'inspect']:
            return json.dumps([self.network])
        if args[:3] == ['docker', 'network', 'rm']:
            self.network = None
            return ''
        if args[:1] == ['systemctl']:
            if self.fail_timer:
                self.fail_timer = False
                raise recovery.RecoveryError('injected_timer_failure')
            return ''
        raise AssertionError(args)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='devres-recovery-test-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = self.base / 'state'
        self.journal = self.state / 'upgrade'
        self.journal.mkdir(mode=0o700, parents=True)
        self.runtime = self.base / ('devres-staging-restore-' + LIVE)
        self.runtime.mkdir(mode=0o700)
        for name in ('postgres', 'evidence', 'config', 'tls'):
            (self.runtime / name).mkdir()
        (self.runtime / 'owner').write_text(LIVE)
        (self.runtime / 'owner').chmod(0o600)
        (self.journal / 'maintenance.lock').touch(mode=0o600)
        self.record = {'version': 1, 'phase': 'rehearsing', 'token': TOKEN,
                       'live_token': LIVE, 'snapshot': SNAPSHOT,
                       'timers': {'devres-staging-backup.timer': 'active'},
                       'verified': [], 'fence': None, 'operation': None}
        recovery.maintenance.State(self.journal).save(self.record)
        self.host = Host(self.runtime)
        self.processes = FakeProcesses()
        self.now = 0

    def tick(self, value):
        self.now += value

    def tool(self, **kwargs):
        return recovery.Recovery(run=self.host.run, state_root=self.state,
            tmp_root=self.base, processes=self.processes, clock=lambda: self.now,
            sleep=self.tick, **kwargs)

    def saved(self):
        return json.loads((self.journal / 'state.json').read_text())

    def mutations(self):
        return [args for args in self.host.commands if args[:2] in (
            ['docker', 'stop'], ['docker', 'rm'], ['zfs', 'destroy'])
            or args[:3] == ['docker', 'network', 'rm'] or args[0] == 'systemctl']

    def test_abort_stops_exact_process_cleans_owned_clones_and_preserves_snapshot(self):
        result = self.tool().abort_rehearsal(TOKEN)
        self.assertTrue(result['snapshot_preserved'])
        self.assertEqual(self.processes.signals, [signal.SIGTERM])
        self.assertEqual(self.saved()['phase'], 'rehearsal_failed')
        self.assertIsNone(self.saved()['live_token'])
        self.assertFalse(self.runtime.exists())
        self.assertFalse(self.host.datasets)
        self.assertFalse(self.host.containers)
        self.assertIsNone(self.host.network)
        commands = self.mutations()
        self.assertEqual(commands[-1], ['systemctl', 'start', 'devres-staging-backup.timer'])
        destroys = [args for args in commands if args[:2] == ['zfs', 'destroy']]
        self.assertEqual(len(destroys), 3)
        self.assertTrue(all(args[-1].startswith(self.host.parent) and '@' not in args[-1] for args in destroys))
        self.assertTrue(all('-r' not in args and '-R' not in args for args in destroys))
        first_destroy = next(i for i, args in enumerate(commands) if args[:2] == ['zfs', 'destroy'])
        last_remove = max(i for i, args in enumerate(commands) if args[:2] == ['docker', 'rm'])
        self.assertLess(last_remove, first_destroy)
        self.assertFalse(any(args[:2] in (['zfs', 'release'], ['k3s', 'kubectl']) for args in self.host.commands))

    def test_invalid_or_wrong_token_never_signals_or_mutates_resources(self):
        for token in ('../bad', 'b' * 24, None):
            with self.subTest(token=token), self.assertRaises(recovery.RecoveryError):
                self.tool().abort_rehearsal(token)
        self.assertFalse(self.processes.signals)
        self.assertFalse(self.mutations())

    def test_exact_isolated_python_flags_match_the_observed_orphan(self):
        self.processes.value['argv'] = ['/usr/bin/python3', '-I', '-B',
            str(recovery.HERE / 'staging.py'), 'upgrade-rehearse']
        self.assertTrue(self.tool().abort_rehearsal(TOKEN)['rehearsal_aborted'])
        self.assertEqual(self.processes.signals, [signal.SIGTERM])

    def test_linux_proc_reads_match_a_real_test_lock_and_pidfd(self):
        processes = recovery.Processes()
        lock_path = self.base / 'test-process.lock'
        with lock_path.open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(processes.holders(lock_path), [os.getpid()])
            identity = processes.identity(os.getpid())
            self.assertEqual(identity['pid'], os.getpid())
            self.assertEqual(identity['ppid'], os.getppid())
            self.assertEqual(identity['uid'][1], os.geteuid())
            self.assertTrue(identity['start'].isdigit())
            fd = processes.open(os.getpid())
            processes.close(fd)

    def test_real_cutover_is_outside_rehearsal_abort_authority(self):
        for field, value in (('phase', 'running_migrate_storage'), ('backend_drained', True),
                             ('dataset_guids', {'postgres': '99'}), ('watchdog_timer', 'timer')):
            record = dict(self.record, **{field: value})
            recovery.maintenance.State(self.journal).save(record)
            with self.subTest(field=field), self.assertRaisesRegex(recovery.RecoveryError, 'disposable_rehearsal'):
                self.tool().abort_rehearsal(TOKEN)
        self.assertFalse(self.processes.signals)
        self.assertFalse(self.mutations())

    def test_wrong_process_or_pid_reuse_never_receives_signal(self):
        for field, value in (('ppid', 42), ('uid', [1000] * 4),
                             ('argv', ['python3', '/other/staging.py', 'upgrade-rehearse']),
                             ('exe', '/tmp/python3')):
            original = copy.deepcopy(self.processes.value)
            self.processes.value[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(recovery.RecoveryError, 'orphan_rehearsal'):
                self.tool().abort_rehearsal(TOKEN)
            self.processes.value = original
        self.processes.changed_on_open = True
        with self.assertRaisesRegex(recovery.RecoveryError, 'identity_changed'):
            self.tool().abort_rehearsal(TOKEN)
        self.assertFalse(self.processes.signals)
        self.assertFalse(self.mutations())

    def test_ownership_or_permanent_mount_mismatch_fails_before_signal(self):
        original = copy.deepcopy(self.host.containers[CONTAINER])
        for change in ('label', 'mount', 'image', 'network'):
            info = self.host.containers[CONTAINER]
            if change == 'label':
                info['Config']['Labels'][recovery.restore.LABEL_KEY] = 'wrong'
            elif change == 'mount':
                info['Mounts'][0]['Source'] = '/mnt/devres-staging/evidence'
            elif change == 'image':
                info['Config']['Image'] = 'unreviewed:latest'
            else:
                info['HostConfig']['NetworkMode'] = 'host'
            with self.subTest(change=change), self.assertRaises(recovery.RecoveryError):
                self.tool().abort_rehearsal(TOKEN)
            self.host.containers[CONTAINER] = copy.deepcopy(original)
        self.assertFalse(self.processes.signals)
        self.assertFalse(self.mutations())

    def test_dataset_owner_origin_and_unexpected_snapshot_are_rejected(self):
        key = self.host.parent + '/evidence'
        original = self.host.datasets[key][:]
        for index, value in ((4, 'wrong'), (1, 'cachepool/unrelated@snapshot'),
                             (3, 'off'), (2, '/mnt/devres-staging/evidence')):
            self.host.datasets[key][index] = value
            with self.subTest(index=index), self.assertRaises(recovery.RecoveryError):
                self.tool().abort_rehearsal(TOKEN)
            self.host.datasets[key] = original[:]
        self.host.datasets[key + '@unexpected'] = ['103', '-', '-', '-', LIVE]
        with self.assertRaisesRegex(recovery.RecoveryError, 'tree_changed'):
            self.tool().abort_rehearsal(TOKEN)
        self.assertFalse(self.processes.signals)
        self.assertFalse(self.mutations())

    def test_unprotected_snapshot_never_signals_or_cleans(self):
        self.host.hold = False
        with self.assertRaisesRegex(recovery.RecoveryError, 'protected_rehearsal_snapshot'):
            self.tool().abort_rehearsal(TOKEN)
        self.assertFalse(self.processes.signals)
        self.assertFalse(self.mutations())

    def test_unowned_network_endpoint_and_runtime_symlink_refuse_before_signal(self):
        self.host.network['Containers'] = {'f' * 64: {}}
        with self.assertRaisesRegex(recovery.RecoveryError, 'network_ownership'):
            self.tool().abort_rehearsal(TOKEN)
        self.host.network['Containers'] = {}
        (self.runtime / 'evidence').rmdir()
        (self.runtime / 'evidence').symlink_to(self.base)
        with self.assertRaisesRegex(recovery.RecoveryError, 'runtime_symlink'):
            self.tool().abort_rehearsal(TOKEN)
        self.assertFalse(self.processes.signals)
        self.assertFalse(self.mutations())

    def test_failed_removal_keeps_journal_active_and_timers_paused_then_resumes(self):
        self.host.fail_remove = True
        with self.assertRaisesRegex(recovery.RecoveryError, 'injected_container_remove'):
            self.tool().abort_rehearsal(TOKEN)
        self.assertEqual(self.saved()['phase'], 'rehearsing')
        self.assertFalse(any(args[0] == 'systemctl' for args in self.host.commands))
        self.assertTrue(self.tool().abort_rehearsal(TOKEN)['timers_restored'])
        self.assertEqual(self.processes.signals, [signal.SIGTERM])

    def test_partial_dataset_cleanup_resumes_using_original_guids(self):
        tool = self.tool()
        run = self.host.run
        fail = [True]
        def interrupted(args):
            if args[:2] == ['zfs', 'destroy'] and args[-1].endswith('/evidence') and fail[0]:
                fail[0] = False
                raise recovery.RecoveryError('interrupted_dataset_cleanup')
            return run(args)
        tool.run = interrupted
        with self.assertRaisesRegex(recovery.RecoveryError, 'interrupted_dataset'):
            tool.abort_rehearsal(TOKEN)
        self.assertNotIn(self.host.parent + '/postgres', self.host.datasets)
        self.assertTrue(self.tool().abort_rehearsal(TOKEN)['snapshot_preserved'])

    def test_timer_failure_resumes_after_cleaned_journal_and_idempotent_completion(self):
        self.host.fail_timer = True
        with self.assertRaisesRegex(recovery.RecoveryError, 'injected_timer'):
            self.tool().abort_rehearsal(TOKEN)
        self.assertEqual(self.saved()['phase'], 'rehearsal_failed')
        self.assertIsNone(self.saved()['live_token'])
        self.assertTrue(self.tool().abort_rehearsal(TOKEN)['timers_restored'])
        self.assertTrue(self.tool().abort_rehearsal(TOKEN)['timers_restored'])
        self.assertEqual(self.processes.signals, [signal.SIGTERM])

    def test_changed_remaining_dataset_identity_refuses_resume(self):
        self.host.fail_remove = True
        with self.assertRaises(recovery.RecoveryError):
            self.tool().abort_rehearsal(TOKEN)
        self.host.datasets[self.host.parent][0] = '999'
        before = len(self.mutations())
        with self.assertRaisesRegex(recovery.RecoveryError, 'inventory_changed'):
            self.tool().abort_rehearsal(TOKEN)
        self.assertEqual(len(self.mutations()), before)

    def test_bounded_process_stop_and_lock_wait_do_not_clean_or_restore_timers(self):
        self.processes.ignore_signals = True
        with self.assertRaisesRegex(recovery.RecoveryError, 'did_not_exit'):
            self.tool().abort_rehearsal(TOKEN)
        self.assertEqual(self.processes.signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertFalse(self.mutations())
        self.processes.value = None
        with (self.journal / 'maintenance.lock').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(recovery.RecoveryError, 'lock_busy'):
                self.tool(lock_timeout=0.2).abort_rehearsal(TOKEN)
        self.assertFalse(self.mutations())


if __name__ == '__main__':
    unittest.main()
