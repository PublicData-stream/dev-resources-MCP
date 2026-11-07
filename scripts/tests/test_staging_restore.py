import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('staging_restore', ROOT / 'deploy/staging/restore.py')
restore = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(restore)
SNAPSHOT = 'devres-20261029T120000Z-daily'
TOKEN = 'a' * 24
BODY = b'RFC 9000 public text fixture for disposable restore tests.\n'
DIGEST = hashlib.sha256(BODY).hexdigest()
CAPTURE = 'b' * 64
TAGGED_DIGEST = 'blake3:' + 'd' * 64
TAGGED_CAPTURE = 'blake3:' + CAPTURE


class FakeHost:
    def __init__(self, root):
        self.root = root
        self.commands = []
        self.datasets = set()
        self.corrupt = False
        self.owner = TOKEN
        self.owners = {}
        self.schema = '9'
        self.capture = True
        self.active = True
        self.offline_exit = 0
        self.offline_running = False
        self.offline_failure = False
        self.remove_failure = False
        self.offline_oom = False
        self.engine_error = ''
        self.ignore_term = False
        self.complete_before_term = False
        self.pool_free = str(restore.REHEARSAL_HEADROOM)

    def run(self, args):
        args = [str(v) for v in args]
        self.commands.append(args)
        if args[:2] == ['zpool', 'list']:
            return self.pool_free
        if args[:2] == ['zfs', 'create']:
            self.datasets.add(args[-1])
            return ''
        if args[:2] == ['zfs', 'clone']:
            self.datasets.add(args[-1])
            child = args[-1].rsplit('/', 1)[1]
            (self.root / child).mkdir()
            if child == 'evidence':
                (self.root / child / 'blobs').mkdir()
                (self.root / child / 'blobs' / DIGEST).write_bytes(b'wrong' if self.corrupt else BODY)
                (self.root / child / 'blobs/blake3').mkdir()
                (self.root / child / 'blobs/blake3' / TAGGED_DIGEST[7:]).write_bytes(
                    b'wrong' if self.corrupt else BODY)
            return ''
        if args[:2] == ['zfs', 'get']:
            return self.owners.get(args[-1], self.owner)
        if args[:2] == ['zfs', 'list']:
            return '\n'.join(sorted(self.datasets))
        if args[:2] == ['zfs', 'destroy']:
            self.datasets.remove(args[-1])
            return ''
        if args[:3] in (['docker', 'network', 'create'], ['docker', 'network', 'rm']):
            return ''
        if args[:3] == ['docker', 'network', 'ls']:
            return 'devres-staging-restore-' + TOKEN
        if args[:2] == ['docker', 'ps']:
            return args[4].removeprefix('name=^/').removesuffix('$')
        if args[:3] == ['docker', 'network', 'inspect']:
            return json.dumps([{'Labels': {restore.LABEL_KEY: self.owner}}])
        if args[:2] == ['docker', 'run']:
            return 'container-id'
        if args[:2] == ['docker', 'inspect']:
            if '{{json .Config.Labels}}' in args:
                return json.dumps({restore.LABEL_KEY: self.owner})
            if '--format' in args:
                return json.dumps({'Running': self.offline_running, 'OOMKilled': self.offline_oom,
                                   'Error': self.engine_error, 'ExitCode': 1 if self.corrupt or self.offline_failure else self.offline_exit})
            return json.dumps([{'Id': 'f' * 64, 'Name': '/' + args[-1],
                                'Config': {'Labels': {restore.LABEL_KEY: self.owner}},
                                'NetworkSettings': {'Networks': {'devres-staging-restore-' + TOKEN: {'IPAddress': '172.28.0.2'}}}}])
        if args[:2] == ['docker', 'rm']:
            if self.remove_failure and '-offline-' in args[-1]:
                raise restore.RestoreError('restore_command_failed')
            return ''
        if args[:3] == ['docker', 'kill', '--signal=SIGTERM']:
            if self.complete_before_term:
                self.offline_running = False
                self.offline_exit = 0
                raise restore.RestoreError('restore_command_failed')
            if not self.ignore_term:
                self.offline_running = False
                self.offline_exit = 1
            return ''
        if args[:2] == ['docker', 'exec']:
            if args[3] == 'pg_isready':
                return ''
            if args[3] == 'psql':
                if args[-1].startswith('SELECT version'):
                    return self.schema
                if args[-1].startswith('SELECT count'):
                    return '2'
                if args[-1].startswith('SELECT active'):
                    return 't' if self.active else 'f'
                if args[-1] == restore.RECORD_SQL:
                    capture, digest = ((CAPTURE, DIGEST) if self.schema == '9'
                                       else (TAGGED_CAPTURE, TAGGED_DIGEST))
                    return capture + '\t' + digest if self.capture else ''
        raise AssertionError(args)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='devres-restore-test-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'owned'
        self.private = self.base / 'private'
        self.private.mkdir()
        config = (ROOT / 'deploy/staging/backend.toml.example').read_text().replace(
            'REPLACE_WITH_PRIVATE_POSTGRES_URL', 'postgres://devres:' + 'c' * 64 + '@postgres:5432/devres')
        (self.private / 'backend.toml').write_text(config)
        for name in ('backend.pem', 'backend-key.pem', 'client-ca.pem'):
            (self.private / name).write_text('disposable test certificate')
        self.host = FakeHost(self.root)
        self.calls = []
        self.log_reads = []
        self.terminal_logs = b''

    def rpc(self, ip, method, params, private):
        self.calls.append((method, params))
        if method == 'tools/call':
            version = restore.PROFILES[int(self.host.schema)][1]
            return {'structuredContent': {'product': 'dev-resources-MCP', 'version': version,
                                          'sourceUrl': restore.SOURCE_PREFIX + version + '/source.tar.gz'}}
        return {'contents': [{'text': BODY.decode()}]}

    def read_logs(self, name):
        self.log_reads.append(name)
        self.assertFalse(any(c[:3] == ['docker', 'rm', '-f'] and c[-1] == name for c in self.host.commands))
        return {'data': self.terminal_logs, 'truncated': False, 'timed_out': False}

    def write_diagnostic(self, root, filename, value):
        restore.write_private_diagnostic(root, filename, value, owner_uid=os.geteuid())

    def inspect_failure(self, name):
        self.host.commands.append(['docker', 'inspect', '--format', restore.DIAGNOSTIC_INSPECT_FORMAT, name])
        return {'owner': self.host.owner, 'state': {
            'ExitCode': 1 if self.host.corrupt or self.host.offline_failure else self.host.offline_exit,
            'OOMKilled': self.host.offline_oom, 'Running': self.host.offline_running,
            'ErrorPresent': bool(self.host.engine_error)}}

    def diagnostic_arguments(self):
        return {'diagnostic_root': self.base / 'diagnostics', 'log_reader': self.read_logs,
                'diagnostic_writer': self.write_diagnostic, 'diagnostic_inspector': self.inspect_failure}

    def drill(self, **kwargs):
        return restore.Drill(SNAPSHOT, run=self.host.run, root=self.root, private=self.private,
                             token=TOKEN, sleep=lambda _: None, call=self.rpc, **self.diagnostic_arguments(), **kwargs)

    def run_verify(self, **kwargs):
        with patch.object(restore.os, 'chown'):
            return restore.verify(SNAPSHOT, run=self.host.run, root=self.root, private=self.private,
                                  token=TOKEN, sleep=lambda _: None, call=self.rpc, **self.diagnostic_arguments(), **kwargs)

    def progress(self, **updates):
        value = {key: 1 for key in restore.DIAGNOSTIC_PROGRESS_COUNTS | restore.DIAGNOSTIC_PROGRESS_TIMES}
        value.update(event='offline_storage_progress', phase='graph_rfc')
        value.update(updates)
        return value

    def diagnostic(self):
        files = list((self.base / 'diagnostics').glob('*.json'))
        self.assertEqual(len(files), 1)
        return files[0], json.loads(files[0].read_bytes())

    def test_failed_worker_preserves_typed_error_and_exit_before_cleanup_without_raw_secrets(self):
        secret = 'postgres://private:password-canary@secret.example/db source-body-canary'
        self.host.offline_exit = 1
        self.host.engine_error = secret
        self.terminal_logs = (json.dumps(self.progress()) + '\n' + secret + '\n'
            + 'Error: Error { code: "integrity", message: "Unresolved RFC migration reference." }\n'
            + 'Error: Error { code: "unavailable", message: ' + json.dumps(secret) + ' }\n').encode()
        tool = self.drill()
        tool.postgres_started = True
        with self.assertRaisesRegex(restore.RestoreError, '^offline_command_failed$') as failure:
            tool.offline('migrate-storage')
        path, value = self.diagnostic()
        self.assertEqual(tool.last_offline_diagnostic, 'saved')
        self.assertEqual(value['exit_code'], 1)
        self.assertFalse(value['oom_killed'])
        self.assertTrue(value['engine_error_present'])
        self.assertEqual(value['engine_error_class'], 'unrecognized')
        self.assertEqual(value['failure_code'], 'offline_command_failed')
        self.assertEqual(value['terminal']['events'][-2:], [
            {'event': 'application_error', 'code': 'integrity', 'reason': 'rfc_reference_unresolved'},
            {'event': 'application_error', 'code': 'unavailable', 'reason': 'unrecognized_message'}])
        self.assertEqual(value['terminal']['events'][0]['phase'], 'graph_rfc')
        self.assertFalse(value['terminal']['raw_logs_retained'])
        self.assertEqual(value['terminal']['dropped_lines'], 1)
        self.assertNotIn(secret, path.read_text() + str(failure.exception) + repr(vars(tool)))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(path.stat().st_uid, os.geteuid())
        self.assertEqual(self.host.commands[-1][:3], ['docker', 'rm', '-f'])
        self.assertFalse(tool.containers)

    def test_oom_failure_survives_runtime_tree_cleanup(self):
        self.host.offline_exit = 137
        self.host.offline_oom = True
        tool = self.drill()
        try:
            with patch.object(restore.os, 'chown'):
                tool.prepare()
            tool.start_postgres()
            with self.assertRaisesRegex(restore.RestoreError, 'offline_command_failed'):
                tool.offline('verify-storage')
        finally:
            tool.cleanup()
        path, value = self.diagnostic()
        self.assertTrue(value['oom_killed'])
        self.assertEqual(value['exit_code'], 137)
        self.assertFalse(self.root.exists())
        self.assertTrue(path.exists())

    def test_timeout_retains_existing_error_and_cleanup(self):
        self.host.offline_running = True
        tool = self.drill()
        tool.postgres_started = True
        with self.assertRaisesRegex(restore.RestoreError, '^offline_command_timed_out$'):
            tool.offline('activate-storage', timeout=1)
        _, value = self.diagnostic()
        self.assertEqual(value['failure_code'], 'offline_command_timed_out')
        self.assertTrue(value['running'])
        self.assertFalse(tool.containers)
        self.assertEqual(self.host.commands[-1][:3], ['docker', 'rm', '-f'])

    def test_diagnostic_writer_failure_cannot_mask_original_error_or_skip_removal(self):
        self.host.offline_exit = 1
        tool = self.drill()
        tool.postgres_started = True
        tool.diagnostic_writer = lambda *args: (_ for _ in ()).throw(OSError('secret storage-error-canary'))
        with self.assertRaisesRegex(restore.RestoreError, '^offline_command_failed$'):
            tool.offline('migrate-storage')
        self.assertEqual(tool.last_offline_diagnostic, 'unavailable')
        self.assertFalse(tool.containers)
        self.assertEqual(self.host.commands[-1][:3], ['docker', 'rm', '-f'])

    def test_unavailable_terminal_reader_still_retains_state_metadata(self):
        self.host.offline_exit = 1
        tool = self.drill()
        tool.postgres_started = True
        tool.log_reader = lambda *args: (_ for _ in ()).throw(RuntimeError('secret log-error-canary'))
        with self.assertRaisesRegex(restore.RestoreError, '^offline_command_failed$'):
            tool.offline('migrate-storage')
        path, value = self.diagnostic()
        self.assertEqual(value['terminal'], {'unavailable': True, 'raw_logs_retained': False})
        self.assertNotIn('log-error-canary', path.read_text())
        self.assertFalse(tool.containers)

    def test_changed_worker_owner_prevents_log_access_and_artifact(self):
        self.host.offline_exit = 1
        self.host.owner = 'b' * 24
        tool = self.drill()
        tool.postgres_started = True
        with self.assertRaisesRegex(restore.RestoreError, '^offline_command_failed$'):
            tool.offline('migrate-storage')
        self.assertFalse(self.log_reads)
        self.assertFalse((self.base / 'diagnostics').exists())
        self.assertFalse(tool.containers)

    def test_success_does_not_read_logs_or_create_diagnostics(self):
        tool = self.drill()
        tool.postgres_started = True
        self.assertEqual(tool.offline('verify-storage'), {'command': 'verify-storage', 'completed': True})
        self.assertFalse(self.log_reads)
        self.assertFalse((self.base / 'diagnostics').exists())
        self.assertIsNone(tool.last_offline_diagnostic)

    def test_candidate_offline_commands_pass_exact_reviewed_limits(self):
        tool = self.drill()
        tool.postgres_started = True
        for command in ('migrate-storage', 'verify-storage', 'activate-storage'):
            tool.offline(command)
            started = [args for args in self.host.commands if args[:2] == ['docker', 'run']][-1]
            self.assertEqual(started[started.index(restore.SERVER) + 1:], [command,
                '/etc/devres/config/backend.toml', *(['--to', 'blake3'] if command == 'migrate-storage' else []),
                '--workers', '8', '--payload-budget-mib', '64', '--graph-memory-budget-mib', '1024'])
        self.assertEqual(tool.offline_options, restore.OFFLINE_OPTIONS)

    def test_schema_nine_restore_does_not_receive_candidate_offline_flags(self):
        self.run_verify(schema=9, server=restore.OLD_SERVER)
        starts = [args for args in self.host.commands if args[:2] == ['docker', 'run']]
        self.assertTrue(any(restore.OLD_SERVER in args for args in starts))
        for args in starts:
            self.assertNotIn('--workers', args)
            self.assertNotIn('--payload-budget-mib', args)
            self.assertNotIn('--graph-memory-budget-mib', args)

    def test_pause_signals_worker_and_preserves_pair_without_force_removal(self):
        tool = self.drill()
        tool.postgres_started = True
        tool.containers.append(tool.name + '-postgres')
        self.host.offline_running = True
        calls = []
        def control(drill, command, name):
            calls.append((drill, command, name))
            return True
        with self.assertRaises(restore.OfflinePaused) as paused:
            tool.offline('migrate-storage', control=control)
        self.assertEqual(paused.exception.command, 'migrate-storage')
        self.assertFalse(paused.exception.command_completed)
        self.assertTrue(paused.exception.preserve_checkpoint)
        self.assertEqual(calls, [(tool, 'migrate-storage', tool.name + '-offline-1')])
        self.assertTrue(any(args[:3] == ['docker', 'kill', '--signal=SIGTERM'] for args in self.host.commands))
        self.assertEqual(self.host.commands[-1], ['docker', 'rm', 'f' * 64])
        self.assertEqual(tool.containers, [tool.name + '-postgres'])
        self.assertTrue(tool.postgres_started)
        self.assertFalse(self.log_reads)

    def test_pause_after_activation_exit_reports_completion_without_signalling(self):
        tool = self.drill()
        tool.postgres_started = True
        with self.assertRaises(restore.OfflinePaused) as paused:
            tool.offline('activate-storage', control=lambda *_: True)
        self.assertTrue(paused.exception.command_completed)
        self.assertFalse(any(args[:2] == ['docker', 'kill'] for args in self.host.commands))
        self.assertEqual(self.host.commands[-1], ['docker', 'rm', 'f' * 64])

    def test_pause_handles_successful_exit_between_inspection_and_sigterm(self):
        tool = self.drill()
        tool.postgres_started = True
        self.host.offline_running = True
        self.host.complete_before_term = True
        with self.assertRaises(restore.OfflinePaused) as paused:
            tool.offline('activate-storage', control=lambda *_: True)
        self.assertTrue(paused.exception.command_completed)
        self.assertEqual(self.host.commands[-1], ['docker', 'rm', 'f' * 64])

    def test_pause_cannot_hide_worker_failure_or_claim_a_forced_stop(self):
        for kind in ('failed', 'unresponsive', 'oom'):
            with self.subTest(kind=kind):
                self.host.commands.clear()
                self.host.offline_exit = 1 if kind == 'failed' else 0
                self.host.offline_running = kind != 'failed'
                self.host.ignore_term = kind == 'unresponsive'
                self.host.offline_oom = kind == 'oom'
                tool = self.drill()
                tool.postgres_started = True
                with self.assertRaises(restore.RestoreError) as failure:
                    tool.offline('migrate-storage', control=lambda *_: True)
                self.assertNotIsInstance(failure.exception, restore.OfflinePaused)
                self.assertEqual(self.host.commands[-1][:3], ['docker', 'rm', '-f'])

    def test_callback_deadline_failure_retains_failure_cleanup(self):
        tool = self.drill()
        tool.postgres_started = True
        self.host.offline_running = True
        def deadline(*_):
            raise restore.RestoreError('upgrade_deadline_exceeded')
        with self.assertRaisesRegex(restore.RestoreError, '^upgrade_deadline_exceeded$'):
            tool.offline('verify-storage', control=deadline)
        self.assertEqual(self.host.commands[-1][:3], ['docker', 'rm', '-f'])

    def test_pause_refuses_changed_worker_owner(self):
        tool = self.drill()
        tool.postgres_started = True
        self.host.owner = 'b' * 24
        self.host.offline_running = True
        with self.assertRaisesRegex(restore.RestoreError, '^offline_worker_owner_changed$'):
            tool.offline('migrate-storage', control=lambda *_: True)
        self.assertFalse(any(args[:2] == ['docker', 'kill'] for args in self.host.commands))
        self.assertFalse(any(args[:2] == ['docker', 'rm'] for args in self.host.commands))
        self.assertEqual(tool.containers, [tool.name + '-offline-1'])
        with self.assertRaisesRegex(restore.RestoreError, 'writer_exclusion'):
            tool.offline('verify-storage')

    def test_terminal_filter_accepts_exact_old_and_graph_progress_schemas(self):
        old = self.progress()
        graph = self.progress(phase='graph_rfc_indexes',
                              **{key: 1 for key in restore.DIAGNOSTIC_GRAPH_COUNTS})
        for phase in ('graph_rfc_indexes', 'graph_npm_rows', 'graph_crate_artifacts',
                      'graph_crate_observations', 'graph_crate_staging'):
            graph['phase'] = phase
            output = restore.diagnostic_terminal({'data': ('\n'.join(map(json.dumps, [old, graph]))).encode(),
                                                  'truncated': False, 'timed_out': False})
            self.assertEqual(output['events'], [old, graph])
            self.assertEqual(output['dropped_lines'], 0)

    def test_terminal_filter_rejects_partial_graph_schemas_and_invalid_graph_numbers(self):
        graph = self.progress(phase='graph_rfc_indexes',
                              **{key: 1 for key in restore.DIAGNOSTIC_GRAPH_COUNTS})
        partial = dict(graph)
        del partial['graph_completed']
        invalid = [partial, {**graph, 'graph_memory_bytes': True},
                   {**graph, 'graph_memory_high_water': -1}, {**graph, 'graph_memory_budget_bytes': 0},
                   {**graph, 'graph_completed': 2**64}, {**graph, 'graph_admitted': 'private-input-canary'},
                   {**graph, 'untrusted': 'private-input-canary'}]
        output = restore.diagnostic_terminal({'data': ('\n'.join(map(json.dumps, invalid))).encode(),
                                              'truncated': False, 'timed_out': False})
        self.assertEqual(output['events'], [])
        self.assertEqual(output['dropped_lines'], len(invalid))
        self.assertNotIn('private-input-canary', json.dumps(output))

    def test_terminal_filter_drops_extra_fields_unknown_phases_and_bad_numeric_types(self):
        secret = 'private-provider-body-canary'
        invalid = [self.progress(phase=secret), self.progress(phase=[]), self.progress(admitted=True),
                   self.progress(elapsed_secs=float('inf')), self.progress(payload=secret)]
        data = ('\n'.join(json.dumps(value) for value in invalid) + '\n' + secret + '\n'
                + json.dumps(self.progress())).encode()
        value = restore.diagnostic_terminal({'data': data, 'truncated': True, 'timed_out': True})
        self.assertEqual(value['dropped_lines'], 6)
        self.assertEqual(value['events'], [self.progress()])
        self.assertTrue(value['truncated'])
        self.assertTrue(value['timed_out'])
        self.assertNotIn(secret, json.dumps(value))
        with self.assertRaisesRegex(restore.RestoreError, 'log_bound'):
            restore.diagnostic_terminal({'data': b'x' * (restore.DIAGNOSTIC_LOG_BYTES + 1)})

    def test_private_diagnostic_writer_refuses_links_unsafe_paths_and_overwrite(self):
        filename = TOKEN + '-offline-1.json'
        root = self.base / 'diagnostics'
        self.write_diagnostic(root, filename, {'fixed': True})
        with self.assertRaises(FileExistsError):
            self.write_diagnostic(root, filename, {'fixed': False})
        self.assertEqual(json.loads((root / filename).read_bytes()), {'fixed': True})
        target = self.base / 'target'
        target.write_text('private canary')
        (root / (TOKEN + '-offline-2.json')).symlink_to(target)
        with self.assertRaises(FileExistsError):
            self.write_diagnostic(root, TOKEN + '-offline-2.json', {})
        symlink = self.base / 'link'
        symlink.symlink_to(root, target_is_directory=True)
        with self.assertRaises(OSError):
            self.write_diagnostic(symlink, TOKEN + '-offline-3.json', {})
        root.chmod(0o755)
        with self.assertRaisesRegex(restore.RestoreError, 'unsafe_diagnostic_directory'):
            self.write_diagnostic(root, TOKEN + '-offline-3.json', {})
        self.assertEqual(target.read_text(), 'private canary')
        for path in (Path('/tmp'), Path('/var/lib/forbidden'), self.base / '..' / 'escape'):
            with self.assertRaisesRegex(restore.RestoreError, 'unsafe_diagnostic_destination'):
                self.write_diagnostic(path, filename, {})

    def test_private_diagnostic_writer_requires_root_by_default_and_bounds_artifacts(self):
        root = self.base / 'diagnostics'
        filename = TOKEN + '-offline-1.json'
        with patch.object(restore.os, 'geteuid', return_value=12345):
            with self.assertRaisesRegex(restore.RestoreError, 'unsafe_diagnostic_destination'):
                restore.write_private_diagnostic(root, filename, {})
        with self.assertRaisesRegex(restore.RestoreError, 'artifact_exceeds_bound'):
            self.write_diagnostic(root, filename, {'oversized': 'x' * restore.DIAGNOSTIC_FILE_BYTES})
        self.assertFalse(root.exists())

    def test_terminal_reader_bounds_single_huge_line_before_buffering(self):
        original = subprocess.Popen
        children = []
        def spawn(args, **kwargs):
            self.assertEqual(args[:4], ['docker', 'logs', '--tail', '64'])
            child = original([sys.executable, '-I', '-B', '-c',
                              'import os; os.write(1, b"x" * (8 * 1024 * 1024))'], **kwargs)
            children.append(child)
            return child
        with patch.object(restore.subprocess, 'Popen', side_effect=spawn):
            value = restore.read_terminal_logs('devres-staging-restore-' + TOKEN + '-offline-1')
        self.assertEqual(len(value['data']), restore.DIAGNOSTIC_LOG_BYTES)
        self.assertTrue(value['truncated'])
        self.assertFalse(value['timed_out'])
        self.assertIsNotNone(children[0].returncode)

    def test_terminal_reader_times_out_and_reaps_stalled_docker_client(self):
        original = subprocess.Popen
        children = []
        def spawn(args, **kwargs):
            child = original([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(60)'], **kwargs)
            children.append(child)
            return child
        started = time.monotonic()
        with patch.object(restore.subprocess, 'Popen', side_effect=spawn), patch.object(restore, 'DIAGNOSTIC_LOG_SECONDS', 0.05):
            value = restore.read_terminal_logs('devres-staging-restore-' + TOKEN + '-offline-1')
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(value['timed_out'])
        self.assertFalse(value['data'])
        self.assertIsNotNone(children[0].returncode)

    def test_diagnostic_inspection_has_its_own_pipe_bound_and_never_requests_raw_engine_error(self):
        original = subprocess.Popen
        children = []
        def spawn(args, **kwargs):
            self.assertEqual(args[:3], ['docker', 'inspect', '--format'])
            self.assertIn('ErrorPresent', args[3])
            self.assertNotIn('json .State.Error', args[3])
            child = original([sys.executable, '-I', '-B', '-c',
                              'import os; os.write(1, b"x" * (8 * 1024 * 1024))'], **kwargs)
            children.append(child)
            return child
        with patch.object(restore.subprocess, 'Popen', side_effect=spawn):
            with self.assertRaisesRegex(restore.RestoreError, 'inspect_unavailable'):
                restore.inspect_offline_failure('devres-staging-restore-' + TOKEN + '-offline-1')
        self.assertIsNotNone(children[0].returncode)

    def test_diagnostic_inspection_timeout_is_best_effort_and_cleanup_still_runs(self):
        self.host.offline_exit = 1
        tool = self.drill()
        tool.postgres_started = True
        tool.diagnostic_inspector = lambda *args: (_ for _ in ()).throw(restore.RestoreError('offline_diagnostic_inspect_unavailable'))
        with self.assertRaisesRegex(restore.RestoreError, '^offline_command_failed$'):
            tool.offline('migrate-storage')
        self.assertEqual(tool.last_offline_diagnostic, 'unavailable')
        self.assertFalse(self.log_reads)
        self.assertFalse(tool.containers)

    def test_restore_owner_is_recorded_before_any_objects_are_created(self):
        seen = []
        def record(drill):
            self.assertFalse(drill.runtime_owned)
            self.assertFalse(self.host.commands)
            seen.append(drill.token)
        result = self.run_verify(on_drill=record)
        self.assertEqual(seen, [TOKEN])
        self.assertEqual(result['schema'], 9)

    def test_failed_owner_record_cannot_start_clone(self):
        def reject(drill):
            raise RuntimeError('journal_unavailable')
        with self.assertRaisesRegex(RuntimeError, 'journal_unavailable'):
            self.run_verify(on_drill=reject)
        self.assertFalse(self.host.commands)
        self.assertFalse(self.root.exists())

    def test_direct_offline_guard_preserves_host_headroom(self):
        tool = self.drill(resource_profile='direct')
        tool.postgres_started = True
        with patch.object(tool, 'require_memory_headroom', side_effect=restore.RestoreError('host_memory_headroom_insufficient')):
            with self.assertRaisesRegex(restore.RestoreError, 'headroom_insufficient'):
                tool.offline('migrate-storage')
        self.assertFalse(self.host.commands)

    def test_direct_profile_bounds_cpu_memory_and_counts_scratch_inside_worker(self):
        tool = self.drill(resource_profile='direct')
        tool.runtime_owned = True
        with patch.object(tool, 'require_memory_headroom'):
            tool.start_postgres()
            tool.offline('migrate-storage')
        pg, worker = [c for c in self.host.commands if c[:2] == ['docker', 'run']]
        self.assertIn('--cpus=2', pg)
        self.assertIn('--memory=16g', pg)
        for setting in ('shared_buffers=8GB', 'max_wal_size=16GB', 'fsync=on',
                        'full_page_writes=on', 'synchronous_commit=on'):
            self.assertIn(setting, pg)
        self.assertIn('--cpus=37', worker)
        self.assertIn('--memory=192g', worker)
        self.assertTrue(any('size=64g,' in a for a in worker))
        self.assertIn('--read-only', worker)
        self.assertIn('--security-opt=no-new-privileges', worker)

    def test_upgrade_profile_matches_requested_worker_database_and_scratch_limits(self):
        tool = self.drill(resource_profile='upgrade')
        tool.runtime_owned = True
        with patch.object(tool, 'require_memory_headroom') as guard:
            tool.start_postgres()
            tool.offline('verify-storage')
        pg, worker = [c for c in self.host.commands if c[:2] == ['docker', 'run']]
        self.assertIn('--memory=32g', pg)
        self.assertIn('--cpus=2', pg)
        self.assertIn('shared_buffers=8GB', pg)
        self.assertIn('fsync=on', pg)
        self.assertIn('full_page_writes=on', pg)
        self.assertIn('synchronous_commit=on', pg)
        self.assertIn('--memory=128g', worker)
        self.assertIn('--cpus=37', worker)
        self.assertTrue(any('size=32g,' in arg for arg in worker))
        self.assertEqual(guard.call_count, 3)

    def test_ordinary_restore_profile_preserves_small_untuned_limits(self):
        tool = self.drill()
        tool.runtime_owned = True
        with patch.object(tool, 'require_memory_headroom') as guard:
            tool.start_postgres()
            tool.offline('verify-storage')
        pg, worker = [c for c in self.host.commands if c[:2] == ['docker', 'run']]
        self.assertIn('--memory=2g', pg)
        self.assertIn('--memory=64g', worker)
        self.assertTrue(any('size=32g,' in arg for arg in worker))
        self.assertFalse(any(arg.startswith('--cpus=') for c in (pg, worker) for arg in c))
        self.assertNotIn('shared_buffers=8GB', pg)
        guard.assert_not_called()

    def test_upgrade_memory_guard_failure_removes_started_worker_before_retry(self):
        tool = self.drill(resource_profile='upgrade')
        tool.postgres_started = True
        with patch.object(tool, 'require_memory_headroom', side_effect=[
                None, restore.RestoreError('host_memory_headroom_insufficient')]):
            with self.assertRaisesRegex(restore.RestoreError, 'headroom_insufficient'):
                tool.offline('migrate-storage')
        self.assertEqual(self.host.commands[-1][:3], ['docker', 'rm', '-f'])
        self.assertFalse(tool.containers)
        inspections = [c for c in self.host.commands if c[:2] == ['docker', 'inspect']]
        # The failed guard prevents normal state polling; diagnostics first
        # revalidate ownership before reading failure state and terminal logs.
        self.assertIn(restore.DIAGNOSTIC_INSPECT_FORMAT, inspections[0])

    def test_upgrade_memory_guard_failure_before_start_does_not_claim_worker(self):
        tool = self.drill(resource_profile='upgrade')
        tool.postgres_started = True
        with patch.object(tool, 'require_memory_headroom', side_effect=restore.RestoreError('host_memory_headroom_insufficient')):
            with self.assertRaisesRegex(restore.RestoreError, 'headroom_insufficient'):
                tool.offline('migrate-storage')
        self.assertFalse(tool.containers)
        self.assertFalse(self.host.commands)

    def test_unreviewed_resource_profile_fails_before_any_commands(self):
        for profile in (None, True, 1, {}, 'accelerated', 'upgrade '):
            with self.subTest(profile=profile), self.assertRaisesRegex(restore.RestoreError, 'invalid_restore_resource_profile'):
                self.drill(resource_profile=profile)
        self.assertFalse(self.host.commands)

    def test_real_capture_hash_schema_and_resource_then_owned_cleanup(self):
        result = self.run_verify()
        self.assertEqual(result['schema'], 9)
        self.assertEqual(result['server'], restore.OLD_SERVER)
        self.assertEqual(result['verified_body_hash'], DIGEST)
        self.assertEqual(result['verified_resource_bytes'], len(BODY))
        self.assertNotIn(BODY.decode(), json.dumps(result))
        self.assertFalse(self.root.exists())
        self.assertFalse(self.host.datasets)
        self.assertEqual(self.calls[-1], ('resources/read', {'uri': 'devres://capture/' + CAPTURE}))
        commands = self.host.commands
        creates = [c for c in commands if c[:3] == ['docker', 'network', 'create']]
        self.assertIn('--internal', creates[0])
        runs = [c for c in commands if c[:2] == ['docker', 'run']]
        self.assertTrue(all('-p' not in c and '--publish' not in c for c in runs))
        backend_rm = next(i for i, c in enumerate(commands) if c[:3] == ['docker', 'rm', '-f'] and c[-1].endswith('-backend'))
        first_destroy = next(i for i, c in enumerate(commands) if c[:2] == ['zfs', 'destroy'])
        self.assertLess(backend_rm, first_destroy)
        self.assertTrue(all('@' not in c[-1] for c in commands if c[:2] == ['zfs', 'destroy']))

    def test_private_operator_umask_keeps_only_runtime_group_access(self):
        import os
        tool = self.drill()
        previous = os.umask(0o077)
        try:
            with patch.object(restore.os, 'chown'):
                tool.prepare()
            for folder in ('config', 'tls'):
                self.assertEqual((self.root / folder).stat().st_mode & 0o777, 0o750)
            self.assertEqual((self.root / 'config/backend.toml').stat().st_mode & 0o777, 0o640)
            self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        finally:
            os.umask(previous)
            tool.cleanup()

    def test_corrupt_blob_never_boots_backend_and_cleans_clones(self):
        self.host.corrupt = True
        with self.assertRaisesRegex(restore.RestoreError, 'hash_mismatch'):
            self.run_verify()
        self.assertFalse(self.root.exists())
        runs = [c for c in self.host.commands if c[:2] == ['docker', 'run']]
        self.assertEqual(len(runs), 1)
        self.assertFalse(self.calls)

    def test_wrong_schema_rejects_and_cleans(self):
        self.host.schema = '8'
        with self.assertRaisesRegex(restore.RestoreError, 'schema_mismatch'):
            self.run_verify()
        self.assertFalse(self.host.datasets)

    def test_empty_or_missing_fixed_rfc_cannot_establish_restore(self):
        self.host.capture = False
        with self.assertRaisesRegex(restore.RestoreError, 'retained_fixed_rfc_required'):
            self.run_verify()
        self.assertFalse(self.calls)

    def test_cleanup_refuses_changed_dataset_owner(self):
        tool = self.drill()
        with patch.object(restore.os, 'chown'):
            tool.prepare()
        self.host.owner = 'different-owner'
        with self.assertRaisesRegex(restore.RestoreError, 'ownership_changed'):
            tool.cleanup()
        self.assertFalse(any(c[:2] == ['zfs', 'destroy'] for c in self.host.commands))
        self.assertTrue(self.root.exists())

    def test_invalid_names_fail_before_commands(self):
        for value in ('../snapshot', 'devres-20269999T120000Z', 'pool@snapshot', SNAPSHOT + ';id'):
            with self.assertRaises(restore.RestoreError):
                restore.Drill(value, run=self.host.run)
        self.assertFalse(self.host.commands)

    def test_clone_quota_accepts_only_reviewed_finite_profiles_before_commands(self):
        for quota in (None, True, 0, 64, '0', 'unlimited', '256G', '1T', '512G;id', ' 64G', '64G\n'):
            with self.subTest(quota=quota), self.assertRaisesRegex(restore.RestoreError, 'invalid_restore_clone_quota'):
                self.drill(clone_quota=quota)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.host.commands)

    def test_ordinary_clone_keeps_64g_without_new_pool_admission(self):
        self.host.pool_free = 'unavailable'
        tool = self.drill()
        try:
            with patch.object(restore.os, 'chown'):
                tool.prepare()
            creates = [c for c in self.host.commands if c[:2] == ['zfs', 'create']]
            self.assertEqual(len(creates), 1)
            self.assertIn('quota=64G', creates[0])
            self.assertFalse(any(c[:2] == ['zpool', 'list'] for c in self.host.commands))
        finally:
            tool.cleanup()

    def test_rehearsal_clone_requires_headroom_before_any_temporary_objects(self):
        self.host.pool_free = str(restore.REHEARSAL_HEADROOM - 1)
        tool = self.drill(clone_quota='512G')
        with self.assertRaisesRegex(restore.RestoreError, 'clone_headroom_insufficient'):
            tool.prepare()
        self.assertEqual(self.host.commands, [['zpool', 'list', '-Hp', '-o', 'free', 'cachepool']])
        self.assertFalse(self.root.exists())
        self.assertFalse(self.host.datasets)
        self.assertFalse(tool.runtime_owned)

    def test_rehearsal_clone_accepts_exact_headroom_and_sets_only_owned_parent_quota(self):
        tool = self.drill(clone_quota='512G')
        try:
            with patch.object(restore.os, 'chown'):
                tool.prepare()
            self.assertEqual(self.host.commands[0], ['zpool', 'list', '-Hp', '-o', 'free', 'cachepool'])
            creates = [c for c in self.host.commands if c[:2] == ['zfs', 'create']]
            self.assertEqual(len(creates), 1)
            self.assertIn('quota=512G', creates[0])
            self.assertEqual(creates[0][-1], tool.dataset)
            self.assertNotEqual(tool.dataset, restore.DATASET)
            self.assertFalse(any(c[:2] == ['zfs', 'set'] for c in self.host.commands))
        finally:
            tool.cleanup()

    def test_rehearsal_clone_rejects_unparseable_or_out_of_range_pool_counters(self):
        for value in ('', 'NaN', '-1', '+1', '1e12', '1\n2', '18446744073709551616', '9' * 21,
                      None, True, 2**50):
            with self.subTest(value=value):
                self.host.commands.clear()
                self.host.pool_free = value
                tool = self.drill(clone_quota='512G')
                with self.assertRaisesRegex(restore.RestoreError, 'clone_headroom_unavailable'):
                    tool.prepare()
                self.assertEqual(self.host.commands, [['zpool', 'list', '-Hp', '-o', 'free', 'cachepool']])
                self.assertFalse(self.root.exists())
                self.assertFalse(self.host.datasets)

    def test_paused_config_only_changes_eight_booleans(self):
        text = (self.private / 'backend.toml').read_text().replace('enabled = false', 'enabled = true')
        changed = restore.paused_config(text)
        before, after = restore.tomllib.loads(text), restore.tomllib.loads(changed)
        for name in restore.COLLECTORS:
            self.assertFalse(after[name]['enabled'])
            before[name]['enabled'] = False
        self.assertEqual(after, before)

    def test_missing_explicit_collector_is_rejected(self):
        text = (self.private / 'backend.toml').read_text().replace('[rfc]\nenabled = false\n', '')
        with self.assertRaisesRegex(restore.RestoreError, 'explicit_collector'):
            restore.paused_config(text)

    def test_blob_symlink_is_rejected_without_reading_target(self):
        directory = self.base / 'blobs'
        directory.mkdir()
        target = self.base / 'secret'
        target.write_bytes(BODY)
        (directory / DIGEST).symlink_to(target)
        with self.assertRaisesRegex(restore.RestoreError, 'unavailable'):
            restore.hash_blob(directory, DIGEST)

    def test_oversized_fixed_capture_is_rejected_before_hashing(self):
        directory = self.base / 'large-blobs'
        directory.mkdir()
        with (directory / DIGEST).open('wb') as stream:
            stream.truncate(restore.MAX_FIXED_BODY + 1)
        with self.assertRaisesRegex(restore.RestoreError, 'size_exceeds_bound'):
            restore.hash_blob(directory, DIGEST)

    def test_resource_mismatch_rejects_and_cleans(self):
        original = self.rpc
        self.rpc = lambda *args: (original(*args) if args[1] == 'tools/call'
                                 else {'contents': [{'text': 'corrupt'}]})
        with self.assertRaisesRegex(restore.RestoreError, 'page_mismatch'):
            self.run_verify()
        self.assertFalse(self.host.datasets)

    def test_schema_ten_tagged_paths_verify_before_backend_and_cleanup(self):
        self.host.schema = '10'
        result = self.run_verify(schema=10, server=restore.SERVER)
        self.assertEqual(result['schema'], 10)
        self.assertEqual(result['verified_capture_id'], TAGGED_CAPTURE)
        self.assertEqual(result['verified_body_hash'], TAGGED_DIGEST)
        self.assertEqual(result['server'], restore.SERVER)
        self.assertEqual(result['verified_resource_bytes'], len(BODY))
        runs = [c for c in self.host.commands if c[:2] == ['docker', 'run']]
        offline = next(c for c in runs if 'verify-storage' in c)
        self.assertIn(restore.SERVER, offline)
        self.assertIn('--read-only', offline)
        self.assertIn('--memory=64g', offline)
        self.assertFalse(any('--publish' in c or '-p' in c for c in runs))
        removal = next(i for i, c in enumerate(self.host.commands)
                       if c[:3] == ['docker', 'rm', '-f'] and '-offline-' in c[-1])
        backend = next(i for i, c in enumerate(self.host.commands)
                       if c[:2] == ['docker', 'run'] and c[c.index('--name') + 1].endswith('-backend'))
        self.assertLess(removal, backend)
        self.assertFalse(self.host.datasets)

    def test_schema_ten_corruption_rejects_before_backend(self):
        self.host.schema = '10'
        self.host.corrupt = True
        with self.assertRaisesRegex(restore.RestoreError, 'offline_command_failed'):
            self.run_verify()
        self.assertFalse(self.calls)
        self.assertFalse(self.host.datasets)

    def test_pending_schema_ten_cannot_pass_restore(self):
        self.host.schema = '10'
        self.host.active = False
        with self.assertRaisesRegex(restore.RestoreError, 'integrity_not_active'):
            self.run_verify()
        self.assertFalse(self.calls)

    def test_explicit_snapshot_profile_cannot_silently_change(self):
        for kwargs in ({'schema': 10}, {'server': restore.SERVER}):
            with self.assertRaisesRegex(restore.RestoreError, 'schema_mismatch|profile_mismatch'):
                self.run_verify(**kwargs)
            self.assertFalse(self.calls)
        for kwargs in ({'schema': 8}, {'schema': True}, {'server': 'unreviewed:latest'},
                       {'schema': 9, 'server': restore.SERVER}):
            before = len(self.host.commands)
            with self.assertRaises(restore.RestoreError):
                self.drill(**kwargs)
            self.assertEqual(len(self.host.commands), before)

    def test_source_identity_matches_restored_binary_even_after_upgrade(self):
        old, new = restore.PROFILES[9][1], restore.PROFILES[10][1]
        original = (self.private / 'backend.toml').read_text()
        original = original.replace(old, new)
        result = self.run_verify(config_text=original)
        self.assertEqual(result['version'], old)
        self.assertIn('/' + old + '/', result['source_url'])

    def test_offline_command_timeout_removes_writer_before_return(self):
        tool = self.drill()
        with patch.object(restore.os, 'chown'):
            tool.prepare()
        try:
            tool.start_postgres()
            self.host.offline_running = True
            with self.assertRaisesRegex(restore.RestoreError, 'timed_out'):
                tool.offline('migrate-storage', timeout=1)
            self.assertFalse(any('-offline-' in name for name in tool.containers))
            self.assertTrue(any(c[:3] == ['docker', 'rm', '-f'] and '-offline-' in c[-1]
                                for c in self.host.commands))
        finally:
            tool.cleanup()

    def test_default_offline_command_can_finish_after_twenty_four_hours(self):
        tool = self.drill()
        tool.postgres_started = True
        self.host.offline_running = True
        tool.sleep = lambda _: setattr(self.host, 'offline_running', False)
        with patch.object(restore.time, 'monotonic', side_effect=[0, 90000]):
            result = tool.offline('migrate-storage')
        self.assertTrue(result['completed'])
        self.assertFalse(any('-offline-' in name for name in tool.containers))

    def test_default_seven_day_ceiling_still_removes_running_writer(self):
        tool = self.drill()
        tool.postgres_started = True
        self.host.offline_running = True
        with patch.object(restore.time, 'monotonic', side_effect=[0, 604800]):
            with self.assertRaisesRegex(restore.RestoreError, 'timed_out'):
                tool.offline('migrate-storage')
        self.assertFalse(any('-offline-' in name for name in tool.containers))
        self.assertTrue(any(c[:3] == ['docker', 'rm', '-f'] and '-offline-' in c[-1]
                            for c in self.host.commands))

    def test_schema_ten_restore_propagates_extended_default_to_verification(self):
        self.host.schema = '10'
        original = restore.Drill.offline
        timeouts = []
        def record(tool, command, **kwargs):
            timeouts.append(kwargs['timeout'])
            return original(tool, command, **kwargs)
        with patch.object(restore.Drill, 'offline', record):
            result = self.run_verify(schema=10, server=restore.SERVER)
        self.assertEqual(result['schema'], 10)
        self.assertEqual(timeouts, [604800])

    def test_offline_commands_require_stopped_backend_and_reviewed_arguments(self):
        tool = self.drill()
        for command, target, timeout in (('serve', restore.SERVER, 1),
                                        ('verify-storage', restore.OLD_SERVER, 1),
                                        ('verify-storage', restore.SERVER, 0),
                                        ('verify-storage', restore.SERVER, restore.OFFLINE_TIMEOUT_SECONDS + 1),
                                        ('verify-storage', restore.SERVER, True),
                                        ('verify-storage', restore.SERVER, float('nan')),
                                        ('verify-storage', restore.SERVER, float('inf'))):
            with self.assertRaises(restore.RestoreError):
                tool.offline(command, target, timeout)
        with self.assertRaisesRegex(restore.RestoreError, 'writer_exclusion'):
            tool.offline('verify-storage')
        self.assertFalse(self.host.commands)

    def test_failed_offline_cleanup_latches_writer_exclusion(self):
        tool = self.drill()
        with patch.object(restore.os, 'chown'):
            tool.prepare()
        try:
            tool.start_postgres()
            self.host.remove_failure = True
            with self.assertRaisesRegex(restore.RestoreError, 'restore_command_failed'):
                tool.offline('migrate-storage', timeout=1)
            before = len(self.host.commands)
            with self.assertRaisesRegex(restore.RestoreError, 'writer_exclusion'):
                tool.offline('activate-storage', timeout=1)
            self.assertEqual(len(self.host.commands), before)
        finally:
            self.host.remove_failure = False
            tool.cleanup()

    def test_tagged_blob_requires_binary_verification_and_no_symlink_parent(self):
        directory = self.base / 'tagged'
        directory.mkdir()
        with self.assertRaisesRegex(restore.RestoreError, 'independent_integrity'):
            restore.hash_blob(directory, TAGGED_DIGEST)
        (directory / 'blake3').symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(restore.RestoreError, 'unavailable'):
            restore.hash_blob(directory, TAGGED_DIGEST, integrity_verified=True)

    def test_nested_restore_accepts_only_token_owned_source_tree(self):
        source_token = 'b' * 24
        source = 'cachepool/devres-staging-restore-' + source_token
        self.host.owners = {source + child: source_token for child in ('', '/postgres', '/evidence')}
        result = self.run_verify(source_dataset=source)
        self.assertEqual(result['schema'], 9)
        clones = [c for c in self.host.commands if c[:2] == ['zfs', 'clone']]
        self.assertEqual({c[-2] for c in clones},
                         {source + '/' + child + '@' + SNAPSHOT for child in ('postgres', 'evidence')})
        self.assertTrue(all(source not in c[-1] for c in self.host.commands if c[:2] == ['zfs', 'destroy']))
        self.assertTrue(all('quota=64G' in c for c in self.host.commands if c[:2] == ['zfs', 'create']))
        self.assertFalse(any(c[:2] == ['zpool', 'list'] for c in self.host.commands))

    def test_nested_restore_refuses_unowned_source_before_creating_anything(self):
        source = 'cachepool/devres-staging-restore-' + 'b' * 24
        tool = self.drill(source_dataset=source)
        with self.assertRaisesRegex(restore.RestoreError, 'source_ownership_changed'):
            tool.prepare()
        self.assertFalse(self.root.exists())
        self.assertFalse(any(c[:2] == ['zfs', 'create'] for c in self.host.commands))
        for bad in ('cachepool/other-service', 'cachepool/devres-staging-restore-../bad',
                    'cachepool/devres-staging-restore-' + TOKEN):
            with self.assertRaises(restore.RestoreError):
                self.drill(source_dataset=bad)

    def test_verify_timeout_reaches_schema_ten_command_without_constructor_override(self):
        self.host.schema = '10'
        self.host.offline_running = True
        with self.assertRaisesRegex(restore.RestoreError, 'timed_out'):
            self.run_verify(timeout=1)
        self.assertFalse(self.root.exists())


if __name__ == '__main__':
    unittest.main()
