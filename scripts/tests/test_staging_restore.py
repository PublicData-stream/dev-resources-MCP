import hashlib
import importlib.util
import json
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

    def run(self, args):
        args = [str(v) for v in args]
        self.commands.append(args)
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
            if '--format' in args:
                return json.dumps({'Running': self.offline_running,
                                   'ExitCode': 1 if self.corrupt or self.offline_failure else self.offline_exit})
            return json.dumps([{'Config': {'Labels': {restore.LABEL_KEY: self.owner}},
                                'NetworkSettings': {'Networks': {'devres-staging-restore-' + TOKEN: {'IPAddress': '172.28.0.2'}}}}])
        if args[:2] == ['docker', 'rm']:
            if self.remove_failure and '-offline-' in args[-1]:
                raise restore.RestoreError('restore_command_failed')
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

    def rpc(self, ip, method, params, private):
        self.calls.append((method, params))
        if method == 'tools/call':
            version = restore.PROFILES[int(self.host.schema)][1]
            return {'structuredContent': {'product': 'dev-resources-MCP', 'version': version,
                                          'sourceUrl': restore.SOURCE_PREFIX + version + '/source.tar.gz'}}
        return {'contents': [{'text': BODY.decode()}]}

    def drill(self, **kwargs):
        return restore.Drill(SNAPSHOT, run=self.host.run, root=self.root, private=self.private,
                             token=TOKEN, sleep=lambda _: None, call=self.rpc, **kwargs)

    def run_verify(self, **kwargs):
        with patch.object(restore.os, 'chown'):
            return restore.verify(SNAPSHOT, run=self.host.run, root=self.root, private=self.private,
                                  token=TOKEN, sleep=lambda _: None, call=self.rpc, **kwargs)

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
        self.assertIn('--memory=16g', offline)
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

    def test_offline_commands_require_stopped_backend_and_reviewed_arguments(self):
        tool = self.drill()
        for command, target, timeout in (('serve', restore.SERVER, 1),
                                        ('verify-storage', restore.OLD_SERVER, 1),
                                        ('verify-storage', restore.SERVER, 0),
                                        ('verify-storage', restore.SERVER, 86401)):
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
