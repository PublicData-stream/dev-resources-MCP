"""Preserving cache-recovery fixtures; no cluster, provider, Git or package execution."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_upgrade_33f3c730 as control

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('cache_resume', ROOT / 'deploy/production/cache_resume_33f3c730.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


class CacheRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = control.Fixture(); self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.c, self.cluster = self.fixture.c, self.fixture.cluster
        self.top, self.bundle = self.fixture.top, self.fixture.root
        self.cache = self.top / 'cache'; self.cache.mkdir(mode=0o2770); self.cache.chmod(0o2770)
        for name, data in {'blob-a': b'public source a', 'blobs/blob-b': b'public source b',
                'mdn/history.git/HEAD': b'ref: refs/heads/main\n',
                'mdn/history.git/objects/pack/a.pack': b'pack-bytes',
                'npm/registry.git/config': b'fixture config'}.items():
            path = self.cache / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        info = self.cache.stat()
        self.journal = self.bundle / 'cache-recovery'
        values = {'BUNDLE': self.bundle, 'JOURNAL': self.journal, 'CACHE': self.cache,
            'ORIGINAL': self.journal / 'writer-original', 'ROOT_UID': info.st_uid, 'ROOT_GID': info.st_gid,
            'ROOT_MODE': 0o2770, 'ROOT_DEVICE': info.st_dev, 'ROOT_INODE': info.st_ino,
            'EXPECTED_ORDINARY_FILES': 2, 'GIT_ROOT_COUNT': 2, 'RESERVE': 0}
        for key, value in values.items():
            p = patch.object(m, key, value); p.start(); self.addCleanup(p.stop)
        self.pvc = {'metadata': {'uid': m.PVC_UID}, 'spec': {'volumeName': 'devres-writer-cache'}}
        self.pv = {'metadata': {'uid': m.PV_UID}, 'spec': {'local': {'path': str(self.cache)},
            'claimRef': {'uid': m.PVC_UID, 'namespace': 'devres', 'name': 'writer-cache'}}}
        writer = self.cluster.deployments['writer']['spec']['template']['spec']
        writer['containers'][0]['volumeMounts'] = [{'name': 'cache', 'mountPath': '/data/cache'}]
        writer['volumes'] = [{'name': 'cache', 'persistentVolumeClaim': {'claimName': 'writer-cache'}}]
        cp = control.u.load(self.bundle / 'prepared.json')
        for role in ('writer', 'backend'):
            self.cluster.deployments[role]['spec']['replicas'] = 0
            self.cluster.deployments[role]['spec']['template']['spec']['containers'][0]['image'] = control.u.IMAGE
            self.cluster.live_pods.pop(role, None)
        for role, (name, key) in control.u.ROLES.items():
            self.cluster.secrets[name]['data'][key] = base64.b64encode(control.u.load(self.bundle / 'configs-paused.json')[role].encode()).decode()
        for role in ('writer', 'backend'):
            projection, _ = control.u.deployment_projection(self.cluster.deployments[role])
            cp['deployments'][role]['projection'] = projection
        prepared_sha = control.private(self.bundle / 'prepared.json', cp)
        state = self.c.state(); state.update(phase='withdrawn', configs='paused', prepared_sha256=prepared_sha)
        state['replicas'].update(writer=0, backend=0); state['pods'] = {'postgres': state['pods']['postgres']}
        state['images'].update(writer=control.u.IMAGE, backend=control.u.IMAGE); self.c.record(state)
        self.c.plan = {'target': {'server': control.u.IMAGE}}
        original_k = self.cluster.k
        def k(*args, **kwargs):
            if args[:2] == ('get', 'pvc'): return m.enc(self.pvc)
            if args[:2] == ('get', 'pv'): return m.enc(self.pv)
            if args[:2] == ('get', 'replicaset'):
                return m.enc({'metadata': {'uid': 'writer-rs', 'ownerReferences': [
                    {'kind': 'Deployment', 'uid': 'writer-deployment'}]}})
            return original_k(*args, **kwargs)
        self.cluster.k = k
        original_new_pod = self.cluster.new_pod
        def new_pod(role):
            original_new_pod(role)
            if role == 'writer': self.cluster.live_pods[role]['metadata']['ownerReferences'][0]['name'] = 'writer-rs'
        self.cluster.new_pod = new_pod
        self.checkpoint = SimpleNamespace(S=self.top / 'checkpoint')
        def stream(kind):
            path = self.checkpoint.S / (kind + '.jsonl')
            data = (kind + '-immutable\n').encode(); path.write_bytes(data); path.chmod(0o600)
            return {'path': str(path), 'sha256': m.sha(data), 'files': 3,
                    'manifest_bytes': len(data), 'logical_file_bytes': 100}
        self.checkpoint.stream_manifest = stream
        self.approval = self.top / 'cache-approval.json'
        value = {'version': 1, 'kind': 'preserving-writer-cache-recovery', 'approved': True,
            'source_sha256': m.sha(Path(m.__file__).read_bytes()), 'controller_sha256': m.CONTROLLER_SHA,
            'controller_prepared_sha256': prepared_sha, 'withdrawn_state_sha256': m.sha(m.raw(self.bundle / 'state.json')),
            'operations': ['prepare', 'rotate', 'start'], 'maximum_rotations': 1, 'maximum_start_attempts': 1,
            'preserve_original_cache': True, 'preserve_git_copies': True, 'new_permanent_mutations': False}
        self.approval_sha = control.private(self.approval, value)
        self.r = m.Recovery(self.c, self.checkpoint, self.approval, self.approval_sha)
        self.identity = {'system_id': m.SYSTEM_ID, 'schema': 18,
            'archive': {'backend': 's3', 'epoch': 2, 'binding': m.ARCHIVE_BINDING,
                'pending_binding': None, 'initializing_s3': False, 'store_id': '1' * 32},
            'control': {'format_version': 1, 'required_policy_epoch': 2, 'required_policy_fingerprint': m.POLICY2},
            'generation_count': 7, 'generations_sha256': 'b' * 64}
        self.r.sql_identity = lambda stopped=True: {**copy.deepcopy(self.identity), 'owners': 0 if stopped else 1}
        self.c.guard()

    def test_prepare_binds_exact_cache_pv_and_complete_content_inventory(self):
        self.r.prepare()
        prepared = self.r.prepared()
        self.assertEqual(prepared['inventory']['ordinary_files'], 2)
        self.assertEqual(prepared['inventory']['git_roots'], ['mdn/history.git', 'npm/registry.git'])
        self.assertEqual(self.r.state()['phase'], 'prepared')
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.checkpoint.S, self.top / 'checkpoint')

    def test_full_preserving_rotation_and_forward_start(self):
        original_inode = self.cache.stat().st_ino
        old_controller_prepared = (self.bundle / 'prepared.json').read_bytes()
        self.r.prepare(); self.r.rotate()
        old = self.journal / 'writer-original'
        self.assertEqual(old.stat().st_ino, original_inode)
        self.assertNotEqual(self.cache.stat().st_ino, original_inode)
        self.assertEqual(self.cache.stat().st_mode & 0o7777, 0o2770)
        self.assertTrue((old / 'blob-a').exists()); self.assertFalse((self.cache / 'blob-a').exists())
        self.assertEqual((old / 'mdn/history.git/HEAD').read_bytes(), (self.cache / 'mdn/history.git/HEAD').read_bytes())
        self.assertNotEqual((old / 'mdn/history.git/HEAD').stat().st_ino, (self.cache / 'mdn/history.git/HEAD').stat().st_ino)
        self.r.start()
        self.assertEqual(self.r.state()['phase'], 'writer_ready')
        self.assertEqual(self.c.state()['phase'], 'writer_ready')
        self.assertEqual(set(self.c.state()['pods']), {'postgres', 'writer'})
        self.assertEqual((self.bundle / 'prepared.json').read_bytes(), old_controller_prepared)
        self.assertTrue((old / 'blobs/blob-b').exists())
        self.assertTrue((self.bundle / 'cache-recovery-start-writer-intent.json').exists())

    def test_old_cache_and_new_git_are_not_hardlink_aliases(self):
        self.r.prepare(); self.r.rotate()
        old = self.journal / 'writer-original/mdn/history.git/HEAD'
        original = old.read_bytes()
        (self.cache / 'mdn/history.git/HEAD').write_bytes(b'new HEAD')
        self.assertEqual(old.read_bytes(), original)
        with self.assertRaisesRegex(m.Stop, 'fresh_cache_changed'): self.r.start()
        self.assertNotIn('writer', self.cluster.live_pods)

    def test_unadmitted_root_inode_or_mode_is_rejected(self):
        self.cache.chmod(0o770)
        with self.assertRaisesRegex(m.Stop, 'original_cache_root_identity'): self.r.prepare()
        self.assertFalse(self.journal.exists())

    def test_wrong_pv_uid_is_rejected_before_journal_creation(self):
        self.pv['metadata']['uid'] = 'different'
        with self.assertRaisesRegex(m.Stop, 'exact_writer_cache_pv'): self.r.prepare()
        self.assertFalse(self.journal.exists())

    def test_incomplete_approval_cannot_authorize_cache_changes(self):
        value = control.u.load(self.approval); value.pop('preserve_original_cache')
        self.r.approval_sha = control.private(self.approval, value)
        with self.assertRaisesRegex(m.Stop, 'recovery_approval_binding'): self.r.prepare()
        self.assertTrue((self.cache / 'blob-a').exists())

    def test_any_source_symlink_is_refused(self):
        (self.cache / 'link').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(m.Stop, 'cache_symlink_or_mount'): self.r.prepare()
        self.assertTrue((self.cache / 'blob-a').exists())
        self.assertFalse((self.journal / 'writer-original').exists())

    def test_symlink_inside_mutable_git_is_not_followed(self):
        (self.cache / 'mdn/history.git/evil').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(m.Stop, 'cache_symlink_or_mount'): self.r.prepare()

    def test_non_regular_cache_entry_is_refused(self):
        os.mkfifo(self.cache / 'fifo')
        with self.assertRaisesRegex(m.Stop, 'cache_special_file'): self.r.prepare()

    def test_source_change_after_prepare_blocks_rotation(self):
        self.r.prepare(); (self.cache / 'blob-a').write_bytes(b'changed')
        with self.assertRaisesRegex(m.Stop, 'cache_changed_after_prepare'): self.r.rotate()
        self.assertFalse((self.journal / 'writer-original').exists())

    def test_uncertain_rotation_preserves_old_root_and_cannot_replay(self):
        self.r.prepare()
        with patch.object(m, 'copy_git_roots', side_effect=OSError('copy interrupted')):
            with self.assertRaises(OSError): self.r.rotate()
        self.assertEqual(self.r.state()['phase'], 'rotate_incomplete')
        self.assertTrue((self.journal / 'writer-original/blob-a').exists())
        with self.assertRaisesRegex(m.Stop, 'recovery_phase'): self.r.rotate()
        with self.assertRaisesRegex(m.Stop, 'recovery_phase'): self.r.start()

    def test_repeated_mutation_intent_cannot_dispatch_again(self):
        self.r.prepare(); action = Mock(side_effect=OSError('uncertain'))
        with self.assertRaises(OSError): self.r.intent('once', action)
        with self.assertRaises(FileExistsError): self.r.intent('once', action)
        action.assert_called_once()

    def test_failed_start_uses_fresh_fence_and_preserves_target_schema_and_cache(self):
        self.r.prepare(); self.r.rotate()
        control.private(self.bundle / 'withdraw-writer-intent.json', {'already_consumed': True})
        self.cluster.fail_rollout = True
        with self.assertRaisesRegex(m.Stop, 'cache_recovery_writer_start_failed_fenced'): self.r.start()
        self.assertEqual(self.r.state()['phase'], 'start_failed_fenced')
        self.assertEqual(self.c.state()['phase'], 'withdrawn')
        self.assertEqual(set(self.cluster.live_pods), {'postgres'})
        self.assertTrue((self.journal / 'failed-cache-recovery-stop-writer-completed.json').exists())
        self.assertTrue((self.journal / 'writer-original/blob-a').exists())
        self.assertEqual(self.c.state()['images']['writer'], control.u.IMAGE)
        self.assertEqual(control.u.load(self.bundle / 'withdraw-writer-intent.json'), {'already_consumed': True})
        with self.assertRaisesRegex(m.Stop, 'recovery_phase'): self.r.start()

    def test_changed_durable_manifest_blocks_start(self):
        self.r.prepare(); self.r.rotate()
        original = self.checkpoint.stream_manifest
        def changed(kind):
            value = original(kind)
            if kind == 'captures': value['sha256'] = 'f' * 64
            return value
        self.checkpoint.stream_manifest = changed
        with self.assertRaisesRegex(m.Stop, 'prestart_permanent_data_changed'): self.r.start()
        self.assertNotIn('writer', self.cluster.live_pods)

    def test_generation_change_during_rotation_fails_preservingly(self):
        self.r.prepare(); self.identity['generations_sha256'] = 'd' * 64
        with self.assertRaisesRegex(m.Stop, 'rotation_changed_permanent_boundary'): self.r.rotate()
        self.assertTrue((self.journal / 'writer-original/blob-a').exists())
        self.assertNotIn('writer', self.cluster.live_pods)

    def test_fence_refuses_unrelated_credential_or_pod_changes(self):
        self.r.prepare(); self.r.rotate()
        self.cluster.secrets['wikipedia-private']['data']['token'] = 'different'
        with self.assertRaises(control.u.Error): self.r.start()
        self.assertNotIn('writer', self.cluster.live_pods)

    def test_copy_refuses_traversal_and_does_not_execute_git(self):
        destination = self.top / 'fresh'; destination.mkdir(mode=0o700)
        for relative in ('../history.git', '/history.git', 'mdn/../history.git'):
            with self.assertRaisesRegex(m.Stop, 'git_path_traversal'):
                m.copy_git_roots(self.cache, destination, [relative])
        self.r.prepare(); self.r.rotate()
        self.assertFalse(any(args[0] in ('git', 'sh', 'bash', 'cargo') for args, _ in self.cluster.calls))

    def test_full_inventory_counts_hardlink_paths_separately(self):
        os.link(self.cache / 'blob-a', self.cache / 'blob-alias')
        result = m.inspect_tree(self.cache, self.top / 'alias-inventory.jsonl')
        self.assertEqual(result['ordinary_files'], 3)
        self.assertEqual(result['git_roots'], ['mdn/history.git', 'npm/registry.git'])

    def test_cache_inventory_sha_binds_mode_and_bytes(self):
        a = m.inspect_tree(self.cache, self.top / 'inventory-a.jsonl')
        (self.cache / 'blob-a').chmod(0o600)
        b = m.inspect_tree(self.cache, self.top / 'inventory-b.jsonl')
        self.assertNotEqual(a['sha256'], b['sha256'])

    def test_real_sql_identity_emits_valid_readonly_identifier_quoting(self):
        captured = []
        def k(*args, **kwargs):
            captured.append((args, kwargs))
            return m.enc({**self.identity, 'owners': 0})
        self.c.old.k = k
        result = m.Recovery.sql_identity(self.r)
        self.assertEqual(result['schema'], 18)
        self.assertEqual(len(captured), 1)
        args, options = captured[0]
        self.assertEqual(args[:3], ('exec', 'deployment/postgres', '-c'))
        query = args[-1]
        self.assertTrue(query.startswith("BEGIN READ ONLY; SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='250ms'; SELECT "))
        self.assertTrue(query.endswith('; COMMIT;'))
        self.assertIn('ORDER BY id COLLATE "C"', query)
        self.assertNotIn(chr(92) + '"', query)
        self.assertIn("E'" + chr(92) + "n'", query)
        self.assertIn('row_to_json(g)::text', query)
        self.assertEqual(options['timeout'], 90)
        self.assertEqual(query, "BEGIN READ ONLY; SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='250ms'; " + m.IDENTITY_SQL + '; COMMIT;')

    def test_real_sql_identity_rejects_wrong_owner_or_archive_binding(self):
        for change in ({'owners': 1}, {'archive': {**self.identity['archive'], 'binding': 'different'}}):
            self.c.old.k = lambda *a, value=change, **kw: m.enc({**self.identity, 'owners': 0, **value})
            with self.subTest(change=change), self.assertRaises(m.Stop):
                m.Recovery.sql_identity(self.r)

    def test_real_sql_identity_requires_one_writer_after_start(self):
        self.c.old.k = lambda *a, **kw: m.enc({**self.identity, 'owners': 1})
        self.assertEqual(m.Recovery.sql_identity(self.r, stopped=False)['owners'], 1)

    def test_source_pins_have_complete_exact_hashes(self):
        self.assertRegex(m.CONTROLLER_SHA, r'^[a-f0-9]{64}$')
        self.assertRegex(m.CHECKPOINT_SHA, r'^[a-f0-9]{64}$')
        self.assertEqual(m.CONTROLLER_SHA, '2b18ea9ee326eabbafa1398f0f065c639b9e70fe01962cca31e6d8fc86365a6e')


if __name__ == '__main__': unittest.main()
