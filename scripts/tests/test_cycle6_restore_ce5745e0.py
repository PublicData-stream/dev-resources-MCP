"""Exercise the exact successor restore source with disposable filesystem state."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.tests import test_restore_1d76fbcc as historical


PRODUCTION = historical.ROOT / 'deploy/production'
adapter = historical.module('cycle6_restore_adapter', PRODUCTION / 'cycle6_restore_ce5745e0.py')
predecessor = historical.module('cycle6_restore_predecessor', PRODUCTION / 'cycle5_3dae7d91.py')


class RestorePolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='cycle6-restore-source-', dir='/tmp')
        cls.addClassCleanup(temporary.cleanup)
        root = Path(temporary.name)
        files = predecessor.render(root / 'predecessor', predecessor.PREVIOUS_CONTROLLER_SHA,
                                   predecessor.PREVIOUS_MANIFEST_SHA)
        cls.original = Path(files['restore-controller.py']['local']).read_text()
        cls.source = adapter.patch_restore(cls.original)
        path = root / 'restore-controller.py'
        path.write_text(cls.source)
        path.chmod(0o600)
        cls.m = historical.module('cycle6_fixture_restore', path)

    def setUp(self):
        fixture_patch = patch.object(historical, 'm', self.m)
        fixture_patch.start()
        self.addCleanup(fixture_patch.stop)
        self.f = historical.RestoreCuts()
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.restore = self.f.restore
        self.real_rename = os.rename
        self.real_process_guard = self.m.cache_process_guard
        process_guard = patch.object(self.m, 'cache_process_guard')
        self.process_guard = process_guard.start()
        self.addCleanup(process_guard.stop)

    def run_restore(self, **kwargs):
        return self.restore.run(self.f.pins, **kwargs)

    def cache_paths(self, role, state):
        source = self.f.cache_roots[role]
        return (source, source.with_name('.restore-' + role + '-' + state['token']),
                source.with_name('.failed-' + role + '-' + state['token']))

    def fail_preservation(self, *roles):
        sources = {self.f.cache_roots[role] for role in roles}

        def rename(source, destination):
            if source in sources:
                raise PermissionError('controlled cache preserve failure')
            return self.real_rename(source, destination)

        return patch.object(self.m.os, 'rename', side_effect=rename)

    def assert_no_recursive_delete(self):
        return patch.object(self.m.shutil, 'rmtree', side_effect=AssertionError('unexpected recursive deletion'))

    def assert_restored(self, receipt, lost):
        self.assertTrue(receipt['preserved_directory'])
        self.assertTrue(receipt['baseline_caches_restored'])
        self.assertEqual(receipt['discarded_candidate_caches'], lost)
        self.assertEqual(receipt['preservation'], 'manifest_verified')
        self.assertEqual(self.f.pg, 1)
        state = self.restore.state()
        stage, old = self.restore.paths(state)
        self.assertFalse(stage.exists())
        self.assertEqual((old / 'base/retained').read_text(), 'post-task')
        self.assertEqual((self.f.live / 'schema').read_text(), '18')
        for role in self.f.cache_roots:
            source, stage, old = self.cache_paths(role, state)
            self.assertEqual((source / 'workspace').read_text(), 'pre-task-' + role)
            self.assertFalse(stage.exists())
            if role in lost:
                self.assertFalse(old.exists())
            else:
                self.assertEqual((old / 'workspace').read_text(), 'newer-task-' + role)
        self.assertFalse((self.restore.root / 'discard-original-intent.json').exists())

    def test_generated_source_replaces_both_sql_deletion_branches(self):
        self.assertNotIn('shutil.rmtree(self.source)', self.source)
        with self.assertRaises(adapter.RenderError):
            adapter.patch_restore(self.source)
        with self.assertRaises(adapter.RenderError):
            adapter.patch_restore(self.original.replace('def golden_size', 'def replaced_golden_size'))
        with self.assertRaisesRegex(adapter.RenderError, 'frozen_restore_method_changed'):
            adapter.patch_restore(self.original.replace('def reconcile(self, state):',
                                                       'def reconcile(self, state):\n        # changed'))

    def test_normal_restore_preserves_all_candidate_bytes(self):
        with self.assert_no_recursive_delete():
            receipt = self.run_restore()
        self.assert_restored(receipt, [])
        self.process_guard.assert_not_called()

    def test_sql_manifest_failure_leaves_database_in_place_without_retry(self):
        state = self.f.stopped()
        old = self.m.tree_identity(self.f.live)
        manifest = self.m.manifest

        def fail_manifest(cp, path):
            if path == self.f.live:
                raise OSError('controlled manifest failure')
            return manifest(cp, path)

        with patch.object(self.m, 'manifest', side_effect=fail_manifest), self.assert_no_recursive_delete():
            with self.assertRaises(OSError):
                self.restore.preserve_and_install(state)
            with self.assertRaisesRegex(self.m.Stop, 'sql_preservation_failed'):
                self.run_restore(resume=True)
        self.assertEqual(self.m.tree_identity(self.f.live), old)
        self.assertEqual((self.f.live / 'base/retained').read_text(), 'post-task')
        self.assertEqual(self.f.pg, 0)
        self.assertEqual(self.m.load(self.restore.root / 'sql-preservation-failed.json')['reason'], 'manifest')

    def test_definitively_failed_sql_rename_never_discards_or_retries(self):
        state = self.f.stopped()
        _, old = self.restore.paths(state)

        def fail_rename(source, destination):
            if source == self.f.live:
                raise PermissionError('controlled SQL preserve failure')
            return self.real_rename(source, destination)

        with patch.object(self.m.os, 'rename', side_effect=fail_rename) as rename, self.assert_no_recursive_delete():
            with self.assertRaisesRegex(self.m.Stop, 'sql_preservation_failed'):
                self.restore.preserve_and_install(state)
            with self.assertRaisesRegex(self.m.Stop, 'sql_preservation_failed'):
                self.run_restore(resume=True)
            rename.assert_called_once_with(self.f.live, old)
        self.assertFalse(old.exists())
        self.assertEqual(self.m.tree_identity(self.f.live), state['original_identity'])
        self.assertEqual((self.f.live / 'base/retained').read_text(), 'post-task')
        self.assertEqual(self.f.pg, 0)
        self.assertEqual(self.m.load(self.restore.root / 'sql-preservation-failed.json')['reason'], 'rename')

    def test_historical_sql_discard_intent_cannot_authorize_resume(self):
        self.f.stopped()
        (self.restore.root / 'discard-original-intent.json').symlink_to('dangling')
        with self.assert_no_recursive_delete(), self.assertRaisesRegex(self.m.Stop, 'sql_discard_forbidden'):
            self.run_restore(resume=True)
        self.assertEqual((self.f.live / 'schema').read_text(), '19')

    def test_lost_database_original_rename_response_keeps_candidate_preserved(self):
        state = self.f.stopped()

        def completed_then_failed(source, destination):
            self.real_rename(source, destination)
            if source == self.f.live:
                raise OSError('controlled lost response')

        with patch.object(self.m.os, 'rename', side_effect=completed_then_failed), self.assert_no_recursive_delete():
            self.restore.preserve_and_install(state)
        self.assert_restored(self.run_restore(resume=True), [])

    def test_single_candidate_cache_discard_reinstalls_verified_baseline(self):
        with self.fail_preservation('serving'):
            receipt = self.run_restore()
        self.assert_restored(receipt, ['serving'])
        self.process_guard.assert_called_once()
        intent = self.m.load(self.restore.root / 'candidate-cache-discard-intent.json')
        completed = self.m.load(self.restore.root / 'candidate-cache-discard-completed.json')
        self.assertEqual(intent['pvc_uid'], 'uid-serving')
        self.assertEqual(intent['pv_uid'], 'pvuid-serving')
        self.assertEqual(intent['original'], self.f.cache_data['layouts']['serving']['identity'])
        self.assertEqual(intent['baseline_sha256'], self.m.sha(self.m.encoded(self.f.cache_data['manifests']['serving'])))
        self.assertEqual(completed, {'role': 'serving', 'intent_sha256': self.m.sha(self.m.encoded(intent)),
                                     'original_root_absent': True})
        with self.assert_no_recursive_delete():
            self.assertEqual(receipt, self.run_restore(resume=True))

    def test_second_cache_rename_failure_cannot_consume_another_discard(self):
        with self.fail_preservation('serving', 'writer'):
            with self.assertRaisesRegex(self.m.Stop, 'single_candidate_cache_discard_required'):
                self.run_restore()
        state = self.restore.state()
        self.assertEqual((self.f.cache_roots['serving'] / 'workspace').read_text(), 'pre-task-serving')
        self.assertEqual((self.f.cache_roots['writer'] / 'workspace').read_text(), 'newer-task-writer')
        self.assertEqual((self.restore.paths(state)[1] / 'base/retained').read_text(), 'post-task')
        self.assertEqual(self.f.pg, 0)
        self.assertFalse((self.restore.root / 'restored.json').exists())
        self.process_guard.assert_called_once()

    def test_lost_cache_rename_response_preserves_exact_old_root(self):
        def completed_then_failed(source, destination):
            self.real_rename(source, destination)
            if source == self.f.cache_roots['serving']:
                raise OSError('controlled lost response')

        with patch.object(self.m.os, 'rename', side_effect=completed_then_failed), self.assert_no_recursive_delete():
            receipt = self.run_restore()
        self.assert_restored(receipt, [])
        self.assertFalse((self.restore.root / 'candidate-cache-discard-intent.json').exists())

    def test_completed_discard_without_receipt_reconciles_without_second_deletion(self):
        receipt = self.restore.receipt

        def cut(name, value):
            if name == 'candidate-cache-discard-completed.json':
                raise RuntimeError('controlled cut after cache removal')
            return receipt(name, value)

        with self.fail_preservation('serving'), patch.object(self.restore, 'receipt', side_effect=cut):
            with self.assertRaisesRegex(RuntimeError, 'controlled cut'):
                self.run_restore()
        state = self.restore.state()
        source, stage, preserved = self.cache_paths('serving', state)
        self.assertFalse(source.exists())
        self.assertFalse(preserved.exists())
        self.assertTrue(stage.exists())
        with self.assert_no_recursive_delete():
            result = self.run_restore(resume=True)
        self.assert_restored(result, ['serving'])

    def test_partial_discard_cannot_replay_or_replace_staging(self):
        def partial(name, *, dir_fd):
            self.assertEqual(name, self.f.cache_roots['serving'].name)
            source_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dir_fd)
            try:
                os.unlink('workspace', dir_fd=source_fd)
            finally:
                os.close(source_fd)
            raise OSError('controlled interrupted tree removal')

        with self.fail_preservation('serving'), patch.object(self.m.shutil, 'rmtree', side_effect=partial):
            with self.assertRaises(OSError):
                self.run_restore()
        state = self.restore.state()
        source, stage, preserved = self.cache_paths('serving', state)
        self.assertTrue(source.exists())
        self.assertFalse(preserved.exists())
        with self.assert_no_recursive_delete(), self.assertRaisesRegex(self.m.Stop, 'cache_preservation_outcome_uncertain'):
            self.run_restore(resume=True)
        self.assertEqual((stage / 'workspace').read_text(), 'pre-task-serving')
        self.assertEqual(self.f.pg, 0)

    def test_cache_install_cut_reconciles_by_exact_installed_inode(self):
        def cut(source, destination):
            if source == self.f.cache_roots['serving']:
                raise PermissionError('controlled cache preserve failure')
            self.real_rename(source, destination)
            if destination == self.f.cache_roots['serving']:
                raise RuntimeError('controlled lost baseline install response')

        with patch.object(self.m.os, 'rename', side_effect=cut):
            with self.assertRaisesRegex(RuntimeError, 'lost baseline install'):
                self.run_restore()
        self.assertEqual((self.f.cache_roots['serving'] / 'workspace').read_text(), 'pre-task-serving')
        with self.assert_no_recursive_delete():
            restored = self.run_restore(resume=True)
        self.assert_restored(restored, ['serving'])

    def test_restart_reconciliation_does_not_scale_ready_postgres_twice(self):
        real_k = self.f.cp.k

        def cut(*args, **kwargs):
            if args[:3] == ('rollout', 'status', 'deployment/postgres'):
                raise OSError('controlled lost PostgreSQL rollout result')
            return real_k(*args, **kwargs)

        with self.fail_preservation('serving'), patch.object(self.f.cp, 'k', side_effect=cut):
            with self.assertRaisesRegex(OSError, 'lost PostgreSQL rollout'):
                self.run_restore()
        self.assertEqual(self.f.pg, 1)
        with self.assert_no_recursive_delete():
            restored = self.run_restore(resume=True)
        self.assert_restored(restored, ['serving'])
        self.assertEqual(self.f.calls.count(('scale', 'deployment/postgres', '--replicas=1')), 1)

    def test_staging_drift_after_failed_cache_rename_prevents_discard(self):
        source = self.f.cache_roots['serving']

        def changed_staging(original, target):
            if original == source:
                _, stage, _ = self.cache_paths('serving', self.restore.state())
                (stage / 'workspace').write_text('unexpected staging bytes')
                raise OSError('controlled failed rename')
            return self.real_rename(original, target)

        with patch.object(self.m.os, 'rename', side_effect=changed_staging), self.assert_no_recursive_delete():
            with self.assertRaisesRegex(self.m.Stop, 'cache_staging_changed'):
                self.run_restore()
        self.assertEqual((source / 'workspace').read_text(), 'newer-task-serving')
        self.assertFalse((self.restore.root / 'candidate-cache-discard-intent.json').exists())
        self.assertEqual(self.f.pg, 0)

    def test_candidate_cache_symlink_and_external_hardlink_prevent_discard(self):
        self.f.cache_roots['serving'].joinpath('internal').symlink_to('workspace')
        with self.fail_preservation('serving'), self.assert_no_recursive_delete():
            with self.assertRaisesRegex(self.m.Stop, 'candidate_cache_unsafe_entry'):
                self.run_restore()
        self.assertFalse((self.restore.root / 'candidate-cache-discard-intent.json').exists())
        source = self.f.cache_roots['writer']
        link = self.f.root / 'external-hardlink'
        os.link(source / 'workspace', link)
        with self.m.cache_parent(source) as fd:
            with self.assertRaisesRegex(self.m.Stop, 'external_candidate_cache_hardlink'):
                self.m.discard_inventory(source, fd, self.m.tree_identity(source))
        self.assertEqual(link.read_text(), 'newer-task-writer')

    def test_mount_and_live_process_references_fail_closed(self):
        source = self.f.cache_roots['serving']
        inode = (source.stat().st_dev, source.stat().st_ino)
        device = f'{os.major(inode[0])}:{os.minor(inode[0])}'
        proc = self.f.root / 'proc'
        host = f'1 0 {device} / / rw - ext4 /dev/test rw\n'
        (proc / 'self').mkdir(parents=True)
        (proc / 'self/mountinfo').write_text(host)
        pid = proc / '123'
        (pid / 'ns').mkdir(parents=True)
        (pid / 'ns/mnt').symlink_to('mnt:[1]')
        (pid / 'fd').mkdir()
        (pid / 'maps').write_text('')
        (pid / 'mountinfo').write_text(host + f'2 1 {device} {source} /mnt/candidate rw - ext4 /dev/test rw\n')
        with self.assertRaisesRegex(self.m.Stop, 'candidate_cache_bind_mount_present'):
            self.real_process_guard(source, {inode}, proc=proc)
        (pid / 'mountinfo').write_text(host)
        (pid / 'fd/4').symlink_to(source)
        with self.assertRaisesRegex(self.m.Stop, 'active_candidate_cache_reference'):
            self.real_process_guard(source, {inode}, proc=proc)


if __name__ == '__main__':
    unittest.main()
