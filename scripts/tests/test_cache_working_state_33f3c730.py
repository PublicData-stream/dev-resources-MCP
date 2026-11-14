"""Complete working-state fixtures, including the actual omitted-owner failure."""
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

import test_cache_resume_33f3c730 as earlier

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('cache_working_state', ROOT / 'deploy/production/cache_working_state_33f3c730.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)
legacy = earlier.m


class WorkingRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.old = earlier.CacheRecoveryTests(); self.old.setUp(); self.addCleanup(self.old.doCleanups)
        self.c, self.cache, self.bundle, self.top = self.old.c, self.old.cache, self.old.bundle, self.old.top
        for child in list(self.cache.iterdir()):
            if child.is_dir(): shutil.rmtree(child)
            else: child.unlink()
        for name in m.TOP: (self.cache / name).mkdir()
        for name in m.TOP - {'npm-search'}:
            (self.cache / name / 'state').write_bytes(('owned ' + name).encode())
        markers = {'crate-git/.devres-git-owned': b'devres registry git v1\n',
            'mdn/content/owner-v1': b'devres-mdn-content-v1\n',
            'mdn/compat/owner-v1': b'devres-mdn-compat-v1\n',
            'rustsec-history/owner-v1': b'devres-rustsec-history-v1\n',
            'whatwg/git/whatwg/html/owner-v1': b'devres-whatwg-whatwg/html-v1\n'}
        self.git_roots = ['crate-git/registry.git', 'mdn/content/history.git', 'mdn/compat/history.git',
            'rustsec-history/history.git', 'whatwg/git/whatwg/html/history.git']
        for name in self.git_roots:
            root = self.cache / name; root.mkdir(parents=True, exist_ok=True); (root / 'HEAD').write_bytes(b'ref: main\n')
            if name != 'crate-git/registry.git':
                artifacts = root.parent / 'artifacts'; artifacts.mkdir(); (artifacts / 'registered').write_bytes(b'registered artifact')
        for name, data in markers.items(): (self.cache / name).write_bytes(data)
        inventory = legacy.inspect_tree(self.cache, self.top / 'seed.jsonl')
        for name, value in (('EXPECTED_ORDINARY_FILES', inventory['ordinary_files']), ('GIT_ROOT_COUNT', len(self.git_roots))):
            p = patch.object(legacy, name, value); p.start(); self.addCleanup(p.stop)
        self.old.r.prepare(); self.old.r.rotate()
        self.old.cluster.fail_rollout = True
        with self.assertRaises(legacy.Stop): self.old.r.start()
        self.old.cluster.fail_rollout = False
        # Reproduce target startup's additional empty registration directories.
        (self.cache / 'startup').mkdir()
        for i in range(19): (self.cache / 'startup' / str(i)).mkdir()
        failed_now = legacy.inspect_tree(self.cache, self.top / 'post-startup-failed.jsonl')
        self.previous = self.old.journal
        self.original = self.previous / 'writer-original'
        self.journal = self.bundle / 'cache-working-state-recovery'
        working = m.working_fingerprint(self.previous / 'original-cache.jsonl')
        values = {'BUNDLE': self.bundle, 'ROOT': self.journal, 'PREVIOUS': self.previous,
            'ORIGINAL': self.original, 'CACHE': self.cache, 'FAILED': self.journal / 'failed-generation',
            'START_INODE': self.cache.stat().st_ino, 'EXPECTED_ORDINARY': working['ordinary_files'],
            'EXPECTED_GIT': 5, 'EXPECTED_WHATWG': 1, 'FAILED_SHA': failed_now['sha256']}
        for name, value in values.items():
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)
        self.approval = self.top / 'working-approval.json'
        value = {'version': 1, 'kind': 'preserving-writer-working-state-recovery', 'approved': True,
            'source_sha256': m.sha(Path(m.__file__).read_bytes()), 'controller_sha256': m.CONTROLLER_SHA,
            'previous_recovery_sha256': m.LEGACY_SHA, 'controller_prepared_sha256': self.c.state()['prepared_sha256'],
            'previous_recovery_state_sha256': m.sha(legacy.raw(self.previous / 'state.json')),
            'withdrawn_state_sha256': m.sha(legacy.raw(self.bundle / 'state.json')),
            'operations': ['prepare', 'restore', 'start'], 'maximum_restores': 1, 'maximum_start_attempts': 1,
            'preserve_all_previous_generations': True, 'new_permanent_mutations': False}
        approval_sha = earlier.control.private(self.approval, value)
        self.r = m.Recovery(self.c, self.old.checkpoint, legacy, self.approval, approval_sha)
        self.r.base.sql_identity = self.old.r.sql_identity

    def test_bare_git_only_layout_reproduces_absent_ownership(self):
        with self.assertRaises(FileNotFoundError): m.owners(self.cache, self.git_roots, legacy)
        self.assertEqual(m.owners(self.original, self.git_roots, legacy),
            {'mdn': 2, 'whatwg': 1, 'rustsec-history': 1, 'crate-git': 1})

    def test_complete_restore_preserves_both_generations_and_all_working_views(self):
        previous_bytes = {name: (self.previous / name).read_bytes() for name in ('state.json', 'prepared.json', 'rotation-proof.json')}
        old_inode, failed_inode = self.original.stat().st_ino, self.cache.stat().st_ino
        self.r.prepare(); self.r.restore()
        self.assertEqual(self.original.stat().st_ino, old_inode)
        self.assertEqual((self.journal / 'failed-generation').stat().st_ino, failed_inode)
        self.assertNotEqual(self.cache.stat().st_ino, failed_inode)
        self.assertEqual({p.name for p in self.cache.iterdir()}, m.RESTORE)
        self.assertTrue((self.cache / 'npm-search').is_dir())
        self.assertFalse((self.cache / '.devres-integrity').exists())
        self.assertFalse((self.cache / 'blake3').exists())
        self.assertEqual((self.cache / 'whatwg/git/whatwg/html/owner-v1').read_bytes(), b'devres-whatwg-whatwg/html-v1\n')
        self.assertTrue((self.cache / 'whatwg/git/whatwg/html/artifacts/registered').exists())
        self.assertNotEqual((self.cache / 'mdn/content/owner-v1').stat().st_ino,
                            (self.original / 'mdn/content/owner-v1').stat().st_ino)
        self.r.start()
        self.assertEqual(self.c.state()['phase'], 'writer_ready')
        self.assertEqual(self.r.state()['phase'], 'writer_ready')
        self.assertEqual({name: (self.previous / name).read_bytes() for name in previous_bytes}, previous_bytes)
        self.assertTrue((self.bundle / 'cache-working-state-start-writer-intent.json').exists())

    def test_missing_any_retained_parent_marker_or_artifact_is_rejected(self):
        for relative in ('crate-git/.devres-git-owned', 'mdn/content/owner-v1', 'rustsec-history/owner-v1',
                         'whatwg/git/whatwg/html/owner-v1'):
            path = self.original / relative; before = path.read_bytes(); path.unlink()
            with self.subTest(marker=relative), self.assertRaises(FileNotFoundError): m.owners(self.original, self.git_roots, legacy)
            path.write_bytes(before)
        path = self.original / 'whatwg/git/whatwg/html/artifacts'
        os.rename(path, path.parent / 'saved-artifacts')
        with self.assertRaisesRegex(m.Stop, 'registered_artifacts_directory_required'): m.owners(self.original, self.git_roots, legacy)

    def test_wrong_marker_bytes_are_not_repaired_or_invented(self):
        marker = self.original / 'whatwg/git/whatwg/html/owner-v1'; marker.write_bytes(b'wrong\n')
        with self.assertRaisesRegex(m.Stop, 'retained_ownership_mismatch'): m.owners(self.original, self.git_roots, legacy)
        self.assertEqual(marker.read_bytes(), b'wrong\n')

    def test_unknown_top_directory_is_not_silently_copied(self):
        (self.original / 'unexpected').mkdir()
        with self.assertRaisesRegex(m.Stop, 'original_generation_changed'): self.r.prepare()
        self.assertFalse((self.journal / 'failed-generation').exists())

    def test_changed_previous_journal_rejects_before_filesystem_mutation(self):
        value = legacy.load(self.previous / 'state.json'); value['phase'] = 'changed'
        earlier.control.private(self.previous / 'state.json', value)
        with self.assertRaises(m.Stop): self.r.prepare()
        self.assertFalse(self.journal.exists())

    def test_changed_failed_generation_is_preserved_without_rotation(self):
        (self.cache / 'extra').write_bytes(b'changed')
        with self.assertRaisesRegex(m.Stop, 'failed_generation_changed'): self.r.prepare()
        self.assertFalse((self.journal / 'failed-generation').exists())

    def test_interrupted_restore_keeps_all_old_data_and_cannot_replay(self):
        self.r.prepare()
        with patch.object(m, 'copy_working', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError): self.r.restore()
        self.assertTrue((self.journal / 'failed-generation/mdn/content/history.git/HEAD').exists())
        self.assertTrue((self.original / '.devres-integrity/state').exists())
        with self.assertRaisesRegex(m.Stop, 'working_phase'): self.r.restore()
        with self.assertRaisesRegex(m.Stop, 'working_phase'): self.r.start()

    def test_new_failed_start_has_fresh_fence_and_preserves_all_generations(self):
        self.r.prepare(); self.r.restore(); self.old.cluster.fail_rollout = True
        with self.assertRaisesRegex(m.Stop, 'working_state_start_failed_fenced'): self.r.start()
        self.assertEqual(self.r.state()['phase'], 'start_failed_fenced')
        self.assertEqual(set(self.old.cluster.live_pods), {'postgres'})
        self.assertTrue((self.journal / 'failed-working-state-stop-writer-completed.json').exists())
        self.assertTrue((self.previous / 'failed-cache-recovery-stop-writer-completed.json').exists())
        with self.assertRaisesRegex(m.Stop, 'working_phase'): self.r.start()

    def test_headroom_limit_is_a_hard_precondition(self):
        with patch.object(m, 'MAX_ORDINARY', 1):
            with self.assertRaisesRegex(m.Stop, 'working_file_headroom'): self.r.prepare()
        self.assertFalse((self.journal / 'failed-generation').exists())

    def test_unowned_additional_whatwg_parent_is_detected_before_start(self):
        extra = self.original / 'whatwg/git/whatwg/extra'; extra.mkdir()
        with self.assertRaises(FileNotFoundError): m.owners(self.original, self.git_roots, legacy)

    def test_postfailure_empty_directories_are_bound_and_preserved(self):
        self.r.prepare()
        prepared = self.r.prepared()
        old = legacy.load(self.previous / 'rotation-proof.json')['fresh']
        self.assertEqual(prepared['failed']['entries'], old['entries'] + 20)
        self.assertEqual(prepared['failed']['git_sha256'], old['git_sha256'])
        self.assertNotEqual(prepared['failed']['sha256'], old['sha256'])
        self.r.restore()
        self.assertTrue((self.journal / 'failed-generation/startup/18').is_dir())
        self.assertFalse((self.cache / 'startup').exists())

    def test_unlisted_restored_top_directory_blocks_start(self):
        self.r.prepare(); self.r.restore()
        (self.cache / 'unlisted').mkdir()
        with self.assertRaisesRegex(m.Stop, 'restored_generation_changed'): self.r.start()
        self.assertNotIn('writer', self.old.cluster.live_pods)

    def test_fixed_top_set_includes_empty_npm_view_and_excludes_only_two_caches(self):
        self.assertEqual(len(m.TOP), 16)
        self.assertEqual(len(m.RESTORE), 14)
        self.assertIn('npm-search', m.RESTORE)
        self.assertEqual(m.TOP - m.RESTORE, {'.devres-integrity', 'blake3'})
        self.assertRegex(m.LEGACY_SHA, r'^[0-9a-f]{64}$')


if __name__ == '__main__': unittest.main()
