import datetime
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = ROOT/'deploy/production'


def load(name):
    spec = importlib.util.spec_from_file_location(name, PRODUCTION/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


reclaim = load('cycle6_reclaim_ce5745e0')
old = load('cycle5_reclaim_3dae7d91')


class ReclamationTests(unittest.TestCase):
    def test_fixed_engine_has_exact_unchanged_bytes(self):
        self.assertEqual(reclaim.digest(Path(old.__file__).read_bytes()), reclaim.ENGINE_SHA)

    def test_historical_phase_counts_rehearsal_margin_with_retained_golden_and_cache(self):
        db = 27_415_165_221
        cache = 11_701_186_054
        self.assertEqual(reclaim.required_free(reclaim.PHASES[0], db, cache), 293_904_358_572)
        self.assertEqual(reclaim.required_free(reclaim.PHASES[1], db, cache), 254_788_007_297)

    def test_backup_dependency_on_copy_via_alias_is_refused_before_body_read(self):
        engine = MagicMock()
        engine.safe_path.side_effect = lambda path: path
        inventory = reclaim.Inventory(engine)
        inventory.leaves = [reclaim.Leaf(Path('/historical/copy'), Path('/tmp/producer/copy'))]
        inventory.backups = [{'path': '/tmp/producer/copy/sub/file', 'sha256': '0'*64}]
        with self.assertRaisesRegex(reclaim.Refused, 'backup_artifact_is_copy_body'):
            inventory.check_backup_dependencies()
        engine.file_record.assert_not_called()

    def test_backup_dependency_on_retained_golden_body_never_reads_body(self):
        engine = MagicMock()
        engine.safe_path.side_effect = lambda path: path
        inventory = reclaim.Inventory(engine)
        inventory.bodies = {'/historical/pg-checkpoint': {'alias': '/tmp/alias/pg-checkpoint'}}
        inventory.backups = [{'path': '/tmp/alias/pg-checkpoint/PG_VERSION', 'sha256': '0'*64}]
        with self.assertRaisesRegex(reclaim.Refused, 'backup_artifact_is_copy_body'):
            inventory.check_backup_dependencies()
        engine.file_record.assert_not_called()

    def test_bind_alias_inode_must_match(self):
        inventory = reclaim.Inventory(MagicMock())
        inventory.engine.directory_record.side_effect = [{'dev': 1,'ino': 2},{'dev': 1,'ino': 3}]
        with self.assertRaisesRegex(reclaim.Refused, 'work_bind_alias_identity'):
            inventory.leaf(Path('/body'), Path('/tmp/alias'))
        self.assertEqual(inventory.leaves, [])

    def test_external_hardlink_is_refused_before_any_delete(self):
        with tempfile.TemporaryDirectory(prefix='reclaim-c6-test-', dir='/tmp') as temporary:
            parent = Path(temporary)
            body = parent/'body'
            body.mkdir()
            (body/'file').write_bytes(b'sealed')
            (parent/'outside').hardlink_to(body/'file')
            inventory = SimpleNamespace(leaves=[reclaim.Leaf(body, body)])
            engine = SimpleNamespace(tree=lambda p: [dict(row, uid=0, gid=0) for row in old.tree(p)],
                                     MAX_ENTRIES=old.MAX_ENTRIES)
            with self.assertRaisesRegex(reclaim.Refused, 'external_hardlink_refused'):
                reclaim.tree_records(engine, inventory)
            self.assertEqual((parent/'outside').read_bytes(), b'sealed')

    def test_copy_with_external_symlink_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='reclaim-c6-test-', dir='/tmp') as temporary:
            parent = Path(temporary)
            body = parent/'body'
            body.mkdir()
            (parent/'outside').write_bytes(b'preserved')
            (body/'escape').symlink_to('../outside')
            inventory = SimpleNamespace(leaves=[reclaim.Leaf(body, body)])
            engine = SimpleNamespace(tree=lambda p: [dict(row, uid=0, gid=0) for row in old.tree(p)],
                                     MAX_ENTRIES=old.MAX_ENTRIES)
            with self.assertRaisesRegex(reclaim.Refused, 'external_disposable_copy_link'):
                reclaim.tree_records(engine, inventory)
            self.assertEqual((parent/'outside').read_bytes(), b'preserved')

    def test_capacity_scan_deduplicates_only_cache_internal_hardlinks(self):
        with tempfile.TemporaryDirectory(prefix='reclaim-c6-test-', dir='/tmp') as temporary:
            parent = Path(temporary)
            cache = parent/'cache'
            cache.mkdir()
            (cache/'value').write_bytes(b'1234')
            (cache/'second').hardlink_to(cache/'value')
            self.assertEqual(reclaim.body_bytes(cache, True), 4)
            with self.assertRaisesRegex(reclaim.Refused, 'postgres_hardlink_refused'):
                reclaim.body_bytes(cache, False)
            (parent/'outside').hardlink_to(cache/'value')
            with self.assertRaisesRegex(reclaim.Refused, 'external_cache_links'):
                reclaim.body_bytes(cache, True)

    def test_approval_must_bind_phase_source_engine_preview_and_near_expiry(self):
        phase = reclaim.PHASES[0]
        now = datetime.datetime(2026, 11, 18, tzinfo=datetime.timezone.utc)
        approval = {'version': 1, 'kind': reclaim.KIND, 'approved': True, 'phase': phase,
                    'operations': ['apply'], 'maximum_applies': 1, 'source_sha256': 'a'*64,
                    'engine_sha256': reclaim.ENGINE_SHA, 'preview_sha256': 'b'*64,
                    'expires_at': (now+datetime.timedelta(minutes=5)).isoformat()}
        reclaim.validate_approval(approval, phase, 'a'*64, 'b'*64, now)
        for replacement in ({'maximum_applies': True}, {'phase': reclaim.PHASES[1]},
                            {'preview_sha256': 'c'*64}, {'engine_sha256': 'd'*64}):
            with self.assertRaisesRegex(reclaim.Refused, 'exact_retirement_approval_required'):
                reclaim.validate_approval(approval | replacement, phase, 'a'*64, 'b'*64, now)
        for expiry in (now, now+datetime.timedelta(minutes=16)):
            with self.assertRaisesRegex(reclaim.Refused, 'finite_retirement_approval_required'):
                reclaim.validate_approval(approval | {'expires_at': expiry.isoformat()}, phase, 'a'*64, 'b'*64, now)

    def test_runtime_recheck_refuses_mismatched_quiet_state_before_durable_intent(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        phase = reclaim.PHASES[0]
        original = {'quiet': {'postgres': 'original'}, 'environment': {}, 'capacity': {}}
        old_preview = json.dumps(original).encode()
        digest = reclaim.digest(old_preview)
        approval = json.dumps({'version': 1, 'kind': reclaim.KIND, 'approved': True, 'phase': phase,
                               'operations': ['apply'], 'maximum_applies': 1, 'source_sha256': 'a'*64,
                               'engine_sha256': reclaim.ENGINE_SHA, 'preview_sha256': digest,
                               'expires_at': (now+datetime.timedelta(minutes=5)).isoformat()}).encode()
        engine = MagicMock()
        engine.environment_binding.side_effect = lambda value: value
        args = SimpleNamespace(phase=phase, preview=Path('/tmp/preview'), approval=Path('/tmp/approval'),
                               preview_sha256=digest, approval_sha256=reclaim.digest(approval),
                               source_sha256='a'*64)
        with tempfile.TemporaryDirectory(prefix='reclaim-c6-test-', dir='/tmp') as temporary:
            journal = Path(temporary)/phase
            with patch.object(reclaim, 'read_private', side_effect=[old_preview, approval]), \
                 patch.object(reclaim, 'preview', return_value=original | {'quiet': {'postgres': 'changed'}}):
                with self.assertRaisesRegex(reclaim.Refused, 'retirement_preview_stale'):
                    reclaim.apply(engine, args, None, journal)
            self.assertFalse(journal.exists())
        engine.Engine.assert_not_called()

    def test_preexisting_journal_fences_any_further_apply_before_preview(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        fixture = {'version': 1, 'kind': reclaim.KIND, 'approved': True, 'phase': reclaim.PHASES[1],
                   'operations': ['apply'], 'maximum_applies': 1, 'source_sha256': 'a'*64,
                   'engine_sha256': reclaim.ENGINE_SHA, 'preview_sha256': reclaim.digest(b'{}'),
                   'expires_at': (now+datetime.timedelta(minutes=5)).isoformat()}
        approval = json.dumps(fixture).encode()
        args = SimpleNamespace(phase=fixture['phase'], preview=Path('/tmp/preview'), approval=Path('/tmp/approval'),
                               preview_sha256=fixture['preview_sha256'], approval_sha256=reclaim.digest(approval),
                               source_sha256='a'*64)
        with tempfile.TemporaryDirectory(prefix='reclaim-c6-test-', dir='/tmp') as temporary:
            with patch.object(reclaim, 'read_private', side_effect=[b'{}', approval]), \
                 patch.object(reclaim, 'preview') as preview:
                with self.assertRaisesRegex(reclaim.Refused, 'retirement_intent_already_consumed'):
                    reclaim.apply(MagicMock(), args, 'c'*64, Path(temporary))
            preview.assert_not_called()
