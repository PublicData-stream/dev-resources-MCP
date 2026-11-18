import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


PATH = Path(__file__).resolve().parents[2]/'deploy/production/cycle5_public_identity_3dae7d91.py'
SPEC = importlib.util.spec_from_file_location('cycle5_public_identity_test', PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class FrozenSource(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'legacy-public-identity-builder.py'
        self.body = b"VALUE = 'verified first-party fixture'\nif __name__ == '__main__': raise RuntimeError('main must not execute')\n"
        self.path.write_bytes(self.body)
        self.path.chmod(0o600)
        self.record = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0,
                                      st_nlink=1, st_size=len(self.body))
        for name, value in (('LEGACY', self.path), ('LEGACY_SHA', hashlib.sha256(self.body).hexdigest())):
            p = patch.object(M, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_executes_verified_private_copy_without_running_old_main(self):
        with patch.object(M.os, 'fstat', return_value=self.record):
            helper = M.frozen_helpers()
        self.assertEqual(helper.VALUE, 'verified first-party fixture')
        self.assertEqual(helper.__file__, str(self.path))
        self.assertEqual(self.path.read_bytes(), self.body)

    def test_transfer_owned_or_group_readable_or_linked_copy_is_refused(self):
        for key, value in (('st_uid', 1001), ('st_gid', 1001), ('st_mode', stat.S_IFREG | 0o640),
                           ('st_mode', stat.S_IFIFO | 0o600), ('st_nlink', 2)):
            record = SimpleNamespace(**{**vars(self.record), key: value})
            with self.subTest(key=key, value=value), patch.object(M.os, 'fstat', return_value=record):
                with self.assertRaisesRegex(RuntimeError, 'legacy_helper_private_source_required'):
                    M.frozen_helpers()

    def test_changed_source_or_symlink_is_refused_before_execution(self):
        self.path.write_bytes(b'raise AssertionError("must never execute")\n')
        self.record.st_size = self.path.stat().st_size
        with patch.object(M.os, 'fstat', return_value=self.record):
            with self.assertRaisesRegex(RuntimeError, 'legacy_helper_source_changed'):
                M.frozen_helpers()
        other = self.path.with_name('actual.py')
        self.path.rename(other)
        self.path.symlink_to(other)
        with self.assertRaisesRegex(RuntimeError, 'legacy_helper_symlink'):
            M.frozen_helpers()


class Identity(unittest.TestCase):
    def setUp(self):
        self.h = SimpleNamespace(INSTALLED={f'operator-{n}.py' for n in range(8)})
        self.old = {f'/usr/local/libexec/old/operator-{n}.py': f'{n:064x}' for n in range(29)}
        self.prior = {'revision': 'same-release', 'target_release': {'image': 'immutable'},
                      'controller_source_sha256': '0'*64, 'source_manifest_sha256': '1'*64,
                      'previous_cycle_source_manifest_sha256': '2'*64, 'dependency_sources': self.old,
                      'previous_cycle_s3_store_get_spent': 3, 'counter_scope': 'old-three',
                      'prior_cycle_ledgers': [{'cycle': str(n)} for n in range(3)],
                      'cycle4_render_manifest_sha256': '3'*64,
                      'legacy91_ledger_binding': {'spent': 'preserved'}, 'cold_read_control': {'bytes': 1024},
                      'approved_new_cycle_s3_store_get_maximum': 1, 'schema_before': 18,
                      'previous_cycle_source_provider_requests_spent': 0,
                      'previous_cycle_public_probe_stages_started': 0}
        self.manifest = {name: '4'*64 for name in self.h.INSTALLED}
        self.pins = {'controller': 'a'*64, 'manifest': 'b'*64, 'render': 'c'*64}

    def test_same_release_preserves_old_ledgers_and_adds_only_new_cycle_authority(self):
        before = copy.deepcopy(self.prior)
        deps = M.dependencies(self.h, self.prior, self.manifest)
        ledger = self.prior['prior_cycle_ledgers'] + [{'cycle': 'fourth', 's3_store_get_spent': 1}]
        result, changed = M.candidate(self.h, self.prior, deps, ledger, self.pins)
        self.assertEqual(self.prior, before)
        self.assertEqual(result['revision'], self.prior['revision'])
        self.assertEqual(result['target_release'], self.prior['target_release'])
        self.assertEqual(result['legacy91_ledger_binding'], self.prior['legacy91_ledger_binding'])
        self.assertEqual(result['cold_read_control'], self.prior['cold_read_control'])
        self.assertEqual(result['prior_cycle_ledgers'][:3], self.prior['prior_cycle_ledgers'])
        self.assertEqual(result['previous_cycle_s3_store_get_spent'], 4)
        self.assertEqual(result['approved_new_cycle_s3_store_get_maximum'], 1)
        self.assertEqual(result['previous_cycle_source_provider_requests_spent'], 0)
        self.assertEqual(result['previous_cycle_public_probe_stages_started'], 0)
        self.assertNotIn('revision', changed)
        self.assertNotIn('target_release', changed)

    def test_dependency_union_preserves_all_29_and_adds_eight_exact_predecessor_paths(self):
        result = M.dependencies(self.h, self.prior, self.manifest)
        self.assertEqual(len(result), 37)
        self.assertEqual({p: result[p] for p in self.old}, self.old)
        self.assertEqual(set(result)-set(self.old), {str(M.PRIOR_INSTALL/n) for n in self.h.INSTALLED})

    def test_38th_dependency_is_refused_without_truncation(self):
        self.prior['dependency_sources']['/usr/local/libexec/extra.py'] = 'f'*64
        before = copy.deepcopy(self.prior)
        with self.assertRaisesRegex(RuntimeError, 'exact_dependency_inventory_required'):
            M.dependencies(self.h, self.prior, self.manifest)
        self.assertEqual(self.prior, before)

    def test_duplicate_predecessor_dependency_and_invalid_source_hash_are_refused(self):
        self.prior['dependency_sources'].pop(next(iter(self.old)))
        self.prior['dependency_sources'][str(M.PRIOR_INSTALL/sorted(self.h.INSTALLED)[0])] = 'a'*64
        with self.assertRaisesRegex(RuntimeError, 'prior_dependency_duplicate'):
            M.dependencies(self.h, self.prior, self.manifest)
        self.prior['dependency_sources'] = {f'/old/{n}': 'a'*64 for n in range(29)}
        self.manifest[next(iter(self.manifest))] = 'foreign'
        with self.assertRaisesRegex(RuntimeError, 'exact_dependency_inventory_required'):
            M.dependencies(self.h, self.prior, self.manifest)

    def test_new_helper_request_maximum_or_schema_change_cannot_enter_candidate(self):
        for key, value in (('approved_new_cycle_s3_store_get_maximum', 2), ('schema_before', 19)):
            prior = {**self.prior, key: value}
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'single_cycle_schema18_scope_required'):
                M.candidate(self.h, prior, M.dependencies(self.h, prior, self.manifest),
                            prior['prior_cycle_ledgers']+[{}], self.pins)


class Ledger(unittest.TestCase):
    def setUp(self):
        self.values = {M.PRIOR/n: {} for n in M.PINS}
        self.values[M.PRIOR/'source-manifest.json'] = {'fixture.py': 'a'*64}
        self.values[M.PRIOR/'store-claim-withdrawn-intent.json'] = {
            'method': 'GET', 'maximum_attempts': 1, 'reader_only': True,
            'url': 'https://s3.fr-par.scw.cloud/dev-resources-mcp/production/store.json',
            'version': 1, 'boundary_mode': 'withdrawn', 'created_at': 'retained', 'source_sha256': 'b'*64}
        self.values[M.PRIOR/'source-store-claim-qualified.json'] = {'status': 200, 'key': 'production/store.json'}
        self.values[M.PRIOR/'target/deployment-result.json'] = {
            'fallback_deployed': False, 'known_complete': False, 'outcome': 'target_failed_restored_withdrawn',
            'runtime': 'restored', 'schema18_restored': True, 'target_deployed': False, 'withdrawal_completed': True}
        self.values[M.PRIOR_BUNDLE/'restore/restored.json'] = {
            'verified': True, 'database_restored': True, 'schema': 18, 'baseline_caches_restored': True,
            's3_rewound': False, 'fallback_accepted': False, 'preservation': 'manifest_verified',
            'preserved_directory': True, 'application_roles_stopped': True}
        self.root = M.PRIOR/'target/command-evidence'
        self.bodies = {}
        self.rows = []
        for label in M.STAGES:
            failed = label == 'deploy-migration-before-npm'
            result = {'version': 1, 'stage': label, 'runtime': 'target', 'final_outcome': True,
                      'supervision': {'code': 'child_failed' if failed else 'ok', 'exit_code': int(failed),
                        'child_cleanup_complete': True, 'persisted': True, 'runtime_evidence_complete': True,
                        'timed_out': False, 'interrupted': False, 'truncated': False, 'descendant_pipes': False,
                        'withdrawal_completed': failed}}
            for name in M.STAGE_FILES:
                path = self.root/label/name
                body = encode(result) if name == 'final-result.json' else b'' if name == 'stderr.log' else b'fixture'
                self.bodies[path] = body
                self.rows.append({'path': str(path.relative_to(self.root)), 'sha256': hashlib.sha256(body).hexdigest(),
                                  'bytes': len(body), 'uid': 0, 'gid': 0, 'mode': 0o600, 'links': 1})
        self.absences = []
        self.calls = []
        self.records = {}
        self.h = SimpleNamespace(decode=json.loads, encode=encode)
        self.inputs = SimpleNamespace(json=self.read_json, directory=lambda _: M.STAGES,
                                      files=lambda _: M.STAGE_FILES, read=self.read,
                                      records=self.records, absent=self.absences.append)
        self.prior = {'prior_cycle_ledgers': [{'cycle': str(n)} for n in range(3)]}

    def read_json(self, path, wanted=None, **kwargs):
        self.calls.append((path, wanted))
        return copy.deepcopy(self.values[path])

    def read(self, path, **kwargs):
        body = self.bodies[path]
        self.records[path] = ((1, 1, 0o100600, 0, 0, 1, len(body), 0, 0), hashlib.sha256(body).hexdigest())
        return body

    def run_ledger(self):
        with patch.object(M, 'STAGE_INVENTORY_SHA', hashlib.sha256(encode(self.rows)).hexdigest()):
            return M.prior_cycle(self.h, self.inputs, self.prior)

    def test_retained_three_stage_failure_appends_fourth_ledger_and_requires_no_public_stages(self):
        _, ledger = self.run_ledger()
        self.assertEqual(ledger[:3], self.prior['prior_cycle_ledgers'])
        self.assertEqual(ledger[3]['s3_store_get_spent'], 1)
        self.assertEqual(ledger[3]['source_provider_requests_spent'], 0)
        self.assertEqual(ledger[3]['public_probe_stages_started'], 0)
        self.assertEqual(len(self.absences), 8)
        self.assertIn((M.PRIOR_BUNDLE/'restore/restored.json', M.RESTORED_SHA), self.calls)
        self.assertIn((M.PRIOR/'target/deployment-result.json', M.PRIOR_RESULT_SHA), self.calls)
        for name, wanted in M.PINS.items():
            self.assertIn((M.PRIOR/name, wanted), self.calls)

    def test_incomplete_restore_rewind_or_accepted_fallback_refused_before_ledger(self):
        for key, value in (('schema', 19), ('verified', False), ('baseline_caches_restored', False),
                           ('s3_rewound', True), ('fallback_accepted', True), ('preserved_directory', False),
                           ('application_roles_stopped', False), ('preservation', 'unchecked')):
            with self.subTest(key=key):
                saved = copy.deepcopy(self.values[M.PRIOR_BUNDLE/'restore/restored.json'])
                self.values[M.PRIOR_BUNDLE/'restore/restored.json'][key] = value
                with self.assertRaisesRegex(RuntimeError, 'prior_restoration_required'):
                    self.run_ledger()
                self.values[M.PRIOR_BUNDLE/'restore/restored.json'] = saved

    def test_extra_public_stage_refused(self):
        self.inputs.directory = lambda _: M.STAGES+['public']
        with self.assertRaisesRegex(RuntimeError, 'prior_public_or_extra_stage_present'):
            self.run_ledger()

    def test_changed_retained_log_refused_even_with_unchanged_stage_status(self):
        self.bodies[self.root/'deploy-apply/stdout.log'] = b'changed'
        with self.assertRaisesRegex(RuntimeError, 'prior_stage_inventory_changed'):
            self.run_ledger()

    def test_timeout_or_incomplete_stage_evidence_refused(self):
        path = self.root/'deploy-migration-before-npm/final-result.json'
        for key, value in (('timed_out', True), ('runtime_evidence_complete', False), ('exit_code', 0)):
            saved = self.bodies[path]
            result = json.loads(saved)
            result['supervision'][key] = value
            self.bodies[path] = encode(result)
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'prior_stage_result_changed'):
                self.run_ledger()
            self.bodies[path] = saved


if __name__ == '__main__':
    unittest.main()
