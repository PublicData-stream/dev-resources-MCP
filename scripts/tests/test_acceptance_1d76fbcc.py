"""Offline runtime binding, source admission and real bounded child supervision."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
SOURCES = REPO / 'deploy/production/acceptance_1d76fbcc'
sys.path.insert(0, str(SOURCES))
try:
    import acceptance_common as common
    def module(name):
        spec = importlib.util.spec_from_file_location('acceptance_1d76_' + name.replace('-', '_'), SOURCES / (name + '.py'))
        value = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = value
        spec.loader.exec_module(value)
        return value
    operational = module('operational-proof')
    observation = module('observation-loop')
    receipts = module('acceptance-receipt')
    public = module('public-matrix')
    runner = module('runner')
    driver = module('phase-driver')
    store_claim = module('store-claim')
    deployment = module('deploy')
finally:
    sys.path.pop(0)


class PrivateFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='acceptance-1d76-', dir='/tmp')
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        for name in ('process-launch.py','process-watch.py','sitecustomize.py','acceptance_common.py'):
            body=(SOURCES/name).read_text()
            if name=='acceptance_common.py':
                body=body.replace("ROOT = Path('/tmp/devres-upgrade-1d76fbcc-20261115')",'ROOT = Path('+repr(str(self.root))+')')
            (self.root/name).write_text(body)
            (self.root/name).chmod(0o600)
        self.work = self.root / 'target'
        self.work.mkdir(mode=0o700)
        self.patches = [patch.object(common, 'ROOT', self.root), patch.object(common, 'WORK', self.work),
                        patch.object(common, 'MANIFEST', self.root / 'source-manifest.json')]
        for value in self.patches:
            value.start()

    def tearDown(self):
        for value in reversed(self.patches):
            value.stop()
        self.tmp.cleanup()

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode())
        path.chmod(0o600)
        return path


class SourceAdmission(PrivateFixture):
    def manifest(self):
        special = {name: self.root / ('special-' + name) for name in common.SPECIAL_NAMES}
        self.patch_special = patch.object(common, 'SPECIAL_NAMES', special)
        self.patch_special.start()
        self.addCleanup(self.patch_special.stop)
        values = {}
        for name in common.SOURCE_NAMES | set(special):
            path = special[name] if name in special else self.root / name
            body = (REPO / 'scripts/mcp_smoke.py').read_bytes() if name == 'mcp_smoke.py' else name.encode()
            self.write(path, body)
            values[name] = hashlib.sha256(body).hexdigest()
        path = self.write(common.MANIFEST, values)
        return values, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_accepts_exact_complete_source_set(self):
        values, digest = self.manifest()
        self.assertEqual(common.manifest_sources(digest), values)

    def test_external_hash_is_mandatory(self):
        self.manifest()
        with self.assertRaisesRegex(RuntimeError, 'external_source_manifest_hash'):
            common.manifest_sources('0' * 64)

    def test_rejects_source_changed_after_manifest(self):
        _, digest = self.manifest()
        self.write(self.root / 'public-matrix.py', b'changed')
        with self.assertRaisesRegex(RuntimeError, 'acceptance_source_changed'):
            common.manifest_sources(digest)

    def test_rejects_unknown_source_and_missing_required_source(self):
        values, _ = self.manifest()
        for bad in ({**values, '../escape.py': 'a' * 64}, {k: v for k, v in values.items() if k != 'runner.py'}):
            self.write(common.MANIFEST, bad)
            with self.assertRaisesRegex(RuntimeError, 'fixed_source_set_required'):
                common.manifest_sources(hashlib.sha256(common.MANIFEST.read_bytes()).hexdigest())

    def test_duplicate_manifest_key_is_rejected(self):
        self.write(common.MANIFEST, b'{"runner.py":"a","runner.py":"b"}')
        with self.assertRaisesRegex(RuntimeError, 'duplicate_source_name'):
            common.manifest_sources(hashlib.sha256(common.MANIFEST.read_bytes()).hexdigest())

    def test_symlink_source_is_rejected(self):
        _, digest = self.manifest()
        path = self.root / 'runner.py'
        path.unlink()
        path.symlink_to(self.root / 'public-matrix.py')
        with self.assertRaisesRegex(RuntimeError, 'private_path_required'):
            common.manifest_sources(digest)

    def test_world_readable_source_is_rejected(self):
        _, digest = self.manifest()
        (self.root / 'runner.py').chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, 'bounded_private_file_required'):
            common.manifest_sources(digest)

    def test_native_qualifier_is_bound_to_exact_runtime(self):
        path = self.root / 'target-native-qualification.json'
        value = {'commit': common.REVISION, 'architecture': 'amd64', 'anonymous_full_pull': True,
                 'binary_sha256': 'a' * 64}
        self.write(path, value)
        self.assertEqual(common.runtime_qualification(), value)
        self.write(path, {**value, 'commit': common.RUNTIMES['fallback']['revision']})
        with self.assertRaisesRegex(RuntimeError, 'native_probe_qualification'):
            common.runtime_qualification()


class RuntimeProofs(PrivateFixture):
    def identity(self):
        generation = {'id': operational.GENERATION, 'data': {'policy_epoch': 1, 'notices': [{}]},
                      'data_integrity': 'blake3:' + 'a' * 64}
        identity = {'schema': 19, 'recovery': False, 'system_id': 'system', 'archive': {'binding': 'binding'},
            'control': {'format_version': 1, 'required_policy_epoch': 2, 'required_policy_fingerprint': operational.POLICY2},
            'npm_recovery_tables': 3, 'new_tables': 2, 'new_columns': 2, 'recovery_trigger': 1,
            'reader_select_gaps': 0, 'reader_mutation_tables': 0, 'reader_default_readonly': True,
            'owners': [{'role': 'devres_writer', 'client_addr': '10.0.0.2'}], 'pinned_generation': generation}
        baseline = {'database': {'system_id': 'system', 'archive': {'binding': 'binding'}},
                    'generation_sha256': operational.generation_hash(generation)}
        state = {'pods': {'writer': {'pod_ip': '10.0.0.2'}}}
        return identity, baseline, state

    def test_schema19_requires_all_three_recovery_tables(self):
        identity, baseline, state = self.identity()
        operational.validate_identity(identity, baseline, state)
        identity['npm_recovery_tables'] = 2
        with self.assertRaisesRegex(operational.Stop, 'runtime_npm_recovery_tables_required'):
            operational.validate_identity(identity, baseline, state)

    def test_target_rejects_schema18_despite_other_valid_fields(self):
        identity, baseline, state = self.identity()
        identity['schema'] = 18
        with self.assertRaisesRegex(operational.Stop, 'runtime_schema_primary_required'):
            operational.validate_identity(identity, baseline, state)

    def test_fallback_schema18_rejects_new_schema19_tables(self):
        identity, baseline, state = self.identity()
        identity['schema'] = 18
        with patch.object(common, 'SCHEMA', 18):
            with self.assertRaisesRegex(operational.Stop, 'runtime_npm_recovery_tables_required'):
                operational.validate_identity(identity, baseline, state)
            identity['npm_recovery_tables'] = 0
            operational.validate_identity(identity, baseline, state)

    def test_owner_and_reader_authority_are_actual_conditions(self):
        identity, baseline, state = self.identity()
        for field, value, code in [('reader_select_gaps', 1, 'actual_reader_authority_changed'),
                                    ('reader_mutation_tables', 1, 'actual_reader_authority_changed'),
                                    ('owners', [], 'sole_writer_owner_required')]:
            changed = {**identity, field: value}
            with self.assertRaisesRegex(operational.Stop, code):
                operational.validate_identity(changed, baseline, state)

    def sample(self):
        identity, _, _ = self.identity()
        identity.update(capture_count=20, archive_files=30)
        flags = {role: {p: True for p in observation.PROVIDERS} for role in ('backend', 'writer')}
        flags['backend']['npm'] = False
        self.write(self.root / 'operational-baseline.json', {'collectors': flags})
        return {'version': 1, 'revision': common.REVISION, 'runtime': 'target',
            'runtime_revision': common.REVISION, 'phase': 'collectors_active', 'configs_variant': 'active',
            'guard_passed': True, 'prepared_sha256': 'prepared',
            'pods': {role: {'container_id': role, 'started_at': 'now', 'pod_ip': '10.0.0.2'} for role in ('backend', 'writer', 'postgres')},
            'database': identity, 'collectors': flags,
            'source_urls': {role: common.SOURCE_URL for role in ('backend', 'writer')},
            'free_bytes': observation.RESERVE, 'free_inodes': 1,
            'timers': {'devres-capacity.timer': 'active', 'devres-cert-renew.timer': 'active'},
            'monotonic': 100, 'edge': {}, 'profiles': {}, 'boot': {}, 'authority_sha256': 'auth'}

    def test_observation_preserves_original_flags_including_false(self):
        sample = self.sample()
        observation.validate(sample)
        sample['collectors']['backend']['npm'] = True
        with self.assertRaisesRegex(observation.Stop, 'original_source_settings_required'):
            observation.validate(sample)

    def test_observation_rejects_cross_runtime_receipt(self):
        sample = self.sample()
        sample['runtime'] = 'fallback'
        with self.assertRaisesRegex(observation.Stop, 'active_guarded_sample_required'):
            observation.validate(sample)

    def test_observation_gap_and_history_regression_fail(self):
        previous = self.sample()
        current = copy.deepcopy(previous)
        current['monotonic'] += 46
        with self.assertRaisesRegex(observation.Stop, 'maximum_sample_gap'):
            observation.validate(current, previous=previous)
        current['monotonic'] = 130
        current['database']['capture_count'] -= 1
        with self.assertRaisesRegex(observation.Stop, 'permanent_history_count_regressed'):
            observation.validate(current, previous=previous)

    def test_paused_and_active_command_sequences_keep_late_checks(self):
        sources = {name: 'a' * 64 for name in common.SOURCE_NAMES | set(common.SPECIAL_NAMES)}
        active = runner.commands('active', sources)
        names = [name for name, _, _ in active]
        self.assertLess(names.index('observation'), names.index('late-public'))
        self.assertLess(names.index('late-codecs'), names.index('final-receipt'))
        self.assertEqual(active[names.index('observation')][2], 1100)
        self.assertEqual(active[names.index('early-public')][1][-1], 'full')
        self.assertEqual(active[names.index('late-public')][1][-1], 'bounded')
        paused = runner.commands('paused', sources)
        self.assertEqual(paused[-1][0], 'activate-existing')
        self.assertTrue(all(str(common.ROOT) in cmd[2] for _, cmd, _ in paused))

    def test_receipts_resolve_to_distinct_runtime_output_directory(self):
        self.assertEqual(driver.receipt_path('start-reader'), self.work / 'operational-proofs/migration/migration-receipt.json')
        self.assertEqual(driver.receipt_path('finish'), self.work / 'observation-receipt.json')
        with patch.object(common, 'WORK', self.root / 'fallback'):
            self.assertEqual(driver.receipt_path('finish'), self.root / 'fallback/observation-receipt.json')


class RealSupervision(PrivateFixture):
    @staticmethod
    def collect(recorder, stop):
        recorder.record('pod', {'role': 'postgres', 'ready': True, 'restarts': 0})
        while not stop.wait(0.02):
            pass

    def setup_diagnostic_class(self):
        name = 'acceptance_fixture_diagnostics'
        directory = REPO / 'deploy/diagnostics'
        spec = importlib.util.spec_from_file_location(name, directory / '__init__.py', submodule_search_locations=[str(directory)])
        package = importlib.util.module_from_spec(spec)
        sys.modules[name] = package
        spec.loader.exec_module(package)
        spec = importlib.util.spec_from_file_location(name + '.runner', directory / 'runner.py')
        value = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = value
        spec.loader.exec_module(value)
        (self.work / 'command-evidence').mkdir(mode=0o700)
        return value.DiagnosticRunner

    def stage(self, label, code, timeout=5):
        diagnostic = self.setup_diagnostic_class()
        fence_path = self.root / 'fence'
        def fence():
            fence_path.write_text('withdrawn')
            return True
        with patch.object(common, 'manifest_sources', return_value={}), \
             patch.object(runner, 'diagnostic_runner', return_value=diagnostic), \
             contextlib.redirect_stdout(io.StringIO()):
            value = runner.run_stage(label, [sys.executable, '-B', '-c', code], timeout, self.collect, fence)
        return value, fence_path

    def test_real_success_has_final_returned_outcome_and_no_fence(self):
        value, fence = self.stage('success', 'print("fixed successful observation")')
        self.assertTrue(value['final_outcome'])
        self.assertEqual(value['supervision']['code'], 'ok')
        self.assertFalse(fence.exists())
        directory = self.work / 'command-evidence/success'
        self.assertFalse(json.loads((directory / 'outcome.json').read_bytes())['final_outcome'])
        self.assertTrue(json.loads((directory / 'final-result.json').read_bytes())['final_outcome'])

    def test_real_failure_invokes_fence_before_reporting_failure(self):
        with self.assertRaisesRegex(RuntimeError, 'acceptance_stage_failed'):
            self.stage('failed', 'import sys;print("fixed failure",file=sys.stderr);sys.exit(7)')
        self.assertEqual((self.root / 'fence').read_text(), 'withdrawn')
        result = json.loads((self.work / 'command-evidence/failed/final-result.json').read_bytes())
        self.assertEqual(result['supervision']['exit_code'], 7)
        self.assertTrue(result['supervision']['withdrawal_completed'])

    def test_real_timeout_invokes_fence_and_keeps_private_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'acceptance_stage_failed'):
            self.stage('timeout', 'import time;time.sleep(10)', 0.1)
        directory = self.work / 'command-evidence/timeout'
        result = json.loads((directory / 'final-result.json').read_bytes())
        self.assertTrue(result['supervision']['timed_out'])
        self.assertTrue((self.root / 'fence').exists())
        self.assertEqual((directory / 'stdout.log').stat().st_mode & 0o777, 0o600)

    def test_stage_directory_excludes_repeat_before_starting_child(self):
        diagnostic = self.setup_diagnostic_class()
        directory = self.work / 'command-evidence/repeat'
        directory.mkdir(mode=0o700)
        with patch.object(common, 'manifest_sources', return_value={}), \
             patch.object(runner, 'diagnostic_runner', return_value=diagnostic) as factory:
            with self.assertRaises(FileExistsError):
                runner.run_stage('repeat', [sys.executable, '-B', '-c', 'print("must not run")'], 5)
            factory.assert_not_called()

    def test_target_failure_prepares_fallback_once_after_withdrawal(self):
        controller = Mock()
        controller.state.return_value = {'runtime': 'fallback', 'phase': 'applied'}
        with patch.object(runner, 'withdraw', return_value=True) as withdraw, \
             patch.object(common, 'controller', return_value=(None, controller)):
            value = runner.recover_failure()
        withdraw.assert_called_once()
        controller.rollback.assert_called_once()
        self.assertTrue(value['fallback_prepared'])

    def test_fallback_failure_never_attempts_another_restore(self):
        with patch.object(common, 'RUNTIME', 'fallback'), \
             patch.object(runner, 'withdraw', return_value=True), \
             patch.object(common, 'controller') as controller:
            value = runner.recover_failure()
        controller.assert_not_called()
        self.assertFalse(value['fallback_prepared'])

    def test_failed_withdrawal_never_attempts_restore(self):
        with patch.object(runner, 'withdraw', return_value=False), \
             patch.object(common, 'controller') as controller:
            value = runner.recover_failure()
        controller.assert_not_called()
        self.assertFalse(value['withdrawal_completed'])


class DeploymentControl(PrivateFixture):
    def controller(self, runtime='target'):
        state = {'runtime': runtime, 'phase': 'stopped' if runtime == 'target' else 'applied',
                 'pods': {'postgres': {}}}
        controller = Mock()
        controller.locked.side_effect = contextlib.nullcontext
        controller.state.side_effect = lambda: dict(state)
        def withdraw():
            state['phase'] = 'withdrawn'
        def rollback():
            if state['phase'] != 'withdrawn':
                raise AssertionError('restore before withdrawal')
            state.update(runtime='fallback', phase='applied')
        controller.withdraw.side_effect = withdraw
        controller.rollback.side_effect = rollback
        return controller, state

    def sources(self):
        return {name: 'a' * 64 for name in common.SOURCE_NAMES | set(common.SPECIAL_NAMES)}

    def supervisor(self, state, fail=None, fallback_fails=False, already_restored=False):
        events = []
        def stage(label, command, timeout, **kwargs):
            events.append(label)
            if label == 'deploy-fallback':
                if fallback_fails:
                    raise RuntimeError('fallback late control failed')
                state.update(runtime='fallback', phase='complete')
                return
            if label == fail:
                if already_restored:
                    state.update(runtime='fallback', phase='applied')
                raise RuntimeError('mandatory control failed')
            transitions = {'deploy-apply': 'applied', 'deploy-start-writer': 'writer_ready',
                'deploy-start-reader': 'reader_ready', 'deploy-paused-acceptance': 'collectors_active',
                'deploy-active-acceptance': 'complete'}
            if label in transitions:
                state['phase'] = transitions[label]
        return types.SimpleNamespace(run_stage=Mock(side_effect=stage)), events

    def complete(self, runtime, controller, supervisor):
        def fallback(c, wrapped, command, timeout=7200):
            self.assertIs(c, controller)
            self.assertEqual(timeout, 7200)
            return wrapped.run_stage('deploy-fallback', command, timeout)
        with patch.dict(os.environ, {'DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256': 'b' * 64}), \
             patch.object(deployment, 'supervise_fallback', side_effect=fallback):
            return deployment.complete(runtime, self.sources(), controller, supervisor, 'b' * 64)

    def test_target_success_never_restores_or_starts_fallback(self):
        controller, state = self.controller()
        supervisor, events = self.supervisor(state)
        result = self.complete('target', controller, supervisor)
        self.assertTrue(result['target_deployed'])
        self.assertFalse(result['fallback_deployed'])
        controller.rollback.assert_not_called()
        self.assertNotIn('deploy-fallback', events)
        self.assertLess(events.index('deploy-npm-recovery'), events.index('deploy-migration'))
        self.assertLess(events.index('deploy-migration'), events.index('deploy-start-reader'))

    def test_target_migration_failure_restores_once_then_revalidates_fallback(self):
        controller, state = self.controller()
        supervisor, events = self.supervisor(state, fail='deploy-migration')
        result = self.complete('target', controller, supervisor)
        self.assertFalse(result['target_deployed'])
        self.assertTrue(result['fallback_deployed'])
        self.assertFalse(result['known_complete'])
        self.assertEqual(result['outcome'], 'target_failed_fallback_accepted')
        controller.withdraw.assert_called_once()
        controller.rollback.assert_called_once()
        self.assertEqual(events.count('deploy-fallback'), 1)
        self.assertNotIn('deploy-start-reader', events)

    def test_uncertain_npm_failure_does_not_rearm_or_continue_target(self):
        controller, state = self.controller()
        supervisor, events = self.supervisor(state, fail='deploy-npm-recovery')
        result = self.complete('target', controller, supervisor)
        self.assertTrue(result['fallback_deployed'])
        self.assertEqual(events.count('deploy-npm-recovery'), 1)
        self.assertNotIn('deploy-start-reader', events)
        controller.rollback.assert_called_once()

    def test_already_prepared_fallback_is_not_restored_again(self):
        controller, state = self.controller()
        supervisor, events = self.supervisor(state, fail='deploy-active-acceptance', already_restored=True)
        result = self.complete('target', controller, supervisor)
        self.assertTrue(result['fallback_deployed'])
        controller.rollback.assert_not_called()
        controller.withdraw.assert_not_called()
        self.assertEqual(events.count('deploy-fallback'), 1)

    def test_restore_failure_is_terminal_without_fallback_start(self):
        controller, state = self.controller()
        controller.rollback.side_effect = RuntimeError('checkpoint verification failed')
        supervisor, events = self.supervisor(state, fail='deploy-migration')
        result = self.complete('target', controller, supervisor)
        self.assertEqual(result['outcome'], 'restore_incomplete')
        self.assertNotIn('deploy-fallback', events)
        controller.rollback.assert_called_once()

    def test_fallback_final_failure_withdraws_without_second_restore(self):
        controller, state = self.controller('fallback')
        supervisor, events = self.supervisor(state, fail='deploy-active-acceptance')
        result = self.complete('fallback', controller, supervisor)
        self.assertEqual(result['outcome'], 'fallback_failed')
        self.assertTrue(result['withdrawal_completed'])
        controller.withdraw.assert_called_once()
        controller.rollback.assert_not_called()
        self.assertNotIn('deploy-apply', events)
        self.assertNotIn('deploy-npm-recovery', events)

    def test_fallback_child_failure_is_fenced_without_second_restore(self):
        controller, state = self.controller()
        supervisor, events = self.supervisor(state, fail='deploy-active-acceptance', fallback_fails=True)
        result = self.complete('target', controller, supervisor)
        self.assertEqual(result['outcome'], 'fallback_failed')
        self.assertTrue(result['withdrawal_completed'])
        controller.rollback.assert_called_once()
        self.assertEqual(events.count('deploy-fallback'), 1)

    def test_nested_runner_defers_restore_to_outer_deployment(self):
        with patch.dict(os.environ, {'DEVRES_ACCEPTANCE_DEFER_ROLLBACK': '1'}), \
             patch.object(runner, 'withdraw', return_value=True), \
             patch.object(common, 'controller') as controller:
            result = runner.recover_failure()
        self.assertTrue(result['withdrawal_completed'])
        self.assertFalse(result['fallback_prepared'])
        controller.assert_not_called()

    def test_npm_hook_runs_outside_phase_driver_lock(self):
        held = [False]
        @contextlib.contextmanager
        def locked():
            self.assertFalse(held[0])
            held[0] = True
            try:
                yield
            finally:
                held[0] = False
        controller = Mock()
        controller.locked.side_effect = locked
        controller.state.return_value = {'runtime': 'target', 'phase': 'writer_ready', 'prepared_sha256': 'prepared'}
        def npm():
            self.assertFalse(held[0])
            return {'eligible': False, 'deferred': True}
        controller.npm_recovery.side_effect = npm
        module = types.SimpleNamespace(save=Mock())
        with patch.object(common, 'controller', return_value=(module, controller)):
            value = driver.dispatch('npm-recovery')
        self.assertTrue(value['known_complete'])
        controller.npm_recovery.assert_called_once()

    def test_unexpected_positive_npm_admission_fails_closed(self):
        controller = Mock()
        controller.locked.side_effect = contextlib.nullcontext
        controller.state.return_value = {'runtime': 'target', 'phase': 'writer_ready', 'prepared_sha256': 'prepared'}
        controller.npm_recovery.return_value = {'eligible': True, 'deferred': False}
        module = types.SimpleNamespace(save=Mock())
        with patch.object(common, 'controller', return_value=(module, controller)), \
             self.assertRaisesRegex(RuntimeError, 'exact_npm_recovery_admission_unavailable'):
            driver.dispatch('npm-recovery')


class FallbackAndNativeBoundaries(PrivateFixture):
    def test_runtime_collector_does_not_apply_target_controller_identity_to_fallback(self):
        pods = {'items': [{'metadata': {'labels': {'app': 'postgres'}},
                          'status': {'containerStatuses': [{'ready': True, 'restartCount': 0}]}}]}
        recorder, stop = Mock(), Mock()
        stop.wait.return_value = True
        with patch.object(common, 'RUNTIME', 'target'), \
             patch.object(common, 'controller', side_effect=AssertionError('target identity would reject fallback')) as controller, \
             patch.object(runner.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout=json.dumps(pods).encode(), stderr=b'')):
            runner.collect_runtime(recorder, stop)
        controller.assert_not_called()
        recorder.record.assert_called_once_with('pod', {'role': 'postgres', 'ready': True, 'restarts': 0})

    def fallback(self, code, state, timeout=3):
        controller = Mock()
        controller.locked.side_effect = contextlib.nullcontext
        controller.state.side_effect = lambda: dict(state)
        def withdraw():
            state['phase'] = 'withdrawn'
        controller.withdraw.side_effect = withdraw
        supervisor = types.SimpleNamespace(private_save=runner.private_save,parent_bound_command=runner.parent_bound_command)
        (self.work/'command-evidence').mkdir(mode=0o700)
        with patch.object(common, 'manifest_sources', return_value={}):
            result = deployment.supervise_fallback(controller, supervisor,
                [sys.executable, '-B', '-c', code], timeout=timeout)
        return result, controller

    def test_real_fallback_child_accepts_complete_without_target_runtime_getter(self):
        state = {'runtime': 'fallback', 'phase': 'complete', 'pods': {'postgres': {}}}
        result, controller = self.fallback('print("finite fallback accepted")', state)
        self.assertTrue(result)
        controller.withdraw.assert_not_called()
        record = json.loads((self.work/'command-evidence/deploy-fallback/result.json').read_bytes())
        self.assertTrue(record['success'])

    def test_real_fallback_timeout_fences_before_result(self):
        state = {'runtime': 'fallback', 'phase': 'collectors_active', 'pods': {'postgres': {}}}
        with self.assertRaisesRegex(RuntimeError, 'fallback_deployment_failed'):
            self.fallback('import time;time.sleep(10)', state, timeout=0.1)
        self.assertEqual(state['phase'], 'withdrawn')
        record = json.loads((self.work/'command-evidence/deploy-fallback/result.json').read_bytes())
        self.assertTrue(record['withdrawal_completed'])
        self.assertFalse(record['success'])

    def probe(self):
        path=self.root/'public-probe'/'devres-probe'
        path.parent.mkdir(mode=0o755)
        path.write_bytes(b'fixed first-party native probe bytes')
        path.chmod(0o555)
        return path,hashlib.sha256(path.read_bytes()).hexdigest()

    def test_native_probe_hash_and_inode_are_rechecked(self):
        path,digest=self.probe()
        original=public.checked_probe(path,digest)
        self.assertEqual(public.checked_probe(path,digest,original),original)
        replacement=path.with_name('replacement')
        replacement.write_bytes(path.read_bytes());replacement.chmod(0o555)
        path.unlink();replacement.rename(path)
        with self.assertRaisesRegex(RuntimeError,'native_probe_changed'):
            public.checked_probe(path,digest,original)

    def test_native_probe_rejects_writable_directory_and_symlink(self):
        path,digest=self.probe()
        path.parent.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError,'native_probe_directory'):
            public.checked_probe(path,digest)
        path.parent.chmod(0o755)
        other=path.with_name('other');other.write_bytes(path.read_bytes());other.chmod(0o555)
        path.unlink();path.symlink_to(other)
        with self.assertRaisesRegex(RuntimeError,'native_probe_path'):
            public.checked_probe(path,digest)

    def test_native_probe_rejects_non_executable_file(self):
        path,digest=self.probe();path.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError,'native_probe_metadata'):
            public.checked_probe(path,digest)


class RestoreRehearsalGate(PrivateFixture):
    def setUp(self):
        super().setUp()
        self.bundle = self.root/'bundle'
        self.bundle.mkdir(mode=0o700)
        value = patch.object(common, 'BUNDLE', self.bundle)
        value.start(); self.patches.append(value)

    def admission(self):
        sources = {name:'a'*64 for name in common.SOURCE_NAMES | set(common.SPECIAL_NAMES)}
        checkpoint = self.root/'checkpoint-state'
        checkpoint.mkdir(mode=0o700)
        state={'runtime':'target','phase':'stopped','prepared_sha256':'prepared', 'pods':{'postgres':{}}}
        for name,body in [('state.json',state),('prepared.json',{'original':'prepared'}),('plan.json',{'original':'plan'})]:
            self.write(self.bundle/name,body)
        manifest_files={'pg_files_sha256':'pg-file-manifest.jsonl','capture_manifest_sha256':'capture-bindings.jsonl',
            'manifest_sha256':'archive-bindings.jsonl','cache_baselines_sha256':'cache-baselines.json'}
        completed={}
        for key,name in manifest_files.items():
            path=self.write(checkpoint/name,('exact '+name).encode())
            completed[key]=deployment.private_hash(path)
        self.write(checkpoint/'completed.json',completed)
        self.write(checkpoint/'checkpoint-completed.json',{'original':'physical checkpoint'})
        production_paths={self.bundle/name for name in ('state.json','prepared.json','plan.json')}
        production_paths|={checkpoint/name for name in ('completed.json','checkpoint-completed.json')}
        files={str(path):deployment.private_hash(path) for path in production_paths}
        fingerprint=common.sha(json.dumps(files,sort_keys=True,separators=(',',':')).encode())
        receipt={'version':1,'kind':'isolated-real-pg-restore-rehearsal','verified':True,'revision':common.REVISION,
            'prepared_sha256':'prepared','observed_at':deployment.dt.datetime.now(deployment.dt.timezone.utc).isoformat(),
            'sources':{name:sources[name] for name in ('restore-rehearsal.py','restore-controller.py','physical-checkpoint.py')},
            'golden':completed,'production_state_scope':'admission_and_checkpoint_files','production_files':files,
            'production_before_sha256':fingerprint,'production_after_sha256':fingerprint,
            'checks':{key:True for key in ('isolated_real_pg_restore','restore_state_machine','full_baseline_caches','production_untouched')}}
        self.path=self.write(self.root/'restore-rehearsal-receipt.json',receipt)
        backup={'new_pg_pod':{'uid':'new-postgres','container_id':'new-process'},
            'artifacts':[{'path':str(self.path),'sha256':deployment.private_hash(self.path)}]}
        self.write(checkpoint/'backup-receipt-after-rehearsal.json',backup)
        controller=Mock();controller.locked.side_effect=contextlib.nullcontext
        controller.state.return_value=state
        controller.receipt.return_value=(backup,b'checked fresh physical checkpoint receipt')
        return sources,receipt,controller

    def test_valid_rehearsal_requires_fresh_backup_and_live_new_pg_bookend(self):
        sources,receipt,controller=self.admission()
        self.assertEqual(deployment.verify_restore_rehearsal(controller,sources),receipt)
        args=controller.receipt.call_args.args
        self.assertTrue(args[0].endswith('backup-receipt-after-rehearsal.json'))
        self.assertEqual(args[2],'coordinated-schema18-backup')
        controller.guard.assert_called_once_with(pg_rebind={'uid':'new-postgres','container_id':'new-process'})
        controller.run.assert_not_called();controller.rollback.assert_not_called()

    def test_stale_rehearsal_cannot_authorize_target(self):
        sources,receipt,controller=self.admission()
        receipt['observed_at']=(deployment.dt.datetime.now(deployment.dt.timezone.utc)-deployment.dt.timedelta(seconds=301)).isoformat()
        self.write(self.path,receipt)
        with self.assertRaisesRegex(RuntimeError,'restore_rehearsal_stale'):
            deployment.verify_restore_rehearsal(controller,sources)
        controller.receipt.assert_not_called();controller.rollback.assert_not_called()

    def test_wrong_helper_or_restore_source_is_rejected(self):
        sources,receipt,controller=self.admission()
        receipt['sources']['restore-controller.py']='b'*64;self.write(self.path,receipt)
        with self.assertRaisesRegex(RuntimeError,'restore_rehearsal_sources_changed'):
            deployment.verify_restore_rehearsal(controller,sources)
        controller.receipt.assert_not_called()

    def test_wrong_prepared_identity_is_rejected(self):
        sources,receipt,controller=self.admission()
        receipt['prepared_sha256']='another-preparation';self.write(self.path,receipt)
        with self.assertRaisesRegex(RuntimeError,'restore_rehearsal_identity'):
            deployment.verify_restore_rehearsal(controller,sources)
        controller.receipt.assert_not_called()

    def test_incomplete_real_restore_or_cache_check_is_rejected(self):
        sources,receipt,controller=self.admission()
        receipt['checks']['full_baseline_caches']=False;self.write(self.path,receipt)
        with self.assertRaisesRegex(RuntimeError,'restore_rehearsal_checks_required'):
            deployment.verify_restore_rehearsal(controller,sources)
        controller.receipt.assert_not_called()

    def test_changed_current_admission_file_is_rejected(self):
        sources,receipt,controller=self.admission()
        self.write(self.bundle/'plan.json',{'changed':'after rehearsal'})
        with self.assertRaisesRegex(RuntimeError,'restore_rehearsal_production_bookend_changed'):
            deployment.verify_restore_rehearsal(controller,sources)
        controller.receipt.assert_not_called()

    def test_changed_gold_manifest_bytes_are_rejected(self):
        sources,receipt,controller=self.admission()
        self.write(self.root/'checkpoint-state/archive-bindings.jsonl',b'changed retained bindings')
        with self.assertRaisesRegex(RuntimeError,'restore_rehearsal_manifest_changed'):
            deployment.verify_restore_rehearsal(controller,sources)
        controller.receipt.assert_not_called()

    def test_real_rehearsal_receipt_must_be_bound_in_fresh_backup(self):
        sources,receipt,controller=self.admission()
        controller.receipt.return_value=({'new_pg_pod':{},'artifacts':[]},b'')
        with self.assertRaisesRegex(RuntimeError,'restore_rehearsal_receipt_unbound'):
            deployment.verify_restore_rehearsal(controller,sources)
        controller.guard.assert_not_called()

    def test_old_backup_path_is_never_selected_by_apply_driver(self):
        self.assertEqual(driver.receipt_path('apply'),self.root/'checkpoint-state/backup-receipt-after-rehearsal.json')

    def test_missing_receipt_stops_run_before_apply_intent_or_rollback(self):
        sources,receipt,controller=self.admission();self.path.unlink()
        supervisor=types.SimpleNamespace(private_save=Mock())
        with patch.dict(os.environ,{},clear=False), \
             patch.object(common,'manifest_sources',return_value=sources), \
             patch.object(common,'bound_module',return_value=supervisor), \
             patch.object(common,'controller',return_value=(None,controller)), \
             patch.object(deployment,'complete') as complete, \
             self.assertRaises(FileNotFoundError):
            deployment.run('target','a'*64)
        complete.assert_not_called();supervisor.private_save.assert_not_called()
        controller.run.assert_not_called();controller.rollback.assert_not_called();controller.withdraw.assert_not_called()

    def test_wrong_source_stops_run_before_any_target_mutation(self):
        sources,receipt,controller=self.admission()
        receipt['sources']['restore-rehearsal.py']='b'*64;self.write(self.path,receipt)
        supervisor=types.SimpleNamespace(private_save=Mock())
        with patch.dict(os.environ,{},clear=False), \
             patch.object(common,'manifest_sources',return_value=sources), \
             patch.object(common,'bound_module',return_value=supervisor), \
             patch.object(common,'controller',return_value=(None,controller)), \
             patch.object(deployment,'complete') as complete, \
             self.assertRaisesRegex(RuntimeError,'restore_rehearsal_sources_changed'):
            deployment.run('target','a'*64)
        complete.assert_not_called();supervisor.private_save.assert_not_called()
        controller.run.assert_not_called();controller.rollback.assert_not_called();controller.withdraw.assert_not_called()


class DescendantLifetime(PrivateFixture):
    def wait_file(self,path,process):
        import time
        deadline=time.monotonic()+8
        while not path.exists():
            if process.poll() is not None:
                self.fail('first-party fixture exited before readiness')
            self.assertLess(time.monotonic(),deadline,'first-party fixture readiness deadline')
            time.sleep(0.01)

    def released(self,path):
        import fcntl,time
        started=time.monotonic()
        with path.open('a') as stream:
            while True:
                try:
                    fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    self.assertLess(time.monotonic()-started,3,'orphan still owns lifecycle lock')
                    time.sleep(0.01)
        return time.monotonic()-started

    def cleanup(self,process,*paths):
        import signal
        for path in paths:
            if path.exists():
                try:os.kill(int(path.read_text()),signal.SIGKILL)
                except ProcessLookupError:pass
        if process.poll() is None:process.kill()
        process.wait(timeout=3)

    def test_nested_sets_id_grandchildren_die_and_release_lock_after_outer_cancel(self):
        import signal,subprocess,time
        lock=self.root/'lifecycle.lock';ready=self.root/'grandchild.pid';middle_pid=self.root/'middle.pid'
        inner='import fcntl,os,time;from pathlib import Path;f=open('+repr(str(lock))+',"a");fcntl.flock(f.fileno(),fcntl.LOCK_EX);Path('+repr(str(ready))+').write_text(str(os.getpid()));time.sleep(30)'
        middle='import os,sys,subprocess,time;from pathlib import Path;Path('+repr(str(middle_pid))+').write_text(str(os.getpid()));subprocess.Popen([sys.executable,"-B","-c",'+repr(inner)+'],start_new_session=True);time.sleep(30)'
        outer='import sys,subprocess,time;subprocess.Popen([sys.executable,"-B","-c",'+repr(middle)+'],start_new_session=True);time.sleep(30)'
        process=subprocess.Popen(common.parent_command([sys.executable,'-B','-c',outer]),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            self.wait_file(ready,process)
            os.kill(process.pid,signal.SIGKILL);process.wait(timeout=3)
            self.assertLess(self.released(lock),3)
        finally:self.cleanup(process,ready,middle_pid)

    def test_forked_fence_worker_dies_and_releases_lock_after_runner_cancel(self):
        import signal,subprocess
        lock=self.root/'lifecycle.lock';ready=self.root/'fence.pid'
        body='import os,time,fcntl,multiprocessing;from pathlib import Path;import acceptance_common as c\nparent=os.getpid()\ndef fence():\n with c.parent_lifetime(parent):\n  f=open('+repr(str(lock))+',"a");fcntl.flock(f.fileno(),fcntl.LOCK_EX);Path('+repr(str(ready))+').write_text(str(os.getpid()));time.sleep(30)\np=multiprocessing.get_context("fork").Process(target=fence);p.start();time.sleep(30)'
        process=subprocess.Popen(common.parent_command([sys.executable,'-B','-c',body]),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            self.wait_file(ready,process)
            os.kill(process.pid,signal.SIGKILL);process.wait(timeout=3)
            self.assertLess(self.released(lock),3)
        finally:self.cleanup(process,ready)

    def test_raw_nested_subprocess_refreshes_common_parent_identity(self):
        import subprocess
        inner='import acceptance_common;print("nested-parent-verified")'
        outer='import subprocess,sys;subprocess.run([sys.executable,"-B","-c",'+repr(inner)+'],check=True)'
        result=subprocess.run(common.parent_command([sys.executable,'-B','-c',outer]),capture_output=True,timeout=8)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'nested-parent-verified\n')


    def test_watcher_launch_failure_never_enters_callback(self):
        entered=False
        with patch.object(common.subprocess,'Popen',side_effect=OSError('fixed launch failure')):
            with self.assertRaisesRegex(OSError,'fixed launch failure'):
                with common.parent_lifetime(os.getppid()):
                    entered=True
        self.assertFalse(entered)

    def test_proc_read_failure_never_admits_callback_lock(self):
        import subprocess
        watch=self.root/'process-watch.py'
        watch.write_text(watch.read_text().replace("with open('/proc/'", "with open('/missing-proc/'"))
        entered=self.root/'callback-entered'
        body='import os;from pathlib import Path;import acceptance_common as c\nwith c.parent_lifetime(os.getppid()):\n Path('+repr(str(entered))+').write_text("must-not-enter")'
        result=subprocess.run(common.parent_command([sys.executable,'-B','-c',body]),capture_output=True,timeout=8)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(entered.exists())

    def test_admitted_callback_is_killed_if_ready_watcher_dies(self):
        import subprocess
        watch=self.root/'process-watch.py'
        watch.write_text('import os,time;os.write(1,b"READY\\n");time.sleep(.2);os._exit(1)')
        lock=self.root/'lifecycle.lock';ready=self.root/'callback-entered'
        body='import os,fcntl,time;from pathlib import Path;import acceptance_common as c\nwith c.parent_lifetime(os.getppid()):\n f=open('+repr(str(lock))+',"a");fcntl.flock(f.fileno(),fcntl.LOCK_EX);Path('+repr(str(ready))+').write_text("entered");time.sleep(30)'
        process=subprocess.Popen(common.parent_command([sys.executable,'-B','-c',body]),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            self.wait_file(ready,process)
            self.assertEqual(process.wait(timeout=5),-9)
            self.assertLess(self.released(lock),3)
        finally:self.cleanup(process)


class WithdrawnStoreClaim(PrivateFixture):
    def fixture(self):
        import base64
        producer=self.write(self.root/'store-claim.py',Path(store_claim.__file__).read_bytes())
        source_patch=patch.object(store_claim,'__file__',str(producer));source_patch.start();self.addCleanup(source_patch.stop)
        b64=lambda text:base64.b64encode(text.encode()).decode()
        original=types.SimpleNamespace(bundle_lock=Mock(side_effect=lambda *args:contextlib.nullcontext()))
        binding={'fixed':'separate admitted role keys'}
        self.binding_patch=patch.object(store_claim,'BIND',store_claim.sha(store_claim.encoded(binding)))
        self.binding_patch.start();self.addCleanup(self.binding_patch.stop)
        self.work_patch=patch.object(store_claim,'WORK',self.root)
        self.work_patch.start();self.addCleanup(self.work_patch.stop)
        controller=Mock();controller.root=self.root/'bundle';controller.root.mkdir(mode=0o700)
        controller.module=original;controller.locked.side_effect=contextlib.nullcontext
        controller.old.auth_mode.return_value='scaleway_static'
        controller.old.static_runtime_binding.return_value=binding
        controller.old.k.return_value=store_claim.encoded({'items':[{'metadata':{'labels':{'app':'postgres'}}}]})
        archive={'backend':'s3','binding':store_claim.ARCHIVE_BINDING,'epoch':2,'pending_binding':None,'initializing_s3':False,'store_id':'1'*32}
        database={'schema':18,'owners':0,'system_id':store_claim.SYSTEM_ID,'archive':archive}
        controller.storage_guard.return_value=database
        objects={};archived={};texts={}
        def deployment_projection(value):
            spec=copy.deepcopy(value['spec']);spec.pop('replicas',None);image=spec['template']['spec']['containers'][0].pop('image')
            return {'uid':value['metadata']['uid'],'spec':spec},image
        def secret_projection(value):
            return {'uid':value['metadata']['uid'],'type':value['type'],'immutable':False,'data':value['data']}
        module=types.SimpleNamespace(deployment_projection=deployment_projection,secret_projection=secret_projection)
        prepared={'deployments':{},'secrets':{}}
        for role,(app,config_role,secret_name,config_secret) in store_claim.ROLES.items():
            config='[storage]\nbackend="s3"\n[storage.s3]\nendpoint="'+store_claim.ENDPOINT+'"\nregion="fr-par"\nbucket="dev-resources-mcp"\nprefix="production"\npath_style=true\n[storage.s3.credentials]\nmode="files"\naccess_key_file="/run/devres-s3/access-key"\nsecret_key_file="/run/devres-s3/secret-key"\n'
            texts[app]=config
            secret={'metadata':{'uid':secret_name},'type':'Opaque','data':{'access-key':b64('fixture-'+role+'-access'),'secret-key':b64('fixture-'+role+'-secret')}}
            cfg={'metadata':{'uid':config_secret},'type':'Opaque','data':{config_role+'.toml':b64(config)}}
            deployment={'metadata':{'uid':app},'spec':{'replicas':0,'template':{'spec':{
                'containers':[{'name':app,'image':'pinned-old','command':['devres-server','collect' if app=='writer' else 'serve','/etc/devres/config/'+config_role+'.toml'],
                    'volumeMounts':[{'name':'s3','mountPath':'/run/devres-s3','readOnly':True},{'name':'config','mountPath':'/etc/devres/config','readOnly':True}]}],
                'volumes':[{'name':'s3','secret':{'secretName':secret_name}},{'name':'config','secret':{'secretName':config_secret}}]}}}}
            objects[('deployment',app)]=deployment;objects[('secret',secret_name)]=secret;objects[('secret',config_secret)]=cfg
            archived[secret_name+'.json']=copy.deepcopy(secret)
            prepared['deployments'][app]={'projection':deployment_projection(deployment)[0]}
            prepared['secrets'][secret_name]=secret_projection(secret);prepared['secrets'][config_secret]=secret_projection(cfg)
        self.write(controller.root/'prepared.json',prepared)
        state={'revision':store_claim.REVISION,'runtime':'target','phase':'prepared','configs':'old',
            'replicas':{'postgres':1,'backend':0,'writer':0},'pods':{'postgres':{}},
            'images':{'backend':'pinned-old','writer':'pinned-old'},'prepared_sha256':store_claim.sha((controller.root/'prepared.json').read_bytes())}
        self.write(controller.root/'state.json',state)
        controller.state.side_effect=lambda:copy.deepcopy(state)
        controller.get.side_effect=lambda kind,name:copy.deepcopy(objects[(kind,name)])
        controller.configurations.return_value=texts
        original.read_json=lambda path:copy.deepcopy(archived[path.name]) if path.name in archived else {'identity':'fixed'}
        original.private_read=lambda path:texts['backend' if path.name=='serving.toml' else 'writer'].encode()
        original.static_binding=Mock(return_value=binding)
        get=Mock(return_value=(store_claim.encoded({'version':1,'store_id':'1'*32}),'fixed-request-id'))
        return module,controller,objects,get

    def test_stable_withdrawn_boundary_uses_one_get_without_mounted_file_claim(self):
        module,controller,objects,get=self.fixture()
        result=store_claim.run(module,controller,get)
        get.assert_called_once()
        self.assertEqual(result['boundary_mode'],'withdrawn')
        self.assertTrue(result['stopped_role_secret_templates_match_admitted_binding'])
        self.assertFalse(result['actual_operating_files_match_admitted_binding'])
        self.assertEqual(result['source_sha256'],store_claim.sha(store_claim.private_read(Path(store_claim.__file__),source=True)))

    def test_application_pod_prevents_get(self):
        module,controller,objects,get=self.fixture()
        controller.old.k.return_value=store_claim.encoded({'items':[{'metadata':{'labels':{'app':'backend'}}}]})
        with self.assertRaisesRegex(store_claim.Stop,'withdrawn_application_pod_present'):
            store_claim.run(module,controller,get)
        get.assert_not_called()

    def test_changed_api_credential_prevents_get(self):
        module,controller,objects,get=self.fixture()
        objects[('secret','devres-serving-s3')]['data']['access-key']='Y2hhbmdlZA=='
        with self.assertRaisesRegex(store_claim.Stop,'withdrawn_prepared_credentials_changed'):
            store_claim.run(module,controller,get)
        get.assert_not_called()

    def test_changed_template_prevents_get(self):
        module,controller,objects,get=self.fixture()
        objects[('deployment','backend')]['spec']['replicas']=1
        with self.assertRaisesRegex(store_claim.Stop,'withdrawn_deployment_changed'):
            store_claim.run(module,controller,get)
        get.assert_not_called()

    def test_failed_legacy_attempt_is_preserved_and_withdrawn_attempt_is_single_use(self):
        module,controller,objects,get=self.fixture()
        legacy={'store-claim-intent.json':b'original consumed intent','store-claim-failed.json':b'original preserved failure'}
        for name,body in legacy.items():self.write(self.root/name,body)
        store_claim.run(module,controller,get)
        for name,body in legacy.items():self.assertEqual((self.root/name).read_bytes(),body)
        with self.assertRaisesRegex(store_claim.Stop,'qualified_store_claim_already_exists'):
            store_claim.run(module,controller,get)
        self.assertEqual(get.call_count,1)


if __name__ == '__main__':
    unittest.main()
