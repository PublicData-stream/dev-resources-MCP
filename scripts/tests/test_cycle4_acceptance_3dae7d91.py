"""Behavioral acceptance/recovery authority tests; no cluster or provider I/O."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


renderer = module('cycle4_acceptance_predecessor', ROOT / 'deploy/production/cycle3_9373f71e.py')
adapter = module('cycle4_acceptance_transform', ROOT / 'deploy/production/cycle4_acceptance_3dae7d91.py')


def need(value, code):
    if not value:
        raise RuntimeError(code)


class Sources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {name: adapter.transform(name, renderer.transform(name, renderer.base_source(path)).decode())
                       for name, path in renderer.SOURCE_MAP.items()}

    def functions(self, filename, names, **values):
        tree = ast.parse(self.sources[filename])
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual({node.name for node in functions}, set(names))
        namespace = {'need': need, **values}
        exec(compile(ast.Module(functions, type_ignores=[]), filename, 'exec'), namespace)
        return SimpleNamespace(**namespace)

    def test_complete_source_closure_parses(self):
        for name, source in self.sources.items():
            with self.subTest(name=name):
                compile(source, name, 'exec')

    def test_changed_reviewed_site_fails_closed(self):
        source = renderer.transform('runner.py', renderer.base_source(renderer.SOURCE_MAP['runner.py'])).decode()
        altered = source.replace("role in {'backend', 'writer', 'postgres'}", "role in {'backend', 'writer'}")
        with self.assertRaisesRegex(adapter.TransformError, 'one_reviewed_acceptance_site'):
            adapter.transform('runner.py', altered)

    def test_reapplying_transform_is_refused(self):
        with self.assertRaises(adapter.TransformError):
            adapter.transform('deploy.py', self.sources['deploy.py'])


class Lifecycle(Sources):
    def lifecycle(self):
        return self.functions('deploy.py', ['run_lifecycle'],
            common=SimpleNamespace(need=need, CONTROLLER=Path('/tmp/controller'), CHECKPOINT=Path('/tmp/checkpoint')),
            source_command=lambda name, *args: [name, *args], os=os).run_lifecycle

    def test_bootstrap_assessment_observer_then_active_order(self):
        stages = []
        with patch.dict(os.environ, {'DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256': 'f' * 64}):
            self.lifecycle()(lambda *args: stages.append(args),
                {'upgrade-controller.py': 'c' * 64, 'physical-checkpoint.py': 'p' * 64}, 'target')
        self.assertEqual([row[0] for row in stages], ['apply', 'start-writer', 'migration-before-npm',
            'npm-recovery', 'start-observer', 'paused-acceptance', 'activate-existing', 'active-acceptance'])
        self.assertEqual(stages[6][1][:2], ['phase-driver.py', 'activate-existing'])
        self.assertTrue(all(0 < timeout <= 3300 for _, _, timeout in stages))
        self.assertEqual(sum(command[:2] == ['phase-driver.py', 'activate-existing'] for _, command, _ in stages), 1)

    def test_no_stage_runs_for_fallback_runtime(self):
        stage = Mock()
        with self.assertRaisesRegex(RuntimeError, 'target_only_deployment'):
            self.lifecycle()(stage, {'upgrade-controller.py': '', 'physical-checkpoint.py': ''}, 'fallback')
        stage.assert_not_called()

    def test_every_lifecycle_failure_stops_before_later_stage(self):
        expected = ['apply', 'start-writer', 'migration-before-npm', 'npm-recovery', 'start-observer',
                    'paused-acceptance', 'activate-existing', 'active-acceptance']
        for failing in expected:
            with self.subTest(failing=failing), patch.dict(os.environ,
                    {'DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256': 'f' * 64}):
                observed = []
                def stage(name, *args):
                    observed.append(name)
                    if name == failing:
                        raise RuntimeError('finite_failure')
                with self.assertRaisesRegex(RuntimeError, 'finite_failure'):
                    self.lifecycle()(stage, {'upgrade-controller.py': '', 'physical-checkpoint.py': ''}, 'target')
                self.assertEqual(observed, expected[:expected.index(failing) + 1])

    def test_paused_runner_emits_proofs_without_activating(self):
        common = SimpleNamespace(CONTROLLER=Path('/tmp/controller'), CHECKPOINT=Path('/tmp/checkpoint'), ROOT=Path('/tmp/root'))
        commands = self.functions('runner.py', ['commands'], common=common, sys=sys).commands('paused',
            {key: 'a' * 64 for key in ('upgrade-controller.py', 'physical-checkpoint.py', 'compressed-probe.py', 'operational-proof.py')})
        labels = [row[0] for row in commands]
        self.assertIn('activation-receipt', labels)
        self.assertNotIn('activate-existing', labels)
        self.assertEqual(labels[-1], 'activation-receipt')


class Recovery(Sources):
    def recovery(self):
        return self.functions('deploy.py', ['recover_target'],
            common=SimpleNamespace(need=need),
            controller_phase=lambda c: (c.state()['runtime'], c.state()['phase']),
            enforce_withdrawal=lambda c: c.withdraw())

    def test_failure_restores_once_and_remains_withdrawn(self):
        state = {'runtime': 'target', 'phase': 'reader_ready', 'pods': {'postgres': {}, 'backend': {}}}
        def restore():
            state.update(runtime='restored', phase='withdrawn', pods={'postgres': {}})
        c = SimpleNamespace(state=lambda: state, withdraw=Mock(return_value=True), rollback=Mock(side_effect=restore),
                            guard=Mock(), storage_guard=Mock())
        recover = self.recovery().recover_target
        self.assertTrue(recover(c))
        self.assertTrue(recover(c))
        c.withdraw.assert_called_once()
        c.rollback.assert_called_once()
        c.storage_guard.assert_called_once_with(18, owner=False)

    def test_uncertain_withdrawal_prevents_restore(self):
        c = SimpleNamespace(state=lambda: {'runtime': 'target', 'phase': 'reader_ready'},
                            withdraw=Mock(return_value=False), rollback=Mock())
        with self.assertRaisesRegex(RuntimeError, 'withdrawal_incomplete'):
            self.recovery().recover_target(c)
        c.rollback.assert_not_called()

    def test_fallback_state_is_rejected(self):
        c = SimpleNamespace(state=lambda: {'runtime': 'fallback', 'phase': 'applied'},
                            withdraw=Mock(), rollback=Mock())
        with self.assertRaisesRegex(RuntimeError, 'unknown_recovery_runtime'):
            self.recovery().recover_target(c)
        c.withdraw.assert_not_called()
        c.rollback.assert_not_called()

    def test_supervision_signal_runs_same_restore_withdraw_path(self):
        recovery = Mock()
        env = self.functions('deploy.py', ['complete'], common=SimpleNamespace(need=need, REVISION='release'),
            controller_phase=lambda c: ('target', 'complete'),
            run_lifecycle=Mock(side_effect=KeyboardInterrupt()), recover_target=recovery,
            enforce_withdrawal=Mock(return_value=True))
        c = object()
        value = env.complete('target', {}, c, SimpleNamespace(run_stage=Mock()), 'a' * 64)
        recovery.assert_called_once_with(c)
        self.assertEqual(value['outcome'], 'target_failed_restored_withdrawn')
        self.assertFalse(value['target_deployed'])
        self.assertFalse(value['fallback_deployed'])

    def test_failed_restore_has_no_fallback_and_attempts_independent_fence(self):
        fence = Mock(return_value=False)
        env = self.functions('deploy.py', ['complete'], common=SimpleNamespace(need=need, REVISION='release'),
            controller_phase=lambda c: ('target', 'complete'), run_lifecycle=Mock(side_effect=RuntimeError()),
            recover_target=Mock(side_effect=RuntimeError()), enforce_withdrawal=fence)
        value = env.complete('target', {}, object(), SimpleNamespace(run_stage=Mock()), 'a' * 64)
        self.assertEqual(value['outcome'], 'restore_incomplete')
        self.assertFalse(value['fallback_deployed'])
        fence.assert_called_once()

    def test_nested_runner_never_restores_even_without_defer_environment(self):
        common = SimpleNamespace(RUNTIME='target', controller=Mock())
        env = self.functions('runner.py', ['recover_failure'], common=common, withdraw=Mock(return_value=True))
        with patch.dict(os.environ, {}, clear=True):
            value = env.recover_failure()
        self.assertTrue(value['withdrawal_completed'])
        self.assertFalse(value['fallback_prepared'])
        common.controller.assert_not_called()


class ObserverAuthority(Sources):
    def identity(self):
        generation = {'id': 'notice'}
        identity = {'schema': 19, 'recovery': False, 'system_id': 'sys', 'archive': {'epoch': 2},
            'control': {'format_version': 1, 'required_policy_epoch': 2, 'required_policy_fingerprint': 'policy'},
            'npm_recovery_tables': 3, 'new_tables': 2, 'new_columns': 2, 'recovery_trigger': 1,
            'reader_select_gaps': 0, 'reader_mutation_tables': 0, 'reader_default_readonly': True,
            'owners': [], 'pinned_generation': generation}
        baseline = {'database': {'system_id': 'sys', 'archive': {'epoch': 2}}, 'generation_sha256': 'generation'}
        state = {'configs': 'observer', 'pods': {'postgres': {}, 'backend': {}, 'status-observer': {'pod_ip': 'observer'}}}
        return identity, baseline, state

    def validator(self):
        return self.functions('operational-proof.py', ['validate_identity'],
            common=SimpleNamespace(SCHEMA=19), POLICY2='policy', generation_hash=lambda _: 'generation').validate_identity

    def test_observer_accepts_zero_owner_and_rejects_hidden_full_writer(self):
        identity, baseline, state = self.identity()
        self.validator()(identity, baseline, state)
        for owners in ([{'role': 'devres_writer', 'client_addr': 'observer'}], [{}]):
            with self.subTest(owners=owners):
                with self.assertRaisesRegex(RuntimeError, 'paused_observer_without_owner_required'):
                    self.validator()({**identity, 'owners': owners}, baseline, state)

    def test_observer_cannot_qualify_active_settings(self):
        identity, baseline, state = self.identity()
        state['configs'] = 'active'
        with self.assertRaisesRegex(RuntimeError, 'paused_observer_without_owner_required'):
            self.validator()(identity, baseline, state)

    def test_active_writer_requires_its_own_owner(self):
        identity, baseline, state = self.identity()
        state['pods'] = {'postgres': {}, 'writer': {'pod_ip': 'writer'}, 'backend': {}}
        state['configs'] = 'active'
        with self.assertRaisesRegex(RuntimeError, 'sole_writer_owner_required'):
            self.validator()(identity, baseline, state)
        identity['owners'] = [{'role': 'devres_writer', 'client_addr': 'writer'}]
        self.validator()(identity, baseline, state)

    def proof(self):
        return {'verified': True, 'process': {'uid': 'observer'}, 'configuration_sha256': 'config',
                **{key: True for key in ('no_publication_owner', 'retained_sql_unchanged',
                                         'no_provider_requests', 'no_repairs_or_queue_writes')}}

    def private_denial(self, status=403, proof=None):
        proof = self.proof() if proof is None else proof
        controlled = SimpleNamespace(observer_proof=Mock(return_value=proof))
        connection = Mock()
        answer = Mock(status=status)
        connection.getresponse.return_value = answer
        constructor = Mock(return_value=connection)
        command = Mock(return_value=SimpleNamespace(returncode=0, stdout=b'private-token'))
        env = self.functions('target-private-acceptance.py', ['prove_observer_authority'],
            http=SimpleNamespace(client=SimpleNamespace(HTTPSConnection=constructor)), command=command)
        return env, controlled, connection, constructor, command

    def test_authenticated_denial_uses_private_token_and_closes_connection(self):
        env, c, connection, constructor, command = self.private_denial()
        state = {'pods': {'status-observer': {'uid': 'observer'}}}
        self.assertTrue(env.prove_observer_authority(c, state, 'verified-tls-context'))
        constructor.assert_called_once_with('writer.devres.svc', 9443, context='verified-tls-context', timeout=15)
        self.assertEqual(connection.request.call_args.args[3]['Authorization'], 'Bearer private-token')
        self.assertNotIn('private-token', repr(command.call_args))
        connection.close.assert_called_once()
        self.assertEqual(c.observer_proof.call_count, 2)

    def test_denial_rejects_success_auth_failure_or_server_failure(self):
        for status in (200, 400, 401, 404, 500):
            with self.subTest(status=status):
                env, c, connection, _, _ = self.private_denial(status)
                with self.assertRaisesRegex(RuntimeError, 'observer_authenticated_acquisition_not_denied'):
                    env.prove_observer_authority(c, {'pods': {'status-observer': {'uid': 'observer'}}}, object())
                connection.close.assert_called_once()

    def test_changed_readonly_proof_rejects_before_identity_read_or_network(self):
        for key in ('verified', 'no_publication_owner', 'retained_sql_unchanged',
                    'no_provider_requests', 'no_repairs_or_queue_writes'):
            with self.subTest(key=key):
                env, c, _, constructor, command = self.private_denial(proof={**self.proof(), key: False})
                with self.assertRaisesRegex(RuntimeError, 'observer_readonly_proof_required'):
                    env.prove_observer_authority(c, {'pods': {'status-observer': {'uid': 'observer'}}}, object())
                constructor.assert_not_called()
                command.assert_not_called()

    def test_process_or_sql_change_during_denial_is_rejected(self):
        env, c, connection, _, _ = self.private_denial()
        changed = {**self.proof(), 'configuration_sha256': 'changed'}
        c.observer_proof.side_effect = [self.proof(), changed]
        with self.assertRaisesRegex(RuntimeError, 'observer_authority_changed'):
            env.prove_observer_authority(c, {'pods': {'status-observer': {'uid': 'observer'}}}, object())
        connection.close.assert_called_once()

    def test_finite_diagnostics_accept_observer_and_assessment_only(self):
        env = self.functions('deploy/diagnostics/evidence.py', ['validate_runtime'], EvidenceError=RuntimeError)
        for role in ('backend', 'writer', 'postgres', 'status-observer', 'devres-npm-assessment'):
            env.validate_runtime('pod', {'role': role, 'ready': True, 'restarts': 0})
        with self.assertRaisesRegex(RuntimeError, 'runtime_role_refused'):
            env.validate_runtime('pod', {'role': 'caller-input', 'ready': True, 'restarts': 0})


class SameProcessMigration(Sources):
    def environment(self, controller, root, work):
        return self.functions('operational-proof.py', ['observation'],
            controller=controller, BUNDLE=root, WORK=work, BASELINE=work / 'baseline.json',
            REVISION='release', load=lambda _: {'revision': 'release'}, private_dir=Mock(),
            contextlib=contextlib)

    def test_locked_override_rejects_nonmigration_operation_before_io(self):
        class Controller:
            root = Path('/tmp/cycle4-migration')
            context = 'default'
        c = Controller()
        env = self.environment(SimpleNamespace(Controller=Controller), c.root, Path('/tmp/cycle4-never-created'))
        with self.assertRaisesRegex(RuntimeError, 'sameprocess_locked_migration_required'):
            env.observation(SimpleNamespace(Controller=Controller), object(), 'sample', 'sample', locked_controller=c)
        env.private_dir.assert_not_called()

    def test_locked_override_rejects_foreign_type_bundle_or_context(self):
        class Controller:
            root = Path('/tmp/cycle4-migration')
            context = 'default'
        class Foreign(Controller):
            pass
        controller = SimpleNamespace(Controller=Controller)
        wrong_bundle = Controller(); wrong_bundle.root = Path('/tmp/wrong-root')
        wrong_context = Controller(); wrong_context.context = 'foreign'
        for c in (Foreign(), wrong_bundle, wrong_context):
            env = self.environment(controller, Controller.root, Path('/tmp/cycle4-never-created'))
            with self.assertRaisesRegex(RuntimeError, 'sameprocess_locked_migration_required'):
                env.observation(controller, object(), 'migration-active', 'active', locked_controller=c)

    def test_already_locked_valid_controller_never_reacquires_lock(self):
        class Sentinel(RuntimeError):
            pass
        class Controller:
            context = 'default'
        with tempfile.TemporaryDirectory(prefix='cycle4-inline-migration-', dir='/tmp') as tmp:
            work = Path(tmp)
            c = Controller(); c.root = work / 'bundle'
            c.locked = Mock(side_effect=AssertionError('must_not_reacquire'))
            c.guard = Mock(side_effect=Sentinel('guard_reached_under_caller_lock'))
            controller = SimpleNamespace(Controller=Controller)
            env = self.environment(controller, c.root, work)
            with self.assertRaisesRegex(Sentinel, 'guard_reached_under_caller_lock'):
                env.observation(controller, object(), 'migration-active', 'active', locked_controller=c)
            c.guard.assert_called_once()
            c.locked.assert_not_called()

    def test_operational_import_registers_controller_before_execution(self):
        with tempfile.TemporaryDirectory(prefix='cycle4-loader-', dir='/tmp') as tmp:
            path = Path(tmp) / 'controller.py'
            body = b'import importlib\nregistered = importlib.import_module(__name__)\n'
            path.write_bytes(body)
            name = 'cycle4_test_registered_controller'
            env = self.functions('operational-proof.py', ['bound_module'],
                re=__import__('re'), raw=lambda _: body, sha=lambda v: hashlib.sha256(v).hexdigest(),
                importlib=importlib, sys=sys)
            with patch.dict(sys.modules):
                value = env.bound_module(path, hashlib.sha256(body).hexdigest(), name)
                self.assertIs(value.registered, value)

    def test_receipt_import_registers_controller_before_execution(self):
        with tempfile.TemporaryDirectory(prefix='cycle4-receipt-loader-', dir='/tmp') as tmp:
            path = Path(tmp) / 'controller.py'
            path.write_text('import importlib\nregistered = importlib.import_module(__name__)\n')
            name = 'cycle4_test_registered_receipt_controller'
            env = self.functions('acceptance-receipt.py', ['source_module'],
                code_sha=Mock(), importlib=importlib, sys=sys)
            with patch.dict(sys.modules):
                value = env.source_module(path, 'a' * 64, name)
                self.assertIs(value.registered, value)


if __name__ == '__main__':
    unittest.main()
