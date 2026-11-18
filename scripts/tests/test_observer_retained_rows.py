import ast
import importlib.util
import json
from contextlib import nullcontext
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, call

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/production'))
import cycle6_ce5745e0 as cycle
from observer_retained_rows import RetainedRowsError, retained_row_manifest
from observer_retained_rows_transform import render_observer_controller


def frames(names, rows):
    return ('\n'.join(json.dumps(value) for value in [names, *rows]) + '\nretained-rows-committed-v1\n').encode('ascii')


class RetainedRowProtocol(unittest.TestCase):
    def setUp(self):
        self.row = {'name': 'devres_a', 'rows': 3, 'sha256': 'a' * 64}
        self.transport = Mock(return_value=frames(['devres_a'], [self.row]))

    def test_one_read_only_exec_and_one_versioned_manifest(self):
        result = retained_row_manifest(self.transport)
        self.assertEqual(set(result), {'algorithm', 'table_count', 'row_count', 'sha256'})
        self.assertEqual((result['algorithm'], result['table_count'], result['row_count']),
                         ('sha256-row-multiset-v1', 1, 3))
        self.assertRegex(result['sha256'], r'^[0-9a-f]{64}$')
        args, kwargs = self.transport.call_args
        self.assertEqual(args[:7], ('exec', '-i', 'deployment/postgres', '-c', 'postgres', '--', 'psql'))
        self.assertEqual(args[-4:], ('-v', 'ON_ERROR_STOP=1', '-f', '-'))
        self.assertEqual(kwargs['request_timeout'], 260)
        self.assertEqual(kwargs['timeout'], 270)
        self.assertIn(b'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;', kwargs['data'])
        self.assertIn(b"SET LOCAL transaction_timeout = '240s';", kwargs['data'])
        self.assertEqual(self.transport.call_count, 1)

    def test_rejects_partial_duplicate_and_malformed_frames(self):
        bad_cases = [
            frames(['devres_a'], [self.row]).split(b'retained-rows-committed-v1')[0],
            frames(['devres_a'], []),
            frames(['devres_a'], [self.row, self.row]),
            frames(['devres_a', 'devres_a'], [self.row, self.row]),
            frames(['devres_b'], [self.row]),
            frames(['devres_a'], [dict(self.row, rows=True)]),
            frames(['devres_a'], [dict(self.row, sha256='f' * 63)]),
            frames(['devres_a'], [dict(self.row, unexpected='extra')]),
            frames(['devres_a'], [self.row]).replace(b'"rows": 3', b'"rows": 3, "rows": 4'),
            b'\xff',
        ]
        for body in bad_cases:
            with self.subTest(body=body):
                self.transport.return_value = body
                with self.assertRaises(RetainedRowsError):
                    retained_row_manifest(self.transport)
        self.transport.return_value = 'retained-rows-invalid-inventory\n'
        with self.assertRaisesRegex(RetainedRowsError, '^retained_table_inventory_changed$'):
            retained_row_manifest(self.transport)

    def test_transport_details_do_not_enter_the_error(self):
        self.transport.side_effect = RuntimeError('sensitive error metadata')
        with self.assertRaisesRegex(RetainedRowsError, '^retained_row_manifest_query_failed$') as raised:
            retained_row_manifest(self.transport)
        self.assertTrue(raised.exception.__suppress_context__)


class SuccessorController(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = tempfile.TemporaryDirectory(prefix='observer-controller-', dir='/tmp')
        cls.addClassCleanup(scratch.cleanup)
        root = Path(scratch.name)
        prior = cycle.predecessor
        artifacts = prior.render(root / 'previous', prior.PREVIOUS_CONTROLLER_SHA, prior.PREVIOUS_MANIFEST_SHA)
        cls.frozen = cycle.transform('upgrade-controller.py', Path(artifacts['upgrade-controller.py']['local']).read_text())
        cls.deployment = cycle.transform('deploy.py', Path(artifacts['deploy.py']['local']).read_text())
        cls.rendered = render_observer_controller(cls.frozen)
        path = root / 'upgrade-controller.py'
        path.write_text(cls.rendered)
        spec = importlib.util.spec_from_file_location('test_successor_observer_controller', path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_refuses_duplicate_or_drifted_controller_sites(self):
        with self.assertRaises(ValueError):
            render_observer_controller(self.frozen.replace('self.change_config(\'observer\', \'observer-config\')', 'pass'))
        with self.assertRaises(ValueError):
            render_observer_controller(self.rendered)

    def test_baseline_transport_failure_precedes_observer_mutations(self):
        controller = Mock()
        controller.locked.return_value = nullcontext()
        controller.state.return_value = {'phase': 'writer_ready', 'configs': 'paused', 'pods': {'postgres': 'uid'}}
        self.addCleanup(setattr, self.module, 'cycle6_check_assessment', self.module.cycle6_check_assessment)
        self.module.cycle6_check_assessment = Mock()
        controller.old.k.side_effect = RuntimeError('simulated timeout')
        controller._retained_row_manifest = lambda: self.module.Controller._retained_row_manifest(controller)
        with self.assertRaisesRegex(self.module.RetainedRowsError, 'retained_row_manifest_query_failed'):
            self.module.Controller.start_observer(controller)
        self.module.cycle6_check_assessment.assert_called_once_with(controller)
        controller.change_config.assert_not_called()
        controller.mutate.assert_not_called()

    def test_baseline_checks_identity_before_changing_configuration(self):
        controller = Mock()
        controller.locked.return_value = nullcontext()
        controller.state.return_value = {'phase': 'writer_ready', 'configs': 'paused', 'pods': {'postgres': 'uid'}}
        self.addCleanup(setattr, self.module, 'cycle6_check_assessment', self.module.cycle6_check_assessment)
        self.module.cycle6_check_assessment = Mock()
        controller._sql_fingerprint.side_effect = ['before', 'changed']
        controller.old.k.return_value = frames(['devres_a'], [{'name': 'devres_a', 'rows': 0, 'sha256': 'a' * 64}])
        controller._retained_row_manifest = lambda: self.module.Controller._retained_row_manifest(controller)
        with self.assertRaisesRegex(Exception, 'observer_baseline_identity_changed'):
            self.module.Controller.start_observer(controller)
        self.assertEqual(controller.guard.call_args_list, [call(), call()])
        controller.change_config.assert_not_called()

    def test_post_proof_failure_leaves_no_activation_receipt(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as path:
            controller = Mock(root=Path(path))
            row = {'name': 'devres_a', 'rows': 1, 'sha256': 'a' * 64}
            old = retained_row_manifest(Mock(return_value=frames(['devres_a'], [row])))
            self.module.save(controller.root / 'observer-resource.json', {'phase': 'running', 'retained_rows': old})
            controller._retained_row_manifest = lambda: self.module.Controller._retained_row_manifest(controller)
            controller.old.k.return_value = frames(['devres_a'], [dict(row, sha256='b' * 64)])
            with self.assertRaisesRegex(Exception, 'observer_retained_rows_changed'):
                self.module.Controller.stop_observer(controller)
            self.assertFalse((controller.root / 'observer-retained-rows-completed.json').exists())
            controller.scale.assert_not_called()
            controller.change_config.assert_not_called()
            controller.mutate.assert_not_called()

    def test_deployment_recovers_after_post_proof_failure(self):
        tree = ast.parse(self.deployment)
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in {'complete', 'recover_target', 'run_lifecycle'}]
        with tempfile.TemporaryDirectory(dir='/tmp') as path:
            controller = Mock(root=Path(path))
            row = {'name': 'devres_a', 'rows': 1, 'sha256': 'a' * 64}
            before = retained_row_manifest(Mock(return_value=frames(['devres_a'], [row])))
            self.module.save(controller.root / 'observer-resource.json', {'phase': 'running', 'retained_rows': before})
            controller._retained_row_manifest = lambda: self.module.Controller._retained_row_manifest(controller)
            controller.old.k.side_effect = TimeoutError
            controller.phase = ('target', 'reader_ready')
            controller.state.return_value = {'runtime': 'restored', 'phase': 'withdrawn', 'pods': {'postgres': 'uid'}}

            def need(condition, code):
                if not condition:
                    raise AssertionError(code)

            def run_stage(label, _command, _timeout):
                if label == 'deploy-activate-existing':
                    self.module.Controller.stop_observer(controller)

            withdraw = Mock(return_value=True)
            supervisor = Mock()
            supervisor.run_stage.side_effect = run_stage
            common = Mock(need=need)
            common.target_mutation_admitted.return_value = True
            scope = {'common': common, 'controller_phase': lambda c: c.phase, 'enforce_withdrawal': withdraw,
                     'os': Mock(environ={'DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256': 'a' * 64}),
                     'source_command': lambda *args: args}
            exec(compile(ast.Module(functions, type_ignores=[]), 'rendered-deployment', 'exec'), scope)
            result = scope['complete']('target', {'upgrade-controller.py': 'a' * 64, 'physical-checkpoint.py': 'b' * 64},
                                       controller, supervisor, 'a' * 64)
            self.assertEqual(result['outcome'], 'target_failed_restored_withdrawn')
            self.assertEqual(supervisor.run_stage.call_args_list[-1].args[0], 'deploy-activate-existing')
            withdraw.assert_called_once_with(controller)
            controller.rollback.assert_called_once_with()
            self.assertFalse((controller.root / 'observer-retained-rows-completed.json').exists())
