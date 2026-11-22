import ast
import importlib.util
import json
from contextlib import nullcontext
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/production'))
import cycle6_ce5745e0 as cycle
import rehearse_retained_rows_5a865235 as rehearsal
from observer_retained_rows import (
    RETAINED_PARALLEL_PROFILE,
    RETAINED_PARALLEL_TEMP_BYTES,
    RetainedRowsError,
    retained_row_manifest,
)
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
        self.assertIn(b"SET LOCAL work_mem = '16MB';", kwargs['data'])
        self.assertIn(b'SET LOCAL max_parallel_workers_per_gather = 0;', kwargs['data'])
        self.assertEqual(self.transport.call_count, 1)

    def test_parallel_profile_only_changes_session_tuning(self):
        expected = retained_row_manifest(self.transport)
        serial = self.transport.call_args.kwargs['data']
        self.transport.reset_mock()
        self.assertEqual(retained_row_manifest(self.transport, profile=RETAINED_PARALLEL_PROFILE), expected)
        parallel = self.transport.call_args.kwargs['data']
        exact_settings = (b"SET LOCAL work_mem = '64MB';\nSET LOCAL temp_file_limit = '1GB';\n"
                          b"SET LOCAL max_parallel_workers_per_gather = 3;\n"
                          b"SET LOCAL min_parallel_table_scan_size = 0;\n"
                          b"SET LOCAL parallel_setup_cost = 0;\nSET LOCAL parallel_tuple_cost = 0;")
        self.assertEqual(parallel, serial.replace(b"SET LOCAL work_mem = '16MB';\n"
                                                 b"SET LOCAL temp_file_limit = '1GB';\n"
                                                 b'SET LOCAL max_parallel_workers_per_gather = 0;', exact_settings))
        self.transport.assert_called_once()

    def test_unknown_profile_runs_no_query(self):
        with self.assertRaisesRegex(RetainedRowsError, '^unsupported_retained_row_profile$'):
            retained_row_manifest(self.transport, profile='unapproved')
        self.transport.assert_not_called()

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
        with self.assertRaisesRegex(ValueError, '^unsupported_retained_row_profile$'):
            render_observer_controller(self.frozen, profile='unapproved')

    def test_parallel_profile_requires_explicit_render_opt_in(self):
        def load_method(source):
            tree = ast.parse(source)
            method, = [node for controller in tree.body
                       if isinstance(controller, ast.ClassDef) and controller.name == 'Controller'
                       for node in controller.body if isinstance(node, ast.FunctionDef)
                       and node.name == '_retained_row_manifest']
            scope = {'retained_row_manifest': Mock(), 'RETAINED_PARALLEL_PROFILE': RETAINED_PARALLEL_PROFILE}
            exec(compile(ast.Module([method], type_ignores=[]), 'rendered-proof-profile', 'exec'), scope)
            return scope['_retained_row_manifest'], scope['retained_row_manifest']

        controller = Mock()
        default, default_proof = load_method(self.rendered)
        default(controller)
        default_proof.assert_called_once_with(controller.old.k)
        opt_in, parallel_proof = load_method(render_observer_controller(self.frozen, profile=RETAINED_PARALLEL_PROFILE))
        opt_in(controller)
        parallel_proof.assert_called_once_with(controller.old.k, profile=RETAINED_PARALLEL_PROFILE)

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


class RehearsalProfile(unittest.TestCase):
    def test_parallel_temp_space_is_in_addition_to_copy_and_reserve(self):
        copy_bytes = 8 * 1024**3
        required = rehearsal.RESERVE + copy_bytes + RETAINED_PARALLEL_TEMP_BYTES
        with patch.object(rehearsal.shutil, 'disk_usage', return_value=Mock(free=required - 1)):
            with self.assertRaisesRegex(RuntimeError, '^rehearsal_copy_reserve_exceeded$'):
                rehearsal.require_disk_headroom(copy_bytes)
        with patch.object(rehearsal.shutil, 'disk_usage', return_value=Mock(free=required)):
            rehearsal.require_disk_headroom(copy_bytes)

    def test_requires_proven_cpu_memory_and_shared_memory_limits(self):
        container = 'a' * 64
        expected = b'6442450944\n400000 100000\n', b'67108864\n'
        with patch.object(rehearsal, 'run', side_effect=expected):
            rehearsal.check_proof_limits(container)
        for limits in ((b'6442450944\n300000 100000\n', expected[1]),
                       (b'4294967296\n400000 100000\n', expected[1]), (expected[0], b'536870912\n')):
            with patch.object(rehearsal, 'run', side_effect=limits):
                with self.assertRaisesRegex(RuntimeError, '^isolated_postgres_proof_limits_mismatch$'):
                    rehearsal.check_proof_limits(container)
