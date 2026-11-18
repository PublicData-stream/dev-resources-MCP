import ast
from contextlib import nullcontext
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/production'))
import cycle6_ce5745e0 as cycle


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


class GeneratedCycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='cycle6-fixture-', dir='/tmp')
        cls.addClassCleanup(cls.scratch.cleanup)
        root = pathlib.Path(cls.scratch.name)
        prior = cycle.predecessor
        sources = prior.render(root / 'previous', prior.PREVIOUS_CONTROLLER_SHA, prior.PREVIOUS_MANIFEST_SHA)
        cls.sources = {name: cycle.transform(name, pathlib.Path(item['local']).read_text())
                       for name, item in sources.items()}
        cls.source_path = root / 'upgrade-controller.py'
        cls.source_path.write_text(cls.sources['upgrade-controller.py'])
        cls.controller = load_module(cls.source_path, 'test_cycle6_generated_controller')

    def test_target_and_all_five_history_identities_are_distinct(self):
        u = self.controller
        self.assertEqual(u.REVISION, cycle.REVISION)
        self.assertEqual(u.IMAGE, cycle.IMAGE)
        self.assertEqual(u.PROBE_IMAGE, cycle.PROBE)
        self.assertEqual(u.PREVIOUS_REVISION, cycle.previous.REVISION)
        self.assertEqual(u.PREVIOUS_IMAGE, cycle.previous.IMAGE)
        self.assertEqual(u.PREVIOUS_CONTROLLER_SHA, cycle.PREVIOUS_CONTROLLER_SHA)
        self.assertEqual(u.PREVIOUS_STATE_SHA, cycle.PREVIOUS_STATE_SHA)
        self.assertEqual(u.PREVIOUS_RESTORE_SHA, cycle.PREVIOUS_RESTORE_SHA)
        self.assertEqual(len(u.HISTORIES), 5)
        self.assertEqual(u.HISTORIES[-1]['work'], cycle.predecessor.WORK)
        self.assertEqual(len(u.HISTORY_SPECIAL_NAMES['cycle5']) + len(u.HISTORY_SOURCE_NAMES['cycle5']), 29)
        self.assertNotEqual(u.OLD_IMAGE, u.PREVIOUS_IMAGE)
        self.assertEqual(self.sources['edge-readmission.py'], (cycle.HERE / 'cycle4_edge_3dae7d91.py').read_text())
        self.assertEqual(self.sources['edge-qualification.py'], (cycle.HERE / 'cycle4_edge_qualification_3dae7d91.py').read_text())

    def test_previous_image_restore_is_cas_bound_and_stays_withdrawn(self):
        u = self.controller

        def deployment(role):
            return {'metadata': {'uid': role, 'name': role, 'resourceVersion': '7'}, 'spec': {
                'replicas': 0, 'template': {'spec': {'containers': [{'name': role, 'image': u.IMAGE}]}}}}

        values = {role: deployment(role) for role in u.ROLES}
        prepared = {'initial_images': {role: u.PREVIOUS_IMAGE for role in u.ROLES},
                    'deployments': {role: {'projection': u.deployment_projection(value)[0]}
                                    for role, value in values.items()}}
        controller = Mock()
        controller.get.side_effect = lambda kind, role: values[role]
        controller.mutate.side_effect = lambda operation, apply: apply()

        def patch(*argv, data):
            role = argv[2]
            commands = json.loads(data)
            self.assertEqual(commands[:4], [
                {'op': 'test', 'path': '/metadata/uid', 'value': role},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'},
                {'op': 'test', 'path': '/spec/replicas', 'value': 0},
                {'op': 'test', 'path': '/spec/template/spec/containers/0/image', 'value': u.IMAGE},
            ])
            values[role]['spec']['template']['spec']['containers'][0]['image'] = commands[4]['value']

        controller.old.k.side_effect = patch
        u.cycle6_restore_template_images(controller, prepared)
        self.assertEqual(controller.old.k.call_count, 2)
        self.assertTrue(all(v['spec']['replicas'] == 0 for v in values.values()))
        u.cycle6_restore_template_images(controller, prepared)
        self.assertEqual(controller.old.k.call_count, 2)

    def test_checkpoint_dependency_union_keeps_exact_prior_union(self):
        tree = ast.parse(self.sources['physical-checkpoint.py'])
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'cycle6_dependency_union')

        def need(ok, code):
            if not ok:
                raise RuntimeError(code)

        env = {'P': pathlib.Path, 'need': need}
        exec(compile(ast.Module([node], type_ignores=[]), 'dependency-union', 'exec'), env)
        old = {f'/usr/local/libexec/fixture-{i}.py': f'{i:064x}' for i in range(37)}
        manifest = dict.fromkeys(self.controller.HISTORY_SPECIAL_NAMES['cycle5'], 'a'*64)
        actual = env[node.name](old, manifest)
        self.assertEqual(len(actual), 45)
        self.assertTrue(old.items() <= actual.items())
        self.assertEqual(actual[cycle.predecessor.INSTALL + '/upgrade-controller.py'], 'a'*64)
        old['/usr/local/libexec/extra.py'] = 'b'*64
        with self.assertRaisesRegex(RuntimeError, 'exact_previous_dependencies'):
            env[node.name](old, manifest)

    def test_fence_uses_read_only_guard_after_consumed_rollback(self):
        tree = ast.parse(self.sources['safety-supervisor.py'])
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'fence')
        with tempfile.TemporaryDirectory(dir='/tmp') as path:
            bundle = pathlib.Path(path)
            (bundle / 'rollback-intent.json').touch()
            env = {'BUNDLE': bundle, 'state': lambda: {'phase': 'withdrawn', 'runtime': 'target'}}
            exec(compile(ast.Module([node], type_ignores=[]), 'safety-fence', 'exec'), env)
            module = Mock()
            module.manifest_sources.return_value = {'upgrade-controller.py': 'b'*64}
            controller = module.bound_module.return_value.Controller.return_value
            controller.locked.return_value = nullcontext()
            result = env['fence'](module, 'a'*64)
            self.assertTrue(result['restore_incomplete'])
            controller.restore_guard.assert_called_once_with(stage='reconciliation-required')
            controller.withdraw.assert_not_called()
            controller.rollback.assert_not_called()

    def test_before_backup_admission_withdrawal_does_not_restore(self):
        tree = ast.parse(self.sources['deploy.py'])
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'recover_target')
        with tempfile.TemporaryDirectory(dir='/tmp') as path:
            env = {'common': Mock(), 'controller_phase': lambda _: ('target', 'stopped'),
                   'enforce_withdrawal': Mock(return_value=True)}
            env['common'].target_mutation_admitted.return_value = False
            exec(compile(ast.Module([node], type_ignores=[]), 'deployment-recovery', 'exec'), env)
            controller = Mock(root=pathlib.Path(path))
            self.assertFalse(env['recover_target'](controller))
            controller.rollback.assert_not_called()
            env['common'].verify_preactivation_withdrawal.assert_called_once_with(env['common'], controller)

    def test_backup_persistence_alone_does_not_admit_physical_restore(self):
        tree = ast.parse(self.sources['acceptance_common.py'])
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'target_mutation_admitted')

        def need(ok, code):
            if not ok:
                raise RuntimeError(code)

        with tempfile.TemporaryDirectory(dir='/tmp') as path:
            bundle = pathlib.Path(path)
            backup = bundle / 'accepted-backup.json'
            backup.write_text(json.dumps({'verified': True, 'schema': 18, 'revision': cycle.REVISION,
                                          'prepared_sha256': 'a'*64}))
            common = Mock(need=need, private_bytes=pathlib.Path.read_bytes, REVISION=cycle.REVISION)
            controller = Mock(root=bundle)
            controller.state.return_value = {'prepared_sha256': 'a'*64}
            env = {'os': os, 'json': json}
            exec(compile(ast.Module([node], type_ignores=[]), 'mutation-admission', 'exec'), env)
            check = env[node.name]
            self.assertFalse(check(common, controller))
            (bundle / 'target-paused-config-backend-intent.json').write_text(json.dumps({
                'version': 1, 'label': 'target-paused-config-backend', 'at': 'fixture', 'maximum_attempts': 1}))
            self.assertTrue(check(common, controller))
            controller.state.return_value = {'prepared_sha256': 'b'*64}
            with self.assertRaisesRegex(RuntimeError, 'target_mutation_backup_binding_changed'):
                check(common, controller)

    def test_observer_requires_assessment_report_and_closed_cleanup(self):
        tree = ast.parse(self.sources['upgrade-controller.py'])
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'cycle6_check_assessment')

        def require(ok, code):
            if not ok:
                raise RuntimeError(code)

        with tempfile.TemporaryDirectory(dir='/tmp') as path:
            work = pathlib.Path(path)
            directory = work / 'npm-assessment'
            directory.mkdir()
            report = b'{}'
            (directory / 'report.json').write_bytes(report)
            expected = {'eligible': False, 'deferred': True, 'reason': 'legacy_unknown', 'job_id': 'fixture', 'revision': 1}
            outcomes = {'npm-assessment-completed.json': {**expected, 'report_sha256': cycle.sha(report),
                'transport': 'uid-bookended-private-exec', 'pod_uid': 'test-uid', 'container_id': 'containerd://fixture',
                'cli_report_in_logs': False, 'phases': None, 'phase_known': False, 'at': 'fixture'},
                'npm-assessment-pod-identity.json': {'name': 'fixture', 'uid': 'test-uid'},
                'npm-assessment-network-admission.json': {'fixture': True},
                'npm-assessment-network-state.json': {'phase': 'removed'}}
            env = {'read': pathlib.Path.read_bytes, 'load': lambda p: outcomes[p.name], 'require': require,
                   'Path': pathlib.Path, 'WORK': str(work), 'json': json, 'os': os, 'digest': cycle.sha}
            exec(compile(ast.Module([node], type_ignores=[]), 'assessment-admission', 'exec'), env)
            controller = Mock(root=work)
            controller.helper.return_value.POD = 'fixture'
            controller.helper.return_value.ASSESSMENT_APP = 'fixture-app'
            controller.helper.return_value.validate_report.return_value = expected
            controller.helper.return_value.network_guard.return_value = set()
            controller.old.k.return_value = '{"items":[]}'
            check = env[node.name]
            check(controller)
            controller.old.k.return_value = '{"items":[{"metadata":{"name":"fixture"}}]}'
            with self.assertRaisesRegex(RuntimeError, 'assessment_pod_remaining'):
                check(controller)
            outcomes['npm-assessment-network-state.json']['phase'] = 'installed'
            with self.assertRaisesRegex(RuntimeError, 'assessment_cleanup_required'):
                check(controller)
            outcomes['npm-assessment-completed.json']['report_sha256'] = 'a'*64
            with self.assertRaisesRegex(RuntimeError, 'verified_assessment_report_required'):
                check(controller)


if __name__ == '__main__':
    unittest.main()
