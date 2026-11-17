"""Actual fresh-cycle rendering and source-bound configuration contracts."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value; spec.loader.exec_module(value)
    return value


r = load('cycle4_renderer_contract', ROOT / 'deploy/production/cycle4_3dae7d91.py')
p = load('cycle4_base_configs', ROOT / 'deploy/production/production.py')


class Rendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(dir='/tmp', prefix='cycle4-contract-')
        cls.top = Path(cls.temporary.name)
        cls.files = r.render(cls.top / 'render', r.PREVIOUS_CONTROLLER_SHA, r.PREVIOUS_MANIFEST_SHA)
        cls.u = load('cycle4_generated_controller', cls.top / 'render/upgrade-controller.py')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_complete_closure_is_deterministic_and_private(self):
        other = r.render(self.top / 'other', r.PREVIOUS_CONTROLLER_SHA, r.PREVIOUS_MANIFEST_SHA)
        self.assertEqual(set(self.files), set(other))
        self.assertEqual(len(self.files), 25)
        for name in self.files:
            left, right = Path(self.files[name]['local']), Path(other[name]['local'])
            self.assertEqual(left.read_bytes(), right.read_bytes())
            self.assertEqual(left.stat().st_mode & 0o777, 0o600)
            ast.parse(left.read_bytes())
        self.assertIn('deploy/diagnostics/npm_assessment.py', self.files)
        with self.assertRaisesRegex(RuntimeError, 'fresh_private_output'):
            r.render(self.top / 'render', r.PREVIOUS_CONTROLLER_SHA, r.PREVIOUS_MANIFEST_SHA)

    def test_exact_predecessor_and_release_remain_distinct(self):
        u = self.u
        self.assertEqual((u.REVISION, u.IMAGE, u.VERSION), (r.REVISION, r.IMAGE, r.VERSION))
        self.assertEqual(u.PREVIOUS_REVISION, '9373f71e06936970b4a8dc4ca30584b9d464a5b9')
        self.assertEqual(str(u.PREVIOUS_WORK), '/tmp/devres-upgrade-9373f71e-20261116')
        self.assertEqual((u.PREVIOUS_CONTROLLER_SHA, u.PREVIOUS_MANIFEST_SHA),
                         (r.PREVIOUS_CONTROLLER_SHA, r.PREVIOUS_MANIFEST_SHA))
        with self.assertRaisesRegex(RuntimeError, 'exact_withdrawn_predecessor'):
            r.render(self.top / 'wrong', '0' * 64, r.PREVIOUS_MANIFEST_SHA)

    def test_observer_variants_have_only_reader_database_and_live_status_delegate(self):
        u = self.u
        variants = {v: {role: u.configuration(p.runtime_config(role == 'writer', 'scaleway_static')
                        .replace(p.VERSION, u.FALLBACK_VERSION).replace('enabled = false', 'enabled = true'), v.endswith('active'))
                        for role in ('writer', 'backend')} for v in ('paused', 'active')}
        original = copy.deepcopy(variants)
        u.observer_variants(variants)
        self.assertEqual({k: variants[k] for k in original}, original)
        reader, observer = (tomllib.loads(variants['observer'][role]) for role in ('backend', 'writer'))
        active_reader = tomllib.loads(original['active']['backend'])
        self.assertEqual(observer['storage']['database_url'], active_reader['storage']['database_url'])
        self.assertIn('devres_reader:', observer['storage']['database_url'])
        self.assertEqual(observer['writer_listener']['access'], 'status_only')
        self.assertEqual(reader['writer_client'], {**active_reader['writer_client'], 'access': 'status_only'})
        self.assertTrue(observer['storage']['blob_dir'].startswith('/tmp/'))
        self.assertTrue(observer['storage']['scratch_dir'].startswith('/tmp/'))
        for config in (reader, observer):
            self.assertTrue(all(config[v]['enabled'] is False for v in u.PROVIDERS))
            self.assertFalse(config['npm']['advisories_enabled'])

    def test_actual_prepare_calls_observer_variant_before_candidate_hashes(self):
        source = Path(self.files['upgrade-controller.py']['local']).read_text()
        base = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == 'Controller')
        prepare = next(n for n in base.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        calls = [n for n in ast.walk(prepare) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'observer_variants']
        self.assertEqual(len(calls), 1)
        self.assertLess(calls[0].lineno, next(n.lineno for n in ast.walk(prepare) if isinstance(n, ast.Dict)
                         and any(isinstance(k, ast.Constant) and k.value == 'config_hashes' for k in n.keys)))


if __name__ == '__main__':
    unittest.main()
