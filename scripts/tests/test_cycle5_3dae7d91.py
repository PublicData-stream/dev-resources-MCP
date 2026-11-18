"""Fresh C5 rendering and restored-template contracts; no remote/cluster I/O."""
import ast
import base64
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts.tests.test_cycle4_runtime_3dae7d91 import Cluster, production

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value; spec.loader.exec_module(value)
    return value


r = module('cycle5_renderer_tests', ROOT / 'deploy/production/cycle5_3dae7d91.py')


class Rendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='cycle5-render-', dir='/tmp')
        cls.output = Path(cls.temp.name) / 'closure'
        cls.files = r.render(cls.output, r.PREVIOUS_CONTROLLER_SHA, r.PREVIOUS_MANIFEST_SHA)
        cls.u = module('cycle5_generated_controller_tests', cls.output / 'upgrade-controller.py')

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_fresh_scope_same_release_exact_frozen_prior_and_baseline_fix(self):
        self.assertEqual(len(self.files), 27)
        self.assertEqual(self.u.IMAGE, r.IMAGE)
        self.assertEqual(self.u.OLD_IMAGE, r.c4.module('c5_old_config', ROOT/'deploy/production/upgrade_1d76fbcc.py').OLD_IMAGE)
        self.assertEqual(self.u.PREVIOUS_CONTROLLER_SHA, r.PREVIOUS_CONTROLLER_SHA)
        self.assertEqual(self.u.PREVIOUS_MANIFEST_SHA, r.PREVIOUS_MANIFEST_SHA)
        self.assertEqual(str(self.u.PREVIOUS_WORK), r.PREVIOUS_WORK)
        self.assertEqual(self.u.WORK, r.WORK)
        self.assertTrue(r.INSTALL.endswith('-cycle5'))
        self.assertEqual(self.u.HISTORIES[-1]['name'], 'cycle4')
        self.assertEqual(len(self.u.HISTORIES), 4)
        self.assertIn('pre_upgrade_operational_baseline_required', Path(self.files['upgrade-controller.py']['local']).read_text())
        deploy = Path(self.files['deploy.py']['local']).read_text()
        self.assertLess(deploy.index('controller.require_operational_baseline()'), deploy.index("supervisor.private_save(common.WORK / 'deployment-intent.json'"))
        cp = Path(self.files['physical-checkpoint.py']['local']).read_text()
        self.assertIn("image == prepared['initial_images'][role]", cp)
        self.assertIn("OLD_REV = '91c7bcb7", cp)
        for name in ('edge-readmission.py', 'edge-qualification.py'):
            self.assertEqual(Path(self.files[name]['local']).read_bytes(), (ROOT/r.c4.HERE.relative_to(ROOT)/
                ('cycle4_edge_3dae7d91.py' if name=='edge-readmission.py' else 'cycle4_edge_qualification_3dae7d91.py')).read_bytes())
        for row in self.files.values():
            self.assertEqual(Path(row['local']).stat().st_mode & 0o777, 0o600)
            self.assertTrue(row['remote'].startswith((r.WORK, r.INSTALL)))
            compile(Path(row['local']).read_bytes(),row['local'],'exec')

    def test_wrong_prior_and_reused_output_fail_before_creation(self):
        with self.assertRaisesRegex(RuntimeError,'exact_consumed_cycle4'):
            r.render(Path(self.temp.name)/'wrong','0'*64,r.PREVIOUS_MANIFEST_SHA)
        self.assertFalse((Path(self.temp.name)/'wrong').exists())
        with self.assertRaisesRegex(RuntimeError,'fresh_private_output'):
            r.render(self.output,r.PREVIOUS_CONTROLLER_SHA,r.PREVIOUS_MANIFEST_SHA)

    def test_history_source_shapes_are_per_cycle_and_never_truncated(self):
        for history in self.u.HISTORIES:
            name=history['name'];special=self.u.HISTORY_SPECIAL_NAMES[name];sources=self.u.HISTORY_SOURCE_NAMES[name]
            self.assertEqual((len(special),len(sources)),(8,21) if name=='cycle4' else (6,20))
        self.assertIn('edge-readmission.py',self.u.HISTORY_SPECIAL_NAMES['cycle4'])
        self.assertNotIn('edge-readmission.py',self.u.HISTORY_SPECIAL_NAMES['cycle3'])
        tree=ast.parse(Path(self.files['upgrade-controller.py']['local']).read_text())
        functions=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('history_metadata_paths','history_metadata_hashes')]
        for fn in functions:
            self.assertIn('HISTORY_SPECIAL_NAMES',ast.unparse(fn))
        self.assertIn('4*1024**3',Path(self.files['upgrade-controller.py']['local']).read_text())

    def test_probe_and_assessment_output_scopes_are_fresh(self):
        common=Path(self.files['acceptance_common.py']['local']).read_text()
        self.assertIn('/tmp/devres-public-probe-3dae7d91-cycle5-20261118',common)
        assessment=Path(self.files['npm-recovery.py']['local']).read_text()
        self.assertIn("POD='devres-npm-assessment-3dae7d91-c5'",assessment)
        self.assertIn("APP='devres-npm-assessment'",assessment)
        self.assertNotIn(r.PREVIOUS_WORK,assessment)
        lifecycle=Path(self.files['deploy.py']['local']).read_text()
        self.assertIn("'migration-before-npm'",lifecycle)
        self.assertNotIn("stage('baseline'",lifecycle)

    def test_dependency_union_is_exact37_and_rejects_38th_or_substitution(self):
        path=Path(self.files['physical-checkpoint.py']['local']);tree=ast.parse(path.read_text())
        funcs=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='cycle5_dependency_union']
        env={'P':Path,'need':lambda ok,code:None if ok else (_ for _ in ()).throw(RuntimeError(code))}
        exec(compile(ast.Module(funcs,type_ignores=[]),str(path),'exec'),env)
        previous={f'/usr/local/libexec/previous-{i}.py':'a'*64 for i in range(29)}
        manifest={name:'b'*64 for name in self.u.C5_SPECIAL_NAMES}
        expected=env['cycle5_dependency_union'](previous,manifest)
        self.assertEqual(len(expected),37);self.assertTrue(previous.items()<=expected.items())
        with self.assertRaisesRegex(RuntimeError,'exact_previous_dependencies'):
            env['cycle5_dependency_union']({**previous,'/usr/local/libexec/extra.py':'a'*64},manifest)
        collision={**previous};collision.pop(next(iter(collision)));collision[r.PREVIOUS_INSTALL+'/edge-readmission.py']='x'*64
        with self.assertRaisesRegex(RuntimeError,'collision'):env['cycle5_dependency_union'](collision,manifest)
        source=ast.unparse(next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='checked_dependencies'))
        self.assertIn("public.get('dependency_sources') == expected",source)
        self.assertNotIn('<= 32',source)


class RestoredPreparation(Rendering):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='cycle5-prepare-',dir='/tmp');self.addCleanup(self.tmp.cleanup)
        self.top=Path(self.tmp.name);self.bundle=self.top/'new-bundle'
        self.cluster=Cluster(self.u)
        for role in self.u.ROLES:self.cluster.objects[('deployment',role)]['spec']['template']['spec']['containers'][0]['image']=self.u.IMAGE
        for role,(name,key) in self.u.ROLES.items():
            text=self.u.configuration(self.cluster.config(role),False).replace(self.u.SOURCE_URL,self.u.fallback_source_url())
            self.cluster.objects[('secret',name)]['data'][key]=base64.b64encode(text.encode()).decode()
        self.c=self.u.Controller.__new__(self.u.Controller);self.c.root=self.bundle;self.c.context='default';self.c.plan_raw=None
        self.c.old=self.cluster;self.c.get=self.cluster.get;self.c.locked=contextlib.nullcontext;self.c.storage_guard=Mock()
        self.c.prior_hashes=lambda:{'all-four-histories':'retained'}
        protected=lambda:{'boot':{},'edge':{},'foundation':self.cluster.foundation(),'profiles':{},'edge_conf_tree':{}}
        self.c.prior_controller=SimpleNamespace(protected_snapshot=protected,edge=lambda:{},boot=lambda:{},profiles=lambda:{},
            prior_controller=SimpleNamespace(safety=Mock(),verify_edge_admission=Mock()))
        edge=patch.object(self.u,'cycle4_edge_bridge',return_value=(SimpleNamespace(native_guard=lambda _:{'edge':{}}),self.u.C5_EDGE_SHA))
        edge.start();self.addCleanup(edge.stop)
        self.previous_state={'revision':self.u.REVISION,'runtime':'restored','phase':'withdrawn','configs':'old',
            'pods':self.c.pods(),'images':{'postgres':self.u.PG_IMAGE,'writer':self.u.IMAGE,'backend':self.u.IMAGE},
            'replicas':{'postgres':1,'writer':0,'backend':0}}
        self.previous=SimpleNamespace(guard=Mock(),state=lambda:copy.deepcopy(self.previous_state),snapshot=lambda:self.c.snapshot())
        prior=patch.object(self.u,'cycle5_previous_controller',return_value=self.previous);prior.start();self.addCleanup(prior.stop)
        prior_bundle=self.top/'frozen-cycle4';prior_bundle.mkdir(mode=0o700)
        original={role:self.cluster.config(role) for role in self.u.ROLES}
        self.u.save(prior_bundle/'configs-fallback-active.json',original)
        self.u.save(prior_bundle/'prepared.json',{'config_hashes':{'fallback-active':self.u.digest(self.u.encoded(original))}})
        loc=patch.object(self.u,'C5_PREVIOUS_BUNDLE',prior_bundle);loc.start();self.addCleanup(loc.stop)

    def test_prepares_original_p3_as_new_p1_with49_templates_and_active_settings(self):
        self.c.prepare();prepared=self.u.load(self.bundle/'prepared.json');state=self.c.state()
        self.assertEqual(prepared['old_pods'],self.previous_state['pods'])
        self.assertEqual(prepared['initial_images'],self.previous_state['images'])
        self.assertEqual(state['images'],self.previous_state['images'])
        self.assertEqual((state['phase'],state['configs']),('prepared','old'))
        self.assertEqual(self.u.load(self.bundle/'plan.json')['cycle'],5)
        import tomllib
        desired=self.u.load(self.bundle/'configs-active.json')
        self.assertTrue(all(tomllib.loads(text)[p]['enabled'] for text in desired.values() for p in self.u.PROVIDERS))
        self.assertFalse((self.top/'frozen-cycle4/operational-baseline.json').exists())
        self.c.guard()
        # Direct apply cannot adopt the new PG or write accepted-backup until baseline exists.
        with patch.object(self.u._Cycle4BaseController,'run') as old_run:
            with self.assertRaisesRegex(RuntimeError,'pre_upgrade_operational_baseline_required'):
                self.c.run('apply',None,None)
            old_run.assert_not_called()
        self.assertFalse((self.bundle/'accepted-backup.json').exists())

    def test_original_mixed_provider_and_advisory_flags_survive_preparation(self):
        import re
        import tomllib
        prior = self.top/'frozen-cycle4'
        desired = self.u.load(prior/'configs-fallback-active.json')
        expected = {}
        for index, role in enumerate(self.u.ROLES):
            text = desired[role]
            values = {provider: (i + index) % 2 == 0 for i, provider in enumerate(self.u.PROVIDERS)}
            for provider, enabled in values.items():
                text, count = re.subn(r'(?m)(^\['+provider+r'\]\n(?:(?!\[)[^\n]*\n)*?enabled = )true',
                    lambda m: m[1]+str(enabled).lower(), text)
                self.assertEqual(count, 1)
            text = text.replace('advisories_enabled = true', 'advisories_enabled = false')
            desired[role] = text
            expected[role] = (values, False)
        self.u.save(prior/'configs-fallback-active.json', desired, replace=True)
        self.u.save(prior/'prepared.json', {'config_hashes':{'fallback-active':self.u.digest(self.u.encoded(desired))}}, replace=True)
        self.c.prepare()
        for variant in ('active', 'fallback-active'):
            actual = self.u.load(self.bundle/('configs-'+variant+'.json'))
            for role, text in actual.items():
                parsed = tomllib.loads(text)
                flags, advisory = expected[role]
                self.assertEqual({provider: parsed[provider]['enabled'] for provider in self.u.PROVIDERS}, flags)
                self.assertEqual(parsed['npm']['advisories_enabled'], advisory)
                self.assertEqual(parsed['source']['url'], self.u.SOURCE_URL if variant == 'active' else self.u.fallback_source_url())
        for variant in ('paused', 'fallback-paused'):
            for text in self.u.load(self.bundle/('configs-'+variant+'.json')).values():
                parsed = tomllib.loads(text)
                self.assertFalse(any(parsed[provider]['enabled'] for provider in self.u.PROVIDERS))
                self.assertFalse(parsed['npm']['advisories_enabled'])

    def test_rejects_old91_template_or_nonrestored_prior_before_bundle_creation(self):
        for mode in ('old-image','wrong-runtime','wrong-config'):
            state=copy.deepcopy(self.previous_state)
            if mode=='old-image':self.cluster.objects[('deployment','writer')]['spec']['template']['spec']['containers'][0]['image']=self.u.OLD_IMAGE
            elif mode=='wrong-runtime':self.previous_state['runtime']='fallback'
            else:self.previous_state['configs']='paused'
            with self.subTest(mode=mode),self.assertRaises(RuntimeError):self.c.prepare()
            self.assertFalse(self.bundle.exists());self.previous_state=state
            self.cluster.objects[('deployment','writer')]['spec']['template']['spec']['containers'][0]['image']=self.u.IMAGE


if __name__=='__main__':unittest.main()
