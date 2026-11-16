"""Fresh-cycle rendering and withdrawn-preimage admission; no cluster/provider I/O."""
import ast
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
r=module('cycle2_renderer',ROOT/'deploy/production/cycle2_1d76fbcc.py')
f=module('cycle2_original_fixture',ROOT/'scripts/tests/test_upgrade_1d76fbcc.py')

def private(path,value):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    body=value if isinstance(value,bytes) else r.encoded(value)
    path.write_bytes(body);path.chmod(0o600);return r.digest(body)

class Rendered(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output=tempfile.TemporaryDirectory(prefix='cycle2-render-tests-',dir='/tmp')
        cls.top=Path(cls.output.name)
        cls.files=r.render(cls.top/'render')
        cls.u=module('rendered_cycle2_controller',cls.top/'render/upgrade-controller.py')
    @classmethod
    def tearDownClass(cls):cls.output.cleanup()

class Rendering(Rendered):
    def test_deterministic_immutable_sources_and_fresh_output(self):
        other=r.render(self.top/'second-render')
        self.assertEqual(set(other),set(r.SOURCE_MAP))
        self.assertEqual((self.top/'render/render-manifest.json').read_bytes(),
                         (self.top/'second-render/render-manifest.json').read_bytes())
        for name,entry in self.files.items():
            self.assertEqual(Path(entry['local']).read_bytes(),Path(other[name]['local']).read_bytes())
            self.assertEqual(entry['source_sha256'],r.digest(r.base_source(entry['source'])))
            self.assertEqual(entry['remote'],str(Path(r.INSTALL if name in r.SPECIAL_NAMES else r.WORK)/name))
            self.assertEqual(Path(entry['local']).stat().st_mode&0o777,0o600)
        with self.assertRaisesRegex(r.RenderError,'fresh_render_directory'):r.render(self.top/'render')
        with self.assertRaisesRegex(r.RenderError,'unreviewed_source_path'):r.base_source('README.md')

    def test_exact_rebases_leave_predecessor_authority_intact(self):
        u=self.u
        self.assertEqual(u.WORK,r.WORK);self.assertEqual(u.BUNDLE,r.BUNDLE)
        self.assertEqual(str(u.PREVIOUS_WORK),r.OLD_WORK)
        self.assertEqual(str(u.PREVIOUS_BUNDLE),r.OLD_BUNDLE)
        self.assertEqual(str(u.PREVIOUS_CONTROLLER),r.OLD_INSTALL+'/upgrade-controller.py')
        self.assertEqual(u.PRIOR_CONTROLLER,f.u.PRIOR_CONTROLLER)
        self.assertEqual(u.PRIOR_BUNDLE,f.u.PRIOR_BUNDLE)
        original=ast.parse(r.base_source(r.SPECIAL_NAMES['upgrade-controller.py']))
        generated=ast.parse(Path(self.files['upgrade-controller.py']['local']).read_bytes())
        before=next(n for n in original.body if isinstance(n,ast.FunctionDef) and n.name=='predecessor')
        after=next(n for n in generated.body if isinstance(n,ast.FunctionDef) and n.name=='predecessor')
        self.assertEqual(ast.dump(before,include_attributes=False),ast.dump(after,include_attributes=False))
        common=Path(self.files['acceptance_common.py']['local']).read_text()
        for directory in r.PROBE_DIRECTORIES.values():
            self.assertIn(directory,common);self.assertEqual(Path(directory).parent,Path('/tmp'))
        npm=Path(self.files['npm-recovery.py']['local']).read_text()
        self.assertIn("POD='devres-npm-assessment-1d76fbcc-cycle2'",npm)
        self.assertEqual(npm.count("'1d76fbcc-cycle2-assessment'"),2)
        self.assertNotIn("'1d76fbcc-assessment'",npm)
        self.assertIn("Path('/var/lib/devres-production-preparation/a938112b-7c7a24f')",
                      Path(self.files['store-claim.py']['local']).read_text())

    def test_writer_rehearsal_preserves_original_capacity_and_fences(self):
        cp=module('rendered_cycle2_checkpoint',self.top/'render/physical-checkpoint.py')
        original=f.module('cycle2_checkpoint_fixture',ROOT/'scripts/tests/test_checkpoint_1d76fbcc.py').Fixtures.config(None)
        original=original.replace('devres_reader:','devres_writer:').replace('cache_max_bytes=34359738368','cache_max_bytes=68719476736')
        original=original[:original.index('[writer_client]')]+('[writer_listener]\nbind="0.0.0.0:9443"\n'
            '[writer_listener.auth]\nkube_api_url="https://kubernetes.default.svc"\nkube_token_file="/run/writer/token"\nkube_ca_file="/run/writer/ca"\n')
        before=cp.tomllib.loads(original);after=cp.tomllib.loads(cp.writer_config(original))
        self.assertEqual(after['storage']['s3']['cache_max_bytes'],68719476736)
        self.assertEqual(after['storage'],before['storage'])
        self.assertTrue(all(after[p]['enabled'] is False for p in cp.PROVIDERS))
        self.assertFalse(after['npm']['advisories_enabled'])
        self.assertEqual(after['writer_listener']['bind'],'127.0.0.1:9443')
        self.assertEqual(after['writer_listener']['auth']['kube_api_url'],'https://127.0.0.1:9')
        self.assertIn('no-authority-token',after['writer_listener']['auth']['kube_token_file'])

    def test_operational_baseline_uses_desired_and_records_actual(self):
        source=Path(self.files['operational-proof.py']['local']).read_text()
        function=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='baseline')
        fields=next(n for n in ast.walk(function) if isinstance(n,ast.Dict)
                    and any(isinstance(k,ast.Constant) and k.value=='collectors' for k in n.keys))
        expressions={key.value:value for key,value in zip(fields.keys,fields.values) if isinstance(key,ast.Constant)}
        state={'configs':'old'}
        def source_flags(controller,value):return ({'all':value['configs']=='active'},None)
        environment={'source_flags':source_flags,'controller':object(),'state':state}
        def evaluate(name):return eval(compile(ast.Expression(expressions[name]),'<baseline>','eval'),environment)
        self.assertEqual(evaluate('collectors'),{'all':True})
        self.assertEqual(evaluate('observed_preimage_collectors'),{'all':False})
        self.assertEqual(state,{'configs':'old'})

class Admission(Rendered):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='cycle2-admission-',dir='/tmp');self.addCleanup(self.temporary.cleanup)
        self.base=Path(self.temporary.name);self.base.chmod(0o700);u=self.u
        self.previous_root=self.base/'previous';self.previous_root.mkdir(mode=0o700)
        for target,name,value in [(f.old.u,'OLD_IMAGE',u.OLD_IMAGE),(f.old,'config',f.config)]:
            item=patch.object(target,name,value);item.start();self.addCleanup(item.stop)
        self.cluster=f.old.FakeCluster(self.base)
        for role in u.ROLES:
            self.cluster.deployments[role]['spec']['replicas']=0;self.cluster.live_pods.pop(role)
            name,key=u.ROLES[role]
            text=u.configuration(f.config(),False).replace(u.SOURCE_URL,u.fallback_source_url())
            self.cluster.secrets[name]['data'][key]=base64.b64encode(text.encode()).decode()
        c=u.Controller.__new__(u.Controller);self.c=c;c.root=self.base/'new';c.context='default';c.plan_raw=None;c.old=self.cluster
        c.get=lambda kind,name:json.loads(self.cluster.k('get',kind,name,'-o','json'))
        c.protected_snapshot=lambda:{'boot':'same','edge':'same','foundation':[],'profiles':{},'edge_conf_tree':{}}
        c.prior_hashes=lambda:{'frozen':'same'};c.storage_guard=Mock()
        c.prior_controller=SimpleNamespace(prior_controller=SimpleNamespace(safety=Mock(),verify_edge_admission=Mock()))
        snap=c.snapshot()
        self.before={'revision':u.REVISION,'runtime':'fallback','phase':'withdrawn','configs':'paused',
                     'replicas':{'postgres':1,'writer':0,'backend':0},'pods':snap['pods']}
        self.previous=SimpleNamespace(guard=Mock(),state=lambda:copy.deepcopy(self.before),snapshot=c.snapshot)
        desired={role:f.config() for role in u.ROLES}
        active_hash=private(self.previous_root/'configs-fallback-active.json',desired)
        private(self.previous_root/'prepared.json',{'config_hashes':{'fallback-active':active_hash}})
        for name,value in [('previous_cycle',lambda context:self.previous),('PREVIOUS_BUNDLE',self.previous_root)]:
            item=patch.object(u,name,value);item.start();self.addCleanup(item.stop)

    def test_current_paused_preimage_and_original_active_flags_remain_distinct(self):
        u=self.u;self.c.prepare()
        prepared=u.load(self.c.root/'prepared.json');state=self.c.state()
        self.assertEqual(state['configs'],'old');self.assertEqual(state['phase'],'prepared')
        self.assertEqual(prepared['secrets'],self.c.snapshot()['secrets'])
        self.assertTrue(all(not u.tomllib.loads(text)[p]['enabled'] for text in self.c.configurations().values() for p in u.PROVIDERS))
        for variant in ('active','fallback-active'):
            values=u.load(self.c.root/('configs-'+variant+'.json'))
            self.assertTrue(all(u.tomllib.loads(text)[p]['enabled'] for text in values.values() for p in u.PROVIDERS))
            self.assertTrue(all(u.tomllib.loads(text)['npm']['advisories_enabled'] for text in values.values()))
        active=u.load(self.c.root/'configs-active.json')['backend']
        self.assertEqual(u.tomllib.loads(active)['writer_client']['endpoint'],'https://writer.devres.svc:9443/v1/acquire')
        self.c.storage_guard.assert_called_once_with(18,owner=False)
        self.assertEqual(self.previous.guard.call_count,2)
        self.previous.guard.side_effect=RuntimeError('must not revisit consumed runtime after admission')
        self.c.guard()
        self.assertEqual(self.previous.guard.call_count,2)
        self.assertFalse(any(call[0][0] in ('patch','scale','delete','apply') for call in self.cluster.calls))

    def test_wrong_predecessor_phase_runtime_or_config_aborts_before_admission(self):
        for field,value in [('phase','complete'),('runtime','target'),('configs','active')]:
            old=self.before[field];self.before[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(self.u.Error,'withdrawn_previous_cycle_required'):self.c.prepare()
            self.assertFalse(self.c.root.exists());self.before[field]=old

    def test_changed_desired_active_or_current_pg_aborts(self):
        self.before['pods']={'postgres':{'uid':'foreign'}}
        with self.assertRaisesRegex(self.u.Error,'previous_cycle_runtime_changed'):self.c.prepare()
        self.before['pods']=self.c.snapshot()['pods']
        private(self.previous_root/'configs-fallback-active.json',{'backend':'changed','writer':'changed'})
        with self.assertRaisesRegex(self.u.Error,'previous_desired_active_config_changed'):self.c.prepare()
        self.assertFalse(self.c.root.exists())

    def test_guard_failure_or_changed_chain_cannot_create_admission(self):
        self.previous.guard.side_effect=RuntimeError('old boundary changed')
        with self.assertRaisesRegex(RuntimeError,'old boundary changed'):self.c.prepare()
        self.assertFalse(self.c.root.exists());self.previous.guard.side_effect=None
        self.c.prior_hashes=Mock(side_effect=[{'one':'before'},{'one':'after'}])
        with self.assertRaisesRegex(self.u.Error,'prepare_runtime_changed'):self.c.prepare()
        self.assertFalse(self.c.root.exists())

class History(Rendered):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='cycle2-history-',dir='/tmp');self.addCleanup(self.temporary.cleanup)
        self.base=Path(self.temporary.name);self.base.chmod(0o700)
        self.work=self.base/'work';self.bundle=self.base/'bundle';self.install=self.base/'install'
        for path in (self.work,self.bundle,self.install):path.mkdir(mode=0o700)
        u=self.u
        for name,value in [('PREVIOUS_WORK',self.work),('PREVIOUS_BUNDLE',self.bundle),('PREVIOUS_CONTROLLER',self.install/'upgrade-controller.py')]:
            item=patch.object(u,name,value);item.start();self.addCleanup(item.stop)
        manifest={}
        for name in (*u.PREVIOUS_SPECIAL_NAMES,*u.PREVIOUS_SOURCE_NAMES):
            path=self.install/name if name in u.PREVIOUS_SPECIAL_NAMES else self.work/name
            manifest[name]=private(path,b'first-party '+name.encode())
        manifest_hash=private(self.work/'source-manifest.json',manifest)
        item=patch.object(u,'PREVIOUS_MANIFEST_SHA',manifest_hash);item.start();self.addCleanup(item.stop)
        for name in ('state.json','prepared.json','plan.json','configs-paused.json','configs-active.json',
                     'configs-fallback-paused.json','configs-fallback-active.json','restore/restored.json'):
            private(self.bundle/name,{'name':name})
        private(self.work/'target/command-evidence/npm/result.json',{'failed':True})
        private(self.work/'target/operational-proofs/migration/observation.json',{'schema':19})
        private(self.work/'target/command-evidence/npm/stdout.log',b'bounded first-party status\n')
        private(self.work/'target/command-evidence/npm/stderr.log',b'forbidden: hostPath\n')
        private(self.work/'target/command-evidence/npm/runtime.jsonl',b'{"exit":1}\n')

    def test_streams_large_manifests_and_excludes_corpus_recursion(self):
        u=self.u
        data=b'a'*(9*1024**2);private(self.work/'checkpoint-state/cache-baselines.json',data)
        excluded=self.work/'checkpoint-state/fallback-cache/writer/packages/deep.json'
        private(excluded,b'not first-party journal');excluded.chmod(0o644)
        first=u.cycle2_metadata_hashes()
        self.assertEqual(first[str(self.work/'checkpoint-state/cache-baselines.json')],hashlib.sha256(data).hexdigest())
        self.assertNotIn(str(excluded),first)
        excluded.write_bytes(b'package changes do not masquerade as journal history')
        self.assertEqual(first,u.cycle2_metadata_hashes())
        self.assertIn(str(self.work/'target/command-evidence/npm/result.json'),first)

    def test_empty_public_directory_and_new_journal_change_inventory(self):
        u=self.u;before=u.cycle2_metadata_hashes()
        (self.work/'target/paused-public').mkdir(mode=0o700)
        self.assertNotEqual(before,u.cycle2_metadata_hashes())
        private(self.bundle/'new-intent.json',{'intent':'cannot be hidden'})
        self.assertIn(str(self.bundle/'new-intent.json'),u.cycle2_metadata_hashes())

    def test_captured_failure_bytes_are_bound_without_checkpoint_jsonl(self):
        u=self.u
        private(self.work/'terminal.log',b'withdrawn\n')
        private(self.work/'target/terminal.log',b'failed\n')
        private(self.work/'target/operational-proofs/migration/query.log',b'bounded query status\n')
        excluded=self.work/'checkpoint-state/archive-bindings.jsonl'
        private(excluded,b'large archive inventory already receipt-bound');excluded.chmod(0o644)
        before=u.cycle2_metadata_hashes()
        self.assertNotIn(str(excluded),before)
        for name in ('stdout.log','stderr.log','runtime.jsonl'):
            path=self.work/'target/command-evidence/npm'/name
            with self.subTest(name=name):
                self.assertIn(str(path),before)
                original=path.read_bytes();private(path,original+b'changed terminal evidence\n')
                self.assertNotEqual(before,u.cycle2_metadata_hashes())
                private(path,original)
                self.assertEqual(before,u.cycle2_metadata_hashes())
        for path in (self.work/'terminal.log',self.work/'target/terminal.log',
                     self.work/'target/operational-proofs/migration/query.log'):
            self.assertIn(str(path),before)

    def test_actual_manifest_source_drift_is_rejected(self):
        private(self.install/'npm-recovery.py',b'drift')
        with self.assertRaisesRegex(self.u.Error,'previous_source_changed'):self.u.cycle2_metadata_hashes()

    def test_journal_hardlink_symlink_and_public_mode_rejected(self):
        path=self.bundle/'state.json';alias=self.base/'alias';os.link(path,alias)
        with self.assertRaisesRegex(self.u.Error,'previous_private_journal_required'):self.u.cycle2_metadata_hashes()
        alias.unlink();path.chmod(0o644)
        with self.assertRaisesRegex(self.u.Error,'previous_private_journal_required'):self.u.cycle2_metadata_hashes()
        path.chmod(0o600);(self.bundle/'foreign.json').symlink_to(path)
        with self.assertRaisesRegex(self.u.Error,'previous_journal_symlink'):self.u.cycle2_metadata_hashes()

if __name__=='__main__':unittest.main()
