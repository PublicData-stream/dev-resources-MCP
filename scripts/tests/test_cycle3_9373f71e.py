"""Fresh-cycle rendering and withdrawn-preimage admission; no cluster/provider I/O."""
import ast
import base64
import copy
import hashlib
import importlib.util
import json
import datetime as dt
import sys
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
r=module('cycle3_renderer',ROOT/'deploy/production/cycle3_9373f71e.py')
f=module('cycle2_original_fixture',ROOT/'scripts/tests/test_upgrade_1d76fbcc.py')

def private(path,value):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    body=value if isinstance(value,bytes) else r.encoded(value)
    path.write_bytes(body);path.chmod(0o600);return r.digest(body)

class Rendered(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output=tempfile.TemporaryDirectory(prefix='cycle3-render-tests-',dir='/tmp')
        cls.top=Path(cls.output.name)
        cls.files=r.render(cls.top/'render')
        cls.u=module('rendered_cycle3_controller',cls.top/'render/upgrade-controller.py')
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
        self.assertEqual(str(u.PREVIOUS_WORK),r.HISTORIES[-1]['work'])
        self.assertEqual(str(u.PREVIOUS_BUNDLE),r.HISTORIES[-1]['bundle'])
        self.assertEqual(str(u.PREVIOUS_CONTROLLER),r.HISTORIES[-1]['install']+'/upgrade-controller.py')
        self.assertEqual(u.PREVIOUS_REVISION,r.PREVIOUS_REVISION);self.assertNotEqual(u.PREVIOUS_REVISION,u.REVISION)
        self.assertEqual(u.REVISION,r.TARGET_REVISION);self.assertEqual(u.IMAGE,r.TARGET_IMAGE)
        self.assertEqual(u.PROBE_IMAGE,r.TARGET_PROBE);self.assertEqual(u.VERSION,r.TARGET_VERSION)
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
        self.assertIn("POD='devres-npm-assessment-9373f71e'",npm)
        self.assertEqual(npm.count("'9373f71e-assessment'"),2)
        self.assertNotIn("'1d76fbcc-assessment'",npm)
        self.assertIn("Path('/var/lib/devres-production-preparation/a938112b-7c7a24f')",
                      Path(self.files['store-claim.py']['local']).read_text())

    def test_writer_rehearsal_preserves_original_capacity_and_fences(self):
        cp=module('rendered_cycle3_checkpoint',self.top/'render/physical-checkpoint.py')
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

def retained_config():
    return f.config().replace('[crates]\n','[crates]\nstatic_requests_per_second=3\nmax_git_bytes=68719476736\n').replace(
        '[npm]\n','[npm]\nregistry_requests_per_second=3\nadvisory_requests_per_second=2\n').replace(
        '[wikipedia]\n','[wikipedia]\nrequests_per_second=2\nuser_agent="ExampleBot/1.0 (https://example.org/bot; operator@example.org)"\n')

class Admission(Rendered):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='cycle3-admission-',dir='/tmp');self.addCleanup(self.temporary.cleanup)
        self.base=Path(self.temporary.name);self.base.chmod(0o700);u=self.u
        self.previous_root=self.base/'previous';self.previous_root.mkdir(mode=0o700)
        for target,name,value in [(f.old.u,'OLD_IMAGE',u.OLD_IMAGE),(f.old,'config',retained_config)]:
            item=patch.object(target,name,value);item.start();self.addCleanup(item.stop)
        self.cluster=f.old.FakeCluster(self.base)
        for role in u.ROLES:
            self.cluster.deployments[role]['spec']['replicas']=0;self.cluster.live_pods.pop(role)
            name,key=u.ROLES[role]
            text=u.configuration(retained_config(),False).replace(u.SOURCE_URL,u.fallback_source_url())
            self.cluster.secrets[name]['data'][key]=base64.b64encode(text.encode()).decode()
        c=u.Controller.__new__(u.Controller);self.c=c;c.root=self.base/'new';c.context='default';c.plan_raw=None;c.old=self.cluster
        c.get=lambda kind,name:json.loads(self.cluster.k('get',kind,name,'-o','json'))
        c.protected_snapshot=lambda:{'boot':'same','edge':'same','foundation':[],'profiles':{},'edge_conf_tree':{}}
        c.prior_hashes=lambda:{'frozen':'same'};c.storage_guard=Mock()
        c.prior_controller=SimpleNamespace(prior_controller=SimpleNamespace(safety=Mock(),verify_edge_admission=Mock()))
        snap=c.snapshot()
        self.before={'revision':u.PREVIOUS_REVISION,'runtime':'fallback','phase':'withdrawn','configs':'paused',
                     'replicas':{'postgres':1,'writer':0,'backend':0},'pods':snap['pods']}
        self.previous=SimpleNamespace(guard=Mock(),state=lambda:copy.deepcopy(self.before),snapshot=c.snapshot)
        desired={role:retained_config() for role in u.ROLES}
        active_hash=private(self.previous_root/'configs-fallback-active.json',desired)
        private(self.previous_root/'prepared.json',{'config_hashes':{'fallback-active':active_hash}})
        for name,value in [('previous_cycle',lambda context:self.previous),('PREVIOUS_BUNDLE',self.previous_root)]:
            item=patch.object(u,name,value);item.start();self.addCleanup(item.stop)

    def test_current_paused_preimage_and_original_active_flags_remain_distinct(self):
        u=self.u;before={path:path.read_bytes() for path in self.previous_root.rglob('*') if path.is_file()}
        self.c.prepare()
        self.assertEqual(before,{path:path.read_bytes() for path in self.previous_root.rglob('*') if path.is_file()})
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
        expected=u.tomllib.loads(retained_config());expected['source']['url']=u.SOURCE_URL
        self.assertEqual(u.tomllib.loads(active),expected)
        self.c.storage_guard.assert_called_once_with(18,owner=False)
        self.assertEqual(self.previous.guard.call_count,2)
        self.previous.guard.side_effect=RuntimeError('must not revisit consumed runtime after admission')
        self.c.guard()
        self.assertEqual(self.previous.guard.call_count,2)
        self.assertFalse(any(call[0][0] in ('patch','scale','delete','apply') for call in self.cluster.calls))

    def test_wrong_predecessor_phase_runtime_or_config_aborts_before_admission(self):
        for field,value in [('phase','complete'),('runtime','target'),('configs','active'),('revision',self.u.REVISION)]:
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


class MethodIdentity(Rendered):
    def test_only_reviewed_methods_floors_and_template_changes_are_rendered(self):
        source=r.rebase(r.base_source(r.SPECIAL_NAMES['upgrade-controller.py']))
        source=source.replace('len(rows) >= 31','len(rows) >= 32').replace("accepted['sample_count'] >= 31","accepted['sample_count'] >= 32")
        before=next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef) and n.name=='Controller')
        after=next(n for n in ast.parse(Path(self.files['upgrade-controller.py']['local']).read_bytes()).body if isinstance(n,ast.ClassDef) and n.name=='Controller')
        old={n.name:n for n in before.body if isinstance(n,ast.FunctionDef)}
        new={n.name:n for n in after.body if isinstance(n,ast.FunctionDef)}
        self.assertEqual(set(old),set(new))
        for name in set(old)-{'prepare','prior_hashes'}:
            with self.subTest(method=name):self.assertEqual(ast.dump(old[name]),ast.dump(new[name]))
        special={'upgrade-controller.py','physical-checkpoint.py','operational-proof.py','acceptance-receipt.py','npm-recovery.py'}
        for name,path in r.SOURCE_MAP.items():
            if name not in special:
                self.assertEqual(Path(self.files[name]['local']).read_bytes(),r.rebase(r.base_source(path)).encode(),name)
        cp_before=ast.parse(r.rebase(r.base_source(r.SPECIAL_NAMES['physical-checkpoint.py'])))
        cp_after=ast.parse(Path(self.files['physical-checkpoint.py']['local']).read_bytes())
        methods=lambda tree:{n.name:ast.dump(n) for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=methods(cp_before),methods(cp_after)
        self.assertEqual({k:v for k,v in a.items() if k!='writer_config'},{k:v for k,v in b.items() if k!='writer_config'})
        with self.assertRaisesRegex(r.RenderError,'unreviewed_logical_source'):r.transform('unreviewed.py',b'')

    def test_current_observability_and_all_source_identity_pins_are_selected(self):
        npm=Path(self.files['npm-recovery.py']['local']).read_text()
        self.assertIn('def assessment_failure_metadata(',npm);self.assertIn('trace is not None or len(frames)>4',npm)
        private_source=Path(self.files['target-private-acceptance.py']['local']).read_text()
        self.assertIn('def failure_metadata(',private_source);self.assertIn('def traced_client(',private_source)
        common=module('cycle3_common_identity',self.top/'render/acceptance_common.py')
        self.assertEqual(common.RUNTIME,'target');self.assertEqual(common.REVISION,r.TARGET_REVISION)
        self.assertEqual(common.RUNTIMES['target']['source_sha256'],r.TARGET_SOURCE_SHA)
        self.assertEqual(common.RUNTIMES['target']['probe_image'],r.TARGET_PROBE)
        self.assertEqual(common.RUNTIMES['fallback']['revision'],self.u.FALLBACK_REVISION)
        cp=module('cycle3_cp_identity',self.top/'render/physical-checkpoint.py')
        self.assertEqual(cp.RESERVE,128*1024**3);self.assertEqual(cp.PV,Path('/database/devres/corpus'))
        self.assertEqual(cp.REV,r.TARGET_REVISION)
        self.assertIn(r.CHECKPOINT_SCOPE,Path(cp.__file__).read_text())
        self.assertNotIn('physical-pg-checkpoint-1d76fbcc',Path(cp.__file__).read_text())
        self.assertEqual(r.BASE_COMMIT,'9373f71e06936970b4a8dc4ca30584b9d464a5b9')

    def test_render_rejects_existing_symlink_and_non_tmp_scope(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as d:
            root=Path(d);(root/'real').mkdir();(root/'link').symlink_to(root/'real')
            with self.assertRaisesRegex(r.RenderError,'owned_temporary'):r.render(root/'link/new')
        with self.assertRaisesRegex(r.RenderError,'owned_temporary'):r.render(Path('/var/lib/unowned-render'))
        with self.assertRaisesRegex(r.RenderError,'owned_temporary'):r.render(Path('/tmp/../unowned-render'))

class History(Rendered):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='cycle3-history-',dir='/tmp');self.addCleanup(self.temporary.cleanup)
        self.base=Path(self.temporary.name);self.base.chmod(0o700);records=[]
        for item in r.HISTORIES:
            root=self.base/item['name'];root.mkdir(mode=0o700)
            work,bundle,install=[root/name for name in ('work','bundle','install')]
            for path in (work,bundle,install):path.mkdir(mode=0o700)
            manifest={}
            for name in (*self.u.PREVIOUS_SPECIAL_NAMES,*self.u.PREVIOUS_SOURCE_NAMES):
                path=install/name if name in self.u.PREVIOUS_SPECIAL_NAMES else work/name
                manifest[name]=private(path,item['name'].encode()+b' source '+name.encode())
            msha=private(work/'source-manifest.json',manifest)
            for name in ('state.json','prepared.json','plan.json','configs-paused.json','configs-active.json',
                         'configs-fallback-paused.json','configs-fallback-active.json','restore/restored.json'):
                private(bundle/name,{'name':name})
            private(work/'target/command-evidence/npm/result.json',{'failed':True})
            private(work/'target/command-evidence/npm/stdout.log',b'bounded first-party status\n')
            private(work/'target/command-evidence/npm/stderr.log',b'closed failure\n')
            private(work/'target/command-evidence/npm/runtime.jsonl',b'{"exit":1}\n')
            records.append({**item,'work':str(work),'bundle':str(bundle),'install':str(install),
                            'controller_sha256':manifest['upgrade-controller.py'],'manifest_sha256':msha})
        self.records=tuple(records)
        patcher=patch.object(self.u,'HISTORIES',self.records);patcher.start();self.addCleanup(patcher.stop)

    def test_both_histories_and_all_old_actual_sources_are_bound(self):
        before=self.u.history_metadata_hashes()
        for history in self.records:
            work,bundle,install=Path(history['work']),Path(history['bundle']),Path(history['install'])
            self.assertIn(str(work/'source-manifest.json'),before)
            for name in (*self.u.PREVIOUS_SPECIAL_NAMES,*self.u.PREVIOUS_SOURCE_NAMES):
                path=install/name if name in self.u.PREVIOUS_SPECIAL_NAMES else work/name
                self.assertEqual(before[str(path)],r.digest(path.read_bytes()))
            path=bundle/'state.json';raw=path.read_bytes();private(path,{'changed':True})
            self.assertNotEqual(before,self.u.history_metadata_hashes());private(path,raw)
        self.assertEqual(before,self.u.history_metadata_hashes())

    def test_changed_source_or_manifest_in_either_chain_is_rejected(self):
        for history in self.records:
            path=Path(history['install'])/'npm-recovery.py';raw=path.read_bytes();private(path,b'drift')
            with self.assertRaisesRegex(self.u.Error,'previous_source_changed'):self.u.history_metadata_hashes()
            private(path,raw)
            path=Path(history['work'])/'source-manifest.json';raw=path.read_bytes();private(path,{})
            with self.assertRaisesRegex(self.u.Error,'previous_cycle_manifest_changed'):self.u.history_metadata_hashes()
            private(path,raw)

    def test_large_manifest_stream_and_diagnostic_metadata_exclude_private_or_pg_trees(self):
        work=Path(self.records[-1]['work']);data=b'x'*(9*1024**2)
        private(work/'checkpoint-state/cache-baselines.json',data)
        root=work/'diagnostic-state/npm-real-graph-v3'
        private(root/'diagnostic-result.json',{'complete':False});private(root/'stderr.log',b'closed diagnostic failure')
        private(root/'report-frame.bin',b'closed metadata report frame');private(work/'diagnostic-drivers/npm-v3.py',b'first-party source')
        excluded=[root/'pg/base/body.json',root/'files/secret-key',work/'checkpoint-state/archive-bindings.jsonl',
                  work/'checkpoint-state/fallback-cache/writer/package/body.json']
        for path in excluded:private(path,b'excluded fixture');path.chmod(0o644)
        before=self.u.history_metadata_hashes()
        self.assertEqual(before[str(work/'checkpoint-state/cache-baselines.json')],r.digest(data))
        for path in excluded:self.assertNotIn(str(path),before);path.write_bytes(b'changed excluded fixture')
        self.assertEqual(before,self.u.history_metadata_hashes())
        for path in (root/'stderr.log',root/'report-frame.bin',work/'diagnostic-drivers/npm-v3.py'):
            raw=path.read_bytes();private(path,raw+b'changed');self.assertNotEqual(before,self.u.history_metadata_hashes());private(path,raw)

    def test_new_empty_public_directory_or_diagnostic_scope_changes_inventory(self):
        before=self.u.history_metadata_hashes();work=Path(self.records[-1]['work'])
        (work/'target/paused-public').mkdir(mode=0o700)
        self.assertNotEqual(before,self.u.history_metadata_hashes())
        before=self.u.history_metadata_hashes();(work/'diagnostic-state').mkdir(mode=0o700)
        (work/'diagnostic-state/npm-real-graph-v4').mkdir(mode=0o700)
        self.assertNotEqual(before,self.u.history_metadata_hashes())

    def test_hardlink_symlink_and_nonprivate_old_journal_fail_closed(self):
        path=Path(self.records[-1]['bundle'])/'state.json';alias=self.base/'alias';os.link(path,alias)
        with self.assertRaisesRegex(self.u.Error,'previous_private_journal_required'):self.u.history_metadata_hashes()
        alias.unlink();path.chmod(0o644)
        with self.assertRaisesRegex(self.u.Error,'previous_private_journal_required'):self.u.history_metadata_hashes()
        path.chmod(0o600);(path.parent/'foreign.json').symlink_to(path)
        with self.assertRaisesRegex(self.u.Error,'previous_journal_symlink'):self.u.history_metadata_hashes()

class ObservationFloors(Rendered):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='cycle3-floors-',dir='/tmp');self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.root.chmod(0o700)

    def test_controller_artifact_consumer_rejects31_and_accepts32_actual_samples(self):
        u=self.u;state={'runtime':'target','configs':'active','prepared_sha256':'a'*64,
                       'pods':{'postgres':{},'writer':{},'backend':{}}}
        c=u.Controller.__new__(u.Controller);c.state=lambda:copy.deepcopy(state);c.receipt_fresh=Mock()
        for count in (31,32):
            rows=[{'pods':state['pods'],'configs':'active','schema':19,'policy':2,'monotonic':i*30,
                   'writer_owner':{'role':'devres_writer','client_addr':'192.0.2.10'}} for i in range(count)]
            observation=self.root/('observation-'+str(count)+'.json');osha=private(observation,{'samples':rows})
            value={'version':1,'kind':'target-observation-acceptance','prepared_sha256':state['prepared_sha256'],
                'revision':u.REVISION,'verified':True,'store_binding_sha256':u.STORE_BINDING,'runtime':'target',
                'runtime_revision':u.REVISION,'processes':state['pods'],'configs':'active','observation_artifact':str(observation),
                'artifacts':[{'path':str(observation),'sha256':osha}]}
            path=self.root/('receipt-'+str(count)+'.json');h=private(path,value)
            if count==31:
                with self.assertRaisesRegex(u.Error,'observation_runtime_binding'):c.receipt(path,h,'target-observation-acceptance',())
            else:self.assertEqual(c.receipt(path,h,'target-observation-acceptance',())[0],value)

    def test_controller_finish_dispatch_rejects31_and_accepts32(self):
        u=self.u
        for count in (31,32):
            root=self.root/str(count);root.mkdir(mode=0o700)
            state={'phase':'collectors_active','runtime':'target'}
            c=u.Controller.__new__(u.Controller);c.root=root;c.state=lambda:copy.deepcopy(state)
            c.record=lambda value:state.update(value);c.approval=Mock();c.guard=Mock();c.receipt_fresh=Mock()
            accepted={'schema':19,'duration_seconds':900,'sample_count':count,'maximum_gap_seconds':30}
            c.receipt=Mock(return_value=(accepted,b'{}'))
            if count==31:
                with self.assertRaisesRegex(u.Error,'observation_interval'):c.run('finish','unused','unused')
                self.assertEqual(state['phase'],'collectors_active')
            else:c.run('finish','unused','unused');self.assertEqual(state['phase'],'complete')

    def test_receipt_aggregator_rejects31_accepts32_and_keeps_actual_time_and_gap_gates(self):
        common=module('cycle3_floor_common',self.top/'render/acceptance_common.py')
        with patch.dict(sys.modules,{'acceptance_common':common}):
            m=module('cycle3_floor_aggregator',self.top/'render/acceptance-receipt.py')
        end=dt.datetime.now(dt.timezone.utc)
        for count,period,error in ((31,30,'observation_sample_count'),(32,30,None),(32,20,'observation_actual_duration'),(32,46,'observation_sample_gap')):
            samples=[{'monotonic':i*period,'observed_at':(end-dt.timedelta(seconds=(count-1-i)*period)).isoformat(),
                      'database':{'capture_count':i,'archive_files':1}} for i in range(count)]
            items=[{'path':str(self.root/'operational-proofs'/str(i)/'observation.json'),'sha256':'a'*64} for i in range(count)]
            completed={'verified':True,'revision':r.TARGET_REVISION,'sources':{'compression':'c'*64},'samples':items,
                       'sample_count':count,'duration_seconds':(count-1)*period,'maximum_gap_seconds':period}
            def read(op,path,artifacts):return completed if path.name=='completed.json' else samples[int(path.parent.name)]
            with patch.object(m,'WORK',self.root),patch.object(m,'read_artifact',side_effect=read),patch.object(m,'code_sha'),patch.object(m,'validate_sample'),patch.object(m,'frozen_projection',return_value={}):
                if error:
                    with self.assertRaisesRegex(RuntimeError,error):m.observation_set(None,'observed',{},None,[],'c'*64)
                else:self.assertEqual(m.observation_set(None,'observed',{},None,[],'c'*64)['sample_count'],32)

if __name__=='__main__':unittest.main()
