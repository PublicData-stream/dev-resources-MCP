"""Real startup and cancellation of generated cycle2 sources, entirely under /tmp."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

REPO=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('independent_cycle2_renderer',REPO/'deploy/production/cycle2_1d76fbcc.py')
renderer=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(renderer)


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


class GeneratedCycleBootstrap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='cycle2-rendered-fixtures-',dir='/tmp')
        cls.top=Path(cls.temporary.name);cls.top.chmod(0o700)
        cls.generated=renderer.render(cls.top/'rendered')
        cls.render_manifest=json.loads((cls.top/'rendered/render-manifest.json').read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='cycle2-startup-',dir='/tmp')
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.work=self.root/'work';self.work.mkdir(mode=0o700)
        self.install=self.root/'install';self.install.mkdir(mode=0o700)
        self.bundle=self.root/'bundle';self.bundle.mkdir(mode=0o700)
        # Only fixture locations are rebound. All executable bodies originate in
        # render(), including its exact sitecustomize and descendant lifetime code.
        replacements={renderer.WORK:str(self.work),renderer.BUNDLE:str(self.bundle),renderer.INSTALL:str(self.install),
                      renderer.PROBE_DIRECTORIES['target']:str(self.root/'public-target'),
                      renderer.PROBE_DIRECTORIES['fallback']:str(self.root/'public-fallback')}
        self.paths={}
        for name,item in self.generated.items():
            body=Path(item['local']).read_text()
            for original,replacement in sorted(replacements.items(),key=lambda pair:-len(pair[0])):
                body=body.replace(original,replacement)
            path=(self.install if name in renderer.SPECIAL_NAMES else self.work)/name
            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            path.write_text(body);path.chmod(0o600);self.paths[name]=path
        for name in ('target-native-qualification.json','fallback-native-qualification.json'):
            path=self.work/name;path.write_text('{"fixture":true}');path.chmod(0o600);self.paths[name]=path
        self.manifest={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in self.paths.items()}
        self.manifest_path=self.work/'source-manifest.json'
        self.manifest_path.write_text(json.dumps(self.manifest,sort_keys=True));self.manifest_path.chmod(0o600)
        self.manifest_sha=hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        self.env=patch.dict(os.environ,{'DEVRES_ACCEPTANCE_RUNTIME':'target',
            'DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256':self.manifest_sha},clear=False)
        self.env.start()
        os.environ.pop('DEVRES_ACCEPTANCE_PARENT_PID',None)
        os.environ.pop('DEVRES_ACCEPTANCE_SUBPROCESS_GUARD',None)
        self.original_common=sys.modules.get('acceptance_common')
        self.common=load(self.paths['acceptance_common.py'],'acceptance_common')
        self.deploy=load(self.paths['deploy.py'],'generated_cycle2_deploy')
        self.runner=load(self.paths['runner.py'],'generated_cycle2_runner')
        self.npm=load(self.paths['npm-recovery.py'],'generated_cycle2_npm')
        self.common.WORK.mkdir(mode=0o700)
        (self.common.WORK/'command-evidence').mkdir(mode=0o700)
        self.probe=self.work/'startup-probe.py'
        self.probe.write_text('''import importlib.util,json,os,sys
preloaded='acceptance_common' in sys.modules
import acceptance_common as c
before=c.RUNTIME
spec=importlib.util.spec_from_file_location('cycle2_actual_bootstrap',__file__.replace('startup-probe.py','deploy.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
print(json.dumps({'preloaded':preloaded,'runtime_before':before,'runtime':c.RUNTIME,
    'environment':os.environ.get('DEVRES_ACCEPTANCE_RUNTIME'),'root':str(c.ROOT),'work':str(c.WORK),
    'bundle':str(c.BUNDLE),'controller':str(c.CONTROLLER),'probe':c.IDENTITY['probe_directory'],
    'version':c.VERSION,'schema':c.SCHEMA,'source_url':c.SOURCE_URL,
    'guard':getattr(__import__('subprocess').Popen,'_devres_parent_guard',False),
    'parent_matches':int(os.environ['DEVRES_ACCEPTANCE_PARENT_PID'])==os.getppid()},sort_keys=True))
''')
        self.probe.chmod(0o600)

    def tearDown(self):
        if self.original_common is None:sys.modules.pop('acceptance_common',None)
        else:sys.modules['acceptance_common']=self.original_common
        self.env.stop();self.tmp.cleanup()

    def test_manifest_covers_every_rendered_source_with_new_remote_destinations(self):
        expected=set(self.common.SOURCE_NAMES)|set(self.common.SPECIAL_NAMES)
        self.assertEqual(set(self.paths),expected)
        self.assertEqual(len(self.generated),24)
        self.assertEqual(self.common.manifest_sources(self.manifest_sha),self.manifest)
        self.assertEqual(self.render_manifest['base_commit'],renderer.BASE_COMMIT)
        self.assertEqual(set(self.render_manifest['files']),set(self.generated))
        for name,item in self.generated.items():
            remote=Path(renderer.INSTALL if name in renderer.SPECIAL_NAMES else renderer.WORK)/name
            self.assertEqual(item['remote'],str(remote))
            self.assertEqual(self.render_manifest['files'][name]['sha256'],hashlib.sha256(Path(item['local']).read_bytes()).hexdigest())
            self.assertEqual(item['source_sha256'],hashlib.sha256(renderer.base_source(item['source'])).hexdigest())

    def test_runtime_helpers_have_no_unintended_cycle1_work_or_install_references(self):
        allowed={renderer.OLD_WORK,renderer.OLD_BUNDLE,renderer.OLD_INSTALL+'/upgrade-controller.py'}
        for name,item in self.generated.items():
            tree=ast.parse(Path(item['local']).read_text())
            previous=[]
            for node in ast.walk(tree):
                if not isinstance(node,ast.Constant) or not isinstance(node.value,str):continue
                value=node.value
                if renderer.OLD_WORK in value or renderer.OLD_BUNDLE in value or renderer.OLD_INSTALL+'/' in value:
                    previous.append(value)
            if name=='upgrade-controller.py':self.assertEqual(set(previous),allowed)
            else:self.assertEqual(previous,[],name)
        self.assertEqual(self.render_manifest['scope']['probe_directories'],renderer.PROBE_DIRECTORIES)
        self.assertTrue(all(Path(v).parent==Path('/tmp') for v in renderer.PROBE_DIRECTORIES.values()))

    def test_actual_generated_target_startup_imports_guarded_new_scope(self):
        result=subprocess.run(self.common.parent_command([sys.executable,'-B',str(self.probe),'--runtime','target']),
                              capture_output=True,timeout=8)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        value=json.loads(result.stdout)
        self.assertTrue(value['preloaded']);self.assertTrue(value['guard']);self.assertTrue(value['parent_matches'])
        self.assertEqual(value['runtime_before'],'target');self.assertEqual(value['runtime'],'target')
        self.assertEqual(value['root'],str(self.work));self.assertEqual(value['work'],str(self.work/'target'))
        self.assertEqual(value['bundle'],str(self.bundle));self.assertEqual(value['controller'],str(self.install/'upgrade-controller.py'))
        self.assertEqual(value['probe'],str(self.root/'public-target'));self.assertEqual(value['schema'],19)
        self.assertEqual(value['version'],'0.1.0-build.1d76fbcc')

    def test_actual_generated_fallback_launch_selects_runtime_before_sitecustomize(self):
        state={'runtime':'fallback','phase':'complete','pods':{'postgres':{}}}
        controller=Mock();controller.locked.side_effect=contextlib.nullcontext;controller.state.side_effect=lambda:dict(state)
        supervisor=types.SimpleNamespace(private_save=self.runner.private_save,parent_bound_command=self.runner.parent_bound_command)
        self.assertTrue(self.deploy.supervise_fallback(controller,supervisor,
            [sys.executable,'-B',str(self.probe),'--runtime','fallback'],timeout=8))
        value=json.loads((self.common.WORK/'command-evidence/deploy-fallback/stdout.log').read_bytes())
        self.assertTrue(value['preloaded']);self.assertTrue(value['guard']);self.assertTrue(value['parent_matches'])
        self.assertEqual(value['runtime_before'],'fallback');self.assertEqual(value['runtime'],'fallback')
        self.assertEqual(value['environment'],'fallback');self.assertEqual(value['root'],str(self.work))
        self.assertEqual(value['work'],str(self.work/'fallback'));self.assertEqual(value['probe'],str(self.root/'public-fallback'))
        self.assertEqual(value['version'],'0.1.0-build.91c7bcb7');self.assertEqual(value['schema'],18)
        self.assertEqual(value['source_url'],'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.91c7bcb7/source.tar.gz')
        self.assertEqual(os.environ['DEVRES_ACCEPTANCE_RUNTIME'],'target');self.assertEqual(self.common.RUNTIME,'target')
        controller.withdraw.assert_not_called()

    def test_changed_generated_helper_is_rejected_before_a_child_launch(self):
        self.paths['npm-recovery.py'].write_text('# changed after admission\n')
        with self.assertRaisesRegex(RuntimeError,'acceptance_source_changed'):
            self.common.manifest_sources(self.manifest_sha)
        self.assertFalse((self.common.WORK/'command-evidence/blocked').exists())

    @staticmethod
    def collect(recorder,stop):
        recorder.record('pod',{'role':'postgres','ready':True,'restarts':0})
        while not stop.wait(.02):pass

    def test_generated_descendant_cancellation_releases_actual_lifecycle_lock(self):
        import fcntl
        lock=self.root/'lifecycle.lock';ready=self.root/'descendant.pid';fenced=self.root/'fenced'
        inner='import fcntl,os,time;from pathlib import Path;f=open('+repr(str(lock))+',"a");fcntl.flock(f.fileno(),fcntl.LOCK_EX);Path('+repr(str(ready))+').write_text(str(os.getpid()));time.sleep(30)'
        middle='import subprocess,sys,time;subprocess.Popen([sys.executable,"-B","-c",'+repr(inner)+'],start_new_session=True);time.sleep(30)'
        outer='import subprocess,sys,time;subprocess.Popen([sys.executable,"-B","-c",'+repr(middle)+'],start_new_session=True);time.sleep(30)'
        def fence():
            deadline=time.monotonic()+2
            with lock.open('a') as stream:
                while True:
                    try:fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB);break
                    except BlockingIOError:
                        if time.monotonic()>deadline:return False
                        time.sleep(.01)
            fenced.write_text('withdrawal lock acquired');return True
        try:
            with contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(RuntimeError,'acceptance_stage_failed'):
                self.runner.run_stage('lifetime',[sys.executable,'-B','-c',outer],2,self.collect,fence)
            self.assertTrue(ready.exists(),'real generated nested child never reached the lock')
            self.assertTrue(fenced.exists())
            value=json.loads((self.common.WORK/'command-evidence/lifetime/final-result.json').read_bytes())
            self.assertTrue(value['supervision']['withdrawal_completed'])
            self.assertTrue(value['supervision']['timed_out'])
        finally:
            if ready.exists():
                try:os.kill(int(ready.read_text()),signal.SIGKILL)
                except ProcessLookupError:pass

    def backend_template(self):
        module=load(REPO/'deploy/production/production.py','cycle2_template_fixture')
        settings=module.settings_checked({'node_name':'node','node_ipv4':'192.0.2.10',
            'kube_api_cidrs':['10.43.0.1/32','192.0.2.10/32'],'storage_auth':'scaleway_static'})
        return next(v['spec']['template'] for v in module.manifests(settings)['items']
                    if v['kind']=='Deployment' and v['metadata']['name']=='backend')

    def test_generated_maintenance_pod_is_restricted_and_unique_to_cycle2(self):
        template=self.backend_template();image=template['spec']['containers'][0]['image']
        pod=self.npm.assessment_pod(template,image)
        self.assertEqual(pod['metadata']['name'],'devres-npm-assessment-1d76fbcc-cycle2')
        self.assertEqual(pod['metadata']['labels']['devres-rollout'],'1d76fbcc-cycle2-assessment')
        self.assertEqual({v['name'] for v in pod['spec']['volumes']},{'config','s3','tmp'})
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        self.assertNotIn('hostPath',json.dumps(pod));self.assertNotIn('persistentVolumeClaim',json.dumps(pod))
        self.assertNotIn('projected',json.dumps(pod))
        self.assertEqual(pod['spec']['securityContext']['runAsUser'],65532)
        self.assertEqual(pod['spec']['securityContext']['seccompProfile'],{'type':'RuntimeDefault'})
        self.assertEqual(self.npm.REPORT,'/tmp/npm-assessment/report.json')

    def cleanup_case(self,marker):
        template=self.backend_template();image=template['spec']['containers'][0]['image']
        expected=self.npm.assessment_pod(template,image)
        expected['spec']['nodeSelector']={'kubernetes.io/hostname':'node'}
        current=copy.deepcopy(expected);current['metadata']['uid']='cycle2-owned-uid'
        current['metadata']['labels']['devres-rollout']=marker;current['spec']['nodeName']='node'
        admission=self.bundle/'npm-assessment-pod-admission.json'
        admission.write_text(json.dumps({'name':self.npm.POD,'pod':expected}));admission.chmod(0o600)
        k=Mock(side_effect=[json.dumps({'items':[current]}).encode(),b'{}',b''])
        controller=types.SimpleNamespace(root=self.bundle,old=types.SimpleNamespace(k=k,settings=lambda:{'node_name':'node'}))
        api=types.SimpleNamespace(load=lambda p:json.loads(p.read_bytes()),encoded=lambda v:json.dumps(v).encode())
        return controller,api,k

    def test_generated_cleanup_uses_cycle2_marker_and_uid_delete(self):
        controller,api,k=self.cleanup_case('1d76fbcc-cycle2-assessment')
        with patch('importlib.import_module',return_value=api):self.npm.cleanup(controller)
        self.assertEqual(k.call_args_list[1].args[2],'/api/v1/namespaces/devres/pods/devres-npm-assessment-1d76fbcc-cycle2')
        self.assertEqual(json.loads(k.call_args_list[1].kwargs['data'])['preconditions'],{'uid':'cycle2-owned-uid'})

    def test_generated_cleanup_refuses_cycle1_marker_before_delete(self):
        controller,api,k=self.cleanup_case('1d76fbcc-assessment')
        with patch('importlib.import_module',return_value=api),self.assertRaisesRegex(RuntimeError,'maintenance_cleanup_identity_changed'):
            self.npm.cleanup(controller)
        self.assertEqual(k.call_count,1)


if __name__=='__main__':unittest.main()
