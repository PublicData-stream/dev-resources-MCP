"""Independent runtime/assessment integration checks for generated cycle4 sources."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


adapter=load('runtime_assessment_adapter',ROOT/'deploy/production/cycle4_assessment_3dae7d91.py')
production=load('runtime_assessment_renderer',ROOT/'deploy/production/production.py')
assessment_source=adapter.transform((ROOT/'deploy/production/npm_recovery_1d76fbcc.py').read_text())
RUNTIME_SOURCE=(ROOT/'deploy/production/cycle4_runtime_3dae7d91.py').read_text()
LEGACY=ast.parse((ROOT/'deploy/production/upgrade_1d76fbcc.py').read_text())
LEGACY_CLASS=next(node for node in LEGACY.body if isinstance(node,ast.ClassDef) and node.name=='Controller')


def need(value,code):
    if not value:raise RuntimeError(code)


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def save(path,value,replace=False):
    if path.exists() and not replace:raise RuntimeError('create_new_required')
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    path.write_bytes(value if type(value) is bytes else encoded(value))


class Cluster:
    def __init__(self):self.pods={};self.policies={};self.calls=[]
    def k(self,*args,**kwargs):
        self.calls.append((args,kwargs))
        if args[:3]==('get','pods','-o'):return encoded({'items':list(self.pods.values())})
        if args[:3]==('get','networkpolicies','-o'):return encoded({'items':list(self.policies.values())})
        if args[0]=='create':
            value=json.loads(kwargs['data']);name=value['metadata']['name']
            value['metadata']['uid']='uid-'+name
            if value['kind']=='NetworkPolicy':self.policies[name]=value
            else:self.pods[name]=value
            return b'{}'
        if args[:2]==('delete','--raw'):
            name=args[2].split('/')[-1]
            target=self.policies if '/networkpolicies/' in args[2] else self.pods
            need(json.loads(kwargs['data'])['preconditions']['uid']==target[name]['metadata']['uid'],'uid_changed')
            del target[name];return b'{}'
        if args[0]=='wait':return b''
        raise AssertionError(args)
    def get(self,kind,name):
        if kind=='networkpolicy':return copy.deepcopy(self.policies[name])
        if kind=='pod':return copy.deepcopy(self.pods[name])
        raise AssertionError((kind,name))


def harness(root):
    root=Path(root);work=root/'work';work.mkdir();install=root/'install';install.mkdir()
    bundle=root/'bundle';bundle.mkdir()
    cluster=Cluster()
    settings=production.settings_checked({'node_name':'node','node_ipv4':'192.0.2.10',
        'kube_api_cidrs':['192.0.2.10/32'],'storage_auth':'scaleway_static','apparmor_profile':'devres-runtime'})
    template=next(v['spec']['template'] for v in production.manifests(settings)['items']
        if v['kind']=='Deployment' and v['metadata']['name']=='backend')
    image=template['spec']['containers'][0]['image']
    module=ModuleType('runtime_assessment_controller_'+root.name.replace('-','_'))
    module.__file__=str(install/'upgrade-controller.py');sys.modules[module.__name__]=module
    globals_=module.__dict__
    def foundation():
        return sorted([{'kind':'NetworkPolicy','name':v['metadata']['name'],'uid':v['metadata']['uid'],
            'labels':v['metadata'].get('labels',{}),'spec':v['spec']} for v in cluster.policies.values()],key=lambda x:x['name'])
    class Base:
        def state(self):return self.state_value
        def get(self,kind,name):return cluster.get(kind,name)
        def protected_snapshot(self):return {'foundation':foundation()}
        def mutate(self,label,action):
            save(self.root/('target-'+label+'-intent.json'),{'maximum_attempts':1});action()
    Base.__module__=module.__name__
    globals_.update(Controller=Base,Path=Path,json=json,copy=copy,re=re,sys=sys,importlib=__import__('importlib'),
        tomllib=__import__('tomllib'),require=need,load=lambda p:json.loads(Path(p).read_bytes()),
        read=lambda p:Path(p).read_bytes(),save=save,encoded=encoded,
        digest=lambda body:hashlib.sha256(body).hexdigest(),stamp=lambda:'2026-11-17T00:00:00Z',
        WORK=str(work),IMAGE=image,PG_IMAGE='postgres-pinned',OLD_IMAGE=image,REVISION='3dae7d91',
        VERSION='0.1.0-build.3dae7d91',pod_projection=lambda obj:{'uid':obj['metadata']['uid']},
        Error=RuntimeError)
    # Preserve the actual inherited assessment methods to reveal integration gaps.
    legacy_source=(ROOT/'deploy/production/upgrade_1d76fbcc.py').read_text()
    for name in ('cleanup_maintenance','npm_recovery'):
        node=next(node for node in LEGACY_CLASS.body if isinstance(node,ast.FunctionDef) and node.name==name)
        body=ast.get_source_segment(legacy_source,node)
        body=body.replace('/usr/local/libexec/devres-upgrade-1d76fbcc',str(install))
        namespace={};exec(body,globals_,namespace);setattr(Base,name,namespace[name])
    exec(compile(RUNTIME_SOURCE,module.__file__,'exec'),globals_)
    c=module.Controller();c.root=bundle;c.old=SimpleNamespace(k=cluster.k,settings=lambda:{'node_name':'node'})
    c.state_value={'runtime':'target','configs':'paused','phase':'writer_ready',
        'images':{'postgres':'postgres-pinned','writer':image,'backend':image},
        'replicas':{'postgres':1,'writer':0,'backend':0},'pods':{'postgres':{'uid':'pg-uid'}}}
    save(bundle/'state.json',c.state_value)
    cluster.pods['postgres']={'metadata':{'name':'postgres','uid':'pg-uid','labels':{'app':'postgres'}},
        'spec':{'nodeName':'node','containers':[{'image':'postgres-pinned'}]}}
    helper_body=assessment_source.replace("WORK=Path('/tmp/devres-upgrade-1d76fbcc-20261115')",'WORK=Path('+repr(str(work))+')')
    (install/'npm-recovery.py').write_text(helper_body)
    helper_path=work/'deploy/diagnostics/npm_assessment.py';helper_path.parent.mkdir(parents=True)
    helper_path.write_bytes((ROOT/'deploy/diagnostics/npm_assessment.py').read_bytes())
    manifest={'npm-recovery.py':hashlib.sha256(helper_body.encode()).hexdigest(),
              'deploy/diagnostics/npm_assessment.py':hashlib.sha256(helper_path.read_bytes()).hexdigest()}
    save(work/'source-manifest.json',manifest)
    return c,cluster,module,template,work,install


class RuntimeAssessment(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.c,self.cluster,self.module,self.template,self.work,self.install=harness(self.temp.name)
    def admission(self):
        helper=self.c.helper('npm-recovery.py','runtime_assessment_bound_helper')
        helper.install_network(self.c)
        pod=helper.assessment_pod(self.template,self.c.state()['images']['backend'])
        save(self.c.root/'npm-assessment-pod-admission.json',{'name':helper.POD,'pod':pod})
        current=copy.deepcopy(pod);current['metadata']['uid']='assessment-uid';current['spec']['nodeName']='node'
        self.cluster.pods[helper.POD]=current
        save(self.c.root/'npm-assessment-pod-identity.json',{'name':helper.POD,'uid':'assessment-uid'})
        return helper,current
    def test_exact_admitted_assessment_is_not_counted_as_application_role(self):
        self.admission()
        self.assertEqual(self.c.pods(),{'postgres':{'uid':'pg-uid'}})
    def test_unadmitted_foreign_assessment_pod_is_rejected(self):
        self.cluster.pods['foreign']={'metadata':{'name':'foreign','uid':'foreign','labels':{'app':'devres-npm-assessment'}},
            'spec':{'nodeName':'node','containers':[{'image':self.c.state()['images']['backend']}]}}
        with self.assertRaises(RuntimeError):self.c.pods()
    def test_admitted_name_with_changed_uid_image_or_mount_is_rejected(self):
        helper,pod=self.admission()
        for mutate in (lambda v:v['metadata'].update(uid='replacement'),
                       lambda v:v['spec']['containers'][0].update(image='foreign'),
                       lambda v:v['spec']['volumes'][0]['secret'].update(secretName='writer-secret')):
            value=copy.deepcopy(pod);mutate(value);self.cluster.pods[helper.POD]=value
            with self.subTest(value=value),self.assertRaises(RuntimeError):self.c.pods()
    def test_assessment_runtime_rejects_unadmitted_node_network_or_process_authority(self):
        helper,pod=self.admission()
        variants=(('wrong-node',lambda v:v['spec'].update(nodeName='foreign-node')),
            ('host-network',lambda v:v['spec'].update(hostNetwork=True)),
            ('host-pid',lambda v:v['spec'].update(hostPID=True)),
            ('host-ipc',lambda v:v['spec'].update(hostIPC=True)),
            ('privileged',lambda v:v['spec']['containers'][0]['securityContext'].update(privileged=True)),
            ('env-secret',lambda v:v['spec']['containers'][0].update(envFrom=[{'secretRef':{'name':'devres-writer-s3'}}])))
        for name,mutate in variants:
            value=copy.deepcopy(pod);mutate(value);self.cluster.pods[helper.POD]=value
            with self.subTest(name=name),self.assertRaises(RuntimeError):self.c.pods()
    def test_network_only_partial_admission_is_cleaned_without_pod_admission(self):
        helper=self.c.helper('npm-recovery.py','runtime_assessment_cleanup_helper')
        helper.install_network(self.c)
        self.assertFalse((self.c.root/'npm-assessment-pod-admission.json').exists())
        self.c.cleanup_maintenance()
        self.assertEqual(self.cluster.policies,{})
    def test_protected_snapshot_normalizes_only_validated_temporary_policies(self):
        helper=self.c.helper('npm-recovery.py','runtime_assessment_snapshot_helper');helper.install_network(self.c)
        self.assertEqual(self.c.protected_snapshot(),{'foundation':[]})
        name=helper.ASSESSMENT_POLICIES[0]
        self.cluster.policies[name]['metadata']['uid']='replacement'
        with self.assertRaisesRegex(RuntimeError,'uid_changed'):self.c.protected_snapshot()
    def test_helper_source_is_checked_before_import_and_module_registered(self):
        helper=self.c.helper('npm-recovery.py','runtime_assessment_registration')
        self.assertIs(sys.modules['runtime_assessment_registration'],helper)
        path=self.install/'npm-recovery.py';path.write_text("raise AssertionError('must_not_execute')\n")
        with self.assertRaisesRegex(RuntimeError,'helper_source_changed'):
            self.c.helper('npm-recovery.py','runtime_assessment_tampered')
        self.assertNotIn('runtime_assessment_tampered',sys.modules)
    def test_maintained_helper_source_is_checked_before_import(self):
        helper=self.c.helper('npm-recovery.py','runtime_assessment_maintained_pin')
        path=self.work/'deploy/diagnostics/npm_assessment.py'
        path.write_text("raise AssertionError('must_not_execute')\n")
        with self.assertRaisesRegex(RuntimeError,'helper_source_changed'):helper.maintained()


class OperationalControllerRegistration(unittest.TestCase):
    def test_actual_generated_operational_loader_registers_before_controller_execution(self):
        acceptance=load('runtime_assessment_acceptance_adapter',ROOT/'deploy/production/cycle4_acceptance_3dae7d91.py')
        original=(ROOT/'deploy/production/acceptance_1d76fbcc/operational-proof.py').read_text()
        transformed=acceptance.transform('operational-proof.py',original)
        node=next(node for node in ast.parse(transformed).body if isinstance(node,ast.FunctionDef) and node.name=='bound_module')
        body=ast.get_source_segment(transformed,node)
        context={'need':need,'re':re,'sha':lambda b:hashlib.sha256(b).hexdigest(),
                 'raw':lambda p:Path(p).read_bytes(),'importlib':__import__('importlib'),'sys':sys}
        exec(body,context)
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            path=Path(temporary)/'controller.py'
            path.write_text('import importlib\nregistered=importlib.import_module(__name__)\n')
            module=context['bound_module'](path,hashlib.sha256(path.read_bytes()).hexdigest(),'cycle4_operational_registration')
            self.assertIs(module,sys.modules['cycle4_operational_registration'])


    def test_actual_generated_receipt_loader_registers_before_controller_execution(self):
        acceptance=load('runtime_assessment_receipt_adapter',ROOT/'deploy/production/cycle4_acceptance_3dae7d91.py')
        original=(ROOT/'deploy/production/acceptance_1d76fbcc/acceptance-receipt.py').read_text()
        transformed=acceptance.transform('acceptance-receipt.py',original)
        node=next(node for node in ast.parse(transformed).body if isinstance(node,ast.FunctionDef) and node.name=='source_module')
        body=ast.get_source_segment(transformed,node)
        def code_sha(path,expected):
            need(hashlib.sha256(Path(path).read_bytes()).hexdigest()==expected,'source_hash_mismatch')
        context={'need':need,'code_sha':code_sha,'importlib':__import__('importlib'),'sys':sys}
        exec(body,context)
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            path=Path(temporary)/'controller.py'
            path.write_text('import importlib\nregistered=importlib.import_module(__name__)\n')
            module=context['source_module'](path,hashlib.sha256(path.read_bytes()).hexdigest(),'cycle4_receipt_registration')
            self.assertIs(module,sys.modules['cycle4_receipt_registration'])


if __name__=='__main__':unittest.main()
