"""Fresh assessment adapter uses maintained supervision and isolated authority."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
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


adapter=load('cycle4_assessment_adapter',ROOT/'deploy/production/cycle4_assessment_3dae7d91.py')
maintained=load('cycle4_assessment_maintained',ROOT/'deploy/diagnostics/npm_assessment.py')
runtime_tree=ast.parse((ROOT/'deploy/production/cycle4_runtime_3dae7d91.py').read_text())
runtime_validator=next(node for node in runtime_tree.body if isinstance(node,ast.FunctionDef) and node.name=='admitted_pod_spec')
def runtime_need(value,code):
    if not value:raise RuntimeError(code)
validator_namespace={'require':runtime_need}
exec(ast.get_source_segment((ROOT/'deploy/production/cycle4_runtime_3dae7d91.py').read_text(),runtime_validator),validator_namespace)
source=adapter.transform((ROOT/'deploy/production/npm_recovery_1d76fbcc.py').read_text())
n=ModuleType('cycle4_generated_assessment');n.__file__='/tmp/generated-assessment.py'
sys.modules[n.__name__]=n;exec(compile(source,n.__file__,'exec'),n.__dict__)


def backend_template():
    renderer=load('cycle4_assessment_production',ROOT/'deploy/production/production.py')
    settings=renderer.settings_checked({'node_name':'node','node_ipv4':'192.0.2.10',
        'kube_api_cidrs':['10.43.0.1/32','192.0.2.10/32'],'storage_auth':'scaleway_static',
        'apparmor_profile':'devres-runtime'})
    return next(value['spec']['template'] for value in renderer.manifests(settings)['items']
                if value['kind']=='Deployment' and value['metadata']['name']=='backend')


def full_report(reason='legacy_unknown'):
    return {'version':1,'job_id':n.JOB,'revision':1,'recipe':'npm-materialization-deadline-v1',
        'state_digest':'blake3:'+'a'*64,'eligible':False,'outcome':'ineligible','reason':reason,
        'operation_id':None,'publication_snapshot':None}


def frame(reason='legacy_unknown'):
    body=json.dumps(full_report(reason)).encode()+b'\n'
    return (f'65532:600:1:{len(body)}:regular file\n'.encode()+maintained.FRAME+body+
            maintained.PHASE_FRAME+b'1\tcli_start\tstart\tnone\t0\t-\n')


class FakeController:
    def __init__(self,root):
        self.root=Path(root);self.policies={};self.pods={};self.calls=[];self.writes=[]
        self.template=backend_template();self.image=self.template['spec']['containers'][0]['image']
        self.old=SimpleNamespace(k=self.k,settings=lambda:{'node_name':'node'})
        self.state_value={'runtime':'target','phase':'writer_ready','configs':'paused',
                          'images':{'backend':self.image}}
        self.api=SimpleNamespace(admitted_pod_spec=validator_namespace['admitted_pod_spec'],
            save=self.save,load=lambda p:json.loads(p.read_bytes()),
            encoded=lambda value:json.dumps(value).encode(),stamp=lambda:'2026-11-17T00:00:00Z',
            digest=lambda body:hashlib.sha256(body).hexdigest())
    def save(self,path,value,replace=False):
        if path.exists() and not replace:raise RuntimeError('create_new_required')
        path.parent.mkdir(parents=True,exist_ok=True)
        body=value if type(value) is bytes else json.dumps(value).encode()
        if path.name=='report.json':
            if self.pods or any(name in self.policies for name in n.ASSESSMENT_POLICIES):
                raise AssertionError('persist_before_cleanup')
        path.write_bytes(body);self.writes.append(path.name)
    def locked(self):return contextlib.nullcontext()
    def guard(self):n.network_guard(self)
    def state(self):return self.state_value
    def storage_guard(self,schema,owner):self.calls.append(('storage',schema,owner))
    def scale(self,role,count,label):self.calls.append(('scale',role,count,label))
    def mutate(self,label,fn):
        self.save(self.root/('target-'+label+'-intent.json'),{'maximum_attempts':1})
        fn()
    def get(self,kind,name):
        if kind=='deployment':return {'spec':{'template':self.template}}
        if kind=='networkpolicy':return copy.deepcopy(self.policies[name])
        if kind=='pod':return copy.deepcopy(self.pods[name])
        raise AssertionError((kind,name))
    def k(self,*args,**kwargs):
        self.calls.append(args)
        if args[:3]==('get','networkpolicies','-o'):return json.dumps({'items':list(self.policies.values())}).encode()
        if args[:3]==('get','pods','-o'):return json.dumps({'items':list(self.pods.values())}).encode()
        if args[0]=='create':
            value=json.loads(kwargs['data']);name=value['metadata']['name']
            value['metadata']['uid']='00000000-0000-0000-0000-000000000001' if value['kind']=='Pod' else 'uid-'+name
            if value['kind']=='NetworkPolicy':self.policies[name]=value
            else:
                value['spec']['nodeName']='node'
                value['status']={'phase':'Running','containerStatuses':[{'restartCount':0,
                    'containerID':'containerd://owned','state':{'running':{}}}]}
                self.pods[name]=value
            return b'{}'
        if args[:2]==('delete','--raw'):
            name=args[2].split('/')[-1];target=self.policies if '/networkpolicies/' in args[2] else self.pods
            options=json.loads(kwargs['data'])
            if target[name]['metadata']['uid']!=options['preconditions']['uid']:raise RuntimeError('uid_precondition')
            del target[name];return b'{}'
        if args[0]=='wait':return b''
        raise AssertionError(args)


class PodTests(unittest.TestCase):
    def test_maintained_restricted_pod_has_dedicated_label_and_only_reader_inputs(self):
        template=backend_template();image=template['spec']['containers'][0]['image']
        with patch.object(n,'maintained',return_value=maintained):pod=n.assessment_pod(template,image)
        self.assertEqual(pod['metadata']['labels'],{'app':n.ASSESSMENT_APP,'devres-assessment':n.ASSESSMENT_SCOPE})
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        self.assertEqual([v['name'] for v in pod['spec']['volumes']],['config','s3','tmp'])
        self.assertEqual(pod['spec']['containers'][0]['terminationMessagePolicy'],'File')
        self.assertNotIn('projected',json.dumps(pod));self.assertNotIn('persistentVolumeClaim',json.dumps(pod))
        self.assertNotIn('hostPath',json.dumps(pod));self.assertNotIn('ports',pod['spec']['containers'][0])
        self.assertEqual(template,backend_template())
    def test_wrong_image_writer_key_and_unconfined_apparmor_are_rejected(self):
        for change in ('image','secret','apparmor'):
            template=backend_template();image=template['spec']['containers'][0]['image']
            if change=='image':image='foreign'
            elif change=='secret':next(v for v in template['spec']['volumes'] if v['name']=='s3')['secret']['secretName']='devres-writer-s3'
            else:template['spec']['securityContext']['appArmorProfile']={'type':'Unconfined'}
            with self.subTest(change=change),patch.object(n,'maintained',return_value=maintained),self.assertRaises(RuntimeError):
                n.assessment_pod(template,image)
    def test_duplicate_or_missing_legacy_function_refuses_transform(self):
        original=(ROOT/'deploy/production/npm_recovery_1d76fbcc.py').read_text()
        for source in (original+'\ndef assess(c):pass\n',original.replace('def assess(c):','def no_assess(c):')):
            with self.assertRaises(adapter.TransformError):adapter.transform(source)
    def test_private_frame_uses_maintained_metadata_and_phase_validation(self):
        with patch.object(n,'maintained',return_value=maintained):body,value,events=n.decode_report_frame(frame())
        self.assertEqual(value,full_report());self.assertEqual(json.loads(body),value)
        self.assertEqual(events[0]['phase'],'cli_start')


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.directory.cleanup)
        self.c=FakeController(self.directory.name)
        self.module=patch.object(n,'_module',return_value=self.c.api);self.module.start();self.addCleanup(self.module.stop)
    def test_only_dns_and_postgres_egress_and_matching_database_ingress(self):
        policies=n.assessment_network_policies();egress=policies[0]['spec']
        self.assertEqual(egress['podSelector'],{'matchLabels':{'app':n.ASSESSMENT_APP}})
        self.assertNotIn('ingress',egress)
        self.assertIn('Ingress',egress['policyTypes'])
        self.assertEqual([v['ports'] for v in egress['egress']],
            [[{'port':53,'protocol':'UDP'},{'port':53,'protocol':'TCP'}],[{'port':5432,'protocol':'TCP'}]])
        self.assertNotIn('ipBlock',json.dumps(policies));self.assertNotIn('443',json.dumps(policies))
        self.assertEqual(policies[1]['spec']['ingress'][0]['from'][0]['podSelector'],egress['podSelector'])
    def test_existing_backend_policy_does_not_apply_and_exact_inventory_restores(self):
        policy={'metadata':{'name':'backend-boundary','uid':'original','namespace':'devres'},
            'spec':{'podSelector':{'matchLabels':{'app':'backend'}},'policyTypes':['Egress'],
                    'egress':[{'to':[{'ipBlock':{'cidr':'0.0.0.0/0'}}]}]}}
        self.c.policies['backend-boundary']=copy.deepcopy(policy)
        n.install_network(self.c)
        self.assertEqual(n.network_guard(self.c),set(n.ASSESSMENT_POLICIES))
        n.cleanup_network(self.c)
        self.assertEqual(self.c.policies,{'backend-boundary':policy})
        self.assertEqual(n.network_guard(self.c),set())
    def test_additive_broad_egress_is_refused_before_any_mutation(self):
        selectors=({}, {'matchLabels':{'devres-assessment':n.ASSESSMENT_SCOPE}},
                   {'matchExpressions':[{'key':'app','operator':'NotIn','values':['writer']}]} )
        for selector in selectors:
            self.c.policies={'foreign':{'metadata':{'name':'foreign','uid':'old'},'spec':{
                'podSelector':selector,'policyTypes':['Egress'],'egress':[{}]}}}
            with self.subTest(selector=selector),self.assertRaisesRegex(RuntimeError,'inherited_egress'):
                n.install_network(self.c)
        self.assertFalse(self.c.writes)
    def test_replacement_policy_uid_or_spec_cannot_qualify(self):
        n.install_network(self.c)
        name=n.ASSESSMENT_POLICIES[0]
        for field,value in (('uid','replaced'),('spec',{'podSelector':{},'egress':[{}]})):
            original=copy.deepcopy(self.c.policies[name])
            if field=='uid':self.c.policies[name]['metadata']['uid']=value
            else:self.c.policies[name]['spec']=value
            with self.subTest(field=field),self.assertRaises(RuntimeError):n.network_guard(self.c)
            self.c.policies[name]=original
    def test_cleanup_refuses_while_credential_bearing_pod_remains(self):
        n.install_network(self.c)
        self.c.pods['foreign']={'metadata':{'name':'foreign','labels':{'app':n.ASSESSMENT_APP}}}
        with self.assertRaisesRegex(RuntimeError,'pod_absence'):n.cleanup_network(self.c)
        self.assertTrue(set(n.ASSESSMENT_POLICIES)<=set(self.c.policies))
    def test_interrupted_create_without_matching_intent_is_not_admitted(self):
        baseline={};expected={v['metadata']['name']:v for v in n.assessment_network_policies()}
        self.c.save(self.c.root/'npm-assessment-network-admission.json',{'baseline':baseline,'policies':expected})
        self.c.save(self.c.root/'npm-assessment-network-state.json',{'phase':'installing'})
        policy=copy.deepcopy(next(iter(expected.values())));policy['metadata']['uid']='unowned'
        self.c.policies[policy['metadata']['name']]=policy
        with self.assertRaisesRegex(RuntimeError,'create_intent'):n.network_guard(self.c)
    def test_lost_create_response_is_reconciled_once_before_policy_removal(self):
        expected={v['metadata']['name']:v for v in n.assessment_network_policies()}
        self.c.save(self.c.root/'npm-assessment-network-admission.json',{'baseline':{},'policies':expected})
        self.c.save(self.c.root/'npm-assessment-network-state.json',{'phase':'installing'})
        name=n.ASSESSMENT_POLICIES[0]
        self.c.save(self.c.root/('target-npm-assessment-network-create-'+name+'-intent.json'),{'maximum_attempts':1})
        value=copy.deepcopy(expected[name]);value['metadata']['uid']='lost-response-uid'
        self.c.policies[name]=value
        n.cleanup_network(self.c)
        self.assertEqual(self.c.policies,{})
        saved=json.loads((self.c.root/('npm-assessment-network-'+name+'-identity.json')).read_bytes())
        self.assertEqual(saved,{'name':name,'uid':'lost-response-uid'})
        deletions=[call for call in self.c.calls if call[:2]==('delete','--raw')]
        n.cleanup_network(self.c)
        self.assertEqual(len([call for call in self.c.calls if call[:2]==('delete','--raw')]),len(deletions))
    def test_admission_saved_before_state_file_can_clean_without_policy_creation(self):
        expected={v['metadata']['name']:v for v in n.assessment_network_policies()}
        self.c.save(self.c.root/'npm-assessment-network-admission.json',{'baseline':{},'policies':expected})
        n.cleanup_network(self.c)
        self.assertEqual(json.loads((self.c.root/'npm-assessment-network-state.json').read_bytes()),{'phase':'removed'})
    def test_completed_network_scope_allows_later_outer_guarded_observer_policies(self):
        n.install_network(self.c);n.cleanup_network(self.c)
        self.c.policies['observer']={'metadata':{'name':'observer','uid':'later'},'spec':{'podSelector':{}}}
        self.assertEqual(n.network_guard(self.c),set())
        # Its own assessment policies may never reappear after cleanup.
        value=copy.deepcopy(n.assessment_network_policies()[0]);value['metadata']['uid']='later'
        self.c.policies[value['metadata']['name']]=value
        with self.assertRaisesRegex(RuntimeError,'cleanup_incomplete'):n.network_guard(self.c)
    def test_default_deny_and_nonmatching_expressions_do_not_inherit_egress(self):
        self.c.policies={'default-deny':{'metadata':{'name':'default-deny','uid':'old'},
            'spec':{'podSelector':{},'policyTypes':['Ingress','Egress']}}}
        n.install_network(self.c);n.cleanup_network(self.c)
        self.assertEqual(set(self.c.policies),{'default-deny'})


class SupervisionTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.directory.cleanup)
        self.c=FakeController(Path(self.directory.name)/'root');self.c.root.mkdir()
        self.work=Path(self.directory.name)/'work';self.work.mkdir()
        self.patches=[patch.object(n,'_module',return_value=self.c.api),patch.object(n,'WORK',self.work),
            patch.object(n,'maintained',return_value=maintained),patch.object(n,'selection',return_value={
                'job_id':n.JOB,'revision':1,'authoritative':False})]
        for value in self.patches:value.start();self.addCleanup(value.stop)
    def test_one_assessment_leaves_writer_stopped_and_cleans_before_persist(self):
        with patch.object(maintained,'report_exchange',return_value=frame()) as exchange:
            result=n.assess(self.c)
        self.assertEqual(result['reason'],'legacy_unknown')
        self.assertEqual(exchange.call_count,1)
        self.assertEqual([call for call in self.c.calls if call[0]=='scale'],
                         [('scale','writer',0,'npm-assessment-stop-writer')])
        self.assertFalse(self.c.pods);self.assertFalse(self.c.policies)
        completed=json.loads((self.c.root/'npm-assessment-completed.json').read_bytes())
        self.assertEqual(completed['container_id'],'containerd://owned')
        self.assertFalse(completed['cli_report_in_logs'])
        self.assertTrue(completed['phase_known'])
    def test_actual_admitted_authority_is_checked_before_any_report_exchange(self):
        original=self.c.get
        def changed(kind,name):
            value=original(kind,name)
            if kind=='pod':value['spec']['hostNetwork']=True
            return value
        self.c.get=changed
        with patch.object(maintained,'report_exchange') as exchange,self.assertRaisesRegex(RuntimeError,'host_authority'):
            n.assess(self.c)
        exchange.assert_not_called()
        self.assertFalse(self.c.pods);self.assertFalse(self.c.policies)
        self.assertNotIn('npm-assessment-completed.json',self.c.writes)
    def test_initial_unscheduled_pending_becomes_running_without_another_cli(self):
        original=self.c.get;observations=[]
        def pending(kind,name):
            value=original(kind,name)
            if kind=='pod':
                observations.append(value)
                if len(observations)==1:
                    value['spec'].pop('nodeName')
                    value['status']={'phase':'Pending','containerStatuses':[]}
            return value
        self.c.get=pending
        with patch.object(maintained,'report_exchange',return_value=frame()) as exchange:
            result=n.assess(self.c)
        self.assertEqual(result['reason'],'legacy_unknown');self.assertEqual(exchange.call_count,1)
        self.assertNotIn('nodeName',observations[0]['spec'])
        self.assertFalse(self.c.pods);self.assertFalse(self.c.policies)
    def test_running_without_pinned_node_never_reaches_report_exchange(self):
        original=self.c.get
        def unassigned(kind,name):
            value=original(kind,name)
            if kind=='pod':value['spec'].pop('nodeName')
            return value
        self.c.get=unassigned
        with patch.object(maintained,'report_exchange') as exchange,self.assertRaisesRegex(RuntimeError,'node_changed'):
            n.assess(self.c)
        exchange.assert_not_called();self.assertFalse(self.c.pods);self.assertFalse(self.c.policies)
    def test_terminal_failure_cleans_and_retains_closed_metadata_without_retry(self):
        original=self.c.get
        def get(kind,name):
            value=original(kind,name)
            if kind=='pod':
                value['status']['phase']='Failed'
                value['status']['containerStatuses'][0]['state']={'terminated':{'reason':'Error','exitCode':1,
                    'message':'1\tcli_exit\terror\tunknown\t0\t1\n'}}
            return value
        self.c.get=get
        with patch.object(maintained,'report_exchange') as exchange,self.assertRaises(maintained.AssessmentError):
            n.assess(self.c)
        self.assertFalse(self.c.pods);self.assertFalse(self.c.policies);exchange.assert_not_called()
        failed=json.loads((self.c.root/'npm-assessment-failed.json').read_bytes())
        self.assertTrue(failed['phase_known']);self.assertEqual(failed['phases'][0]['phase'],'cli_exit')
        self.assertNotIn('stderr',json.dumps(failed));self.assertNotIn('report.json',self.c.writes)
    def test_failure_to_persist_report_does_not_leave_credentials_or_repeat_cli(self):
        save=self.c.save
        def fail(path,value,replace=False):
            if path.name=='report.json':raise OSError('private secret must not be copied')
            return save(path,value,replace)
        self.c.api.save=fail
        with patch.object(maintained,'report_exchange',return_value=frame()) as exchange,self.assertRaises(OSError):
            n.assess(self.c)
        self.assertFalse(self.c.pods);self.assertFalse(self.c.policies);self.assertEqual(exchange.call_count,1)
        self.assertNotIn('npm-assessment-completed.json',self.c.writes)
    def test_lost_pod_create_response_is_uid_cleaned_without_repeating_cli(self):
        original=self.c.k
        def lose(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[0]=='create' and json.loads(kwargs['data'])['kind']=='Pod':
                raise ConnectionError('response unknown')
            return result
        self.c.old.k=lose
        with patch.object(maintained,'report_exchange') as exchange,self.assertRaises(ConnectionError):n.assess(self.c)
        self.assertFalse(self.c.pods);self.assertFalse(self.c.policies);exchange.assert_not_called()
        self.assertNotIn('npm-assessment-completed.json',self.c.writes)
    def test_changed_legacy_reason_does_not_qualify_completed_receipt(self):
        with (patch.object(maintained,'report_exchange',return_value=frame('already_published')),
              self.assertRaisesRegex(RuntimeError,'exact_legacy_unknown')):
            n.assess(self.c)
        self.assertFalse(self.c.pods);self.assertFalse(self.c.policies)
        self.assertNotIn('npm-assessment-completed.json',self.c.writes)


if __name__=='__main__':unittest.main()
