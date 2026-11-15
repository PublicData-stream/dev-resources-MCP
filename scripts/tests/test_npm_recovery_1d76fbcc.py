"""This exact schema18 incident must stay legacy; never fabricate rearm authority."""
import importlib.util
import copy
import json
import tempfile
import contextlib
import os
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('npm_rollout',ROOT/'deploy/production/npm_recovery_1d76fbcc.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)

def full_report():
    return {'version':1,'job_id':n.JOB,'revision':1,'recipe':'npm-materialization-deadline-v1',
            'state_digest':'blake3:'+'a'*64,'eligible':False,'outcome':'ineligible','reason':'legacy_unknown',
            'operation_id':None,'publication_snapshot':None}


class Recovery(unittest.TestCase):
    def test_only_exact_migrated_non_authoritative_revision_is_admitted(self):
        value={'job_id':n.JOB,'revision':1,'authoritative':False}
        with patch.object(n,'sql',return_value=[value]):self.assertEqual(n.selection(object()),value)
        for rows in ([],[{**value,'revision':2}],[{**value,'authoritative':True}],[{**value,'job_id':'blake3:'+'1'*64}],[value,value]):
            with self.subTest(rows=rows),patch.object(n,'sql',return_value=rows):
                with self.assertRaisesRegex(RuntimeError,'exact_migrated_legacy_incident_required'):n.selection(object())

    def test_sealed_legacy_report_is_deferred_without_recovery(self):
        value=full_report()
        self.assertEqual(n.validate_report(value)['reason'],'legacy_unknown')
        for change in ({'eligible':True},{'reason':'evidence_not_verified'},{'recipe':'new'},{'revision':2}):
            with self.subTest(change=change),self.assertRaisesRegex(RuntimeError,'sealed_legacy_ineligibility_required'):
                n.validate_report({**value,**change})

class Cleanup(unittest.TestCase):
    def test_lost_create_scheduled_node_selector_is_reconciled_with_uid_delete(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root=Path(directory)
            expected={'spec':{'containers':[{'image':'pinned','command':['dry-run'],'volumeMounts':[]}],
                'nodeSelector':{'kubernetes.io/hostname':'node'},'volumes':[{'name':'config','secret':{'secretName':'reader'}}],
                'securityContext':{'runAsUser':65532},'serviceAccountName':'devres-serving'}}
            (root/'npm-assessment-pod-admission.json').write_text(json.dumps({'name':n.POD,'pod':expected}))
            current=copy.deepcopy(expected)
            current['metadata']={'name':n.POD,'uid':'owned-uid','labels':{'app':'backend','devres-rollout':'1d76fbcc-assessment'}}
            current['spec']['nodeName']='node'
            current['spec']['volumes'][0]['secret']['defaultMode']=288
            k=Mock(side_effect=[json.dumps({'items':[current]}).encode(),b'{}',b''])
            c=SimpleNamespace(root=root,old=SimpleNamespace(k=k,settings=lambda:{'node_name':'node'}))
            api=SimpleNamespace(load=lambda path:json.loads(path.read_text()),encoded=lambda value:json.dumps(value).encode())
            with patch('importlib.import_module',return_value=api):n.cleanup(c)
            deletion=k.call_args_list[1]
            self.assertEqual(json.loads(deletion.kwargs['data'])['preconditions'],{'uid':'owned-uid'})
            self.assertEqual(deletion.args[:2],('delete','--raw'))

def backend_template():
    spec=importlib.util.spec_from_file_location('npm_production_fixture',ROOT/'deploy/production/production.py')
    renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)
    settings=renderer.settings_checked({'node_name':'node','node_ipv4':'192.0.2.10',
        'kube_api_cidrs':['10.43.0.1/32','192.0.2.10/32'],'storage_auth':'scaleway_static'})
    items=renderer.manifests(settings)['items']
    return next(value['spec']['template'] for value in items if value['kind']=='Deployment' and value['metadata']['name']=='backend')


def frame(report=None):
    body=(json.dumps(report or full_report(),indent=2)+'\n').encode()
    return ('65532:600:1:'+str(len(body))+':regular file\n').encode()+n.FRAME+body


class RestrictedPod(unittest.TestCase):
    def test_actual_production_template_remains_restricted_without_hostpath_pvc_or_token(self):
        template=backend_template();image=template['spec']['containers'][0]['image']
        pod=n.assessment_pod(template,image);spec=pod['spec'];container=spec['containers'][0]
        self.assertEqual({value['name'] for value in spec['volumes']},{'config','s3','tmp'})
        self.assertTrue(all(set(value)-{'name'} in ({'secret'},{'emptyDir'}) for value in spec['volumes']))
        self.assertFalse(spec['automountServiceAccountToken']);self.assertNotIn('initContainers',spec)
        self.assertEqual(spec['securityContext']['runAsUser'],65532)
        self.assertTrue(spec['securityContext']['runAsNonRoot'])
        self.assertEqual(spec['securityContext']['seccompProfile'],{'type':'RuntimeDefault'})
        self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
        self.assertEqual(container['securityContext']['capabilities']['drop'],['ALL'])
        self.assertEqual(container['command'][0],'/usr/bin/timeout')
        self.assertIn('420s',container['command']);self.assertEqual(spec['activeDeadlineSeconds'],450)
        self.assertNotIn('ports',container);self.assertNotIn('hostPath',json.dumps(pod))
        self.assertNotIn('projected',json.dumps(pod));self.assertNotIn('persistentVolumeClaim',json.dumps(pod))
        self.assertIn('--output '+n.REPORT,n.CLI_SCRIPT)
        self.assertNotIn('/bin/cat',n.CLI_SCRIPT)  # Report JSON never enters container logs.
    def test_foreign_image_or_weakened_security_and_wrong_reader_secret_are_rejected(self):
        template=backend_template();image=template['spec']['containers'][0]['image']
        with self.assertRaisesRegex(RuntimeError,'image_changed'):n.assessment_pod(template,'foreign')
        for mutate in (lambda s:s['securityContext'].update(runAsNonRoot=False),
                       lambda s:s['containers'][0]['securityContext'].update(allowPrivilegeEscalation=True),
                       lambda s:next(v for v in s['volumes'] if v['name']=='s3')['secret'].update(secretName='devres-writer-s3')):
            value=copy.deepcopy(template);mutate(value['spec'])
            with self.assertRaises(RuntimeError):n.assessment_pod(value,image)


class ReportTransport(unittest.TestCase):
    def test_complete_private_metadata_frame_recovers_only_exact_report(self):
        body,value=n.decode_report_frame(frame())
        self.assertEqual(value,full_report());self.assertEqual(json.loads(body),full_report())
    def test_missing_marker_truncated_file_permissions_links_and_oversize_are_rejected(self):
        original=frame()
        for body in (original.replace(b'65532:',b'0:',1),original.replace(b':600:',b':644:',1),
                     original.replace(b':600:1:',b':600:2:',1),original.replace(b'regular file',b'symbolic link',1),
                     original.replace(n.FRAME,b'wrong-marker\n'),original[:-1],b'x'*(n.MAX_STREAM+1)):
            with self.subTest(body=body[:30]),self.assertRaises(RuntimeError):n.decode_report_frame(body)
        with self.assertRaises(RuntimeError):n.decode_report_frame(frame({**full_report(),'lockfile':'private-input'}))
        with self.assertRaises(RuntimeError):n.decode_report_frame(frame({**full_report(),'eligible':True}))
    def test_real_stream_transfer_is_bounded_and_nonzero_exec_is_not_ready(self):
        body=frame();command=[sys.executable,'-c','import sys;sys.stdout.buffer.write('+repr(body)+')']
        self.assertEqual(n.report_exchange(command),body)
        self.assertIsNone(n.report_exchange([sys.executable,'-c','raise SystemExit(1)']))
    def test_flooded_stdout_stderr_and_hanging_descendant_are_killed_promptly(self):
        commands=[([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"x"*2000000)'],.5),
                  ([sys.executable,'-c','import sys;sys.stderr.buffer.write(b"x"*5000)'],.5),
                  ([sys.executable,'-c','import subprocess;subprocess.Popen(["/bin/sleep","30"])'],.05)]
        for command,timeout in commands:
            started=time.monotonic()
            with self.subTest(command=command),self.assertRaisesRegex(RuntimeError,'maintenance_report_stream_'):
                n.report_exchange(command,timeout=timeout)
            self.assertLess(time.monotonic()-started,2)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.tmp.cleanup)
        self.top=Path(self.tmp.name);self.top.chmod(0o700);self.root=self.top/'controller';self.root.mkdir(mode=0o700)
        self.template=backend_template();self.image=self.template['spec']['containers'][0]['image']
        self.pod=None;self.events=[];self.create_error=None;self.lose_create=False;self.replace_after_exec=False;self.pod_gets=0
        def save(path,value):
            path.write_bytes(value if isinstance(value,bytes) else json.dumps(value).encode());path.chmod(0o600)
        self.api=SimpleNamespace(save=save,load=lambda p:json.loads(p.read_text()),encoded=lambda v:json.dumps(v).encode(),
            digest=lambda b:__import__('hashlib').sha256(b).hexdigest(),stamp=lambda:'now')
        self.c=SimpleNamespace(root=self.root,locked=contextlib.nullcontext,guard=Mock(),storage_guard=Mock(),
            pacing_delay=Mock(),state=lambda:{'runtime':'target','phase':'writer_ready','configs':'paused','images':{'backend':self.image}},
            get=self.get,scale=lambda *a:self.events.append(('scale',*a[:2])),mutate=lambda label,fn:fn(),
            old=SimpleNamespace(k=self.k,settings=lambda:{'node_name':'node'}))
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(n,'WORK',self.top))
        self.stack.enter_context(patch('importlib.import_module',return_value=self.api))
        self.stack.enter_context(patch.object(n,'selection',return_value={'job_id':n.JOB,'revision':1,'authoritative':False}))
    def get(self,kind,name):
        if kind=='deployment':return {'spec':{'template':self.template}}
        if kind=='pod':
            self.pod_gets+=1
            value=copy.deepcopy(self.pod)
            if self.replace_after_exec and self.pod_gets>=3:value['metadata']['uid']='replacement'
            return value
        raise AssertionError((kind,name))
    def k(self,*args,**kwargs):
        self.events.append(('k',args,kwargs))
        if args[:2]==('create','-f'):
            if self.create_error:raise RuntimeError(self.create_error)
            self.pod=json.loads(kwargs['data']);self.pod['metadata']['uid']='owned-uid'
            self.pod['spec']['nodeName']='node'
            self.pod['status']={'phase':'Running','containerStatuses':[{'containerID':'containerd://owned','restartCount':0}]}
            if self.lose_create:raise OSError('lost create response')
            return b'{}'
        if args[:2]==('get','pods'):return json.dumps({'items':[self.pod] if self.pod else []}).encode()
        if args[:2]==('delete','--raw'):
            self.assertEqual(json.loads(kwargs['data'])['preconditions'],{'uid':'owned-uid'});self.pod=None;return b'{}'
        if args[:2]==('wait','--for=delete'):return b''
        raise AssertionError(args)
    def test_success_stream_is_root_private_and_pod_cleanup_precedes_writer_restart(self):
        with patch.object(n,'report_exchange',return_value=frame()) as exchange:
            result=n.assess(self.c)
        self.assertTrue(result['deferred']);self.assertIsNone(self.pod)
        report=self.top/'npm-assessment/report.json'
        self.assertEqual(json.loads(report.read_bytes()),full_report());self.assertEqual(report.stat().st_mode&0o777,0o600)
        self.assertEqual(self.events[0],('scale','writer',0));self.assertEqual(self.events[-1],('scale','writer',1))
        self.assertEqual(exchange.call_args.args[0],n.assessment_command())
    def test_create_rejection_never_executes_cli_or_restarts_writer(self):
        self.create_error='Forbidden restricted hostPath'
        with patch.object(n,'report_exchange') as exchange,self.assertRaisesRegex(RuntimeError,'Forbidden'):
            n.assess(self.c)
        exchange.assert_not_called();self.assertEqual(self.events[0],('scale','writer',0))
        self.assertNotIn(('scale','writer',1),self.events);self.assertIsNone(self.pod)
    def test_lost_create_response_is_uid_deleted_without_exec_or_retry(self):
        self.lose_create=True
        with patch.object(n,'report_exchange') as exchange,self.assertRaisesRegex(OSError,'lost create'):
            n.assess(self.c)
        exchange.assert_not_called();self.assertIsNone(self.pod)
        self.assertEqual(sum(event[0]=='k' and event[1][:2]==('create','-f') for event in self.events),1)
        self.assertNotIn(('scale','writer',1),self.events)
    def test_uid_change_across_private_exec_discards_report_and_prevents_restart(self):
        self.replace_after_exec=True
        with patch.object(n,'report_exchange',return_value=frame()),self.assertRaises(RuntimeError):n.assess(self.c)
        self.assertFalse((self.top/'npm-assessment/report.json').exists())
        self.assertNotIn(('scale','writer',1),self.events)
    def test_local_report_persistence_failure_happens_after_uid_cleanup(self):
        save=self.api.save
        def persist(path,value):
            if path==self.top/'npm-assessment/report.json':
                self.assertIsNone(self.pod)
                raise OSError('private report fsync failed')
            return save(path,value)
        self.api.save=persist
        with patch.object(n,'report_exchange',return_value=frame()),self.assertRaisesRegex(OSError,'fsync'):
            n.assess(self.c)
        self.assertIsNone(self.pod);self.assertNotIn(('scale','writer',1),self.events)
    def test_running_pod_without_container_id_never_starts_report_exec(self):
        get=self.c.get
        def missing(kind,name):
            value=get(kind,name)
            if kind=='pod':value['status']['containerStatuses'][0].pop('containerID',None)
            return value
        self.c.get=missing
        with patch.object(n,'report_exchange') as exchange,self.assertRaisesRegex(RuntimeError,'process_identity_required'):
            n.assess(self.c)
        exchange.assert_not_called();self.assertIsNone(self.pod)

if __name__=='__main__':unittest.main()
