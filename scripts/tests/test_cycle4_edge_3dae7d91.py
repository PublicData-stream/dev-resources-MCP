"""Exact edge metadata delta, source-pinned receipts, and read-only facades."""
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('cycle4_edge_bridge',ROOT/'deploy/production/cycle4_edge_3dae7d91.py')
n=importlib.util.module_from_spec(spec);sys.modules[spec.name]=n;spec.loader.exec_module(n)


def snapshots():
    before={'edge':{'id':'c'*64,'image':'sha256:'+'d'*64,'pid':10,'pid_start_ticks':'100','started':'2026-11-14T00:00:00Z','restarts':0},
        'docker':{'id':'c'*64,'image':'sha256:'+'d'*64,'config':{'Env':['private=value']},'health':None,
            'host_config':{'Dns':None,'DnsOptions':None,'DnsSearch':None,'ReadonlyRootfs':True},
            'mounts':[],'networks':{},'ports':{}},'networks':{},'files':{'unchanged':'hash'},
        'conf_tree':{'unchanged':'hash'},'conf_contents':{'unchanged':'private-base64'}}
    for index,name in enumerate(('devres-net','pdf2md-net'),1):
        mac=f'02:00:00:00:00:0{index}'
        before['docker']['networks'][name]={'MacAddress':mac,'IPAddress':f'10.0.{index}.3'}
        before['networks'][name]={'Id':str(index)*64,'edge_member':{'MacAddress':mac,'EndpointID':str(index)*64}}
    after=copy.deepcopy(before);after['edge'].update(pid=20,pid_start_ticks='200',started='2026-11-17T00:00:00Z')
    for key in ('Dns','DnsOptions','DnsSearch'):after['docker']['host_config'][key]=[]
    for index,name in enumerate(('devres-net','pdf2md-net'),3):
        mac=f'02:00:00:00:00:0{index}'
        after['docker']['networks'][name]['MacAddress']=mac
        after['networks'][name]['edge_member'].update(MacAddress=mac,EndpointID=str(index)*64)
    return before,after


def put(path,value):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    path.write_bytes(value if type(value) is bytes else n.encode(value));path.chmod(0o600)


class Delta(unittest.TestCase):
    def test_only_exact_observed_twelve_fields_are_admitted(self):
        before,after=snapshots();self.assertTrue(n.validate_delta(before,after))
        self.assertEqual(len(n.changed_paths(before,after)),12)
    def test_another_structurally_identical_restart_is_not_the_observed_admission(self):
        before,after=snapshots()
        with patch.multiple(n,EXPECTED_BEFORE_SHA=n.sha(n.encode(before)),EXPECTED_AFTER_SHA=n.sha(n.encode(after))):
            self.assertTrue(n.validate_observed_snapshots(before,after))
            later=copy.deepcopy(after);later['edge']['pid']=30;later['edge']['pid_start_ticks']='300'
            self.assertTrue(n.validate_delta(before,later))
            with self.assertRaisesRegex(n.Refused,'exact_observed_native_snapshot'):
                n.validate_observed_snapshots(before,later)
    def test_extra_or_missing_change_is_rejected(self):
        before,after=snapshots()
        variants=[]
        value=copy.deepcopy(after);value['edge']['id']='x'*64;variants.append(value)
        value=copy.deepcopy(after);value['docker']['config']['Env']=['changed'];variants.append(value)
        value=copy.deepcopy(after);value['docker']['health']='unhealthy';variants.append(value)
        value=copy.deepcopy(after);value['edge']['restarts']=1;variants.append(value)
        value=copy.deepcopy(after);value['conf_tree']['unchanged']='changed';variants.append(value)
        value=copy.deepcopy(after);value['edge']['pid']=before['edge']['pid'];variants.append(value)
        for value in variants:
            with self.subTest(value=value),self.assertRaises(n.Refused):n.validate_delta(before,value)
    def test_dns_direction_process_order_and_endpoint_correspondence_are_required(self):
        before,after=snapshots()
        for mutate in (lambda a:a['docker']['host_config'].update(Dns=['8.8.8.8']),
            lambda a:a['edge'].update(pid_start_ticks='10'),
            lambda a:a['edge'].update(started='2026-11-13T00:00:00Z'),
            lambda a:a['networks']['devres-net']['edge_member'].update(MacAddress='02:00:00:00:00:ff'),
            lambda a:a['networks']['devres-net']['edge_member'].update(EndpointID='bad')):
            value=copy.deepcopy(after);mutate(value)
            with self.subTest(value=value),self.assertRaises(n.Refused):n.validate_delta(before,value)


class ConstructorInjection(unittest.TestCase):
    def test_private_globals_replace_only_factory_without_mutating_original_module(self):
        namespace={'__name__':'unchanged_historical_module'}
        exec("def predecessor(context):return 'old'\nclass Controller:\n def __init__(self,bundle,plan,context):\n  assert context=='default'\n  self.root=bundle;self.prior=predecessor(context)\n",namespace)
        original=namespace['Controller'];factory=namespace['predecessor']
        injected=n._injected_constructor(original.__init__,lambda context:'readmitted')
        facade=n._read_only_facade(original,injected)
        obj=facade('bundle','plan','default')
        self.assertEqual(obj.prior,'readmitted');self.assertIs(namespace['predecessor'],factory)
        self.assertEqual(original('bundle','plan','default').prior,'old')
        self.assertIs(injected.__code__,original.__init__.__code__)
    def test_original_ctor_checks_still_reject_invalid_context(self):
        namespace={};exec("def predecessor(context):return 1\nclass Controller:\n def __init__(self,bundle,plan,context):\n  if context!='default':raise RuntimeError('context')\n  self.prior=predecessor(context)\n",namespace)
        original=namespace['Controller'];injected=n._injected_constructor(original.__init__,lambda context:2)
        facade=n._read_only_facade(original,injected)
        with self.assertRaisesRegex(RuntimeError,'context'):facade('bundle','plan','foreign')
    def test_facade_denies_mutation_and_restores_context_even_on_guard_error(self):
        class Base:
            def guard(self):
                self.depth=n._DEPTH.get();raise RuntimeError('failure')
            def record(self,value):raise AssertionError('must not execute')
        facade=n._read_only_facade(Base);value=facade()
        with self.assertRaisesRegex(RuntimeError,'failure'):value.guard()
        self.assertGreater(value.depth,0);self.assertEqual(n._DEPTH.get(),0)
        with self.assertRaisesRegex(n.Refused,'read_only'):value.record({})


class CompressionFacade(unittest.TestCase):
    def setUp(self):
        self.before,self.after=snapshots();self.compose=b'exact compose';self.old_raw=b'exact historical receipt'
        self.pins=patch.multiple(n,EXPECTED_BEFORE_SHA=n.sha(n.encode(self.before)),EXPECTED_AFTER_SHA=n.sha(n.encode(self.after)))
        self.pins.start();self.addCleanup(self.pins.stop)
        self.admission={'before':copy.deepcopy(self.before),'after':copy.deepcopy(self.before)}
        self.native_calls=[]
        before,after,admission=self.before,self.after,self.admission
        class Original:
            def __init__(self,bundle,plan,context):
                self._compat_depth=0;self._admission=copy.deepcopy(admission);self._admission_raw=b'exact historical receipt'
                self._actual()
            def _actual(self):raise RuntimeError('admitted_sse_edge_changed')
            def snapshot(self):return {'edge':self.edge()}
            def guard(self):return self.snapshot()
            def record(self,value):raise AssertionError('must not execute')
        def native(self,base,contents):self_test.native_calls.append(True);return copy.deepcopy(self_test.after),self_test.compose
        self_test=self
        self.wrapper=SimpleNamespace(Controller=Original,_implementation_module=SimpleNamespace(native_snapshot=native,raw=lambda p:self.compose),
            _immutable_predecessor=SimpleNamespace(EDGE_COMPOSE='/unchanged'))
        self.receipt={'candidate':{'old_admission_sha256':n.sha(self.old_raw),'after':self.after,'compose_sha256':n.sha(self.compose)}}
    def value(self):return n._compression_controller(self.wrapper,self.receipt,Path('/fixed-bundle'),'default')
    def test_native_reality_and_historical_projection_are_separate(self):
        value=self.value();native,_=value._actual();self.assertEqual(native,self.after)
        with self.assertRaisesRegex(n.Refused,'projection_context'):value.edge()
        self.assertEqual(value.guard()['edge'],self.before['edge'])
        self.assertTrue(self.native_calls)
    def test_readonly_capture_retains_denial_and_exact_current_snapshot(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            admission=Path(temporary)/'old.json';put(admission,self.old_raw)
            self.admission['compose_sha256']=n.sha(self.compose)
            original=self.wrapper.Controller._actual
            with (patch.object(n,'source_guard',return_value={'frozen':'hash'}),
                  patch.object(n,'_wrapper',return_value=self.wrapper),
                  patch.object(n,'OLD_ADMISSION',admission),
                  patch.object(n,'_retained_bindings',return_value={'state':'same'})):
                candidate=n.capture_current()
            self.assertTrue(candidate['original_guard_denied'])
            self.assertEqual(candidate['after'],self.after)
            self.assertIs(self.wrapper.Controller._actual,original)
    def test_whitelisted_ctor_chain_is_injected_without_mutating_frozen_factories(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root=Path(temporary);path91=root/'91.py';path3=root/'3.py'
            body=b'''def predecessor(context):raise AssertionError('original factory must remain uncalled')\nclass Controller:\n def __init__(self,bundle,plan,context):\n  assert context=='default';self.root=bundle;self.prior_controller=predecessor(context)\n def guard(self):return self.prior_controller.guard()\n def snapshot(self):return self.prior_controller.snapshot()\n def edge(self):return self.prior_controller.edge()\n def record(self,value):raise AssertionError('must not mutate')\n'''
            put(path91,body);put(path3,body)
            chain={str(n.WRAPPER):('33f3c730',n.WRAPPER_SHA,root/'bundle33'),
                str(path91):('91c7bcb7',n.sha(body),root/'bundle91'),
                str(path3):('9373f71e',n.sha(body),root/'bundle3')}
            with (patch.object(n,'CHAIN',chain),patch.object(n,'_receipt',return_value=self.receipt),
                  patch.object(n,'_wrapper',return_value=self.wrapper)):
                controller=n.load_controller(path3,n.sha(body),root/'bundle3','default',receipt_sha='a'*64)
                self.assertEqual(controller.guard()['edge'],self.before['edge'])
                with self.assertRaisesRegex(n.Refused,'projection_context'):controller.edge()
                with self.assertRaisesRegex(n.Refused,'read_only'):controller.record({})
                for name in ('cycle4_checked_historical_91c7bcb7','cycle4_checked_historical_9373f71e'):
                    with self.assertRaises(AssertionError):sys.modules[name].predecessor('default')
            self.assertEqual(path91.read_bytes(),body);self.assertEqual(path3.read_bytes(),body)
    def test_original_guard_must_reject_exact_reason(self):
        with (patch.object(self.wrapper.Controller,'_actual',side_effect=RuntimeError('different_failure')),
              self.assertRaisesRegex(n.Refused,'original_edge_denial')):self.value()
    def test_unlisted_native_drift_or_compose_change_rejects(self):
        value=self.value();self.after['docker']['config']['Env']=['different']
        with self.assertRaises(n.Refused):value._actual()
        self.after=snapshots()[1];self.compose=b'changed'
        with self.assertRaisesRegex(n.Refused,'new_native_edge_changed'):value._actual()
    def test_original_guard_success_is_not_used_to_accept_reversed_transition(self):
        with patch.object(self.wrapper.Controller,'_actual',return_value=({},b'')),self.assertRaisesRegex(n.Refused,'original_edge_denial'):
            self.value()


class Receipt(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.scope=Path(self.temp.name);self.candidate_path=self.scope/'candidate.json';self.admission_path=self.scope/'admission.json'
        self.qualifier=self.scope/'producer.py';put(self.qualifier,b'# reviewed producer\n')
        self.producer_sha=n.sha(self.qualifier.read_bytes());before,after=snapshots()
        self.pins=patch.multiple(n,EXPECTED_BEFORE_SHA=n.sha(n.encode(before)),EXPECTED_AFTER_SHA=n.sha(n.encode(after)))
        self.pins.start();self.addCleanup(self.pins.stop)
        self.candidate={'version':1,'kind':'cycle4-edge-readmission-candidate','revision':n.REVISION,
            'bridge_source_sha256':n.sha(Path(n.__file__).read_bytes()),'historical_sources':{'frozen':'hash'},
            'public_identity_sha256':n.PUBLIC_SHA,'original_guard_denied':True,'original_error':'admitted_sse_edge_changed',
            'before':before,'after':after,'compose_sha256':n.sha(b'exact compose'),
            'old_admission_sha256':n.sha(b'old admission'),'retained_context':{'frozen':'same'},
            'qualification_producer_sha256':self.producer_sha}
        put(self.scope/'old.json',b'old admission');put(self.candidate_path,self.candidate)
        put(self.scope/'artifact.json',{'closed':True})
        self.qualification={'version':1,'kind':'cycle4-native-edge-qualification','candidate_sha256':n.sha(self.candidate_path.read_bytes()),
            'producer_sha256':self.producer_sha,'fixture':False,'verified':True,'checks':{key:True for key in n.CHECKS},
            'full_public_mcp_acceptance':False,'native_webtransport_acceptance':False,
            'artifacts':[{'path':str(self.scope/'artifact.json'),'sha256':n.sha((self.scope/'artifact.json').read_bytes())}]}
        put(self.scope/'qualification.json',self.qualification)
        self.patch=patch.multiple(n,SCOPE=self.scope,CANDIDATE=self.candidate_path,ADMISSION=self.admission_path,
            QUALIFIER=self.qualifier,OLD_ADMISSION=self.scope/'old.json')
        self.patch.start();self.addCleanup(self.patch.stop)
    def admit(self):
        with patch.object(n,'candidate_matches_current',return_value=True):
            return n.admit(n.sha(self.candidate_path.read_bytes()),self.scope/'qualification.json',
                n.sha((self.scope/'qualification.json').read_bytes()),self.producer_sha)
    def test_real_qualified_receipt_is_source_pinned_and_cannot_be_rewritten(self):
        result=self.admit()
        with patch.object(n,'source_guard',return_value={'frozen':'hash'}),patch.object(n,'_retained_bindings',return_value={'frozen':'same'}):
            self.assertTrue(n._receipt(result['admission_sha256'])['verified'])
        with self.assertRaises(FileExistsError):self.admit()
        self.assertFalse(result['full_public_mcp_acceptance'])
    def test_fixture_or_incomplete_qualification_never_admits(self):
        for change in ({'fixture':True},{'native_webtransport_acceptance':True},{'checks':{}},{'verified':False}):
            value={**self.qualification,**change};put(self.scope/'qualification.json',value)
            with self.subTest(change=change),self.assertRaises(n.Refused):self.admit()
            self.assertFalse(self.admission_path.exists())
    def test_changed_candidate_source_artifact_or_native_reality_never_admits(self):
        put(self.scope/'artifact.json',{'changed':True})
        with self.assertRaises(n.Refused):self.admit()
        self.assertFalse(self.admission_path.exists())
    def test_actual_native_change_during_qualification_does_not_publish_receipt(self):
        with patch.object(n,'candidate_matches_current',return_value=False),self.assertRaisesRegex(n.Refused,'native_reality_changed'):
            n.admit(n.sha(self.candidate_path.read_bytes()),self.scope/'qualification.json',
                n.sha((self.scope/'qualification.json').read_bytes()),self.producer_sha)
        self.assertFalse(self.admission_path.exists())


if __name__=='__main__':unittest.main()
