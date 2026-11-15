"""Exact withdrawn admission, runtime identity, and rollback dispatch boundaries."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
u=module('upgrade1d76',ROOT/'deploy/production/upgrade_1d76fbcc.py')
old=module('old_fixture1d76',ROOT/'scripts/tests/test_upgrade_33f3c730.py')

def config():
    return ('[source]\nurl="'+u.fallback_source_url()+'"\n'
        +''.join(f'[{p}]\nenabled = true\n'+('advisories_enabled = true\n' if p=='npm' else '') for p in u.PROVIDERS)
        +'[storage]\ndatabase_url="postgres://fixture:fixture-secret@postgres/devres"\n'
        +'[writer_client]\nendpoint="https://writer.devres.svc:9443/v1/acquire"\ntoken_file="/run/token"\nca_file="/run/ca"\n')

def private(path,value):
    path.write_bytes(value if isinstance(value,bytes) else u.encoded(value));path.chmod(0o600)
    return u.digest(path.read_bytes())

class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.top=Path(self.temp.name);self.top.chmod(0o700)
        self.root=self.top/'upgrade';self.root.mkdir(mode=0o700)
        for target,name,value in [(old.u,'OLD_IMAGE',u.OLD_IMAGE),(old,'config',config)]:
            item=patch.object(target,name,value);item.start();self.addCleanup(item.stop)
        self.cluster=old.FakeCluster(self.top)
        self.c=u.Controller.__new__(u.Controller);self.c.root=self.root;self.c.context='default';self.c.plan_raw=b'plan'
        self.c.old=self.cluster
        self.c.get=lambda kind,name:json.loads(self.cluster.k('get',kind,name,'-o','json'))
        self.frozen={'prior-state':'immutable'};self.c.prior_hashes=lambda:copy.deepcopy(self.frozen)
        self.c.prior_controller=SimpleNamespace(prior_controller=SimpleNamespace(safety=Mock(),verify_edge_admission=Mock()))
        self.protected={'boot':'same','edge':'same','foundation':[],'profiles':{},'edge_conf_tree':{}}
        self.c.protected_snapshot=lambda:copy.deepcopy(self.protected)
        self.c.storage_guard=Mock()
        self.c.pacing_delay=Mock()
        for name in ('backend','writer'):
            self.cluster.deployments[name]['spec']['replicas']=0
            self.cluster.live_pods.pop(name)
        snap=self.c.snapshot()
        variants={v:{r:u.configuration(config(),v.endswith('active')).replace(u.SOURCE_URL,u.fallback_source_url())
                  if v.startswith('fallback-') else u.configuration(config(),v=='active') for r in u.ROLES}
                  for v in ('paused','active','fallback-paused','fallback-active')}
        for variant,values in variants.items():private(self.root/('configs-'+variant+'.json'),values)
        prepared={**self.protected,'at':u.stamp(),'old_pods':snap['pods'],'prior_artifacts':self.frozen,
            'deployments':{n:{'projection':v['projection'],'manifest':copy.deepcopy(self.cluster.deployments[n])} for n,v in snap['deployments'].items()},
            'secrets':snap['secrets'],'config_hashes':{n:u.digest(u.encoded(v)) for n,v in variants.items()}}
        sha=private(self.root/'prepared.json',prepared)
        private(self.root/'state.json',{'revision':u.REVISION,'runtime':'target','version':1,'phase':'prepared',
            'plan_sha256':u.digest(self.c.plan_raw),'source_sha256':u.digest(Path(u.__file__).read_bytes()),
            'prepared_sha256':sha,'images':{n:v['image'] for n,v in snap['deployments'].items()},
            'replicas':{'postgres':1,'writer':0,'backend':0},'configs':'old','pods':snap['pods']})
        self.c.guard()

    def run_op(self,operation,receipt=None):
        state=self.c.state();path=self.top/(operation+'-approval.json')
        sha=private(path,{'version':1,'operation':operation,'reviewed':True,'source_sha256':state['source_sha256'],'prepared_sha256':state['prepared_sha256']})
        self.c.run(operation,path,sha,*(receipt or (None,None)))

    def applied(self):
        self.c.change_config('paused','pause')
        for role in u.ROLES:
            self.cluster.deployments[role]['spec']['template']['spec']['containers'][0]['image']=u.IMAGE
        state=self.c.state();state['images'].update(dict.fromkeys(u.ROLES,u.IMAGE));state['phase']='applied';self.c.record(state)

    def test_stop_accepts_only_withdrawn_original_runtime(self):
        self.run_op('stop')
        self.assertEqual(self.c.state()['phase'],'stopped')
        self.c.storage_guard.assert_called_with(18,owner=False)

    def test_target_configuration_and_fallback_candidates_are_distinct(self):
        self.applied()
        self.assertTrue(all(u.SOURCE_URL in text for text in self.c.configurations().values()))
        state=self.c.state();state['runtime']='fallback';state['phase']='restored';self.c.record(state)
        self.c.prepare_fallback()
        self.assertEqual(self.c.runtime_schema(),18)
        self.assertEqual(self.c.runtime_revision(),u.FALLBACK_REVISION)
        self.assertTrue(all(u.fallback_source_url() in text for text in self.c.configurations().values()))
        self.c.guard()

    def test_fallback_activation_selects_original_flags_and_source_offer(self):
        self.applied();state=self.c.state();state['runtime']='fallback';state['phase']='restored';self.c.record(state)
        self.c.prepare_fallback();self.c.change_config('active','fallback-active-config')
        self.assertTrue(all(u.fallback_source_url() in text for text in self.c.configurations().values()))
        self.assertTrue(all('enabled = true' in text for text in self.c.configurations().values()))
        self.c.guard()

    def test_uncertain_target_start_reconciles_withdrawal(self):
        self.applied();self.cluster.fail_rollout=True
        with self.assertRaises(RuntimeError):self.run_op('start-writer')
        self.c.withdraw();self.c.withdraw()
        self.assertEqual(self.c.state()['phase'],'withdrawn')
        self.assertEqual(set(self.c.pods()),{'postgres'})

    def test_cleanup_failure_cannot_keep_known_application_deployments_running(self):
        self.applied()
        self.c.scale('writer',1,'test-start-writer')
        self.c.scale('backend',1,'test-start-reader')
        self.c.cleanup_maintenance=Mock(side_effect=RuntimeError('cleanup-unavailable'))
        with self.assertRaisesRegex(u.Error,'withdrawal_incomplete'):self.c.withdraw()
        self.assertTrue(all(self.cluster.deployments[role]['spec']['replicas']==0 for role in u.ROLES))
        self.assertEqual(self.c.state()['phase'],'withdraw_incomplete')

    def test_mixed_unadmitted_secret_and_foreign_pod_block_restoration(self):
        self.applied();name,key=u.ROLES['backend']
        self.cluster.secrets[name]['data'][key]=base64.b64encode(b'foreign').decode()
        with self.assertRaisesRegex(u.Error,'secret_boundary_changed'):self.c.restore_guard()

    def test_restored_record_requires_verified_schema18(self):
        self.applied()
        with self.assertRaisesRegex(u.Error,'verified_restore_required'):self.c.restore_record({'schema':19,'database_restored':True})
        self.c.restore_record({'schema':18,'database_restored':True})
        self.assertEqual(self.c.state()['runtime'],'fallback')
        self.assertEqual(self.c.state()['phase'],'restored')

    def test_receipt_for_other_runtime_cannot_admit_reader(self):
        self.applied();self.run_op('start-writer')
        body={'version':1,'kind':'migration19','schema':19,'revision':u.REVISION,'runtime':'fallback',
              'runtime_revision':u.FALLBACK_REVISION,'verified':True,'prepared_sha256':self.c.state()['prepared_sha256'],
              'store_binding_sha256':u.STORE_BINDING,'checks':{},'observed_at':u.stamp()}
        path=self.top/'wrong-runtime.json';sha=private(path,body)
        with self.assertRaisesRegex(u.Error,'receipt_runtime_revision'):self.c.receipt(path,sha,'migration19',())

    def test_newer_cache_not_part_of_unverified_restore_record(self):
        self.applied()
        with self.assertRaisesRegex(u.Error,'one_target_rollback_only'):
            state=self.c.state();state['runtime']='fallback';self.c.record(state);self.c.rollback()

    def test_old_configuration_keeps_private_storage_credentials(self):
        before=config();target=u.configuration(before,False)
        self.assertIn('fixture-secret',target)
        self.assertNotIn('enabled = true',target)
        self.assertIn('[writer_client]',target)
        self.assertIn('https://127.0.0.1:9/v1/acquire',target)
        self.assertIn('/run/devres-writer-identity/no-forwarding-token',target)
        self.assertIn('[writer_client]',u.configuration(before,True))
        self.assertEqual(u.configuration(before,True).count(u.SOURCE_URL),1)

if __name__=='__main__':unittest.main()
