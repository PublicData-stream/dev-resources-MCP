"""Behavioral safety of the same-schema immutable successor."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
u=module('upgrade91',ROOT/'deploy/production/upgrade_91c7bcb7.py')
old=module('old_fixture91',ROOT/'scripts/tests/test_upgrade_33f3c730.py')

def config():
    return ('[source]\nurl="https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.33f3c730/source.tar.gz"\n'
        +''.join(f'[{p}]\nenabled = true\n'+('advisories_enabled = true\n' if p=='npm' else '') for p in u.PROVIDERS)
        +'[storage]\ndatabase_url="postgres://fixture:fixture-secret@postgres/devres"\n')

def private(path,value):
    path.write_bytes(value if isinstance(value,bytes) else u.encoded(value));path.chmod(0o600)
    return u.digest(path.read_bytes())

class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.top=Path(self.temp.name);self.top.chmod(0o700)
        self.root=self.top/'upgrade';self.root.mkdir(mode=0o700)
        for target,name,value in [(old.u,'OLD_IMAGE',u.OLD_IMAGE),(old,'config',config)]:
            p=patch.object(target,name,value);p.start();self.addCleanup(p.stop)
        self.cluster=old.FakeCluster(self.top)
        self.c=u.Controller.__new__(u.Controller);self.c.root=self.root;self.c.context='default';self.c.plan_raw=b'plan'
        self.c.old=self.cluster
        self.c.get=lambda kind,name:json.loads(self.cluster.k('get',kind,name,'-o','json'))
        self.frozen={'frozen-state':'immutable'};self.c.prior_hashes=lambda:copy.deepcopy(self.frozen)
        self.c.prior_controller=SimpleNamespace(safety=Mock(),verify_edge_admission=Mock(),
            pods=Mock(side_effect=AssertionError('retired pod inventory called')),
            snapshot=Mock(side_effect=AssertionError('retired snapshot called')))
        self.protected={'boot':'same','edge':'same','foundation':[],'profiles':{},'edge_conf_tree':{}}
        self.c.protected_snapshot=lambda:copy.deepcopy(self.protected)
        snap=self.c.snapshot()
        variants={v:{r:u.configuration(config(),v=='active') for r in u.ROLES} for v in ('paused','active')}
        for v,c in variants.items():private(self.root/('configs-'+v+'.json'),c)
        prepared={**self.protected,'at':u.stamp(),'old_pods':snap['pods'],'prior_artifacts':self.frozen,
            'deployments':{n:{'projection':v['projection'],'manifest':copy.deepcopy(self.cluster.deployments[n])} for n,v in snap['deployments'].items()},
            'secrets':snap['secrets'],'config_hashes':{n:u.digest(u.encoded(v)) for n,v in variants.items()}}
        sha=private(self.root/'prepared.json',prepared)
        private(self.root/'state.json',{'revision':u.REVISION,'version':1,'phase':'prepared',
            'plan_sha256':u.digest(self.c.plan_raw),'source_sha256':u.digest(Path(u.__file__).read_bytes()),
            'prepared_sha256':sha,'images':{n:v['image'] for n,v in snap['deployments'].items()},
            'replicas':dict.fromkeys(('postgres','writer','backend'),1),'configs':'old','pods':snap['pods']})
        self.c.guard()

    def run_op(self,operation,receipt=None):
        state=self.c.state();path=self.top/(operation+'-approval.json')
        sha=private(path,{'version':1,'operation':operation,'reviewed':True,'source_sha256':state['source_sha256'],'prepared_sha256':state['prepared_sha256']})
        self.c.run(operation,path,sha,*(receipt or (None,None)))

    def receipt(self,kind,checks,**fields):
        proof=self.top/(kind+'-proof');psha=private(proof,b'proof')
        state=self.c.state();value={'version':1,'kind':kind,'schema':18,'revision':u.REVISION,
            'prepared_sha256':state['prepared_sha256'],'store_binding_sha256':u.STORE_BINDING,
            'verified':True,'observed_at':u.stamp(),'checks':dict.fromkeys(checks,True),
            'processes':state['pods'],'configs':state['configs'],'artifacts':[{'path':str(proof),'sha256':psha}],**fields}
        path=self.top/(kind+'.json');return path,private(path,value)

    def apply(self):
        self.run_op('stop');oldpg=self.c.state()['pods']['postgres'];self.cluster.new_pod('postgres')
        r=self.receipt('coordinated-schema18-backup',('coordinated_pg_s3','old_clone_verified','roles_stopped','pg_restarted_without_restore','credentials_preserved'),
            recovery_scope='physical_pg_checkpoint_original_immutable_s3_retained',independent_s3_backup=False,
            system_identifier='7706567225121447965',old_pg_pod=oldpg,new_pg_pod=self.c.pods()['postgres'],
            postgres_deployment_sha256=u.digest(u.encoded(u.load(self.root/'prepared.json')['deployments']['postgres']['projection'])))
        self.run_op('apply',r)

    def test_target_start_and_activation_use_local_pods_and_preserve_frozen_chain(self):
        before=copy.deepcopy(self.frozen);self.apply();self.run_op('start-writer')
        self.run_op('start-reader',self.receipt('migration18',('schema18','policy2','sole_writer','new_table_reader_grants','history_preserved','archive_binding_preserved','historical_notices_preserved')))
        self.run_op('runtime-ready',self.receipt('target-private-acceptance',('schema18','policy2','sole_writer','read_only_serving','private_boundary','capture_notice_preserved','tool_contract')))
        self.run_op('activate-existing',self.receipt('target-activation-acceptance',('schema18','policy2','sole_writer','private_boundary','public_http_both_families_revisions','public_wt_both_families_revisions','public_compression_gzip_br_zstd','capture_notice_preserved')))
        self.assertEqual(self.c.state()['phase'],'collectors_active');self.assertEqual(self.frozen,before)
        self.assertTrue(all(v['image_id']==u.IMAGE for r,v in self.c.pods().items() if r in u.ROLES))
        for role,(name,key) in u.ROLES.items():
            parsed=tomllib.loads(base64.b64decode(self.cluster.secrets[name]['data'][key]).decode())
            self.assertTrue(all(parsed[p]['enabled'] for p in u.PROVIDERS));self.assertTrue(parsed['npm']['advisories_enabled'])

    def test_uncertain_start_can_be_withdrawn_without_journal_replica_adoption(self):
        self.apply();self.cluster.fail_rollout=True
        with self.assertRaises(RuntimeError):self.run_op('start-writer')
        self.assertEqual(self.c.state()['replicas']['writer'],0)
        self.assertEqual(self.cluster.deployments['writer']['spec']['replicas'],1)
        self.run_op('withdraw');self.assertEqual(self.c.state()['phase'],'withdrawn')
        self.assertEqual(set(self.c.pods()),{'postgres'})

    def test_uncertain_stop_can_be_withdrawn(self):
        self.cluster.fail_after_patch=True
        with self.assertRaises(RuntimeError):self.run_op('stop')
        self.run_op('withdraw');self.assertEqual(set(self.c.pods()),{'postgres'})

    def test_checkpoint_guard_tolerates_only_expected_postgres_restart(self):
        self.run_op('stop');self.cluster.deployments['postgres']['spec']['replicas']=0;self.cluster.live_pods.pop('postgres')
        self.c.boundary_guard(check_pods=False)
        self.cluster.deployments['writer']['spec']['replicas']=1
        with self.assertRaisesRegex(u.Error,'checkpoint_replica_changed'):self.c.boundary_guard(check_pods=False)

    def test_runtime_receipt_rejects_repackaged_paused_processes(self):
        r=self.receipt('target-private-acceptance',())
        self.cluster.new_pod('backend');state=self.c.state();state['pods']=self.c.pods();self.c.record(state)
        with self.assertRaisesRegex(u.Error,'receipt_runtime_binding'):self.c.receipt(*r,'target-private-acceptance',())

    def test_frozen_history_or_secret_drift_blocks_before_mutation(self):
        self.frozen['frozen-state']='changed'
        with self.assertRaisesRegex(u.Error,'prior_chain_changed'):self.run_op('stop')
        self.assertFalse(any(c[0][0]=='patch' for c in self.cluster.calls))

    def test_uncertain_intent_is_not_replayed(self):
        calls=[]
        with self.assertRaises(RuntimeError):self.c.mutate('once',lambda:(_ for _ in ()).throw(RuntimeError('uncertain')))
        with self.assertRaises(FileExistsError):self.c.mutate('once',lambda:calls.append('replayed'))
        self.assertEqual(calls,[])

    def test_pause_disables_all_admission_without_changing_credentials(self):
        before=tomllib.loads(config());after=tomllib.loads(u.configuration(config(),False))
        self.assertEqual(after['storage'],before['storage']);self.assertFalse(after['npm']['advisories_enabled'])
        self.assertTrue(all(not after[p]['enabled'] for p in u.PROVIDERS))

if __name__=='__main__':unittest.main()
