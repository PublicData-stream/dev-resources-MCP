"""Offline exact-target resume state-machine tests; all synthetic state is /tmp."""
import contextlib
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('resume_fixture', ROOT / 'deploy/production/resume_91c7bcb7.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
NOW = dt.datetime(2026, 11, 15, 12, 0, tzinfo=dt.timezone.utc)


class FakeController:
    """First-party namespace model with unknown-patch/partial-ready outcomes."""
    def __init__(self, fixture):
        self.fixture = fixture
        self.root = fixture.bundle
        self.live = {'postgres':1,'writer':0,'backend':0}
        self.actual_pods = {'postgres':{'uid':'pg-uid','container_id':'pg-container','pod_ip':'10.42.0.1'}}
        self.scale_calls = []
        self.mutation_labels = []
        self.commands = []
        self.fail_start = None
        self.fail_withdraw = False
        self.drift = False
        self.old = types.SimpleNamespace(k=self.command)

    def locked(self):
        return contextlib.nullcontext()

    def state(self):
        return m.load(self.root / 'state.json')

    def record(self, value):
        self.fixture.write(self.root / 'state.json', value)

    def guard(self):
        if self.drift:
            raise m.Error('protected_runtime_changed')
        state = self.state()
        if state['replicas'] != self.live or state['pods'] != self.actual_pods:
            raise m.Error('process_identity_changed')

    def boundary_guard(self, check_pods=True, withdrawing=False):
        if self.drift:
            raise m.Error('protected_runtime_changed')
        if check_pods:
            self.guard()
        else:
            assert withdrawing
            assert self.live['postgres'] == 1
            assert all(self.live[r] in (0,1) for r in ('writer','backend'))

    def get(self, kind, name):
        assert kind == 'deployment'
        return {'metadata':{'uid':'deployment-'+name,'resourceVersion':'rv-'+name},
                'spec':{'replicas':self.live[name], 'template':{'spec':{'containers':[
                    {'image':m.PG_IMAGE if name == 'postgres' else m.IMAGE}]}}}}

    def pods(self):
        return copy.deepcopy(self.actual_pods)

    def snapshot(self):
        return {'pods':self.pods(),'protected':{'edge':'unchanged','credentials_sha256':'c'*64}}

    def mutate(self, label, function):
        self.mutation_labels.append(label)
        m.save(self.root / (label+'-intent.json'), {'maximum_attempts':1})
        function()
        m.save(self.root / (label+'-completed.json'), {'known':True})

    def scale(self, role, count, label):
        self.guard()
        self.scale_calls.append((role,count,label))
        def action():
            self.live[role] = count
            self.actual_pods[role] = {'uid':'new-'+role,'container_id':'new-container-'+role,
                                      'pod_ip':'10.42.0.2' if role == 'writer' else '10.42.0.3'}
            if self.fail_start == role:
                raise TimeoutError('patch outcome is unknown to the caller')
        self.mutate(label, action)
        state = self.state(); state['replicas'][role] = count; state['pods'] = self.pods(); self.record(state)

    def command(self, *args, **kwargs):
        self.commands.append((args,kwargs))
        if args[0] == 'exec':
            query = args[-1]
            assert query.startswith('BEGIN READ ONLY;')
            assert "SET LOCAL statement_timeout='20s'" in query
            assert kwargs['timeout'] == 45
            value = self.fixture.authority if 'FROM pg_authid' in query else self.fixture.identity(self)
            return m.enc(value)
        if args[0] == 'patch':
            role = args[2]
            if self.fail_withdraw:
                raise TimeoutError('withdrawal patch unknown')
            patch_json = json.loads(args[5])
            assert patch_json[:2] == [{'op':'test','path':'/metadata/uid','value':'deployment-'+role},
                                     {'op':'test','path':'/metadata/resourceVersion','value':'rv-'+role}]
            assert patch_json[2] == {'op':'replace','path':'/spec/replicas','value':0}
            self.live[role] = 0; self.actual_pods.pop(role,None)
            return b''
        if args[0] == 'wait':
            role = args[4].split('=',1)[1]
            assert self.live[role] == 0
            self.actual_pods.pop(role,None)
            return b''
        raise AssertionError('Unexpected runtime command '+repr(args))


class ResumeFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='resume-91c7-', dir='/tmp')
        self.root = Path(self.temporary.name)
        self.work = self.root / 'work';self.work.mkdir(mode=0o700)
        self.bundle = self.root / 'bundle';self.bundle.mkdir(mode=0o700)
        self.journal = self.bundle / 'resume-v1'
        self.baseline = self.work / 'operational-baseline.json'
        self.admission = self.work / 'resume-v1-admission.json'
        installed = self.root/'installed';installed.mkdir(mode=0o700)
        source_hashes={}
        for name in m.SOURCE_HASHES:
            source=(installed/name) if name in ('upgrade-controller.py','physical-checkpoint.py') else (self.work/name)
            source.write_bytes(('# synthetic first-party admitted source '+name+'\n').encode());source.chmod(0o600)
            source_hashes[name]=m.sha(source.read_bytes())
        self.write(self.work/'source-manifest.json',source_hashes)
        helper = self.work / 'resume-helper.py'
        helper.write_bytes((ROOT / 'deploy/production/resume_91c7bcb7.py').read_bytes());helper.chmod(0o600)
        self.patches = [patch.object(m,'WORK',self.work),patch.object(m,'BUNDLE',self.bundle),
            patch.object(m,'JOURNAL',self.journal),patch.object(m,'BASELINE',self.baseline),
            patch.object(m,'ADMISSION',self.admission),patch.object(m,'now',return_value=NOW),
            patch.object(m,'CONTROLLER',installed/'upgrade-controller.py'),patch.object(m,'SOURCE_HASHES',source_hashes),
            patch.object(m,'__file__',str(helper)),
            patch.object(m.os,'fsync'),patch.object(m.os,'statvfs',return_value=types.SimpleNamespace(f_favail=1000)),
            patch('shutil.disk_usage',return_value=types.SimpleNamespace(free=m.RESERVE+1024**3))]
        for p in self.patches:p.start()
        self.authority = {'roles':[{'rolname':r,'verifier_sha256':r+'-hash'}
                          for r in ('devres_admin','devres_reader','devres_writer')],'memberships':[]}
        self.archive = {'backend':'s3','binding':'blake3:'+'b'*64,'epoch':2,
                        'store_id':'c'*32,'pending_binding':None,'initializing_s3':False}
        self.write(self.bundle / 'prepared.json',{'protected':'prepared'})
        prepared_sha = m.sha(m.raw(self.bundle/'prepared.json'))
        self.write(self.bundle / 'plan.json',{'revision':m.REVISION,'context':'default'})
        self.controller = FakeController(self)
        self.initial = {'revision':m.REVISION,'phase':'withdrawn','configs':'active','prepared_sha256':prepared_sha,
            'source_sha256':m.CONTROLLER_SHA,'replicas':{'postgres':1,'writer':0,'backend':0},
            'pods':self.controller.pods(),'images':{'postgres':m.PG_IMAGE,'writer':m.IMAGE,'backend':m.IMAGE}}
        self.write(self.bundle/'state.json',self.initial)
        self.original_state = m.raw(self.bundle/'state.json');self.expected_state=m.sha(self.original_state)
        self.write(self.baseline,{'revision':m.REVISION,'prepared_sha256':prepared_sha,
            'database':{'system_id':'system-id','archive':self.archive},'authority_sha256':m.sha(m.enc(self.authority))})
        config='[source]\nurl='+json.dumps(m.SOURCE_URL)+'\n'
        for provider in m.PROVIDERS:
            config+='['+provider+']\nenabled=true\n'
            if provider == 'npm':config+='advisories_enabled=true\n'
        self.write(self.bundle/'configs-active.json',{'backend':config,'writer':config})
        for name in m.FAILURE_NAMES:
            value={'context':'retained'}
            if name == 'late-failure-record.json':value={'version':1,'revision':m.REVISION,'withdrawal_completed':True,'root_cause':'unproved'}
            elif name == 'active-observation/completed.json':value={'revision':m.REVISION,'verified':True,'sample_count':32,'duration_seconds':929.967}
            self.write(self.work/name,value)
        for name in m.WT_NAMES:self.write(self.work/name,{'exit':0,'client_transport_override':False})
        for role in ('backend','writer'):
            self.write(self.bundle/('withdraw-'+role+'-intent.json'),{'original':'must remain immutable'})
        self.module = types.SimpleNamespace()

    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temporary.cleanup()

    def write(self,path,value):
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.write_bytes(value if isinstance(value,bytes) else m.enc(value));path.chmod(0o600)

    def identity(self, controller):
        owner=[]
        if controller.live['writer']:
            owner=[{'pid':29,'backend_start':'fixed','role':'devres_writer','client_addr':'10.42.0.2'}]
        return {'system_id':'system-id','schema':18,'recovery':False,'archive':copy.deepcopy(self.archive),
                'control':copy.deepcopy(m.POLICY),'owners':owner,'reader_select_gaps':0,
                'reader_mutation_tables':0,'reader_default_readonly':True}

    def approve(self):
        m.inspect(self.controller,self.expected_state)
        preflight=m.load(self.journal/'preflight.json')
        value={k:preflight[k] for k in ('state_sha256','helper_sha256','controller_sha256',
            'prepared_sha256','plan_sha256','baseline_sha256','failure_artifacts_sha256','namespace_preimage_sha256')}
        value.update(version=1,kind='exact-target-withdrawn-resume-admission',revision=m.REVISION,
            reviewed=True,operation='resume-v1',preflight_sha256=m.sha(m.raw(self.journal/'preflight.json')))
        self.write(self.admission,value)
        return m.sha(m.raw(self.admission))

    def execute(self,sha):
        return m.run(self.controller,self.module,self.expected_state,self.admission,sha)

    def test_inspect_preserves_withdrawn_state_and_never_creates_admission_or_changes_runtime(self):
        result=m.inspect(self.controller,self.expected_state)
        self.assertFalse(result['runtime_changed']);self.assertTrue(result['reviewed_admission_required'])
        self.assertFalse(self.admission.exists());self.assertFalse((self.journal/'admitted.json').exists())
        self.assertEqual(m.raw(self.journal/'withdrawn-state.json'),self.original_state)
        self.assertEqual(m.raw(self.bundle/'state.json'),self.original_state)
        self.assertEqual(self.controller.scale_calls,[])

    def test_wrong_expected_state_refused_before_creating_journal(self):
        with self.assertRaisesRegex(m.Error,'expected_withdrawn_state_changed'):
            m.inspect(self.controller,'f'*64)
        self.assertFalse(self.journal.exists());self.assertEqual(self.controller.scale_calls,[])

    def test_orphaned_new_resume_intent_is_not_replayed_or_admitted(self):
        self.write(self.bundle/'resume-v1-start-writer-intent.json',{'unknown':'prior result'})
        with self.assertRaisesRegex(m.Error,'resume_intent_already_exists'):
            m.inspect(self.controller,self.expected_state)
        self.assertFalse(self.journal.exists());self.assertEqual(self.controller.scale_calls,[])

    def test_preflight_requires_known_target_active_config_no_owner_and_unconsumed_finish(self):
        for field,value in [('phase','collectors_active'),('configs','paused')]:
            changed={**self.initial,field:value};self.write(self.bundle/'state.json',changed)
            with self.assertRaisesRegex(m.Error,'known_withdrawn_target_required'):
                m.inspect(self.controller,m.sha(m.raw(self.bundle/'state.json')))
        self.write(self.bundle/'state.json',self.initial)
        self.write(self.work/'observation-receipt.json',{'already':'consumed'})
        with self.assertRaisesRegex(m.Error,'finish_must_be_unconsumed'):
            m.inspect(self.controller,self.expected_state)

    def test_changed_credential_authority_or_schema_refused_before_mutation(self):
        self.authority['roles'][0]['verifier_sha256']='different'
        with self.assertRaisesRegex(m.Error,'database_credentials_or_roles_changed'):
            m.inspect(self.controller,self.expected_state)
        self.assertFalse(self.journal.exists());self.assertEqual(self.controller.scale_calls,[])

    def test_schema_policy_reader_permissions_and_remaining_owner_rejected(self):
        original=self.identity
        changes=[('schema',15,'original_database_policy_or_archive_changed'),
                 ('control',{**m.POLICY,'required_policy_epoch':1},'original_database_policy_or_archive_changed'),
                 ('reader_mutation_tables',1,'reader_authority_changed'),
                 ('owners',[{'role':'devres_writer','client_addr':'10.42.0.99'}],'writer_owner_remains')]
        for key,value,reason in changes:
            with self.subTest(field=key),patch.object(self,'identity',side_effect=lambda c,k=key,v=value:{**original(c),k:v}):
                with self.assertRaisesRegex(m.Error,reason):m.inspect(self.controller,self.expected_state)
            self.assertFalse(self.journal.exists())
        with self.assertRaisesRegex(m.Error,'fixed_readonly_query_required'):
            m.sql(self.controller,'UPDATE devres_schema SET version=1')

    def test_frozen_controller_is_hash_checked_before_import(self):
        source=self.work/'controller.py'
        source.write_bytes(b'raise AssertionError("unapproved controller executed")\n');source.chmod(0o600)
        with patch.object(m,'CONTROLLER',source):
            with self.assertRaisesRegex(m.Error,'frozen_controller_changed'):m.controller_module()

    def test_exact_external_admission_hash_and_freshness_required(self):
        sha=self.approve()
        with self.assertRaisesRegex(m.Error,'external_admission_hash'):
            self.execute('f'*64)
        with patch.object(m,'now',return_value=NOW+dt.timedelta(seconds=301)):
            with self.assertRaisesRegex(m.Error,'resume_preflight_stale'):self.execute(sha)
        self.assertFalse((self.journal/'admitted.json').exists());self.assertEqual(self.controller.scale_calls,[])

    def test_admission_is_rechecked_after_runtime_facts_before_mutation(self):
        sha=self.approve()
        with patch.object(m,'now',side_effect=[NOW,NOW+dt.timedelta(seconds=301)]):
            with self.assertRaisesRegex(m.Error,'resume_preflight_stale'):self.execute(sha)
        self.assertFalse((self.journal/'admitted.json').exists());self.assertEqual(self.controller.scale_calls,[])

    def test_modified_external_admission_cannot_self_expand_operation_scope(self):
        self.approve();value=m.load(self.admission);value['reviewed']=False
        self.write(self.admission,value)
        with self.assertRaisesRegex(m.Error,'exact_external_admission_required'):
            self.execute(m.sha(m.raw(self.admission)))
        self.assertFalse((self.journal/'admitted.json').exists());self.assertEqual(self.controller.scale_calls,[])

    def test_post_inspect_failure_artifact_or_namespace_drift_refused(self):
        sha=self.approve()
        self.write(self.work/'late-failure-pipeline.log',b'changed retained failure bytes')
        with self.assertRaisesRegex(m.Error,'resume_preflight_changed'):self.execute(sha)
        self.assertFalse((self.journal/'admitted.json').exists());self.assertEqual(self.controller.scale_calls,[])

    def test_all_eleven_original_proof_sources_are_pinned_before_resume(self):
        sha=self.approve()
        preflight=m.load(self.journal/'preflight.json')
        source_paths={item['path'] for item in preflight['failure_artifacts']}
        self.assertIn(str(self.work/'source-manifest.json'),source_paths)
        self.assertTrue(all(str((m.CONTROLLER.parent/name) if name in ('upgrade-controller.py','physical-checkpoint.py')
                               else (self.work/name)) in source_paths for name in m.SOURCE_HASHES))
        self.write(self.work/'phase-driver.py',b'# changed producer bytes\n')
        with self.assertRaisesRegex(m.Error,'original_operational_source_changed'):self.execute(sha)
        self.assertFalse((self.journal/'admitted.json').exists());self.assertEqual(self.controller.scale_calls,[])

    def test_changed_helper_or_namespace_preimage_refused_before_admission(self):
        sha=self.approve()
        snapshot=self.controller.snapshot()
        with patch.object(self.controller,'snapshot',return_value={**snapshot,'protected':{'edge':'changed'}}):
            with self.assertRaisesRegex(m.Error,'resume_preflight_changed'):self.execute(sha)
        Path(m.__file__).write_bytes(b'# changed helper bytes\n')
        with self.assertRaisesRegex(m.Error,'resume_preflight_changed'):self.execute(sha)
        self.assertFalse((self.journal/'admitted.json').exists());self.assertEqual(self.controller.scale_calls,[])

    def test_resume_uses_new_intents_preserves_old_evidence_and_requires_fresh_acceptance(self):
        sha=self.approve();old={p.name:p.read_bytes() for p in self.bundle.glob('withdraw-*-intent.json')}
        result=self.execute(sha)
        self.assertTrue(result['known_complete']);self.assertTrue(result['fresh_full_acceptance_required'])
        self.assertTrue(result['fresh_observation_required'])
        self.assertEqual(self.controller.state()['phase'],'collectors_active')
        self.assertEqual(self.controller.scale_calls,[('writer',1,'resume-v1-start-writer'),('backend',1,'resume-v1-start-reader')])
        self.assertEqual(m.raw(self.journal/'withdrawn-state.json'),self.original_state)
        self.assertEqual(old,{p.name:p.read_bytes() for p in self.bundle.glob('withdraw-*-intent.json')})
        with self.assertRaisesRegex(m.Error,'one_resume_attempt_only'):self.execute(sha)
        self.assertEqual(len(self.controller.scale_calls),2)

    def test_unknown_partial_start_is_withdrawn_with_only_new_role_intents(self):
        sha=self.approve();self.controller.fail_start='writer'
        result=self.execute(sha)
        self.assertFalse(result['known_complete']);self.assertTrue(result['withdrawal_completed'])
        self.assertFalse(result['manual_reconciliation_required'])
        self.assertEqual(self.controller.live,{'postgres':1,'writer':0,'backend':0})
        self.assertEqual(self.controller.state()['phase'],'withdrawn')
        self.assertEqual(self.controller.mutation_labels,['resume-v1-start-writer','resume-v1-withdraw-writer'])
        self.assertFalse((self.bundle/'resume-v1-start-writer-completed.json').exists())
        self.assertTrue((self.journal/'withdrawal.json').exists())

    def test_unknown_reader_start_with_running_writer_fences_both_using_new_intents(self):
        sha=self.approve();self.controller.fail_start='backend'
        result=self.execute(sha)
        self.assertTrue(result['withdrawal_completed'])
        self.assertEqual(self.controller.live,{'postgres':1,'writer':0,'backend':0})
        self.assertEqual(self.controller.mutation_labels,['resume-v1-start-writer','resume-v1-start-reader',
            'resume-v1-withdraw-backend','resume-v1-withdraw-writer'])

    def test_failed_fallback_never_claims_completed_withdrawal_and_is_not_replayed(self):
        sha=self.approve();self.controller.fail_start='writer';self.controller.fail_withdraw=True
        result=self.execute(sha)
        self.assertFalse(result['withdrawal_completed']);self.assertTrue(result['manual_reconciliation_required'])
        self.assertEqual(self.controller.live['writer'],1)
        with self.assertRaisesRegex(m.Error,'one_resume_attempt_only'):self.execute(sha)
        self.assertEqual(self.controller.mutation_labels,['resume-v1-start-writer','resume-v1-withdraw-writer'])

    def test_emergency_withdraw_after_success_allows_old_admission_but_preserves_full_history(self):
        sha=self.approve();self.execute(sha)
        state_sha=m.sha(m.raw(self.bundle/'state.json'))
        with patch.object(m,'now',return_value=NOW+dt.timedelta(minutes=25)):
            result=m.emergency_withdraw(self.controller,self.module,state_sha)
        self.assertTrue(result['withdrawal_completed'])
        self.assertEqual(self.controller.live,{'postgres':1,'writer':0,'backend':0})
        self.assertEqual(self.controller.mutation_labels,['resume-v1-start-writer','resume-v1-start-reader',
            'resume-v1-withdraw-backend','resume-v1-withdraw-writer'])
        self.assertTrue((self.journal/'resumed.json').exists());self.assertTrue((self.journal/'emergency-state.json').exists())
        with self.assertRaisesRegex(m.Error,'one_resume_withdrawal_attempt_only'):
            m.emergency_withdraw(self.controller,self.module,m.sha(m.raw(self.bundle/'state.json')))

    def test_emergency_fence_tolerates_actual_partial_zero_one_replicas(self):
        sha=self.approve();self.execute(sha)
        self.controller.live['backend']=0;self.controller.actual_pods.pop('backend')
        result=m.emergency_withdraw(self.controller,self.module,m.sha(m.raw(self.bundle/'state.json')))
        self.assertTrue(result['withdrawal_completed'])
        self.assertNotIn('resume-v1-withdraw-backend',self.controller.mutation_labels)
        self.assertIn('resume-v1-withdraw-writer',self.controller.mutation_labels)

    def test_emergency_fence_handles_finish_incomplete_and_failed_patch_honestly(self):
        sha=self.approve();self.execute(sha)
        state=self.controller.state();state['phase']='finish_incomplete';self.controller.record(state)
        self.controller.fail_withdraw=True
        result=m.emergency_withdraw(self.controller,self.module,m.sha(m.raw(self.bundle/'state.json')))
        self.assertFalse(result['withdrawal_completed']);self.assertTrue(result['manual_reconciliation_required'])
        self.assertEqual(self.controller.live['backend'],1)
        with self.assertRaisesRegex(m.Error,'one_resume_withdrawal_attempt_only'):
            m.emergency_withdraw(self.controller,self.module,m.sha(m.raw(self.bundle/'state.json')))

    def test_emergency_fence_refuses_changed_source_history_before_any_new_intent(self):
        sha=self.approve();self.execute(sha)
        self.write(self.bundle/'plan.json',{'changed':'plan'})
        with self.assertRaisesRegex(m.Error,'original_resume_boundary_changed'):
            m.emergency_withdraw(self.controller,self.module,m.sha(m.raw(self.bundle/'state.json')))
        self.assertFalse((self.journal/'emergency-withdraw-intent.json').exists())
        self.assertEqual(len(self.controller.mutation_labels),2)


if __name__=='__main__':unittest.main()
