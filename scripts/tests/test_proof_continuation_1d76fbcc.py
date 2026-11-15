"""One-shot continuation bounds; no provider, Docker or production operations."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
m=module('proof_successor_test',ROOT/'deploy/production/proof_continuation_1d76fbcc.py')
cp=module('proof_config_source',ROOT/'deploy/production/checkpoint_1d76fbcc.py')
fixtures=module('proof_config_fixture',ROOT/'scripts/tests/test_checkpoint_1d76fbcc.py')

class ProofContinuation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='proof-successor-tests-',dir='/tmp');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.original=self.root/'original';self.original.mkdir(mode=0o700)
        self.scope=self.original/'proof-successor-v1';self.scope.mkdir(mode=0o700)
        self.install=self.root/'install';self.install.mkdir(mode=0o700)
        self.patches=[patch.object(m,'ORIGINAL',self.original),patch.object(m,'SCOPE',self.scope),patch.object(m,'INSTALL',self.install)]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def writer_text(self):
        fixture=fixtures.Fixtures('test_writer_clone_has_no_provider_or_kubernetes_authority')
        text=fixture.config().split('[writer_client]')[0].replace('devres_reader:','devres_writer:')
        return text+'[writer_listener]\nbind="0.0.0.0:9443"\ncertificate="/run/devres-writer-tls/tls.crt"\nprivate_key="/run/devres-writer-tls/tls.key"\nallowed_clients=[{namespace="devres",service_account="devres-serving"}]\n[writer_listener.auth]\nkube_api_url="https://kubernetes.default.svc"\nkube_token_file="/run/devres-kube/token"\nkube_ca_file="/run/devres-kube/ca.crt"\naudience="devres-writer"\n'
    def test_only_writer_cache_ceiling_changes_from_frozen_configuration(self):
        text=self.writer_text();limit=64*1024**3
        text=cp.replace_scalar(text,'storage.s3','cache_max_bytes',limit)
        frozen=cp.tomllib.loads(cp.writer_config(text))
        value=m.corrected_writer_config(cp,cp.writer_config,text,limit)
        expected=cp.tomllib.loads(value)
        self.assertEqual(expected['storage']['s3']['cache_max_bytes'],limit)
        expected['storage']['s3']['cache_max_bytes']=64*1024**2
        self.assertEqual(expected,frozen)
        self.assertTrue(all(not cp.tomllib.loads(value)[provider]['enabled'] for provider in cp.PROVIDERS))
        self.assertEqual(cp.tomllib.loads(value)['writer_listener']['bind'],'127.0.0.1:9443')
        with self.assertRaisesRegex(m.Stop,'original_cache_ceiling_changed'):
            m.corrected_writer_config(cp,cp.writer_config,text,limit+1)
    def test_sanitized_diagnostics_exclude_keys_database_urls_and_private_keys(self):
        body=b'failure secret-token postgres://user:pass@host/db\nhttps://source.example/private\n-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\nError capacity\n'
        text=m.sanitize_logs(body,['secret-token'])
        for private in ('secret-token','postgres://','https://','private-material','BEGIN PRIVATE KEY'):
            self.assertNotIn(private,text)
        self.assertIn('Error capacity',text)
    def test_pem_start_outside_tail_and_already_truncated_base64_are_suppressed(self):
        secret='MIIEBASE64PRIVATEPAYLOAD0123456789abcdefghijklmnopqrstuvwxyz'
        text=m.sanitize_logs(('-----BEGIN PRIVATE KEY-----\n'+(secret+'\n')*90+'-----END PRIVATE KEY-----\nError capacity\n').encode(),[])
        self.assertNotIn(secret,text);self.assertIn('Error capacity',text)
        text=m.sanitize_logs((secret+'\n'+secret[-12:]+'\n-----END PRIVATE KEY-----\nError capacity').encode(),[])
        self.assertNotIn(secret,text);self.assertNotIn(secret[-12:],text);self.assertIn('Error capacity',text)
    def test_real_blocked_fsync_child_cannot_hold_original_cleanup(self):
        import time
        m.save(self.scope/'owner.json',{'token':'ab'*12,'pins':{}})
        events=[];parent=os.getpid();actual_fsync=os.fsync
        def writer(*a,**kw):raise m.Stop('fixture_writer_failure')
        fake=types.SimpleNamespace(S=self.original,writer_config=lambda s:s,disk_identity=lambda:{'id':1},
            cleanup_clone=lambda *a:events.append('cleanup'),fallback_writer_proof=writer,
            cold_body_readback=lambda:None,notice_readback=lambda:None,Stop=m.Stop)
        def proof(pins):
            try:fake.fallback_writer_proof()
            finally:fake.cleanup_clone([],None,'ab'*12)
        fake.proof=proof
        def blocked_fsync(fd):
            if os.getpid()!=parent:time.sleep(30)
            return actual_fsync(fd)
        original_capture=m.capture_independently
        def capture(*args):return original_capture(*args,timeout=.05)
        started=time.monotonic()
        with patch.object(m,'seed_scope',return_value={'disk_identity':{'id':1}}),\
             patch.object(m,'capture_before_cleanup',side_effect=lambda *a:m.save(self.scope/'blocking.json',{})),\
             patch.object(m.os,'fsync',side_effect=blocked_fsync),patch.object(m,'capture_independently',side_effect=capture):
            with self.assertRaisesRegex(m.Stop,'fixture_writer_failure'):
                m.execute(fake,{'writer_cache_max_bytes':64*1024**3},self.root/'admission','a'*64)
        self.assertEqual(events,['cleanup']);self.assertLess(time.monotonic()-started,2)
        self.assertFalse(m.load(self.scope/'failure.json')['diagnostics_persisted'])
    def test_capture_success_requires_persisted_acknowledgement(self):
        def produce(*args):m.save(self.scope/'pre-cleanup-diagnostics.json',{'containers':[]})
        with patch.object(m,'capture_before_cleanup',side_effect=produce):
            self.assertTrue(m.capture_independently(None,[],'ab'*12,'writer',timeout=1))
        ack=m.load(self.scope/'diagnostics-ack.json')
        self.assertEqual(ack['token'],'ab'*12)
        self.assertEqual(ack['diagnostics_sha256'],m.sha(m.read(self.scope/'pre-cleanup-diagnostics.json')))
    def test_bounded_child_caps_real_stdout_and_stderr_before_buffering(self):
        body,truncated=m.bounded_child([sys.executable,'-c','import sys;sys.stderr.buffer.write(b"x"*1000000)'],maximum=512,merge_stderr=True)
        self.assertEqual(len(body),512);self.assertTrue(truncated)
    def test_blocked_child_is_killed_within_bounded_reader_deadline(self):
        import time
        started=time.monotonic()
        _,cut=m.bounded_child([sys.executable,'-c','import time;time.sleep(30)'],timeout=.05)
        self.assertTrue(cut);self.assertLess(time.monotonic()-started,2)
    def test_diagnostic_failure_never_prevents_owned_cleanup_or_changes_frozen_callbacks(self):
        m.save(self.scope/'owner.json',{'token':'ab'*12,'pins':{}})
        events=[]
        def writer(*a,**kw):raise m.Stop('fixture_writer_failure')
        def cleanup(*a):events.append('cleanup')
        fake=types.SimpleNamespace(S=self.original,writer_config=lambda s:s,disk_identity=lambda:{'id':1},
            cleanup_clone=cleanup,fallback_writer_proof=writer,cold_body_readback=lambda:None,notice_readback=lambda:None,Stop=m.Stop)
        def proof(pins):
            try:fake.fallback_writer_proof()
            finally:fake.cleanup_clone([],None,'ab'*12)
        fake.proof=proof
        with patch.object(m,'seed_scope',return_value={'disk_identity':{'id':1}}),\
             patch.object(m,'capture_independently',return_value=False):
            with self.assertRaisesRegex(m.Stop,'fixture_writer_failure'):
                m.execute(fake,{'writer_cache_max_bytes':64*1024**3},self.root/'admission','a'*64)
        self.assertEqual(events,['cleanup']);self.assertEqual(fake.S,self.original)
        self.assertIs(fake.cleanup_clone,cleanup);self.assertIs(fake.fallback_writer_proof,writer)
        failure=m.load(self.scope/'failure.json')
        self.assertFalse(failure['diagnostics_persisted']);self.assertEqual(failure['phase'],'fallback_writer_proof')
    def test_diagnostics_are_attempted_before_cleanup_on_original_writer_failure(self):
        m.save(self.scope/'owner.json',{'token':'ab'*12,'pins':{}})
        events=[]
        def writer(*a,**kw):raise m.Stop('fixture_writer_failure')
        fake=types.SimpleNamespace(S=self.original,writer_config=lambda s:s,disk_identity=lambda:{'id':1},
            cleanup_clone=lambda *a:events.append('cleanup'),fallback_writer_proof=writer,
            cold_body_readback=lambda:None,notice_readback=lambda:None,Stop=m.Stop)
        def proof(pins):
            try:fake.fallback_writer_proof()
            finally:fake.cleanup_clone([],None,'ab'*12)
        fake.proof=proof
        with patch.object(m,'seed_scope',return_value={'disk_identity':{'id':1}}),\
             patch.object(m,'capture_independently',side_effect=lambda *a:(events.append('diagnostics') or True)):
            with self.assertRaises(m.Stop):m.execute(fake,{'writer_cache_max_bytes':64*1024**3},self.root/'admission','a'*64)
        self.assertEqual(events,['diagnostics','cleanup'])
    def publication_inputs(self):
        old={name:('failed:'+name).encode() for name in m.FAILED}
        for name,body in old.items():m.save(self.original/name,body)
        for name in ('clone-proof-result.json','clone-writer-proof.json','completed.json','admission.json'):
            m.save(self.scope/name,{'success':name})
        m.save(self.scope/'backup-receipt.json',{'kind':'coordinated-schema18-backup','artifacts':[]})
        m.save(self.scope/'pre-cleanup-0.log',b'redacted diagnostic line')
        m.save(self.scope/'owner.json',{'token':'ab'*12})
        m.save(self.scope/'pre-cleanup-diagnostics.json',{'phase':'writer','containers':[{'log_path':str(self.scope/'pre-cleanup-0.log'),'log_sha256':m.sha(b'redacted diagnostic line')}]})
        m.save(self.scope/'diagnostics-ack.json',{'token':'ab'*12,'phase':'writer','diagnostics_sha256':m.sha(m.read(self.scope/'pre-cleanup-diagnostics.json')),'logs':{str(self.scope/'pre-cleanup-0.log'):m.sha(b'redacted diagnostic line')}})
        m.save(self.install/'proof-continuation.py',b'reviewed-source')
        a={'source_sha256':m.sha(b'reviewed-source'),'failed_proof_sha256':{name:m.sha(body) for name,body in old.items()},
           'global_manifest_sha256':'f'*64,'private_input_manifest_sha256':'e'*64,'writer_cache_max_bytes':64*1024**3}
        return a,old
    def test_published_success_creates_missing_outputs_and_retains_original_failed_bytes(self):
        a,old=self.publication_inputs()
        m.publish_missing(None,a,'a'*64)
        self.assertEqual({name:m.read(self.original/name) for name in m.FAILED},old)
        completed=m.load(self.original/'completed.json')
        self.assertEqual(completed['proof_continuation']['admission_sha256'],'a'*64)
        backup=m.load(self.original/'backup-receipt.json')
        self.assertEqual(backup['proof_continuation']['only_change'],'restore_original_writer_cache_ceiling')
        self.assertTrue(any(a['path']==str(self.scope/'admission.json') for a in backup['artifacts']))
        self.assertTrue(any(a['path']==str(self.scope/'pre-cleanup-0.log') for a in backup['artifacts']))
        planned=m.load(self.scope/'publication-intent.json')['planned_output_sha256']
        self.assertEqual(planned['backup-receipt.json'],m.sha(m.read(self.original/'backup-receipt.json')))
        with self.assertRaisesRegex(m.Stop,'already_present'):m.publish_missing(None,a,'a'*64)
    def test_partial_publication_has_planned_hashes_and_never_publishes_backup_early(self):
        a,old=self.publication_inputs();save=m.save;attempts=[]
        def cut(path,body):
            if path.parent==self.original:
                attempts.append(path.name)
                if path.name=='completed.json':raise OSError('fixture publication disk failure')
            return save(path,body)
        with patch.object(m,'save',side_effect=cut),self.assertRaises(OSError):m.publish_missing(None,a,'a'*64)
        self.assertFalse((self.original/'backup-receipt.json').exists())
        self.assertEqual(attempts,['clone-proof-result.json','clone-writer-proof.json','completed.json'])
        planned=m.load(self.scope/'publication-intent.json')
        self.assertTrue(planned['backup_last']);self.assertIn('backup-receipt.json',planned['planned_output_sha256'])
        self.assertEqual({name:m.read(self.original/name) for name in m.FAILED},old)
        with self.assertRaises(m.Stop):m.publish_missing(None,a,'a'*64)
    def test_conflicting_preexisting_output_or_changed_log_blocks_all_original_writes(self):
        a,_=self.publication_inputs();m.save(self.original/'clone-writer-proof.json',b'conflict')
        with self.assertRaisesRegex(m.Stop,'already_present'):m.publish_missing(None,a,'a'*64)
        self.assertFalse((self.original/'completed.json').exists());self.assertFalse((self.original/'backup-receipt.json').exists())
        self.assertEqual(m.read(self.original/'clone-writer-proof.json'),b'conflict')
    def test_log_drift_is_detected_before_publication_intent(self):
        a,_=self.publication_inputs();(self.scope/'pre-cleanup-0.log').write_bytes(b'changed')
        with self.assertRaisesRegex(m.Stop,'diagnostic_log_changed'):m.publish_missing(None,a,'a'*64)
        self.assertFalse((self.scope/'publication-intent.json').exists())
        self.assertFalse((self.original/'completed.json').exists())
    def test_scope_cannot_reuse_existing_failed_or_completed_attempt(self):
        with self.assertRaisesRegex(m.Stop,'one_successor_proof_attempt_only'):
            m.seed_scope(None,{},self.root/'admission','a'*64)

    def test_original_private_authority_and_every_immutable_pin_are_revalidated(self):
        work=self.root/'work';work.mkdir(mode=0o700);bundle=self.root/'bundle';bundle.mkdir(mode=0o700)
        source=self.root/'continuation.py';m.save(source,b'new reviewed helper')
        m.save(self.install/'physical-checkpoint.py',b'frozen checkpoint')
        public=work/'public.json';approval=work/'approval.json'
        for path in (work/'source-manifest.json',public,approval,bundle/'prepared.json'):
            m.save(path,b'original-admitted')
        m.save(self.original/'owner.json',{'pins':{'source':'original'}})
        for name in m.IMMUTABLE+m.FAILED:m.save(self.original/name,('original:'+name).encode())
        private_manifest={'files':'sealed-private-config-keys-tls'}
        fake=types.SimpleNamespace(PUBLIC=public,APPROVAL=approval,enc=m.enc,
            cache_manifest=lambda path:private_manifest,authorize=lambda:{'source':'original'})
        a={'source_sha256':m.sha(m.read(source)),'checkpoint_source_sha256':m.sha(b'frozen checkpoint'),
           'global_manifest_sha256':m.sha(m.read(work/'source-manifest.json')),'public_identity_sha256':m.sha(m.read(public)),
           'checkpoint_approval_sha256':m.sha(m.read(approval)),'prepared_sha256':m.sha(m.read(bundle/'prepared.json')),
           'original_owner_sha256':m.sha(m.read(self.original/'owner.json')),
           'immutable_sha256':{name:m.sha(m.read(self.original/name)) for name in m.IMMUTABLE},
           'failed_proof_sha256':{name:m.sha(m.read(self.original/name)) for name in m.FAILED},
           'private_input_manifest_sha256':m.sha(m.enc(private_manifest))}
        with patch.object(m,'WORK',work),patch.object(m,'BUNDLE',bundle),patch.object(m,'__file__',str(source)):
            m.verify_original_pins(fake,a)
            for path in [*(self.original/name for name in m.IMMUTABLE),public,approval,work/'source-manifest.json',bundle/'prepared.json',self.original/'owner.json',source,self.install/'physical-checkpoint.py']:
                original=m.read(path);path.write_bytes(original+b'changed')
                with self.subTest(path=path),self.assertRaises(m.Stop):m.verify_original_pins(fake,a)
                path.write_bytes(original)
            private_manifest['files']='changed-private-config'
            with self.assertRaisesRegex(m.Stop,'private_proof_inputs_changed'):m.verify_original_pins(fake,a)
    def test_actual_old_owned_containers_networks_or_nft_table_block_new_scope(self):
        token='ab'*12;m.save(self.original/'owner.json',{'token':token})
        fake=types.SimpleNamespace(LABEL='owner',run=None)
        for container,network,tables in [(b'old-id',b'',[]),(b'',b'old-network',[]),(b'',b'',[{'table':{'name':'devres_cp_'+token}}])]:
            results=iter((container,network,m.enc({'nftables':tables})))
            fake.run=lambda *a:next(results)
            with self.assertRaises(m.Stop):m.old_scope_absent(fake)

if __name__=='__main__':unittest.main()
