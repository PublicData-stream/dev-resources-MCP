"""Offline runner evidence and fencing regressions with /tmp first-party children."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'deploy/production/acceptance_91c7bcb7/resume-v1-runner.py'
spec=importlib.util.spec_from_file_location('resume_runner_fixture',SOURCE)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class RunnerFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='resume-runner-',dir='/tmp')
        self.root=Path(self.temporary.name);self.root.chmod(0o700)
        self.work=self.root/'work';self.work.mkdir(mode=0o700)
        self.bundle=self.root/'bundle';self.bundle.mkdir(mode=0o700)
        self.logs=self.work/'command-evidence'
        self.patches=[patch.object(m,'WORK',self.work),patch.object(m,'BUNDLE',self.bundle),
            patch.object(m,'LOGS',self.logs),patch.object(m,'MANIFEST',self.work/'resume-v1-sources.json'),
            patch.object(m.os,'fsync')]
        for p in self.patches:p.start()

    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temporary.cleanup()

    def write(self,path,value):
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.write_bytes(value if isinstance(value,bytes) else json.dumps(value,sort_keys=True).encode())
        path.chmod(0o600)

    def record(self,label):
        return json.loads((self.logs/(label+'-result.json')).read_text())

    def child(self,code):
        return [sys.executable,'-B','-c',code]

    def test_stage_success_preserves_separate_stdout_stderr_bytes_and_hashes(self):
        self.logs.mkdir(mode=0o700)
        with contextlib.redirect_stdout(io.StringIO()):
            result=m.step('first',self.child('import sys;sys.stdout.buffer.write(b"stdout bytes\\n");sys.stderr.buffer.write(b"stderr bytes\\n")'),5)
        out=(self.logs/'first-stdout.log').read_bytes();err=(self.logs/'first-stderr.log').read_bytes()
        self.assertEqual(out,b'stdout bytes\n');self.assertEqual(err,b'stderr bytes\n')
        self.assertEqual(result,self.record('first'));self.assertEqual(result['exit_code'],0)
        self.assertFalse(result['timed_out']);self.assertFalse(result['log_truncated'])
        self.assertEqual(result['stdout_sha256'],hashlib.sha256(out).hexdigest())
        self.assertEqual(result['stderr_sha256'],hashlib.sha256(err).hexdigest())
        self.assertEqual((self.logs/'first-stdout.log').stat().st_mode&0o777,0o600)

    def test_nonzero_exit_keeps_both_streams_and_real_failure_status(self):
        self.logs.mkdir(mode=0o700)
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(m.Error,'child_step_failed'):
            m.step('nonzero',self.child('import sys;print("partial progress");print("concrete failure",file=sys.stderr);sys.exit(7)'),5)
        result=self.record('nonzero')
        self.assertEqual(result['exit_code'],7);self.assertFalse(result['timed_out'])
        self.assertEqual((self.logs/'nonzero-stdout.log').read_bytes(),b'partial progress\n')
        self.assertEqual((self.logs/'nonzero-stderr.log').read_bytes(),b'concrete failure\n')

    def test_timeout_keeps_partial_both_streams_without_claiming_an_exit_code(self):
        self.logs.mkdir(mode=0o700)
        code='import sys,time;print("partial stdout",flush=True);print("partial stderr",file=sys.stderr,flush=True);time.sleep(10)'
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(m.Error,'child_step_failed'):
            m.step('timeout',self.child(code),0.2)
        result=self.record('timeout')
        self.assertTrue(result['timed_out']);self.assertIsNone(result['exit_code'])
        self.assertEqual((self.logs/'timeout-stdout.log').read_bytes(),b'partial stdout\n')
        self.assertEqual((self.logs/'timeout-stderr.log').read_bytes(),b'partial stderr\n')

    def test_truncation_is_recorded_and_fails_even_if_child_exits_zero(self):
        self.logs.mkdir(mode=0o700)
        with patch.object(m,'MAX_LOG',8),contextlib.redirect_stdout(io.StringIO()),self.assertRaisesRegex(m.Error,'child_step_failed'):
            m.step('excess',self.child('import sys;sys.stdout.buffer.write(b"a"*20);sys.stderr.buffer.write(b"b"*12)'),5)
        result=self.record('excess')
        self.assertEqual((result['stdout_bytes'],result['stderr_bytes']),(20,12));self.assertTrue(result['log_truncated'])
        self.assertEqual((self.logs/'excess-stdout.log').read_bytes(),b'a'*8)
        self.assertEqual((self.logs/'excess-stderr.log').read_bytes(),b'b'*8)

    def test_exclusive_stage_intent_prevents_replaying_child_or_overwriting_evidence(self):
        self.logs.mkdir(mode=0o700)
        with contextlib.redirect_stdout(io.StringIO()):m.step('once',self.child('print("original")'),5)
        before={p.name:p.read_bytes() for p in self.logs.iterdir()}
        with patch.object(m.subprocess,'run') as child:
            with self.assertRaises(FileExistsError):m.step('once',self.child('print("replayed")'),5)
            child.assert_not_called()
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.logs.iterdir()})

    def setup_main(self):
        self.state={'phase':'collectors_active','resume_continuation':{'reviewed':True},
            'source_sha256':'a'*64,'prepared_sha256':'b'*64,
            'pods':{r:{'container_id':'new-'+r,'uid':'new-pod-'+r} for r in ('postgres','writer','backend')}}
        self.write(self.bundle/'state.json',self.state)
        self.controller=Mock();self.controller.locked.side_effect=contextlib.nullcontext
        self.controller.state.side_effect=lambda:copy.deepcopy(self.state)
        def finish(*args):
            self.assertEqual(args[0],'finish')
            self.assertEqual(args[3],str(self.work/'resume-v1-observation-receipt.json'))
            self.assertEqual(args[4],m.sha(m.read(self.work/'resume-v1-observation-receipt.json')))
            self.state['phase']='complete';self.write(self.bundle/'state.json',self.state)
        self.controller.run.side_effect=finish
        self.frozen=types.SimpleNamespace(Controller=Mock(return_value=self.controller))
        self.resume=types.SimpleNamespace(JOURNAL=self.work/'resume-journal',
            controller_module=Mock(return_value=self.frozen),
            load=Mock(return_value={'known_complete':True,'pods':self.state['pods']}),
            emergency_withdraw=Mock(return_value={'withdrawal_completed':True}))
        self.new={k:k+'-hash' for k in ('helper','public','receipt','runner')}
        self.old={k:'c'*64 for k in ('upgrade-controller.py','physical-checkpoint.py','compressed-probe.py')}
        self.commands=[]
        def success(label,command,timeout):
            self.commands.append((label,command,timeout))
            if label=='aggregate':self.write(self.work/'resume-v1-observation-receipt.json',{'verified':True,'new':'receipt'})
            return {'exit_code':0}
        return success

    def main(self,step):
        output=io.StringIO()
        actual_uid=os.geteuid();first=[True]
        def uid():
            # Only the CLI root gate is simulated; real /tmp ownership checks use
            # the actual invoking fixture user rather than bypassing file guards.
            if first[0]:first[0]=False;return 0
            return actual_uid
        with patch.object(m.os,'geteuid',side_effect=uid),\
             patch.object(m.sys,'argv',['resume-v1-runner.py','--source-manifest-sha256','d'*64]),\
             patch.object(m,'checked_sources',return_value=(self.new,self.old)) as sources,\
             patch.object(m,'module',return_value=self.resume) as load_module,\
             patch.object(m,'step',side_effect=step),contextlib.redirect_stdout(output):
            result=m.main()
        load_module.assert_called_once_with(m.RESUME,self.new['helper'],'admitted_resume_helper')
        return result,output,sources.call_count

    def test_main_success_runs_fresh_full_early_matrix_new_observation_and_custom_receipt(self):
        step=self.setup_main();code,output,source_checks=self.main(step)
        self.assertEqual(code,0);self.assertEqual(source_checks,14)
        labels=[label for label,_,_ in self.commands]
        self.assertEqual(labels,['early-before','early-private','early-public','early-codecs','early-after','observation',
            'late-before','late-private','late-public','late-codecs','late-after','aggregate'])
        commands={label:command for label,command,_ in self.commands}
        self.assertEqual(commands['early-public'][-2:],['resume-v1-early-public','full'])
        self.assertEqual(commands['late-public'][-2:],['resume-v1-late-public','bounded'])
        observe=commands['observation'];self.assertEqual(observe[observe.index('--label')+1],'resume-v1-observation')
        aggregate=commands['aggregate'];self.assertEqual(aggregate[aggregate.index('--observation')+1],'resume-v1-observation')
        self.assertEqual(aggregate[aggregate.index('--early')+1],'resume-v1-early')
        self.assertEqual(aggregate[aggregate.index('--late')+1],'resume-v1-late')
        self.controller.run.assert_called_once();self.controller.withdraw.assert_not_called()
        self.resume.emergency_withdraw.assert_not_called()
        self.assertTrue((self.logs/'completed.json').exists());self.assertFalse((self.logs/'failed.json').exists())
        self.assertEqual(json.loads(output.getvalue()),{'known_complete':True,'phase':'complete'})

    def test_main_stage_failure_uses_new_resume_fence_and_never_old_withdraw(self):
        self.setup_main()
        def fail(*args):raise m.Error('child_step_failed')
        code,_,_=self.main(fail)
        self.assertEqual(code,1);self.controller.run.assert_not_called();self.controller.withdraw.assert_not_called()
        self.resume.emergency_withdraw.assert_called_once_with(self.controller,self.frozen,m.sha(m.read(self.bundle/'state.json')))
        result=json.loads((self.logs/'failed.json').read_text())
        self.assertTrue(result['withdrawal_completed']);self.assertFalse(result['manual_reconciliation_required'])
        self.assertEqual(result['code'],'child_step_failed')

    def test_main_failed_new_fence_never_claims_withdrawal_completed(self):
        self.setup_main();self.resume.emergency_withdraw.side_effect=RuntimeError('fence unavailable')
        def fail(*args):raise m.Error('child_step_failed')
        code,_,_=self.main(fail)
        self.assertEqual(code,1);self.controller.withdraw.assert_not_called()
        self.resume.emergency_withdraw.assert_called_once()
        result=json.loads((self.logs/'failed.json').read_text())
        self.assertFalse(result['withdrawal_completed']);self.assertTrue(result['manual_reconciliation_required'])

    def test_main_new_fence_false_result_is_also_reported_incomplete(self):
        self.setup_main();self.resume.emergency_withdraw.return_value={'withdrawal_completed':False}
        def fail(*args):raise TimeoutError('child runner exception')
        code,_,_=self.main(fail)
        self.assertEqual(code,1);self.controller.withdraw.assert_not_called()
        self.resume.emergency_withdraw.assert_called_once()
        result=json.loads((self.logs/'failed.json').read_text())
        self.assertFalse(result['withdrawal_completed']);self.assertTrue(result['manual_reconciliation_required'])
        self.assertEqual(result['code'],'resume_acceptance_failed')

    def test_main_finish_failure_also_uses_new_fence_and_preserves_finish_intent(self):
        step=self.setup_main();self.controller.run.side_effect=RuntimeError('finish failed')
        code,_,_=self.main(step)
        self.assertEqual(code,1);self.resume.emergency_withdraw.assert_called_once();self.controller.withdraw.assert_not_called()
        self.assertTrue((self.logs/'finish-intent.json').exists())
        self.assertFalse((self.logs/'completed.json').exists())
        self.assertTrue((self.logs/'failed.json').exists())

    def test_main_existing_attempt_is_not_replayed(self):
        self.setup_main();self.logs.mkdir(mode=0o700);self.write(self.logs/'existing.json',{'retained':True})
        with self.assertRaisesRegex(m.Error,'one_acceptance_runner_attempt_only'):
            self.main(lambda *a:self.fail('child was replayed'))
        self.controller.run.assert_not_called();self.resume.emergency_withdraw.assert_not_called()
        self.assertEqual(json.loads((self.logs/'existing.json').read_text()),{'retained':True})


if __name__=='__main__':unittest.main()
