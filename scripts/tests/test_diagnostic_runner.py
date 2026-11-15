"""Local supervision fixtures; no cluster/provider commands or production state."""
import json
import multiprocessing
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from deploy.diagnostics.evidence import EventRecorder, EvidenceError
from deploy.diagnostics.runner import DiagnosticRunner
import deploy.diagnostics.runner as runner_module


class DiagnosticRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp', prefix='diagnostic-runner-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # Unit success cases verify contents/ownership; explicit fault fixtures
        # below replace fsync with a hang/error. Avoid timing dependence on other
        # concurrent workspace builds flushing the same host filesystem.
        sync = patch('os.fsync', return_value=None)
        sync.start()
        self.addCleanup(sync.stop)
        self.fenced = multiprocessing.get_context('fork').Event()

    def collect(self, recorder, stop):
        recorder.record('pod', {'role': 'backend', 'ready': True, 'restarts': 1})
        stop.wait()

    def fence(self):
        self.fenced.set()
        return True

    def run_child(self, code, *, collect=None, fence=None, **options):
        runner_options = {k: options.pop(k) for k in list(options)
                          if k in {'output_limit', 'evidence_timeout', 'fence_timeout', 'pipe_grace'}}
        runner = DiagnosticRunner(self.root, evidence_timeout=runner_options.pop('evidence_timeout', 1.0),
                                  fence_timeout=runner_options.pop('fence_timeout', 0.2), **runner_options)
        return runner.run([sys.executable, '-B', '-c', code], timeout_seconds=options.pop('timeout', 2),
                          collect=collect or self.collect, fence=fence or self.fence, **options)

    def test_success_preserves_stdout_stderr_and_starts_runtime_before_child(self):
        started = multiprocessing.get_context('fork').Event()
        def collect(recorder, stop):
            started.set()
            self.collect(recorder, stop)
        result = self.run_child('import sys;print("fixture out");print("fixture err",file=sys.stderr)', collect=collect)
        self.assertTrue(started.is_set())
        self.assertEqual(result.code, 'ok')
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.persisted)
        self.assertTrue(result.runtime_evidence_complete)
        self.assertFalse(self.fenced.is_set())
        self.assertEqual((self.root/'stdout.log').read_bytes(), b'fixture out\n')
        self.assertEqual((self.root/'stderr.log').read_bytes(), b'fixture err\n')
        for path in self.root.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        receipt = json.loads((self.root/'outcome.json').read_text())
        self.assertFalse(receipt['final_outcome'])
        self.assertFalse(receipt['capture']['persisted'])
        self.assertEqual(receipt['capture']['stdout_bytes'], 12)
        self.assertNotIn('command', receipt)

    def test_saturated_both_pipes_drain_without_deadlock_with_fixed_prefixes(self):
        code = 'import os,threading;t=threading.Thread(target=lambda:os.write(2,b"e"*1000000));t.start();os.write(1,b"o"*1000000);t.join()'
        result = self.run_child(code, output_limit=2048)
        self.assertEqual(result.code, 'output_truncated')
        self.assertEqual((result.stdout_bytes, result.stderr_bytes), (1000000, 1000000))
        self.assertEqual((result.stdout_retained, result.stderr_retained), (2048, 2048))
        self.assertTrue(result.truncated)
        self.assertTrue(result.withdrawal_completed)
        self.assertEqual(len((self.root/'stdout.log').read_bytes()), 2048)

    def test_timeout_preserves_partial_streams_and_kills_child(self):
        result = self.run_child('import sys,time;print("partial",flush=True);print("error",file=sys.stderr,flush=True);time.sleep(30)', timeout=0.15)
        self.assertEqual(result.code, 'timeout')
        self.assertTrue(result.timed_out)
        self.assertTrue(result.withdrawal_completed)
        self.assertEqual((self.root/'stdout.log').read_bytes(), b'partial\n')
        self.assertEqual((self.root/'stderr.log').read_bytes(), b'error\n')
        self.assertEqual(result.exit_code, -signal.SIGKILL)

    def test_killed_child_records_signal_and_fences(self):
        result = self.run_child('import os,signal;os.kill(os.getpid(),signal.SIGKILL)')
        self.assertEqual((result.code, result.exit_code), ('child_failed', -signal.SIGKILL))
        self.assertTrue(result.withdrawal_completed)

    def test_descendant_held_pipe_has_bounded_cleanup(self):
        started = time.monotonic()
        code = 'import os,time;pid=os.fork();time.sleep(30) if pid==0 else None'
        result = self.run_child(code, pipe_grace=0.08)
        self.assertLess(time.monotonic()-started, 1.5)
        self.assertTrue(result.descendant_pipes)
        self.assertEqual(result.code, 'descendant_pipe_deadline')
        self.assertTrue(result.withdrawal_completed)

    def test_launch_failure_retains_finite_outcome_without_arguments_or_error(self):
        result = DiagnosticRunner(self.root, evidence_timeout=0.15).run(
            ['/does-not-exist/PRIVATE_ARGUMENT'], timeout_seconds=1, collect=self.collect, fence=self.fence)
        self.assertEqual(result.code, 'launch_failed')
        self.assertIsNone(result.exit_code)
        self.assertTrue(result.withdrawal_completed)
        self.assertNotIn('PRIVATE_ARGUMENT', (self.root/'outcome.json').read_text())

    def test_fsync_hang_cannot_delay_failure_fence_or_return(self):
        fenced_at = multiprocessing.get_context('fork').Value('d', 0.0)
        def fence():
            fenced_at.value = time.monotonic()
            return True
        started = time.monotonic()
        with patch('os.fsync', side_effect=lambda _: time.sleep(10)):
            result = self.run_child('raise SystemExit(2)', fence=fence, evidence_timeout=0.08)
        self.assertLess(fenced_at.value-started, 0.7)
        self.assertLess(time.monotonic()-started, 1.2)
        self.assertTrue(result.withdrawal_completed)
        self.assertFalse(result.persisted)
        self.assertFalse(result.runtime_evidence_complete)

    def test_disk_write_error_still_fences_and_reports_missing_artifact(self):
        with patch('os.fsync', side_effect=OSError('PRIVATE_DISK_ERROR')):
            result = self.run_child('raise SystemExit(1)')
        self.assertTrue(result.withdrawal_completed)
        self.assertFalse(result.persisted)
        for path in self.root.iterdir():
            self.assertNotIn(b'PRIVATE_DISK_ERROR', path.read_bytes())

    def test_collector_hang_is_killed_and_successful_child_cannot_pass(self):
        def hang(recorder, stop):
            recorder.record('edge', {'code':'started'})
            time.sleep(30)
        started = time.monotonic()
        result = self.run_child('pass', collect=hang, evidence_timeout=0.08)
        self.assertLess(time.monotonic()-started, 1)
        self.assertEqual(result.code, 'runtime_incomplete')
        self.assertFalse(result.runtime_evidence_complete)
        self.assertTrue(result.withdrawal_completed)

    def test_runtime_event_or_selector_setup_failure_still_fences(self):
        for target in ('event','selector'):
            with self.subTest(target=target), tempfile.TemporaryDirectory(dir='/tmp') as root:
                before = signal.getsignal(signal.SIGTERM)
                patched = (patch.object(runner_module.CONTEXT,'Event',side_effect=OSError('PRIVATE_SETUP_ERROR'))
                           if target=='event' else patch.object(runner_module.selectors,'DefaultSelector',side_effect=OSError('PRIVATE_SETUP_ERROR')))
                with patched:
                    result = DiagnosticRunner(Path(root),evidence_timeout=0.15).run(
                        [sys.executable,'-B','-c','pass'],timeout_seconds=1,collect=self.collect,fence=self.fence)
                self.assertEqual(result.code,'supervision_failed')
                self.assertTrue(result.withdrawal_completed)
                self.assertEqual(result.fence_code,'complete')
                self.assertEqual(signal.getsignal(signal.SIGTERM),before)

    def test_fence_pipe_setup_failure_is_explicitly_incomplete(self):
        original = runner_module.CONTEXT.Pipe
        calls = [0]
        def pipe(*args,**kwargs):
            calls[0] += 1
            if calls[0] == 2:
                raise OSError('PRIVATE_PIPE_FAILURE')
            return original(*args,**kwargs)
        before = signal.getsignal(signal.SIGTERM)
        with patch.object(runner_module.CONTEXT,'Pipe',side_effect=pipe):
            result = self.run_child('raise SystemExit(1)')
        self.assertFalse(result.withdrawal_completed)
        self.assertEqual(result.fence_code,'launch_failed')
        self.assertEqual(signal.getsignal(signal.SIGTERM),before)
        self.assertNotIn('PRIVATE_', (self.root/'outcome.json').read_text())

    def test_persistence_pipe_setup_failure_still_fences_and_restores_handlers(self):
        original = runner_module.CONTEXT.Pipe
        calls = [0]
        def pipe(*args,**kwargs):
            calls[0] += 1
            if calls[0] == 2:
                raise OSError('PRIVATE_PIPE_FAILURE')
            return original(*args,**kwargs)
        before = signal.getsignal(signal.SIGTERM)
        with patch.object(runner_module.CONTEXT,'Pipe',side_effect=pipe):
            result = self.run_child('pass')
        self.assertEqual(result.code,'persistence_failed')
        self.assertFalse(result.persisted)
        self.assertTrue(result.withdrawal_completed)
        self.assertEqual(result.fence_code,'complete')
        self.assertEqual(signal.getsignal(signal.SIGTERM),before)

    def test_all_pipe_setup_failures_return_finite_incomplete_outcome(self):
        before = signal.getsignal(signal.SIGTERM)
        with patch.object(runner_module.CONTEXT,'Pipe',side_effect=OSError('PRIVATE_RESOURCE_ERROR')):
            result = self.run_child('pass')
        self.assertEqual(result.code,'supervision_failed')
        self.assertEqual(result.fence_code,'launch_failed')
        self.assertFalse(result.persisted)
        self.assertFalse(result.withdrawal_completed)
        self.assertEqual(signal.getsignal(signal.SIGTERM),before)

    def test_group_signal_error_never_bypasses_independent_fence(self):
        with patch.object(runner_module, '_group_signal', side_effect=PermissionError('PRIVATE_KILL_ERROR')):
            result = self.run_child('raise SystemExit(1)')
        self.assertTrue(self.fenced.is_set())
        self.assertTrue(result.withdrawal_completed)
        self.assertEqual(result.fence_code,'complete')
        self.assertFalse(result.child_cleanup_complete)
        for artifact in self.root.iterdir():
            self.assertNotIn(b'PRIVATE_KILL_ERROR',artifact.read_bytes())

    def test_interrupt_during_persistence_cannot_leave_a_final_success_receipt(self):
        def interrupt(fd):
            if os.readlink('/proc/self/fd/'+str(fd)).endswith('/outcome.json'):
                os.kill(os.getppid(),signal.SIGTERM)
                time.sleep(0.05)
        with patch('os.fsync', side_effect=interrupt):
            result = self.run_child('pass')
        self.assertEqual(result.code,'interrupted')
        self.assertTrue(result.interrupted)
        self.assertTrue(result.withdrawal_completed)
        candidate = json.loads((self.root/'outcome.json').read_text())
        self.assertEqual(candidate['kind'],'diagnostic-capture-candidate')
        self.assertFalse(candidate['final_outcome'])
        self.assertFalse(candidate['capture']['persisted'])

    def test_lost_persistence_ack_leaves_provisional_capture_and_fences(self):
        original = runner_module._persist
        class SilentPipe:
            def send(self, _value):
                pass
            def close(self):
                pass
        def lose_ack(root,outcome,stdout,stderr,pipe):
            original(root,outcome,stdout,stderr,SilentPipe())
            time.sleep(30)
        with patch.object(runner_module,'_persist',lose_ack):
            result = self.run_child('pass',evidence_timeout=0.08)
        self.assertEqual(result.code,'persistence_failed')
        self.assertFalse(result.persisted)
        self.assertTrue(result.withdrawal_completed)
        candidate = json.loads((self.root/'outcome.json').read_text())
        self.assertFalse(candidate['final_outcome'])
        self.assertFalse(candidate['capture']['persisted'])

    def test_fence_failure_is_honestly_incomplete(self):
        def fail():
            raise ValueError('PRIVATE_FENCE_ERROR')
        result = self.run_child('raise SystemExit(1)', fence=fail)
        self.assertFalse(result.withdrawal_completed)
        self.assertEqual(result.fence_code, 'failed')
        for artifact in self.root.iterdir():
            self.assertNotIn(b'PRIVATE_FENCE_ERROR', artifact.read_bytes())

    def test_fence_hang_is_bounded_and_incomplete(self):
        result = self.run_child('raise SystemExit(1)', fence=lambda: time.sleep(30), fence_timeout=0.08)
        self.assertFalse(result.withdrawal_completed)
        self.assertEqual(result.fence_code, 'deadline_or_failed')

    def test_sigint_and_sigterm_restore_handlers_and_fence(self):
        for number in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(number=number), tempfile.TemporaryDirectory(dir='/tmp') as root:
                def collect(recorder, stop):
                    recorder.record('edge', {'code':'started'})
                    time.sleep(0.05)
                    os.kill(os.getppid(), number)
                    stop.wait()
                before = signal.getsignal(number)
                result = DiagnosticRunner(Path(root), evidence_timeout=0.15).run(
                    [sys.executable, '-B', '-c', 'import time;time.sleep(30)'], timeout_seconds=1,
                    collect=collect, fence=self.fence)
                self.assertTrue(result.interrupted)
                self.assertEqual(result.code, 'interrupted')
                self.assertTrue(result.withdrawal_completed)
                self.assertEqual(signal.getsignal(number), before)

    def test_missing_initial_runtime_record_prevents_child_launch(self):
        marker = self.root/'child-must-not-start'
        def no_initial_record(recorder, stop):
            stop.wait()
        result = self.run_child('from pathlib import Path;Path('+repr(str(marker))+').touch()',
                                collect=no_initial_record, evidence_timeout=0.08)
        self.assertEqual(result.code, 'runtime_setup_failed')
        self.assertFalse(marker.exists())
        self.assertTrue(result.withdrawal_completed)

    def test_existing_output_is_never_overwritten_or_replayed(self):
        (self.root/'runtime.jsonl').write_bytes(b'retained evidence')
        (self.root/'runtime.jsonl').chmod(0o600)
        result = self.run_child('pass')
        self.assertEqual(result.code, 'runtime_setup_failed')
        self.assertEqual((self.root/'runtime.jsonl').read_bytes(), b'retained evidence')
        self.assertTrue(result.withdrawal_completed)

    def test_symlink_output_root_cannot_write_outside_scope(self):
        real = self.root/'real';real.mkdir(mode=0o700)
        link = self.root/'link';link.symlink_to(real)
        result = DiagnosticRunner(link, evidence_timeout=0.08).run(
            [sys.executable, '-B', '-c', 'pass'], timeout_seconds=1, collect=self.collect, fence=self.fence)
        self.assertEqual(result.code, 'runtime_setup_failed')
        self.assertTrue(result.withdrawal_completed)
        self.assertFalse(result.persisted)
        self.assertEqual(list(real.iterdir()), [])

    def test_runtime_sink_charges_failed_attempt_and_refuses_repeated_appends(self):
        recorder = EventRecorder(self.root,'runtime',limit=512)
        self.addCleanup(recorder.close)
        with patch('os.fsync',side_effect=OSError('PRIVATE_SYNC_ERROR')):
            with self.assertRaises(EvidenceError):
                recorder.record('edge',{'code':'closed'})
        size = (self.root/'runtime.jsonl').stat().st_size
        charged = recorder.written
        self.assertGreater(charged,0)
        for _ in range(20):
            with self.assertRaises(EvidenceError):
                recorder.record('edge',{'code':'closed'})
        self.assertEqual(recorder.written,charged)
        self.assertEqual((self.root/'runtime.jsonl').stat().st_size,size)
        self.assertLessEqual(size,512)

    def test_closed_runtime_events_reject_payloads_raw_messages_and_bounds(self):
        recorder = EventRecorder(self.root, 'runtime', limit=512)
        self.addCleanup(recorder.close)
        for kind, value in [
            ('application', {'role':'backend','code':'PRIVATE_MESSAGE'}),
            ('pod', {'role':'backend','ready':True,'restarts':0,'arguments':'PRIVATE_ARGUMENT'}),
            ('secret', {'body':'PRIVATE_PAYLOAD'}),
            ('resource', {'role':'backend','rss_bytes':-1,'cpu_millicores':1}),
        ]:
            with self.assertRaises(EvidenceError):
                recorder.record(kind, value)
        recorder.record('edge', {'code':'timeout'})
        with self.assertRaises(EvidenceError):
            for _ in range(100):
                recorder.record('edge', {'code':'closed'})
        self.assertLessEqual((self.root/'runtime.jsonl').stat().st_size, 512)
        self.assertNotIn('PRIVATE_', (self.root/'runtime.jsonl').read_text())


if __name__ == '__main__':
    unittest.main()
