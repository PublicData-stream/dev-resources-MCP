"""Real wrapper behavior and closed metadata, without any production resources."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from deploy.diagnostics import npm_assessment as n

SELECTION = n.Selection('blake3:' + 'a'*64)


def report():
    return {'version': 1, 'job_id': SELECTION.job_id, 'revision': 1, 'recipe': SELECTION.recipe,
        'state_digest': 'blake3:'+'b'*64, 'eligible': False, 'outcome': 'ineligible',
        'reason': 'legacy_unknown', 'operation_id': None, 'publication_snapshot': None}


def frame(phases=b'1\tcli_exit\tok\tnone\t0\t0\n'):
    body = (json.dumps(report())+'\n').encode()
    return f'65532:600:1:{len(body)}:regular file\n'.encode()+n.FRAME+body+n.PHASE_FRAME+phases


def pod(message=None, phase='Running'):
    state = {'running': {}} if phase == 'Running' else {'terminated': {'exitCode': 1,
        'reason': 'Error', 'message': message}}
    return {'metadata': {'uid': 'fixture-uid'}, 'spec': {'containers': [{'image': 'pinned',
        'terminationMessagePath': n.TERMINATION_FILE, 'terminationMessagePolicy': 'File'}]},
        'status': {'phase': phase, 'containerStatuses': [{'containerID': 'containerd://fixture',
            'restartCount': 0, 'state': state}]}}


class ClosedPhases(unittest.TestCase):
    def test_default_pod_uses_distinct_private_and_kubelet_termination_files(self):
        template = {'spec': {'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532,
                'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
            'volumes': [{'name': 'config', 'secret': {'secretName': 'synthetic-config'}},
                        {'name': 's3', 'secret': {'secretName': 'synthetic-reader'}},
                        {'name': 'tmp', 'emptyDir': {}}],
            'containers': [{'image': 'pinned', 'securityContext': {
                'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                'capabilities': {'drop': ['ALL']}, 'appArmorProfile': {'type':'Localhost','localhostProfile':'devres-runtime'}}, 'volumeMounts': [
                    {'name': 'config', 'mountPath': '/etc/devres/config', 'readOnly': True},
                    {'name': 's3', 'mountPath': '/run/devres-s3', 'readOnly': True},
                    {'name': 'tmp', 'mountPath': '/tmp'}]}]}}
        value = n.build_assessment_pod(template, 'pinned', SELECTION, 'assessment', 'fixture')
        container = value['spec']['containers'][0]
        self.assertEqual(container['terminationMessagePath'], n.TERMINATION_FILE)
        self.assertEqual(container['terminationMessagePolicy'], 'File')
        self.assertNotEqual(n.TERMINATION_FILE, n.PHASE_FILE)
        self.assertFalse(value['spec']['automountServiceAccountToken'])
        self.assertNotIn('--connect-readiness', container['command'][-1])
        self.assertEqual(subprocess.run(['/bin/sh', '-n', '-c', container['command'][-1]],
            capture_output=True).returncode, 0)
        with_readiness = n.build_assessment_pod(template, 'pinned', SELECTION, 'assessment',
            'fixture', connect_readiness=True)
        command = with_readiness['spec']['containers'][0]['command']
        self.assertEqual(command[:-1], container['command'][:-1])
        self.assertIn('--connect-readiness wait', command[-1])
        for change in ({'runAsUser': 0}, {'runAsNonRoot': False}, {'runAsGroup': 0},
                {'seccompProfile': {'type': 'Unconfined'}}, {'appArmorProfile': {'type': 'Unconfined'}},
                {'procMount': 'Unmasked'}):
            altered = copy.deepcopy(template)
            altered['spec']['containers'][0]['securityContext'].update(change)
            with self.subTest(change=change), self.assertRaises(n.AssessmentError):
                n.build_assessment_pod(altered, 'pinned', SELECTION, 'assessment', 'fixture')

    def test_decodes_finite_records_and_rejects_untrusted_detail(self):
        raw = b'1\tsql_connect\tstart\tnone\t0\t-\n1\tsql_connect\terror\tauthentication\t4\t-\n'
        rows = n.parse_phases(raw)
        self.assertEqual(rows[1]['reason'], 'authentication')
        self.assertEqual(rows[1]['ordinal'], 1)
        for value in (raw.replace(b'authentication', b'password=secret'), raw[:-1],
                raw.replace(b'\t4\t', b'\t-1\t'), raw+b'private',
                b'1\tcli_exit\tok\tnone\t0\t1\n', raw*25,
                b'1\tunknown_phase\tok\tnone\t0\t-\n'):
            with self.subTest(value=value[:80]), self.assertRaises(n.AssessmentError):
                n.parse_phases(value)

    def test_connection_readiness_has_closed_retry_and_cancellation_records(self):
        start = b'1\tsql_connect\tstart\tnone\t0\t-\n'
        retry = b'1\tsql_connect_retry\terror\tconnection\t4\t-\n'
        cancel = b'1\tsql_connect\terror\tcancelled\t8\t-\n'
        events = n.parse_phases(start + retry + cancel)
        self.assertEqual([event['reason'] for event in events], ['none', 'connection', 'cancelled'])
        recovered = n.parse_phases(start + retry.replace(b'\tconnection\t', b'\ttimeout\t')
            + b'1\tsql_connect\tok\tnone\t8\t-\n')
        self.assertEqual(recovered[1]['reason'], 'timeout')
        self.assertEqual(recovered[-1]['outcome'], 'ok')
        for value in (retry + retry, retry.replace(b'\terror\tconnection\t', b'\tstart\tnone\t'),
                retry.replace(b'\tconnection\t', b'\tauthentication\t'),
                cancel.replace(b'\tsql_connect\t', b'\tsql_setup\t')):
            with self.subTest(value=value), self.assertRaises(n.AssessmentError):
                n.parse_phases(start + value)

    def test_terminal_metadata_is_file_only_and_identity_fenced(self):
        message = '1\tcli_exit\terror\tunknown\t0\t7\n'
        value = pod(message, 'Failed')
        self.assertEqual(n.termination_phases(value, uid='fixture-uid', image='pinned')[0]['child_exit'], 7)
        value['status']['containerStatuses'][0]['state']['terminated']['message'] = 'password=secret'
        self.assertIsNone(n.termination_phases(value, uid='fixture-uid', image='pinned'))
        for mutate in (lambda v: v['metadata'].update(uid='replacement'),
                       lambda v: v['spec']['containers'][0].update(terminationMessagePolicy='FallbackToLogsOnError'),
                       lambda v: v['status']['containerStatuses'][0].update(restartCount=1)):
            altered = pod(message, 'Failed'); mutate(altered)
            with self.assertRaises(n.AssessmentError):
                n.termination_phases(altered, uid='fixture-uid', image='pinned')
        pending = pod(phase='Pending')
        pending['status']['containerStatuses'][0].pop('containerID')
        pending['status']['containerStatuses'][0]['state'] = {'waiting': {'reason': 'ContainerCreating'}}
        self.assertIsNone(n.termination_phases(pending, uid='fixture-uid', image='pinned'))

    def test_private_report_frame_keeps_closed_status_distinct(self):
        raw, value, rows = n.decode_report_frame(frame(), SELECTION)
        self.assertEqual(json.loads(raw), value)
        self.assertEqual(value['reason'], 'legacy_unknown')
        self.assertEqual(rows[0]['child_exit'], 0)
        _, _, rows = n.decode_report_frame(frame(b'private stderr'), SELECTION)
        self.assertIsNone(rows)
        for body in (frame()[:-40], frame().replace(b':600:', b':644:', 1),
                     frame().replace(b':600:1:', b':600:2:', 1)):
            with self.assertRaises(n.AssessmentError):
                n.decode_report_frame(body, SELECTION)


class RealWrapper(unittest.TestCase):
    def run_case(self, exit_code=0, marker_failure=False, telemetry_failure=False,
                 connect_readiness=False):
        scratch = tempfile.TemporaryDirectory(prefix='devres-assessment-wrapper-', dir='/tmp')
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        cli = root/'cli'
        phase_file = root/'phases'/'status'
        expected_args = ['--connect-readiness', 'wait'] if connect_readiness else []
        if not telemetry_failure:
            expected_args += ['--phase-file', str(phase_file)]
        cli.write_text('#!'+sys.executable+'\nimport json,pathlib,sys\n'
            +'args=sys.argv[1:]\noutput_flag=args.index("--output")\n'
            +'assert args[output_flag+2:]=='+repr(expected_args)+'\n'
            +'output=pathlib.Path(args[output_flag+1])\n'
            +'output.parent.mkdir(mode=0o700)\n'
            +'output.write_text('+repr(json.dumps(report())+'\n')+')\n'
            +('output.with_name("ready").mkdir()\n' if marker_failure else '')
            +'raise SystemExit('+str(exit_code)+')\n')
        cli.chmod(0o700)
        if telemetry_failure:
            phase_file.parent.mkdir()
            phase_file.write_text('previous private artifact')
        termination = root/'termination'; termination.touch(mode=0o600)
        script = n.wrapper_script(SELECTION, cli=str(cli), report=str(root/'report'/'report.json'),
            phase_file=str(phase_file), termination_file=str(termination), hold_seconds=0,
            connect_readiness=connect_readiness)
        result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, timeout=5)
        return result, phase_file, termination, root/'report'/'report.json'

    def test_child_nonzero_survives_wrapper_and_is_independent(self):
        result, phases, termination, _ = self.run_case(exit_code=7)
        self.assertEqual(result.returncode, 7)
        events = n.parse_phases(phases.read_bytes())
        self.assertEqual(events[-1]['child_exit'], 7)
        self.assertEqual(n.parse_phases(termination.read_bytes()), events)

    def test_success_then_marker_failure_preserves_zero_child_status(self):
        result, phases, _, output = self.run_case(marker_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(output.read_bytes())['reason'], 'legacy_unknown')
        events = n.parse_phases(phases.read_bytes())
        self.assertEqual(next(row['child_exit'] for row in events if row['phase'] == 'cli_exit'), 0)
        self.assertEqual(events[-1]['phase'], 'ready_write')
        self.assertEqual(events[-1]['outcome'], 'error')

    def test_success_enters_hold_without_raw_report_logs(self):
        result, phases, _, _ = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(n.parse_phases(phases.read_bytes())[-1]['phase'], 'hold_start')
        self.assertNotIn(SELECTION.job_id.encode(), result.stdout)

    def test_unavailable_telemetry_does_not_replace_child_outcome_or_old_file(self):
        result, phases, termination, _ = self.run_case(exit_code=7, telemetry_failure=True)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(phases.read_text(), 'previous private artifact')
        self.assertEqual(n.parse_phases(termination.read_bytes())[-1]['child_exit'], 7)

    def test_connection_readiness_opt_in_is_independent_of_telemetry(self):
        for telemetry_failure in (False, True):
            with self.subTest(telemetry_failure=telemetry_failure):
                result, _, termination, output = self.run_case(telemetry_failure=telemetry_failure,
                    connect_readiness=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(output.is_file())
                events = n.parse_phases(termination.read_bytes())
                self.assertEqual(sum(event['phase'] == 'cli_start' for event in events), 1)
                self.assertEqual(sum(event['phase'] == 'cli_exit' for event in events), 1)


class Supervisor(unittest.TestCase):
    def test_missing_phase_telemetry_keeps_container_exit_and_oom_independently(self):
        events = []
        terminal = pod(None, 'Failed')
        detail = terminal['status']['containerStatuses'][0]['state']['terminated']
        detail.update(exitCode=137, reason='OOMKilled')
        receipts = []
        with self.assertRaises(n.AssessmentError):
            n.supervise(get_pod=lambda: terminal, read_report=lambda _: None,
                cleanup=lambda: events.append('cleanup'), persist=lambda _: self.fail('not a report'),
                persist_failure=lambda value: receipts.append(value),
                selection=SELECTION, uid='fixture-uid', image='pinned')
        self.assertEqual(events, ['cleanup'])
        self.assertFalse(receipts[0]['phase_known'])
        state = receipts[0]['last_pod']['containers'][0]
        self.assertEqual(state['exit_code'], 137)
        self.assertTrue(state['oom_killed'])
        self.assertTrue(state['container_id_present'])
        detail.update(reason='private exception password=secret')
        self.assertNotIn('secret', json.dumps(n.pod_failure_metadata(terminal)))

    def test_failure_extracts_termination_before_cleanup_and_persists_after(self):
        events = []
        def cleanup(): events.append('cleanup')
        def persist_failure(value):
            self.assertEqual(events, ['cleanup'])
            self.assertEqual(value['phases'][0]['child_exit'], 3)
            events.append('evidence')
        with self.assertRaisesRegex(n.AssessmentError, 'assessment_container_ended'):
            n.supervise(get_pod=lambda: pod('1\tcli_exit\terror\tunknown\t0\t3\n', 'Failed'),
                read_report=lambda _: self.fail('terminal Pod must not exec'), cleanup=cleanup,
                persist=lambda _: self.fail('failure is not a report'), persist_failure=persist_failure,
                selection=SELECTION, uid='fixture-uid', image='pinned')
        self.assertEqual(events, ['cleanup', 'evidence'])

    def test_report_fsync_failure_cannot_leave_pod_running(self):
        events = []
        def persist(_):
            self.assertEqual(events, ['cleanup'])
            raise OSError('private evidence disk failure')
        with self.assertRaises(OSError):
            n.supervise(get_pod=lambda: pod(), read_report=lambda _: frame(),
                cleanup=lambda: events.append('cleanup'), persist=persist,
                selection=SELECTION, uid='fixture-uid', image='pinned')

    def test_lost_process_identity_still_cleans_and_never_persists_report(self):
        changed = pod(); changed['metadata']['uid'] = 'replacement'
        values = iter((pod(), changed)); events = []
        with self.assertRaises(n.AssessmentError):
            n.supervise(get_pod=lambda: next(values), read_report=lambda _: frame(),
                cleanup=lambda: events.append('cleanup'), persist=lambda _: self.fail('changed identity'),
                selection=SELECTION, uid='fixture-uid', image='pinned')
        self.assertEqual(events, ['cleanup'])


class BoundedExchange(unittest.TestCase):
    def test_complete_nonzero_and_saturated_streams(self):
        command = [sys.executable, '-c', 'import sys;sys.stdout.buffer.write('+repr(frame())+')']
        self.assertEqual(n.report_exchange(command), frame())
        self.assertIsNone(n.report_exchange([sys.executable, '-c', 'raise SystemExit(1)']))
        for stream in ('stdout', 'stderr'):
            with self.assertRaises(n.AssessmentError):
                n.report_exchange([sys.executable, '-c',
                    f'import sys;sys.{stream}.buffer.write(b"x"*2000000)'])


if __name__ == '__main__':
    unittest.main()
