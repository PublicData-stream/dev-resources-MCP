"""Exercise synthetic admission, restrictions and failure assertions without a cluster."""
import importlib.util
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'npm-assessment-fixture.py'
SPEC = importlib.util.spec_from_file_location('npm_assessment_fixture', SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)

IDENTITY = {'expected_artifact': 'sha256:' + '1' * 64, 'matched_artifact': 'sha256:' + '1' * 64,
            'runtime_reference_digest': 'sha256:' + '2' * 64, 'resolved_cri_id': 'sha256:' + '3' * 64,
            'known_digests': ['sha256:' + '1' * 64, 'sha256:' + '3' * 64],
            'expected_configs': ['sha256:' + '3' * 64], 'resolved_config': 'sha256:' + '3' * 64}


class SyntheticFixtureTests(unittest.TestCase):
    def test_pauses_every_provider_without_replacing_unrelated_configuration(self):
        original = '[storage]\ndatabase_url="fixture-old"\nblob_dir="/unmounted/cache"\n[npm]\nenabled=true\nadvisories_enabled=true\npackages=["first-party-fixture"]\n[limits]\ncall_timeout_secs=30\n'
        value = tomllib.loads(fixture.configuration(original))
        self.assertEqual(value['storage'], {'database_url': fixture.DATABASE_READER, 'blob_dir': '/unmounted/cache'})
        self.assertEqual(value['limits'], {'call_timeout_secs': 30})
        for provider in ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'wikipedia', 'npm'):
            self.assertFalse(value[provider]['enabled'])
        self.assertFalse(value['npm']['advisories_enabled'])
        self.assertEqual(value['npm']['packages'], ['first-party-fixture'])
        with self.assertRaisesRegex(fixture.FixtureError, 'one_fixture_database'):
            fixture.configuration(original + '[other]\ndatabase_url="second"\n')

    def test_real_helper_preserves_confined_runtime_and_private_termination(self):
        api = fixture.helper()
        selected = api.Selection('blake3:' + '1' * 64)
        pod = api.build_assessment_pod(fixture.template('candidate:server'), 'candidate:server', selected,
                                       name='fixture-assessment', namespace=fixture.NAMESPACE)
        spec = pod['spec']
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertEqual(spec['securityContext']['seccompProfile'], {'type': 'RuntimeDefault'})
        self.assertEqual({item['name'] for item in spec['volumes']}, {'config', 's3', 'tmp'})
        self.assertEqual(next(item for item in spec['volumes'] if item['name'] == 'tmp')['emptyDir'], {'sizeLimit': '16Mi'})
        container = spec['containers'][0]
        self.assertEqual(container['securityContext']['appArmorProfile'], {'type': 'Localhost', 'localhostProfile': 'devres-runtime'})
        self.assertEqual(container['terminationMessagePolicy'], 'File')
        self.assertNotEqual(container['terminationMessagePath'], api.REPORT)
        self.assertNotIn('env', container)
        self.assertEqual(container['command'][:5], ['/usr/bin/timeout', '--signal=TERM', '--kill-after=5s', '420s', '/bin/sh'])

    def test_assessment_network_permits_only_dns_and_owned_postgres(self):
        policies = fixture.policies()
        default = policies[0]['spec']
        self.assertEqual(default, {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']})
        outbound = policies[1]['spec']['egress']
        self.assertEqual({(port['port'], port['protocol']) for rule in outbound for port in rule['ports']}, {(53, 'TCP'), (53, 'UDP'), (5432, 'TCP')})
        self.assertFalse(any('ipBlock' in destination for rule in outbound for destination in rule['to']))
        self.assertEqual(outbound[1]['to'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'], 'devres-acceptance')
        self.assertEqual(policies[2]['spec']['ingress'][0]['from'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'], fixture.NAMESPACE)

    def test_effective_runtime_accepts_only_expected_policy_and_finite_metadata(self):
        payload = (b'APPARMOR=devres-runtime (enforce)\nSECCOMP=2\nNO_NEW_PRIVS=1\n'
                   b'CAP_EFF=0000000000000000\nCONFIG=0:65532:440\nTMP=0:65532:2777\n')
        self.assertEqual(fixture.validate_runtime(payload)['SECCOMP'], '2')
        for old, new in ((b'(enforce)', b'(complain)'), (b'SECCOMP=2', b'SECCOMP=0'),
                         (b'CAP_EFF=0000000000000000', b'CAP_EFF=0000000000000001'),
                         (b'CONFIG=0:65532:440', b'CONFIG=0:0:444')):
            with self.subTest(new=new), self.assertRaises(fixture.FixtureError):
                fixture.validate_runtime(payload.replace(old, new))

    def test_receipt_is_private_create_new_and_bounded(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            path = Path(temporary) / 'receipt.json'
            fixture.private_json(path, {'synthetic': True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_bytes()), {'synthetic': True})
            with self.assertRaises(FileExistsError):
                fixture.private_json(path, {})

    def test_constructed_receipts_survive_scratch_cleanup_in_owned_tmp_diagnostics(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            scratch = root / 'scratch'
            scratch.mkdir()
            cluster = fixture.Cluster('devres-acceptance-123-fixture', scratch)
            value = {'version': 1, 'synthetic': True, 'result': {'case': 'malformed-config', 'phase': 'terminal', 'exit_code': 1, 'diagnostics': None, 'image_identity': IDENTITY}}
            name = 'case-assessment-malformed-config-result.json'
            with patch.dict(os.environ, {'DEVRES_E2E_DIAGNOSTICS_DIR': str(root / 'retained')}):
                self.assertTrue(fixture.receipt(cluster, name, value))
            (scratch / name).unlink()
            retained = root / 'retained' / cluster.profile / name
            self.assertEqual(json.loads(retained.read_bytes()), value)
            self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
            with patch.dict(os.environ, {'DEVRES_E2E_DIAGNOSTICS_DIR': '/var/lib/unowned'}):
                self.assertFalse(fixture.receipt(cluster, name, value))
            self.assertTrue(cluster.receipt_failures)

    def test_invalid_or_unwritable_retention_cannot_mask_original_child_failure(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-123-fixture', Path(temporary))
            result = {'case': 'malformed-config', 'phase': 'terminal', 'exit_code': 1, 'diagnostics': None, 'image_identity': IDENTITY}
            value = {'version': 1, 'synthetic': True, 'result': result}
            with patch.object(fixture, 'private_json', side_effect=OSError('secret-sentinel-must-not-be-output')), \
                 patch.object(fixture.sys, 'stderr') as stderr:
                self.assertFalse(fixture.receipt(cluster, 'case-assessment-malformed-config-result.json', value))
                self.assertNotIn('secret-sentinel', str(stderr.mock_calls))
            self.assertEqual(result['exit_code'], 1)
            self.assertTrue(cluster.receipt_failures)
            with patch.object(fixture, 'private_json') as persist:
                self.assertFalse(fixture.receipt(cluster, 'case-assessment-malformed-config-result.json', {**value, 'raw_stderr': 'private-marker'}))
                persist.assert_not_called()

    def test_fault_matrix_requires_actual_phase_and_separate_child_exit(self):
        class Cluster:
            def __init__(self): self.calls = []
            def sql(self, value):
                self.calls.append(value)
                return ('blake3:' + '1' * 64).encode()
        cluster = Cluster()
        expected = {'malformed-config': 'config_load', 'wrong-dns': 'sql_connect', 'bad-password': 'sql_connect',
                    'existing-output': 'output_create', 'ready-denied': 'ready_write',
                    'wrong-schema': 'schema', 'missing-grant': 'history_select',
                    'output-symlink': 'output_create', 'output-wrong-mode': 'output_create',
                    'output-wrong-owner': 'output_create', 'restore-pending': 'schema',
                    'corrupt-history': 'history_select', 'held-lifecycle': 'lifecycle'}
        def assess(_cluster, _image, _selected, _api, case):
            if case == 'telemetry-unavailable':
                return {'phase': 'report_transferred', 'events': None}
            return {'phase': 'terminal', 'exit_code': 1, 'diagnostics': [
                {'phase': 'cli_start', 'outcome': 'start'},
                {'phase': expected[case], 'outcome': 'error'},
                {'phase': 'cli_exit', 'outcome': 'ok' if case == 'ready-denied' else 'error',
                 'child_exit': 0 if case == 'ready-denied' else 1}]}
        with patch.object(fixture, 'snapshot', return_value={'fixture': 'unchanged'}), \
             patch.object(fixture, 'set_config'), patch.object(fixture, 'assess', side_effect=assess), \
             patch.object(fixture, 'lifecycle_exclusion', return_value=contextlib.nullcontext()):
            self.assertEqual(len(fixture.failure_matrix(cluster, 'server', {}, None, 'synthetic config', 'harness')), 14)
        self.assertIn('UPDATE devres_schema SET version=19 WHERE singleton', cluster.calls)
        self.assertIn('GRANT SELECT ON devres_npm_advisory_job_history TO devres_assessment_reader', cluster.calls)
        with patch.object(fixture, 'snapshot', return_value={}), patch.object(fixture, 'set_config'), \
             patch.object(fixture, 'assess', return_value={'phase': 'terminal', 'exit_code': 1, 'diagnostics': []}):
            with self.assertRaisesRegex(fixture.FixtureError, 'phase_unknown'):
                fixture.failure_matrix(cluster, 'server', {}, None, 'synthetic config', 'harness')

    def test_source_bound_cleanup_passes_uid_precondition_to_api(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-123-fixture', Path(temporary))
            calls = []
            def k(*arguments, **kwargs):
                calls.append((arguments, kwargs))
                return subprocess.CompletedProcess(arguments, 0, b'', b'')
            with patch.object(cluster, 'pod', return_value={'metadata': {'uid': 'owned-uid'}}), patch.object(cluster, 'k', side_effect=k):
                cluster.delete('assessment-success', 'owned-uid')
            deletion = calls[0]
            self.assertIn('/api/v1/namespaces/devres-assessment/pods/assessment-success', deletion[0][1])
            self.assertEqual(json.loads(deletion[1]['data'])['preconditions'], {'uid': 'owned-uid'})
            with patch.object(cluster, 'pod', return_value={'metadata': {'uid': 'different'}}):
                with self.assertRaisesRegex(fixture.FixtureError, 'uid_changed'):
                    cluster.delete('assessment-success', 'owned-uid')

    def test_actual_supervisor_fences_report_and_runtime_and_cleans_before_persist(self):
        api = fixture.helper()
        selected = {'job_id': 'blake3:' + '1' * 64, 'revision': 1}
        report = {'version': 1, **selected, 'recipe': 'npm-materialization-deadline-v1',
                  'state_digest': 'blake3:' + '2' * 64, 'eligible': False, 'outcome': 'ineligible',
                  'reason': 'legacy_unknown', 'operation_id': None, 'publication_snapshot': None}
        raw = json.dumps(report).encode() + b'\n'
        frame = f'65532:600:1:{len(raw)}:regular file\n'.encode() + api.FRAME + raw + api.PHASE_FRAME + b'1\tcli_exit\tok\tnone\t0\t0\n'
        runtime = (b'APPARMOR=devres-runtime (enforce)\nSECCOMP=2\nNO_NEW_PRIVS=1\n'
                   b'CAP_EFF=0000000000000000\nCONFIG=0:65532:440\nTMP=0:65532:2777\n')
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                events = []
                class Cluster:
                    scratch = Path(temporary)
                    profile = 'devres-acceptance-123-fixture'
                    expected_image = {'artifact': 'sha256:' + '1' * 64, 'configs': ['sha256:' + '3' * 64], 'known_digests': ['sha256:' + '1' * 64, 'sha256:' + '3' * 64]}
                    calls = 0
                    def apply(self, pod): self.value = pod
                    def pod(self, _name):
                        self.calls += 1
                        value = copy.deepcopy(self.value)
                        value['metadata']['uid'] = ('different' if changed and self.calls == 3 else '11111111-1111-1111-1111-111111111111')
                        value['status'] = {'phase': 'Running', 'containerStatuses': [{'containerID': 'containerd://fixture',
                            'restartCount': 0, 'imageID': 'sha256:fixture', 'state': {'running': {}}}]}
                        return value
                    def argv(self, *args): return ['fixture-kubectl', *args]
                    def delete(self, _name, _uid): events.append('cleanup')
                cluster = Cluster()
                with patch.object(api, 'report_exchange', side_effect=[frame, runtime]) as exchange, \
                     patch.object(fixture, 'resolved_image_identity', return_value=IDENTITY), \
                     patch.object(fixture, 'private_json', side_effect=lambda *_args: events.append('persist')):
                    if changed:
                        with self.assertRaisesRegex(api.AssessmentError, 'uid_changed'):
                            fixture.assess(cluster, 'candidate:server', selected, api)
                        self.assertEqual(events, ['cleanup'])
                    else:
                        result = fixture.assess(cluster, 'candidate:server', selected, api)
                        self.assertEqual(result['phase'], 'report_transferred')
                        self.assertEqual(events, ['cleanup', 'persist'])
                    self.assertEqual(exchange.call_count, 2)
                    self.assertTrue(all(0 < call.kwargs['timeout'] <= 5 for call in exchange.call_args_list))

    def test_image_identity_matches_index_digest_without_mislabeling_config(self):
        index = 'sha256:' + '1' * 64
        config = 'sha256:' + '2' * 64
        inspected = (index + '\n' + json.dumps(['fixture/server@' + index]) + '\n').encode()
        with patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, inspected, b'')), \
             patch.object(fixture, 'docker_config_digests', return_value=[config]) as export:
            expected = fixture.expected_image_identity('fixture/server:candidate')
        export.assert_called_once_with(index)
        self.assertEqual(expected, {'artifact': index, 'configs': [config], 'known_digests': [index, config]})
        class Cluster: profile = 'devres-acceptance-123-fixture'
        cri = {'status': {'id': config, 'repoDigests': ['fixture/server@' + index]}}
        with patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps(cri).encode(), b'')) as execute:
            value = fixture.resolved_image_identity(Cluster(), 'fixture/server@' + index, expected)
        self.assertEqual(value['matched_artifact'], index)
        self.assertEqual(value['resolved_cri_id'], config)
        self.assertNotIn('expected_config', value)
        self.assertEqual(execute.call_args.args[0][-1], 'fixture/server@' + index)

    def test_substituted_runtime_image_digest_is_rejected_even_with_same_tag(self):
        expected = {'artifact': 'sha256:' + '1' * 64, 'configs': ['sha256:' + '2' * 64], 'known_digests': ['sha256:' + '1' * 64, 'sha256:' + '2' * 64]}
        wrong = 'sha256:' + '9' * 64
        class Cluster: profile = 'devres-acceptance-123-fixture'
        cri = {'status': {'id': wrong, 'repoDigests': ['fixture/server@' + wrong]}}
        with patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps(cri).encode(), b'')):
            with self.assertRaisesRegex(fixture.FixtureError, 'candidate_image_mismatch'):
                fixture.resolved_image_identity(Cluster(), 'fixture/server@' + wrong, expected)

    def test_streamed_export_derives_config_and_matches_rewritten_manifest(self):
        config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': []}}).encode()
        digest = hashlib.sha256(config).hexdigest()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as output:
            for name, payload in [('blobs/sha256/' + digest, config),
                                  ('manifest.json', json.dumps([{'Config': 'blobs/sha256/' + digest, 'RepoTags': ['fixture/server:candidate'], 'Layers': []}]).encode())]:
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                output.addfile(member, io.BytesIO(payload))
        original = subprocess.Popen
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            path = Path(temporary) / 'synthetic-save.tar'
            path.write_bytes(archive.getvalue())
            producer = "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())"
            with patch.object(fixture.subprocess, 'Popen', side_effect=lambda _args, **kwargs: original([sys.executable, '-I', '-B', '-c', producer, str(path)], **kwargs)):
                configs = fixture.docker_config_digests('fixture/server:candidate')
        self.assertEqual(configs, ['sha256:' + digest])
        expected = {'artifact': 'sha256:' + '1' * 64, 'configs': configs, 'known_digests': ['sha256:' + '1' * 64, *configs]}
        class Cluster: profile = 'devres-acceptance-123-fixture'
        rewritten = 'sha256:' + '9' * 64
        cri = {'status': {'id': configs[0], 'repoDigests': ['fixture/server@' + rewritten]}}
        with patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps(cri).encode(), b'')):
            result = fixture.resolved_image_identity(Cluster(), 'fixture/server@' + rewritten, expected)
        self.assertEqual(result['resolved_config'], configs[0])
        self.assertEqual(result['matched_artifact'], configs[0])

    def test_streamed_export_timeout_terminates_owned_process_group(self):
        original = subprocess.Popen
        with patch.object(fixture.subprocess, 'Popen', side_effect=lambda _args, **kwargs: original([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(5)'], **kwargs)):
            with self.assertRaises(fixture.FixtureError):
                fixture.docker_config_digests('fixture/server:candidate', timeout=.1)

    def test_apparmor_unload_requires_namespace_cleanup_and_no_attached_tasks(self):
        for tasks_stopped, attached, should_unload in ((True, False, True), (False, False, False), (True, True, False)):
            with self.subTest(tasks_stopped=tasks_stopped, attached=attached), tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                calls = []
                def command(arguments, **_kwargs):
                    calls.append(arguments)
                    output = (b'docker-default (enforce)\n' if len(calls) == 1
                              else b'devres-runtime (enforce)\n')
                    return subprocess.CompletedProcess(arguments, 0, output, b'')
                with patch.object(fixture, 'command', side_effect=command), \
                     patch.object(fixture, 'no_attached_tasks', return_value=not attached):
                    if should_unload:
                        with fixture.apparmor(Path(temporary), lambda: tasks_stopped) as digest:
                            self.assertEqual(digest, fixture.APPARMOR_SHA256)
                    else:
                        with self.assertRaisesRegex(fixture.FixtureError, 'cleanup_incomplete_profile_retained'):
                            with fixture.apparmor(Path(temporary), lambda: tasks_stopped):
                                pass
                self.assertEqual(any('-R' in call for call in calls), should_unload)

    def test_apparmor_refuses_asset_with_unreviewed_digest(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary, patch.object(fixture, 'APPARMOR_SHA256', '0' * 64), \
             patch.object(fixture, 'command') as commands:
            with self.assertRaisesRegex(fixture.FixtureError, 'canonical_hash_mismatch'):
                with fixture.apparmor(Path(temporary)):
                    pass
            commands.assert_not_called()

    def test_apparmor_task_scan_fails_closed_for_attached_or_unknown_labels(self):
        for value, expected in (({'attached': 0, 'unknown': False}, True),
                                ({'attached': 1, 'unknown': False}, False),
                                ({'attached': 0, 'unknown': True}, False)):
            with self.subTest(value=value), patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b'')):
                self.assertEqual(fixture.no_attached_tasks(), expected)


if __name__ == '__main__':
    unittest.main()
