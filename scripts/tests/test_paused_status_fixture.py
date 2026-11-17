"""Test observer harness authority/configuration without creating a cluster."""
import copy
import contextlib
import http.client
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import ssl
import sys
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / 'paused-status-fixture.py'
SPEC = importlib.util.spec_from_file_location('paused_status_fixture', SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


IDENTITY = ('backend-fixture', 'pod-uid', 'backend', 'containerd://fixture', 0, '10.244.1.2')


def timing(stage='statistics', *, failed=1, reason='unavailable', calls=1):
    return (f'DEBUG status operation status_stage="{stage}" calls={calls} '
            f'elapsed_micros=2 failed={failed} cancelled=0 reason="{reason}"\n').encode()


class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now
    def pause(self, seconds): self.now += seconds


class RecordingCluster:
    phase = 'setup'
    fault_case = 'none'

    def __init__(self, profile='devres-acceptance-test', scratch=None):
        self.profile = profile
        self.scratch = scratch
        self.calls = []
        self.observer_identity = IDENTITY

    def argv(self, *arguments): return list(arguments)

    def sql(self, statement):
        self.calls.append(('sql', statement))
        return b'0'

    def apply(self, documents): self.calls.append(('apply', documents))

    def k(self, *arguments, **kwargs):
        self.calls.append((arguments, kwargs))
        if arguments[:2] == ('get', 'pods'):
            value = {'items': [{'metadata': {'name': IDENTITY[0], 'uid': IDENTITY[1]},
                'status': {'podIP': IDENTITY[5], 'containerStatuses': [{'name': IDENTITY[2], 'containerID': IDENTITY[3],
                    'restartCount': IDENTITY[4], 'ready': True, 'state': {'running': {}}}]}}]}
        elif arguments[:1] == ('get',) and arguments[1].startswith('deployment/'):
            value = {'spec': {'template': {'spec': {'containers': [{'name': 'fixture',
                'volumeMounts': [{'name': 'data', 'mountPath': '/data'}]}],
                'volumes': [{'name': 'data', 'emptyDir': {}}]}}}}
        elif arguments[:2] == ('get', 'service/kubernetes'):
            value = {'spec': {'clusterIP': '10.96.0.1'}}
        elif arguments[:2] == ('get', 'endpointslices'):
            value = {'items': []}
        elif kwargs.get('data') == fixture.FAILURE_PROBE.encode():
            value = {'http': 200, 'structured_error': 'unavailable'}
        elif kwargs.get('data') == fixture.PUBLIC_PROBE.encode():
            value = [{'revision': revision, 'observation_state': 'complete', 'scan_gap_count': 0}
                     for revision in ('2026-07-28', '2025-11-25')]
        else:
            value = None
        return SimpleNamespace(stdout=json.dumps(value).encode(), returncode=0)


class ObserverFixtureTests(unittest.TestCase):
    def test_config_uses_select_identity_and_preserves_tls_and_coordination(self):
        writer = ('[storage]\ndatabase_url="synthetic-writer"\nblob_dir="/data/blobs"\n'
                  '[writer_listener]\nbind="0.0.0.0:9443"\ncertificate="/fixture/cert/writer.pem"\n'
                  'private_key="/fixture/cert/writer-key.pem"\n')
        value = tomllib.loads(fixture.paused_config(writer, listener=True, s3=True))
        self.assertEqual(value['storage']['database_url'], 'postgres://devres_reader:reader-fixture-only@postgres/devres')
        self.assertEqual(value['storage']['blob_dir'], '/observer-cache')
        self.assertEqual(value['storage']['scratch_dir'], '/tmp/observer-scratch')
        self.assertEqual(value['writer_listener']['access'], 'status_only')
        self.assertEqual(value['writer_listener']['certificate'], '/fixture/cert/writer.pem')
        self.assertFalse(value['npm']['advisories_enabled'])
        reader = writer.replace('writer_listener', 'writer_client')
        self.assertEqual(tomllib.loads(fixture.paused_config(reader))['writer_client']['access'], 'status_only')
        filesystem = tomllib.loads(fixture.paused_config(writer, listener=True))
        self.assertEqual(filesystem['storage']['scratch_dir'], '/tmp/observer-scratch')
        self.assertEqual(filesystem['storage']['blob_dir'], '/data/blobs')
        with_scratch = writer.replace('[storage]\n', '[storage]\nscratch_dir="/existing/scratch"\n')
        self.assertEqual(tomllib.loads(fixture.paused_config(with_scratch, listener=True))['storage']['scratch_dir'], '/tmp/observer-scratch')

    def test_s3_observer_uses_reader_key_fresh_cache_and_readonly_permanent_mount(self):
        original = {'metadata': {'labels': {'app': 'writer'}}, 'spec': {
            'containers': [{'name': 'writer', 'volumeMounts': [
                {'name': 'data', 'mountPath': '/data'}, {'name': 's3', 'mountPath': '/fixture/s3', 'readOnly': True}]}],
            'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'permanent'}},
                        {'name': 's3', 'secret': {'secretName': 'devres-writer-s3', 'defaultMode': 0o440}}]}}
        before = copy.deepcopy(original)
        result = fixture.readonly_template(original, True)
        self.assertEqual(original, before)
        spec = result['spec']
        self.assertEqual(next(volume for volume in spec['volumes'] if volume['name'] == 's3')['secret']['secretName'], 'devres-serving-s3')
        self.assertEqual(next(volume for volume in spec['volumes'] if volume['name'] == 'observer-cache'), {'name': 'observer-cache', 'emptyDir': {'sizeLimit': '1Gi'}})
        self.assertTrue(next(mount for mount in spec['containers'][0]['volumeMounts'] if mount['name'] == 'data')['readOnly'])
        self.assertFalse(any(volume.get('secret', {}).get('secretName') == 'devres-writer-s3' for volume in spec['volumes']))

    def test_egress_excludes_sources_and_binds_kube_api_to_exact_local_addresses(self):
        documents = fixture.policy_documents(['10.96.0.1', '192.168.49.2', 'fd00::1'])
        writer = documents[1]['spec']
        self.assertEqual(writer['policyTypes'], ['Egress'])
        addresses = {destination['ipBlock']['cidr'] for rule in writer['egress'] for destination in rule.get('to', []) if 'ipBlock' in destination}
        self.assertEqual(addresses, {'10.96.0.1/32', '192.168.49.2/32', 'fd00::1/128'})
        self.assertNotIn('0.0.0.0/0', addresses)
        reader_ports = {port['port'] for rule in documents[0]['spec']['egress'] for port in rule['ports']}
        self.assertEqual(reader_ports, {53, 5432, 9000, 9443})
        with self.assertRaises(ValueError):
            fixture.policy_documents(['public-provider.invalid'])

    def test_retained_snapshot_rejects_unexpected_table_before_interpolation(self):
        class Cluster:
            def sql(self, _statement): return b'caller_supplied_table; DROP TABLE devres_schema\n'
        with self.assertRaisesRegex(fixture.base.FixtureError, 'table_admission'):
            fixture.snapshot(Cluster())

    def test_snapshot_hashes_all_fixture_tables_without_exporting_row_bodies(self):
        class Cluster:
            def __init__(self): self.calls = []
            def sql(self, statement):
                self.calls.append(statement)
                return b'devres_heads\ndevres_npm_state\n' if len(self.calls) == 1 else b'[{"name":"devres_heads","rows":1,"digest":"fixture"}]'
        cluster = Cluster()
        self.assertEqual(fixture.snapshot(cluster)[0]['rows'], 1)
        self.assertIn('BEGIN READ ONLY', cluster.calls[1])
        self.assertIn('statement_timeout', cluster.calls[1])
        self.assertIn('md5(row_to_json(t)::text)', cluster.calls[1])
        self.assertIn('FROM devres_heads t', cluster.calls[1])
        self.assertIn('FROM devres_npm_state t', cluster.calls[1])

    def test_finite_timing_parser_keeps_stage_codes_and_discards_other_log_data(self):
        logs = (b'private-provider-sentinel must never be retained\n'
                b'2026-11-16 DEBUG status operation status_stage="saved_state" calls=1 elapsed_micros=2 failed=0 cancelled=0 reason=""\n'
                b'2026-11-16 DEBUG status operation status_stage="statistics" calls=1 elapsed_micros=3 failed=1 cancelled=0 reason="unavailable"\n')
        result = fixture.timing_evidence(logs)
        self.assertEqual(result, [
            {'stage': 'saved_state', 'reason': 'none', 'calls': 1, 'failed': 0, 'cancelled': 0},
            {'stage': 'statistics', 'reason': 'unavailable', 'calls': 1, 'failed': 1, 'cancelled': 0}])
        self.assertNotIn('sentinel', json.dumps(result))
        with self.assertRaises(fixture.base.FixtureError):
            fixture.timing_evidence(logs.replace(b'statistics', b'arbitrary_source_url'))

    def test_grants_and_objectstore_restore_even_if_ordered_probe_fails(self):
        cluster = RecordingCluster()
        with patch.object(fixture, 'fresh_backend'), patch.object(fixture, 'capture_failure'), \
             patch.object(fixture, 'earlier_storage_failure', side_effect=fixture.base.FixtureError('fixture-failed')):
            with self.assertRaises(fixture.base.FixtureError):
                fixture.ordered_storage_faults(cluster, False)
        self.assertEqual(cluster.calls[-1], ('sql', 'GRANT SELECT ON devres_npm_evidence TO devres_reader'))
        cluster = RecordingCluster()
        with patch.object(fixture, 'fresh_backend'), patch.object(fixture, 'capture_failure'), \
             patch.object(fixture, 'earlier_storage_failure', side_effect=[{'case': 'sql'}, fixture.base.FixtureError('fixture-failed')]):
            with self.assertRaises(fixture.base.FixtureError):
                fixture.ordered_storage_faults(cluster, True)
        self.assertIn((('scale', 'deployment/objectstore', '--replicas=1'), {}), cluster.calls)
        self.assertEqual(cluster.calls[-1][0][0:3], ('rollout', 'status', 'deployment/objectstore'))

    def test_timing_parser_rejects_missing_duplicate_unknown_malformed_and_excessive_records(self):
        eight = b''.join(timing(stage) for stage in sorted(fixture.base.OBSERVER_STAGES))
        self.assertEqual(len(fixture.timing_evidence(eight)), 8)
        for payload, code in (
            (b'ordinary log only', 'observer_timing_missing'),
            (timing() * 2, 'observer_timing_duplicate'),
            (timing('secret_url'), 'observer_timing_schema'),
            (timing(reason='caller_secret'), 'observer_timing_schema'),
            (timing().replace(b'calls=1 ', b'calls=-1 '), 'observer_timing_schema'),
            (timing().replace(b'calls=1 ', b'calls=1e9 '), 'observer_timing_schema'),
            (timing().replace(b'failed=1 ', b'failed=1x '), 'observer_timing_schema'),
            (timing().replace(b'status_stage="statistics"', b'status_stage="statistics"suffix'), 'observer_timing_schema'),
            (timing().replace(b'reason="unavailable"', b'reason="unavailable"suffix'), 'observer_timing_schema'),
            (timing(calls=1000001), 'observer_timing_count_bound'),
            (eight + timing(), 'observer_timing_overflow'),
            (b'x' * 65537, 'observer_timing_bound'),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(fixture.base.FixtureError, '^' + code + '$'):
                fixture.timing_evidence(payload)
        self.assertEqual(fixture.timing_evidence(b'', allow_empty=True), [])

    def timing_api(self, payloads):
        return SimpleNamespace(report_exchange=Mock(side_effect=itertools.chain(payloads, itertools.repeat(payloads[-1]))),
                               AssessmentError=RuntimeError)

    def test_fault_log_polling_accepts_delayed_complete_evidence_for_exact_process(self):
        cluster, clock = RecordingCluster(), Clock()
        api = self.timing_api([b'', timing('saved_state', failed=0, reason=''),
                               timing('saved_state', failed=0, reason='') + timing()])
        with patch.object(fixture.base, 'helper', return_value=api):
            result = fixture.fault_timings(cluster, 'sql-permission', clock=clock, pause=clock.pause)
        self.assertEqual([event['stage'] for event in result], ['saved_state', 'statistics'])
        self.assertEqual(api.report_exchange.call_count, 40)
        for call in api.report_exchange.call_args_list:
            self.assertEqual(call.args[0], ['logs', 'pod/' + IDENTITY[0], '-c', IDENTITY[2],
                                            '--tail=-1', '--limit-bytes=65537'])
            self.assertLessEqual(call.kwargs['timeout'], 2)
        self.assertEqual(clock.now, 10)

    def test_fault_log_deadline_distinguishes_unavailable_missing_and_wrong_stage(self):
        for payload, code in ((None, 'observer_timing_unavailable'),
                              (b'', 'observer_timing_missing'),
                              (timing('saved_state', failed=0, reason=''), 'observer_earlier_storage_stage_missing')):
            cluster, clock = RecordingCluster(), Clock()
            api = SimpleNamespace(report_exchange=Mock(return_value=payload), AssessmentError=RuntimeError)
            with self.subTest(code=code), patch.object(fixture.base, 'helper', return_value=api):
                with self.assertRaisesRegex(fixture.base.FixtureError, '^' + code + '$'):
                    fixture.fault_timings(cluster, 'sql-permission', clock=clock, pause=clock.pause)
            self.assertEqual(clock.now, 10)
            self.assertEqual(api.report_exchange.call_count, 40)

    def test_fault_log_transport_error_can_recover_without_repeating_public_work(self):
        cluster, clock = RecordingCluster(), Clock()
        api = self.timing_api([RuntimeError('private-transport-sentinel'), timing()])
        real_timings = fixture.fault_timings
        with patch.object(fixture.base, 'helper', return_value=api), \
             patch.object(fixture, 'fault_timings', side_effect=lambda c, name: real_timings(c, name, clock=clock, pause=clock.pause)):
            result = fixture.earlier_storage_failure(cluster, 'sql-permission')
        probes = [entry for entry in cluster.calls if isinstance(entry[0], tuple)
                  and entry[1].get('data') == fixture.FAILURE_PROBE.encode()]
        self.assertEqual(len(probes), 1)
        self.assertEqual(api.report_exchange.call_count, 40)
        self.assertEqual(result['result'], {'http': 200, 'structured_error': 'unavailable'})
        self.assertFalse(result['attribution_entered'])

    def test_later_forwarding_record_is_not_hidden_by_first_failed_stage(self):
        cluster, clock = RecordingCluster(), Clock()
        api = self.timing_api([timing(), timing() + timing('attribution')])
        real_timings = fixture.fault_timings
        with patch.object(fixture.base, 'helper', return_value=api), \
             patch.object(fixture, 'fault_timings', side_effect=lambda c, name: real_timings(c, name, clock=clock, pause=clock.pause)):
            with self.assertRaisesRegex(fixture.base.FixtureError, '^observer_forwarded_after_storage_failure$'):
                fixture.earlier_storage_failure(cluster, 'sql-permission')
        probes = [entry for entry in cluster.calls if isinstance(entry[0], tuple)
                  and entry[1].get('data') == fixture.FAILURE_PROBE.encode()]
        self.assertEqual(len(probes), 1)
        self.assertEqual(api.report_exchange.call_count, 2)

    def test_fault_log_evidence_fails_closed_on_forwarding_or_truncation(self):
        for payload, code in ((timing() + timing('attribution'), 'observer_forwarded_after_storage_failure'),
                              (timing() + timing('writer_token'), 'observer_forwarded_after_storage_failure'),
                              (timing() + timing('writer_transport'), 'observer_forwarded_after_storage_failure'),
                              (b'x' * 65537, 'observer_timing_bound')):
            api = self.timing_api([payload])
            with self.subTest(code=code), patch.object(fixture.base, 'helper', return_value=api):
                with self.assertRaisesRegex(fixture.base.FixtureError, '^' + code + '$'):
                    fixture.fault_timings(RecordingCluster(), 'sql-permission')
            self.assertEqual(api.report_exchange.call_count, 1)

    def test_changed_pod_container_or_restart_is_rejected_before_and_after_logs(self):
        for field in (0, 1, 3, 4, 5):
            changed = list(IDENTITY)
            changed[field] = 1 if field == 4 else 'replacement'
            for before in (True, False):
                api = self.timing_api([timing()])
                identities = [tuple(changed)] if before else [IDENTITY, tuple(changed)]
                with self.subTest(field=field, before=before), \
                     patch.object(fixture, 'backend_identity', side_effect=identities), \
                     patch.object(fixture.base, 'helper', return_value=api):
                    with self.assertRaisesRegex(fixture.base.FixtureError, '^observer_process_changed$'):
                        fixture.fault_timings(RecordingCluster(), 'sql-permission')
                self.assertEqual(api.report_exchange.call_count, 0 if before else 1)

    def test_backend_identity_requires_one_ready_running_undeleted_container(self):
        cluster = RecordingCluster()
        self.assertEqual(fixture.backend_identity(cluster), IDENTITY)
        original = json.loads(cluster.k('get', 'pods').stdout)
        for change in ('multiple-pods', 'multiple-containers', 'unready', 'terminated', 'deleted', 'no-container-id'):
            value = copy.deepcopy(original)
            status = value['items'][0]['status']['containerStatuses'][0]
            if change == 'multiple-pods': value['items'] *= 2
            if change == 'multiple-containers': value['items'][0]['status']['containerStatuses'] *= 2
            if change == 'unready': status['ready'] = False
            if change == 'terminated': status['state'] = {'terminated': {'exitCode': 1}}
            if change == 'deleted': value['items'][0]['metadata']['deletionTimestamp'] = 'fixture'
            if change == 'no-container-id': status.pop('containerID')
            with self.subTest(change=change), patch.object(cluster, 'k', return_value=SimpleNamespace(stdout=json.dumps(value).encode())):
                with self.assertRaisesRegex(fixture.base.FixtureError, '^observer_process_unavailable$'):
                    fixture.backend_identity(cluster, healthy=True)
            if change == 'unready':
                with patch.object(cluster, 'k', return_value=SimpleNamespace(stdout=json.dumps(value).encode())):
                    self.assertEqual(fixture.backend_identity(cluster), IDENTITY)

    def test_fresh_backend_is_ready_and_identified_before_fault_injection(self):
        cluster = RecordingCluster()
        events = []
        def fresh(c):
            self.assertIs(c, cluster)
            events.append(('fresh', len(cluster.calls)))
        with patch.object(fixture, 'fresh_backend', side_effect=fresh) as restart, \
             patch.object(fixture, 'earlier_storage_failure', return_value={'synthetic': True}):
            fixture.ordered_storage_faults(cluster, True)
        self.assertEqual(restart.call_count, 2)
        sql_revoke = next(i for i, call in enumerate(cluster.calls) if call[0] == 'sql' and 'REVOKE' in call[1])
        sql_grant = next(i for i, call in enumerate(cluster.calls) if call[0] == 'sql' and 'GRANT' in call[1])
        s3_stop = next(i for i, call in enumerate(cluster.calls) if call[0] == ('scale', 'deployment/objectstore', '--replicas=0'))
        self.assertLessEqual(events[0][1], sql_revoke)
        self.assertGreater(events[1][1], sql_grant)
        self.assertLessEqual(events[1][1], s3_stop)
        events.clear()
        with patch.object(fixture, 'scale_role', side_effect=lambda c, role, count: events.append((role, count))), \
             patch.object(fixture, 'semantic_ready', side_effect=lambda c: events.append('ready')), \
             patch.object(fixture, 'backend_identity', side_effect=lambda c, **kwargs: events.append(('identity', kwargs)) or IDENTITY):
            fixture.fresh_backend(cluster)
        self.assertEqual(events, [('backend', 0), ('backend', 1), 'ready', ('identity', {'healthy': True})])

    def test_semantic_readiness_executes_only_offline_server_info_until_ready(self):
        events = []
        client = object()
        api = SimpleNamespace(Client=Mock(return_value=client),
                              wait_ready=Mock(side_effect=lambda c, seconds: events.append((c, seconds))))
        with patch.dict('sys.modules', {'mcp_smoke': api}), patch.object(sys, 'path', sys.path.copy()), \
             contextlib.redirect_stdout(io.StringIO()):
            exec(fixture.READY_PROBE, {})
        self.assertEqual(events, [(client, 30)])
        cluster = RecordingCluster()
        fixture.semantic_ready(cluster)
        self.assertEqual(cluster.calls[0][1]['data'], fixture.READY_PROBE.encode())
        self.assertEqual(cluster.calls[0][1]['timeout'], 40)

    def test_slow_process_check_cannot_accept_logs_after_deadline(self):
        for slow_after_logs in (False, True):
            cluster, clock = RecordingCluster(), Clock()
            api = self.timing_api([timing()])
            count = 0
            def identity(_cluster, **kwargs):
                nonlocal count
                count += 1
                self.assertLessEqual(kwargs['timeout'], 5)
                if count == (2 if slow_after_logs else 1): clock.now += 11
                return IDENTITY
            with self.subTest(slow_after_logs=slow_after_logs), \
                 patch.object(fixture, 'backend_identity', side_effect=identity), \
                 patch.object(fixture.base, 'helper', return_value=api):
                with self.assertRaisesRegex(fixture.base.FixtureError, '^observer_timing_unavailable$'):
                    fixture.fault_timings(cluster, 'sql-permission', clock=clock, pause=clock.pause)
            self.assertEqual(api.report_exchange.call_count, 1 if slow_after_logs else 0)

    def sql_fault_snapshot(self):
        # SQL statistics failure includes its failed nested kind inventory stage.
        return timing('saved_state', failed=0, reason='') + timing() + timing('kind_inventory')

    def test_boundary_identity_timeout_keeps_previously_verified_sql_snapshot(self):
        cluster, clock = RecordingCluster(), Clock()
        payload = self.sql_fault_snapshot()
        api = self.timing_api([payload])
        checks = 0
        def identity(_cluster, **kwargs):
            nonlocal checks
            checks += 1
            self.assertLessEqual(kwargs['timeout'], 5)
            if checks == 3:
                clock.now = 10
                raise fixture.CommandError('observer_command_timeout', 'timeout')
            return IDENTITY
        with patch.object(fixture, 'backend_identity', side_effect=identity), \
             patch.object(fixture.base, 'helper', return_value=api):
            result = fixture.fault_timings(cluster, 'sql-permission', clock=clock, pause=clock.pause)
        self.assertEqual(result, fixture.timing_evidence(payload))
        self.assertEqual([event['stage'] for event in result], ['saved_state', 'statistics', 'kind_inventory'])
        self.assertEqual(api.report_exchange.call_count, 1)
        self.assertEqual(checks, 3)
        self.assertEqual(clock.now, 10)

    def test_boundary_identity_timeout_without_verified_evidence_is_unavailable(self):
        for after_log in (False, True):
            cluster, clock = RecordingCluster(), Clock()
            api = self.timing_api([self.sql_fault_snapshot()])
            checks = 0
            def identity(_cluster, **kwargs):
                nonlocal checks
                checks += 1
                if checks == (2 if after_log else 1):
                    clock.now = 10
                    raise fixture.CommandError('observer_command_timeout', 'timeout')
                return IDENTITY
            with self.subTest(after_log=after_log), \
                 patch.object(fixture, 'backend_identity', side_effect=identity), \
                 patch.object(fixture.base, 'helper', return_value=api):
                with self.assertRaisesRegex(fixture.base.FixtureError, '^observer_timing_unavailable$'):
                    fixture.fault_timings(cluster, 'sql-permission', clock=clock, pause=clock.pause)
            self.assertEqual(api.report_exchange.call_count, 1 if after_log else 0)
            self.assertFalse(getattr(cluster, 'timing_stages', []))

    def test_early_identity_timeout_remains_fatal_despite_verified_snapshot(self):
        cluster, clock = RecordingCluster(), Clock()
        payload = self.sql_fault_snapshot()
        api = self.timing_api([payload])
        checks = 0
        primary = fixture.CommandError('observer_command_timeout', 'timeout')
        def identity(_cluster, **kwargs):
            nonlocal checks
            checks += 1
            if checks == 3: raise primary
            return IDENTITY
        with patch.object(fixture, 'backend_identity', side_effect=identity), \
             patch.object(fixture.base, 'helper', return_value=api):
            with self.assertRaises(fixture.CommandError) as caught:
                fixture.fault_timings(cluster, 'sql-permission', clock=clock, pause=clock.pause)
        self.assertIs(caught.exception, primary)
        self.assertLess(clock.now, 10)
        self.assertEqual(cluster.timing_stages, fixture.timing_evidence(payload))
        self.assertEqual(api.report_exchange.call_count, 1)

    def test_post_log_boundary_timeout_rejects_fetched_forbidden_or_malformed_snapshot(self):
        for late,code in ((timing(stage),'observer_forwarded_after_storage_failure')
                          for stage in ('attribution','writer_token','writer_transport')):
            self.assert_boundary_snapshot_refused(late,code)
        self.assert_boundary_snapshot_refused(timing('unrecognized'),'observer_timing_schema')

    def assert_boundary_snapshot_refused(self,late,code):
        cluster, clock = RecordingCluster(), Clock()
        payload = self.sql_fault_snapshot()
        api = self.timing_api([payload, payload + late])
        checks = 0
        def identity(_cluster, **kwargs):
            nonlocal checks
            checks += 1
            if checks == 4:
                clock.now = 10
                raise fixture.CommandError('observer_command_timeout', 'timeout')
            return IDENTITY
        with self.subTest(code=code,late=late),patch.object(fixture, 'backend_identity', side_effect=identity), \
             patch.object(fixture.base, 'helper', return_value=api):
            with self.assertRaisesRegex(fixture.base.FixtureError,'^'+code+'$'):
                fixture.fault_timings(cluster, 'sql-permission', clock=clock, pause=clock.pause)
        self.assertEqual(cluster.timing_stages,fixture.timing_evidence(payload))
        self.assertEqual(api.report_exchange.call_count,2)
        self.assertEqual(checks,4)
        self.assertEqual(clock.now,10)

    def test_post_log_boundary_timeout_keeps_only_earlier_identity_verified_benign_snapshot(self):
        cluster, clock = RecordingCluster(), Clock()
        payload = self.sql_fault_snapshot()
        api = self.timing_api([payload, b''])
        checks = 0
        def identity(_cluster, **kwargs):
            nonlocal checks
            checks += 1
            if checks == 4:
                clock.now = 10
                raise fixture.CommandError('observer_command_timeout', 'timeout')
            return IDENTITY
        with patch.object(fixture, 'backend_identity', side_effect=identity), \
             patch.object(fixture.base, 'helper', return_value=api):
            result = fixture.fault_timings(cluster, 'sql-permission', clock=clock, pause=clock.pause)
        self.assertEqual(result, fixture.timing_evidence(payload))
        self.assertEqual(cluster.timing_stages, result)
        self.assertEqual(api.report_exchange.call_count, 2)
        self.assertEqual(checks, 4)
        self.assertEqual(clock.now, 10)

    def timed_control_reads(self,cluster,clock,latency=2.25,replace_at=None):
        original=cluster.k;calls=[]
        def command(*args,**kwargs):
            if args[:2] != ('get','pods'):return original(*args,**kwargs)
            budget=kwargs['timeout'];calls.append((clock.now,budget))
            self.assertEqual(budget,min(5,10-clock.now))
            clock.pause(min(latency,budget))
            if latency>budget:raise fixture.CommandError('observer_command_timeout','timeout')
            result=original(*args,**kwargs)
            if len(calls)==replace_at:
                value=json.loads(result.stdout);value['items'][0]['metadata']['uid']='replacement'
                result=SimpleNamespace(stdout=json.dumps(value).encode(),returncode=0)
            return result
        return calls,patch.object(cluster,'k',side_effect=command)

    def test_control_reads_over_two_seconds_fit_the_unchanged_ten_second_window(self):
        cluster,clock=RecordingCluster(),Clock();payload=self.sql_fault_snapshot();api=self.timing_api([payload])
        calls,control=self.timed_control_reads(cluster,clock)
        with control,patch.object(fixture.base,'helper',return_value=api):
            result=fixture.fault_timings(cluster,'sql-permission',clock=clock,pause=clock.pause)
        self.assertEqual(result,fixture.timing_evidence(payload))
        self.assertEqual(calls,[(0,5),(2.25,5),(4.75,5),(7.0,3.0),(9.5,.5)])
        self.assertEqual(api.report_exchange.call_count,2)
        self.assertEqual(clock.now,10)
        self.assertTrue(all(call.kwargs['timeout']<=2 for call in api.report_exchange.call_args_list))

    def test_slow_control_timeout_before_deadline_still_fails_immediately(self):
        cluster,clock=RecordingCluster(),Clock();api=self.timing_api([self.sql_fault_snapshot()])
        calls,control=self.timed_control_reads(cluster,clock,latency=5.5)
        with control,patch.object(fixture.base,'helper',return_value=api):
            with self.assertRaisesRegex(fixture.CommandError,'^observer_command_timeout$'):
                fixture.fault_timings(cluster,'sql-permission',clock=clock,pause=clock.pause)
        self.assertEqual(calls,[(0,5)]);self.assertEqual(clock.now,5)
        api.report_exchange.assert_not_called()

    def test_slow_control_replacement_before_or_after_log_still_fails_closed(self):
        for replacement in (1,2):
            cluster,clock=RecordingCluster(),Clock();api=self.timing_api([self.sql_fault_snapshot()])
            calls,control=self.timed_control_reads(cluster,clock,replace_at=replacement)
            with self.subTest(replacement=replacement),control,patch.object(fixture.base,'helper',return_value=api):
                with self.assertRaisesRegex(fixture.base.FixtureError,'^observer_process_changed$'):
                    fixture.fault_timings(cluster,'sql-permission',clock=clock,pause=clock.pause)
            self.assertEqual(api.report_exchange.call_count,replacement-1)
            self.assertFalse(getattr(cluster,'timing_stages',[]))
            self.assertLess(clock.now,10)

    def test_slow_healthy_controls_do_not_hide_late_forbidden_stages(self):
        for stage in ('attribution','writer_token','writer_transport'):
            cluster,clock=RecordingCluster(),Clock();payload=self.sql_fault_snapshot()
            api=self.timing_api([payload,payload+timing(stage)])
            calls,control=self.timed_control_reads(cluster,clock)
            with self.subTest(stage=stage),control,patch.object(fixture.base,'helper',return_value=api):
                with self.assertRaisesRegex(fixture.base.FixtureError,'^observer_forwarded_after_storage_failure$'):
                    fixture.fault_timings(cluster,'sql-permission',clock=clock,pause=clock.pause)
            self.assertEqual(clock.now,9.25);self.assertEqual(api.report_exchange.call_count,2)
            self.assertEqual(cluster.timing_stages,fixture.timing_evidence(payload))

    def test_diagnostics_are_closed_and_captured_before_all_restoration_attempts(self):
        cluster = RecordingCluster()
        cluster.phase, cluster.fault_case = 'fault-probe', 'sql-permission'
        events = []
        primary = fixture.CommandError('fixture_command_failed', 'nonzero', 7)
        def fail_restore():
            events.append('grant')
            raise OSError('private-restore-sentinel')
        def persist(_cluster, name, record):
            fixture.base.validate_receipt(name, record)
            events.append(('receipt', copy.deepcopy(record)))
            return False
        with patch.object(fixture.base, 'receipt', side_effect=persist):
            with self.assertRaises(fixture.CommandError) as caught:
                with fixture.restoring(cluster, [('sql-grant', fail_restore),
                                                  ('objectstore-start', lambda: events.append('objectstore'))]):
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(events[0][0], 'receipt')
        self.assertEqual(events[1:], ['grant', 'objectstore'])
        self.assertEqual(events[0][1]['exit_code'], 7)
        self.assertEqual(cluster.restoration_steps, [{'step': 'sql-grant', 'restored': False},
                                                     {'step': 'objectstore-start', 'restored': True}])
        self.assertNotIn('sentinel', json.dumps(events))

    def test_failed_restoration_is_not_a_success_without_a_primary_error(self):
        cluster = RecordingCluster()
        attempted = []
        def fail():
            attempted.append('grant')
            raise OSError('private-secret')
        with self.assertRaisesRegex(fixture.base.FixtureError, '^observer_restoration_failed$'):
            with fixture.restoring(cluster, [('sql-grant', fail), ('writer-start', lambda: attempted.append('start'))]):
                pass
        self.assertEqual(attempted, ['grant', 'start'])
        self.assertEqual(cluster.phase, 'restore')

    def failure_receipt(self):
        return {'version': 1, 'synthetic': True, 'phase': 'fault-timing', 'case': 'sql-permission',
                'code': 'observer_timing_missing', 'command_outcome': 'none', 'exit_code': None,
                'stages': fixture.timing_evidence(timing())}

    def test_failure_capture_sanitizes_exceptions_and_is_create_once(self):
        for error in (RuntimeError('private-token-sentinel'), fixture.base.FixtureError('private-url-sentinel'),
                      KeyboardInterrupt(), fixture.CommandError('observer_command_timeout', 'timeout')):
            cluster = RecordingCluster()
            cluster.phase = 'fault-probe'
            with self.subTest(error=type(error).__name__), patch.object(fixture.base, 'receipt') as persist:
                fixture.capture_failure(cluster, error)
                fixture.capture_failure(cluster, error)
                persist.assert_called_once()
                name, record = persist.call_args.args[1:]
                fixture.base.validate_receipt(name, record)
                self.assertNotIn('sentinel', json.dumps(record))
                self.assertEqual(record['code'], 'interrupted' if isinstance(error, KeyboardInterrupt)
                                 else 'observer_command_timeout' if isinstance(error, fixture.CommandError) else 'unknown')

    def test_failure_receipt_rejects_open_fields_invalid_codes_and_nonfinite_counts(self):
        for field, replacement in (('phase', 'private-url'), ('case', 'private-package'),
                                   ('code', 'raw-exception'), ('command_outcome', 'stderr'),
                                   ('exit_code', True), ('exit_code', 256), ('stages', [{'raw': 'secret'}])):
            value = self.failure_receipt()
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(fixture.base.FixtureError):
                fixture.base.validate_receipt('paused-status-failure.json', value)
        value = self.failure_receipt()
        value['raw_stderr'] = 'private-token-sentinel'
        with self.assertRaises(fixture.base.FixtureError):
            fixture.base.validate_receipt('paused-status-failure.json', value)
        for count in (True, -1, 1000001, 1.5):
            value = self.failure_receipt()
            value['stages'][0]['calls'] = count
            with self.subTest(count=count), self.assertRaises(fixture.base.FixtureError):
                fixture.base.validate_receipt('paused-status-failure.json', value)
        value = self.failure_receipt()
        value['stages'] *= 2
        with self.assertRaises(fixture.base.FixtureError):
            fixture.base.validate_receipt('paused-status-failure.json', value)

    def test_restoration_receipt_rejects_unknown_steps_or_untyped_results(self):
        for steps in ([], [{'step': 'raw-private-command', 'restored': True}],
                      [{'step': 'sql-grant', 'restored': 1}],
                      [{'step': 'sql-grant', 'restored': True, 'stderr': 'private-secret'}]):
            with self.subTest(steps=steps), self.assertRaises(fixture.base.FixtureError):
                fixture.base.validate_receipt('paused-status-restoration.json',
                                              {'version': 1, 'synthetic': True, 'steps': steps})

    def test_private_failure_receipts_survive_scratch_and_refuse_overwrite_or_symlink(self):
        with tempfile.TemporaryDirectory(dir='/tmp', prefix='devres-observer-receipt-test.') as temporary:
            root = Path(temporary)
            scratch = root / 'scratch'
            scratch.mkdir()
            cluster = RecordingCluster(scratch=scratch)
            name = 'paused-status-failure.json'
            with patch.dict(os.environ, {'DEVRES_E2E_DIAGNOSTICS_DIR': str(root / 'retained')}):
                self.assertTrue(fixture.base.receipt(cluster, name, self.failure_receipt()))
                retained = root / 'retained' / cluster.profile / name
                original = retained.read_bytes()
                self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
                (scratch / name).unlink()
                self.assertEqual(json.loads(retained.read_bytes()), self.failure_receipt())
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertFalse(fixture.base.receipt(cluster, name, self.failure_receipt()))
                self.assertEqual(retained.read_bytes(), original)
            target = root / 'unrelated'
            target.write_text('preserved')
            link = scratch / 'linked.json'
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                fixture.base.private_json(link, self.failure_receipt())
            self.assertEqual(target.read_text(), 'preserved')

    def test_real_persistence_failure_does_not_replace_primary_probe_error(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = RecordingCluster(scratch=Path(temporary))
            primary = fixture.CommandError('fixture_command_failed', 'nonzero', 5)
            output = io.StringIO()
            with patch.object(fixture.base, 'private_json', side_effect=OSError('private-persistence-sentinel')), \
                 contextlib.redirect_stderr(output):
                with self.assertRaises(fixture.CommandError) as caught:
                    with fixture.restoring(cluster, [('sql-grant', lambda: None)]):
                        raise primary
            self.assertIs(caught.exception, primary)
            self.assertTrue(cluster.receipt_failures)
            self.assertNotIn('sentinel', output.getvalue())

    def test_cluster_command_errors_retain_only_fixed_exit_or_timeout_metadata(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-test', Path(temporary))
            for result, code, outcome in ((SimpleNamespace(returncode=9), 'fixture_command_failed', 'nonzero'),
                                           (subprocess.TimeoutExpired(['private-command'], 1, output=b'private-secret'),
                                            'observer_command_timeout', 'timeout')):
                settings = {'side_effect': result} if isinstance(result, Exception) else {'return_value': result}
                with self.subTest(code=code), patch.object(fixture.base.Cluster, 'k', **settings):
                    with self.assertRaisesRegex(fixture.CommandError, '^' + code + '$') as caught:
                        cluster.k('get', 'pods')
                self.assertEqual(caught.exception.outcome, outcome)
                self.assertNotIn('private', str(caught.exception))

    def test_pinned_fault_probe_preserves_backend_host_sni_and_tls_validation(self):
        connections = []
        raw_socket, tls_socket = object(), object()
        context = ssl.create_default_context()
        def exchange(_self, method, parameters, revision):
            connections.append((method, parameters, revision))
            connection = api.http.client.HTTPSConnection('backend', 8080, context=context, timeout=2)
            connection.connect()
            self.assertIs(connection.sock, tls_socket)
            return 200, {'result': {'isError': True, 'structuredContent': {'code': 'unavailable'}}}
        client = SimpleNamespace(exchange=exchange)
        constructor = Mock(side_effect=lambda *args: SimpleNamespace(exchange=lambda *values: exchange(client, *values)))
        api = SimpleNamespace(Client=constructor, MODERN='fixture-revision', http=http)
        original = http.client.HTTPSConnection
        with patch.dict(sys.modules, {'mcp_smoke': api}), patch.object(sys, 'path', sys.path.copy()), \
             patch.object(sys, 'argv', ['-', IDENTITY[5]]), \
             patch.object(http.client, 'HTTPSConnection', original), \
             patch('socket.create_connection', return_value=raw_socket) as connect, \
             patch.object(context, 'wrap_socket', return_value=tls_socket) as wrap, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            exec(fixture.FAILURE_PROBE, {})
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        connect.assert_called_once_with((IDENTITY[5], 8080), 2)
        wrap.assert_called_once_with(raw_socket, server_hostname='backend')
        self.assertEqual(constructor.call_args.args[0], 'https://backend:8080/mcp')
        self.assertEqual(connections, [('tools/call', {'name': 'packages.npm.corpus_status', 'arguments': {}}, 'fixture-revision')])
        self.assertEqual(json.loads(output.getvalue()), {'http': 200, 'structured_error': 'unavailable'})

    def run_fixture(self, *, failure=False, cleanup_failure=False):
        temporary = tempfile.TemporaryDirectory(dir='/tmp', prefix='devres-observer-run-test.')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / 'fixture').mkdir()
        text = '[storage]\ndatabase_url="fixture-only"\nblob_dir="/data/blobs"\n[writer_listener]\nbind="0.0.0.0:9443"\n'
        (root / 'fixture/writer.toml').write_text(text)
        (root / 'fixture/backend.toml').write_text(text.replace('writer_listener', 'writer_client'))
        cluster = RecordingCluster(scratch=root)
        events, receipts = [], {}
        primary = fixture.CommandError('fixture_command_failed', 'nonzero', 8)
        original_k = cluster.k
        def k(*args, **kwargs):
            data = kwargs.get('data')
            if data == fixture.PUBLIC_PROBE.encode():
                events.append('public-status')
                if failure: raise primary
            if args[:2] == ('delete', 'networkpolicy'):
                events.append('restore-policy')
                if cleanup_failure: raise OSError('private-cleanup-sentinel')
            return original_k(*args, **kwargs)
        cluster.k = k
        def faults(c, s3):
            events.append('frozen-fault-evidence')
            return [{'case': 'sql-permission', 'result': {'http': 200, 'structured_error': 'unavailable'},
                     'stages': fixture.timing_evidence(timing()), 'attribution_entered': False}]
        def receipt(c, name, value):
            fixture.base.validate_receipt(name, value)
            receipts[name] = copy.deepcopy(value)
            events.append(name)
            return True
        arguments = SimpleNamespace(scratch=str(root), profile=cluster.profile, s3=False)
        with patch.object(fixture, 'Cluster', return_value=cluster), \
             patch.object(fixture, 'snapshot', return_value=[{'rows': 1, 'digest': 'retained'}]), \
             patch.object(fixture, 'ordered_storage_faults', side_effect=faults), \
             patch.object(fixture.base, 'receipt', side_effect=receipt), \
             contextlib.redirect_stdout(io.StringIO()):
            if failure:
                with self.assertRaises(fixture.CommandError) as caught:
                    fixture.run(arguments)
                self.assertIs(caught.exception, primary)
            else:
                fixture.run(arguments)
        return cluster, events, receipts

    def test_run_checks_healthy_status_after_faults_and_restores_before_success_receipt(self):
        cluster, events, receipts = self.run_fixture()
        self.assertLess(events.index('frozen-fault-evidence'), events.index('public-status'))
        self.assertLess(events.index('restore-policy'), events.index('paused-status-receipt.json'))
        self.assertNotIn('paused-status-failure.json', receipts)
        self.assertTrue(all(step['restored'] for step in receipts['paused-status-restoration.json']['steps']))
        public = receipts['paused-status-receipt.json']
        self.assertEqual({row['revision'] for row in public['public_status']}, {'2026-07-28', '2025-11-25'})
        self.assertTrue(public['startup_and_calls_metadata_unchanged'])
        self.assertEqual(public['provider_requests'], 0)

    def test_run_preserves_failed_public_probe_once_and_retains_evidence_before_restoration(self):
        cluster, events, receipts = self.run_fixture(failure=True, cleanup_failure=True)
        self.assertEqual(events.count('public-status'), 1)
        self.assertLess(events.index('paused-status-failure.json'), events.index('restore-policy'))
        self.assertNotIn('paused-status-receipt.json', receipts)
        failure = receipts['paused-status-failure.json']
        self.assertEqual((failure['phase'], failure['code'], failure['exit_code']),
                         ('public-status', 'fixture_command_failed', 8))
        steps = receipts['paused-status-restoration.json']['steps']
        self.assertEqual(len(steps), 10)
        self.assertEqual([step for step in steps if not step['restored']], [{'step': 'policy-remove', 'restored': False}])
        self.assertEqual(steps[-1], {'step': 'semantic-ready', 'restored': True})
        self.assertNotIn('sentinel', json.dumps(receipts))


if __name__ == '__main__':
    unittest.main()
