"""Test observer harness authority/configuration without creating a cluster."""
import copy
import importlib.util
import json
from pathlib import Path
import tomllib
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'paused-status-fixture.py'
SPEC = importlib.util.spec_from_file_location('paused_status_fixture', SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


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
        class Cluster:
            def __init__(self): self.calls = []
            def sql(self, statement): self.calls.append(statement)
            def k(self, *arguments, **_kwargs): self.calls.append(arguments)
        cluster = Cluster()
        with patch.object(fixture, 'earlier_storage_failure', side_effect=fixture.base.FixtureError('fixture-failed')):
            with self.assertRaises(fixture.base.FixtureError):
                fixture.ordered_storage_faults(cluster, False)
        self.assertEqual(cluster.calls[-1], 'GRANT SELECT ON devres_npm_evidence TO devres_reader')
        cluster = Cluster()
        with patch.object(fixture, 'earlier_storage_failure', side_effect=[{'case': 'sql'}, fixture.base.FixtureError('fixture-failed')]):
            with self.assertRaises(fixture.base.FixtureError):
                fixture.ordered_storage_faults(cluster, True)
        self.assertIn(('scale', 'deployment/objectstore', '--replicas=1'), cluster.calls)
        self.assertEqual(cluster.calls[-1][0:3], ('rollout', 'status', 'deployment/objectstore'))


if __name__ == '__main__':
    unittest.main()
