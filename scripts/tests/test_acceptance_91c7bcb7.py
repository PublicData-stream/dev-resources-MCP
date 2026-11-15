"""Offline behavioral checks for the exact deployment evidence producers.

Synthetic /tmp artifacts exercise real validators; no provider, runtime or cluster
commands are executed and no successful gate is substituted for a failing check.
"""
import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / 'deploy/production/acceptance_91c7bcb7'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SOURCES / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


loop = module('deployment_loop_fixture', 'observation-loop.py')
receipt = module('deployment_receipt_fixture', 'acceptance-receipt.py')
compression = module('deployment_compression_fixture', 'compressed-probe.py')
operational = module('deployment_operational_fixture', 'operational-proof.py')
driver = module('deployment_phase_driver_fixture', 'phase-driver.py')
NOW = dt.datetime(2026, 11, 15, 12, 0, tzinfo=dt.timezone.utc)
POLICY = {'format_version': 1, 'required_policy_epoch': 2,
          'required_policy_fingerprint': 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'}
URL = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.91c7bcb7/source.tar.gz'


class AcceptanceFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='acceptance-91c7-', dir='/tmp')
        self.work = Path(self.temporary.name)
        self.patches = [patch.object(receipt, 'WORK', self.work),
                        patch.object(loop, 'WORK', self.work),
                        patch.object(receipt, 'now', return_value=NOW)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
        path.chmod(0o600)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def sample(self, index=0):
        pods = {role: {'container_id': 'containerd://' + role, 'started_at': 'start-' + role,
                       'pod_ip': address, 'restarts': 1, 'uid': 'pod-' + role}
                for role, address in (('postgres', '10.42.0.1'), ('writer', '10.42.0.2'), ('backend', '10.42.0.3'))}
        return {'version': 1, 'revision': receipt.REVISION, 'phase': 'collectors_active',
                'configs_variant': 'active', 'guard_passed': True, 'prepared_sha256': 'a' * 64,
                'pods': pods, 'edge': {'id': 'edge', 'pid': 17}, 'profiles': {'runtime': 'b' * 64},
                'boot': {'id': 'boot'}, 'authority_sha256': 'c' * 64,
                'collectors': {role: {provider: True for provider in loop.PROVIDERS}
                               for role in ('writer', 'backend')},
                'source_urls': {role: URL for role in ('writer', 'backend')},
                'timers': {'devres-capacity.timer': 'active', 'devres-cert-renew.timer': 'active'},
                'free_bytes': loop.RESERVE + 1024**3, 'free_inodes': 10000,
                'observed_at': (NOW - dt.timedelta(seconds=900 - index * 30)).isoformat(),
                'monotonic': 10000 + index * 30,
                'database': {'system_id': 'system-id', 'schema': 18, 'control': copy.deepcopy(POLICY),
                             'archive': {'store_id': 'd' * 32, 'binding': 'blake3:' + 'e' * 64, 'epoch': 2},
                             'owners': [{'role': 'devres_writer', 'client_addr': '10.42.0.2', 'pid': 29}],
                             'reader_select_gaps': 0, 'reader_mutation_tables': 0,
                             'reader_default_readonly': True,
                             'pinned_generation': {'id': 'historical-generation', 'data_integrity': 'seal'},
                             'capture_count': 100 + index, 'archive_files': 200 + index}}

    def state(self):
        sample = self.sample()
        return {'phase': 'collectors_active', 'configs': 'active',
                'pods': sample['pods'], 'prepared_sha256': sample['prepared_sha256']}

    def mutate(self, value, path, replacement):
        result = copy.deepcopy(value)
        parent = result
        fields = path.split('.')
        for field in fields[:-1]:
            parent = parent[field]
        parent[fields[-1]] = replacement
        return result

    def test_sampler_and_operational_sources_require_exact_bytes_before_import(self):
        source = self.work / 'synthetic-source.py'
        # This first-party fixture has no imports or side effects.
        source.write_bytes(b'FIXTURE_VALUE = 17\n');source.chmod(0o600)
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(loop.load_source(source, expected).FIXTURE_VALUE, 17)
        self.assertEqual(operational.bound_module(source, expected, 'bound_fixture').FIXTURE_VALUE, 17)
        source.write_bytes(b'raise AssertionError("unapproved source was executed")\n')
        with self.assertRaisesRegex(loop.Stop, 'sampler_source_hash'):
            loop.load_source(source, expected)
        with self.assertRaisesRegex(operational.Stop, 'source_hash_mismatch'):
            operational.bound_module(source, expected, 'changed_fixture')

    def test_operational_source_refuses_group_readable_and_symlink_inputs(self):
        source = self.work / 'synthetic-source.py'
        source.write_bytes(b'FIXTURE_VALUE = 17\n');source.chmod(0o640)
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        with self.assertRaisesRegex(operational.Stop, 'bounded_private_file_required'):
            operational.bound_module(source, expected, 'bad_permissions')
        source.chmod(0o600)
        alias = self.work / 'alias.py';alias.symlink_to(source)
        with self.assertRaisesRegex(loop.Stop, 'sampler_path'):
            loop.load_source(alias, expected)

    def failed_driver(self, operation, withdrawal_failure=False):
        source = self.work / 'synthetic-controller.py'
        source.write_bytes(b'# source-bound first-party controller fixture\n');source.chmod(0o600)
        source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
        bundle = self.work / 'bundle'
        controller = Mock()
        controller.locked.return_value = contextlib.nullcontext()
        controller.state.return_value = {'prepared_sha256':'a'*64,'phase':'stopped'}
        controller.run.side_effect = RuntimeError('phase_failed')
        if withdrawal_failure:
            controller.withdraw.side_effect = RuntimeError('withdraw_failed')
        writes = {}
        def save(path, value):
            writes[path.name] = copy.deepcopy(value)
            self.write(path, value)
        runtime = types.SimpleNamespace(BUNDLE=str(bundle),WORK=str(self.work),REVISION=receipt.REVISION,
            Controller=Mock(return_value=controller),save=save,stamp=lambda:NOW.isoformat(),
            read=lambda path:Path(path).read_bytes(),digest=lambda body:hashlib.sha256(body).hexdigest())
        spec = types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=Mock()))
        output = io.StringIO()
        with patch.object(driver,'C',source),patch.object(driver,'N',self.work),patch.object(driver,'B',bundle),\
             patch.object(driver.os,'geteuid',return_value=0),\
             patch.object(driver.sys,'argv',['phase-driver.py',operation,'--controller-sha',source_sha]),\
             patch.object(driver.importlib.util,'spec_from_file_location',return_value=spec) as import_spec,\
             patch.object(driver.importlib.util,'module_from_spec',return_value=runtime),\
             contextlib.redirect_stdout(output):
            exit_code = driver.main()
        import_spec.assert_called_once_with('source_bound_phase',source)
        spec.loader.exec_module.assert_called_once_with(runtime)
        intent = writes['driver-'+operation+'-intent.json']
        self.assertEqual(intent['source_sha256'],source_sha)
        self.assertEqual(intent['prepared_sha256'],'a'*64)
        self.assertEqual(intent['maximum_attempts'],1)
        result = json.loads(output.getvalue())
        self.assertEqual(result,writes['driver-'+operation+'-result.json'])
        self.assertEqual(exit_code,1)
        self.assertFalse(result['known_complete'])
        return result,controller

    def test_explicit_withdraw_failure_never_claims_withdrawal_completed(self):
        result,controller = self.failed_driver('withdraw')
        self.assertFalse(result['withdrawal_completed'])
        controller.run.assert_called_once()
        controller.withdraw.assert_not_called()

    def test_failed_phase_records_withdrawal_completed_only_after_fallback_success(self):
        result,controller = self.failed_driver('stop')
        self.assertTrue(result['withdrawal_completed'])
        controller.run.assert_called_once()
        controller.withdraw.assert_called_once_with()

    def test_failed_phase_and_failed_fallback_record_incomplete_withdrawal(self):
        result,controller = self.failed_driver('stop',withdrawal_failure=True)
        self.assertFalse(result['withdrawal_completed'])
        controller.run.assert_called_once()
        controller.withdraw.assert_called_once_with()

    def assert_loop_rejects(self, value, reason, first=None, previous=None):
        with self.assertRaisesRegex(loop.Stop, reason):
            loop.validate(value, first, previous)

    def test_loop_accepts_actual_active_runtime_and_advancing_history(self):
        first, second = self.sample(0), self.sample(1)
        loop.validate(first)
        loop.validate(second, first, first)

    def test_loop_rejects_wrong_phase_policy_reader_authority_and_provider_scope(self):
        changes = [('phase', 'reader_ready', 'active_guarded_sample_required'),
                   ('database.schema', 15, 'schema18_readonly_policy2_required'),
                   ('database.control.required_policy_epoch', 1, 'schema18_readonly_policy2_required'),
                   ('database.reader_mutation_tables', 1, 'schema18_readonly_policy2_required'),
                   ('collectors.writer.wikipedia', False, 'nine_source_settings_required'),
                   ('source_urls.backend', 'https://unrelated.invalid/source', 'target_source_url_required'),
                   ('timers', {'devres-capacity.timer': 'active', 'devres-cert-renew.timer': 'inactive'}, 'capacity_and_timers_required'),
                   ('free_bytes', loop.RESERVE - 1, 'capacity_and_timers_required')]
        for path, changed, reason in changes:
            with self.subTest(path=path):
                self.assert_loop_rejects(self.mutate(self.sample(), path, changed), reason)

    def test_loop_binds_sole_writer_owner_to_actual_writer_pod(self):
        value = self.sample()
        for owners in ([], value['database']['owners'] * 2,
                       [{'role': 'devres_reader', 'client_addr': '10.42.0.2'}],
                       [{'role': 'devres_writer', 'client_addr': '10.42.0.99'}]):
            self.assert_loop_rejects(self.mutate(value, 'database.owners', owners), 'one_unchanged_writer_required')

    def test_loop_rejects_added_restart_pid_owner_or_boot_without_rebaselining(self):
        first = self.sample()
        for path, changed in [('pods.writer.restarts', 2), ('pods.writer.container_id', 'new-container'),
                              ('boot.id', 'new-boot'), ('database.owners', [{'role': 'devres_writer', 'client_addr': '10.42.0.2', 'pid': 30}])]:
            with self.subTest(path=path):
                self.assert_loop_rejects(self.mutate(self.sample(1), path, changed), 'sampled_process_or_boundary_drift', first, first)

    def test_loop_enforces_actual_monotonic_gap_and_permanent_history(self):
        first = self.sample()
        for delta in (0, -1, 45.001):
            value = self.sample(1)
            value['monotonic'] = first['monotonic'] + delta
            self.assert_loop_rejects(value, 'maximum_sample_gap', first, first)
        for key in ('capture_count', 'archive_files'):
            value = self.sample(1)
            value['database'][key] = first['database'][key] - 1
            self.assert_loop_rejects(value, 'permanent_history_count_regressed', first, first)

    def observation_fixture(self):
        samples = [self.sample(index) for index in range(31)]
        paths = []
        for index, value in enumerate(samples):
            path = self.work / 'operational-proofs' / ('sample-%02d' % index) / 'observation.json'
            paths.append({'path': str(path), 'sha256': self.write(path, value)})
        summary = {'verified': True, 'revision': receipt.REVISION, 'sources': {'compression': 'f' * 64},
                   'samples': paths, 'sample_count': 31, 'duration_seconds': 900, 'maximum_gap_seconds': 30}
        target = self.work / 'observation' / 'completed.json'
        self.write(target, summary)
        return samples, summary, target

    def aggregate(self, artifacts=None):
        return receipt.observation_set(operational, 'observation', self.state(), self.sample(30),
                                       artifacts if artifacts is not None else [], 'f' * 64)

    def test_observation_aggregate_reads_and_hash_binds_all_real_sample_files(self):
        _, summary, _ = self.observation_fixture()
        artifacts = []
        result = self.aggregate(artifacts)
        self.assertEqual(result['sample_count'], 31)
        self.assertEqual(result['duration_seconds'], 900)
        self.assertEqual(result['maximum_gap_seconds'], 30)
        self.assertEqual(len(artifacts), 32)
        self.assertEqual({item['sha256'] for item in artifacts[1:]}, {item['sha256'] for item in summary['samples']})

    def test_observation_aggregate_rejects_modified_sample_before_trusting_summary(self):
        samples, summary, _ = self.observation_fixture()
        self.write(Path(summary['samples'][5]['path']), self.mutate(samples[5], 'pods.backend.restarts', 2))
        with self.assertRaisesRegex(receipt.Stop, 'artifact_hash'):
            self.aggregate()

    def test_observation_aggregate_rejects_cross_runtime_sample_even_with_fresh_hash(self):
        samples, summary, target = self.observation_fixture()
        summary['samples'][5]['sha256'] = self.write(Path(summary['samples'][5]['path']),
            self.mutate(samples[5], 'pods.backend.container_id', 'different-runtime'))
        self.write(target, summary)
        with self.assertRaisesRegex(receipt.Stop, 'sample_runtime_identity'):
            self.aggregate()

    def test_observation_aggregate_rejects_self_declared_duration_or_unowned_paths(self):
        _, summary, target = self.observation_fixture()
        for key, value in [('duration_seconds', 3600), ('maximum_gap_seconds', 1)]:
            self.write(target, {**summary, key: value})
            with self.assertRaisesRegex(receipt.Stop, 'observation_actual_duration'):
                self.aggregate()
        changed = copy.deepcopy(summary)
        changed['samples'][0]['path'] = str(self.work / 'unrelated' / 'sample' / 'observation.json')
        self.write(target, changed)
        with self.assertRaisesRegex(receipt.Stop, 'owned_observation_sample_path'):
            self.aggregate()

    def test_observation_aggregate_rejects_duplicate_time_and_rehashed_history_regression(self):
        samples, summary, target = self.observation_fixture()
        changed = copy.deepcopy(samples[5])
        changed['monotonic'] = samples[4]['monotonic']
        summary['samples'][5]['sha256'] = self.write(Path(summary['samples'][5]['path']), changed)
        self.write(target, summary)
        with self.assertRaisesRegex(receipt.Stop, 'duplicate_observation_sample'):
            self.aggregate()
        changed = self.mutate(samples[5], 'database.capture_count', 0)
        summary['samples'][5]['sha256'] = self.write(Path(summary['samples'][5]['path']), changed)
        self.write(target, summary)
        with self.assertRaisesRegex(receipt.Stop, 'permanent_history_count_regressed'):
            self.aggregate()

    def test_observation_aggregate_enforces_31_samples_and_real_maximum_gap(self):
        samples, summary, target = self.observation_fixture()
        self.write(target, {**summary, 'samples':summary['samples'][:21], 'sample_count':21})
        with self.assertRaisesRegex(receipt.Stop, 'observation_sample_count'):
            self.aggregate()
        changed = copy.deepcopy(samples[5])
        changed['monotonic'] += 20
        summary['samples'][5]['sha256'] = self.write(Path(summary['samples'][5]['path']), changed)
        self.write(target, summary)
        with self.assertRaisesRegex(receipt.Stop, 'observation_sample_gap'):
            self.aggregate()

    def test_observation_aggregate_rejects_stale_last_sample_and_replaced_producer(self):
        samples, summary, target = self.observation_fixture()
        self.write(target, {**summary, 'sources':{'compression':'0'*64}})
        with self.assertRaisesRegex(receipt.Stop, 'observation_compression_source_changed'):
            self.aggregate()
        changed = copy.deepcopy(samples[-1])
        changed['observed_at'] = (NOW - dt.timedelta(seconds=301)).isoformat()
        summary['samples'][-1]['sha256'] = self.write(Path(summary['samples'][-1]['path']), changed)
        self.write(target, summary)
        with self.assertRaisesRegex(receipt.Stop, 'observation_last_sample_stale'):
            self.aggregate()

    def test_observation_aggregate_rejects_symlinked_artifact(self):
        _, summary, _ = self.observation_fixture()
        path = Path(summary['samples'][5]['path'])
        replacement = self.work / 'synthetic-replacement.json'
        replacement.write_bytes(path.read_bytes());replacement.chmod(0o600)
        path.unlink();path.symlink_to(replacement)
        with self.assertRaisesRegex(receipt.Stop, 'artifact_path'):
            self.aggregate()

    def private_fixture(self):
        return {'version': 1, 'release': receipt.VERSION, 'observed_at': NOW.isoformat(),
                'private_mcp_both_revisions': True, 'tool_inventory': 98, 'source_offer_verified': True,
                'no_provider_acquisition': True,
                'client_certificate': {'missing': 'rejected', 'wrong': 'rejected'},
                'writer_authorization': {'missing': 401, 'invalid': 401},
                'reader_sqlstates': {'explicit_read_only': '25006', 'privilege': '42501'},
                'reader_noop_transactions_rolled_back': True,
                'edge_private_denials': {'postgres': 'blocked', 'writer': 'blocked', 'private_health': 'blocked'},
                'edge_nodeport_positive': True,
                'pinned': {revision: {'capture': receipt.CID, 'historical_notice_sha256': receipt.NOTICE,
                                     'current_policy_read': 'ready', 'body_hash': receipt.BODY,
                                     'generation': 'devres://attribution/blake3:' + 'a' * 64}
                           for revision in receipt.REVISIONS}}

    def test_private_proof_requires_both_protocols_pinned_body_and_historical_notice(self):
        value = self.private_fixture()
        receipt.private_proof(value)
        for field, changed, reason in [('capture', 'other-capture', 'private_immutable_notice'),
                                      ('historical_notice_sha256', 'b' * 64, 'private_immutable_notice'),
                                      ('body_hash', 'blake3:' + 'b' * 64, 'private_ready_capture_identity'),
                                      ('generation', 'https://unrelated.invalid/notice', 'private_ready_capture_identity')]:
            target = copy.deepcopy(value)
            target['pinned'][receipt.REVISIONS[0]][field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(receipt.Stop, reason):
                receipt.private_proof(target)
        del value['pinned'][receipt.REVISIONS[0]]
        with self.assertRaisesRegex(receipt.Stop, 'private_protocol_cells'):
            receipt.private_proof(value)

    def test_private_proof_rejects_boundary_control_missing_positive_and_stale_evidence(self):
        value = self.private_fixture()
        for path, changed, reason in [('client_certificate.wrong', 'accepted', 'private_authentication_or_readonly'),
                                     ('writer_authorization.invalid', 200, 'private_authentication_or_readonly'),
                                     ('edge_nodeport_positive', False, 'private_network_boundary'),
                                     ('observed_at', (NOW - dt.timedelta(seconds=301)).isoformat(), 'private_proof_stale')]:
            with self.subTest(path=path), self.assertRaisesRegex(receipt.Stop, reason):
                receipt.private_proof(self.mutate(value, path, changed))

    def test_private_positive_baseline_must_not_downgrade_to_unavailable(self):
        value = self.private_fixture()
        value['pinned'][receipt.REVISIONS[0]]['current_policy_read'] = 'explicit_attribution_unavailable'
        with self.assertRaises(receipt.Stop):
            receipt.private_proof(value)

    def compressed_fixture(self):
        tools = [{'name': 'fixture.tool_%03d' % i} for i in range(98)]
        payload = {'jsonrpc': '2.0', 'id': 17, 'result': {'tools': tools}}
        body = b'data: ' + json.dumps(payload).encode() + b'\n\n'
        head = {'content-encoding': 'gzip', 'vary': 'Accept-Encoding',
                'content-type': 'text/event-stream', 'cache-control': 'no-store'}
        return body, head, {tool['name'] for tool in tools}, payload

    def test_compression_decoded_sse_requires_exact_inventory_and_canonical_json(self):
        body, head, tools, payload = self.compressed_fixture()
        value = compression.decode(body, head, 'gzip', tools)
        self.assertEqual(value['framing'], 'sse')
        canonical = json.dumps(payload['result'], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        self.assertEqual(value['canonical_result_sha256'], hashlib.sha256(canonical).hexdigest())
        with self.assertRaisesRegex(compression.Stop, 'exact_tool_inventory'):
            compression.decode(body, head, 'gzip', (tools - {'fixture.tool_000'}) | {'wrong.tool'})
        with self.assertRaisesRegex(compression.Stop, 'one_rpc_result_required'):
            compression.decode(body + body, head, 'gzip', tools)

    def test_compression_rejects_corrupted_native_decoded_body_and_wrong_encoding(self):
        body, head, tools, _ = self.compressed_fixture()
        with self.assertRaises((compression.Stop, json.JSONDecodeError)):
            compression.decode(b'data: corrupted\n\n', head, 'gzip', tools)
        with self.assertRaisesRegex(compression.Stop, 'selected_codec_required'):
            compression.decode(body, {**head, 'content-encoding': 'br'}, 'gzip', tools)
        with self.assertRaisesRegex(compression.Stop, 'vary_required'):
            compression.decode(body, {**head, 'vary': 'Origin'}, 'gzip', tools)

    def test_compression_requires_sse_media_type(self):
        _, head, tools, payload = self.compressed_fixture()
        with self.assertRaises(compression.Stop):
            compression.decode(json.dumps(payload).encode(), {**head, 'content-type': 'application/json'}, 'gzip', tools)

    def test_compression_requires_no_store_for_negotiated_sse(self):
        body, head, tools, _ = self.compressed_fixture()
        for cache in ('public, max-age=3600', ''):
            with self.subTest(cache=cache), self.assertRaises(compression.Stop):
                compression.decode(body, {**head, 'cache-control': cache}, 'gzip', tools)


if __name__ == '__main__':
    unittest.main()
