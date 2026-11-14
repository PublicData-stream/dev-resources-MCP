"""Production successor safety behavior without cluster or provider traffic."""
import base64
import contextlib
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('upgrade_33f3c730', ROOT / 'deploy/production/upgrade_33f3c730.py')
u = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(u)


def config():
    return ('[source]\nurl = "https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.65236494/source.tar.gz"\n'
            + ''.join(f'[{name}]\nenabled = true\n' for name in u.PROVIDERS)
            + 'user_agent = "unchanged-bot/65236494"\noauth2_token_file = "/run/private/token"\n'
            + '[storage]\ndatabase_url = "postgres://fixture:private-fixture@postgres/devres"\n')


def private(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = value if isinstance(value, bytes) else u.encoded(value)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    path.chmod(0o600)
    return u.digest(raw)


class FakeCluster:
    def __init__(self, bundle):
        self.bundle = bundle
        self.calls = []
        self.serial = 1
        self.fail_after_patch = False
        self.fail_rollout = False
        self.deployments = {}
        self.secrets = {}
        self.live_pods = {}
        self.settings = lambda: {'node_name': 'node'}
        for role in ('postgres', 'writer', 'backend'):
            image = u.PG_IMAGE if role == 'postgres' else u.OLD_IMAGE
            self.deployments[role] = {'metadata': {'uid': role + '-deployment', 'resourceVersion': '1'},
                'spec': {'replicas': 1, 'template': {'spec': {'containers': [{'name': role, 'image': image}],
                    'nodeName': 'node', 'securityContext': {'runAsNonRoot': True}}}}}
            self.new_pod(role)
        for role, (name, key) in u.ROLES.items():
            self.secrets[name] = {'metadata': {'name': name, 'uid': name, 'resourceVersion': '1'},
                'type': 'Opaque', 'data': {key: base64.b64encode(config().encode()).decode()}}
        self.secrets['wikipedia-private'] = {'metadata': {'name': 'wikipedia-private', 'uid': 'token', 'resourceVersion': '1'},
            'type': 'Opaque', 'data': {'token': base64.b64encode(b'fixture-only').decode()}}
        self.runtime_secrets = lambda: list(self.secrets)

    def new_pod(self, role):
        self.serial += 1
        image = self.deployments[role]['spec']['template']['spec']['containers'][0]['image']
        self.live_pods[role] = {'metadata': {'name': f'{role}-{self.serial}', 'uid': f'{role}-{self.serial}',
            'labels': {'app': role}, 'ownerReferences': [{'kind': 'ReplicaSet', 'uid': role + '-rs'}]},
            'spec': {'nodeName': 'node', 'containers': [{'name': role, 'image': image}]},
            'status': {'phase': 'Running', 'podIP': f'10.0.0.{self.serial}', 'containerStatuses': [
                {'ready': True, 'containerID': f'container://{role}-{self.serial}', 'imageID': image,
                 'state': {'running': {'startedAt': f'2026-11-14T12:00:{self.serial:02d}Z'}}, 'restartCount': 0}]}}

    def k(self, *args, data=None, **kwargs):
        self.calls.append((args, data))
        if args[0] == 'get':
            kind = args[1]
            if kind == 'pods':
                return json.dumps({'items': list(self.live_pods.values())}).encode()
            if kind == 'secrets':
                return json.dumps({'items': list(self.secrets.values())}).encode()
            if kind in ('deployment', 'secret'):
                values = self.deployments if kind == 'deployment' else self.secrets
                return json.dumps(values[args[2]]).encode()
        if args[0] == 'patch':
            kind, name = args[1:3]
            value = self.deployments[name] if kind == 'deployment' else self.secrets[name]
            changes = json.loads(data if data is not None else args[args.index('-p') + 1])
            for change in changes:
                keys = change['path'].strip('/').split('/')
                target = value
                for key in keys[:-1]:
                    target = target[int(key)] if isinstance(target, list) else target[key]
                key = int(keys[-1]) if isinstance(target, list) else keys[-1]
                if change['op'] == 'test':
                    if target[key] != change['value']:
                        raise RuntimeError('json_patch_test_failed')
                else:
                    target[key] = change['value']
            value['metadata']['resourceVersion'] = str(int(value['metadata']['resourceVersion']) + 1)
            if kind == 'deployment':
                self.live_pods.pop(name, None)
                if value['spec']['replicas']:
                    self.new_pod(name)
            if self.fail_after_patch:
                self.fail_after_patch = False
                raise RuntimeError('lost_response_after_patch')
            return b'{}'
        if args[0] == 'rollout' and self.fail_rollout:
            raise RuntimeError('target_start_failed')
        if args[0] in ('rollout', 'wait'):
            return b''
        raise AssertionError(args)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.sync = patch.object(u.os, 'fsync')
        self.sync_mock = self.sync.start()
        self.addCleanup(self.sync.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='upgrade33-fixture-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.top = Path(self.temp.name)
        self.root = self.top / 'upgrade'
        self.root.mkdir(mode=0o700)
        self.prior = self.top / 'activation'
        self.prior.mkdir(mode=0o700)
        self.original = self.top / 'original'
        self.original.mkdir(mode=0o700)
        self.c = u.Controller.__new__(u.Controller)
        self.c.root, self.c.prior, self.c.context = self.root, self.prior, 'default'
        self.c.plan_raw = b'fixture-plan'
        self.cluster = FakeCluster(self.original)
        self.c.old = self.cluster
        self.c.module = SimpleNamespace(read_json=lambda p: json.loads(Path(p).read_bytes()),
            bundle_lock=lambda *a: contextlib.nullcontext(), safe_directory=lambda *a, **k: None)
        self.c.base = SimpleNamespace(safety=Mock())
        self.c.boot = lambda: {'boot': 'same'}
        self.c.edge = lambda: {'edge': 'same'}
        self.c.foundation = lambda: [{'policy': 'same'}]
        self.c.profiles = lambda: {'tls-profile': b'unchanged'}
        self.prior_source = self.top / 'prior-controller.py'
        private(self.prior_source, b'fixture-controller')
        self.patch_path = patch.object(u, 'PRIOR_CONTROLLER', str(self.prior_source))
        self.patch_sha = patch.object(u, 'PRIOR_CONTROLLER_SHA', u.digest(b'fixture-controller'))
        self.patch_path.start(); self.patch_sha.start()
        self.addCleanup(self.patch_path.stop); self.addCleanup(self.patch_sha.stop)
        old_state = {'version': 1, 'kind': 'wikipedia-activation', 'revision': u.PRIOR_REVISION,
            'phase': 'enabled', 'configs': 'enabled', 'edge_phase': 'published', 'base_link_phase': 'wikipedia_enabled',
            'source_sha256': u.PRIOR_CONTROLLER_SHA, 'source_history': None,
            'replicas': {'postgres': 1, 'writer': 1, 'backend': 1}, 'pods': self.c.pods()}
        active = {r: config() for r in u.ROLES}
        private(self.prior / 'configs-enabled.json', active)
        ap = {'revision': u.PRIOR_REVISION, 'kind': 'wikipedia-activation',
            'enabled_config_sha256': u.digest(u.encoded(active)), 'base_artifacts': {}}
        old_state['prepared_sha256'] = private(self.prior / 'prepared.json', ap)
        private(self.prior / 'state.json', old_state)
        for name in ('route-candidate.toml', 'cidr-candidate.json', 'edge-config-check.json',
                     'cidr-activation-receipt.json', 'cidr-activation-validation.json'):
            private(self.prior / name, b'fixture-evidence')
        self.c.activation = SimpleNamespace(state=lambda: u.load(self.prior / 'state.json'), admit=Mock(),
            artifact_hashes=lambda: {}, cidr_copies=Mock(), edge_guard=Mock(), guard=Mock())
        anchor = {'phase': 'runtime_upgraded', 'edge_admitted': True}
        private(self.original / 'state.json', anchor)
        snapshot = self.c.snapshot()
        variants = {v: {r: u.configuration(config(), v == 'active') for r in u.ROLES} for v in ('paused', 'active')}
        for name, value in variants.items():
            private(self.root / ('configs-' + name + '.json'), value)
        prepared = {'version': 1, 'revision': u.REVISION, 'at': (u.utc_now() - dt.timedelta(seconds=20)).isoformat(),
            'deployments': {n: {'projection': v['projection'], 'manifest': self.cluster.deployments[n]}
                            for n, v in snapshot['deployments'].items()},
            'secrets': snapshot['secrets'], 'edge': snapshot['edge'], 'boot': snapshot['boot'],
            'foundation': snapshot['foundation'], 'profiles': snapshot['profiles'],
            'old_anchor': anchor, 'old_pods': snapshot['pods'], 'store_binding_sha256': u.STORE_BINDING,
            'prior_artifacts': self.c.prior_artifacts(), 'prior_state': old_state,
            'config_hashes': {n: u.digest(u.encoded(v)) for n, v in variants.items()}}
        state = {'version': 1, 'revision': u.REVISION, 'phase': 'prepared', 'chain_phase': None,
            'plan_sha256': u.digest(self.c.plan_raw), 'source_sha256': u.digest(Path(u.__file__).read_bytes()),
            'prepared_sha256': private(self.root / 'prepared.json', prepared),
            'images': {n: v['image'] for n, v in snapshot['deployments'].items()},
            'replicas': {'postgres': 1, 'writer': 1, 'backend': 1}, 'configs': 'old', 'pods': snapshot['pods']}
        private(self.root / 'state.json', state)
        self.c.guard()

    def approval(self, operation):
        state = self.c.state()
        p = self.top / (operation + '-approval.json')
        sha = private(p, {'version': 1, 'operation': operation, 'reviewed': True,
            'source_sha256': state['source_sha256'], 'prepared_sha256': state['prepared_sha256']})
        return p, sha

    def run_op(self, operation, receipt=None):
        p, sha = self.approval(operation)
        self.c.run(operation, p, sha, *(receipt or (None, None)))

    def envelope(self, kind, checks, **fields):
        evidence = self.top / (kind + '-proof.txt')
        evidence_sha = private(evidence, b'fixture-proof')
        value = {'version': 1, 'revision': u.REVISION, 'kind': kind, 'schema': 18,
            'prepared_sha256': self.c.state()['prepared_sha256'], 'store_binding_sha256': u.STORE_BINDING,
            'verified': True, 'observed_at': u.stamp(), 'checks': dict.fromkeys(checks, True),
            'artifacts': [{'path': str(evidence), 'sha256': evidence_sha}], **fields}
        path = self.top / (kind + '-receipt.json')
        return path, private(path, value)

    def checkpoint(self):
        self.run_op('stop')
        old_pg = self.c.state()['pods']['postgres']
        self.cluster.new_pod('postgres')
        new_pg = self.c.pods()['postgres']
        return self.envelope('coordinated-schema15-backup',
            ('coordinated_pg_s3', 'old_clone_verified', 'roles_stopped', 'pg_restarted_without_restore', 'credentials_preserved'),
            schema=15, recovery_scope='physical_pg_checkpoint_original_immutable_s3_retained', independent_s3_backup=False,
            system_identifier='7706567225121447965', old_pg_pod=old_pg, new_pg_pod=new_pg,
            postgres_deployment_sha256=u.digest(u.encoded(u.load(self.root / 'prepared.json')['deployments']['postgres']['projection'])))

    def apply(self):
        self.run_op('apply', self.checkpoint())


class ConfigurationTests(unittest.TestCase):
    def test_pauses_nine_sources_and_preserves_identity_passwords(self):
        original = tomllib.loads(config())
        actual = tomllib.loads(u.configuration(config(), False))
        expected = copy.deepcopy(original)
        expected['source']['url'] = u.SOURCE_URL
        for name in u.PROVIDERS:
            expected[name]['enabled'] = False
        self.assertEqual(actual, expected)
        self.assertEqual(len(u.PROVIDERS), 9)

    def test_restores_admitted_flags_including_disabled_source(self):
        text = config().replace('[npm]\nenabled = true', '[npm]\nenabled = false')
        actual = tomllib.loads(u.configuration(text, True))
        self.assertFalse(actual['npm']['enabled'])
        self.assertTrue(actual['wikipedia']['enabled'])
        self.assertEqual(actual['wikipedia']['user_agent'], 'unchanged-bot/65236494')

    def test_absent_or_nonboolean_source_switch_is_rejected(self):
        for text in (config().replace('[wikipedia]\nenabled = true', '[wikipedia]'),
                     config().replace('[wikipedia]\nenabled = true', '[wikipedia]\nenabled = "yes"')):
            with self.assertRaises(u.Error):
                u.configuration(text, False)

    def test_source_url_must_be_exact_predecessor(self):
        with self.assertRaisesRegex(u.Error, 'old_source_url'):
            u.configuration(config().replace('65236494/source', 'wrong/source'), False)

    def test_schema18_release_is_exact(self):
        self.assertEqual(u.target_identity()['schema'], 18)
        self.assertEqual(u.target_identity()['revision'], '33f3c730123319625fe3a25713988201eb5d82e0')


class LifecycleTests(Fixture):
    def test_stop_orders_reader_before_writer_and_links_only_activation(self):
        self.run_op('stop')
        patches = [args[2] for args, _ in self.cluster.calls if args[0] == 'patch']
        self.assertEqual(patches, ['backend', 'writer'])
        self.assertEqual(self.c.state()['phase'], 'stopped')
        self.assertEqual(set(self.c.pods()), {'postgres'})
        predecessor = u.load(self.prior / 'state.json')
        self.assertEqual(predecessor['upgrade_successor'], str(self.root))
        self.assertEqual(predecessor['phase'], 'enabled')
        self.assertEqual(u.load(self.original / 'state.json'), {'phase': 'runtime_upgraded', 'edge_admitted': True})

    def test_apply_requires_checkpoint_then_preserves_postgres_and_credentials(self):
        receipt = self.checkpoint()
        old_token = copy.deepcopy(self.cluster.secrets['wikipedia-private'])
        self.run_op('apply', receipt)
        state = self.c.state()
        self.assertEqual(state['phase'], 'applied')
        self.assertEqual(state['configs'], 'paused')
        self.assertEqual(state['images']['writer'], u.IMAGE)
        self.assertEqual(self.cluster.secrets['wikipedia-private'], old_token)
        for role, (name, key) in u.ROLES.items():
            config_text = base64.b64decode(self.cluster.secrets[name]['data'][key]).decode()
            self.assertFalse(any(tomllib.loads(config_text)[n]['enabled'] for n in u.PROVIDERS))
        self.assertEqual([a[2] for a, _ in self.cluster.calls if a[0] == 'patch' and a[1] == 'deployment'],
                         ['backend', 'writer', 'writer', 'backend'])
        secret_calls = [(a, data) for a, data in self.cluster.calls if a[0] == 'patch' and a[1] == 'secret']
        self.assertTrue(all('--patch-file=/dev/stdin' in a and data for a, data in secret_calls))

    def test_unapproved_postgres_process_change_is_refused(self):
        self.cluster.new_pod('postgres')
        with self.assertRaisesRegex(u.Error, 'process_identity_changed'):
            self.c.guard()

    def test_postgres_rebind_requires_stopped_phase(self):
        with self.assertRaisesRegex(u.Error, 'pg_rebind_phase'):
            self.c.guard(pg_rebind=self.c.pods()['postgres'])

    def test_checkpoint_cannot_change_postgres_owner_or_image(self):
        receipt = self.checkpoint()
        path, _ = receipt
        value = u.load(path)
        value['new_pg_pod']['owner'] = [{'uid': 'unadmitted-owner'}]
        receipt = path, private(path, value)
        with self.assertRaisesRegex(u.Error, 'backup_pg_runtime_boundary'):
            self.run_op('apply', receipt)
        self.assertEqual(self.c.state()['images']['writer'], u.OLD_IMAGE)

    def test_checkpoint_cannot_assert_unverified_independent_backup(self):
        path, _ = self.checkpoint()
        value = u.load(path)
        value['independent_s3_backup'] = True
        with self.assertRaisesRegex(u.Error, 'backup_scope'):
            self.run_op('apply', (path, private(path, value)))

    def test_interrupted_patch_is_not_replayed(self):
        self.cluster.fail_after_patch = True
        with self.assertRaisesRegex(RuntimeError, 'lost_response'):
            self.run_op('stop')
        self.assertEqual(self.cluster.deployments['backend']['spec']['replicas'], 0)
        self.assertEqual(self.c.state()['phase'], 'stop_incomplete')
        count = len([a for a, _ in self.cluster.calls if a[0] == 'patch'])
        with self.assertRaisesRegex(u.Error, 'operation_phase'):
            self.run_op('stop')
        self.assertEqual(count, len([a for a, _ in self.cluster.calls if a[0] == 'patch']))

    def test_single_mutation_intent_refuses_second_attempt(self):
        action = Mock(side_effect=RuntimeError('unknown'))
        with self.assertRaises(RuntimeError):
            self.c.mutate('uncertain', action)
        with self.assertRaises(FileExistsError):
            self.c.mutate('uncertain', action)
        action.assert_called_once()

    def test_failing_start_is_preservingly_withdrawn_without_postgres_or_restore(self):
        self.apply()
        self.cluster.fail_rollout = True
        with self.assertRaisesRegex(RuntimeError, 'target_start_failed'):
            self.run_op('start-writer')
        self.run_op('withdraw')
        self.assertEqual(self.c.state()['phase'], 'withdrawn')
        self.assertEqual(set(self.cluster.live_pods), {'postgres'})
        self.assertEqual(self.cluster.deployments['writer']['spec']['template']['spec']['containers'][0]['image'], u.IMAGE)
        self.assertFalse(any(a[0] == 'patch' and a[2] == 'postgres' for a, _ in self.cluster.calls))

    def test_no_old_image_rollback_operation_exists(self):
        self.apply()
        with self.assertRaises((KeyError, u.Error)):
            self.run_op('rollback')
        self.assertEqual(self.c.state()['images']['writer'], u.IMAGE)

    def test_migration18_acceptance_is_required_before_reader(self):
        self.apply(); self.run_op('start-writer')
        receipt = self.envelope('migration18',
            ('schema18', 'policy2', 'sole_writer', 'new_table_reader_grants', 'history_preserved',
             'archive_binding_preserved', 'historical_notices_preserved'))
        self.run_op('start-reader', receipt)
        self.assertEqual(self.c.state()['phase'], 'reader_ready')

    def test_old_schema_receipt_cannot_start_reader(self):
        self.apply(); self.run_op('start-writer')
        receipt = self.envelope('migration18',
            ('schema18', 'policy2', 'sole_writer', 'new_table_reader_grants', 'history_preserved',
             'archive_binding_preserved', 'historical_notices_preserved'), schema=15)
        with self.assertRaisesRegex(u.Error, 'target_schema_receipt'):
            self.run_op('start-reader', receipt)
        self.assertNotIn('backend', self.cluster.live_pods)

    def test_namespace_token_drift_is_rejected(self):
        self.cluster.secrets['wikipedia-private']['data']['token'] = 'changed'
        with self.assertRaisesRegex(u.Error, 'secret_boundary_changed'):
            self.c.guard()

    def test_added_namespace_secret_is_rejected(self):
        self.cluster.secrets['extra'] = {'metadata': {'name': 'extra', 'uid': 'extra'}, 'data': {}}
        with self.assertRaisesRegex(u.Error, 'namespace_secret_set_changed'):
            self.c.guard()

    def test_unrelated_template_drift_is_rejected(self):
        self.cluster.deployments['backend']['spec']['template']['spec']['hostNetwork'] = True
        with self.assertRaisesRegex(u.Error, 'deployment_boundary_changed'):
            self.c.guard()

    def test_predecessor_extra_field_is_rejected(self):
        value = u.load(self.prior / 'state.json'); value['unadmitted'] = True
        private(self.prior / 'state.json', value)
        with self.assertRaisesRegex(u.Error, 'prior_chain_changed'):
            self.c.guard()

    def test_predecessor_proof_drift_is_rejected(self):
        private(self.prior / 'edge-config-check.json', b'changed')
        with self.assertRaisesRegex(u.Error, 'prior_artifact_changed'):
            self.c.guard()

    def test_withdraw_refuses_unrecognized_template(self):
        self.cluster.deployments['writer']['spec']['template']['spec']['hostNetwork'] = True
        with self.assertRaisesRegex(u.Error, 'deployment_boundary_changed'):
            self.run_op('withdraw')
        self.assertEqual(self.cluster.deployments['writer']['spec']['replicas'], 1)

    def test_receipt_staleness_and_artifact_tampering(self):
        path, sha = self.envelope('proof', ('good',))
        v = u.load(path); v['observed_at'] = (u.utc_now() - dt.timedelta(seconds=301)).isoformat()
        with self.assertRaisesRegex(u.Error, 'receipt_stale'):
            self.c.receipt(path, private(path, v), 'proof', ('good',))
        path, sha = self.envelope('proof', ('good',))
        private(self.top / 'proof-proof.txt', b'modified')
        with self.assertRaisesRegex(u.Error, 'artifact_changed'):
            self.c.receipt(path, sha, 'proof', ('good',))

    def test_receipt_freshness_is_rechecked_after_hashing(self):
        path, sha = self.envelope('proof', ('good',))
        recent = u.utc_now()
        with patch.object(u, 'utc_now', side_effect=[recent, recent + dt.timedelta(seconds=301)]):
            with self.assertRaisesRegex(u.Error, 'receipt_stale'):
                self.c.receipt(path, sha, 'proof', ('good',))

    def test_full_paused_and_active_lifecycle_restores_exact_nine_flags(self):
        self.apply(); self.run_op('start-writer')
        self.run_op('start-reader', self.envelope('migration18',
            ('schema18', 'policy2', 'sole_writer', 'new_table_reader_grants', 'history_preserved',
             'archive_binding_preserved', 'historical_notices_preserved')))
        self.run_op('runtime-ready', self.envelope('target-private-acceptance',
            ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary', 'capture_notice_preserved', 'tool_contract98')))
        self.run_op('activate-existing', self.envelope('target-activation-acceptance',
            ('schema18', 'policy2', 'sole_writer', 'private_boundary', 'public_http_both_families_revisions',
             'public_wt_both_families_revisions', 'capture_notice_preserved')))
        self.assertEqual(self.c.state()['phase'], 'collectors_active')
        for role, (name, key) in u.ROLES.items():
            actual = tomllib.loads(base64.b64decode(self.cluster.secrets[name]['data'][key]).decode())
            expected = tomllib.loads(config())
            expected['source']['url'] = u.SOURCE_URL
            self.assertEqual(actual, expected)
        checks = ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary',
                  'public_http_both_families_revisions', 'public_wt_both_families_revisions',
                  'nine_source_settings_preserved', 'capture_notice_preserved', 'timers_preserved', 'stable_processes')
        self.run_op('finish', self.envelope('target-observation-acceptance', checks,
            duration_seconds=630.5, sample_count=22, maximum_gap_seconds=30.2))
        self.assertEqual(self.c.state()['phase'], 'complete')

    def test_short_observation_cannot_finish(self):
        state = self.c.state()
        state['phase'] = 'collectors_active'
        self.c.record(state)
        checks = ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary',
                  'public_http_both_families_revisions', 'public_wt_both_families_revisions',
                  'nine_source_settings_preserved', 'capture_notice_preserved', 'timers_preserved', 'stable_processes')
        receipt = self.envelope('target-observation-acceptance', checks,
            duration_seconds=599.9, sample_count=21, maximum_gap_seconds=30)
        with self.assertRaisesRegex(u.Error, 'observation_interval'):
            self.run_op('finish', receipt)
        self.assertEqual(self.c.state()['phase'], 'collectors_active')

    def test_mutation_durability_barriers_precede_dispatch(self):
        self.sync_mock.reset_mock()
        observed = []
        self.c.mutate('durable', lambda: observed.append(self.sync_mock.call_count))
        self.assertEqual(observed, [3])
        self.assertEqual(self.sync_mock.call_count, 6)
        self.assertTrue((self.root / 'durable-intent.json').exists())
        self.assertTrue((self.root / 'durable-completed.json').exists())


    def test_policy_v2_receipt_can_report_withheld_content(self):
        receipt = self.envelope('proof', ('policy2',), withheld_content_count=123)
        value, _ = self.c.receipt(*receipt, 'proof', ('policy2',))
        self.assertEqual(value['withheld_content_count'], 123)


if __name__ == '__main__':
    unittest.main()
