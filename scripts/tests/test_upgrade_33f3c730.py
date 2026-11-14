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
             'public_wt_both_families_revisions', 'public_compression_gzip_br_zstd', 'capture_notice_preserved')))
        self.assertEqual(self.c.state()['phase'], 'collectors_active')
        for role, (name, key) in u.ROLES.items():
            actual = tomllib.loads(base64.b64decode(self.cluster.secrets[name]['data'][key]).decode())
            expected = tomllib.loads(config())
            expected['source']['url'] = u.SOURCE_URL
            self.assertEqual(actual, expected)
        checks = ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary',
                  'public_http_both_families_revisions', 'public_wt_both_families_revisions', 'public_compression_gzip_br_zstd',
                  'nine_source_settings_preserved', 'capture_notice_preserved', 'timers_preserved', 'stable_processes')
        self.run_op('finish', self.envelope('target-observation-acceptance', checks,
            duration_seconds=630.5, sample_count=22, maximum_gap_seconds=30.2))
        self.assertEqual(self.c.state()['phase'], 'complete')

    def test_short_observation_cannot_finish(self):
        state = self.c.state()
        state['phase'] = 'collectors_active'
        self.c.record(state)
        checks = ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary',
                  'public_http_both_families_revisions', 'public_wt_both_families_revisions', 'public_compression_gzip_br_zstd',
                  'nine_source_settings_preserved', 'capture_notice_preserved', 'timers_preserved', 'stable_processes')
        receipt = self.envelope('target-observation-acceptance', checks,
            duration_seconds=599.9, sample_count=21, maximum_gap_seconds=30)
        with self.assertRaisesRegex(u.Error, 'observation_interval'):
            self.run_op('finish', receipt)
        self.assertEqual(self.c.state()['phase'], 'collectors_active')


    def test_collector_activation_rejects_missing_or_false_public_compression(self):
        state = self.c.state(); state['phase'] = 'runtime_ready'; self.c.record(state)
        checks = ('schema18', 'policy2', 'sole_writer', 'private_boundary',
                  'public_http_both_families_revisions', 'public_wt_both_families_revisions', 'capture_notice_preserved')
        for flag in (None, False):
            path, sha = self.envelope('target-activation-acceptance', checks)
            if flag is False:
                value = u.load(path); value['checks']['public_compression_gzip_br_zstd'] = False
                sha = private(path, value)
            with self.subTest(flag=flag), self.assertRaisesRegex(u.Error, 'receipt_checks'):
                self.run_op('activate-existing', (path, sha))
        self.assertEqual(self.c.state()['phase'], 'runtime_ready')
        self.assertFalse(any(a[0] == 'patch' for a, _ in self.cluster.calls))

    def test_finish_rejects_missing_or_false_public_compression(self):
        state = self.c.state(); state['phase'] = 'collectors_active'; self.c.record(state)
        checks = ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary',
                  'public_http_both_families_revisions', 'public_wt_both_families_revisions',
                  'nine_source_settings_preserved', 'capture_notice_preserved', 'timers_preserved', 'stable_processes')
        for flag in (None, False):
            path, sha = self.envelope('target-observation-acceptance', checks,
                duration_seconds=630.5, sample_count=22, maximum_gap_seconds=30.2)
            if flag is False:
                value = u.load(path); value['checks']['public_compression_gzip_br_zstd'] = False
                sha = private(path, value)
            with self.subTest(flag=flag), self.assertRaisesRegex(u.Error, 'receipt_checks'):
                self.run_op('finish', (path, sha))
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


def padded_toml(body, size):
    raw = body.encode()
    assert len(raw) + 2 <= size
    return b'#' + b'x' * (size - len(raw) - 2) + b'\n' + raw


def compression_fixture():
    old = {
        '20-proxy.toml': padded_toml('proxy_setting = "fixture"\n[compression]\nenabled = false\n', 1146),
        '62-route-devres.toml': padded_toml('[[routes]]\ncompression = "off"\nendpoint = "fixture"\n', 759)}
    body = '[compression]\n' + ''.join(k + ' = ' + json.dumps(v) + '\n' for k, v in u.CURRENT_COMPRESSION['compression'].items())
    current = {
        '20-proxy.toml': padded_toml('proxy_setting = "fixture"\n', 1116),
        '62-route-devres.toml': padded_toml('[[routes]]\ncompression = "default"\nendpoint = "fixture"\n', 763),
        '40-compression.toml': padded_toml(body, 835)}
    return old, current


def edge_fixture():
    value = {'services': {'oxibelt': {'networks': {'devres-net': {}}}},
             'networks': {'devres-net': {'driver': 'bridge', 'name': 'devres-net'}}, 'fixture_padding': ''}
    prefix = '# fixture\n'
    value['fixture_padding'] = 'x' * (5204 - len((prefix + json.dumps(value, indent=2)).encode()))
    old_raw = (prefix + json.dumps(value, indent=2)).encode()
    current = copy.deepcopy(value)
    current['services']['oxibelt']['networks']['pdf2md-net'] = {}
    current['networks']['pdf2md-net'] = {'driver': 'bridge', 'name': 'pdf2md-net'}
    raw = (prefix + json.dumps(current, indent=2) + '\n').encode()
    edge = {'id': u.OLD_EDGE_ID, 'pid': 101, 'pid_start_ticks': '1001',
            'started': '2026-11-13T12:00:00Z', 'restarts': 0, 'image': u.EDGE_IMAGE}
    docker = {'id': u.OLD_EDGE_ID, 'image': u.EDGE_IMAGE, 'restart_count': 0, 'health': 'healthy',
        'config': {'Hostname': u.OLD_EDGE_ID[:12], 'Env': ['SAFE=fixture'],
            'Labels': {'com.docker.compose.config-hash': u.OLD_COMPOSE_CONFIG,
                       'com.docker.compose.version': '5.7.0'}, 'User': '65532', 'Entrypoint': ['/oxibelt']},
        'host_config': {'Dns': [], 'DnsOptions': [], 'DnsSearch': [], 'Privileged': False,
                       'NetworkMode': 'devres-net', 'ReadonlyRootfs': True},
        'mounts': [{'Source': '/serve/config', 'Destination': '/etc/config', 'RW': False}],
        'ports': {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]},
        'networks': {'devres-net': {'IPAddress': '10.0.0.3', 'IPPrefixLen': 16, 'Gateway': '10.0.0.1',
            'MacAddress': u.OLD_DEVRES_MAC, 'DNSNames': ['oxibelt', u.OLD_EDGE_ID[:12]], 'Aliases': ['oxibelt']}}}
    files = {u.EDGE_COMPOSE: {'uid': 0, 'gid': 0, 'mode': 0o600, 'device': 1, 'inode': 100,
                'kind': 'file', 'size': 5204, 'mtime_ns': 1, 'sha256': u.digest(old_raw)},
             '/serve/oxibelt.toml': {'uid': 0, 'gid': 0, 'mode': 0o600, 'kind': 'file', 'sha256': 'a' * 64}}
    historical = {'edge': edge, 'docker': docker, 'files': files}
    actual = copy.deepcopy(historical)
    actual['edge'] = {'id': u.NEW_EDGE_ID, 'pid': 1898071, 'pid_start_ticks': '12826648',
        'started': '2026-11-14T12:18:56.706543666Z', 'restarts': 0, 'image': u.EDGE_IMAGE}
    after = actual['docker']
    after['id'] = u.NEW_EDGE_ID
    after['config']['Hostname'] = u.NEW_EDGE_ID[:12]
    after['config']['Labels'].update({'com.docker.compose.config-hash': u.NEW_COMPOSE_CONFIG,
                                      'com.docker.compose.version': '5.7.1'})
    for name in ('Dns', 'DnsOptions', 'DnsSearch'):
        after['host_config'][name] = None
    after['networks']['devres-net']['MacAddress'] = u.NEW_DEVRES_MAC
    after['networks']['devres-net']['DNSNames'] = ['oxibelt', u.NEW_EDGE_ID[:12]]
    after['networks']['pdf2md-net'] = copy.deepcopy(u.PDF_NETWORK)
    actual['files'][u.EDGE_COMPOSE].update({'inode': 101, 'mtime_ns': 2, 'size': 5311, 'sha256': u.digest(raw)})
    actual['networks'] = {}
    for name, subnet, gateway, address, mac in (
            ('devres-net', '10.0.0.0/16', '10.0.0.1', '10.0.0.3/16', u.NEW_DEVRES_MAC),
            ('pdf2md-net', '172.19.0.0/16', '172.19.0.1', '172.19.0.2/16', u.PDF_NETWORK['MacAddress'])):
        actual['networks'][name] = {'Name': name, 'Id': u.NETWORK_IDS[name], 'Driver': 'bridge', 'Scope': 'local',
            'EnableIPv6': False, 'Internal': False, 'ConfigOnly': False, 'Ingress': False,
            'IPAM': {'Config': [{'Gateway': gateway, 'Subnet': subnet}], 'Driver': 'default', 'Options': None},
            'Options': {'com.docker.network.bridge.name': 'devres-edge0'} if name == 'devres-net' else {},
            'Labels': {'com.docker.compose.config-hash': u.NETWORK_LABEL_HASHES[name], 'com.docker.compose.network': name,
                       'com.docker.compose.project': 'serve', 'com.docker.compose.version': '5.7.0' if name == 'devres-net' else '5.7.1'},
            'edge_member': {'Name': 'oxibelt', 'MacAddress': mac, 'IPv4Address': address, 'IPv6Address': '', 'EndpointID': u.NETWORK_ENDPOINTS[name]}}
    old_contents, current_contents = compression_fixture()
    historical['conf_tree'] = {'.': {'kind': 'directory', 'inode': 10, 'mtime_ns': 1}}
    for name, rule in u.CONF_FILE_RULES.items():
        historical['conf_tree'][name] = {'uid': 0, 'gid': 0, 'mode': 0o644, 'device': 2305,
            'inode': rule['inode'], 'kind': 'file', 'size': rule['old_size'],
            'sha256': u.digest(old_contents[name]) if name in old_contents else rule['old_sha'],
            'mtime_ns': rule.get('old_mtime', 1)}
    historical['conf_tree']['63-route-wikimedia-cidrs.toml'] = {'kind': 'file', 'sha256': 'f' * 64}
    historical['conf_preimages'] = {name: base64.b64encode(body).decode() for name, body in old_contents.items()}
    actual['conf_tree'] = copy.deepcopy(historical['conf_tree'])
    for name, rule in u.CONF_FILE_RULES.items():
        actual['conf_tree'][name].update(size=rule['new_size'], mtime_ns=rule['new_mtime'],
            sha256=u.digest(current_contents[name]) if name in current_contents else rule['new_sha'])
    actual['conf_contents'] = {name: base64.b64encode(body).decode() for name, body in current_contents.items()}
    return historical, actual, old_raw, raw


class EdgeAdmissionTests(Fixture):
    def setUp(self):
        super().setUp()
        self.historical, self.actual, self.old_raw, self.raw = edge_fixture()
        for name, value in (('OLD_COMPOSE_SHA', u.digest(self.old_raw)), ('NEW_COMPOSE_SHA', u.digest(self.raw)), ('WORK', str(self.top))):
            p = patch.object(u, name, value); p.start(); self.addCleanup(p.stop)
        rules = copy.deepcopy(u.CONF_FILE_RULES)
        for name, rule in rules.items():
            rule['old_sha'] = self.historical['conf_tree'][name]['sha256']
            rule['new_sha'] = self.actual['conf_tree'][name]['sha256']
        rule_patch = patch.object(u, 'CONF_FILE_RULES', rules)
        rule_patch.start(); self.addCleanup(rule_patch.stop)
        def preimage(path, size, sha):
            body = base64.b64decode(self.historical['conf_preimages'][Path(path).name])
            u.require(len(body) == size and u.digest(body) == sha, 'fixture_preimage_mismatch')
            return body
        read_patch = patch.object(u, 'public_config_read', side_effect=preimage)
        read_patch.start(); self.addCleanup(read_patch.stop)
        self.c.root = self.top / 'not-yet-prepared'
        prior_state = u.load(self.prior / 'state.json')
        prior_state['edge'] = self.historical['edge']
        prior_state['new_conf'] = {'63-route-wikimedia-cidrs.toml': self.historical['conf_tree']['63-route-wikimedia-cidrs.toml']}
        prepared = u.load(self.prior / 'prepared.json')
        prepared['edge_docker'] = self.historical['docker']
        prepared['edge_base_files'] = self.historical['files']
        prepared['edge_conf_tree'] = {k: v for k, v in self.historical['conf_tree'].items() if k not in prior_state['new_conf']}
        prior_state['prepared_sha256'] = private(self.prior / 'prepared.json', prepared)
        private(self.prior / 'state.json', prior_state)
        self.c.activation.edge_files = lambda: copy.deepcopy(self.actual['files'])
        self.c.activation.conf_tree = lambda: copy.deepcopy(self.actual['conf_tree'])
        self.c.native_edge_snapshot = lambda: (copy.deepcopy(self.actual), self.raw)
        self.c.edge = lambda: copy.deepcopy(self.actual['edge'])
        self.c.module.call = Mock(return_value=b'native check passed')
        self.value = {'version': 1, 'kind': 'explicit-pdf2md-compression-edge-admission', 'revision': u.REVISION,
            'controller_sha256': u.digest(Path(u.__file__).read_bytes()),
            'predecessor_controller_sha256': u.PRIOR_CONTROLLER_SHA,
            'predecessor_state_sha256': u.digest(u.read(self.prior / 'state.json')),
            'predecessor_prepared_sha256': u.digest(u.read(self.prior / 'prepared.json')),
            'historical_state': prior_state, 'historical': self.historical, 'actual': copy.deepcopy(self.actual),
            'boot': self.c.boot(), 'verified': True, 'observed_at': u.stamp(),
            'native_check': {'verified': True, 'container': u.NEW_EDGE_ID, 'stdout_sha256': 'b' * 64}}

    def test_exact_network_change_normalizes_only_allowed_fields(self):
        normalized = u.normalized_edge_delta(self.historical, self.actual, self.raw)
        self.assertEqual(normalized, {k: v for k, v in self.historical.items() if k != 'conf_preimages'})
        self.assertIn('pdf2md-net', self.actual['docker']['networks'])
        self.assertEqual(self.actual['edge']['id'], u.NEW_EDGE_ID)

    def test_unlisted_docker_security_and_credentials_changes_are_rejected(self):
        changes = [lambda a: a['docker']['config']['Env'].append('AWS_SECRET_ACCESS_KEY=fixture'),
                   lambda a: a['docker']['host_config'].__setitem__('Privileged', True),
                   lambda a: a['docker']['mounts'][0].__setitem__('RW', True),
                   lambda a: a['docker']['ports'].__setitem__('5432/tcp', []),
                   lambda a: a['docker']['networks']['devres-net'].__setitem__('IPAddress', '10.0.0.9'),
                   lambda a: a['docker'].__setitem__('image', 'unadmitted-image')]
        for change in changes:
            current = copy.deepcopy(self.actual); change(current)
            with self.subTest(change=change), self.assertRaises(u.Error):
                u.normalized_edge_delta(self.historical, current, self.raw)

    def test_both_old_and_current_compose_labels_are_exact(self):
        for side in ('old', 'current'):
            old, current = copy.deepcopy(self.historical), copy.deepcopy(self.actual)
            selected = old if side == 'old' else current
            selected['docker']['config']['Labels']['com.docker.compose.config-hash'] = 'c' * 64
            with self.assertRaisesRegex(u.Error, 'compose_runtime_label_delta'):
                u.normalized_edge_delta(old, current, self.raw)

    def test_nonapproved_network_id_subnet_or_endpoint_is_rejected(self):
        changes = [lambda a: a['networks']['pdf2md-net'].__setitem__('Id', 'c' * 64),
                   lambda a: a['networks']['pdf2md-net']['IPAM']['Config'][0].__setitem__('Subnet', '0.0.0.0/0'),
                   lambda a: a['networks']['devres-net']['edge_member'].__setitem__('MacAddress', '02:00:00:00:00:01'),
                   lambda a: a['docker']['networks'].__setitem__('extra-network', {}),
                   lambda a: a['networks']['pdf2md-net']['Options'].__setitem__('com.docker.network.bridge.enable_icc', 'true'),
                   lambda a: a['networks']['devres-net']['edge_member'].__setitem__('EndpointID', 'e' * 64)]
        for change in changes:
            current = copy.deepcopy(self.actual); change(current)
            with self.subTest(change=change), self.assertRaises(u.Error):
                u.normalized_edge_delta(self.historical, current, self.raw)

    def test_reconstructed_historical_compose_must_match_exact_bytes(self):
        changed = self.raw.replace(b'fixture_padding', b'different_field')
        with self.assertRaises(u.Error):
            u.normalized_edge_delta(self.historical, self.actual, changed)
        with patch.object(u, 'OLD_COMPOSE_SHA', 'f' * 64):
            with self.assertRaisesRegex(u.Error, 'historical_compose_reconstruction'):
                u.normalized_edge_delta(self.historical, self.actual, self.raw)

    def test_changed_base_file_permissions_are_not_normalized(self):
        self.actual['files'][u.EDGE_COMPOSE]['mode'] = 0o666
        with self.assertRaisesRegex(u.Error, 'compose_file_security_changed'):
            u.normalized_edge_delta(self.historical, self.actual, self.raw)

    def test_adapters_preserve_actual_controller_snapshots(self):
        self.c.attach_edge_admission(None, self.value)
        self.assertEqual(self.c.activation.edge_files(), self.historical['files'])
        self.assertEqual(self.c.activation.edge_docker(), self.historical['docker'])
        self.assertEqual(self.c.activation.conf_tree(), self.historical['conf_tree'])
        self.assertEqual(self.c.base.edge(), self.historical['edge'])
        self.assertEqual(self.c.edge(), self.actual['edge'])
        self.assertEqual(self.c.snapshot()['edge'], self.actual['edge'])
        self.assertEqual(self.c.snapshot()['edge_conf_tree'], self.actual['conf_tree'])

    def test_every_adapter_refuses_second_runtime_drift(self):
        self.c.attach_edge_admission(None, self.value)
        self.actual['docker']['config']['Env'].append('UNADMITTED=true')
        for adapter in (self.c.activation.edge_files, self.c.activation.edge_docker, self.c.activation.conf_tree, self.c.base.edge):
            with self.assertRaisesRegex(u.Error, 'admitted_current_edge_changed'):
                adapter()

    def test_different_controller_or_predecessor_cannot_use_receipt(self):
        for field in ('controller_sha256', 'predecessor_prepared_sha256', 'predecessor_controller_sha256'):
            value = copy.deepcopy(self.value); value[field] = 'e' * 64
            with self.subTest(field=field), self.assertRaisesRegex(u.Error, 'edge_admission_identity'):
                self.c.attach_edge_admission(None, value)

    def test_admission_artifact_is_rehashed_before_each_adapter(self):
        path = self.top / 'admission.json'
        reference = {'path': str(path), 'sha256': private(path, self.value)}
        self.c.attach_edge_admission(reference)
        private(path, {'tampered': True})
        with self.assertRaisesRegex(u.Error, 'edge_admission_changed'):
            self.c.base.edge()

    def test_old_admission_is_rejected_for_capture_and_prepare(self):
        value = copy.deepcopy(self.value)
        value['observed_at'] = (u.utc_now() - dt.timedelta(seconds=301)).isoformat()
        self.c.attach_edge_admission(None, value)
        with self.assertRaisesRegex(u.Error, 'edge_admission_stale'):
            self.c.edge_admission_fresh(value)


    def test_exact_compression_policy_and_tls_mtime_are_narrowly_normalized(self):
        result = u.normalized_conf_delta(self.historical, self.actual)
        self.assertEqual(result, self.historical['conf_tree'])
        self.assertEqual(tomllib.loads(base64.b64decode(self.actual['conf_contents']['40-compression.toml']).decode()), u.CURRENT_COMPRESSION)
        self.assertEqual(self.historical['conf_tree']['10-tls.toml']['sha256'], self.actual['conf_tree']['10-tls.toml']['sha256'])

    def test_unlisted_conf_tree_node_or_metadata_is_rejected(self):
        for mutate in (lambda t: t.__setitem__('new-private-route.toml', {}),
                       lambda t: t.pop('63-route-wikimedia-cidrs.toml'),
                       lambda t: t['.'].__setitem__('mtime_ns', 99),
                       lambda t: t['20-proxy.toml'].__setitem__('mode', 0o666),
                       lambda t: t['10-tls.toml'].__setitem__('sha256', '1' * 64)):
            actual = copy.deepcopy(self.actual); mutate(actual['conf_tree'])
            with self.subTest(mutate=mutate), self.assertRaises(u.Error):
                u.normalized_conf_delta(self.historical, actual)

    def test_admitted_metadata_cannot_hide_other_proxy_or_route_semantics(self):
        for name, body, code in (
                ('20-proxy.toml', 'proxy_setting = "changed"\n', 'unlisted_proxy_semantic_delta'),
                ('62-route-devres.toml', '[[routes]]\ncompression = "default"\nendpoint = "untrusted"\n', 'unlisted_route_semantic_delta')):
            actual = copy.deepcopy(self.actual)
            raw = padded_toml(body, u.CONF_FILE_RULES[name]['new_size'])
            rules = copy.deepcopy(u.CONF_FILE_RULES); rules[name]['new_sha'] = u.digest(raw)
            actual['conf_tree'][name]['sha256'] = u.digest(raw)
            actual['conf_contents'][name] = base64.b64encode(raw).decode()
            with patch.object(u, 'CONF_FILE_RULES', rules), self.assertRaisesRegex(u.Error, code):
                u.normalized_conf_delta(self.historical, actual)

    def test_global_compression_requires_complete_exact_approved_policy(self):
        for change in (lambda c: c['compression'].__setitem__('deflate', True),
                       lambda c: c['compression'].__setitem__('vary', False),
                       lambda c: c['compression'].__setitem__('mime_types', ['*/*'])):
            policy = copy.deepcopy(u.CURRENT_COMPRESSION); change(policy)
            body = '[compression]\n' + ''.join(k + ' = ' + json.dumps(v) + '\n' for k, v in policy['compression'].items())
            raw = padded_toml(body, 835)
            actual = copy.deepcopy(self.actual)
            actual['conf_tree']['40-compression.toml']['sha256'] = u.digest(raw)
            actual['conf_contents']['40-compression.toml'] = base64.b64encode(raw).decode()
            rules = copy.deepcopy(u.CONF_FILE_RULES); rules['40-compression.toml']['new_sha'] = u.digest(raw)
            with patch.object(u, 'CONF_FILE_RULES', rules), self.assertRaisesRegex(u.Error, 'current_compression_policy_changed'):
                u.normalized_conf_delta(self.historical, actual)

    def test_conf_adapter_detects_post_admission_current_tree_drift(self):
        self.c.attach_edge_admission(None, self.value)
        self.actual['conf_tree']['40-compression.toml']['mtime_ns'] += 1
        with self.assertRaisesRegex(u.Error, 'admitted_current_edge_changed'):
            self.c.activation.conf_tree()

    def test_admission_generator_checks_native_config_once_and_preserves_history(self):
        before = {p.name: p.read_bytes() for p in self.prior.iterdir()}
        path = self.top / 'current-edge-admission.json'
        self.c.admit_edge(path)
        value = u.load(path)
        self.assertEqual(value['actual']['edge'], self.actual['edge'])
        self.c.module.call.assert_called_once_with(['docker', 'exec', u.NEW_EDGE_ID, '/usr/local/bin/oxibelt',
            '--config', '/etc/oxibelt/config/oxibelt.toml', '--check'], timeout=45)
        self.c.activation.guard.assert_called_once()
        self.assertEqual({p.name: p.read_bytes() for p in self.prior.iterdir()}, before)
        with self.assertRaises(FileExistsError):
            self.c.admit_edge(path)
        self.c.module.call.assert_called_once()


if __name__ == '__main__':
    unittest.main()
