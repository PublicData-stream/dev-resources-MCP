"""Production lifecycle safety checks without a cluster or public provider traffic."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('production_operator', ROOT / 'scripts/production-operator.py')
operator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(operator)


def receipt(fixture=False):
    now = datetime.now(timezone.utc)
    apps = ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222')
    return {'fixture': fixture, 'ttl_secs': 900, 'broker_key_budget': 40,
            'issuer_access_key': 'test-issuer', 'issuer_application_id': '33333333-3333-4333-8333-333333333333',
            'profile_fingerprints': {app: 'a' * 64 for app in apps}, 'confined_application_ids': list(apps),
            'issuer_secret_fingerprint': 'b' * 64, 'unrelated_application_denied': True,
            'policy_management_denied': True, 'expiry_accepted': True,
            'verified_at': (now - timedelta(minutes=1)).isoformat(), 'expires_at': (now + timedelta(hours=1)).isoformat()}


class FakeOperator(operator.Operator):
    def __init__(self, bundle):
        super().__init__('production-test', bundle)
        self.events = []
        self.current = {name: {'desired': 0, 'ready': 0} for name in operator.WORKLOADS}
        self.fail_scale = set()

    def validate_cluster(self, bind=False):
        self.validate_identity()

    def validate_runtime_state(self):
        pass

    def status(self):
        return self.current

    def k(self, *args, data=None, timeout=180):
        self.events.append(('k', args, json.loads(data) if data else None))
        return b'{}'

    def scale(self, name, count):
        self.events.append(('scale', name, count))
        if (name, count) in self.fail_scale:
            raise operator.OperatorError('simulated_rollout_failure')
        self.current[name] = {'desired': count, 'ready': count}

    def prepare_local_volumes(self):
        self.events.append(('local-volumes',))

    def install_firewall(self):
        self.events.append(('firewall',))


class ProductionOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / 'bundle'
        self.settings = {'node_name': 'publicdatamcp-b130e', 'node_ipv4': '62.210.240.40',
                         'kube_api_cidrs': ['10.43.0.1/32', '62.210.240.40/32'],
                         'iam_cidrs': ['51.159.0.1/32']}
        previous = os.umask(0o077)
        try:
            operator.renderer().render(self.bundle, self.settings)
        finally:
            os.umask(previous)
        passwords, manifests = operator.postgres_inputs()
        self.write('database-passwords.json', json.dumps(passwords))
        for manifest in manifests:
            self.write(manifest['metadata']['name'] + '.json', json.dumps(manifest))
        settings_text = json.dumps(self.settings, sort_keys=True)
        self.write('settings.json', settings_text)
        self.write('state.json', json.dumps({'version': 1, 'revision': operator.REVISION, 'phase': 'prepared',
                   'settings_sha256': hashlib.sha256(settings_text.encode()).hexdigest()}))
        self.write('broker-keyring.json', json.dumps({'active_key_id': 'test', 'keys': {'test': 'c' * 64}}))
        for name in ('backend.crt', 'backend.key', 'edge-client-ca.crt', 'writer.crt', 'writer.key',
                     'coordination-ca.crt', 'credential-broker.crt', 'credential-broker.key'):
            operator.private_write(self.bundle / 'tls' / name, 'test-only-certificate-data')
        self.op = FakeOperator(self.bundle)

    def write(self, name, value):
        operator.private_replace(self.bundle / name, value)

    def private_inputs(self, fixture=False):
        accepted = receipt(fixture)
        self.write('real-receipt.json', json.dumps(accepted))
        self.write('issuer-key', 'test-only-synthetic-secret')
        values = {'organization_id': '55555555-5555-4555-8555-555555555555',
                  'project_id': '44444444-4444-4444-8444-444444444444',
                  'issuer_access_key': accepted['issuer_access_key'],
                  'issuer_application_id': accepted['issuer_application_id'],
                  'reader_application_id': accepted['confined_application_ids'][0],
                  'writer_application_id': accepted['confined_application_ids'][1],
                  'reader_policy_sha256': 'd' * 64, 'writer_policy_sha256': 'e' * 64,
                  'acceptance_receipt_file': str(self.bundle / 'real-receipt.json'),
                  'issuer_secret_file': str(self.bundle / 'issuer-key')}
        self.write('inputs.json', json.dumps(values))
        return self.bundle / 'inputs.json'

    def test_initial_install_orders_firewall_and_denies_before_nodeports(self):
        with patch.object(operator, 'call', return_value=b'Encryption Status: Enabled\nServer Encryption Hashes: All hashes match\n'):
            self.op.install()
        firewall = self.op.events.index(('firewall',))
        applies = [(i, event[2]) for i, event in enumerate(self.op.events)
                   if event[0] == 'k' and event[1][0] == 'apply']
        self.assertGreater(applies[0][0], firewall)
        self.assertEqual({item['kind'] for item in applies[0][1]['items']}, {'Namespace', 'NetworkPolicy'})
        nodeport_apply = next(i for i, manifest in applies if any(item.get('spec', {}).get('type') == 'NodePort'
                                for item in manifest.get('items', [])))
        self.assertGreater(nodeport_apply, applies[0][0])
        created = [event[2]['metadata']['name'] for event in self.op.events
                   if event[0] == 'k' and event[2] and event[2].get('kind') == 'Secret']
        self.assertEqual(created, ['devres-corpus-postgres', 'devres-broker-postgres'])

    def test_install_refuses_changed_or_live_runtime_before_writes(self):
        self.op.current['writer']['desired'] = 1
        with self.assertRaises(operator.OperatorError):
            self.op.install()
        self.assertEqual(self.op.events, [])
        self.op.current['writer']['desired'] = 0
        manifest = json.loads(operator.private_read(self.bundle / 'kubernetes.json'))
        next(item for item in manifest['items'] if item['kind'] == 'Deployment')['spec']['replicas'] = 1
        self.write('kubernetes.json', json.dumps(manifest))
        with self.assertRaises(operator.OperatorError):
            self.op.install()
        self.assertEqual(self.op.events, [])

    def test_runtime_receipt_gate_and_canonical_binding_precede_all_secret_writes(self):
        with self.assertRaises(operator.OperatorError):
            self.op.provision_runtime(self.private_inputs(fixture=True))
        self.assertEqual(self.op.events, [])
        inputs = self.private_inputs()
        with patch.object(operator, 'verify_broker_fingerprints', side_effect=operator.OperatorError('mismatch')):
            with self.assertRaises(operator.OperatorError):
                self.op.provision_runtime(inputs)
        self.assertEqual(self.op.events, [])
        with patch.object(operator, 'verify_broker_fingerprints') as verify:
            self.op.provision_runtime(inputs)
            verify.assert_called_once()
        self.assertEqual(len(self.op.events), 7)
        broker = tomllib.loads(operator.private_read(self.bundle / 'credential-broker.toml').decode())
        self.assertEqual(broker['organization_id'], '55555555-5555-4555-8555-555555555555')
        self.assertFalse(broker['fixture_mode'])
        for name in ('serving', 'writer'):
            config = tomllib.loads(operator.private_read(self.bundle / (name + '.toml')).decode())
            self.assertTrue(all(not config[provider]['enabled'] for provider in operator.COLLECTORS))

    def test_partial_start_failure_attempts_both_stops_and_preserves_databases(self):
        self.op.record(phase='runtime_provisioned')
        self.write('acceptance-receipt.json', json.dumps(receipt()))
        for role in ('serving', 'writer'):
            self.write(role + '.toml', operator.renderer().runtime_config(role == 'writer'))
        self.op.fail_scale.add(('backend', 1))
        with patch.object(operator.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(1000, 0, operator.MIN_FREE + 1)):
            with self.assertRaises(operator.OperatorError):
                self.op.admit_start()
        self.assertIn(('scale', 'backend', 0), self.op.events)
        self.assertIn(('scale', 'writer', 0), self.op.events)
        for name in ('postgres', 'broker-postgres'):
            self.assertEqual(self.op.current[name]['desired'], 1)
        self.assertFalse(any(event[0] == 'k' and 'delete' in event[1] for event in self.op.events))

    def test_stop_attempts_writer_even_when_reader_stop_fails(self):
        self.op.fail_scale.add(('backend', 0))
        with self.assertRaises(operator.OperatorError):
            self.op.stop()
        self.assertIn(('scale', 'writer', 0), self.op.events)
        self.assertEqual(operator.read_json(self.bundle / 'state.json')['phase'], 'stop_incomplete')

    def test_capacity_withdraws_edge_and_roles_without_destroying_storage(self):
        free = shutil._ntuple_diskusage(operator.MIN_FREE * 2, operator.MIN_FREE + 1, operator.MIN_FREE - 1)
        with patch.object(operator.shutil, 'disk_usage', return_value=free), patch.object(operator, 'call', return_value=b'') as call:
            result = self.op.capacity()
        self.assertTrue(result['capacity_fenced'])
        self.assertTrue(any('stop' in invocation.args[0] and 'oxibelt' in invocation.args[0]
                            for invocation in call.call_args_list))
        self.assertEqual([event for event in self.op.events if event[0] == 'scale'],
                         [('scale', 'backend', 0), ('scale', 'writer', 0)])

    def test_activation_changes_only_explicit_switches_and_preserves_npm_budget(self):
        original = operator.renderer().runtime_config(True)
        active = tomllib.loads(operator.collector_config(original, True))
        before = tomllib.loads(original)
        for name in operator.COLLECTORS:
            self.assertTrue(active[name].pop('enabled'))
            before[name].pop('enabled')
        self.assertEqual(active, before)
        self.assertEqual(active['npm']['packages'], [])
        self.assertTrue(active['npm']['advisories_enabled'])

    def test_activation_partial_failure_restores_disabled_configs(self):
        self.op.record(phase='edge_ready')
        self.write('acceptance-receipt.json', json.dumps(receipt()))
        for role in ('serving', 'writer'):
            self.write(role + '.toml', operator.renderer().runtime_config(role == 'writer'))
        source = {'release_revision': operator.REVISION, 'fixture': False,
                  'providers': {name: {'passed': True, 'attempts': 1} for name in operator.COLLECTORS}, 'github_attempts': 1}
        edge = {name: True for name in ('http_2025_11_25', 'http_2026_07_28', 'wt_2025_11_25', 'wt_2026_07_28',
                                      'ipv4', 'ipv6', 'nodeport_denied', 'private_services_denied',
                                      'representative_writer_s3_readback', 'sql_readonly', 's3_readonly',
                                      'boot_guard_failure_denied')}
        edge.update(release_revision=operator.REVISION, fixture=False)
        self.write('source.json', json.dumps(source))
        self.write('edge.json', json.dumps(edge))
        self.op.fail_scale.add(('backend', 1))
        with patch.object(operator.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(1000, 0, operator.MIN_FREE + 1)):
            with self.assertRaises(operator.OperatorError):
                self.op.activate(self.bundle / 'source.json', self.bundle / 'edge.json')
        applied = [event[2] for event in self.op.events if event[0] == 'k' and event[2] and event[2].get('kind') == 'Secret']
        for item in applied[-2:]:
            config = tomllib.loads(base64.b64decode(next(iter(item['data'].values()))).decode())
            self.assertTrue(all(not config[name]['enabled'] for name in operator.COLLECTORS))
        self.assertEqual(operator.read_json(self.bundle / 'state.json')['phase'], 'activation_failed')

    def test_edge_merge_keeps_lego_token_and_rejects_other_live_services(self):
        lego = {'image': 'goacme/lego:latest', 'profiles': ['run-lego'], 'secrets': ['lego_cf_token'], 'networks': {'default': None}}
        existing = {'services': {'lego': lego, 'oxibelt': {'image': 'old'}},
                    'secrets': {'lego_cf_token': {'file': '/serve/lego/lego_cf_token'}},
                    'networks': {'default': {'name': 'serve_default'}, 'openlegal4everyone-net': {}}}
        desired = operator.renderer().edge_compose({})
        merged = operator.merge_edge_compose(existing, desired)
        self.assertEqual(merged['services']['lego'], {**lego, 'image': operator.renderer().LEGO})
        self.assertEqual(merged['secrets'], existing['secrets'])
        self.assertEqual(set(merged['networks']), {'devres-net', 'default'})
        existing['services']['unrelated'] = {}
        with self.assertRaises(operator.OperatorError):
            operator.merge_edge_compose(existing, desired)

    def test_api_defaulted_runtime_accepts_writable_mounts_and_rejects_image_or_privilege_changes(self):
        manifest = operator.read_json(self.bundle / 'kubernetes.json')
        live = {'items': [item for item in manifest['items'] if item['kind'] == 'Deployment']}
        for item in live['items']:
            for mount in item['spec']['template']['spec']['containers'][0]['volumeMounts']:
                if not mount.get('readOnly'):
                    mount.pop('readOnly', None)
        secrets = {name: operator.secret_manifest(name, {'test': 'value'}) for name in operator.RUNTIME_SECRETS}
        for name, value in secrets.items():
            self.write(name + '.json', json.dumps(value))

        def get(*args, **kwargs):
            return json.dumps(live if args[1] == 'deployments' else secrets[args[2]]).encode()

        with patch.object(self.op, 'k', side_effect=get):
            operator.Operator.validate_runtime_state(self.op)
            container = live['items'][0]['spec']['template']['spec']['containers'][0]
            original = container['image']
            container['image'] = 'unrelated:latest'
            with self.assertRaises(operator.OperatorError):
                operator.Operator.validate_runtime_state(self.op)
            container['image'] = original
            live['items'][0]['spec']['template']['spec']['hostNetwork'] = True
            with self.assertRaises(operator.OperatorError):
                operator.Operator.validate_runtime_state(self.op)

    def renewal_fixture(self):
        edge = self.root / 'serve'
        certs = edge / 'lego/data/certificates'
        certs.mkdir(parents=True)
        (edge / 'lego/.lego.yaml').write_text('test-only-retained-lego-configuration\n')
        (certs / 'publicdata-stream.crt').write_bytes(b'test-only-original-certificate')
        compose = {'services': {'lego': {'image': operator.renderer().LEGO, 'user': '10001:10001',
                    'command': ['--config', '/.lego.yaml'],
                    'volumes': [{'source': str(edge / 'lego/.lego.yaml'), 'target': '/.lego.yaml', 'read_only': True},
                                {'source': str(edge / 'lego/data'), 'target': '/var/lib/lego'}],
                    'secrets': [{'source': 'lego_cf_token'}]}},
                   'secrets': {'lego_cf_token': {'file': str(edge / 'lego/lego_cf_token')}}}
        with patch.object(operator, 'EDGE', edge):
            self.write('lego-renewal.json', json.dumps({'revision': operator.REVISION,
                       'image': operator.renderer().LEGO,
                       'lego_service_sha256': operator.lego_service_identity(compose),
                       'config_sha256': hashlib.sha256((edge / 'lego/.lego.yaml').read_bytes()).hexdigest()}))
        return edge, compose

    def test_renewal_uses_preserved_config_and_validates_changed_certificate_without_restart(self):
        edge, compose = self.renewal_fixture()
        self.op.record(phase='edge_ready')
        calls = []

        def run(args, **kwargs):
            calls.append([str(value) for value in args])
            if 'config' in args and '--format' in args:
                return json.dumps(compose).encode()
            if args[:2] == ['docker', 'compose'] and 'run' in args:
                (edge / 'lego/data/certificates/publicdata-stream.crt').write_bytes(b'test-only-renewed-certificate')
            return b''

        with patch.object(operator, 'EDGE', edge), patch.object(operator, 'call', side_effect=run):
            result = self.op.cert_renew()
        self.assertTrue(result['changed'])
        self.assertFalse(result['edge_restarted'])
        renewal = next(value for value in calls if value[:2] == ['docker', 'compose'] and 'run' in value)
        self.assertEqual(renewal[-1], 'lego')
        self.assertNotIn('renew', renewal)
        self.assertTrue(any('-checkhost' in value for value in calls))
        self.assertTrue(any('--check' in value and 'oxibelt' in value for value in calls))
        self.assertFalse(any('restart' in value for value in calls))

    def test_renewal_failure_or_changed_settings_cannot_restart_edge(self):
        edge, compose = self.renewal_fixture()
        self.op.record(phase='edge_ready')
        calls = []

        def fail(args, **kwargs):
            calls.append([str(value) for value in args])
            if 'config' in args and '--format' in args:
                return json.dumps(compose).encode()
            if args[:2] == ['docker', 'compose'] and 'run' in args:
                raise operator.OperatorError('test-only-provider-failure')
            return b''

        with patch.object(operator, 'EDGE', edge), patch.object(operator, 'call', side_effect=fail):
            with self.assertRaises(operator.OperatorError):
                self.op.cert_renew()
            self.assertFalse((self.bundle / 'certificate-renewal-state.json').exists())
            (edge / 'lego/.lego.yaml').write_text('changed-before-provider-request')
            calls.clear()
            with self.assertRaises(operator.OperatorError):
                self.op.cert_renew()
            self.assertFalse(any(value[:2] == ['docker', 'compose'] and 'run' in value for value in calls))
        self.assertFalse(any('restart' in value or ('stop' in value and 'oxibelt' in value) for value in calls))

    def test_renewal_is_unavailable_during_preparation(self):
        with patch.object(operator, 'call') as run:
            with self.assertRaises(operator.OperatorError):
                self.op.cert_renew()
        run.assert_not_called()

    def test_certificate_inventory_rejects_empty_default_store_and_wrong_domain(self):
        valid = {'name': 'publicdata-stream', 'path': '/var/lib/lego/certificates/publicdata-stream.crt',
                 'expired': False, 'domains': ['publicdata.stream', '*.mcp.publicdata.stream']}
        operator.validate_lego_certificate_list(json.dumps([valid]))
        for values in (None, [], [{**valid, 'path': '.lego/certificates/publicdata-stream.crt'}],
                       [{**valid, 'domains': ['unrelated.example']}], [{**valid, 'expired': True}]):
            with self.subTest(values=values), self.assertRaises(operator.OperatorError):
                operator.validate_lego_certificate_list(json.dumps(values))

    @unittest.skipUnless(os.environ.get('DEVRES_LEGO_TEST_DOCKER_HOST'), 'Opt-in isolated /tmp Docker fixture')
    def test_actual_pinned_lego_requires_configured_store_and_rejects_malformed_yaml(self):
        docker_host = os.environ['DEVRES_LEGO_TEST_DOCKER_HOST']
        if not docker_host.startswith('unix:///tmp/'):
            self.fail('Expected the task-owned Docker socket below /tmp')
        root = self.root / 'lego-cli'
        certificates = root / 'data/certificates'
        certificates.mkdir(parents=True)
        (root / 'empty/certificates').mkdir(parents=True)
        root.chmod(0o755)
        certificate = certificates / 'publicdata-stream.crt'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-days', '2', '-subj', '/CN=publicdata.stream',
                        '-addext', 'subjectAltName=DNS:publicdata.stream,DNS:*.mcp.publicdata.stream',
                        '-keyout', str(root / 'fixture.key'), '-out', str(certificate)],
                       check=True, capture_output=True)
        (certificates / 'publicdata-stream.json').write_text('{}')
        config = root / 'lego.yaml'
        configuration = ('storage: /var/lib/lego\nchallenges:\n  cf:\n    dns:\n      provider: cloudflare\n'
                         'certificates:\n  publicdata-stream:\n    challenge: cf\n    domains:\n'
                         '      - publicdata.stream\n      - "*.mcp.publicdata.stream"\n')
        config.write_text(configuration)
        command = ['docker', '--host', docker_host, 'run', '--rm', '--pull', 'never', '--network', 'none',
                   '--read-only', '--user', '10001:10001', '-v', str(config) + ':/.lego.yaml:ro',
                   '-v', str(root / 'data') + ':/var/lib/lego:ro',
                   '-v', str(root / 'empty') + ':/default-store:ro',
                   '-v', str(root / 'empty') + ':/.lego:ro', operator.renderer().LEGO,
                   'certificates', 'list', '--json', '--config', '/.lego.yaml']
        valid = subprocess.run(command, check=True, capture_output=True, timeout=30)
        operator.validate_lego_certificate_list(valid.stdout)
        config.write_text(configuration.replace('/var/lib/lego', '/default-store'))
        empty = subprocess.run(command, check=True, capture_output=True, timeout=30)
        with self.assertRaises(operator.OperatorError):
            operator.validate_lego_certificate_list(empty.stdout)
        config.write_text('storage: [malformed YAML\n')
        invalid = subprocess.run(command, check=False, capture_output=True, timeout=30)
        if invalid.returncode == 0:
            with self.assertRaises(operator.OperatorError):
                operator.validate_lego_certificate_list(invalid.stdout)
        else:
            self.assertEqual(invalid.returncode, 1)

    def test_recreated_node_namespace_or_changed_settings_refuse_cluster_actions(self):
        node = {'metadata': {'uid': 'node-1'}, 'status': {'addresses': [{'address': self.settings['node_ipv4']}]}}
        namespaces = {'kube-system': 'cluster-1', 'devres': 'namespace-1'}

        def get(*args, **kwargs):
            return json.dumps(node if args[1] == 'node' else {'metadata': {'uid': namespaces[args[2]]}}).encode()

        with patch.object(self.op, 'k', side_effect=get):
            operator.Operator.validate_cluster(self.op, bind=True)
            operator.Operator.validate_cluster(self.op)
            node['metadata']['uid'] = 'recreated-node'
            with self.assertRaises(operator.OperatorError):
                operator.Operator.validate_cluster(self.op)
            node['metadata']['uid'] = 'node-1'
            namespaces['devres'] = 'recreated-namespace'
            with self.assertRaises(operator.OperatorError):
                operator.Operator.validate_cluster(self.op)
            namespaces['devres'] = 'namespace-1'
            self.write('settings.json', json.dumps({**self.settings, 'node_ipv4': '62.210.240.41'}))
            with self.assertRaises(operator.OperatorError):
                operator.Operator.validate_cluster(self.op)

    def test_activation_metadata_failure_after_rollout_stops_both_roles(self):
        self.op.record(phase='edge_ready')
        self.write('acceptance-receipt.json', json.dumps(receipt()))
        for role in ('serving', 'writer'):
            self.write(role + '.toml', operator.renderer().runtime_config(role == 'writer'))
        source = {'release_revision': operator.REVISION, 'fixture': False,
                  'providers': {name: {'passed': True, 'attempts': 1} for name in operator.COLLECTORS}, 'github_attempts': 1}
        self.write('source.json', json.dumps(source))
        self.write('edge.json', '{}')
        original_replace = operator.private_replace
        failed = False

        def fail_metadata(path, value):
            nonlocal failed
            if Path(path).name == 'writer.toml' and not failed:
                failed = True
                raise OSError('test-only-full-filesystem')
            return original_replace(path, value)

        with patch.object(operator, 'edge_receipt'), patch.object(operator, 'private_replace', side_effect=fail_metadata), \
                patch.object(operator.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(1000, 0, operator.MIN_FREE + 1)):
            with self.assertRaises(OSError):
                self.op.activate(self.bundle / 'source.json', self.bundle / 'edge.json')
        for name in ('writer', 'backend'):
            self.assertIn(('scale', name, 1), self.op.events)
            self.assertEqual(self.op.current[name]['desired'], 0)
        for role in ('writer', 'serving'):
            config = tomllib.loads(operator.private_read(self.bundle / (role + '.toml')).decode())
            self.assertTrue(all(not config[name]['enabled'] for name in operator.COLLECTORS))
        self.assertEqual(operator.read_json(self.bundle / 'state.json')['phase'], 'activation_failed')

    @unittest.skipUnless(os.geteuid() == 0, 'Legacy ownership adoption requires root')
    def test_scoped_legacy_adoption_retains_preimages_and_original_metadata(self):
        edge = self.root / 'serve'
        conf = edge / 'oxibelt-conf'
        conf.mkdir(parents=True)
        paths = [edge / 'docker-compose.yml', edge / 'oxibelt.toml', conf / 'old-route.toml']
        for path in paths:
            path.write_text('test-only-prior-configuration\n')
            os.chown(path, 1000, 1000)
        for path in (edge, conf):
            os.chown(path, 1000, 1000)
        with patch.object(operator, 'EDGE', edge), patch.object(operator, 'call', return_value=b''):
            result = self.op.adopt_serve()
        self.assertFalse(result['edge_started'])
        inventory = json.loads(operator.private_read(self.bundle / 'edge-previous/inventory.json'))
        self.assertTrue(all(item['uid'] == 1000 for item in inventory))
        for path in paths:
            self.assertEqual(path.stat().st_uid, 0)
            self.assertEqual(path.read_text(), 'test-only-prior-configuration\n')
        self.assertEqual(operator.private_read(self.bundle / 'edge-previous/conf-old-route.toml'),
                         b'test-only-prior-configuration\n')

    def test_prepare_produces_private_tls_and_never_a_passing_provider_receipt(self):
        settings = self.root / 'settings.json'
        operator.private_write(settings, json.dumps(self.settings))
        destination = self.root / 'actual-prepare'
        operator.prepare(destination, settings)
        self.assertFalse((destination / 'acceptance-receipt.json').exists())
        for name in ('database-passwords.json', 'state.json', 'tls/backend.key', 'tls/writer.key', 'broker-keyring.json'):
            self.assertEqual((destination / name).stat().st_mode & 0o077, 0)
        certificate = operator.call(['openssl', 'x509', '-in', destination / 'tls/backend.crt', '-noout', '-ext', 'subjectAltName'])
        self.assertIn(b'DNS:devres-k8s', certificate)
        writer = operator.call(['openssl', 'x509', '-in', destination / 'tls/writer.crt', '-noout', '-ext', 'subjectAltName'])
        self.assertIn(b'DNS:writer.devres.svc', writer)


if __name__ == '__main__':
    unittest.main()
