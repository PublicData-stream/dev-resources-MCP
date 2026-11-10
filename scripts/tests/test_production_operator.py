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



class StaticProductionOperatorTests(unittest.TestCase):
    write = ProductionOperatorTests.write
    # Reuse setup helpers, but run the static-focused tests below only.
    def setUp(self):
        ProductionOperatorTests.setUp(self)
        self.settings['storage_auth'] = 'scaleway_static'
        self.settings.pop('iam_cidrs')
        previous = os.umask(0o077)
        try:
            operator.renderer().render(self.bundle, self.settings)
        finally:
            os.umask(previous)
        encoded = json.dumps(self.settings, sort_keys=True)
        self.write('settings.json', encoded)
        self.write('state.json', json.dumps({'version': 1, 'revision': operator.REVISION, 'phase': 'prepared',
                   'settings_sha256': hashlib.sha256(encoded.encode()).hexdigest()}))
        self.op = FakeOperator(self.bundle)
        self.op.current = {name: {'desired': 0, 'ready': 0} for name in self.op.workloads()}

    def static_inputs(self):
        apps = ('66666666-6666-4666-8666-666666666666', '77777777-7777-4777-8777-777777777777')
        values = {'organization_id': '55555555-5555-4555-8555-555555555555',
                  'project_id': '44444444-4444-4444-8444-444444444444',
                  'reader_application_id': apps[0], 'writer_application_id': apps[1],
                  'reader_policy_sha256': 'd' * 64, 'writer_policy_sha256': 'e' * 64,
                  'acceptance_receipt_file': str(self.bundle / 'real-static-receipt.json')}
        for role in ('reader', 'writer'):
            for kind in ('access_key', 'secret_key'):
                name = role + '-' + kind
                self.write(name, 'test-only-' + name)
                values[role + '_' + kind + '_file'] = str(self.bundle / name)
        self.write('static-inputs.json', json.dumps(values))
        binding = self.op.static_inputs(self.bundle / 'static-inputs.json')[2]
        now = datetime.now(timezone.utc)
        accepted = {'version': 1, 'mode': 'scaleway_static', 'fixture': False, 'binding': binding,
                    'checks': {key: True for key in operator.STATIC_STORAGE_CHECKS},
                    'verified_at': (now - timedelta(minutes=1)).isoformat(),
                    'expires_at': (now + timedelta(hours=1)).isoformat()}
        self.write('real-static-receipt.json', json.dumps(accepted))
        return self.bundle / 'static-inputs.json', accepted

    def static_provision(self):
        inputs, _ = self.static_inputs()
        with patch.object(self.op, 'require_static_release'):
            self.op.provision_runtime(inputs)
        return inputs

    def test_static_old_release_denied_before_any_secret_write(self):
        inputs, _ = self.static_inputs()
        unqualified = operator.renderer()
        unqualified.STATIC_AUTH_RELEASE_QUALIFIED = False
        with patch.object(operator, 'renderer', return_value=unqualified), self.assertRaisesRegex(operator.OperatorError, 'qualified_static_storage_release_required'):
            self.op.provision_runtime(inputs)
        self.assertEqual(self.op.events, [])

    def test_qualified_release_does_not_admit_an_older_bundle(self):
        self.op.require_static_release()
        identity = operator.read_json(self.bundle / 'release.json')
        identity['version'] = '0.1.0-build.172d528d'
        identity['revision'] = '172d528d88d16c9ec4fd83a16674280815178930'
        self.write('release.json', json.dumps(identity))
        with self.assertRaisesRegex(operator.OperatorError, 'bundle_release_identity_mismatch'):
            self.op.validate_identity()
        self.assertEqual(self.op.events, [])

    def test_static_import_separates_keys_and_excludes_issuer_material(self):
        self.static_provision()
        secrets = {event[2]['metadata']['name']: event[2] for event in self.op.events
                   if event[0] == 'k' and event[2] and event[2].get('kind') == 'Secret'}
        self.assertEqual(set(secrets), set(self.op.runtime_secrets()))
        self.assertNotIn('devres-credential-broker-private', secrets)
        self.assertNotEqual(secrets['devres-serving-s3']['data'], secrets['devres-writer-s3']['data'])
        with patch.object(self.op, 'require_static_release'):
            self.op.admit_storage_receipt()
        for role in ('serving', 'writer'):
            config = operator.private_read(self.bundle / (role + '.toml')).decode()
            self.assertNotIn('test-only-reader-secret_key', config)
            self.assertEqual(tomllib.loads(config)['storage']['s3']['credentials']['mode'], 'files')

    def test_static_receipt_rejects_fixture_expired_checks_binding_and_broker_mode(self):
        _, accepted = self.static_inputs()
        binding = accepted['binding']
        for changed in ({'fixture': True}, {'mode': 'broker'}, {'checks': {}},
                        {'binding': {**binding, 'prefix': 'different'}},
                        {'expires_at': '2000-01-01T00:00:00Z'}):
            with self.subTest(changed=changed), self.assertRaises(operator.OperatorError):
                operator.static_storage_receipt({**accepted, **changed}, binding)
        with self.assertRaises(operator.OperatorError):
            operator.provider_receipt(accepted)
        with self.assertRaises(operator.OperatorError):
            operator.static_storage_receipt(receipt(), binding)

    def test_static_key_swap_requires_renewed_receipt_and_complete_distinct_pairs(self):
        inputs, accepted = self.static_inputs()
        self.write('reader-secret_key', 'test-only-rotated-secret')
        self.op.events.clear()
        with patch.object(self.op, 'require_static_release'), self.assertRaises(operator.OperatorError):
            self.op.provision_runtime(inputs)
        self.assertFalse(any(event[2] for event in self.op.events if event[0] == 'k'))
        self.write('reader-access_key', 'test-only-writer-access_key')
        with self.assertRaisesRegex(operator.OperatorError, 'static_storage_keys_must_differ'):
            self.op.static_inputs(inputs)
        self.write('reader-access_key', '\n')
        with self.assertRaises(operator.OperatorError):
            self.op.static_inputs(inputs)

    def test_static_running_roles_refuse_rotation(self):
        inputs, _ = self.static_inputs()
        self.op.current['writer']['desired'] = 1
        with patch.object(self.op, 'require_static_release'), self.assertRaises(operator.OperatorError):
            self.op.provision_runtime(inputs)
        self.assertEqual(self.op.events, [])

    def test_static_modified_private_secret_rejected_at_start(self):
        self.static_provision()
        value = operator.read_json(self.bundle / 'devres-serving-s3.json')
        value['data']['secret-key'] = base64.b64encode(b'test-only-different-key').decode()
        self.write('devres-serving-s3.json', json.dumps(value))
        with patch.object(self.op, 'require_static_release'), self.assertRaises(operator.OperatorError):
            self.op.admit_start()
        self.assertFalse(any(event[0] == 'scale' for event in self.op.events))

    def test_static_start_has_no_broker_and_starts_writer_before_serving(self):
        self.static_provision()
        self.op.events.clear()
        with patch.object(self.op, 'require_static_release'), patch.object(operator.shutil, 'disk_usage',
                return_value=shutil._ntuple_diskusage(1000, 0, operator.MIN_FREE + 1)):
            self.op.admit_start()
        self.assertEqual([event for event in self.op.events if event[0] == 'scale'],
                         [('scale', 'postgres', 1), ('scale', 'writer', 1), ('scale', 'backend', 1)])

    def test_static_mode_settings_cannot_be_changed_in_place(self):
        self.settings['storage_auth'] = 'broker'
        self.write('settings.json', json.dumps(self.settings))
        with self.assertRaisesRegex(operator.OperatorError, 'bundle_settings_changed'):
            self.op.auth_mode()

    def test_static_cutover_provision_stages_secrets_without_cluster_writes(self):
        self.op.record(auth_switch_pending=True, auth_switch_source=str(self.root / 'original'))
        self.static_provision()
        self.assertFalse(any(event[2] for event in self.op.events if event[0] == 'k'))
        self.assertEqual(operator.read_json(self.bundle / 'state.json')['phase'], 'runtime_provisioned')

    def test_static_writer_template_tampering_rejected_before_secret_writes(self):
        inputs, _ = self.static_inputs()
        text = operator.private_read(self.bundle / 'writer.toml.example').decode()
        self.write('writer.toml.example', text.replace('prefix = "production"', 'prefix = "other"'))
        with patch.object(self.op, 'require_static_release'), self.assertRaisesRegex(
                operator.OperatorError, 'static_storage_configuration_changed'):
            self.op.provision_runtime(inputs)
        self.assertFalse(any(event[2] for event in self.op.events if event[0] == 'k'))
        self.assertFalse((self.bundle / 'static-storage-identity.json').exists())

    def test_database_restart_preserves_admission_for_static_start(self):
        self.static_provision()
        self.op.start_postgres()
        self.assertEqual(operator.read_json(self.bundle / 'state.json')['phase'], 'runtime_provisioned')
        with patch.object(self.op, 'require_static_release'), patch.object(operator.shutil, 'disk_usage',
                return_value=shutil._ntuple_diskusage(1000, 0, operator.MIN_FREE + 1)):
            self.op.admit_start()
        self.assertEqual(self.op.current['backend']['ready'], 1)

    def test_static_postgres_generation_has_no_broker_identity(self):
        passwords, manifests = operator.postgres_inputs('scaleway_static')
        self.assertEqual(set(passwords), {'corpus_admin', 'reader', 'writer'})
        self.assertEqual([item['metadata']['name'] for item in manifests], ['devres-corpus-postgres'])



class AuthenticationSwitchTests(unittest.TestCase):
    setUp = ProductionOperatorTests.setUp
    write = ProductionOperatorTests.write
    private_inputs = ProductionOperatorTests.private_inputs

    def prepared_target(self):
        self.write('devres-guard.nft', 'test-only-firewall')
        with patch.object(operator, 'verify_broker_fingerprints'):
            self.op.provision_runtime(self.private_inputs())
        target_settings = {key: value for key, value in self.settings.items() if key != 'iam_cidrs'}
        target_settings['storage_auth'] = 'scaleway_static'
        self.write('target-settings.json', json.dumps(target_settings))
        target_path = self.root / 'static-bundle'
        self.op.prepare_auth_switch(target_path, self.bundle / 'target-settings.json')
        target = FakeOperator(target_path)
        holder = type('Fixture', (), {})()
        holder.bundle = target_path
        holder.op = target
        holder.write = lambda name, value: operator.private_replace(target_path / name, value)
        inputs, _ = StaticProductionOperatorTests.static_inputs(holder)
        with patch.object(target, 'require_static_release'):
            target.provision_runtime(inputs)
        return target

    def switch(self, source, target):
        # Fixture only: never represent this mocked qualification as a production receipt.
        with patch.object(operator, 'Operator', return_value=target), patch.object(target, 'require_static_release'):
            return source.switch_storage_auth(target.bundle)

    def test_cutover_and_original_bundle_rollback_preserve_database_binding_and_leave_stopped(self):
        target = self.prepared_target()
        original_database = operator.private_read(self.bundle / 'database-passwords.json')
        self.assertEqual(operator.private_read(target.bundle / 'database-passwords.json'), original_database)
        with patch.object(self.op, 'broker_drained'):
            result = self.switch(self.op, target)
        self.assertTrue(result['runtime_stopped'])
        self.assertEqual(operator.read_json(self.bundle / 'state.json')['phase'], 'auth_retired')
        self.assertFalse(operator.read_json(target.bundle / 'state.json')['auth_switch_pending'])
        self.assertIn(('scale', 'credential-broker', 0), self.op.events)
        self.assertIn(('scale', 'broker-postgres', 0), self.op.events)
        deleted = [event[1] for event in self.op.events if event[0] == 'k' and event[1][0] == 'delete']
        self.assertTrue(deleted)
        self.assertFalse(any(kind in args for args in deleted for kind in ('secret', 'persistentvolume', 'persistentvolumeclaim', 'deployment')))
        self.switch(target, self.op)
        self.assertEqual(operator.read_json(self.bundle / 'state.json')['phase'], 'runtime_provisioned')
        self.assertEqual(operator.private_read(self.bundle / 'database-passwords.json'), original_database)
        self.assertFalse(any(event[0] == 'scale' and event[2] == 1 for event in self.op.events + target.events))

    def test_unresolved_broker_journal_blocks_cutover_before_runtime_changes(self):
        target = self.prepared_target()
        self.op.events.clear()
        with self.assertRaisesRegex(operator.OperatorError, 'broker_issuance_or_revocation_unresolved'):
            self.switch(self.op, target)
        self.assertFalse(any(event[0] == 'scale' or (event[0] == 'k' and event[1][0] in ('apply', 'delete'))
                             for event in self.op.events))

    def test_broker_count_probe_requires_zero_nonrevoked_records(self):
        with patch.object(self.op, 'k', return_value=b'1\n'), self.assertRaises(operator.OperatorError):
            self.op.broker_drained()
        with patch.object(self.op, 'k', return_value=b'0\n'):
            self.op.broker_drained()

    def test_pending_authentication_bundle_cannot_start(self):
        target = self.prepared_target()
        target.events.clear()
        with self.assertRaisesRegex(operator.OperatorError, 'authentication_switch_not_applied'):
            target.admit_start()
        self.assertEqual(target.events, [])

    def test_binding_change_and_running_roles_prevent_cutover(self):
        target = self.prepared_target()
        self.op.current['writer']['desired'] = 1
        with self.assertRaisesRegex(operator.OperatorError, 'authentication_switch_requires_stopped_roles'):
            self.switch(self.op, target)
        self.op.current['writer']['desired'] = 0
        self.write('writer.toml', operator.private_read(self.bundle / 'writer.toml').decode().replace('prefix = "production"', 'prefix = "changed"'))
        with self.assertRaisesRegex(operator.OperatorError, 'authentication_switch_archive_binding_changed'):
            self.switch(self.op, target)

    def test_application_overlap_prevents_broker_retirement(self):
        target = self.prepared_target()
        accepted = operator.read_json(self.bundle / 'acceptance-receipt.json')
        identity = operator.read_json(target.bundle / 'static-storage-identity.json')
        accepted['confined_application_ids'][0] = identity['reader_application_id']
        self.write('acceptance-receipt.json', json.dumps(accepted))
        with self.assertRaisesRegex(operator.OperatorError, 'static_applications_must_be_outside_broker_management'):
            self.switch(self.op, target)

    def test_old_release_cutover_gate_precedes_mutations(self):
        target = self.prepared_target()
        self.op.events.clear()
        unqualified = operator.renderer()
        unqualified.STATIC_AUTH_RELEASE_QUALIFIED = False
        with patch.object(operator, 'renderer', return_value=unqualified), patch.object(operator, 'Operator', return_value=target), self.assertRaisesRegex(
                operator.OperatorError, 'qualified_static_storage_release_required'):
            self.op.switch_storage_auth(target.bundle)
        self.assertEqual(self.op.events, [])

    def test_cutover_database_restart_start_and_rollback_start(self):
        target = self.prepared_target()
        with patch.object(self.op, 'broker_drained'):
            self.switch(self.op, target)
        target.start_postgres()
        with patch.object(target, 'require_static_release'), patch.object(operator.shutil, 'disk_usage',
                return_value=shutil._ntuple_diskusage(1000, 0, operator.MIN_FREE + 1)):
            target.admit_start()
        target.stop()
        self.switch(target, self.op)
        self.op.start_postgres()
        with patch.object(operator.shutil, 'disk_usage',
                return_value=shutil._ntuple_diskusage(1000, 0, operator.MIN_FREE + 1)):
            self.op.admit_start()
        self.assertEqual(self.op.current['backend']['ready'], 1)

    def test_partial_apply_restores_source_configuration_without_starting_roles(self):
        target = self.prepared_target()
        with patch.object(self.op, 'broker_drained'), patch.object(target, 'apply_secret', side_effect=operator.OperatorError('fixture-apply-failure')):
            with self.assertRaisesRegex(operator.OperatorError, 'fixture-apply-failure'):
                self.switch(self.op, target)
        self.assertEqual(operator.read_json(self.bundle / 'state.json')['phase'], 'stopped')
        self.assertTrue(operator.read_json(target.bundle / 'state.json')['auth_switch_pending'])
        self.assertFalse(any(event[0] == 'scale' and event[2] == 1 for event in self.op.events))


    def test_enabled_collectors_block_prepare_until_stopped_pause_preserving_broker(self):
        self.write('devres-guard.nft', 'test-only-firewall')
        with patch.object(operator, 'verify_broker_fingerprints'):
            self.op.provision_runtime(self.private_inputs())
        for role in ('serving', 'writer'):
            text = operator.private_read(self.bundle / (role + '.toml')).decode()
            self.write(role + '.toml', operator.collector_config(text, True))
        self.op.record(phase='collectors_active', legacy_edge_adopted=True)
        self.op.stop()
        settings = {**self.settings, 'storage_auth': 'scaleway_static'}
        self.write('target-settings.json', json.dumps(settings))
        with self.assertRaisesRegex(operator.OperatorError, 'authentication_switch_requires_disabled_collectors'):
            self.op.prepare_auth_switch(self.root / 'refused', self.bundle / 'target-settings.json')
        self.assertFalse((self.root / 'refused').exists())
        self.op.current['credential-broker']['desired'] = 1
        original = {role: tomllib.loads(operator.private_read(self.bundle / (role + '.toml')).decode()) for role in ('serving', 'writer')}
        self.op.pause_collectors()
        self.assertEqual(self.op.current['credential-broker']['desired'], 1)
        for role in ('serving', 'writer'):
            expected = original[role]
            for provider in operator.COLLECTORS:
                expected[provider]['enabled'] = False
            self.assertEqual(tomllib.loads(operator.private_read(self.bundle / (role + '.toml')).decode()), expected)
        self.op.prepare_auth_switch(self.root / 'paused-target', self.bundle / 'target-settings.json')
        target = FakeOperator(self.root / 'paused-target')
        self.assertTrue(operator.read_json(target.bundle / 'state.json')['edge_admitted'])
        for role in ('serving', 'writer'):
            config = tomllib.loads(operator.private_read(self.bundle / (role + '.toml')).decode())
            self.assertFalse(any(config[name]['enabled'] for name in operator.COLLECTORS))

    def test_edge_ownership_and_existing_timers_follow_cutover_and_rollback(self):
        self.op.record(phase='edge_ready', legacy_edge_adopted=True)
        self.op.stop()
        accepted = {'revision': operator.REVISION, 'test_only': True}
        self.write('lego-renewal.json', json.dumps(accepted))
        operator.private_write(self.bundle / 'edge-previous' / 'original.toml', 'test-only-edge-preimage')
        target = self.prepared_target()
        self.assertTrue(operator.read_json(target.bundle / 'state.json')['legacy_edge_adopted'])
        self.assertEqual(operator.read_json(target.bundle / 'lego-renewal.json'), accepted)
        self.assertEqual(operator.private_read(target.bundle / 'edge-previous' / 'original.toml'), b'test-only-edge-preimage')
        with patch.object(self.op, 'broker_drained'):
            self.switch(self.op, target)
        with patch.object(operator, 'Operator', return_value=target), patch.object(target, 'cert_renew', return_value={'forwarded': True}):
            self.assertEqual(self.op.cert_renew(), {'forwarded': True})
        with patch.object(operator, 'Operator', return_value=target), patch.object(target, 'capacity', return_value={'forwarded': True}):
            self.assertEqual(self.op.capacity(), {'forwarded': True})
        self.switch(target, self.op)
        self.assertIs(self.op.active_auth_operator(), self.op)
        with patch.object(operator, 'Operator', return_value=self.op):
            self.assertIs(target.active_auth_operator(), self.op)


if __name__ == '__main__':
    unittest.main()
