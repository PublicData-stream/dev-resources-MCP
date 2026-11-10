"""Behavioral checks for production rendering and runtime isolation contracts."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('devres_production', ROOT / 'deploy/production/production.py')
production = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(production)


class ProductionDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.settings = {'node_name': 'publicdatamcp-b130e', 'node_ipv4': '62.210.240.40',
                         'kube_api_cidrs': ['10.43.0.1/32', '62.210.240.40/32'],
                         'iam_cidrs': ['51.159.0.1/32'], 'oxibelt_digest': 'a' * 64}
        self.manifest = production.manifests(production.settings_checked(self.settings))
        self.objects = {(item['kind'], item['metadata']['name']): item for item in self.manifest['items']}

    def test_render_is_deterministic_and_templates_parse(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            first = production.render(root / 'first', self.settings)
            second = production.render(root / 'second', self.settings)
            self.assertEqual(set(first), set(second))
            for name in first:
                self.assertEqual(first[name].read_bytes(), second[name].read_bytes())
                if '.toml' in name:
                    tomllib.loads(first[name].read_text())
            self.assertEqual(json.loads(first['kubernetes.json'].read_text()), self.manifest)

    def test_deployments_remain_stopped_and_permanent_volumes_retained(self):
        deployments = [item for (kind, _), item in self.objects.items() if kind == 'Deployment']
        self.assertEqual(len(deployments), 5)
        for item in deployments:
            self.assertEqual(item['spec']['replicas'], 0)
            self.assertEqual(item['spec']['strategy']['type'], 'Recreate')
            pod = item['spec']['template']['spec']
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertEqual(pod['nodeSelector']['kubernetes.io/hostname'], self.settings['node_name'])
        for (kind, _), item in self.objects.items():
            if kind == 'PersistentVolume':
                self.assertEqual(item['spec']['persistentVolumeReclaimPolicy'], 'Retain')
                self.assertFalse(item['spec']['local']['path'].startswith('/tmp'))
        self.assertNotIn('Secret', {kind for kind, _ in self.objects})

    def test_runtime_configs_preserve_split_identity_and_no_collection(self):
        reader = tomllib.loads(production.runtime_config())
        writer = tomllib.loads(production.runtime_config(True))
        for value in (reader, writer):
            for provider in production.PROVIDERS:
                self.assertFalse(value[provider]['enabled'])
            self.assertEqual(value['npm']['packages'], [])
            self.assertTrue(value['npm']['advisories_enabled'])
            self.assertEqual(value['storage']['s3']['bucket'], 'dev-resources-mcp')
            self.assertEqual(value['storage']['s3']['prefix'], 'production')
            self.assertEqual(value['storage']['s3']['storage_class'], 'ONEZONE_IA')
        self.assertIn('devres_reader:', reader['storage']['database_url'])
        self.assertIn('devres_writer:', writer['storage']['database_url'])
        self.assertNotEqual(reader['storage']['scratch_dir'], reader['storage']['blob_dir'])
        self.assertIn('writer_client', reader)
        self.assertNotIn('writer_listener', reader)
        self.assertIn('writer_listener', writer)
        self.assertEqual(writer['writer_listener']['allowed_clients'],
                         [{'namespace': 'devres', 'service_account': 'devres-serving'}])

    def test_serving_cannot_mount_writer_key_and_broker_tokens_rotate(self):
        pod = self.objects['Deployment', 'backend']['spec']['template']['spec']
        writer_tls = next(value for value in pod['volumes'] if value['name'] == 'writer-tls')
        self.assertEqual(writer_tls['secret']['items'], [{'key': 'ca.crt', 'path': 'ca.crt'}])
        for deployment in ('backend', 'writer'):
            volumes = self.objects['Deployment', deployment]['spec']['template']['spec']['volumes']
            projection = next(value for value in volumes if value['name'] == 'broker-identity')
            token = projection['projected']['sources'][0]['serviceAccountToken']
            self.assertEqual(token, {'path': 'token', 'audience': 'devres-credential-broker', 'expirationSeconds': 3600})

    def test_database_identity_and_broker_separation(self):
        for name, db in (('postgres', 'devres'), ('broker-postgres', 'devres_broker')):
            pod = self.objects['Deployment', name]['spec']['template']['spec']
            self.assertEqual(pod['securityContext']['runAsUser'], 70)
            container = pod['containers'][0]
            env = {value['name']: value['value'] for value in container['env']}
            self.assertEqual(env['POSTGRES_DB'], db)
            self.assertEqual(env['PGDATA'], '/var/lib/postgresql/18/docker')
            self.assertNotIn('POSTGRES_PASSWORD', env)
            startup = container['startupProbe']
            self.assertEqual(startup['exec']['command'],
                             ['pg_isready', '-h', '127.0.0.1', '-U', 'devres_admin', '-d', db])
            self.assertGreaterEqual(startup['periodSeconds'] * startup['failureThreshold'], 600)
            self.assertGreater(startup['timeoutSeconds'], 3)
            self.assertLess(startup['timeoutSeconds'], startup['periodSeconds'])
            self.assertEqual(container['readinessProbe']['exec'], startup['exec'])
            self.assertEqual(container['livenessProbe']['exec'], startup['exec'])
            self.assertGreater(self.objects['Deployment', name]['spec']['progressDeadlineSeconds'],
                               startup['periodSeconds'] * startup['failureThreshold'])
        policy = self.objects['NetworkPolicy', 'broker-postgres-boundary']['spec']
        self.assertEqual(policy['ingress'][0]['from'], [production.peer('credential-broker')])
        broker = self.objects['Deployment', 'credential-broker']['spec']['template']['spec']['containers'][0]
        self.assertEqual(broker['readinessProbe']['httpGet']['path'], '/healthz')
        self.assertEqual(broker['livenessProbe']['tcpSocket']['port'], 'credentials')

    def test_private_ports_and_actual_egress_boundaries(self):
        deny = self.objects['NetworkPolicy', 'default-deny']['spec']
        self.assertEqual(deny['podSelector'], {})
        self.assertEqual(deny['policyTypes'], ['Ingress', 'Egress'])
        backend = self.objects['NetworkPolicy', 'backend-boundary']['spec']
        self.assertEqual(backend['ingress'][0]['from'], [{'ipBlock': {'cidr': '10.0.0.3/32'}}])
        public = backend['egress'][1]['to'][0]['ipBlock']
        self.assertEqual(public['cidr'], '0.0.0.0/0')
        exclusions = [ipaddress.ip_network(value) for value in public['except']]
        for address in ('10.42.0.1', '127.0.0.1', '169.254.169.254', '192.168.1.1', '62.210.240.40'):
            self.assertTrue(any(ipaddress.ip_address(address) in network for network in exclusions))
        for (kind, name), item in self.objects.items():
            if kind == 'Service':
                self.assertNotIn(9090, {port['port'] for port in item['spec']['ports']})
                if name != 'backend':
                    self.assertNotIn('NodePort', item['spec'].get('type', 'ClusterIP'))
        broker = self.objects['NetworkPolicy', 'credential-broker-boundary']['spec']
        self.assertEqual(broker['egress'][-1]['to'], [{'ipBlock': {'cidr': '51.159.0.1/32'}}])

    def test_renderer_refuses_broad_or_invalid_destination_settings(self):
        for changes in ({'iam_cidrs': ['0.0.0.0/0']}, {'iam_cidrs': ['10.0.0.1/32']},
                        {'kube_api_cidrs': []}, {'node_name': 'Invalid Node'},
                        {'oxibelt_digest': 'latest'}, {'unexpected': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                production.settings_checked({**self.settings, **changes})

    def test_static_storage_omits_issuer_resources_and_isolates_credentials(self):
        settings = {key: value for key, value in self.settings.items() if key != 'iam_cidrs'}
        settings['storage_auth'] = 'scaleway_static'
        checked = production.settings_checked(settings)
        manifest = production.manifests(checked)
        objects = {(item['kind'], item['metadata']['name']): item for item in manifest['items']}
        self.assertEqual({name for kind, name in objects if kind == 'Deployment'},
                         set(production.workload_names(checked)))
        self.assertEqual(set(production.workload_names(checked)), {'postgres', 'writer', 'backend'})
        self.assertFalse(any('broker' in name for _, name in objects))
        self.assertNotIn('Secret', {kind for kind, _ in objects})
        for role, secret in (('backend', 'devres-serving-s3'), ('writer', 'devres-writer-s3')):
            pod = objects['Deployment', role]['spec']['template']['spec']
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertEqual(objects['Deployment', role]['spec']['replicas'], 0)
            volume = next(value for value in pod['volumes'] if value['name'] == 's3')
            self.assertEqual(volume['secret'], {'secretName': secret, 'defaultMode': 0o440,
                             'items': [{'key': key, 'path': key} for key in ('access-key', 'secret-key')]})
            mounted = next(value for value in pod['containers'][0]['volumeMounts'] if value['name'] == 's3')
            self.assertEqual(mounted, {'name': 's3', 'mountPath': '/run/devres-s3', 'readOnly': True})
            serialized = json.dumps(pod)
            self.assertNotIn('broker', serialized)
            self.assertNotIn('devres-writer-s3' if role == 'backend' else 'devres-serving-s3', serialized)
            policy = objects['NetworkPolicy', role + '-boundary']['spec']
            self.assertNotIn('credential-broker', json.dumps(policy))
            self.assertNotIn('iam_cidrs', json.dumps(policy))
        serving = objects['Deployment', 'backend']['spec']['template']['spec']
        writer_tls = next(value for value in serving['volumes'] if value['name'] == 'writer-tls')
        self.assertEqual(writer_tls['secret']['items'], [{'key': 'ca.crt', 'path': 'ca.crt'}])
        writer_token = next(value for value in serving['volumes'] if value['name'] == 'writer-identity')
        self.assertEqual(writer_token['projected']['sources'][0]['serviceAccountToken']['audience'], 'devres-writer')
        self.assertIn(('ClusterRole', 'devres-writer-reviewer'), objects)
        self.assertIn(('NetworkPolicy', 'default-deny'), objects)
        self.assertIn(production.peer('writer'), objects['NetworkPolicy', 'backend-boundary']['spec']['egress'][-1]['to'])
        self.assertEqual(production.runtime_secret_names(checked),
                         ('devres-serving-config', 'devres-writer-config', 'devres-backend-tls',
                          'devres-writer-tls', 'devres-serving-s3', 'devres-writer-s3'))

    def test_static_render_uses_files_without_changing_public_or_writer_contracts(self):
        settings = {**self.settings, 'storage_auth': 'scaleway_static'}
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            paths = production.render(Path(temporary), settings)
            self.assertNotIn('credential-broker.toml.example', paths)
            for writer, role in ((False, 'serving'), (True, 'writer')):
                before = tomllib.loads(production.runtime_config(writer))
                after = tomllib.loads(paths[role + '.toml.example'].read_text())
                credentials = after['storage']['s3']['credentials']
                self.assertEqual(credentials, {'mode': 'files',
                                 'access_key_file': '/run/devres-s3/access-key',
                                 'secret_key_file': '/run/devres-s3/secret-key'})
                after['storage']['s3']['credentials'] = before['storage']['s3']['credentials']
                self.assertEqual(after, before)
        self.assertTrue(production.STATIC_AUTH_RELEASE_QUALIFIED)

    def test_qualified_release_identity_reaches_rendered_workloads(self):
        self.assertEqual(production.VERSION, '0.1.0-build.a938112b')
        self.assertEqual(production.REVISION, 'a938112b5af87996661ddd91ae68755dc0d579b9')
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            paths = production.render(Path(temporary), self.settings)
            identity = json.loads(paths['release.json'].read_text())
        self.assertEqual(identity['revision'], production.REVISION)
        self.assertEqual(identity['source_sha256'], '98f107f09bc4cb69b519408cbd21518307470f77006597bdc70a3feebe339a06')
        expected = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:a966e685fe3d32ffc5625b471d0ab77b71d881827f4ae17e5a16bd2b760016a8'
        self.assertEqual(identity['server'], expected)
        for workload in ('backend', 'writer'):
            container = self.objects['Deployment', workload]['spec']['template']['spec']['containers'][0]
            self.assertEqual(container['image'], expected)

    def test_auth_selection_is_explicit_and_broker_remains_default(self):
        self.assertEqual(production.storage_auth({}), 'broker')
        self.assertEqual(production.manifests(production.settings_checked(self.settings)),
                         production.manifests(production.settings_checked({**self.settings, 'storage_auth': 'broker'})))
        for invalid in ('files', '', None, False, []):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                production.settings_checked({**self.settings, 'storage_auth': invalid})
        no_iam = {key: value for key, value in self.settings.items() if key != 'iam_cidrs'}
        with self.assertRaises(ValueError):
            production.settings_checked(no_iam)

    def test_static_policy_examples_allow_abort_and_omit_permanent_deletion(self):
        directory = ROOT / 'deploy/examples/scaleway-static'
        for role in ('readonly', 'readwrite'):
            policy = json.loads((directory / (role + '-bucket-policy.json')).read_text())
            statements = policy['Statement']
            allowed = {action for statement in statements if statement['Effect'] == 'Allow'
                       for action in statement['Action']}
            self.assertTrue(all(statement['Effect'] == 'Allow' for statement in statements))
            self.assertTrue({'s3:GetObject', 's3:ListBucket'} <= allowed)
            self.assertFalse({'s3:DeleteObject', 's3:DeleteObjectVersion'} & allowed)
            if role == 'readwrite':
                self.assertTrue({'s3:PutObject', 's3:AbortMultipartUpload',
                                 's3:ListMultipartUploadParts', 's3:ListBucketMultipartUploads'} <= allowed)
            else:
                self.assertFalse({'s3:PutObject', 's3:AbortMultipartUpload'} & allowed)
        for role in ('serving', 'writer'):
            fragment = tomllib.loads((directory / (role + '-fragment.toml.example')).read_text())
            self.assertEqual(fragment['storage']['s3']['credentials'],
                             tomllib.loads(production.runtime_config(role == 'writer', 'scaleway_static'))
                             ['storage']['s3']['credentials'])

    def test_edge_is_dedicated_and_preserves_transport_boundary(self):
        compose = production.edge_compose(production.settings_checked(self.settings))
        self.assertEqual(set(compose['networks']), {'devres-net'})
        edge = compose['services']['oxibelt']
        self.assertEqual(edge['mem_limit'], '1g')
        self.assertEqual(edge['cpus'], 1)
        self.assertEqual(edge['networks'], {'devres-net': {'ipv4_address': '10.0.0.3'}})
        self.assertIn('@sha256:', edge['image'])
        routes = tomllib.loads((production.HERE / 'edge-conf/62-route-devres.toml').read_text())['routes']
        self.assertEqual({value['match']['path']['exact'] for value in routes}, {'/mcp', '/mcp-wt/v1'})
        for value in routes:
            self.assertEqual(value['hosts'], [production.HOST])
            self.assertEqual(value['compression'], 'off')
            self.assertEqual(value['tls']['ssl_early_data'], 'off')


if __name__ == '__main__':
    unittest.main()
