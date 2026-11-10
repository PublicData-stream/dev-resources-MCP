import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest
import http.client
import json
import ssl
import os
import subprocess
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


SCRIPT = Path(__file__).resolve().parents[1] / 's3-kubernetes-fixture.py'
SPEC = importlib.util.spec_from_file_location('s3_kubernetes_fixture', SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
STATIC_SPEC = importlib.util.spec_from_file_location('static_s3_fixture', SCRIPT.with_name('static-s3-fixture.py'))
static = importlib.util.module_from_spec(STATIC_SPEC)
STATIC_SPEC.loader.exec_module(static)


class S3FixtureTests(unittest.TestCase):
    def test_private_configuration_selects_one_backend_and_preserves_provider_settings(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'fixture').mkdir()
            config = root / 'fixture' / 'backend.toml'
            config.write_text('[storage]\ndatabase_url="fixture"\nblob_dir="/data/blobs"\n'
                              '[rfc]\nenabled=false\n')
            fixture.prepare(root)
            parsed = tomllib.loads(config.read_text())
            self.assertEqual(parsed['storage']['backend'], 's3')
            self.assertFalse(parsed['rfc']['enabled'])
            direct = tomllib.loads((root / 'fixture/s3/s3.toml').read_text())
            self.assertEqual(parsed['storage']['s3'], direct)
            access = (root / 'fixture/s3/access-key').read_text()
            secret = (root / 'fixture/s3/secret-key').read_text()
            self.assertNotIn(access, config.read_text())
            self.assertNotIn(secret, config.read_text())
            for path in (root / 'fixture/s3').iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_role_mounts_never_receive_admin_or_other_role_credentials(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'fixture').mkdir()
            (root / 'fixture/backend.toml').write_text('[storage]\ndatabase_url="fixture"\nblob_dir="/data"\n')
            fixture.prepare(root)
            admin = json.loads((root / 'fixture/s3/static-fixture.json').read_text())
            identities = []
            for role in ('serving', 'writer'):
                directory = root / ('fixture/s3-' + role)
                identities.append((directory / 'access-key').read_text())
                mounted = ''.join(path.read_text() for path in directory.iterdir())
                self.assertNotIn(admin['access_key'], mounted)
                self.assertNotIn(admin['secret_key'], mounted)
                other = 'writer' if role == 'serving' else 'serving'
                self.assertNotIn(admin['identities'][other]['secret_key'], mounted)
                self.assertEqual(set(json.loads((directory / 'probe.json').read_text())),
                                 {'endpoint', 'bucket', 'prefix'})
            self.assertEqual(len(set(identities + [admin['access_key']])), 3)
            for function, source, expected, forbidden in (
                    (fixture.foundation, 'foundation.yaml', 'devres-serving-s3', 'devres-writer-s3'),
                    (fixture.writer, 'split-runtime.yaml', 'devres-writer-s3', 'devres-serving-s3')):
                path = root / source
                path.write_text((SCRIPT.parents[1] / 'deploy/kubernetes' / source).read_text())
                function(path)
                text = path.read_text()
                self.assertIn('secretName: ' + expected, text)
                self.assertNotIn('secretName: devres-s3-credentials', text)
                self.assertNotIn('secretName: ' + forbidden, text)

    def test_rotation_replaces_both_pairs_and_retains_coordinates_and_revocation_inputs(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'fixture').mkdir()
            (root / 'fixture/backend.toml').write_text('[storage]\ndatabase_url="fixture"\nblob_dir="/data"\n')
            fixture.prepare(root)
            setup_file = root / 'fixture/s3/static-fixture.json'
            original = json.loads(setup_file.read_text())
            fixture.rotate(root)
            rotated = json.loads(setup_file.read_text())
            self.assertEqual(rotated['retired_identities'], list(original['identities'].values()))
            for key in ('endpoint', 'bucket', 'prefix', 'access_key', 'secret_key'):
                self.assertEqual(rotated[key], original[key])
            for role in ('serving', 'writer'):
                pair = rotated['identities'][role]
                previous = original['identities'][role]
                self.assertNotEqual(pair['access_key'], previous['access_key'])
                self.assertNotEqual(pair['secret_key'], previous['secret_key'])
                directory = root / ('fixture/s3-' + role)
                self.assertEqual((directory / 'access-key').read_text(), pair['access_key'])
                self.assertEqual((directory / 'secret-key').read_text(), pair['secret_key'])
                for path in directory.iterdir():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_cutover_changes_only_credential_tables(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            (root / 'fixture').mkdir()
            original = ('[storage]\ndatabase_url="private-fixture"\nblob_dir="/cache"\n'
                        '[storage.s3]\nendpoint="https://fixture.invalid"\nbucket="archive"\n'
                        'region="region"\nprefix="retained"\npath_style=true\n'
                        '[storage.s3.credentials]\nmode="container"\nendpoint="https://broker.invalid"\n'
                        'authorization_token_file="/run/broker/token"\n'
                        '[writer_client]\nendpoint="https://writer.invalid/v1/acquire"\n'
                        'token_file="/run/writer/token"\n')
            for name in ('backend', 'writer'):
                (root / 'fixture' / (name + '.toml')).write_text(original)
            fixture.configure_static(root)
            before = tomllib.loads(original)
            for name in ('backend', 'writer'):
                parsed = tomllib.loads((root / 'fixture' / (name + '.toml')).read_text())
                self.assertEqual(parsed['storage']['s3'].pop('credentials'), {
                    'mode': 'files', 'access_key_file': '/fixture/s3/access-key',
                    'secret_key_file': '/fixture/s3/secret-key'})
                expected = tomllib.loads(original)
                expected['storage']['s3'].pop('credentials')
                self.assertEqual(parsed, expected)
            self.assertEqual(before['storage']['s3']['credentials']['mode'], 'container')

    def test_static_policy_permits_abort_without_permanent_deletion(self):
        reader = static.policy('archive', 'capture', False)
        writer = static.policy('archive', 'capture', True)
        for policy in (reader, writer):
            allowed = {action for statement in policy['Statement'] if statement['Effect'] == 'Allow'
                       for action in statement['Action']}
            self.assertNotIn('s3:DeleteObject', allowed)
            self.assertNotIn('s3:DeleteObjectVersion', allowed)
            self.assertFalse(any(action.endswith('*') for action in allowed))
            denied = {action for statement in policy['Statement'] if statement['Effect'] == 'Deny'
                      for action in statement['Action']}
            self.assertEqual(denied, {'s3:DeleteObject', 's3:DeleteObjectVersion'})
        self.assertNotIn('s3:AbortMultipartUpload', reader['Statement'][0]['Action'])
        self.assertIn('s3:AbortMultipartUpload', writer['Statement'][0]['Action'])
        self.assertIn('s3:ListMultipartUploadParts', writer['Statement'][0]['Action'])

    def test_bucket_initializer_uses_private_files_without_secret_arguments(self):
        manifest = fixture.initializer('fixture-image:local')
        pod = manifest['spec']['template']
        self.assertEqual(pod['metadata']['labels']['app'], 'backend')
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        container = pod['spec']['containers'][0]
        self.assertEqual(container['command'][:2], ['sh', '-ec'])
        self.assertEqual(manifest['spec']['activeDeadlineSeconds'], 90)
        self.assertTrue(container['volumeMounts'][0]['readOnly'])
        self.assertNotIn('env', container)

    def run_initializer_dns_fixture(self, ready_after, health_ready_after=1):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            scripts = {
                'getent': '#!/bin/sh\nn=$(cat "$DNS_PROBE_COUNT" 2>/dev/null || echo 0)\n'
                          'n=$((n+1)); echo "$n" > "$DNS_PROBE_COUNT"\n'
                          'test "$n" -ge "$DNS_READY_AFTER"\n',
                'sleep': '#!/bin/sh\nexit 0\n',
                'python3': '#!/bin/sh\nexit 0\n',
                'date': '#!/bin/sh\nn=$(cat "$CLOCK_COUNT" 2>/dev/null || echo 0)\n'
                        'n=$((n+1)); echo "$n" > "$CLOCK_COUNT"; echo "$n"\n',
                'curl': '#!/bin/sh\ncase "$*" in *--config*) '
                        'printf "%s\\n" "$*" >> "$DNS_AUTH_REQUESTS";; *) '
                        'n=$(cat "$HEALTH_COUNT" 2>/dev/null || echo 0); '
                        'n=$((n+1)); echo "$n" > "$HEALTH_COUNT"; '
                        'test "$n" -ge "$HEALTH_READY_AFTER";; esac\n',
            }
            for name, source in scripts.items():
                path = root / name
                path.write_text(source)
                path.chmod(0o700)
            command = fixture.initializer('fixture-image:local')['spec']['template']['spec']['containers'][0]['command']
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                               DNS_PROBE_COUNT=str(root / 'count'), DNS_READY_AFTER=str(ready_after),
                               DNS_AUTH_REQUESTS=str(root / 'requests'), CLOCK_COUNT=str(root / 'clock'),
                               HEALTH_COUNT=str(root / 'health'), HEALTH_READY_AFTER=str(health_ready_after))
            result = subprocess.run(command, env=environment, capture_output=True, timeout=5)
            requests = (root / 'requests').read_text().splitlines() if (root / 'requests').exists() else []
            return result.returncode, int((root / 'count').read_text()), requests

    def test_initializer_retries_transient_s3_unavailability_after_health_is_ready(self):
        class Bucket(BaseHTTPRequestHandler):
            attempts = 0

            def do_PUT(self):
                type(self).attempts += 1
                self.send_response(503 if self.attempts < 3 else 200)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(('127.0.0.1', 0), Bucket)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                root = Path(temporary)
                config = root / 'bucket.curl'
                config.write_text('url = "http://127.0.0.1:' + str(server.server_port) +
                                  '/synthetic"\nrequest = "PUT"\nnoproxy = "*"\nsilent\nfail\n')
                config.chmod(0o600)
                helpers = {'getent': '#!/bin/sh\nexit 0\n', 'python3': '#!/bin/sh\nexit 0\n',
                           'curl': '#!/bin/sh\ncase "$*" in *--config*) exec ' + shutil.which('curl') +
                                   ' "$@";; *) exit 0;; esac\n'}
                for name, value in helpers.items():
                    (root / name).write_text(value)
                    (root / name).chmod(0o700)
                command = fixture.initializer('fixture-image:local')['spec']['template']['spec']['containers'][0]['command']
                command[-1] = command[-1].replace('/fixture/s3/create-bucket.curl', str(config))
                result = subprocess.run(command, env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH']},
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(Bucket.attempts, 3)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_initializer_waits_for_dns_then_authenticates_once(self):
        code, attempts, requests = self.run_initializer_dns_fixture(3)
        self.assertEqual(code, 0)
        self.assertEqual(attempts, 3)
        self.assertEqual(requests, ['--connect-timeout 5 --max-time 15 --retry 5 --retry-delay 1 --retry-max-time 20 --config /fixture/s3/create-bucket.curl'])

    def test_initializer_dns_failure_is_bounded_and_never_authenticates(self):
        code, attempts, requests = self.run_initializer_dns_fixture(100)
        self.assertNotEqual(code, 0)
        self.assertEqual(attempts, 60)
        self.assertEqual(requests, [])

    def test_initializer_waits_for_service_health_before_single_authenticated_put(self):
        code, attempts, requests = self.run_initializer_dns_fixture(1, health_ready_after=4)
        self.assertEqual(code, 0)
        self.assertEqual(attempts, 4)
        self.assertEqual(requests, ['--connect-timeout 5 --max-time 15 --retry 5 --retry-delay 1 --retry-max-time 20 --config /fixture/s3/create-bucket.curl'])

    def test_initializer_service_failure_is_bounded_and_never_authenticates(self):
        code, attempts, requests = self.run_initializer_dns_fixture(1, health_ready_after=100)
        self.assertNotEqual(code, 0)
        self.assertEqual(attempts, 60)
        self.assertEqual(requests, [])

    def test_fixture_rejects_state_outside_tmp(self):
        with self.assertRaises(ValueError):
            fixture.prepare('/')

    def test_loopback_tls_fixture_preserves_the_standard_connection_constructor(self):
        source = (SCRIPT.parent / 'test-minikube.sh').read_text()
        program = source.split("<<'PYS3CAPTURE'\n", 1)[1].split('\nPYS3CAPTURE', 1)[0]
        preparation = program.split('client = Client(', 1)[0].replace(
            '/harness/mcp_smoke.py', str(SCRIPT.parent / 'mcp_smoke.py'))
        original = http.client.HTTPSConnection
        namespace = {}
        exec(compile(preparation, '<s3-loopback-fixture>', 'exec'), namespace)
        connection = namespace['LoopbackHTTPS'](
            'backend', 8080, context=ssl.create_default_context(), timeout=1)
        connection.close()
        self.assertIs(http.client.HTTPSConnection, original)
        self.assertIs(namespace['Client'].exchange.__globals__['http'].client.HTTPSConnection,
                      namespace['LoopbackHTTPS'])


if __name__ == '__main__':
    unittest.main()
