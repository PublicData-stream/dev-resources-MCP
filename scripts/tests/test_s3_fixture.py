import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest
import http.client
import ssl
import os
import subprocess


SCRIPT = Path(__file__).resolve().parents[1] / 's3-kubernetes-fixture.py'
SPEC = importlib.util.spec_from_file_location('s3_kubernetes_fixture', SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


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

    def run_initializer_dns_fixture(self, ready_after):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            scripts = {
                'getent': '#!/bin/sh\nn=$(cat "$DNS_PROBE_COUNT" 2>/dev/null || echo 0)\n'
                          'n=$((n+1)); echo "$n" > "$DNS_PROBE_COUNT"\n'
                          'test "$n" -ge "$DNS_READY_AFTER"\n',
                'sleep': '#!/bin/sh\nexit 0\n',
                'curl': '#!/bin/sh\nprintf "%s\\n" "$*" >> "$DNS_AUTH_REQUESTS"\n',
            }
            for name, source in scripts.items():
                path = root / name
                path.write_text(source)
                path.chmod(0o700)
            command = fixture.initializer('fixture-image:local')['spec']['template']['spec']['containers'][0]['command']
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                               DNS_PROBE_COUNT=str(root / 'count'), DNS_READY_AFTER=str(ready_after),
                               DNS_AUTH_REQUESTS=str(root / 'requests'))
            result = subprocess.run(command, env=environment, capture_output=True, timeout=5)
            requests = (root / 'requests').read_text().splitlines() if (root / 'requests').exists() else []
            return result.returncode, int((root / 'count').read_text()), requests

    def test_initializer_waits_for_dns_then_authenticates_once(self):
        code, attempts, requests = self.run_initializer_dns_fixture(3)
        self.assertEqual(code, 0)
        self.assertEqual(attempts, 3)
        self.assertEqual(requests, ['--connect-timeout 5 --max-time 15 --config /fixture/s3/create-bucket.curl'])

    def test_initializer_dns_failure_is_bounded_and_never_authenticates(self):
        code, attempts, requests = self.run_initializer_dns_fixture(100)
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
