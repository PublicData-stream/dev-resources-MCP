"""Verify lifecycle admission and native encryption fixture boundaries."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


control = load('split_control', 'split-runtime-control.py')
encryption = load('secrets_encryption', 'secrets-encryption-fixture.py')


class SplitRuntimeTests(unittest.TestCase):
    def invoke(self, operation, missing=None):
        calls = []

        def execute(args, **_):
            calls.append(args)
            self.assertEqual(args[:6], ['kubectl', '--context', 'selected', '--namespace', 'isolated', '--request-timeout=30s'])
            if args[6] == 'get':
                name = args[8]
                if name == missing:
                    raise subprocess.CalledProcessError(1, args)
                return json.dumps({'metadata': {'name': name, 'namespace': 'isolated'},
                                   'spec': {'replicas': 1, 'template': {'spec': {'containers': [
                                       {'command': ['devres-server', 'collect', '/config.toml']} ]}}}}).encode()
            return b''

        with patch.object(control.subprocess, 'check_output', side_effect=execute):
            if missing:
                with self.assertRaises(subprocess.CalledProcessError):
                    control.run('selected', 'isolated', operation, 's3')
            else:
                control.run('selected', 'isolated', operation, 's3')
        return [args[6:] for args in calls]

    def test_missing_component_never_scales_existing_workloads(self):
        calls = self.invoke('start', missing='writer')
        self.assertTrue(all(call[0] == 'get' for call in calls))

    def test_status_is_read_only_and_stop_waits_before_stopping_writer(self):
        self.assertTrue(all(call[0] == 'get' for call in self.invoke('status')))
        mutations = [call for call in self.invoke('stop') if call[0] != 'get']
        self.assertEqual([call[:3] for call in mutations], [
            ['scale', 'deployment/backend', '--replicas=0'], ['wait', '--for=delete', 'pod'],
            ['scale', 'deployment/writer', '--replicas=0'], ['wait', '--for=delete', 'pod']])

    def test_start_waits_for_broker_then_writer_before_serving(self):
        mutations = [call for call in self.invoke('start') if call[0] != 'get']
        self.assertEqual([call[1] for call in mutations if call[0] == 'scale'],
                         ['deployment/credential-broker', 'deployment/writer', 'deployment/backend'])
        self.assertEqual([call[0] for call in mutations], ['scale', 'rollout'] * 3)

    def test_encryption_fixture_requires_private_tmp_and_datastore_ciphertext(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            encryption.prepare(root)
            config = root / '.minikube/files/var/lib/minikube/certs/devres-encryption.json'
            data = json.loads(config.read_text())
            self.assertIn('secretbox', data['resources'][0]['providers'][0])
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            value = root / 'value'
            for invalid in (b'plaintext', encryption.SENTINEL, b'k8s:enc:secretbox:v1:devres-fixture:' + encryption.SENTINEL):
                value.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    encryption.verify(value)
            value.write_bytes(b'k8s:enc:secretbox:v1:devres-fixture:opaque-synthetic-ciphertext')
            encryption.verify(value)


if __name__ == '__main__':
    unittest.main()
