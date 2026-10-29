import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('staging_operator', ROOT / 'deploy/staging/staging.py')
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)


class ConfigurationTests(unittest.TestCase):
    def test_cli_imports_without_shadowing_python_standard_modules(self):
        import subprocess
        import sys
        result = subprocess.run([sys.executable, str(ROOT / 'deploy/staging/staging.py'), '--help'], cwd=ROOT / 'deploy/staging', capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('edge-activate', result.stdout)

    def test_additive_array_preserves_other_policy(self):
        source = '[tls]\nserver_names = ["existing.example"]\nmin_version = "tls1.3"\n'
        result = op.append_array(source, 'tls', 'server_names', 'new.example')
        self.assertEqual(result, '[tls]\nserver_names = ["existing.example", "new.example"]\nmin_version = "tls1.3"\n')
        self.assertEqual(op.append_array(result, 'tls', 'server_names', 'new.example'), result)

    def test_changed_layout_fails_without_rewriting(self):
        with self.assertRaises(op.OperatorError):
            op.append_array('[tls]\nserver_names = [\n"old.example",\n]\n', 'tls', 'server_names', 'new.example')

    def test_compose_update_preserves_unrelated_services(self):
        source = 'services:\n  oxibelt:\n    extra_hosts:\n    - openlegal-k8s:10.0.0.1\n  unrelated:\n    image: keep\n'
        result = op.add_host(source)
        self.assertEqual(result, source.replace('    - openlegal-k8s:10.0.0.1\n', '    - openlegal-k8s:10.0.0.1\n    - devres-k8s:10.0.0.1\n'))
        self.assertEqual(op.add_host(result), result)
        with self.assertRaises(op.OperatorError):
            op.add_host('services: {}\n')

    def test_secret_has_no_last_applied_or_secret_arguments(self):
        with tempfile.TemporaryDirectory() as root:
            secret = Path(root) / 'secret'
            secret.write_text('sensitive-test-value')
            calls = []
            with patch.object(op, 'k', side_effect=lambda *args, **kw: calls.append((args, kw))):
                op.secret('devres-config', {'backend.toml': secret})
        args, kwargs = calls[0]
        self.assertIn('--server-side', args)
        self.assertNotIn('sensitive-test-value', str(args))
        obj = json.loads(kwargs['data'])
        self.assertNotIn('annotations', obj['metadata'])
        self.assertEqual(obj['metadata']['namespace'], 'devres-staging')

    def test_atomic_write_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'target'
            target.write_text('original')
            link = Path(root) / 'link'
            link.symlink_to(target)
            with self.assertRaises(op.OperatorError):
                op.write(link, 'changed')
            self.assertEqual(target.read_text(), 'original')


class FirewallTests(unittest.TestCase):
    def evaluate(self, address):
        calls = []
        def fake(args, data=None, timeout=240):
            calls.append((args, data))
            if args[:2] == ['docker', 'inspect']:
                return json.dumps([{'NetworkSettings': {'Networks': {'openlegal4everyone-net': {'IPAddress': address}}}}])
            if args[:3] == ['docker', 'network', 'inspect']:
                return json.dumps([{'Options': {'com.docker.network.bridge.name': 'openlegal-edge0'}}])
            return ''
        with patch.object(op, 'run', side_effect=fake), patch.object(op.subprocess, 'run') as sub:
            sub.return_value.returncode = 1
            if address == '10.0.0.3':
                op.firewall()
            else:
                with self.assertRaisesRegex(op.OperatorError, 'ports_fenced'):
                    op.firewall()
        return calls[-1][1]

    def test_expected_topology_admits_only_edge(self):
        rules = self.evaluate('10.0.0.3')
        self.assertEqual(rules.count(' accept\n'), 2)
        self.assertIn('ip daddr 10.0.0.1 ip saddr 10.0.0.3 iifname "openlegal-edge0" tcp dport 30081 accept', rules)
        self.assertIn('fib daddr type local udp dport 30434 drop', rules)
        self.assertNotIn('openlegal_nodeport_guard', rules)

    def test_topology_drift_installs_drop_before_failure(self):
        rules = self.evaluate('10.0.0.9')
        self.assertNotIn(' accept\n', rules)
        self.assertEqual(rules.count(' drop\n'), 2)


class RecoveryTests(unittest.TestCase):
    def test_prepare_api_failure_does_not_rewrite_credentials_or_storage(self):
        with patch.object(op, 'private_dirs'), patch.object(op, 'run', side_effect=op.OperatorError('command_failed:k3s')), patch.object(op, 'dataset') as ds:
            with self.assertRaises(op.OperatorError):
                op.prepare()
            ds.assert_not_called()

    def test_zero_replicas_with_terminating_writer_refuses_prepare(self):
        with patch.object(op, 'private_dirs'), patch.object(op, 'run', return_value='namespace/devres-staging'), patch.object(op, 'k', side_effect=[json.dumps({'items': [{'spec': {'replicas': 0}}]}), json.dumps({'items': [{'metadata': {'deletionTimestamp': 'now'}}]})]), patch.object(op, 'dataset') as ds:
            with self.assertRaisesRegex(op.OperatorError, 'writer_termination'):
                op.prepare()
            ds.assert_not_called()

    def test_failed_rollback_restart_can_retry_restored_baseline(self):
        import hashlib
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state, edge = root / 'state', root / 'edge'
            previous = state / 'edge-previous'
            baseline, installed = {}, {}
            owned = ('oxibelt-conf/10-tls.toml', 'oxibelt-conf/20-proxy.toml', 'docker-compose.yml')
            for name in owned:
                live, old = edge / name, previous / name
                live.parent.mkdir(parents=True, exist_ok=True)
                old.parent.mkdir(parents=True, exist_ok=True)
                live.write_text('new configuration')
                old.write_text('old configuration')
                baseline[name] = hashlib.sha256(old.read_bytes()).hexdigest()
                installed[name] = hashlib.sha256(live.read_bytes()).hexdigest()
            for snippet in op.SNIPPETS:
                name = 'oxibelt-conf/' + snippet
                (edge / name).write_text('new snippet')
                installed[name] = hashlib.sha256((edge / name).read_bytes()).hexdigest()
            (previous / 'activated.json').write_text(json.dumps({'baseline': baseline, 'installed': installed, 'phase': 'activated'}))
            with patch.object(op, 'EDGE', edge), patch.object(op, 'STATE', state), patch.object(op, 'firewall'), patch.object(op, 'run', side_effect=[op.OperatorError('command_failed:docker'), '']):
                with self.assertRaises(op.OperatorError):
                    op.edge_activate(True)
                op.edge_activate(True)
            self.assertTrue(all((edge / name).read_text() == 'old configuration' for name in owned))


if __name__ == '__main__':
    unittest.main()
