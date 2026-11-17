"""Bounded edge qualification: no Docker, public network, or retained writes."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('cycle4_edge_qualifier_tests', ROOT / 'deploy/production/cycle4_edge_qualification_3dae7d91.py')
n = importlib.util.module_from_spec(spec); sys.modules[spec.name] = n; spec.loader.exec_module(n)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(value if type(value) is bytes else n.encode(value)); path.chmod(0o600)


def snapshot(root):
    config = root / 'config'; config.mkdir(exist_ok=True)
    return {'edge': {'image': 'sha256:' + 'a' * 64, 'id': 'b' * 64, 'pid': 123},
        'docker': {'image': 'sha256:' + 'a' * 64, 'config': {'User': '10001:10001'},
            'mounts': [{'Type': 'bind', 'Source': str(config), 'Destination': '/etc/oxibelt/config', 'RW': False}]}}


class Docker:
    def __init__(self, value, fail=False):
        self.snapshot = value; self.created = False; self.removed = False; self.calls = []; self.fail = fail
        self.uid = 'c' * 64; self.name = 'devres-edge-check-3dae7d91'

    def inspect(self):
        return {'Id': self.uid, 'Name': '/' + self.name, 'Image': self.snapshot['docker']['image'],
            'Config': {'Labels': {'devres.edge-qualification': '3dae7d91'}, 'Entrypoint': ['/usr/local/bin/oxibelt'],
                'User': self.snapshot['docker']['config']['User'],
                'Cmd': ['--config', '/etc/oxibelt/config/oxibelt.toml', '--check']},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'Privileged': False,
                'Memory': 512 * 1024 ** 2, 'PidsLimit': 64,
                'SecurityOpt': ['no-new-privileges']},
            'Mounts': copy.deepcopy(self.snapshot['docker']['mounts']), 'State': {'Status': 'exited', 'ExitCode': int(self.fail)}}

    def command(self, args, **kwargs):
        self.calls.append(args)
        if args[:2] == ['docker', 'inspect']:
            if self.created and not self.removed:
                return {'returncode': 0, 'stdout': n.encode([self.inspect()]), 'stderr': b''}
            return {'returncode': 1, 'stdout': b'[]', 'stderr': b'Error: No such object: owned-checker'}
        if args[:2] == ['docker', 'create']:
            self.created = True
            return {'returncode': 0, 'stdout': self.uid.encode() + b'\n', 'stderr': b''}
        if args[:3] == ['docker', 'start', '--attach']:
            return {'returncode': int(self.fail), 'stdout': b'configuration checked', 'stderr': b''}
        if args[:3] == ['docker', 'rm', '--force']:
            if args[-1] != self.uid:
                raise AssertionError('name-based cleanup')
            self.removed = True
            return {'returncode': 0, 'stdout': b'', 'stderr': b''}
        raise AssertionError(args)


class NativeCheck(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.value = snapshot(self.root)

    def test_checker_uses_exact_image_numeric_user_network_none_and_readonly_mounts(self):
        args = n.checker_arguments(self.value, 'owned')
        self.assertEqual(args[args.index('--network') + 1], 'none')
        self.assertIn('--read-only', args); self.assertIn('ALL', args)
        self.assertEqual(args[args.index('--user') + 1], '10001:10001')
        self.assertEqual(args[-4:], [self.value['docker']['image'], '--config', '/etc/oxibelt/config/oxibelt.toml', '--check'])
        self.assertTrue(args[args.index('--mount') + 1].endswith(',readonly'))

    def test_mount_syntax_foreign_image_or_user_is_rejected(self):
        for modify in (lambda v: v['docker']['mounts'][0].update(Source='/private,path'),
                lambda v: v['docker']['mounts'][0].update(Type='volume'),
                lambda v: v['docker'].update(image='mutable:latest'),
                lambda v: v['docker']['config'].update(User='root')):
            value = copy.deepcopy(self.value); modify(value)
            with self.assertRaises(n.Refused):
                n.checker_arguments(value, 'owned')

    def test_native_check_cleans_up_by_uid_before_returning(self):
        docker = Docker(self.value)
        with patch.object(n, 'command', side_effect=docker.command):
            result = n.offline_check(self.value, self.root)
        self.assertTrue(result['verified']); self.assertTrue(docker.removed)
        self.assertTrue(json.loads((self.root / 'offline-cleanup.json').read_bytes())['known_complete'])

    def test_native_failure_still_cleans_up_and_never_passes(self):
        docker = Docker(self.value, fail=True)
        with patch.object(n, 'command', side_effect=docker.command), self.assertRaisesRegex(n.Refused, 'native_image_config_check_failed'):
            n.offline_check(self.value, self.root)
        self.assertTrue(docker.removed)

    def test_unknown_inspection_failure_is_not_treated_as_absence(self):
        with patch.object(n, 'command', return_value={'returncode': 1, 'stdout': b'', 'stderr': b'daemon unavailable'}), \
                self.assertRaisesRegex(n.Refused, 'checker_inspection_unavailable'):
            n.offline_check(self.value, self.root)
        self.assertFalse((self.root / 'offline-create.stdout').exists())

    def test_checker_cannot_cleanup_foreign_container_or_writable_mount(self):
        docker = Docker(self.value)
        for mutate in (lambda v: v.update(Id='d' * 64),
                lambda v: v['HostConfig'].update(NetworkMode='host'),
                lambda v: v['Config']['Labels'].update({'devres.edge-qualification': 'other'}),
                lambda v: v['Mounts'][0].update(RW=True)):
            obj = docker.inspect(); mutate(obj)
            with self.assertRaises(n.Refused):
                n.checker_identity(obj, self.value, docker.name, docker.uid)


class CommandBounds(unittest.TestCase):
    def test_bounded_command_retains_exact_finite_bytes(self):
        value = n.command([sys.executable, '-c', "import sys;sys.stdout.write('ok');sys.stderr.write('finite')"], limit=128)
        self.assertEqual(value, {'returncode': 0, 'stdout': b'ok', 'stderr': b'finite'})

    def test_output_bound_kills_owned_process(self):
        with self.assertRaisesRegex(n.Refused, 'qualification_command_output_bound'):
            n.command([sys.executable, '-c', "import sys;sys.stdout.write('x'*65536)"], limit=64)

    def test_deadline_kills_owned_process(self):
        with self.assertRaisesRegex(n.Refused, 'qualification_command_deadline'):
            n.command([sys.executable, '-c', 'import time;time.sleep(5)'], timeout=.03)


class PublicTLS(unittest.TestCase):
    def execute(self, status=502, version='TLSv1.3', family='ipv4'):
        body = b'{"error":"upstream request failed"}'
        response = f'HTTP/1.1 {status} status\r\nContent-Length: {len(body)}\r\n\r\n'.encode() + body
        tls = Mock(); tls.__enter__ = Mock(return_value=tls); tls.__exit__ = Mock(return_value=False)
        tls.version.return_value = version; tls.selected_alpn_protocol.return_value = 'http/1.1'
        tls.makefile.return_value = io.BytesIO(response)
        expiry = time.strftime('%b %d %H:%M:%S %Y GMT', time.gmtime(time.time() + 2 * 86400))
        tls.getpeercert.side_effect = lambda binary_form=False: b'certificate' if binary_form else {'notAfter': expiry}
        connection = Mock(); connection.__enter__ = Mock(return_value=connection); connection.__exit__ = Mock(return_value=False)
        context = Mock(); context.wrap_socket.return_value = tls
        with patch.object(n.ssl, 'create_default_context', return_value=context), patch.object(n.socket, 'socket', return_value=connection):
            result = n.public_probe(family)
        return result, connection, context

    def test_real_tls_policy_withdrawn_response_and_fixed_family_address(self):
        for family in ('ipv4', 'ipv6'):
            result, connection, context = self.execute(family=family)
            self.assertTrue(result['tls_verified']); self.assertFalse(result['full_mcp_acceptance'])
            connection.connect.assert_called_once_with((n.ADDRESSES[family], 443))
            self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], n.HOST)
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)

    def test_successful_mcp_or_wrong_tls_does_not_qualify_withdrawal(self):
        for status, version in ((200, 'TLSv1.3'), (503, 'TLSv1.3'), (502, 'TLSv1.2')):
            with self.subTest(status=status, version=version), self.assertRaises(n.Refused):
                self.execute(status, version)


class ListenerControls(unittest.TestCase):
    def test_listeners_bind_to_exact_native_pid_on_both_transports(self):
        tcp = b'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("oxibelt",pid=123,fd=9))\n'
        udp = b'UNCONN 0 0 [::]:443 [::]:* users:(("oxibelt",pid=123,fd=10))\n'
        self.assertTrue(n.validate_listeners({'edge': {'pid': 123}}, tcp, udp)['verified'])
        for changed in (udp.replace(b'pid=123', b'pid=1234'), b'', udp.replace(b':443', b':444')):
            with self.assertRaises(n.Refused):
                n.validate_listeners({'edge': {'pid': 123}}, tcp, changed)

    def test_timer_requires_exact_source_and_original_bundle(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            operator = Path(temporary) / 'operator.py'; write(operator, b'# fixed operator')
            helper = Path(temporary) / 'helper.py'; write(helper, b'# other first-party code')
            context = {'sources': {str(p): n.sha(p.read_bytes()) for p in (operator, helper)},
                'operator_bundle': Path('/var/lib/original'), 'operator_module': SimpleNamespace(__file__=str(operator))}
            text = '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 ' + str(operator) + ' --context default --bundle /var/lib/original capacity ; ignore_errors=no ; }'
            self.assertEqual(n.validate_timer_entrypoint(text, 'capacity', context)['operation'], 'capacity')
            for modified in (text.replace(str(operator), str(helper)), text.replace('/var/lib/original', '/other'), text.replace('capacity', 'withdraw')):
                with self.assertRaises(n.Refused):
                    n.validate_timer_entrypoint(modified, 'capacity', context)


class FirewallControls(unittest.TestCase):
    def rules(self):
        match = lambda left, right: {'match': {'op': '==', 'left': left, 'right': right}}
        expressions = []
        for protocol, port in (('tcp', 30081), ('udp', 30434)):
            expressions.append([match({'meta': {'key': 'iifname'}}, 'devres-edge0'),
                match({'payload': {'protocol': 'ip', 'field': 'saddr'}}, '10.0.0.3'),
                match({'payload': {'protocol': 'ip', 'field': 'daddr'}}, '10.0.0.1'),
                match({'payload': {'protocol': protocol, 'field': 'dport'}}, port), {'accept': None}])
        for protocol, port in (('tcp', 30081), ('udp', 30434)):
            expressions.append([match({'payload': {'protocol': protocol, 'field': 'dport'}}, port), {'drop': None}])
        return {'nftables': [{'metainfo': {'json_schema_version': 1}}, {'table': {'family': 'inet', 'name': 'devres_guard'}},
            {'chain': {'family': 'inet', 'table': 'devres_guard', 'name': 'nodeports', 'type': 'filter',
                'hook': 'prerouting', 'prio': -310, 'policy': 'accept'}}] + [
            {'rule': {'family': 'inet', 'table': 'devres_guard', 'chain': 'nodeports', 'expr': expr}} for expr in expressions]}

    def test_exact_four_rules_and_priority_are_required(self):
        self.assertEqual(len(n.nft_expressions(self.rules())), 64)
        variants = []
        value = self.rules(); value['nftables'][2]['chain']['prio'] = 0; variants.append(value)
        value = self.rules(); value['nftables'][3]['rule']['expr'][1]['match']['right'] = '0.0.0.0/0'; variants.append(value)
        value = self.rules(); value['nftables'][-1]['rule']['expr'][-1] = {'accept': None}; variants.append(value)
        value = self.rules(); value['nftables'].pop(); variants.append(value)
        value = self.rules(); value['nftables'].append({'rule': copy.deepcopy(value['nftables'][-1]['rule'])}); variants.append(value)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(n.Refused):
                n.nft_expressions(value)


class OptionalQUIC(unittest.TestCase):
    def test_unavailable_binary_support_is_explicitly_deferred(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary, patch.object(n, 'command', return_value={
                'returncode': 0, 'stdout': b'help without optional transport', 'stderr': b''}):
            result = n.optional_quic_probe(Path(temporary))
        self.assertEqual(result['status'], 'deferred')
        self.assertIs(result['native_webtransport_acceptance'], False)

    def test_advertised_quic_support_must_actually_verify_both_certificates(self):
        help_ = {'returncode': 0, 'stdout': b'-quic', 'stderr': b''}
        verified = {'returncode': 0, 'stdout': b'', 'stderr': b'Verification: OK'}
        failed = {'returncode': 1, 'stdout': b'', 'stderr': b'failed'}
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary, patch.object(n, 'command', side_effect=[help_, verified, failed]), \
                self.assertRaisesRegex(n.Refused, 'available_quic_tls_probe_failed'):
            n.optional_quic_probe(Path(temporary))
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary, patch.object(n, 'command', side_effect=[help_, verified, verified]):
            result = n.optional_quic_probe(Path(temporary))
        self.assertEqual(result['status'], 'transport_tls_only')
        self.assertEqual(set(result['cells']), {'ipv4', 'ipv6'})
        self.assertIs(result['native_webtransport_acceptance'], False)


class QualificationBookends(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.scope = self.root / 'scope'; self.scope.mkdir(mode=0o700)
        self.work = self.root / 'work'; self.value = snapshot(self.root)
        self.producer_sha = n.sha(Path(n.__file__).read_bytes()); self.bridge_sha = 'd' * 64
        self.candidate = {'revision': n.REVISION, 'qualification_producer_sha256': self.producer_sha,
            'bridge_source_sha256': self.bridge_sha, 'after': self.value}
        write(self.scope / 'candidate.json', self.candidate)
        self.candidate_sha = n.sha((self.scope / 'candidate.json').read_bytes())
        self.bridge = SimpleNamespace(candidate_matches_current=Mock(return_value=True),
            qualification_context=Mock(return_value={'bindings': {'retained': 'same'}}))
        self.patchers = [patch.object(n, 'SCOPE', self.scope),
            patch.object(n, 'control_snapshot', return_value={'policy': 'unchanged'}),
            patch.object(n, 'offline_check', return_value={'verified': True, 'no_network': True}),
            patch.object(n, 'validate_listeners', return_value={'verified': True}),
            patch.object(n, 'output', return_value=b'closed'),
            patch.object(n, 'public_probe', return_value={'tls_verified': True, 'withdrawn_http_verified': True, 'certificate_sha256': 'same'}),
            patch.object(n, 'negative_connect', return_value={'connected': False}),
            patch.object(n, 'optional_quic_probe', return_value={'status': 'deferred', 'reason': 'openssl_quic_unavailable'})]
        for p in self.patchers:
            p.start(); self.addCleanup(p.stop)

    def qualify(self):
        return n.qualify(self.candidate_sha, self.bridge_sha, bridge=self.bridge, work=self.work)

    def test_only_complete_sourcebound_bookends_emit_narrow_receipt(self):
        result = self.qualify(); self.assertTrue(result['verified'])
        receipt = json.loads((self.scope / 'qualification.json').read_bytes())
        self.assertEqual(set(receipt['checks']), n.CHECKS)
        self.assertTrue(all(receipt['checks'].values()))
        self.assertIs(receipt['fixture'], False)
        self.assertIs(receipt['full_public_mcp_acceptance'], False)
        self.assertIs(receipt['native_webtransport_acceptance'], False)
        artifact = receipt['artifacts'][0]
        self.assertEqual(n.sha(Path(artifact['path']).read_bytes()), artifact['sha256'])

    def test_changed_native_or_retained_controls_emit_no_receipt(self):
        self.bridge.candidate_matches_current.side_effect = [True, False]
        with self.assertRaisesRegex(n.Refused, 'runtime_bookend_changed'):
            self.qualify()
        self.assertFalse((self.scope / 'qualification.json').exists())

    def test_bad_source_pin_fails_before_work_or_checks(self):
        with self.assertRaisesRegex(n.Refused, 'external_candidate_hash'):
            n.qualify('0' * 64, self.bridge_sha, bridge=self.bridge, work=self.work)
        self.assertFalse(self.work.exists())

    def test_false_offline_or_tls_result_cannot_be_promoted_to_true(self):
        n.offline_check.return_value = {'verified': False, 'no_network': True}
        with self.assertRaisesRegex(n.Refused, 'complete_available_edge_checks'):
            self.qualify()
        self.assertFalse((self.scope / 'qualification.json').exists())

    def test_existing_work_intent_forbids_replay(self):
        self.qualify()
        with self.assertRaisesRegex(n.Refused, 'fresh_qualification_work'):
            self.qualify()


if __name__ == '__main__':
    unittest.main()
