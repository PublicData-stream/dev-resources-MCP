"""Bounded edge qualification: no Docker, public network, or retained writes."""
import copy
import errno
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
            return {'returncode': 1, 'stdout': b'[]', 'stderr': b'error: no such object: ' + args[2].encode() + b'\n'}
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
        recorded = json.loads((self.root / 'offline-inspections.json').read_bytes())
        self.assertEqual(recorded['observations'][0]['class'], 'unknown')
        self.assertNotIn('daemon unavailable', (self.root / 'offline-inspections.json').read_text())

    def test_inspection_absence_requires_exact_reference_output_and_finite_grammar(self):
        name = n.CHECKER_NAME
        for message in ('error: no such object: ', 'Error: No such object: ', 'Error response from daemon: No such container: '):
            value = {'returncode': 1, 'stdout': b'[]\n', 'stderr': (message + name + '\n').encode()}
            observations = []
            with patch.object(n, 'command', return_value=value):
                self.assertIsNone(n.inspect_checker(name, observations))
            self.assertEqual(observations[0]['class'], 'absent')
        invalid = [
            {'returncode': 1, 'stdout': b'[]', 'stderr': b'error: no such object: other-name\n'},
            {'returncode': 1, 'stdout': b'[{}]', 'stderr': ('error: no such object: ' + name).encode()},
            {'returncode': 1, 'stdout': b'[]', 'stderr': ('daemon unavailable; no such object: ' + name).encode()},
            {'returncode': 2, 'stdout': b'[]', 'stderr': ('error: no such object: ' + name).encode()},
        ]
        for value in invalid:
            with self.subTest(value=value), patch.object(n, 'command', return_value=value), \
                    self.assertRaisesRegex(n.Refused, 'checker_inspection_unavailable'):
                n.inspect_checker(name)

    def test_diagnostic_persistence_failure_happens_after_owned_cleanup(self):
        docker = Docker(self.value); original = n.save
        def save(path, value):
            if path.name == 'offline-inspections.json':
                raise OSError('evidence_destination_unavailable')
            return original(path, value)
        with patch.object(n, 'command', side_effect=docker.command), patch.object(n, 'save', side_effect=save), \
                self.assertRaisesRegex(OSError, 'evidence_destination_unavailable'):
            n.offline_check(self.value, self.root)
        self.assertTrue(docker.removed)

    def test_cleanup_failure_does_not_replace_primary_failure_or_claim_completion(self):
        docker = Docker(self.value, fail=True)
        original = docker.command
        def command(args, **kwargs):
            if args[:2] == ['docker', 'inspect'] and any(v[:3] == ['docker', 'start', '--attach'] for v in docker.calls):
                return {'returncode': 1, 'stdout': b'', 'stderr': b'daemon unavailable'}
            return original(args, **kwargs)
        with patch.object(n, 'command', side_effect=command), self.assertRaisesRegex(n.Refused, 'native_image_config_check_failed'):
            n.offline_check(self.value, self.root)
        self.assertFalse(docker.removed)
        self.assertFalse(json.loads((self.root / 'offline-cleanup.json').read_bytes())['known_complete'])
        diagnostics = json.loads((self.root / 'offline-inspections.json').read_bytes())
        self.assertTrue(diagnostics['primary_failed']); self.assertTrue(diagnostics['cleanup_failed'])

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
    def execute(self, status=502, version='TLSv1.3', family='ipv4', body=b'upstream request failed'):
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

    def test_only_the_exact_source_defined_upstream_body_qualifies(self):
        for body in (b'request admission unavailable', b'{"error":"upstream request failed"}',
                     b'upstream request failed\n', b'prefix upstream request failed'):
            with self.subTest(body=body), self.assertRaisesRegex(n.Refused, 'withdrawn_public_route_required'):
                self.execute(body=body)


class PrivateEndpoint(unittest.TestCase):
    def probe(self, error, elapsed=3.01, peer_error=errno.ENOTCONN, socket_error=0):
        connection = Mock(); connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False); connection.connect.side_effect = error
        connection.getpeername.side_effect = OSError(peer_error, 'private detail') if peer_error else None
        connection.getsockopt.return_value = socket_error
        with patch.object(n.socket, 'socket', return_value=connection), \
                patch.object(n.time, 'monotonic', side_effect=[100., 100. + elapsed]):
            result = n.negative_connect('127.0.0.1', 30081)
        connection.connect_ex.assert_not_called()
        connection.settimeout.assert_called_once_with(3)
        return result

    def test_bounded_timeout_requires_actual_unconnected_socket(self):
        value = self.probe(TimeoutError('private detail'))
        self.assertFalse(value['connected']); self.assertEqual(value['outcome'], 'socket_timeout')
        self.assertEqual(value['peer_errno'], errno.ENOTCONN)
        self.assertEqual(value['socket_so_error'], 0)
        self.assertIsNone(value['errno']); self.assertNotIn('private', json.dumps(value))

    def test_explicit_transport_denial_is_separate_from_timeout(self):
        value = self.probe(ConnectionRefusedError(errno.ECONNREFUSED, 'private detail'), elapsed=.01)
        self.assertEqual(value['outcome'], 'transport_error'); self.assertEqual(value['errno'], errno.ECONNREFUSED)

    def test_connected_unknown_or_unbounded_outcomes_never_prove_denial(self):
        cases = [(None, 0, errno.ENOTCONN, 0), (OSError(errno.EAGAIN, 'detail'), 3.01, errno.ENOTCONN, 0),
            (TimeoutError('detail'), .01, errno.ENOTCONN, 0), (TimeoutError('detail'), 5.1, errno.ENOTCONN, 0),
            (TimeoutError('detail'), 3.01, 0, 0), (TimeoutError('detail'), 3.01, errno.EBADF, 0),
            (TimeoutError('detail'), 3.01, errno.ENOTCONN, errno.EAGAIN)]
        for error, elapsed, peer, socket_error in cases:
            with self.subTest(error=error, elapsed=elapsed, peer=peer), self.assertRaises(n.Refused):
                self.probe(error, elapsed, peer, socket_error)


class CooldownPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.value = snapshot(self.root)
        config = Path(self.value['docker']['mounts'][0]['Source'])
        self.value['docker']['mounts'][0]['Destination'] = '/etc/oxibelt/config/oxibelt-conf'
        self.files = [config / (str(i) + '.toml') for i in range(16)]
        for p in self.files:
            write(p, b'[http]\nvalue = 1\n')
        self.image = {'Id': self.value['docker']['image'], 'Config': {'Labels': {
            'org.opencontainers.image.revision': n.EDGE_REVISION,
            'org.opencontainers.image.version': '0.11.0-build.4f3154d8',
            'org.opencontainers.image.source': 'https://github.com/OxiBelt/OxiBelt'}}}

    def policy(self):
        with patch.object(n, 'output', return_value=n.encode([self.image])):
            return n.cooldown_policy({'after': self.value})

    def test_spacing_is_bound_to_actual_image_revision_and_no_config_overrides(self):
        result = self.policy()
        self.assertEqual(result['fixed_quiet_ms'], 31000)
        self.assertEqual(result['max_open_timeout_ms'], 30000)
        self.assertEqual(result['configuration_files'], 16)
        self.assertFalse(result['http_503_accepted'])
        self.assertEqual(result['source_sha256'], n.ADMISSION_SOURCES)

    def test_nested_override_foreign_revision_or_inventory_is_refused(self):
        self.image['Config']['Labels']['org.opencontainers.image.revision'] = 'f' * 40
        with self.assertRaisesRegex(n.Refused, 'cooldown_source_revision'):
            self.policy()
        self.image['Config']['Labels']['org.opencontainers.image.revision'] = n.EDGE_REVISION
        write(self.files[0], b'[runtime.circuit_breakers.failure]\nmax_open_timeout_ms = 60000\n')
        with self.assertRaisesRegex(n.Refused, 'override_refused'):
            self.policy()
        self.files[0].unlink()
        with self.assertRaisesRegex(n.Refused, 'fixed_cooldown_configuration'):
            self.policy()

    def test_quiet_period_cannot_be_shortened_or_extended_without_bound(self):
        for elapsed in (30.9, 31., 36.1):
            with self.subTest(elapsed=elapsed), patch.object(n.time, 'sleep') as sleep, \
                    patch.object(n.time, 'monotonic', side_effect=[0., elapsed]):
                if elapsed == 31.:
                    self.assertEqual(n.public_cooldown()['elapsed_ms'], 31000)
                else:
                    with self.assertRaisesRegex(n.Refused, 'fixed_public_cooldown'):
                        n.public_cooldown()
                sleep.assert_called_once_with(31)


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

    def test_source_repair_requires_explicit_bound_continuation_and_preserves_old_work(self):
        self.candidate['qualification_producer_sha256'] = 'a' * 64
        self.candidate['bridge_source_sha256'] = 'b' * 64
        write(self.scope / 'candidate.json', self.candidate)
        self.candidate_sha = n.sha((self.scope / 'candidate.json').read_bytes())
        with self.assertRaisesRegex(n.Refused, 'qualification_source_binding_required'):
            self.qualify()
        self.work.mkdir(mode=0o700); write(self.work / 'intent.json', {'consumed': True})
        old = {p.name: p.read_bytes() for p in self.work.iterdir()}
        continued_work = self.root / 'continuation-work'
        continuation_sha = 'e' * 64
        self.bridge.validate_qualification_continuation = Mock(return_value={
            'candidate_sha256': self.candidate_sha, 'producer_sha256': self.producer_sha})
        with patch.object(n, 'CONTINUATION_WORK', continued_work):
            result = n.qualify(self.candidate_sha, self.bridge_sha, bridge=self.bridge, continuation_sha=continuation_sha)
        self.assertTrue(result['verified'])
        self.bridge.validate_qualification_continuation.assert_called_once_with(continuation_sha, producer_sha=self.producer_sha)
        self.assertEqual({p.name: p.read_bytes() for p in self.work.iterdir()}, old)
        self.assertTrue((continued_work / 'intent.json').exists())
        self.assertEqual(n.offline_check.call_args.kwargs['name'], n.CONTINUATION_CHECKER_NAME)
        receipt = json.loads((self.scope / 'qualification.json').read_bytes())
        self.assertEqual(receipt['qualification_continuation_sha256'], continuation_sha)
        self.assertEqual(receipt['producer_sha256'], self.producer_sha)
        self.assertEqual(json.loads((self.scope / 'candidate.json').read_bytes())['qualification_producer_sha256'], 'a' * 64)

    def test_wrong_continuation_candidate_or_producer_is_refused_before_new_work(self):
        self.bridge.validate_qualification_continuation = Mock(return_value={
            'candidate_sha256': '0' * 64, 'producer_sha256': self.producer_sha})
        with self.assertRaisesRegex(n.Refused, 'qualification_continuation_identity_required'):
            n.qualify(self.candidate_sha, self.bridge_sha, bridge=self.bridge, work=self.work, continuation_sha='e' * 64)
        self.assertFalse(self.work.exists())


class QualificationCompletion(unittest.TestCase):
    def setUp(self):
        QualificationBookends.setUp(self)
        self.completion_sha = 'f' * 64; self.continuation_sha = 'e' * 64
        self.candidate['qualification_producer_sha256'] = '1' * 64
        self.candidate['bridge_source_sha256'] = '2' * 64
        write(self.scope / 'candidate.json', self.candidate)
        self.candidate_sha = n.sha((self.scope / 'candidate.json').read_bytes())
        self.sealed = {'candidate_sha256': self.candidate_sha, 'producer_sha256': self.producer_sha,
            'qualification_continuation_sha256': self.continuation_sha, 'offline': {'verified': True,
                'image': self.value['docker']['image'], 'no_network': True, 'readonly_mounts': True,
                'stdout_sha256': '3' * 64, 'stderr_sha256': n.sha(b'')}}
        self.bridge.validate_qualification_completion = Mock(return_value=self.sealed)
        self.old_work = self.root / 'consumed-continuation-work'; self.old_work.mkdir(mode=0o700)
        write(self.old_work / 'offline-cleanup.json', {'known_complete': True, 'owned_only': True, 'uid': '4' * 64})
        write(self.old_work / 'offline-check.stdout', b'preserved old config proof')
        self.preserved = {p: (p.read_bytes(), p.stat().st_ino) for p in (self.scope / 'candidate.json', *self.old_work.iterdir())}
        self.events = []
        self.extra_patchers = [patch.object(n, 'COMPLETION_WORK', self.work),
            patch.object(n, 'CONTINUATION_WORK', self.old_work),
            patch.object(n, 'cooldown_policy', return_value={'max_open_timeout_ms': 30000, 'configuration_overrides': False}),
            patch.object(n, 'public_cooldown', side_effect=self.quiet)]
        for p in self.extra_patchers:
            p.start(); self.addCleanup(p.stop)
        n.offline_check.side_effect = AssertionError('completion must never create another checker')
        n.public_probe.side_effect = self.public

    def quiet(self):
        self.events.append('quiet-31-seconds')
        return {'required_ms': 31000, 'elapsed_ms': 31000}

    def public(self, family):
        self.events.append(family)
        return {'tls_verified': True, 'withdrawn_http_verified': True, 'certificate_sha256': 'same',
            'http_status': 502, 'body_sha256': n.sha(n.WITHDRAWN_BODY)}

    def complete(self):
        return n.complete(self.candidate_sha, self.bridge_sha, self.completion_sha, bridge=self.bridge)

    def assert_preserved(self):
        self.assertEqual({p: (p.read_bytes(), p.stat().st_ino) for p in self.preserved}, self.preserved)
        n.offline_check.assert_not_called()

    def test_completion_reuses_sealed_offline_success_and_runs_one_spaced_request_per_family(self):
        self.assertTrue(self.complete()['verified'])
        self.assertEqual(self.events, ['quiet-31-seconds', 'ipv6', 'quiet-31-seconds', 'ipv4'])
        self.assertEqual(n.public_probe.call_count, 2)
        self.assertEqual(n.negative_connect.call_count, 2)
        n.optional_quic_probe.assert_called_once_with(self.work)
        self.assertEqual(self.bridge.validate_qualification_completion.call_count, 2)
        self.bridge.candidate_matches_current.assert_called_with(self.candidate, completion_sha=self.completion_sha)
        receipt = json.loads((self.scope / 'qualification.json').read_bytes())
        self.assertEqual(receipt['qualification_completion_sha256'], self.completion_sha)
        self.assertEqual(receipt['qualification_continuation_sha256'], self.continuation_sha)
        self.assertEqual(receipt['producer_sha256'], self.producer_sha)
        self.assertIs(receipt['fixture'], False)
        self.assertIs(receipt['full_public_mcp_acceptance'], False)
        detail = json.loads((self.scope / 'qualification-detail.json').read_bytes())
        self.assertEqual(detail['offline'], self.sealed['offline'])
        self.assertIs(detail['new_checker_allowed'], False)
        self.assertEqual(detail['journal_sha256'], n.sha((self.work / 'completion-journal.json').read_bytes()))
        self.assert_preserved()

    def test_wrong_completion_identity_or_unsealed_offline_proof_fails_before_any_work(self):
        for mutate in (lambda v: v.update(candidate_sha256='0' * 64), lambda v: v.update(producer_sha256='0' * 64),
                       lambda v: v.update(qualification_continuation_sha256=None),
                       lambda v: v['offline'].update(verified=False), lambda v: v['offline'].update(readonly_mounts=False),
                       lambda v: v['offline'].update(image='sha256:' + '0' * 64),
                       lambda v: v['offline'].update(stderr_sha256='unsealed')):
            value = copy.deepcopy(self.sealed); mutate(value)
            self.bridge.validate_qualification_completion.return_value = value
            with self.subTest(value=value), self.assertRaises(n.Refused):
                self.complete()
            self.assertFalse(self.work.exists())
        n.public_probe.assert_not_called(); n.public_cooldown.assert_not_called()
        self.assert_preserved()

    def test_first_public_503_fails_without_retry_or_second_family(self):
        n.public_probe.side_effect = n.Refused('withdrawn_public_route_required')
        with self.assertRaisesRegex(n.Refused, 'withdrawn_public_route_required'):
            self.complete()
        self.assertEqual(self.events, ['quiet-31-seconds'])
        n.public_probe.assert_called_once_with('ipv6')
        n.negative_connect.assert_not_called()
        self.assertFalse((self.scope / 'qualification.json').exists())
        failure = json.loads((self.work / 'completion-failure.json').read_bytes())
        self.assertEqual(failure['phase'], 'public-ipv6'); self.assertEqual(failure['failure'], 'refused')
        self.assert_preserved()

    def test_native_control_policy_or_seal_drift_cannot_publish_receipt(self):
        self.bridge.candidate_matches_current.side_effect = [True, False]
        with self.assertRaisesRegex(n.Refused, 'runtime_bookend_changed'):
            self.complete()
        self.assertFalse((self.scope / 'qualification.json').exists())
        self.assertEqual(json.loads((self.work / 'completion-failure.json').read_bytes())['phase'], 'control-after')
        self.assert_preserved()

    def test_changed_historical_proof_at_final_bookend_is_rejected(self):
        self.bridge.validate_qualification_completion.side_effect = [self.sealed, {**self.sealed, 'changed': True}]
        with self.assertRaisesRegex(n.Refused, 'runtime_bookend_changed'):
            self.complete()
        self.assertFalse((self.scope / 'qualification.json').exists()); self.assert_preserved()

    def test_actual_config_override_prevents_wait_and_public_requests(self):
        n.cooldown_policy.side_effect = n.Refused('cooldown_configuration_override_refused')
        with self.assertRaisesRegex(n.Refused, 'override_refused'):
            self.complete()
        n.public_probe.assert_not_called(); n.public_cooldown.assert_not_called()
        self.assert_preserved()

    def test_consumed_completion_cannot_replay_after_success_or_failure(self):
        n.public_probe.side_effect = n.Refused('withdrawn_public_route_required')
        with self.assertRaises(n.Refused):
            self.complete()
        n.public_probe.reset_mock(); n.public_cooldown.reset_mock()
        with self.assertRaisesRegex(n.Refused, 'fresh_qualification_completion_work_required'):
            self.complete()
        n.public_probe.assert_not_called(); n.public_cooldown.assert_not_called()
        self.assert_preserved()

    def test_failure_retention_never_exposes_details_or_replaces_original_exception(self):
        primary = OSError('PRIVATE_TRANSPORT_CONFIGURATION'); n.public_probe.side_effect = primary
        with self.assertRaises(OSError) as caught:
            self.complete()
        self.assertIs(caught.exception, primary)
        body = (self.work / 'completion-failure.json').read_bytes()
        self.assertNotIn(b'PRIVATE', body); self.assertEqual(json.loads(body)['failure'], 'unknown')
        self.assertFalse((self.scope / 'qualification.json').exists()); self.assert_preserved()


class QualificationCLI(unittest.TestCase):
    def test_explicit_completion_mode_does_not_dispatch_qualify(self):
        args = ['edge-qualification.py', '--candidate-sha256', 'a' * 64, '--bridge-sha256', 'b' * 64,
            '--qualification-completion-sha256', 'c' * 64]
        with patch.object(sys, 'argv', args), patch.object(n.os, 'geteuid', return_value=0), \
                patch.object(n.os, 'umask') as umask, \
                patch.object(n, 'complete', return_value={'verified': True}) as complete, \
                patch.object(n, 'qualify') as qualify, patch('sys.stdout', new_callable=io.StringIO):
            n.main()
        complete.assert_called_once_with('a' * 64, 'b' * 64, 'c' * 64); qualify.assert_not_called()
        umask.assert_called_once_with(0o077)

    def test_continuation_and_completion_flags_are_mutually_exclusive(self):
        args = ['edge-qualification.py', '--candidate-sha256', 'a' * 64, '--bridge-sha256', 'b' * 64,
            '--qualification-completion-sha256', 'c' * 64, '--qualification-continuation-sha256', 'd' * 64]
        with patch.object(sys, 'argv', args), patch.object(n.os, 'umask') as umask, patch.object(n, 'complete') as complete, \
                patch.object(n, 'qualify') as qualify, patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            n.main()
        complete.assert_not_called(); qualify.assert_not_called()
        umask.assert_called_once_with(0o077)


class ActualBridgeCompletion(unittest.TestCase):
    def test_producer_and_actual_bridge_share_sealed_offline_and_admission_contract(self):
        fixture_spec = importlib.util.spec_from_file_location('cycle4_completion_bridge_fixture',
            ROOT / 'scripts/tests/test_cycle4_edge_3dae7d91.py')
        fixture_module = importlib.util.module_from_spec(fixture_spec)
        sys.modules[fixture_spec.name] = fixture_module; fixture_spec.loader.exec_module(fixture_module)
        fixture = fixture_module.QualificationCompletion(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        bridge = fixture_module.n; previous = fixture.fixture
        write(previous.qualifier, Path(n.__file__).read_bytes())
        previous.producer_sha = n.sha(previous.qualifier.read_bytes())
        prepared = fixture.prepare(); completion_sha = prepared['qualification_completion_sha256']
        tcp = b'LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("oxibelt",pid=20,fd=9))\n'
        public = {'tls_verified': True, 'withdrawn_http_verified': True, 'certificate_sha256': 'same',
            'http_status': 502, 'body_sha256': n.sha(n.WITHDRAWN_BODY)}
        with (patch.object(n, 'SCOPE', fixture.scope), patch.object(n, 'COMPLETION_WORK', fixture.completion_work),
              patch.object(bridge, 'qualification_context', return_value={'bindings': {'frozen': 'same'}}),
              patch.object(n, 'control_snapshot', return_value={'retained': 'same'}),
              patch.object(n, 'cooldown_policy', return_value={'max_open_timeout_ms': 30000}),
              patch.object(n, 'public_cooldown', return_value={'required_ms': 31000, 'elapsed_ms': 31000}),
              patch.object(n, 'public_probe', return_value=public) as probes,
              patch.object(n, 'output', return_value=tcp),
              patch.object(n, 'negative_connect', return_value={'connected': False}),
              patch.object(n, 'optional_quic_probe', return_value={'status': 'deferred'}),
              patch.object(n, 'command', side_effect=AssertionError('no checker command')),
              patch.object(n, 'offline_check', side_effect=AssertionError('no checker')) as offline):
            result = n.complete(previous.old_candidate_sha, n.sha(Path(bridge.__file__).read_bytes()),
                completion_sha, bridge=bridge)
        offline.assert_not_called()
        self.assertEqual([c.args[0] for c in probes.call_args_list], ['ipv6', 'ipv4'])
        admitted = bridge.admit(previous.old_candidate_sha, fixture.scope / 'qualification.json',
            result['qualification_sha256'], previous.producer_sha, completion_sha=completion_sha)
        with patch.object(bridge, 'source_guard', return_value={'frozen': 'hash'}), \
                patch.object(bridge, '_retained_bindings', return_value={'frozen': 'same'}):
            receipt = bridge._receipt(admitted['admission_sha256'])
            self.assertEqual(receipt['qualification']['qualification_completion_sha256'], completion_sha)
            self.assertEqual(receipt['qualification']['qualification_continuation_sha256'], fixture.control_sha)
            write(fixture.work / 'offline-check.stdout', b'changed retained proof')
            with self.assertRaisesRegex(bridge.Refused, 'successful_offline_artifact_changed'):
                bridge._receipt(admitted['admission_sha256'])


if __name__ == '__main__':
    unittest.main()
