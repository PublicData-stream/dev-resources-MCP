"""Exercise synthetic admission, restrictions and failure assertions without a cluster."""
import importlib.util
import contextlib
import copy
import hashlib
import io
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import types
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'npm-assessment-fixture.py'
SPEC = importlib.util.spec_from_file_location('npm_assessment_fixture', SCRIPT)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)

IDENTITY = {'expected_artifact': 'sha256:' + '1' * 64, 'matched_artifact': 'sha256:' + '1' * 64,
            'runtime_reference_digest': 'sha256:' + '2' * 64, 'resolved_cri_id': 'sha256:' + '3' * 64,
            'known_digests': ['sha256:' + '1' * 64, 'sha256:' + '3' * 64],
            'expected_configs': ['sha256:' + '3' * 64], 'resolved_config': 'sha256:' + '3' * 64}


class SyntheticFixtureTests(unittest.TestCase):
    def setUp(self):
        context = patch.dict(os.environ, {'DOCKER_CONTEXT': ''})
        context.start()
        self.addCleanup(context.stop)

    def test_owned_node_admission_refuses_foreign_labels_and_host_pid_mode(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary, socket.socket(socket.AF_UNIX) as endpoint:
            path = Path(temporary) / 'docker.sock'
            endpoint.bind(str(path))
            cluster = types.SimpleNamespace(profile='devres-acceptance-fixture')
            valid = {'Id': '1' * 64, 'Name': '/' + cluster.profile,
                'Config': {'Labels': {'created_by.minikube.sigs.k8s.io': 'true',
                                     'name.minikube.sigs.k8s.io': cluster.profile}},
                'HostConfig': {'Privileged': True, 'PidMode': '', 'NetworkMode': cluster.profile},
                'State': {'Running': True, 'Pid': 1234}}
            with patch.dict(os.environ, {'DEVRES_TMP_STATE': '1', 'DOCKER_HOST': 'unix://' + str(path)}):
                for change in ('none', 'foreign-owner', 'foreign-name', 'not-privileged', 'host-pid', 'host-network'):
                    value = copy.deepcopy(valid)
                    if change == 'foreign-owner': value['Config']['Labels']['created_by.minikube.sigs.k8s.io'] = 'false'
                    if change == 'foreign-name': value['Config']['Labels']['name.minikube.sigs.k8s.io'] = 'foreign'
                    if change == 'not-privileged': value['HostConfig']['Privileged'] = False
                    if change == 'host-pid': value['HostConfig']['PidMode'] = 'host'
                    if change == 'host-network': value['HostConfig']['NetworkMode'] = 'host'
                    with self.subTest(change=change), patch.object(fixture, 'command', return_value=
                         subprocess.CompletedProcess([], 0, json.dumps([value]).encode(), b'')) as calls:
                        if change == 'none':
                            self.assertEqual(fixture.node_docker_identity(cluster), {'container_id': '1' * 64, 'container_pid': 1234})
                        else:
                            with self.assertRaisesRegex(fixture.FixtureError, 'fixture_node_identity'):
                                fixture.node_docker_identity(cluster)
                        self.assertEqual(calls.call_args.args[0], ['docker', 'inspect', '--', cluster.profile])

    def test_owned_node_admission_refuses_shared_or_non_socket_endpoints(self):
        for endpoint in ('unix:///var/run/docker.sock', 'unix:///tmp/../var/run/docker.sock'):
            with self.subTest(endpoint=endpoint), patch.dict(os.environ, {'DEVRES_TMP_STATE': '1', 'DOCKER_HOST': endpoint}), \
                 patch.object(fixture, 'command') as calls:
                with self.assertRaisesRegex(fixture.FixtureError, 'fixture_owned_docker_required'):
                    fixture.node_docker_identity(types.SimpleNamespace(profile='devres-acceptance-fixture'))
                calls.assert_not_called()

    def test_docker_context_override_is_refused_before_any_docker_consumer(self):
        identity = {'container_id': '1' * 64, 'container_pid': 1234}
        operations = (
            lambda: fixture.node_docker_identity(types.SimpleNamespace(profile='devres-acceptance-fixture')),
            lambda: fixture.node_exec(identity, 'systemctl', 'restart', 'containerd'),
            lambda: fixture.expected_image_identity('candidate:server'),
            lambda: fixture.docker_config_digests('candidate:server'),
        )
        with patch.dict(os.environ, {'DEVRES_TMP_STATE': '1', 'DOCKER_HOST': 'unix:///tmp/owned/docker.sock',
                                    'DOCKER_CONTEXT': 'alternate-context'}), \
             patch.object(fixture.subprocess, 'run') as run, patch.object(fixture.subprocess, 'Popen') as popen:
            for operation in operations:
                with self.assertRaises(fixture.FixtureError):
                    operation()
            run.assert_not_called()
            popen.assert_not_called()

    def test_namespace_freshness_requires_successful_authoritative_absence(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-fixture', Path(temporary))
            arguments = types.SimpleNamespace(scratch=temporary, profile=cluster.profile,
                                              harness_image='harness:fixture', server_image='candidate:server')
            for result in (subprocess.CompletedProcess([], 1, b'{"apiVersion":"v1","kind":"NamespaceList","items":[]}', b'NotFound or private API failure'),
                           subprocess.CompletedProcess([], 0, b'{"apiVersion":"v1","kind":"NamespaceList","items":[{"metadata":{"name":"devres-assessment"}}]}', b'')):
                with self.subTest(code=result.returncode), patch.object(fixture, 'Cluster', return_value=cluster), \
                     patch.object(cluster, 'k', return_value=result) as calls, \
                     patch.object(fixture, 'prepare_node_apparmor') as prepare, patch.object(fixture, 'receipt'):
                    with self.assertRaises(fixture.FixtureError):
                        fixture.run(arguments)
                    prepare.assert_not_called()
                    self.assertGreater(calls.call_count, 0)
                    self.assertTrue(all(call.args[0] == 'get' for call in calls.call_args_list))
            with patch.object(cluster, 'k', return_value=subprocess.CompletedProcess([], 0, b'{"apiVersion":"v1","kind":"NamespaceList","items":[]}', b'')):
                self.assertEqual(cluster.owned_objects('namespace'), [])

    def test_owned_absence_uses_exact_raw_api_schema_and_refuses_unknown_responses(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-fixture', Path(temporary))
            for kind, version, expected, endpoint, namespace in (
                    ('namespace', 'v1', 'NamespaceList', '/api/v1/namespaces?fieldSelector=metadata.name%3Ddevres-assessment', fixture.NAMESPACE),
                    ('policy', 'networking.k8s.io/v1', 'NetworkPolicyList', '/apis/networking.k8s.io/v1/namespaces/devres-acceptance/networkpolicies?fieldSelector=metadata.name%3Dpostgres-owned-assessment', 'devres-acceptance')):
                body = {'apiVersion': version, 'kind': expected, 'items': []}
                with self.subTest(kind=kind), patch.object(cluster, 'k', return_value=subprocess.CompletedProcess([], 0, json.dumps(body).encode(), b'')) as calls:
                    self.assertEqual(cluster.owned_objects(kind), [])
                    calls.assert_called_once_with('get', '--raw=' + endpoint, namespace=namespace)
                for response in ({'apiVersion': 'v1', 'kind': 'List', 'items': []},
                                 {'apiVersion': 'unknown/v1', 'kind': expected, 'items': []},
                                 {'apiVersion': version, 'kind': 'Status', 'status': 'Failure'},
                                 {'apiVersion': version, 'kind': expected, 'items': None}):
                    with self.subTest(kind=kind, response=response), patch.object(cluster, 'k', return_value=subprocess.CompletedProcess([], 0, json.dumps(response).encode(), b'')):
                        with self.assertRaisesRegex(fixture.FixtureError, 'fixture_owned_resource_list'):
                            cluster.owned_objects(kind)
                with patch.object(cluster, 'k', side_effect=subprocess.TimeoutExpired(['private'], 30)):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        cluster.owned_objects(kind)
                with patch.object(cluster, 'k', return_value=subprocess.CompletedProcess([], 1, b'{"kind":"Status","reason":"Forbidden"}', b'private')):
                    with self.assertRaisesRegex(fixture.FixtureError, 'fixture_owned_resource_unavailable'):
                        cluster.owned_objects(kind)

    def test_owned_namespace_and_policy_cleanup_reconcile_uid_but_refuse_foreign_replacements(self):
        owner = '0' * 32
        original = '12345678-1234-1234-1234-123456789abc'
        replacement = '23456789-1234-1234-1234-123456789abc'
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            for kind in ('namespace', 'policy'):
                cluster = fixture.Cluster('devres-acceptance-fixture', Path(temporary))
                cluster.fixture_owner = owner
                for scenario in ('uncertain-apply', 'replacement', 'foreign-owner'):
                    setattr(cluster, kind + '_uid', None if scenario == 'uncertain-apply' else original)
                    metadata = {'uid': replacement if scenario == 'replacement' else original,
                                'labels': {fixture.FIXTURE_OWNER_LABEL: 'foreign' if scenario == 'foreign-owner' else owner}}
                    objects = [{'metadata': metadata}]
                    with self.subTest(kind=kind, scenario=scenario), \
                         patch.object(cluster, 'owned_objects', side_effect=[objects, []]), \
                         patch.object(cluster, 'k', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as calls:
                        if scenario == 'uncertain-apply':
                            cluster.cleanup_owned(kind)
                            deletion = calls.call_args_list[0]
                            self.assertEqual(deletion.args[:1], ('delete',))
                            self.assertTrue(deletion.args[1].startswith('--raw='))
                            self.assertEqual(json.loads(deletion.kwargs['data'])['preconditions'], {'uid': original})
                            self.assertFalse(any('--uid' in arg for arg in deletion.args))
                            self.assertEqual(getattr(cluster, kind + '_uid'), original)
                        else:
                            with self.assertRaises(fixture.FixtureError):
                                cluster.cleanup_owned(kind)
                            calls.assert_not_called()

    def test_namespace_create_conflict_cannot_adopt_or_delete_a_foreign_namespace(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-fixture', Path(temporary))
            original = fixture.FixtureError('fixture_command_failed')
            namespace_reads = [[], [{'metadata': {'name': fixture.NAMESPACE,
                'uid': '12345678-1234-1234-1234-123456789abc',
                'labels': {fixture.FIXTURE_OWNER_LABEL: 'foreign-owner'}}}]]
            calls = []
            def query(*args, **kwargs):
                calls.append((args, kwargs))
                if args[:2] == ('get', '--raw=/api/v1/namespaces?fieldSelector=metadata.name%3Ddevres-assessment'):
                    items = namespace_reads.pop(0) if len(namespace_reads) > 1 else namespace_reads[0]
                    return subprocess.CompletedProcess([], 0, json.dumps({'apiVersion': 'v1', 'kind': 'NamespaceList', 'items': items}).encode(), b'')
                if args[:2] == ('get', '--raw=/apis/networking.k8s.io/v1/namespaces/devres-acceptance/networkpolicies?fieldSelector=metadata.name%3Dpostgres-owned-assessment'):
                    return subprocess.CompletedProcess([], 0, b'{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicyList","items":[]}', b'')
                if args[0] == 'create': raise original
                raise AssertionError(args)
            records = []
            arguments = types.SimpleNamespace(scratch=temporary, profile=cluster.profile,
                                              harness_image='harness:fixture', server_image='candidate:server')
            with patch.object(fixture, 'Cluster', return_value=cluster), patch.object(cluster, 'k', side_effect=query), \
                 patch.object(fixture, 'prepare_node_apparmor'), \
                 patch.object(fixture, 'apparmor', return_value=contextlib.nullcontext(fixture.APPARMOR_SHA256)), \
                 patch.object(fixture, 'receipt', side_effect=lambda _cluster, _name, record: records.append(record)):
                with self.assertRaises(fixture.FixtureError) as caught:
                    fixture.run(arguments)
            self.assertIs(caught.exception, original)
            self.assertEqual([args[0] for args, _ in calls if args[0] != 'get'], ['create'])
            self.assertEqual(records[0]['namespace_cleanup'], 'incomplete')
            self.assertEqual(records[0]['phase'], 'namespace')

    def test_postgres_process_requires_actual_uid_container_and_bounded_restart_count(self):
        pod = {'metadata': {'uid': '12345678-1234-1234-1234-123456789abc'},
               'status': {'containerStatuses': [{'ready': True, 'containerID': 'containerd://' + '2' * 64,
                                                 'restartCount': 0}]}}
        for field, value in (('valid', None), ('containerID', None), ('containerID', ''),
                             ('containerID', 'containerd://not-a-digest'), ('uid', None),
                             ('uid', 'replacement'), ('uid', '-' * 36), ('restartCount', 2**31)):
            with self.subTest(field=field, value=value):
                candidate = copy.deepcopy(pod)
                if field == 'uid': candidate['metadata']['uid'] = value
                elif field != 'valid': candidate['status']['containerStatuses'][0][field] = value
                cluster = types.SimpleNamespace(k=unittest.mock.Mock(return_value=
                    subprocess.CompletedProcess([], 0, json.dumps({'items': [candidate]}).encode(), b'')))
                if field == 'valid':
                    self.assertEqual(fixture.postgres_process(cluster)['container_id'], 'containerd://' + '2' * 64)
                else:
                    with self.assertRaisesRegex(fixture.FixtureError, 'fixture_postgres_process'):
                        fixture.postgres_process(cluster)

    def test_containerd_restart_admission_requires_process_stop_mode(self):
        identity = {'container_id': '1' * 64, 'container_pid': 1234}
        with patch.object(fixture, 'node_exec', return_value=subprocess.CompletedProcess([], 0, b'control-group\n', b'')) as calls, \
             patch.object(fixture, 'node_process') as process:
            with self.assertRaisesRegex(fixture.FixtureError, 'fixture_containerd_stop_mode'):
                fixture.containerd_process(identity)
            self.assertEqual(calls.call_args.args[1:], ('systemctl', 'show', '--property=KillMode', '--value', 'containerd'))
            process.assert_not_called()

    def test_node_process_rejects_foreign_executable_and_records_exact_start_identity(self):
        identity = {'container_id': '1' * 64, 'container_pid': 1234}
        fields = ['S', '1'] + ['0'] * 17 + ['4242']
        outputs = [b'/usr/bin/containerd\n', ('700 (containerd) ' + ' '.join(fields)).encode(),
                   ('7' * 64 + '  /proc/700/exe\n').encode()]
        with patch.object(fixture, 'node_exec', side_effect=[subprocess.CompletedProcess([], 0, value, b'') for value in outputs]):
            process, parent = fixture.node_process(identity, 700, 'containerd')
        self.assertEqual(process, {'pid': 700, 'start_ticks': 4242, 'binary_sha256': '7' * 64})
        self.assertEqual(parent, 1)
        with patch.object(fixture, 'node_exec', return_value=subprocess.CompletedProcess([], 0, b'/usr/bin/foreign-helper\n', b'')) as calls:
            with self.assertRaisesRegex(fixture.FixtureError, 'fixture_node_runtime_process'):
                fixture.node_process(identity, 700, 'containerd')
            self.assertEqual(calls.call_count, 1)

    def test_node_preparation_guards_host_namespace_propagation_and_identity(self):
        before_mount = b'1 0 0:1 / / rw shared:10 - overlay overlay rw\n2 1 0:2 / /sys rw shared:11 - sysfs sysfs rw\n'
        after_mount = before_mount + b'3 2 0:3 / /sys/kernel/security ro,nosuid,nodev,noexec - securityfs securityfs rw\n'
        identity = {'container_id': '1' * 64, 'container_pid': 1234}
        postgres = {'uid': '2' * 8 + '-' + '2' * 4 + '-' + '2' * 4 + '-' + '2' * 4 + '-' + '2' * 12,
                    'container_id': 'containerd://' + '2' * 64, 'restart_count': 0}
        uid = '1' * 8 + '-' + '1' * 4 + '-' + '1' * 4 + '-' + '1' * 4 + '-' + '1' * 12
        daemon = {'pid': 90, 'start_ticks': 900, 'binary_sha256': '5' * 64, 'kill_mode': 'process'}
        runtime = {'pid': 2000, 'start_ticks': 3000,
                   'shim': {'pid': 1999, 'start_ticks': 2999, 'binary_sha256': '6' * 64}}
        for scenario in ('fresh', 'ready', 'host-namespace', 'host-propagation', 'lost-intent', 'host-changed',
                         'postgres-replaced', 'shim-replaced', 'daemon-replaced'):
            with self.subTest(scenario=scenario):
                cluster = types.SimpleNamespace(profile='devres-acceptance-fixture', k=unittest.mock.Mock())
                mutations, records = [], []
                mounts = [after_mount, after_mount] if scenario == 'ready' else [before_mount, after_mount]
                if scenario == 'host-propagation': mounts[0] = before_mount.replace(b'shared:11', b'shared:3')
                def execute(_identity, *args, **_kwargs):
                    self.assertEqual(_identity, identity)
                    if args == ('readlink', '/proc/1/ns/mnt'): output = b'mnt:[20]\n'
                    elif args == ('cat', '/proc/self/mountinfo'): output = mounts.pop(0)
                    elif args == ('cat', '/sys/module/apparmor/parameters/enabled'): output = b'Y\n'
                    elif args[:2] == ('/bin/sh', '-c'):
                        output = b''
                        if 'mount -t' in args[2]:
                            self.assertIn('ro,nosuid,nodev,noexec', args[2])
                            self.assertLess(args[2].index('test "$(readlink'), args[2].index('mount -t'))
                            self.assertGreaterEqual(args[2].count('\n'), 4)
                            mutations.append('mount')
                    elif args == ('systemctl', 'restart', 'kubelet'):
                        output = b'';mutations.append('kubelet')
                    elif args == ('systemctl', 'restart', 'containerd'):
                        output = b'';mutations.append('containerd')
                    else: raise AssertionError(args)
                    return subprocess.CompletedProcess([], 0, output, b'')
                def save(_cluster, name, value):
                    fixture.validate_receipt(name, value)
                    records.append((name, value))
                    return scenario != 'lost-intent'
                host_namespace = 'mnt:[20]' if scenario == 'host-namespace' else 'mnt:[10]'
                states = [(host_namespace, '3' * 64, {'shared:3'})] * 4
                if scenario == 'host-changed': states[1] = (host_namespace, '4' * 64, {'shared:3'})
                with patch.object(fixture, 'node_docker_identity', return_value=identity), \
                     patch.object(fixture, 'node_uid', return_value=uid), \
                     patch.object(fixture, 'node_namespace', return_value='mnt:[20]'), \
                     patch.object(fixture, 'host_mount_state', side_effect=states), \
                     patch.object(fixture, 'node_exec', side_effect=execute), \
                     patch.object(fixture, 'kubelet_process', side_effect=[100, 100 if scenario == 'ready' else 200]), \
                     patch.object(fixture, 'containerd_process', side_effect=[daemon,
                         {**daemon, 'pid': 91} if scenario == 'daemon-replaced' else daemon,
                         {**daemon, 'pid': 190, 'start_ticks': 1900}]), \
                     patch.object(fixture, 'postgres_runtime', side_effect=[runtime,
                         {**runtime, 'shim': {**runtime['shim'], 'pid': 2999}} if scenario == 'shim-replaced' else runtime]), \
                     patch.object(fixture, 'postgres_process', side_effect=[postgres,
                         {**postgres, 'uid': '3' * 8 + '-' + '3' * 4 + '-' + '3' * 4 + '-' + '3' * 4 + '-' + '3' * 12}
                         if scenario == 'postgres-replaced' else postgres]), \
                     patch.object(fixture, 'receipt', side_effect=save):
                    if scenario in ('fresh', 'ready'):
                        result = fixture.prepare_node_apparmor(cluster, 'candidate:server')
                        self.assertEqual(result['state'], 'complete')
                        self.assertEqual(mutations, [] if scenario == 'ready' else ['mount', 'containerd', 'kubelet'])
                        self.assertEqual(result['before']['postgres'], result['after']['postgres'])
                        self.assertEqual(cluster.k.call_count, 2)
                        malformed = copy.deepcopy(result)
                        malformed['identity']['node_uid'] = '-' * 36
                        with self.assertRaises(fixture.FixtureError):
                            fixture.validate_receipt('npm-assessment-node-preparation.json', malformed)
                    else:
                        with self.assertRaises(fixture.FixtureError):
                            fixture.prepare_node_apparmor(cluster, 'candidate:server')
                        if scenario in ('postgres-replaced', 'shim-replaced'):
                            self.assertEqual(mutations, ['mount', 'containerd', 'kubelet'])
                            self.assertEqual(cluster.k.call_count, 2)
                        else:
                            self.assertEqual(mutations, ['mount'] if scenario in ('host-changed', 'daemon-replaced') else [])
                            self.assertNotIn('kubelet', mutations)
                            cluster.k.assert_not_called()

    def test_apply_groups_explicit_namespaces_without_changing_policy_grants(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-fixture', Path(temporary))
            documents = fixture.policies()
            original = copy.deepcopy(documents)
            completed = subprocess.CompletedProcess([], 0, b'', b'')
            with patch.object(cluster, 'k', return_value=completed) as commands:
                self.assertIs(cluster.apply(documents), completed)
            self.assertEqual(documents, original)
            self.assertEqual([call.kwargs['namespace'] for call in commands.call_args_list],
                             [fixture.NAMESPACE, 'devres-acceptance'])
            for call in commands.call_args_list:
                items = json.loads(call.kwargs['data'])['items']
                self.assertTrue(all(item['metadata']['namespace'] == call.kwargs['namespace'] for item in items))
            self.assertEqual(sum(len(json.loads(call.kwargs['data'])['items']) for call in commands.call_args_list), 3)

    def test_apply_validates_all_namespaces_before_any_command(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-fixture', Path(temporary))
            documents = fixture.policies()
            documents[-1]['metadata']['namespace'] = 'untrusted namespace'
            with patch.object(cluster, 'k') as commands:
                with self.assertRaisesRegex(fixture.FixtureError, 'fixture_apply_namespace_invalid'):
                    cluster.apply(documents)
                commands.assert_not_called()

    def test_command_failure_keeps_only_closed_operation_exit_and_byte_counts(self):
        arguments = ['minikube', '-p', 'PRIVATE_PROFILE', 'kubectl', '--', '-n', 'PRIVATE_NAMESPACE',
                     'apply', '-f', 'PRIVATE_CONFIGURATION']
        result = subprocess.CompletedProcess(arguments, 1, b'PRIVATE_REPORT', b'PRIVATE_SECRET')
        with patch.object(fixture.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(fixture.FixtureError, '^fixture_command_failed$') as caught:
                fixture.command(arguments, data=b'PRIVATE_INPUT')
        metadata = fixture.closed_failure(caught.exception)
        self.assertEqual(metadata['command_outcome'], {'command': 'kubectl.apply', 'outcome': 'nonzero',
            'exit_code': 1, 'stdout_bytes': 14, 'stderr_bytes': 14})
        self.assertNotIn('PRIVATE', json.dumps(metadata))

    def test_command_timeout_preserves_exception_type_without_retaining_private_bytes(self):
        original = subprocess.TimeoutExpired(['PRIVATE_COMMAND'], 3, output=b'PRIVATE_REPORT', stderr=b'PRIVATE_SECRET')
        with patch.object(fixture.subprocess, 'run', side_effect=original):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                fixture.command(['docker', 'image', 'inspect', 'PRIVATE_IMAGE'])
        self.assertIs(caught.exception, original)
        metadata = fixture.closed_failure(original)
        self.assertEqual(metadata['code'], 'fixture_command_timeout')
        self.assertEqual(metadata['command_outcome'], {'command': 'docker-metadata', 'outcome': 'timeout',
            'exit_code': None, 'stdout_bytes': None, 'stderr_bytes': None})
        self.assertNotIn('PRIVATE', json.dumps(metadata))

    def test_unknown_errors_and_untrusted_command_metadata_are_not_retained(self):
        error = fixture.FixtureError('PRIVATE_ERROR')
        error.command_outcome = {'command': 'PRIVATE_COMMAND', 'stderr': 'PRIVATE_SECRET'}
        self.assertEqual(fixture.closed_failure(error), {'code': 'unknown', 'command_outcome': None})

    def test_network_failure_metadata_is_process_bound_and_contains_no_output(self):
        pod = {'metadata': {'uid': 'owned'}, 'status': {'phase': 'Failed', 'containerStatuses': [
            {'containerID': 'containerd://owned', 'restartCount': 0,
             'state': {'terminated': {'reason': 'Error', 'exitCode': 1}}}]}}
        output = b'PRIVATE_TRACEBACK: assessment egress unexpectedly admitted local API\n'
        for changed in (False, True):
            after = copy.deepcopy(pod)
            if changed:
                after['metadata']['uid'] = 'replacement'
            cluster = types.SimpleNamespace(k=unittest.mock.Mock(side_effect=[
                subprocess.CompletedProcess([], 0, json.dumps(pod).encode(), b''),
                subprocess.CompletedProcess([], 0, output, b''),
                subprocess.CompletedProcess([], 0, json.dumps(after).encode(), b'')]))
            value = fixture.network_failure_metadata(cluster, 'owned')
            fixture.validate_probe_failure(value)
            self.assertEqual(value['network'], 'unknown' if changed else 'api_admitted')
            self.assertNotIn('PRIVATE', json.dumps(value))
            self.assertNotIn('owned', json.dumps(value))
            self.assertTrue(all(call.kwargs['timeout'] == 5 for call in cluster.k.call_args_list))
        with self.assertRaises(fixture.FixtureError):
            fixture.validate_probe_failure({**value, 'stderr': 'PRIVATE_SECRET'})

    def test_network_probe_inspects_failure_before_uid_cleanup_and_preserves_error(self):
        for cleanup_failure in (False, True):
            with self.subTest(cleanup_failure=cleanup_failure):
                events = []
                error = fixture.FixtureError('fixture_command_failed')
                metadata = {'pod_phase': 'Failed', 'container_reason': 'Error', 'exit_code': 1, 'network': 'api_admitted'}
                def delete(name, uid):
                    events.append(('delete', name, uid))
                    if cleanup_failure:
                        raise fixture.FixtureError('assessment_cleanup_uid_changed')
                cluster = types.SimpleNamespace(apply=lambda _pod: events.append('apply'),
                    pod=lambda _name: {'metadata': {'uid': 'owned'}},
                    k=unittest.mock.Mock(side_effect=error), delete=delete)
                def inspect(_cluster, uid):
                    events.append(('inspect', uid))
                    return metadata
                with patch.object(fixture, 'network_failure_metadata', side_effect=inspect):
                    with self.assertRaises(fixture.FixtureError) as caught:
                        fixture.network_probe(cluster, 'harness:fixture')
                self.assertIs(caught.exception, error)
                self.assertEqual(error.probe_metadata, metadata)
                self.assertEqual(events, ['apply', ('inspect', 'owned'), ('delete', 'assessment-network', 'owned')])

    def test_setup_failure_receipt_rejects_private_fields_and_unbounded_counters(self):
        value = {'version': 1, 'synthetic': True, 'phase': 'policy', 'case': 'none',
            'failure': {'code': 'fixture_command_failed', 'command_outcome': None},
            'cleanup_failure': None, 'namespace_cleanup': 'removed', 'apparmor_cleanup': 'removed'}
        fixture.validate_receipt('npm-assessment-setup-failure.json', value)
        for replacement in ({**value, 'stderr': 'PRIVATE_SECRET'}, {**value, 'phase': 'PRIVATE_PHASE'},
                            {**value, 'case': 'PRIVATE_CASE'}, {**value, 'failure': None}):
            with self.subTest(replacement=replacement), self.assertRaises(fixture.FixtureError):
                fixture.validate_receipt('npm-assessment-setup-failure.json', replacement)
        outcome = {'command': 'kubectl.apply', 'outcome': 'nonzero', 'exit_code': 1,
                   'stdout_bytes': 0, 'stderr_bytes': fixture.MAX_METADATA + 2}
        value['failure']['command_outcome'] = outcome
        with self.assertRaises(fixture.FixtureError):
            fixture.validate_receipt('npm-assessment-setup-failure.json', value)

    def test_setup_failure_preserves_primary_and_attempts_every_cleanup_before_receipt(self):
        for failed_phase, cleanup_failure, lost_receipt in (('policy', False, False), ('namespace', False, False),
                                                           ('policy', True, False), ('policy', False, True),
                                                           ('network', True, False), ('none', True, False)):
            with self.subTest(phase=failed_phase, cleanup_failure=cleanup_failure, lost_receipt=lost_receipt), \
                 tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                events = []
                primary = fixture.FixtureError('fixture_command_failed')
                cleanup = fixture.FixtureError('fixture_command_failed')
                class Cluster:
                    profile = 'devres-acceptance-fixture'
                    scratch = Path(temporary)
                    def apply(self, objects):
                        phase = 'policy' if isinstance(objects, list) else 'namespace' if objects['kind'] == 'Namespace' else 'identity'
                        events.append(('apply', phase))
                        if phase == failed_phase:
                            raise primary
                    def create(self, objects): return self.apply(objects)
                    def k(self, *args, **kwargs):
                        events.append(('command', args[:2]))
                        if args[:2] == ('get', 'namespace'):
                            return subprocess.CompletedProcess([], 1, b'', b'')
                        if args[:2] == ('delete', 'namespace') and cleanup_failure:
                            raise cleanup
                        return subprocess.CompletedProcess([], 0, b'{"items":[]}', b'')
                    def owned_objects(self, _kind): return []
                    def admit_owned(self, _kind): return '12345678-1234-1234-1234-123456789abc'
                    def cleanup_owned(self, kind):
                        return self.k('delete', 'namespace' if kind == 'namespace' else 'networkpolicy')
                cluster = Cluster()
                (cluster.scratch / 'fixture').mkdir()
                (cluster.scratch / 'fixture/backend.toml').write_text('synthetic configuration')
                @contextlib.contextmanager
                def policy(_scratch, stopped):
                    try:
                        yield fixture.APPARMOR_SHA256
                    finally:
                        events.append(('apparmor-cleanup', stopped()))
                        if not stopped():
                            raise fixture.FixtureError('apparmor_cleanup_incomplete_profile_retained')
                records = []
                def save(_cluster, name, record):
                    events.append(('receipt', name))
                    if name == 'npm-assessment-receipt.json':
                        return
                    fixture.validate_receipt(name, record)
                    records.append(record)
                    if lost_receipt:
                        raise OSError('PRIVATE_DIAGNOSTIC_ERROR')
                arguments = types.SimpleNamespace(scratch=temporary, profile=cluster.profile,
                                                  harness_image='harness:fixture', server_image='candidate:server')
                with patch.object(fixture, 'Cluster', return_value=cluster), patch.object(fixture, 'apparmor', side_effect=policy), \
                     patch.object(fixture, 'prepare_node_apparmor'), \
                     patch.object(fixture, 'receipt', side_effect=save), \
                     patch.object(fixture, 'configuration', return_value='synthetic configuration'), \
                     patch.object(fixture, 'network_probe', side_effect=primary if failed_phase == 'network' else None), patch.object(fixture, 'seed'), \
                     patch.object(fixture, 'snapshot', return_value={}), patch.object(fixture, 'failure_matrix'), \
                     patch.object(fixture, 'assess', return_value={'phase': 'report_transferred'}) as assessment:
                    with self.assertRaises(fixture.FixtureError) as caught:
                        fixture.run(arguments)
                self.assertIs(caught.exception, cleanup if failed_phase == 'none' else primary)
                if failed_phase == 'none':
                    assessment.assert_called_once()
                else:
                    assessment.assert_not_called()
                self.assertIn(('command', ('delete', 'namespace')), events)
                if failed_phase != 'namespace':
                    self.assertIn(('command', ('delete', 'networkpolicy')), events)
                self.assertEqual(events[-1], ('receipt', 'npm-assessment-setup-failure.json'))
                self.assertNotIn(('receipt', 'npm-assessment-receipt.json'), events)
                self.assertEqual(records[0]['phase'], 'cleanup' if failed_phase == 'none' else failed_phase)
                self.assertEqual(records[0]['namespace_cleanup'], 'removed')
                self.assertEqual(records[0]['apparmor_cleanup'], 'unknown' if cleanup_failure else 'removed')
                self.assertEqual(records[0]['cleanup_failure'] is not None, cleanup_failure)

    def test_pauses_every_provider_without_replacing_unrelated_configuration(self):
        original = '[storage]\ndatabase_url="fixture-old"\nblob_dir="/unmounted/cache"\n[npm]\nenabled=true\nadvisories_enabled=true\npackages=["first-party-fixture"]\n[limits]\ncall_timeout_secs=30\n'
        value = tomllib.loads(fixture.configuration(original))
        self.assertEqual(value['storage'], {'database_url': fixture.DATABASE_READER, 'blob_dir': '/unmounted/cache'})
        self.assertEqual(value['limits'], {'call_timeout_secs': 30})
        for provider in ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'wikipedia', 'npm'):
            self.assertFalse(value[provider]['enabled'])
        self.assertFalse(value['npm']['advisories_enabled'])
        self.assertEqual(value['npm']['packages'], ['first-party-fixture'])
        with self.assertRaisesRegex(fixture.FixtureError, 'one_fixture_database'):
            fixture.configuration(original + '[other]\ndatabase_url="second"\n')

    def test_real_helper_preserves_confined_runtime_and_private_termination(self):
        api = fixture.helper()
        selected = api.Selection('blake3:' + '1' * 64)
        pod = api.build_assessment_pod(fixture.template('candidate:server'), 'candidate:server', selected,
                                       name='fixture-assessment', namespace=fixture.NAMESPACE)
        spec = pod['spec']
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertEqual(spec['securityContext']['seccompProfile'], {'type': 'RuntimeDefault'})
        self.assertEqual({item['name'] for item in spec['volumes']}, {'config', 's3', 'tmp'})
        self.assertEqual(next(item for item in spec['volumes'] if item['name'] == 'tmp')['emptyDir'], {'sizeLimit': '16Mi'})
        container = spec['containers'][0]
        self.assertEqual(container['securityContext']['appArmorProfile'], {'type': 'Localhost', 'localhostProfile': 'devres-runtime'})
        self.assertEqual(container['terminationMessagePolicy'], 'File')
        self.assertNotEqual(container['terminationMessagePath'], api.REPORT)
        self.assertNotIn('env', container)
        self.assertEqual(container['command'][:5], ['/usr/bin/timeout', '--signal=TERM', '--kill-after=5s', '420s', '/bin/sh'])

    def test_assessment_network_permits_only_dns_and_owned_postgres(self):
        policies = fixture.policies()
        default = policies[0]['spec']
        self.assertEqual(default, {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']})
        outbound = policies[1]['spec']['egress']
        self.assertEqual({(port['port'], port['protocol']) for rule in outbound for port in rule['ports']}, {(53, 'TCP'), (53, 'UDP'), (5432, 'TCP')})
        self.assertFalse(any('ipBlock' in destination for rule in outbound for destination in rule['to']))
        self.assertEqual(outbound[1]['to'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'], 'devres-acceptance')
        self.assertEqual(policies[2]['spec']['ingress'][0]['from'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name'], fixture.NAMESPACE)

    def test_effective_runtime_accepts_only_expected_policy_and_finite_metadata(self):
        payload = (b'APPARMOR=devres-runtime (enforce)\nSECCOMP=2\nNO_NEW_PRIVS=1\n'
                   b'CAP_EFF=0000000000000000\nCONFIG=0:65532:440\nTMP=0:65532:2777\n')
        self.assertEqual(fixture.validate_runtime(payload)['SECCOMP'], '2')
        for old, new in ((b'(enforce)', b'(complain)'), (b'SECCOMP=2', b'SECCOMP=0'),
                         (b'CAP_EFF=0000000000000000', b'CAP_EFF=0000000000000001'),
                         (b'CONFIG=0:65532:440', b'CONFIG=0:0:444')):
            with self.subTest(new=new), self.assertRaises(fixture.FixtureError):
                fixture.validate_runtime(payload.replace(old, new))

    def test_receipt_is_private_create_new_and_bounded(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            path = Path(temporary) / 'receipt.json'
            fixture.private_json(path, {'synthetic': True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_bytes()), {'synthetic': True})
            with self.assertRaises(FileExistsError):
                fixture.private_json(path, {})

    def test_constructed_receipts_survive_scratch_cleanup_in_owned_tmp_diagnostics(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary)
            scratch = root / 'scratch'
            scratch.mkdir()
            cluster = fixture.Cluster('devres-acceptance-123-fixture', scratch)
            value = {'version': 1, 'synthetic': True, 'result': {'case': 'malformed-config', 'phase': 'terminal', 'exit_code': 1, 'diagnostics': None, 'image_identity': IDENTITY}}
            name = 'case-assessment-malformed-config-result.json'
            with patch.dict(os.environ, {'DEVRES_E2E_DIAGNOSTICS_DIR': str(root / 'retained')}):
                self.assertTrue(fixture.receipt(cluster, name, value))
            (scratch / name).unlink()
            retained = root / 'retained' / cluster.profile / name
            self.assertEqual(json.loads(retained.read_bytes()), value)
            self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
            with patch.dict(os.environ, {'DEVRES_E2E_DIAGNOSTICS_DIR': '/var/lib/unowned'}):
                self.assertFalse(fixture.receipt(cluster, name, value))
            self.assertTrue(cluster.receipt_failures)

    def test_invalid_or_unwritable_retention_cannot_mask_original_child_failure(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-123-fixture', Path(temporary))
            result = {'case': 'malformed-config', 'phase': 'terminal', 'exit_code': 1, 'diagnostics': None, 'image_identity': IDENTITY}
            value = {'version': 1, 'synthetic': True, 'result': result}
            with patch.object(fixture, 'private_json', side_effect=OSError('secret-sentinel-must-not-be-output')), \
                 patch.object(fixture.sys, 'stderr') as stderr:
                self.assertFalse(fixture.receipt(cluster, 'case-assessment-malformed-config-result.json', value))
                self.assertNotIn('secret-sentinel', str(stderr.mock_calls))
            self.assertEqual(result['exit_code'], 1)
            self.assertTrue(cluster.receipt_failures)
            with patch.object(fixture, 'private_json') as persist:
                self.assertFalse(fixture.receipt(cluster, 'case-assessment-malformed-config-result.json', {**value, 'raw_stderr': 'private-marker'}))
                persist.assert_not_called()

    def test_fault_matrix_requires_actual_phase_and_separate_child_exit(self):
        class Cluster:
            def __init__(self): self.calls = []
            def sql(self, value):
                self.calls.append(value)
                return ('blake3:' + '1' * 64).encode()
        cluster = Cluster()
        expected = {'malformed-config': 'config_load', 'wrong-dns': 'sql_connect', 'bad-password': 'sql_connect',
                    'existing-output': 'output_create', 'ready-denied': 'ready_write',
                    'wrong-schema': 'schema', 'missing-grant': 'history_select',
                    'output-symlink': 'output_create', 'output-wrong-mode': 'output_create',
                    'output-wrong-owner': 'output_create', 'restore-pending': 'schema',
                    'corrupt-history': 'history_select', 'held-lifecycle': 'lifecycle'}
        def assess(_cluster, _image, _selected, _api, case):
            if case == 'telemetry-unavailable':
                return {'phase': 'report_transferred', 'events': None}
            return {'phase': 'terminal', 'exit_code': 1, 'diagnostics': [
                {'phase': 'cli_start', 'outcome': 'start'},
                {'phase': expected[case], 'outcome': 'error'},
                {'phase': 'cli_exit', 'outcome': 'ok' if case == 'ready-denied' else 'error',
                 'child_exit': 0 if case == 'ready-denied' else 1}]}
        with patch.object(fixture, 'snapshot', return_value={'fixture': 'unchanged'}), \
             patch.object(fixture, 'set_config'), patch.object(fixture, 'assess', side_effect=assess), \
             patch.object(fixture, 'lifecycle_exclusion', return_value=contextlib.nullcontext()):
            self.assertEqual(len(fixture.failure_matrix(cluster, 'server', {}, None, 'synthetic config', 'harness')), 14)
        self.assertIn('UPDATE devres_schema SET version=19 WHERE singleton', cluster.calls)
        self.assertIn('GRANT SELECT ON devres_npm_advisory_job_history TO devres_assessment_reader', cluster.calls)
        with patch.object(fixture, 'snapshot', return_value={}), patch.object(fixture, 'set_config'), \
             patch.object(fixture, 'assess', return_value={'phase': 'terminal', 'exit_code': 1, 'diagnostics': []}):
            with self.assertRaisesRegex(fixture.FixtureError, 'phase_unknown'):
                fixture.failure_matrix(cluster, 'server', {}, None, 'synthetic config', 'harness')

    def test_source_bound_cleanup_passes_uid_precondition_to_api(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-123-fixture', Path(temporary))
            calls = []
            def k(*arguments, **kwargs):
                calls.append((arguments, kwargs))
                return subprocess.CompletedProcess(arguments, 0, b'', b'')
            with patch.object(cluster, 'pod', return_value={'metadata': {'uid': 'owned-uid'}}), patch.object(cluster, 'k', side_effect=k):
                cluster.delete('assessment-success', 'owned-uid')
            deletion = calls[0]
            self.assertIn('/api/v1/namespaces/devres-assessment/pods/assessment-success', deletion[0][1])
            self.assertEqual(json.loads(deletion[1]['data'])['preconditions'], {'uid': 'owned-uid'})
            with patch.object(cluster, 'pod', return_value={'metadata': {'uid': 'different'}}):
                with self.assertRaisesRegex(fixture.FixtureError, 'uid_changed'):
                    cluster.delete('assessment-success', 'owned-uid')

    def test_actual_supervisor_fences_report_and_runtime_and_cleans_before_persist(self):
        api = fixture.helper()
        selected = {'job_id': 'blake3:' + '1' * 64, 'revision': 1}
        report = {'version': 1, **selected, 'recipe': 'npm-materialization-deadline-v1',
                  'state_digest': 'blake3:' + '2' * 64, 'eligible': False, 'outcome': 'ineligible',
                  'reason': 'legacy_unknown', 'operation_id': None, 'publication_snapshot': None}
        raw = json.dumps(report).encode() + b'\n'
        frame = f'65532:600:1:{len(raw)}:regular file\n'.encode() + api.FRAME + raw + api.PHASE_FRAME + b'1\tcli_exit\tok\tnone\t0\t0\n'
        runtime = (b'APPARMOR=devres-runtime (enforce)\nSECCOMP=2\nNO_NEW_PRIVS=1\n'
                   b'CAP_EFF=0000000000000000\nCONFIG=0:65532:440\nTMP=0:65532:2777\n')
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                events = []
                class Cluster:
                    scratch = Path(temporary)
                    profile = 'devres-acceptance-123-fixture'
                    expected_image = {'artifact': 'sha256:' + '1' * 64, 'configs': ['sha256:' + '3' * 64], 'known_digests': ['sha256:' + '1' * 64, 'sha256:' + '3' * 64]}
                    calls = 0
                    def apply(self, pod): self.value = pod
                    def pod(self, _name):
                        self.calls += 1
                        value = copy.deepcopy(self.value)
                        value['metadata']['uid'] = ('different' if changed and self.calls == 3 else '11111111-1111-1111-1111-111111111111')
                        value['status'] = {'phase': 'Running', 'containerStatuses': [{'containerID': 'containerd://fixture',
                            'restartCount': 0, 'imageID': 'sha256:fixture', 'state': {'running': {}}}]}
                        return value
                    def argv(self, *args): return ['fixture-kubectl', *args]
                    def delete(self, _name, _uid): events.append('cleanup')
                cluster = Cluster()
                with patch.object(api, 'report_exchange', side_effect=[frame, runtime]) as exchange, \
                     patch.object(fixture, 'resolved_image_identity', return_value=IDENTITY), \
                     patch.object(fixture, 'private_json', side_effect=lambda *_args: events.append('persist')):
                    if changed:
                        with self.assertRaisesRegex(api.AssessmentError, 'uid_changed'):
                            fixture.assess(cluster, 'candidate:server', selected, api)
                        self.assertEqual(events, ['cleanup'])
                    else:
                        result = fixture.assess(cluster, 'candidate:server', selected, api)
                        self.assertEqual(result['phase'], 'report_transferred')
                        self.assertEqual(events, ['cleanup', 'persist'])
                    self.assertEqual(exchange.call_count, 2)
                    self.assertTrue(all(0 < call.kwargs['timeout'] <= 5 for call in exchange.call_args_list))

    def test_image_identity_matches_index_digest_without_mislabeling_config(self):
        index = 'sha256:' + '1' * 64
        config = 'sha256:' + '2' * 64
        inspected = (index + '\n' + json.dumps(['fixture/server@' + index]) + '\n').encode()
        with patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, inspected, b'')), \
             patch.object(fixture, 'docker_config_digests', return_value=[config]) as export:
            expected = fixture.expected_image_identity('fixture/server:candidate')
        export.assert_called_once_with(index)
        self.assertEqual(expected, {'artifact': index, 'configs': [config], 'known_digests': [index, config]})
        class Cluster: profile = 'devres-acceptance-123-fixture'
        cri = {'status': {'id': config, 'repoDigests': ['fixture/server@' + index]}}
        with patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps(cri).encode(), b'')) as execute:
            value = fixture.resolved_image_identity(Cluster(), 'fixture/server@' + index, expected)
        self.assertEqual(value['matched_artifact'], index)
        self.assertEqual(value['resolved_cri_id'], config)
        self.assertNotIn('expected_config', value)
        self.assertEqual(execute.call_args.args[0][-1], 'fixture/server@' + index)

    def test_substituted_runtime_image_digest_is_rejected_even_with_same_tag(self):
        expected = {'artifact': 'sha256:' + '1' * 64, 'configs': ['sha256:' + '2' * 64], 'known_digests': ['sha256:' + '1' * 64, 'sha256:' + '2' * 64]}
        wrong = 'sha256:' + '9' * 64
        class Cluster: profile = 'devres-acceptance-123-fixture'
        cri = {'status': {'id': wrong, 'repoDigests': ['fixture/server@' + wrong]}}
        with patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps(cri).encode(), b'')):
            with self.assertRaisesRegex(fixture.FixtureError, 'candidate_image_mismatch'):
                fixture.resolved_image_identity(Cluster(), 'fixture/server@' + wrong, expected)

    def test_streamed_export_derives_config_and_matches_rewritten_manifest(self):
        config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': []}}).encode()
        digest = hashlib.sha256(config).hexdigest()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as output:
            for name, payload in [('blobs/sha256/' + digest, config),
                                  ('manifest.json', json.dumps([{'Config': 'blobs/sha256/' + digest, 'RepoTags': ['fixture/server:candidate'], 'Layers': []}]).encode())]:
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                output.addfile(member, io.BytesIO(payload))
        original = subprocess.Popen
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            path = Path(temporary) / 'synthetic-save.tar'
            path.write_bytes(archive.getvalue())
            producer = "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())"
            with patch.object(fixture.subprocess, 'Popen', side_effect=lambda _args, **kwargs: original([sys.executable, '-I', '-B', '-c', producer, str(path)], **kwargs)):
                configs = fixture.docker_config_digests('fixture/server:candidate')
        self.assertEqual(configs, ['sha256:' + digest])
        expected = {'artifact': 'sha256:' + '1' * 64, 'configs': configs, 'known_digests': ['sha256:' + '1' * 64, *configs]}
        class Cluster: profile = 'devres-acceptance-123-fixture'
        rewritten = 'sha256:' + '9' * 64
        cri = {'status': {'id': configs[0], 'repoDigests': ['fixture/server@' + rewritten]}}
        with patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps(cri).encode(), b'')):
            result = fixture.resolved_image_identity(Cluster(), 'fixture/server@' + rewritten, expected)
        self.assertEqual(result['resolved_config'], configs[0])
        self.assertEqual(result['matched_artifact'], configs[0])

    def test_streamed_export_timeout_terminates_owned_process_group(self):
        original = subprocess.Popen
        with patch.object(fixture.subprocess, 'Popen', side_effect=lambda _args, **kwargs: original([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(5)'], **kwargs)):
            with self.assertRaises(fixture.FixtureError):
                fixture.docker_config_digests('fixture/server:candidate', timeout=.1)

    def test_apparmor_unload_requires_namespace_cleanup_and_no_attached_tasks(self):
        for tasks_stopped, attached, should_unload in ((True, False, True), (False, False, False), (True, True, False)):
            with self.subTest(tasks_stopped=tasks_stopped, attached=attached), tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                calls = []
                def command(arguments, **_kwargs):
                    calls.append(arguments)
                    output = (b'docker-default (enforce)\n' if len(calls) == 1
                              else b'devres-runtime (enforce)\n')
                    return subprocess.CompletedProcess(arguments, 0, output, b'')
                with patch.object(fixture, 'command', side_effect=command), \
                     patch.object(fixture, 'no_attached_tasks', return_value=not attached):
                    if should_unload:
                        with fixture.apparmor(Path(temporary), lambda: tasks_stopped) as digest:
                            self.assertEqual(digest, fixture.APPARMOR_SHA256)
                    else:
                        with self.assertRaisesRegex(fixture.FixtureError, 'cleanup_incomplete_profile_retained'):
                            with fixture.apparmor(Path(temporary), lambda: tasks_stopped):
                                pass
                self.assertEqual(any('-R' in call for call in calls), should_unload)

    def test_apparmor_refuses_asset_with_unreviewed_digest(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary, patch.object(fixture, 'APPARMOR_SHA256', '0' * 64), \
             patch.object(fixture, 'command') as commands:
            with self.assertRaisesRegex(fixture.FixtureError, 'canonical_hash_mismatch'):
                with fixture.apparmor(Path(temporary)):
                    pass
            commands.assert_not_called()

    def test_apparmor_task_scan_fails_closed_for_attached_or_unknown_labels(self):
        for value, expected in (({'attached': 0, 'unknown': False}, True),
                                ({'attached': 1, 'unknown': False}, False),
                                ({'attached': 0, 'unknown': True}, False)):
            with self.subTest(value=value), patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b'')):
                self.assertEqual(fixture.no_attached_tasks(), expected)


if __name__ == '__main__':
    unittest.main()
