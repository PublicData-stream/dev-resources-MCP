"""Exercise synthetic admission, restrictions and failure assertions without a cluster."""
import importlib.util
import contextlib
import copy
import hashlib
import io
import json
import os
import shlex
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
PARSER = {'package_sha256': fixture.PARSER_PACKAGE_SHA256, 'package_size': fixture.PARSER_PACKAGE_SIZE,
          'binary_sha256': fixture.PARSER_SHA256, 'binary_size': fixture.PARSER_SIZE, 'libc': '2.36', 'preexisting': False}
PARSER_FILE = {'device': 1, 'inode': 2, 'ctime': '2026-11-17 12:00:00.123456789 +0000'}
PLACEMENT = {'path': '/usr/sbin/apparmor_parser', 'version': '3.0.8', 'mode': 0o500,
             'binary_sha256': fixture.PARSER_SHA256, 'file_identity': PARSER_FILE}


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

    def test_image_graph_keeps_exact_index_native_config_name_and_platform(self):
        identity={'container_id':'1'*64,'container_pid':42}
        for scenario in ('valid','wrong-name','wrong-target','wrong-config','wrong-native-config','wrong-platform','duplicate-platform','wrong-config-arch','corrupt-root','local-tag'):
            cfg={'architecture':'arm64' if scenario=='wrong-config-arch' else 'amd64','os':'linux','rootfs':{'diff_ids':[]}}
            cfg_raw=json.dumps(cfg).encode();cfg_id='sha256:'+hashlib.sha256(cfg_raw).hexdigest()
            native={'schemaVersion':2,'config':{'digest':'sha256:'+'9'*64 if scenario=='wrong-native-config' else cfg_id},'layers':[]}
            native_raw=json.dumps(native).encode();native_id='sha256:'+hashlib.sha256(native_raw).hexdigest()
            item={'digest':native_id,'platform':{'os':'linux','architecture':'arm64' if scenario=='wrong-platform' else 'amd64'}}
            index={'schemaVersion':2,'manifests':[item,item] if scenario=='duplicate-platform' else [item]}
            index_raw=json.dumps(index).encode();root='sha256:'+hashlib.sha256(index_raw).hexdigest()
            image='candidate:server' if scenario=='local-tag' else 'ghcr.io/example/server@'+root
            expected={'artifact':root,'configs':[cfg_id],'known_digests':[root,cfg_id]}
            blobs={root:index_raw,native_id:native_raw,cfg_id:cfg_raw}
            def execute(_identity,*args,**kwargs):
                self.assertEqual(_identity,identity)
                if args[:2]==('crictl','inspecti'):
                    data={'status':{'id':'sha256:'+'8'*64 if scenario=='wrong-config' else cfg_id,
                                   'repoDigests':[] if scenario=='wrong-name' else [image]}}
                    output=json.dumps(data).encode()
                elif args[:5]==('ctr','-n','k8s.io','images','ls'):
                    output=('REF TYPE DIGEST SIZE PLATFORMS LABELS\n'+image+' application/vnd.oci.image.index.v1+json '+('sha256:'+'7'*64 if scenario=='wrong-target' else root)+' 0B linux/amd64 -\n').encode()
                elif args[:5]==('ctr','-n','k8s.io','content','get'):
                    output=blobs[args[5]]
                    if scenario=='corrupt-root' and args[5]==root:output+=b' '
                else:raise AssertionError(args)
                return subprocess.CompletedProcess([],0,output,b'')
            with self.subTest(scenario=scenario),patch.object(fixture,'node_exec',side_effect=execute):
                if scenario in ('valid','local-tag'):
                    result=fixture.admitted_image(identity,image,expected,'amd64','local-tag' if scenario=='local-tag' else 'digest')
                    self.assertEqual(result['config'],cfg_id)
                    self.assertEqual(result['native_manifest'],None if scenario=='local-tag' else native_id)
                else:
                    with self.assertRaises(fixture.FixtureError):fixture.admitted_image(identity,image,expected,'amd64','digest')

    def test_image_preparation_single_dispatch_failures_and_receipt_replay(self):
        identity={'container_id':'1'*64,'container_pid':42};uid='12345678-1234-1234-1234-123456789abc'
        root='sha256:'+'2'*64;config='sha256:'+'3'*64
        expected={'artifact':root,'configs':[config],'known_digests':[root,config]}
        for scenario in ('digest','local-tag','pull-failure','pull-timeout','pull-cancel','import-failure','storage-refused','storage-drift','node-refused','identity-drift','lost-intent','replay'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                image='candidate:server' if scenario in ('local-tag','import-failure') else 'ghcr.io/example/server@'+root
                cluster=fixture.Cluster('devres-acceptance-fixture',Path(temporary));operations=[]
                arguments=types.SimpleNamespace(profile=cluster.profile,scratch=temporary,server_image=image)
                graph={'root_digest':None if scenario in ('local-tag','import-failure') else root,
                       'native_manifest':None if scenario in ('local-tag','import-failure') else 'sha256:'+'4'*64,
                       'config':config,'architecture':'amd64','os':'linux'}
                def execute(_identity,*args,**kwargs):
                    if args==('uname','-m'):return subprocess.CompletedProcess([],0,b'x86_64\n',b'')
                    if args[:2]==('crictl','pull'):
                        operations.append('pull')
                        if scenario=='pull-failure':raise fixture.FixtureError('fixture_command_failed')
                        if scenario=='pull-timeout':raise subprocess.TimeoutExpired(['PRIVATE_ARGUMENT'],240)
                        if scenario=='pull-cancel':raise KeyboardInterrupt()
                        return subprocess.CompletedProcess([],0,b'public digest',b'')
                    raise AssertionError(args)
                def command(args,**kwargs):
                    self.assertEqual(args,['minikube','-p',cluster.profile,'image','load',image]);operations.append('import')
                    if scenario=='import-failure':raise fixture.FixtureError('fixture_command_failed')
                    return subprocess.CompletedProcess([],0,b'',b'')
                actual_receipt=fixture.receipt
                def receipt(_cluster,name,value):
                    if scenario=='lost-intent' and name.endswith('-intent.json'):return False
                    return actual_receipt(_cluster,name,value)
                with patch.dict(os.environ,{'DEVRES_E2E_DIAGNOSTICS_DIR':''}),patch.object(fixture,'Cluster',return_value=cluster), \
                     patch.object(fixture,'node_docker_identity',side_effect=fixture.FixtureError('fixture_node_identity') if scenario=='node-refused' else None,return_value=identity), \
                     patch.object(fixture,'node_uid',side_effect=[uid,'23456789-1234-1234-1234-123456789abc'] if scenario=='identity-drift' else None,return_value=uid), \
                     patch.object(fixture,'node_namespace',return_value='mnt:[20]'),patch.object(fixture,'host_mount_state',return_value=('mnt:[10]','5'*64,set())), \
                     patch.object(fixture,'node_exec',side_effect=execute),patch.object(fixture,'command',side_effect=command), \
                     patch.object(fixture,'expected_image_identity',return_value=expected), \
                     patch.object(fixture,'image_cache_boundary',side_effect=fixture.FixtureError('fixture_image_storage') if scenario=='storage-refused' else ['6'*64,'7'*64] if scenario=='storage-drift' else None,return_value='6'*64), \
                     patch.object(fixture,'admitted_image',return_value=graph),patch.object(fixture,'receipt',side_effect=receipt):
                    if scenario in ('digest','local-tag','replay'):
                        fixture.prepare_image(arguments)
                        self.assertEqual(operations,['import' if scenario=='local-tag' else 'pull'])
                        if scenario=='replay':
                            with self.assertRaisesRegex(fixture.FixtureError,'fixture_evidence_retention_incomplete'):fixture.prepare_image(arguments)
                            self.assertEqual(operations,['pull'])
                    else:
                        error_type=subprocess.TimeoutExpired if scenario=='pull-timeout' else KeyboardInterrupt if scenario=='pull-cancel' else fixture.FixtureError
                        with self.assertRaises(error_type):fixture.prepare_image(arguments)
                        self.assertEqual(operations,['pull'] if scenario in ('pull-failure','pull-timeout','pull-cancel') else ['import'] if scenario=='import-failure' else [])
                    for path in Path(temporary).glob('npm-assessment-image-*.json'):
                        value=json.loads(path.read_bytes());fixture.validate_receipt(path.name,value)
                        self.assertNotIn('private',path.read_text().lower())
                        with self.assertRaises(fixture.FixtureError):fixture.validate_receipt(path.name,{**value,'stderr':'PRIVATE_SECRET'})
                    if scenario in ('pull-timeout','pull-cancel'):
                        failure=json.loads((Path(temporary)/'npm-assessment-image-preparation-failure.json').read_bytes())
                        self.assertEqual(failure['phase'],'operation')
                        self.assertEqual(failure['failure']['code'],'fixture_command_timeout' if scenario=='pull-timeout' else 'unknown')

    def test_image_preparation_refuses_context_and_invalid_refs_before_operations(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary,patch.dict(os.environ,{'DOCKER_CONTEXT':'foreign'}), \
             patch.object(fixture,'Cluster') as cluster,patch.object(fixture,'command') as command:
            with self.assertRaisesRegex(fixture.FixtureError,'fixture_docker_context_refused'):
                fixture.prepare_image(types.SimpleNamespace(scratch=temporary))
            cluster.assert_not_called();command.assert_not_called()
        for image in ('sha256:'+'1'*64,'candidate@not-a-digest','https://user:password@registry/image','candidate','candidate:tag;foreign'):
            with self.subTest(image=image),self.assertRaises(fixture.FixtureError):fixture.image_reference_kind(image)

    def test_image_cache_storage_rejects_foreign_bind_mount_alias_and_kernel_source(self):
        profile='devres-acceptance-fixture';state=Path('/tmp/owned-daemon');storage=str(state/'data/volumes'/profile/'_data')
        identity={'container_id':'1'*64,'container_pid':42}
        host=b'1 0 253:1 / /tmp rw - ext4 /dev/vda1 rw\n'
        node=('2 1 253:1 '+storage.removeprefix('/tmp')+' /var rw shared:2 - ext4 /dev/vda1 rw\n').encode()
        original={'Id':identity['container_id'],'State':{'Pid':42},'HostConfig':{},'Mounts':[{'Type':'volume','Name':profile,'Driver':'local','Source':storage,'RW':True,'Destination':'/var'}]}
        for scenario in ('valid','foreign-source','foreign-name','bind','remote-driver','readonly','descendant','kernel-root','kernel-submount'):
            value,raw=copy.deepcopy(original),node
            mount=value['Mounts'][0]
            if scenario=='foreign-source':mount['Source']='/foreign/data'
            elif scenario=='foreign-name':mount['Name']='foreign'
            elif scenario=='bind':mount['Type']='bind'
            elif scenario=='remote-driver':mount['Driver']='foreign'
            elif scenario=='readonly':mount['RW']=False
            elif scenario=='descendant':value['Mounts'].append({'Destination':'/var/lib/containerd','Type':'bind','Source':'/foreign'})
            elif scenario=='kernel-root':raw=raw.replace(storage.removeprefix('/tmp').encode(),b'/foreign')
            elif scenario=='kernel-submount':raw+=b'3 2 253:1 /foreign /var/lib/containerd/sub rw - ext4 /dev/vda1 rw\n'
            with self.subTest(scenario=scenario),patch.dict(os.environ,{'DOCKER_HOST':'unix:///tmp/owned-daemon/docker.sock'}), \
                 patch.object(fixture,'node_docker_identity',return_value=identity),patch.object(fixture,'command',side_effect=[subprocess.CompletedProcess([],0,b'"/tmp/owned-daemon/data"',b''),subprocess.CompletedProcess([],0,json.dumps([value]).encode(),b'')]), \
                 patch.object(fixture,'verify_private_storage') as verify,patch.object(fixture.Path,'read_bytes',return_value=host), \
                 patch.object(fixture,'node_exec',return_value=subprocess.CompletedProcess([],0,raw,b'')):
                if scenario=='valid':
                    self.assertEqual(len(fixture.image_cache_boundary(types.SimpleNamespace(profile=profile),identity)),64)
                    verify.assert_called_once_with(state,[storage])
                else:
                    with self.assertRaisesRegex(fixture.FixtureError,'fixture_image_storage'):
                        fixture.image_cache_boundary(types.SimpleNamespace(profile=profile),identity)

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
                    ('policy', 'networking.k8s.io/v1', 'NetworkPolicyList', '/apis/networking.k8s.io/v1/namespaces/devres-acceptance/networkpolicies?fieldSelector=metadata.name%3Dpostgres-owned-assessment', 'devres-acceptance'),
                    ('readiness_policy', 'networking.k8s.io/v1', 'NetworkPolicyList', '/apis/networking.k8s.io/v1/namespaces/devres-acceptance/networkpolicies?fieldSelector=metadata.name%3Dpostgres-owned-assessment-readiness', 'devres-acceptance')):
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
            for kind in ('namespace', 'policy', 'readiness_policy'):
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

    def test_parser_archive_accepts_only_integrity_bound_regular_member(self):
        payload = b'owned synthetic native ELF data'
        def package(scenario):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w:xz') as archive:
                for _ in range(2 if scenario == 'duplicate' else 1):
                    member = tarfile.TarInfo('./sbin/apparmor_parser')
                    member.mode, member.uid, member.gid = 0o755, 0, 0
                    member.size = len(payload)
                    if scenario == 'symlink': member.type, member.linkname, member.size = tarfile.SYMTYPE, '/etc/foreign', 0
                    archive.addfile(member, io.BytesIO(payload) if member.isfile() else None)
            result = bytearray(b'!<arch>\n')
            for name, data in ((b'debian-binary', b'2.0\n'), (b'control.tar.xz', b'unused'), (b'data.tar.xz', output.getvalue())):
                result.extend(name.ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) + b'0'.ljust(6) + b'100644'.ljust(8) + str(len(data)).encode().ljust(10) + b'`\n')
                result.extend(data)
                if len(data) % 2: result.extend(b'\n')
            return bytes(result)
        for scenario in ('valid', 'symlink', 'duplicate', 'wrong-member-hash'):
            raw = package(scenario)
            with self.subTest(scenario=scenario), patch.object(fixture, 'PARSER_PACKAGE_SIZE', len(raw)), \
                 patch.object(fixture, 'PARSER_PACKAGE_SHA256', hashlib.sha256(raw).hexdigest()), \
                 patch.object(fixture, 'PARSER_SIZE', len(payload)), \
                 patch.object(fixture, 'PARSER_SHA256', '0' * 64 if scenario == 'wrong-member-hash' else hashlib.sha256(payload).hexdigest()):
                if scenario == 'valid': self.assertEqual(fixture.parser_payload(raw), payload)
                else:
                    with self.assertRaises(fixture.FixtureError): fixture.parser_payload(raw)
                with patch.object(fixture.tarfile, 'open') as archive:
                    with self.assertRaisesRegex(fixture.FixtureError, 'fixture_parser_package'):
                        fixture.parser_payload(raw[:-1] + bytes([raw[-1] ^ 1]))
                    archive.assert_not_called()

    def test_parser_downloader_pins_endpoint_bounds_bytes_and_refuses_redirects(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            response = unittest.mock.MagicMock()
            response.__enter__.return_value = response
            response.geturl.return_value = fixture.PARSER_URL
            response.read.return_value = b'package-data'
            opener = unittest.mock.Mock(open=unittest.mock.Mock(return_value=response))
            with patch.object(fixture.urllib.request, 'build_opener', return_value=opener) as factory, \
                 patch.object(fixture, 'parser_payload', return_value=b'parser-data'):
                self.assertEqual(fixture.genuine_parser(Path(temporary)), b'parser-data')
                opener.open.assert_called_once_with(fixture.PARSER_URL, timeout=30)
                response.read.assert_called_once_with(fixture.PARSER_PACKAGE_SIZE + 1)
                self.assertEqual((Path(temporary) / 'apparmor-native-package.deb').stat().st_mode & 0o777, 0o600)
                with self.assertRaisesRegex(fixture.FixtureError, 'fixture_parser_download'):
                    factory.call_args.args[0].redirect_request(None, None, None, None, None, None)
            response.geturl.return_value = 'https://foreign.invalid/redirect'
            response.read.reset_mock()
            with patch.object(fixture.urllib.request, 'build_opener', return_value=opener), patch.object(fixture, 'parser_payload') as payload:
                with self.assertRaisesRegex(fixture.FixtureError, 'fixture_parser_download'):
                    fixture.genuine_parser(Path(temporary))
                response.read.assert_not_called();payload.assert_not_called()

    def test_parser_copy_requires_admission_hash_version_and_never_overwrites(self):
        payload, identity = b'synthetic-parser-data', {'container_id': '1' * 64, 'container_pid': 42}
        digest = hashlib.sha256(payload).hexdigest()
        for scenario in ('valid', 'foreign-node', 'copy-hash', 'wrong-version', 'late-copy-boundary', 'late-file-boundary'):
            calls = []
            guard_calls = []
            def guard():
                guard_calls.append(True)
                if len(guard_calls) == (1 if scenario == 'late-copy-boundary' else 2 if scenario == 'late-file-boundary' else -1):
                    raise fixture.FixtureError('fixture_parser_write_boundary')
            def execute(_identity, *args, **_kwargs):
                calls.append(args)
                if args[0] == 'sha256sum': value = ((('0' * 64) if scenario == 'copy-hash' else digest) + ' file\n').encode()
                elif args[0] == 'readlink': value = b'/usr/sbin/apparmor_parser\n'
                elif args[:3] == ('env','LC_ALL=C','stat'):
                    value=(PARSER_FILE['ctime']+'\n').encode() if args[4]=='%z' else ('regular file:0:0:500:'+str(len(payload))+':1:1:2\n').encode()
                elif args[0] == '/sbin/apparmor_parser': value = b'AppArmor parser version ' + (b'3.0.8' if scenario != 'wrong-version' else b'unknown') + b'\n'
                else: raise AssertionError(args)
                return subprocess.CompletedProcess([], 0, value, b'')
            with self.subTest(scenario=scenario), patch.object(fixture, 'PARSER_SIZE', len(payload)), \
                 patch.object(fixture, 'PARSER_SHA256', digest), patch.object(fixture, 'node_exec', side_effect=execute), \
                 patch.object(fixture, 'parser_admission', side_effect=fixture.FixtureError('fixture_parser_node') if scenario == 'foreign-node' else None), \
                 patch.object(fixture, 'command', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as copy_command:
                if scenario == 'valid': self.assertEqual(fixture.install_parser(identity, 'mnt:[20]', payload, guard)['version'], '3.0.8')
                else:
                    with self.assertRaises(fixture.FixtureError): fixture.install_parser(identity, 'mnt:[20]', payload, guard)
                if scenario == 'foreign-node':
                    self.assertEqual(calls, []);copy_command.assert_not_called()
                elif scenario == 'late-copy-boundary':
                    copy_command.assert_not_called();self.assertFalse(any(call[0] == 'ln' for call in calls))
                else:
                    self.assertEqual(copy_command.call_args.kwargs['data'], payload)
                    self.assertEqual(copy_command.call_args.args[0][:4], ['docker', 'exec', '-i', identity['container_id']])
                    self.assertFalse(any(call[0] in ('ln','mktemp','mount') for call in calls))
                    if scenario in ('copy-hash', 'late-file-boundary'):
                        self.assertFalse(any(call[0] == '/sbin/apparmor_parser' for call in calls))
                    if scenario == 'valid':
                        # Exercise the rendered dd interface on disposable files,
                        # including a symlink to a separate readable preimage.
                        script=copy_command.call_args.args[0][6]
                        arguments=shlex.split(next(line for line in script.splitlines() if line.startswith('dd ')))
                        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                            directory=Path(temporary);preimage=directory/'preimage';preimage.write_bytes(b'preserved')
                            existing=directory/'existing';existing.write_bytes(b'existing')
                            symlink=directory/'symlink';symlink.symlink_to(preimage)
                            for name,path in (('new',directory/'new'),('existing',existing),('symlink',symlink)):
                                command=[('of='+str(path)) if item.startswith('of=') else item for item in arguments]
                                result=subprocess.run(command,input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
                                self.assertEqual(result.returncode,0 if name=='new' else 1)
                                self.assertEqual(preimage.read_bytes(),b'preserved');self.assertEqual(existing.read_bytes(),b'existing')
                            self.assertEqual((directory/'new').read_bytes(),payload)

    def test_parser_write_projection_rejects_docker_aliases_foreign_overlay_and_propagation(self):
        state = Path('/tmp/owned-daemon')
        mountinfo = b'1 0 0:1 / / rw - overlay overlay rw,upperdir=/tmp/owned-daemon/containerd/snapshots/1/fs,workdir=/tmp/owned-daemon/containerd/snapshots/1/work\n2 1 0:2 / /tmp rw - tmpfs tmpfs rw\n'
        value = {'HostConfig': {'Tmpfs': {'/tmp': 'rw'}}, 'Mounts': [{'Type': 'tmpfs', 'Destination': '/tmp'}]}
        digest, directories = fixture.parser_write_projection(value, mountinfo, state)
        self.assertEqual(len(digest),64);self.assertEqual(directories, ['/tmp/owned-daemon/containerd/snapshots/1/fs','/tmp/owned-daemon/containerd/snapshots/1/work'])
        for scenario in ('ancestor-bind', 'parser-bind', 'descendant-volume', 'volumes-from', 'foreign-upper', 'usr-mount', 'usr-child', 'slave', 'usr-tmpfs','foreign-work','missing-work','duplicate-work'):
            candidate, raw = copy.deepcopy(value), mountinfo
            if scenario == 'ancestor-bind': candidate['HostConfig']['Binds'] = ['/foreign:/usr:rw']
            elif scenario == 'parser-bind': candidate['Mounts'] = [{'Type': 'bind', 'Destination': '/usr/sbin/apparmor_parser'}]
            elif scenario == 'descendant-volume': candidate['Mounts'].append({'Type':'volume','Destination':'/usr/sbin/parser'})
            elif scenario == 'volumes-from': candidate['HostConfig']['VolumesFrom'] = ['foreign']
            elif scenario == 'foreign-upper': raw = raw.replace(b'/tmp/owned-daemon/containerd', b'/var/lib/docker')
            elif scenario == 'usr-mount': raw += b'3 1 0:3 / /usr rw - ext4 /dev/foreign rw\n'
            elif scenario == 'usr-child': raw += b'3 1 0:3 / /usr/sbin/staged rw - ext4 /dev/foreign rw\n'
            elif scenario == 'slave': raw = raw.replace(b'/ / rw -', b'/ / rw master:50 -')
            elif scenario == 'usr-tmpfs': candidate['HostConfig']['Tmpfs']['/usr/sbin'] = 'rw'
            elif scenario == 'foreign-work': raw = raw.replace(b'workdir=/tmp/owned-daemon/containerd/snapshots/1/work',b'workdir=/foreign/work')
            elif scenario == 'missing-work': raw = raw.replace(b',workdir=/tmp/owned-daemon/containerd/snapshots/1/work',b'')
            elif scenario == 'duplicate-work': raw = raw.replace(b'\n2 ',b',workdir=/tmp/owned-daemon/containerd/snapshots/1/work\n2 ')
            with self.subTest(scenario=scenario), self.assertRaisesRegex(fixture.FixtureError, 'fixture_parser_write_boundary'):
                fixture.parser_write_projection(candidate, raw, state)

    def test_parser_late_workdir_drift_refuses_copy_before_payload_or_link(self):
        state=Path('/tmp/owned-daemon')
        raw=b'1 0 0:1 / / rw - overlay overlay rw,upperdir=/tmp/owned-daemon/containerd/1/fs,workdir=/tmp/owned-daemon/containerd/1/work\n'
        value={'HostConfig':{},'Mounts':[]}
        baseline=fixture.parser_write_projection(value,raw,state)[0]
        changed=raw.replace(b'/1/work',b'/2/work')
        mounts=iter([changed])
        def guard():
            fixture.need(fixture.parser_write_projection(value,next(mounts),state)[0]==baseline,'fixture_parser_write_boundary')
        payload=b'synthetic-parser'
        with patch.object(fixture,'PARSER_SIZE',len(payload)),patch.object(fixture,'PARSER_SHA256',hashlib.sha256(payload).hexdigest()), \
             patch.object(fixture,'parser_admission'),patch.object(fixture,'node_exec',return_value=subprocess.CompletedProcess([],0,b'/tmp/devres-apparmor.ABCDef01\n',b'')) as node, \
             patch.object(fixture,'command') as copy_command:
            with self.assertRaisesRegex(fixture.FixtureError,'fixture_parser_write_boundary'):
                fixture.install_parser({'container_id':'1'*64,'container_pid':42},'mnt:[20]',payload,guard)
            copy_command.assert_not_called();self.assertEqual(node.call_count,0)

    def test_real_minikube_shared_overlay_and_noexec_tmp_remain_physically_owned_and_topology_bound(self):
        # Sanitized exact Docker29/minikube1.39 observed refusal, not invented
        # private-propagation defaults. No parser ELF is staged on node /tmp.
        state=Path('/tmp/owned-daemon')
        raw=(b'489 349 0:53 / / rw,relatime shared:330 - overlay overlay rw,lowerdir=/tmp/owned-daemon/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/18/fs:/tmp/owned-daemon/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs,upperdir=/tmp/owned-daemon/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/19/fs,workdir=/tmp/owned-daemon/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/19/work,nouserxattr\n'
             b'505 489 0:74 / /tmp rw,nosuid,nodev,noexec,relatime shared:340 - tmpfs tmpfs rw,inode64\n'
             b'387 505 253:1 /devres-state/data/volumes/devres-acceptance-fixture/_data/hostpath_pv /tmp/hostpath_pv rw,relatime shared:341 master:113 - ext4 /dev/vda1 rw\n'
             b'390 505 253:1 /devres-state/data/volumes/devres-acceptance-fixture/_data/hostpath-provisioner /tmp/hostpath-provisioner rw,relatime shared:341 master:113 - ext4 /dev/vda1 rw\n')
        value={'HostConfig':{'Binds':['devres-acceptance-fixture:/var','/lib/modules:/lib/modules:ro'],
                            'Mounts':None,'Tmpfs':{'/run':'','/tmp':''},'VolumesFrom':None},
               'Mounts':[{'Type':'volume','Destination':'/var','Source':'/tmp/owned-daemon/data/volumes/devres-acceptance-fixture/_data','Propagation':''},
                         {'Type':'bind','Destination':'/lib/modules','Source':'/lib/modules','Propagation':'rprivate'}]}
        digest,directories=fixture.parser_write_projection(value,raw,state)
        self.assertEqual(len(directories),2)
        self.assertNotEqual(digest,fixture.parser_write_projection(value,raw.replace(b'shared:330',b'shared:331'),state)[0])
        self.assertEqual(digest,fixture.parser_write_projection(value,raw.replace(b'shared:340',b'shared:350'),state)[0])
        with self.assertRaisesRegex(fixture.FixtureError,'fixture_parser_write_boundary'):
            fixture.parser_write_projection(value,raw.replace(b'upperdir=/tmp/owned-daemon/',b'upperdir=/foreign/'),state)

    def test_parser_write_admission_refuses_canonical_path_drift_before_privileged_check(self):
        identity = {'container_id':'1'*64,'container_pid':42}
        cluster = types.SimpleNamespace(profile='devres-acceptance-fixture')
        inspected = [{'Id':identity['container_id'],'State':{'Pid':42}}]
        with patch.dict(os.environ, {'DOCKER_HOST':'unix:///tmp/owned-daemon/docker.sock'}), \
             patch.object(fixture,'node_docker_identity',return_value=identity), patch.object(fixture,'node_uid',return_value='owned-uid'), \
             patch.object(fixture,'command',side_effect=[subprocess.CompletedProcess([],0,b'"/tmp/owned-daemon/data"',b''),subprocess.CompletedProcess([],0,json.dumps(inspected).encode(),b'')]) as commands, \
             patch.object(fixture,'node_exec',return_value=subprocess.CompletedProcess([],0,b'/foreign-root\n/usr\n/usr/sbin\n',b'')):
            with self.assertRaisesRegex(fixture.FixtureError,'fixture_parser_write_boundary'):
                fixture.node_write_boundaries(cluster,identity,'owned-uid')
            self.assertEqual(commands.call_count,2)

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

    def test_kubelet_identity_accepts_only_canonical_versioned_binary_and_closed_parser_inode(self):
        identity={'container_id':'1'*64,'container_pid':1234}
        fields=['S','1']+['0']*17+['4242']
        for path,accepted in (('/var/lib/minikube/binaries/v1.37.0/kubelet',True),
                              ('/var/lib/minikube/binaries/../kubelet',False),
                              ('/var/lib/minikube/binaries/v1.37.0/foreign',False),('/tmp/kubelet',False)):
            outputs=[(path+'\n').encode(),('700 (kubelet) '+' '.join(fields)).encode(),('4'*64+' file\n').encode()]
            with self.subTest(path=path),patch.object(fixture,'node_exec',side_effect=[subprocess.CompletedProcess([],0,value,b'') for value in outputs]):
                if accepted:self.assertEqual(fixture.node_process(identity,700,'kubelet')[0]['start_ticks'],4242)
                else:
                    with self.assertRaises(fixture.FixtureError):fixture.node_process(identity,700,'kubelet')
        for value in ({**PARSER_FILE,'inode':0},{**PARSER_FILE,'device':-1},{**PARSER_FILE,'ctime':'PRIVATE_METADATA'},
                      {**PARSER_FILE,'unknown':'PRIVATE_METADATA'}):
            with self.assertRaises(fixture.FixtureError):fixture.validate_parser_file_identity(value)

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
                cluster = types.SimpleNamespace(profile='devres-acceptance-fixture', scratch=Path('/tmp'), k=unittest.mock.Mock())
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
                states = [(host_namespace, '3' * 64, {'shared:3'})] * 8
                if scenario == 'host-changed': states[1] = (host_namespace, '4' * 64, {'shared:3'})
                with patch.object(fixture, 'node_docker_identity', return_value=identity), \
                     patch.object(fixture, 'node_uid', return_value=uid), \
                     patch.object(fixture, 'node_namespace', return_value='mnt:[20]'), \
                     patch.object(fixture, 'host_mount_state', side_effect=states), \
                     patch.object(fixture, 'node_exec', side_effect=execute), \
                     patch.object(fixture, 'kubelet_process', side_effect=[100, 200]), \
                     patch.object(fixture, 'parser_admission', return_value=PARSER), \
                     patch.object(fixture, 'node_write_boundaries', return_value={'projection_sha256':'a'*64}), \
                     patch.object(fixture, 'genuine_parser', return_value=b'fixture-parser'), \
                     patch.object(fixture, 'install_parser', side_effect=lambda *_args: mutations.append('parser') or PLACEMENT), \
                     patch.object(fixture, 'parser_placement_state',return_value=PARSER_FILE), \
                     patch.object(fixture, 'node_process',side_effect=lambda _identity,pid,_name: ({'pid':pid,'start_ticks':pid*10,'binary_sha256':'4'*64},1)), \
                     patch.object(fixture, 'containerd_process', side_effect=[daemon,
                         {**daemon, 'pid': 91} if scenario == 'daemon-replaced' else daemon,
                         {**daemon, 'pid': 190, 'start_ticks': 1900}]), \
                     patch.object(fixture, 'postgres_runtime', side_effect=[runtime,
                         {**runtime, 'shim': {**runtime['shim'], 'pid': 2999}} if scenario == 'shim-replaced' else runtime, runtime]), \
                     patch.object(fixture, 'postgres_process', side_effect=[postgres,
                         {**postgres, 'uid': '3' * 8 + '-' + '3' * 4 + '-' + '3' * 4 + '-' + '3' * 4 + '-' + '3' * 12}
                         if scenario == 'postgres-replaced' else postgres, postgres]), \
                     patch.object(fixture, 'receipt', side_effect=save):
                    if scenario in ('fresh', 'ready'):
                        result = fixture.prepare_node_apparmor(cluster, 'candidate:server')
                        self.assertEqual(result['state'], 'complete')
                        self.assertEqual(mutations, ([] if scenario == 'ready' else ['mount']) + ['parser', 'containerd', 'kubelet'])
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
                            self.assertEqual(mutations, ['mount', 'parser'])
                            cluster.k.assert_not_called()
                        else:
                            self.assertEqual(mutations, ['mount'] + (['parser'] if scenario == 'daemon-replaced' else []) if scenario in ('host-changed', 'daemon-replaced') else [])
                            self.assertNotIn('kubelet', mutations)
                            cluster.k.assert_not_called()

    def test_owned_node_restoration_preserves_preimages_and_refuses_drift_replay_or_live_tasks(self):
        old_mount=b'1 0 0:1 / / rw shared:10 - overlay overlay rw\n2 1 0:2 / /sys rw shared:11 - sysfs sysfs rw\n'
        new_mount=old_mount+b'3 2 0:3 / /sys/kernel/security ro,nosuid,nodev,noexec - securityfs securityfs rw\n'
        identity={'container_id':'1'*64,'container_pid':1234};uid='12345678-1234-1234-1234-123456789abc'
        postgres={'uid':'23456789-1234-1234-1234-123456789abc','container_id':'containerd://'+'2'*64,'restart_count':0}
        runtime={'pid':2000,'start_ticks':3000,'shim':{'pid':1999,'start_ticks':2999,'binary_sha256':'6'*64}}
        def processes(kubelet,daemon):
            return {'kubelet_pid':kubelet,'kubelet_process':{'pid':kubelet,'start_ticks':kubelet*10,'binary_sha256':'4'*64},
                'containerd':{'pid':daemon,'start_ticks':daemon*10,'binary_sha256':'5'*64,'kill_mode':'process'},
                'postgres':postgres,'postgres_runtime':runtime,'host_mounts_sha256':'3'*64}
        for scenario in ('valid','preexisting','wrong-uid','wrong-cid','wrong-ns','wrong-inode','wrong-ctime','wrong-mount',
                         'wrong-preimage','pg-drift','shim-drift','kubelet-binary-drift','host-drift','private-storage-drift',
                         'namespace-live','policy-live','profile-live','attached-live','replay','lost-intent',
                         'unlink-failure','umount-failure','reset-failure','pg-after-reset'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                mutations=[];parser_present=[True]
                original=new_mount if scenario=='preexisting' else old_mount
                mounted,after_sha=fixture.securityfs_state(new_mount)
                _cover,before_sha=fixture.securityfs_state(original)
                prepared={'version':1,'synthetic':True,'state':'complete','identity':{**identity,'profile':'devres-acceptance-fixture',
                    'node_uid':uid,'host_mount_namespace':'mnt:[10]','node_mount_namespace':'mnt:[20]'},
                    'source_sha256':hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),'apparmor_sha256':fixture.APPARMOR_SHA256,
                    'before':processes(80,50),'after':processes(100,90),'securityfs_preexisting':scenario=='preexisting',
                    'server_image':'candidate:server','parser':PARSER,'write_boundaries':{'projection_sha256':'a'*64},
                    'securityfs_before_sha256':before_sha,'securityfs_after_sha256':after_sha,'securityfs_mount':mounted,
                    'securityfs_created':scenario!='preexisting','kubelet_restarted':True,'containerd_restarted':True,
                    'parser_placement':PLACEMENT}
                fixture.validate_node_preparation('npm-assessment-node-preparation.json',prepared)
                cluster=fixture.Cluster('devres-acceptance-fixture',Path(temporary));cluster.k=unittest.mock.Mock()
                def objects(kind):return [{}] if scenario==kind+'-live' else []
                cluster.owned_objects=objects
                def execute(_identity,*args,**kwargs):
                    self.assertEqual(_identity,identity)
                    if args==('cat','/proc/self/mountinfo'):
                        raw=original if 'umount' in mutations else new_mount
                        if scenario=='wrong-mount':raw=raw.replace(b'3 2 0:3',b'4 2 0:3')
                        if scenario=='wrong-preimage' and 'umount' in mutations:raw=raw.replace(b'shared:11',b'shared:12')
                        return subprocess.CompletedProcess([],0,raw,b'')
                    if args[:1]==('unlink',):
                        self.assertEqual(args,('unlink','--','/usr/sbin/apparmor_parser'));mutations.append('unlink');parser_present[0]=False
                        if scenario=='unlink-failure':raise fixture.FixtureError('fixture_command_failed')
                    elif args[:1]==('umount',):
                        self.assertEqual(args,('umount','--',fixture.NODE_SECURITYFS));mutations.append('umount')
                        if scenario=='umount-failure':raise fixture.FixtureError('fixture_command_failed')
                    elif args[:2]==('/bin/sh','-c'):
                        self.assertFalse(parser_present[0]);self.assertIn('test ! -e /usr/sbin/apparmor_parser',args[2])
                    elif args[:2]==('systemctl','restart'):
                        self.assertIn(args[2],('containerd','kubelet'));mutations.append(args[2])
                        if scenario=='reset-failure':raise fixture.FixtureError('fixture_command_failed')
                    else:raise AssertionError(args)
                    return subprocess.CompletedProcess([],0,b'',b'')
                file_identity=copy.deepcopy(PARSER_FILE)
                if scenario=='wrong-inode':file_identity['inode']+=1
                if scenario=='wrong-ctime':file_identity['ctime']='2026-11-17 12:00:00.123456788 +0000'
                def pg(_cluster):
                    return {**postgres,'restart_count':1} if scenario=='pg-drift' or scenario=='pg-after-reset' and 'containerd' in mutations else postgres
                def daemon(_identity):return processes(100,190 if 'containerd' in mutations else 90)['containerd']
                def kubelet_runtime(_identity,pid,_name):
                    value=processes(pid,90)['kubelet_process']
                    if scenario=='kubelet-binary-drift':value={**value,'binary_sha256':'7'*64}
                    return value,1
                actual_receipt=fixture.receipt
                def save(_cluster,name,value):
                    if scenario=='lost-intent' and name=='npm-assessment-node-restoration-intent.json':return False
                    return actual_receipt(_cluster,name,value)
                if scenario=='replay':
                    intent={'version':1,'synthetic':True,'state':'prepared','preparation':prepared,
                        'preparation_sha256':hashlib.sha256(json.dumps(prepared,sort_keys=True).encode()+b'\n').hexdigest(),
                        'before':prepared['after'],'after':None,'parser_removed':False,'securityfs_restored':False,'securityfs_final_sha256':None}
                    fixture.private_json(Path(temporary)/'npm-assessment-node-restoration-intent.json',intent)
                with patch.dict(os.environ,{'DEVRES_E2E_DIAGNOSTICS_DIR':''}), \
                     patch.object(fixture,'node_docker_identity',return_value={**identity,'container_id':'2'*64} if scenario=='wrong-cid' else identity), \
                     patch.object(fixture,'node_uid',return_value='34567890-1234-1234-1234-123456789abc' if scenario=='wrong-uid' else uid), \
                     patch.object(fixture,'node_namespace',return_value='mnt:[30]' if scenario=='wrong-ns' else 'mnt:[20]'), \
                     patch.object(fixture,'host_mount_state',return_value=('mnt:[10]','9'*64 if scenario=='host-drift' else '3'*64,{'shared:3'})), \
                     patch.object(fixture,'node_write_boundaries',return_value={'projection_sha256':'b'*64 if scenario=='private-storage-drift' else 'a'*64}), \
                     patch.object(fixture,'no_attached_tasks',return_value=scenario!='attached-live'), \
                     patch.object(fixture,'command',return_value=subprocess.CompletedProcess([],0,b'devres-runtime (enforce)\n' if scenario=='profile-live' else b'docker-default (enforce)\n',b'')), \
                     patch.object(fixture,'parser_placement_state',return_value=file_identity),patch.object(fixture,'node_exec',side_effect=execute), \
                     patch.object(fixture,'postgres_process',side_effect=pg), \
                     patch.object(fixture,'postgres_runtime',return_value={**runtime,'shim':{**runtime['shim'],'pid':1998}} if scenario=='shim-drift' else runtime), \
                     patch.object(fixture,'containerd_process',side_effect=daemon), \
                     patch.object(fixture,'kubelet_process',side_effect=lambda _identity:200 if 'kubelet' in mutations else 100), \
                     patch.object(fixture,'node_process',side_effect=kubelet_runtime),patch.object(fixture,'receipt',side_effect=save):
                    if scenario in ('valid','preexisting'):
                        fixture.restore_node_apparmor(cluster,prepared)
                        self.assertEqual(mutations,['unlink']+([] if scenario=='preexisting' else ['umount'])+['containerd','kubelet'])
                        value=json.loads((Path(temporary)/'npm-assessment-node-restoration.json').read_bytes())
                        fixture.validate_node_restoration('npm-assessment-node-restoration.json',value)
                        self.assertEqual(value['securityfs_final_sha256'],before_sha)
                    else:
                        with self.assertRaises(fixture.FixtureError):fixture.restore_node_apparmor(cluster,prepared)
                        self.assertFalse((Path(temporary)/'npm-assessment-node-restoration.json').exists())
                        if scenario=='unlink-failure':self.assertEqual(mutations,['unlink'])
                        elif scenario in ('umount-failure','wrong-preimage'):self.assertEqual(mutations,['unlink','umount'])
                        elif scenario=='reset-failure':self.assertEqual(mutations,['unlink','umount','containerd'])
                        elif scenario=='pg-after-reset':self.assertEqual(mutations,['unlink','umount','containerd','kubelet'])
                        else:self.assertEqual(mutations,[])
                        failure=json.loads((Path(temporary)/'npm-assessment-node-restoration-failure.json').read_bytes())
                        fixture.validate_receipt('npm-assessment-node-restoration-failure.json',failure)
                        self.assertNotIn('stderr',json.dumps(failure))

    def test_securityfs_restoration_refuses_stacked_or_descendant_mounts(self):
        raw=b'1 0 0:1 / /sys rw - sysfs sysfs rw\n2 1 0:2 / /sys/kernel/security ro,nosuid,nodev,noexec - securityfs securityfs rw\n'
        fixture.securityfs_state(raw)
        for extra in (b'3 1 0:3 / /sys/kernel/security ro - securityfs securityfs rw\n',
                      b'3 2 0:3 / /sys/kernel/security/foreign rw - tmpfs tmpfs rw\n'):
            with self.assertRaises(fixture.FixtureError):fixture.securityfs_state(raw+extra)

    def test_restoration_follows_checked_task_cleanup_and_precedes_final_success(self):
        for failed in (False,True):
            with self.subTest(failed=failed),tempfile.TemporaryDirectory(dir='/tmp') as temporary:
                events=[];records=[];prepared=object()
                class Cluster:
                    profile='devres-acceptance-fixture';scratch=Path(temporary)
                    def owned_objects(self,_kind):return []
                    def apply(self,_objects):pass
                    def create(self,_objects):pass
                    def admit_owned(self,_kind):return '12345678-1234-1234-1234-123456789abc'
                    def cleanup_owned(self,kind):events.append(kind+'-cleaned')
                    def k(self,*_args,**_kwargs):return subprocess.CompletedProcess([],0,b'',b'')
                cluster=Cluster();(cluster.scratch/'fixture').mkdir();(cluster.scratch/'fixture/backend.toml').write_text('synthetic')
                @contextlib.contextmanager
                def profile(_scratch,stopped):
                    try:yield fixture.APPARMOR_SHA256
                    finally:
                        self.assertTrue(stopped());events.append('profile-cleaned')
                error=fixture.FixtureError('fixture_node_restoration_identity')
                def restore(actual_cluster,actual_prepared):
                    self.assertIs(actual_cluster,cluster);self.assertIs(actual_prepared,prepared)
                    self.assertIn('namespace-cleaned',events);self.assertIn('policy-cleaned',events)
                    self.assertEqual(events[-1],'profile-cleaned');events.append('restore-attempt')
                    if failed:raise error
                    events.append('restored')
                def receipt(_cluster,name,value):events.append(name);records.append((name,value));return True
                args=types.SimpleNamespace(profile=cluster.profile,scratch=temporary,harness_image='harness:fixture',server_image='candidate:server')
                with patch.object(fixture,'Cluster',return_value=cluster),patch.object(fixture,'prepare_node_apparmor',return_value=prepared), \
                     patch.object(fixture,'apparmor',side_effect=profile),patch.object(fixture,'restore_node_apparmor',side_effect=restore), \
                     patch.object(fixture,'configuration',return_value='synthetic'),patch.object(fixture,'network_probe',return_value={}), \
                     patch.object(fixture,'seed',return_value={}),patch.object(fixture,'snapshot',return_value={}), \
                     patch.object(fixture,'assess',return_value={'phase':'report_transferred'}),patch.object(fixture,'failure_matrix',return_value=[]), \
                     patch.object(fixture,'receipt',side_effect=receipt):
                    if failed:
                        with self.assertRaises(fixture.FixtureError) as caught:fixture.run(args)
                        self.assertIs(caught.exception,error)
                        self.assertNotIn('npm-assessment-receipt.json',events)
                        self.assertEqual(records[-1][1]['phase'],'node-restoration')
                        self.assertEqual(records[-1][1]['namespace_cleanup'],'removed')
                        self.assertEqual(records[-1][1]['apparmor_cleanup'],'removed')
                    else:
                        fixture.run(args)
                        self.assertEqual(events[-2:],['restored','npm-assessment-receipt.json'])

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
                uid = '12345678-1234-1234-1234-123456789abc'
                admitted = {}
                def apply(pod):
                    admitted.update(copy.deepcopy(pod));admitted['metadata']['uid'] = uid;events.append('apply')
                cluster = types.SimpleNamespace(profile='devres-acceptance-fixture', create=apply,
                    pod=lambda _name: admitted,
                    k=unittest.mock.Mock(side_effect=error), delete=delete)
                def inspect(_cluster, uid):
                    events.append(('inspect', uid))
                    return metadata
                with patch.object(fixture, 'network_failure_metadata', side_effect=inspect):
                    with self.assertRaises(fixture.FixtureError) as caught:
                        fixture.network_probe(cluster, 'harness:fixture')
                self.assertIs(caught.exception, error)
                self.assertEqual(error.probe_metadata, metadata)
                self.assertEqual(events, ['apply', ('inspect', uid), ('delete', 'assessment-network', uid)])

    def test_network_probe_uses_create_only_without_last_applied_metadata(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-fixture',Path(temporary))
            admitted, calls = {}, []
            def query(*args,**kwargs):
                calls.append((args,kwargs))
                if args[:3] == ('create','-f','-'):
                    value=json.loads(kwargs['data']);self.assertEqual(value['kind'],'List');self.assertEqual(len(value['items']),1)
                    admitted.update(value['items'][0]);admitted['metadata']['uid']='12345678-1234-1234-1234-123456789abc'
                    return subprocess.CompletedProcess([],0,b'',b'')
                raise fixture.FixtureError('fixture_command_failed')
            with patch.object(cluster,'k',side_effect=query),patch.object(cluster,'pod',return_value=admitted), \
                 patch.object(cluster,'apply') as apply,patch.object(cluster,'delete'),patch.object(fixture,'network_failure_metadata',return_value=None):
                with self.assertRaises(fixture.FixtureError):fixture.network_probe(cluster,'harness:fixture')
            apply.assert_not_called()
            self.assertEqual(calls[0][0],('create','-f','-'));self.assertEqual(calls[0][1]['namespace'],fixture.NAMESPACE)
            self.assertNotIn('annotations',admitted['metadata'])
            self.assertTrue(all(args[0]!='apply' for args,_kwargs in calls))

    def test_network_probe_enforcement_code_rejects_unconfined_alias_access_and_wrong_errno(self):
        admitted = {}
        def apply(pod):
            admitted.update(copy.deepcopy(pod));admitted['metadata']['uid'] = '12345678-1234-1234-1234-123456789abc'
        cluster = types.SimpleNamespace(profile='devres-acceptance-fixture', create=apply, pod=lambda _name: admitted,
            k=unittest.mock.Mock(side_effect=fixture.FixtureError('fixture_command_failed')), delete=unittest.mock.Mock())
        with patch.object(fixture, 'network_failure_metadata', return_value=None):
            with self.assertRaises(fixture.FixtureError): fixture.network_probe(cluster, 'harness:fixture')
        container = admitted['spec']['containers'][0]
        self.assertEqual(container['volumeMounts'], [{'name': 'tmp', 'mountPath': '/tmp'},
                         {'name': 'tmp', 'mountPath': '/sys/kernel/security', 'readOnly': True}])
        self.assertEqual(admitted['spec']['volumes'], [{'name': 'tmp', 'emptyDir': {'sizeLimit': '16Mi'}}])
        self.assertEqual(container['securityContext'], fixture.template('harness:fixture')['spec']['containers'][0]['securityContext'])
        source = container['command'][-1]
        class DeniedConnection:
            def settimeout(self, _timeout): pass
            def connect(self, _address): raise OSError('owned synthetic denied API')
            def close(self): pass
        for scenario in ('valid', 'unconfined', 'alias-readable', 'alias-absent', 'positive-unreadable'):
            def open_file(path, mode='r', *_args, **_kwargs):
                if path == '/proc/self/attr/current': return io.StringIO('unconfined' if scenario == 'unconfined' else 'devres-runtime (enforce)')
                if path == '/tmp/apparmor-canary' and mode == 'xb': return io.BytesIO()
                if path == '/tmp/apparmor-canary':
                    if scenario == 'positive-unreadable': raise PermissionError(13, 'synthetic')
                    return io.BytesIO(b'owned-synthetic-apparmor-canary')
                if path == '/sys/kernel/security/apparmor-canary':
                    if scenario == 'alias-readable': return io.BytesIO(b'owned-synthetic-apparmor-canary')
                    raise OSError(2 if scenario == 'alias-absent' else 13, 'synthetic')
                raise AssertionError(path)
            output = io.StringIO()
            with self.subTest(scenario=scenario), patch('builtins.open', side_effect=open_file), \
                 patch.object(os, 'chmod'), patch.object(socket, 'create_connection', return_value=contextlib.nullcontext()), \
                 patch.object(socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('10.0.0.1',443))]), \
                 patch.object(socket, 'socket', return_value=DeniedConnection()), contextlib.redirect_stdout(output):
                if scenario == 'valid':
                    exec(compile(source, '<owned-first-party-network-probe>', 'exec'), {})
                    result = json.loads(output.getvalue());self.assertTrue(result['apparmor_enforcing']);self.assertTrue(result['canonical_alias_read_denied'])
                else:
                    with self.assertRaises((AssertionError, OSError)):
                        exec(compile(source, '<owned-first-party-network-probe>', 'exec'), {})

    def test_network_probe_refuses_changed_admitted_alias_before_wait_and_uid_cleans_it(self):
        uid = '12345678-1234-1234-1234-123456789abc'
        for scenario in ('alias', 'uid', 'image', 'command'):
            admitted = {}
            def apply(pod):
                admitted.update(copy.deepcopy(pod));admitted['metadata']['uid'] = uid
                container = admitted['spec']['containers'][0]
                if scenario == 'alias': container['volumeMounts'][1]['readOnly'] = False
                elif scenario == 'uid': admitted['spec']['securityContext']['runAsUser'] = 0
                elif scenario == 'image': container['image'] = 'foreign:fixture'
                elif scenario == 'command': container['command'] = ['foreign-command']
            cluster = types.SimpleNamespace(profile='devres-acceptance-fixture', create=apply, pod=lambda _name: admitted, k=unittest.mock.Mock(), delete=unittest.mock.Mock())
            with self.subTest(scenario=scenario), patch.object(fixture, 'network_failure_metadata', return_value=None):
                with self.assertRaisesRegex(fixture.FixtureError, 'assessment_egress_evidence_invalid'):
                    fixture.network_probe(cluster, 'harness:fixture')
            cluster.k.assert_not_called();cluster.delete.assert_called_once_with('assessment-network', uid)

    def test_probe_authority_accepts_only_safe_api_defaults_and_rejects_every_executable_mutation(self):
        expected = fixture.template('harness:fixture')
        expected['metadata'] = {'name':'assessment-network','namespace':fixture.NAMESPACE,'labels':{'app':'backend'}}
        expected['spec'].update(nodeName='devres-acceptance-fixture',restartPolicy='Never',activeDeadlineSeconds=30)
        cluster = types.SimpleNamespace(profile='devres-acceptance-fixture')
        actual = copy.deepcopy(expected);actual['metadata']['uid'] = '12345678-1234-1234-1234-123456789abc'
        actual['spec'].update(hostNetwork=False,hostPID=False,hostIPC=False,initContainers=[],ephemeralContainers=[],
            serviceAccount='assessment',dnsPolicy='ClusterFirst',schedulerName='default-scheduler',priority=0,
            preemptionPolicy='PreemptLowerPriority',terminationGracePeriodSeconds=30,enableServiceLinks=True)
        actual['spec']['containers'][0].update(terminationMessagePath='/dev/termination-log',terminationMessagePolicy='File',
            stdin=False,tty=False,env=[],args=[])
        self.assertEqual(fixture.probe_authority(cluster,expected,actual),actual['metadata']['uid'])
        mutations = (
            ('hostNetwork',lambda value:value['spec'].update(hostNetwork=True)),
            ('hostPID',lambda value:value['spec'].update(hostPID=True)),
            ('hostIPC',lambda value:value['spec'].update(hostIPC=True)),
            ('init',lambda value:value['spec'].update(initContainers=[{'image':'foreign'}])),
            ('ephemeral',lambda value:value['spec'].update(ephemeralContainers=[{'image':'foreign'}])),
            ('extra-container',lambda value:value['spec']['containers'].append({'image':'foreign'})),
            ('service-account',lambda value:value['spec'].update(serviceAccountName='foreign')),
            ('automount',lambda value:value['spec'].update(automountServiceAccountToken=True)),
            ('node',lambda value:value['spec'].update(nodeName='foreign')),
            ('labels',lambda value:value['metadata']['labels'].update(app='foreign')),
            ('annotation',lambda value:value['metadata'].update(annotations={'container.apparmor.security.beta.kubernetes.io/probe':'unconfined'})),
            ('dns',lambda value:value['spec'].update(dnsPolicy='Default')),
            ('env',lambda value:value['spec']['containers'][0].update(env=[{'name':'LD_PRELOAD','value':'foreign'}])),
            ('envFrom',lambda value:value['spec']['containers'][0].update(envFrom=[{'secretRef':{'name':'foreign'}}])),
            ('args',lambda value:value['spec']['containers'][0].update(args=['foreign'])),
            ('privileged',lambda value:value['spec']['containers'][0]['securityContext'].update(privileged=True)),
            ('hostpath',lambda value:value['spec']['volumes'].append({'name':'foreign','hostPath':{'path':'/'}})),
            ('runtimeclass',lambda value:value['spec'].update(runtimeClassName='foreign')),
            ('unknown',lambda value:value['spec'].update(foreignFutureAuthority=True)))
        for name, mutate in mutations:
            candidate = copy.deepcopy(actual);mutate(candidate)
            with self.subTest(name=name), self.assertRaisesRegex(fixture.FixtureError,'assessment_egress_evidence_invalid'):
                fixture.probe_authority(cluster,expected,candidate)

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

    def test_readiness_policy_targets_only_the_allowed_assessment_sender(self):
        _default, baseline_outbound, baseline_inbound = fixture.policies()
        outbound, inbound = fixture.readiness_policies()
        self.assertEqual(outbound['spec']['policyTypes'], ['Ingress', 'Egress'])
        self.assertNotIn('ingress', outbound['spec'])
        self.assertEqual(outbound['spec']['podSelector'], {'matchLabels': {'app': 'devres-npm-assessment'}})
        self.assertEqual(outbound['spec']['egress'], baseline_outbound['spec']['egress'])
        self.assertEqual(inbound['spec']['podSelector'], baseline_inbound['spec']['podSelector'])
        rule, = inbound['spec']['ingress']
        self.assertEqual(rule['ports'], [{'port': 5432, 'protocol': 'TCP'}])
        self.assertEqual(rule['from'], [{
            'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': fixture.NAMESPACE}},
            'podSelector': {'matchLabels': {'app': 'devres-npm-assessment', 'devres-assessment': 'cold-readiness'}},
        }])

    def test_readiness_requires_single_cli_and_denial_stops_before_sql_setup(self):
        def event(phase, outcome, reason='none', elapsed_ms=None, child_exit=None):
            return {'phase': phase, 'outcome': outcome, 'reason': reason,
                    'elapsed_ms': elapsed_ms, 'child_exit': child_exit}

        start = [event('cli_start', 'start'), event('sql_connect', 'start', elapsed_ms=1)]
        retry = event('sql_connect_retry', 'error', 'timeout', elapsed_ms=3001)
        sql_setup = [event('sql_setup', 'start'), event('sql_setup', 'ok')]
        connected = [event('sql_connect', 'ok'), *sql_setup, event('cli_exit', 'ok', child_exit=0)]
        timed_out = [event('sql_connect', 'error', 'timeout', elapsed_ms=30_002),
                     event('cli_exit', 'error', 'unknown', child_exit=1)]
        for retries in ([], [retry]):
            fixture.validate_readiness_result({'case': 'cold-readiness', 'phase': 'report_transferred',
                                               'events': [*start, *retries, *connected]})
        denial = {'case': 'readiness-denied', 'phase': 'terminal', 'exit_code': 1,
                  'diagnostics': [*start, retry, *timed_out]}
        fixture.validate_readiness_result(denial)
        for invalid in ([*start, *timed_out], [*start, retry, retry, *timed_out],
                        [*start, retry, *sql_setup, *timed_out], [*start, retry, *timed_out, *start],
                        [*start, retry, {**timed_out[0], 'elapsed_ms': 3002}, timed_out[1]]):
            with self.subTest(diagnostics=invalid), self.assertRaisesRegex(fixture.FixtureError, 'assessment_readiness_result'):
                fixture.validate_readiness_result({**denial, 'diagnostics': invalid})

    def test_cold_readiness_uses_create_only_and_production_assessment_label(self):
        api = fixture.helper()
        selected = {'job_id': 'blake3:' + '1' * 64, 'revision': 1}
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            cluster = fixture.Cluster('devres-acceptance-fixture', Path(temporary))
            cluster.expected_image = IDENTITY
            admitted = {}
            uid = '12345678-1234-1234-1234-123456789abc'

            def create(pod):
                self.assertEqual(pod['metadata']['labels'], {
                    'app': 'devres-npm-assessment', 'devres-assessment': 'cold-readiness'})
                self.assertIn('--connect-readiness wait', pod['spec']['containers'][0]['command'][-1])
                admitted.update(copy.deepcopy(pod))
                admitted['metadata']['uid'] = uid

            def supervise(*, get_pod, cleanup, **_kwargs):
                try:
                    self.assertEqual(get_pod()['metadata']['uid'], uid)
                    admitted['metadata']['labels'] = {'app': 'backend'}
                    get_pod()
                finally:
                    cleanup()

            with patch.object(cluster, 'create', side_effect=create) as created, \
                 patch.object(cluster, 'apply') as applied, \
                 patch.object(cluster, 'pod', side_effect=lambda _name: admitted), \
                 patch.object(cluster, 'delete') as deleted, \
                 patch.object(api, 'supervise', side_effect=supervise):
                with self.assertRaisesRegex(fixture.FixtureError, 'assessment_readiness_labels_changed'):
                    fixture.assess(cluster, 'candidate:server', selected, api, 'cold-readiness')
                created.assert_called_once()
                applied.assert_not_called()
                deleted.assert_called_once_with('assessment-cold-readiness', uid)

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
                if value == 'SHOW ssl':
                    return b'off\n'
                return ('blake3:' + '1' * 64).encode()
        cluster = Cluster()
        expected = {'malformed-config': 'config_load', 'wrong-dns': 'sql_connect', 'bad-password': 'sql_connect',
                    'existing-output': 'output_create', 'ready-denied': 'ready_write',
                    'wrong-schema': 'schema', 'missing-grant': 'history_select',
                    'output-symlink': 'output_create', 'output-wrong-mode': 'output_create',
                    'output-wrong-owner': 'output_create', 'restore-pending': 'schema',
                    'corrupt-history': 'history_select', 'held-lifecycle': 'lifecycle', 'required-tls': 'sql_connect'}
        readiness_enabled = []
        def assess(_cluster, _image, _selected, _api, case, *, connect_readiness=False):
            if connect_readiness:
                readiness_enabled.append(case)
            if case == 'telemetry-unavailable':
                return {'phase': 'report_transferred', 'events': None}
            return {'phase': 'terminal', 'exit_code': 1, 'diagnostics': [
                {'phase': 'cli_start', 'outcome': 'start'},
                {'phase': expected[case], 'outcome': 'error', 'reason': fixture.READINESS_FAULTS.get(case)},
                {'phase': 'cli_exit', 'outcome': 'ok' if case == 'ready-denied' else 'error',
                 'child_exit': 0 if case == 'ready-denied' else 1}]}
        with patch.object(fixture, 'snapshot', return_value={'fixture': 'unchanged'}), \
             patch.object(fixture, 'set_config') as set_config, patch.object(fixture, 'assess', side_effect=assess), \
             patch.object(fixture, 'lifecycle_exclusion', return_value=contextlib.nullcontext()):
            config = '[storage]\ndatabase_url="' + fixture.DATABASE_READER + '"\n'
            self.assertEqual(len(fixture.failure_matrix(cluster, 'server', {}, None, config, 'harness')), 14)
            self.assertEqual(readiness_enabled, [])
            self.assertEqual(len(fixture.failure_matrix(cluster, 'server', {}, None, config, 'harness',
                                                        connect_readiness=True)), 15)
            self.assertEqual(readiness_enabled, list(fixture.READINESS_FAULTS))
            self.assertTrue(any('?sslmode=require' in call.args[1] for call in set_config.call_args_list))
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
