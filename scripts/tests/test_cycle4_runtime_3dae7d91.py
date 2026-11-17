"""Independent generated-controller tests with first-party Kubernetes templates."""
import base64
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


renderer = module('independent_cycle4_renderer', ROOT / 'deploy/production/cycle4_3dae7d91.py')
production = module('independent_cycle4_templates', ROOT / 'deploy/production/production.py')


class Cluster:
    def __init__(self, controller):
        self.u = controller
        self.settings = lambda: {'node_name': 'node'}
        settings = production.settings_checked({'node_name': 'node', 'node_ipv4': '192.0.2.10',
            'kube_api_cidrs': ['192.0.2.10/32'], 'storage_auth': 'scaleway_static',
            'apparmor_profile': 'devres-runtime'})
        self.objects = {}
        self.live_pods = {}
        self.serial = 0
        self.calls = []
        self.rows_changed = False
        for original in production.manifests(settings)['items']:
            obj = copy.deepcopy(original)
            obj['metadata'].update(uid=obj['metadata']['name'] + '-uid', resourceVersion='1')
            self.objects[(obj['kind'].lower(), obj['metadata']['name'])] = obj
        for role in ('postgres', 'writer', 'backend'):
            obj = self.get('deployment', role)
            obj['spec']['template']['spec']['containers'][0]['image'] = controller.PG_IMAGE if role == 'postgres' else controller.OLD_IMAGE
            obj['spec']['replicas'] = int(role == 'postgres')
            self.objects[('deployment', role)] = obj
        self.new_pod('postgres')
        for role, (name, key) in controller.ROLES.items():
            self.objects[('secret', name)] = {'kind': 'Secret', 'metadata': {'name': name, 'uid': name + '-uid', 'resourceVersion': '1'},
                'type': 'Opaque', 'data': {key: base64.b64encode(self.config(role).encode()).decode()}}

    def config(self, role):
        return production.runtime_config(writer=role == 'writer', auth='scaleway_static').replace(
            production.VERSION, self.u.FALLBACK_VERSION).replace('enabled = false', 'enabled = true')

    def get(self, kind, name):
        return copy.deepcopy(self.objects[(kind.lower(), name)])

    def new_pod(self, role):
        self.serial += 1
        deployment = self.objects[('deployment', role)]
        template = copy.deepcopy(deployment['spec']['template'])
        rsname = role + '-replica'
        owner = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'name': role,
            'uid': deployment['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}
        self.objects[('replicaset', rsname)] = {'metadata': {'name': rsname, 'uid': rsname + '-uid', 'ownerReferences': [owner]}}
        self.objects[('replicaset', rsname)]['kind'] = 'ReplicaSet'
        template['kind'] = 'Pod'
        template['metadata'].update(name=role + '-pod', uid=role + '-' + str(self.serial),
            ownerReferences=[{'apiVersion': 'apps/v1', 'kind': 'ReplicaSet', 'name': rsname,
                'uid': rsname + '-uid', 'controller': True, 'blockOwnerDeletion': True}])
        template['spec']['nodeName'] = 'node'
        image = template['spec']['containers'][0]['image']
        template['status'] = {'phase': 'Running', 'podIP': '10.0.0.' + str(self.serial),
            'containerStatuses': [{'ready': True, 'containerID': 'containerd://' + role + str(self.serial),
                'imageID': image, 'restartCount': 0, 'state': {'running': {'startedAt': '2026-11-17T00:00:00Z'}}}]}
        self.live_pods[role] = template

    def foundation(self):
        kinds = {'networkpolicy', 'role', 'rolebinding', 'serviceaccount', 'service', 'persistentvolumeclaim'}
        return self.u.foundation_projection([copy.deepcopy(v) for (kind, _), v in self.objects.items() if kind in kinds])

    def k(self, *args, data=None, **kwargs):
        self.calls.append((args, data))
        if args[0] == 'get':
            if args[1] == 'pods':
                return self.u.encoded({'items': list(self.live_pods.values())})
            if args[1] == 'deployments':
                return self.u.encoded({'items': [v for (kind, _), v in self.objects.items() if kind == 'deployment']})
            if args[1] == 'secrets':
                return self.u.encoded({'items': [v for (kind, _), v in self.objects.items() if kind == 'secret']})
            if args[1] == 'networkpolicies':
                return self.u.encoded({'items': [v for (kind, _), v in self.objects.items() if kind == 'networkpolicy']})
            if args[1] == 'deployments,replicasets,pods':
                return self.u.encoded({'items': [v for (kind, _), v in self.objects.items()
                    if kind in ('deployment', 'replicaset')] + list(self.live_pods.values())})
            if args[1] == 'endpointslices':
                selector = self.objects[('service', 'writer')]['spec']['selector']
                selected = [v for v in self.live_pods.values() if all(v['metadata']['labels'].get(k) == x for k, x in selector.items())]
                return self.u.encoded({'items': [{'endpoints': [{'conditions': {'ready': True},
                    'targetRef': {'uid': v['metadata']['uid']}} for v in selected]}]})
        if args[0] == 'patch':
            kind, name = args[1:3]
            obj = self.objects[(kind, name)]
            changes = json.loads(data if data is not None else args[args.index('-p') + 1])
            for change in changes:
                keys = change['path'].strip('/').split('/')
                target = obj
                for key in keys[:-1]:
                    target = target[int(key)] if isinstance(target, list) else target[key]
                key = int(keys[-1]) if isinstance(target, list) else keys[-1]
                if change['op'] == 'test':
                    if target[key] != change['value']:
                        raise RuntimeError('patch_preimage_changed')
                else:
                    target[key] = change['value']
            obj['metadata']['resourceVersion'] = str(int(obj['metadata']['resourceVersion']) + 1)
            if kind == 'deployment':
                self.live_pods.pop(name, None)
                if obj['spec']['replicas']:
                    self.new_pod(name)
            return b'{}'
        if args[0] == 'create':
            obj = json.loads(data)
            name = obj['metadata']['name']
            obj['metadata'].update(uid=name + '-uid', resourceVersion='1')
            self.objects[(obj['kind'].lower(), name)] = obj
            if obj['kind'] == 'Deployment':
                self.new_pod(name)
            return b'{}'
        if args[:2] == ('delete', '--raw'):
            kind = 'deployment' if '/deployments/' in args[2] else 'networkpolicy'
            name = args[2].split('/')[-1]
            obj = self.objects[(kind, name)]
            if json.loads(data)['preconditions']['uid'] != obj['metadata']['uid']:
                raise RuntimeError('delete_uid_changed')
            del self.objects[(kind, name)]
            if kind == 'deployment':
                self.live_pods.pop(name, None)
                self.objects.pop(('replicaset', name + '-replica'), None)
            return b'{}'
        if args[0] in ('wait', 'rollout'):
            return b''
        if args[0] == 'exec':
            query = args[args.index('-c', args.index('--')) + 1]
            if 'pg_stat_user_tables' in query:
                return self.u.encoded({'tables': [], 'captures': 4, 'archive': 5, 'owners': 0,
                    'reader_readonly': True, 'reader_mutation_tables': 0})
            if 'json_agg(c.relname' in query:
                return self.u.encoded(['devres_captures', 'devres_schema'])
            if 'row_to_json(t)' in query:
                return self.u.encoded([{'name': 'devres_captures', 'rows': 4, 'sha256': ('b' if self.rows_changed else 'a') * 64},
                    {'name': 'devres_schema', 'rows': 1, 'sha256': 'c' * 64}])
        raise AssertionError(args)


class GeneratedRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.render_root = tempfile.TemporaryDirectory(prefix='cycle4-independent-render-', dir='/tmp')
        cls.output = Path(cls.render_root.name) / 'closure'
        cls.files = renderer.render(cls.output, renderer.PREVIOUS_CONTROLLER_SHA, renderer.PREVIOUS_MANIFEST_SHA)
        cls.u = module('independent_generated_cycle4_controller', cls.output / 'upgrade-controller.py')

    @classmethod
    def tearDownClass(cls):
        cls.render_root.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cycle4-runtime-review-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.top = Path(self.temp.name)
        edge_patch = patch.object(self.u, 'cycle4_edge_bridge', return_value=(
            SimpleNamespace(native_guard=lambda _: {'edge': {}}), 'b' * 64))
        edge_patch.start(); self.addCleanup(edge_patch.stop)
        self.bundle = self.top / 'bundle'; self.bundle.mkdir(mode=0o700)
        self.cluster = Cluster(self.u)
        self.c = self.u.Controller.__new__(self.u.Controller)
        self.c.root = self.bundle; self.c.context = 'default'; self.c.plan_raw = b'plan'
        self.c.old = self.cluster; self.c.get = self.cluster.get
        self.c.locked = contextlib.nullcontext
        self.c.storage_guard = Mock()
        self.c.prior_hashes = lambda: {'predecessor': 'unchanged'}
        protected = lambda: {'boot': {}, 'edge': {}, 'foundation': self.cluster.foundation(), 'profiles': {}, 'edge_conf_tree': {}}
        self.c.prior_controller = SimpleNamespace(protected_snapshot=protected,
            edge=lambda: {}, boot=lambda: {}, profiles=lambda: {},
            prior_controller=SimpleNamespace(safety=Mock(), verify_edge_admission=Mock()))
        snap = self.c.snapshot()
        variants = {variant: {role: self.u.configuration(self.cluster.config(role), variant.endswith('active')).replace(
            self.u.SOURCE_URL, self.u.fallback_source_url()) if variant.startswith('fallback-') else
            self.u.configuration(self.cluster.config(role), variant == 'active') for role in self.u.ROLES}
            for variant in ('paused', 'active', 'fallback-paused', 'fallback-active')}
        self.u.observer_variants(variants)
        for name, value in variants.items():
            self.u.save(self.bundle / ('configs-' + name + '.json'), value)
        prepared = {**protected(), 'at': self.u.stamp(), 'prior_artifacts': self.c.prior_hashes(),
            'edge_readmission_sha256': 'b' * 64,
            'secrets': snap['secrets'], 'old_pods': snap['pods'],
            'deployments': {role: {'projection': value['projection'], 'manifest': self.cluster.get('deployment', role)}
                for role, value in snap['deployments'].items()},
            'config_hashes': {name: self.u.digest(self.u.encoded(value)) for name, value in variants.items()}}
        self.u.save(self.bundle / 'prepared.json', prepared)
        self.u.save(self.bundle / 'state.json', {'version': 1, 'revision': self.u.REVISION, 'runtime': 'target',
            'source_sha256': self.u.digest(Path(self.u.__file__).read_bytes()), 'plan_sha256': self.u.digest(self.c.plan_raw),
            'prepared_sha256': self.u.digest(self.u.encoded(prepared)), 'phase': 'prepared', 'configs': 'old',
            'images': {role: value['image'] for role, value in snap['deployments'].items()},
            'replicas': {'postgres': 1, 'writer': 0, 'backend': 0}, 'pods': snap['pods']})
        self.c.guard()
        self.c.change_config('paused', 'test-paused')
        for role in self.u.ROLES:
            self.cluster.objects[('deployment', role)]['spec']['template']['spec']['containers'][0]['image'] = self.u.IMAGE
        state = self.c.state(); state['images'].update(dict.fromkeys(self.u.ROLES, self.u.IMAGE)); state['phase'] = 'writer_ready'
        self.c.record(state)
        self.u.save(self.bundle / 'npm-assessment-completed.json', {'eligible': False, 'deferred': True, 'reason': 'legacy_unknown'})

    def observer(self):
        with patch.object(socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]):
            self.c.start_observer()

    def test_actual_generated_start_admits_only_reader_observer_authority(self):
        self.observer()
        state = self.c.state()
        self.assertEqual(state['configs'], 'observer')
        self.assertEqual(set(state['pods']), {'postgres', 'backend', 'status-observer'})
        self.assertEqual(self.cluster.get('service', 'writer')['spec']['selector'], {'app': 'status-observer'})
        pod = self.cluster.live_pods['status-observer']
        volumes = {v['name']: v for v in pod['spec']['volumes']}
        self.assertEqual(volumes['s3']['secret']['secretName'], 'devres-serving-s3')
        self.assertFalse(any('persistentVolumeClaim' in v or 'hostPath' in v for v in volumes.values()))
        self.assertTrue(self.c.observer_proof()['verified'])

    def test_observer_guard_rejects_foreign_owner_and_writer_credential_mount(self):
        self.observer()
        original = copy.deepcopy(self.cluster.live_pods['status-observer'])
        for mutate in (lambda v: v['metadata']['ownerReferences'][0].update(uid='foreign'),
                lambda v: v['spec']['volumes'].append({'name': 'writer-key', 'secret': {'secretName': 'devres-writer-s3'}}),
                lambda v: v['spec'].update(hostNetwork=True),
                lambda v: v['spec'].update(initContainers=[{'name': 'injected', 'image': 'foreign'}])):
            value = copy.deepcopy(original); mutate(value); self.cluster.live_pods['status-observer'] = value
            with self.assertRaises(RuntimeError):
                self.c.guard()
        self.cluster.live_pods['status-observer'] = original
        self.c.guard()

    def test_changed_retained_rows_prevent_transition_and_preserve_participants(self):
        self.observer(); self.cluster.rows_changed = True
        with self.assertRaisesRegex(RuntimeError, 'observer_retained_rows_changed'):
            self.c.stop_observer()
        self.assertEqual(set(self.c.state()['pods']), {'postgres', 'backend', 'status-observer'})
        self.assertFalse((self.bundle / 'observer-retained-rows-completed.json').exists())

    def test_normal_observer_stop_seals_rows_restores_service_and_removes_owned_resources(self):
        self.observer(); self.c.stop_observer()
        self.assertEqual(set(self.c.state()['pods']), {'postgres'})
        self.assertEqual(self.c.state()['configs'], 'paused')
        self.assertEqual(self.cluster.get('service', 'writer')['spec']['selector'], {'app': 'writer'})
        self.assertNotIn(('deployment', 'status-observer'), self.cluster.objects)
        self.assertFalse(any(kind == 'networkpolicy' and name.startswith('cycle4-') for kind, name in self.cluster.objects))
        self.assertTrue(self.u.load(self.bundle / 'observer-retained-rows-completed.json')['verified'])
        self.c.guard()

    def test_later_withdrawal_accepts_already_removed_observer(self):
        self.observer(); self.c.stop_observer(); self.c.withdraw()
        self.assertEqual(self.c.state()['phase'], 'withdrawn')
        self.assertEqual(set(self.c.state()['pods']), {'postgres'})

    def test_uncertain_observer_create_uid_is_not_marked_removed(self):
        self.observer()
        path = self.bundle / 'observer-resource.json'; value = self.u.load(path)
        value['deployment']['uid'] = None; value['phase'] = 'installing'; self.u.save(path, value, replace=True)
        self.cluster.objects[('deployment', 'backend')]['spec']['replicas'] = 0
        self.cluster.live_pods.pop('backend')
        state = self.c.state(); state.pop('observer', None); state['replicas']['backend'] = 0
        state['pods'] = {'postgres': state['pods']['postgres']}; self.c.record(state)
        self.c.observer_proof = Mock()
        with self.assertRaisesRegex(RuntimeError, 'observer_create_identity_reconciliation_required'):
            self.c.stop_observer(verify=False)
        self.assertNotEqual(self.u.load(path)['phase'], 'removed')

    def test_retained_manifest_admits_catalog_identifiers_and_never_exports_rows(self):
        value = self.c._retained_row_manifest()
        self.assertEqual(value['table_count'], 2)
        self.assertEqual(value['row_count'], 5)
        statements = [args[args.index('-c', args.index('--')) + 1] for args, _ in self.cluster.calls if args[0] == 'exec']
        self.assertTrue(all('READ ONLY' in sql for sql in statements))
        self.assertTrue(any('row_to_json(t)' in sql and 'sha256' in sql for sql in statements))

    def test_removed_observer_cannot_hide_resurrected_resources_or_service_selector(self):
        self.observer(); record = self.u.load(self.bundle / 'observer-resource.json'); self.c.stop_observer()
        policy = next(iter(record['policies'].values()))
        obj = copy.deepcopy(policy['manifest']); obj['metadata']['uid'] = 'unexpected-retained-policy'
        self.cluster.objects[('networkpolicy', obj['metadata']['name'])] = obj
        with self.assertRaisesRegex(RuntimeError, 'removed_observer_policy_remaining'):
            self.c.guard()
        del self.cluster.objects[('networkpolicy', obj['metadata']['name'])]
        self.cluster.objects[('deployment', 'status-observer')] = {'kind': 'Deployment',
            'metadata': {'name': 'status-observer', 'uid': 'resurrected'}}
        with self.assertRaisesRegex(RuntimeError, 'removed_observer_resource_remaining'):
            self.c.guard()
        del self.cluster.objects[('deployment', 'status-observer')]
        self.cluster.objects[('service', 'writer')]['spec']['selector'] = {'app': 'status-observer'}
        with self.assertRaisesRegex(RuntimeError, 'removed_observer_service_changed'):
            self.c.guard()

    def test_active_migration_uses_actual_bound_sampler_without_child_or_lock_reentry(self):
        self.c.change_config('active', 'test-active')
        self.c.scale('writer', 1, 'test-start-active-writer')
        state = self.c.state(); state['phase'] = 'activate-existing_incomplete'; self.c.record(state)
        work = self.top / 'work'; work.mkdir(mode=0o700)
        source = (self.output / 'operational-proof.py').read_bytes()
        self.u.save(work / 'operational-proof.py', source)
        self.u.save(work / 'source-manifest.json', {'operational-proof.py': self.u.digest(source)})
        generation = {'id': 'blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81',
            'data': {'policy_epoch': 1, 'notices': [{}]}, 'data_integrity': 'blake3:' + 'a' * 64}
        archive = {'store_id': 'store', 'epoch': 2}
        database = {'schema': 19, 'recovery': False, 'system_id': 'sys', 'archive': archive,
            'control': {'format_version': 1, 'required_policy_epoch': 2,
                'required_policy_fingerprint': 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'},
            'npm_recovery_tables': 3, 'new_tables': 2, 'new_columns': 2, 'recovery_trigger': 1,
            'reader_select_gaps': 0, 'reader_mutation_tables': 0, 'reader_default_readonly': True,
            'owners': [{'role': 'devres_writer', 'client_addr': state['pods']['writer']['pod_ip']}],
            'pinned_generation': generation, 'capture_count': 4, 'archive_files': 5}
        authority = {'roles': ['reader', 'writer', 'admin']}
        self.u.save(work / 'operational-baseline.json', {'revision': self.u.REVISION,
            'prepared_sha256': state['prepared_sha256'], 'database': {'system_id': 'sys', 'archive': archive},
            'generation_sha256': self.u.digest(self.u.encoded(generation)),
            'authority_sha256': self.u.digest(self.u.encoded(authority))})
        prior = work / 'operational-proofs/migration-before-npm'; prior.mkdir(mode=0o700, parents=True)
        prior.parent.chmod(0o700)
        self.u.save(prior / 'observation.json', {'revision': self.u.REVISION,
            'prepared_sha256': state['prepared_sha256'], 'configs_variant': 'paused',
            'pods': {'postgres': {}, 'writer': {'uid': 'bootstrap-process'}}, 'database': database})
        self.u.save(prior / 'archive-bindings.jsonl', b'archive-fixture\n')
        self.u.save(prior / 'capture-bindings.jsonl', b'capture-fixture\n')
        artifacts = [{'path': str(prior / name), 'sha256': self.u.digest((prior / name).read_bytes())}
            for name in ('observation.json', 'archive-bindings.jsonl', 'capture-bindings.jsonl')]
        self.u.save(prior / 'migration-receipt.json', {'version': 1, 'kind': 'migration19',
            'revision': self.u.REVISION, 'runtime': 'target', 'runtime_revision': self.u.REVISION,
            'prepared_sha256': state['prepared_sha256'], 'verified': True, 'configs': 'paused',
            'processes': {'postgres': {}, 'writer': {'uid': 'bootstrap-process'}}, 'artifacts': artifacts,
            'checks': {key: True for key in ('schema19', 'policy2', 'sole_writer', 'new_table_reader_grants',
                'history_preserved', 'archive_binding_preserved', 'historical_notices_preserved')}})
        common = SimpleNamespace(WORK=work, ROOT=work, RUNTIME='target', SCHEMA=19,
            IDENTITY={'revision': self.u.REVISION}, SOURCE_URL=self.u.SOURCE_URL)
        self.c.helper = Mock(return_value=SimpleNamespace())
        self.c.locked = Mock(side_effect=AssertionError('lifecycle_lock_reentry'))
        original_spec = importlib.util.spec_from_file_location
        def spec(name, path, *args, **kwargs):
            value = original_spec(name, path, *args, **kwargs)
            if name == 'cycle4_active_migration':
                loader = value.loader
                def execute(m):
                    loader.exec_module(m)
                    m.BUNDLE = self.bundle
                    m.sql = lambda query: copy.deepcopy(authority if 'verifier_sha256' in query else database)
                    m.run = lambda command: b'active'
                value.loader = SimpleNamespace(create_module=loader.create_module, exec_module=execute)
            return value
        with patch.object(self.u, 'WORK', str(work)), patch.dict(sys.modules, {'acceptance_common': common}), \
                patch.object(importlib.util, 'spec_from_file_location', side_effect=spec), \
                patch.object(self.u.Controller, '__init__', lambda value, *args: value.__dict__.update(self.c.__dict__)), \
                patch('shutil.disk_usage', return_value=SimpleNamespace(free=128 * 1024 ** 3)), \
                patch.object(os, 'statvfs', return_value=SimpleNamespace(f_favail=100)), \
                patch.object(subprocess, 'run', side_effect=AssertionError('unexpected_child_process')):
            self.c.renew_active_migration()
        receipt = self.u.load(work / 'operational-proofs/migration-active/migration-receipt.json')
        self.assertEqual(receipt['processes'], state['pods'])
        self.assertEqual(receipt['configs'], 'active')
        self.assertTrue(receipt['checks']['sole_writer'])
        self.c.locked.assert_not_called()

    def test_generated_supervisor_never_starts_fallback_for_any_failure_branch(self):
        supervisor = module('independent_generated_cycle4_supervisor', self.output / 'safety-supervisor.py')
        common = SimpleNamespace(CONTROLLER=Path(self.u.__file__),
            manifest_sources=lambda: {'upgrade-controller.py': 'digest'},
            bound_module=lambda *args: SimpleNamespace(Controller=lambda *args: self.c))
        self.c.rollback = Mock()
        with patch.object(supervisor, 'BUNDLE', self.bundle), patch.object(supervisor, 'ROOT', self.output), \
                patch.object(supervisor.subprocess, 'run', side_effect=AssertionError('fallback_child_forbidden')):
            result = supervisor.fence(common, 'manifest')
            self.assertTrue(result['pre_activation_stopped'])
            self.c.rollback.assert_not_called()
            self.u.save(self.bundle / 'accepted-backup.json', {'fixture': True})
            def restore():
                state = self.c.state(); state.update(runtime='restored', phase='withdrawn'); self.c.record(state)
            self.c.rollback.side_effect = restore
            result = supervisor.fence(common, 'manifest')
            self.assertTrue(result['schema18_restored'])
            self.assertFalse(result['fallback_service_accepted'])
            self.c.rollback.assert_called_once()
            supervisor.fence(common, 'manifest')
            self.c.rollback.assert_called_once()

    def test_generated_supervisor_consumed_restore_requires_reconciliation(self):
        supervisor = module('independent_generated_cycle4_consumed_supervisor', self.output / 'safety-supervisor.py')
        common = SimpleNamespace(CONTROLLER=Path(self.u.__file__), manifest_sources=lambda: {'upgrade-controller.py': 'digest'},
            bound_module=lambda *args: SimpleNamespace(Controller=lambda *args: self.c))
        self.u.save(self.bundle / 'rollback-intent.json', {'maximum_attempts': 1})
        self.c.rollback = Mock()
        with patch.object(supervisor, 'BUNDLE', self.bundle):
            value = supervisor.fence(common, 'manifest')
        self.assertTrue(value['directory_identity_reconciliation_required'])
        self.c.rollback.assert_not_called()


class OperationalBaselineGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        GeneratedRuntime.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        GeneratedRuntime.tearDownClass.__func__(cls)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cycle4-baseline-admission-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.top = Path(self.temp.name)
        self.work = self.top / 'work'; self.work.mkdir(mode=0o700)
        self.bundle = self.top / 'bundle'; self.bundle.mkdir(mode=0o700)
        self.c = self.u.Controller.__new__(self.u.Controller)
        self.c.root = self.bundle; self.c.context = 'default'; self.c.plan_raw = b'plan'
        self.p1 = {'postgres': {'uid': 'original-p1', 'container_id': 'first-party-fixture'}}
        self.prepared = {'revision': self.u.REVISION, 'at': self.u.stamp(), 'old_pods': self.p1}
        self.u.save(self.bundle / 'prepared.json', self.prepared)
        self.state = {'version': 1, 'revision': self.u.REVISION, 'runtime': 'target', 'phase': 'stopped',
            'configs': 'old', 'source_sha256': self.u.digest(Path(self.u.__file__).read_bytes()),
            'plan_sha256': self.u.digest(self.c.plan_raw), 'prepared_sha256': self.u.digest(self.u.encoded(self.prepared)),
            'replicas': {'postgres': 1, 'writer': 0, 'backend': 0}, 'pods': self.p1,
            'images': {'postgres': self.u.PG_IMAGE, 'writer': self.u.OLD_IMAGE, 'backend': self.u.OLD_IMAGE}}
        self.u.save(self.bundle / 'state.json', self.state)
        self.sources = {name: self.u.digest((self.output / name).read_bytes()) for name in
            ('upgrade-controller.py', 'physical-checkpoint.py', 'operational-proof.py')}
        (self.work / 'operational-proof.py').write_bytes((self.output / 'operational-proof.py').read_bytes())
        (self.work / 'operational-proof.py').chmod(0o600)
        self.u.save(self.work / 'source-manifest.json', self.sources)
        self.manifest_sha = self.u.digest(self.u.encoded(self.sources))
        patcher = patch.object(self.u, 'WORK', str(self.work)); patcher.start(); self.addCleanup(patcher.stop)
        patcher = patch.dict(os.environ, {'DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256': self.manifest_sha})
        patcher.start(); self.addCleanup(patcher.stop)
        authority = {'roles': [{'rolname': name, 'verifier_sha256': 'a' * 64} for name in
            ('devres_admin', 'devres_reader', 'devres_writer')], 'memberships': []}
        generation = {'id': 'blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81',
            'data': {'policy_epoch': 1, 'notices': ['first-party 원문 fixture']}, 'data_integrity': 'blake3:' + 'b' * 64}
        canonical = lambda value: self.u.digest(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())
        self.baseline = {'version': 1, 'kind': 'pre-upgrade-operational-baseline', 'revision': self.u.REVISION,
            'observed_at': self.u.stamp(), 'prepared_sha256': self.state['prepared_sha256'],
            'source_manifest_sha256': self.manifest_sha, 'sources': self.sources,
            'pre_upgrade': {'phase': 'stopped', 'configs': 'old', 'replicas': self.state['replicas'], 'pods': self.p1},
            'database': {'schema': 18, 'system_id': '7706567225121447965', 'control': {
                'format_version': 1, 'required_policy_epoch': 2,
                'required_policy_fingerprint': 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'},
                'archive': {'backend': 's3', 'binding': 'blake3:7cf193132e3e32eb53c877dfcce166453e5bbb1b0d3f9a39f922f194f82f38e3',
                    'epoch': 2, 'pending_binding': None, 'initializing_s3': False, 'store_id': 'a' * 32},
                'pinned_generation': generation}, 'authority': authority,
            'authority_sha256': canonical(authority), 'generation_sha256': canonical(generation),
            'collectors': {role: dict.fromkeys(self.u.PROVIDERS, True) for role in self.u.ROLES},
            'observed_preimage_collectors': {role: dict.fromkeys(self.u.PROVIDERS, False) for role in self.u.ROLES}}

    def write_baseline(self, value=None):
        path = self.work / 'operational-baseline.json'
        path.write_bytes(self.u.encoded(self.baseline if value is None else value)); path.chmod(0o600)
        return path

    def assert_no_apply(self):
        before = (self.bundle / 'state.json').read_bytes()
        with patch.object(self.u._Cycle4BaseController, 'run') as base_run:
            with self.assertRaisesRegex(RuntimeError, '^pre_upgrade_operational_baseline_required$'):
                self.c.run('apply', None, None)
            base_run.assert_not_called()
        self.assertEqual((self.bundle / 'state.json').read_bytes(), before)
        self.assertFalse((self.bundle / 'accepted-backup.json').exists())

    def test_missing_baseline_cannot_enter_direct_apply_or_mutate_state(self):
        self.assert_no_apply()
        self.assertFalse((self.work / 'operational-baseline.json').exists())

    def test_valid_baseline_enters_original_apply_flow_without_import_or_query(self):
        path = self.write_baseline(); before = path.read_bytes()
        with patch.object(self.u._Cycle4BaseController, 'run', return_value='original-flow') as base_run:
            self.assertEqual(self.c.run('apply', 'approval', 'approval-sha', 'backup', 'backup-sha'), 'original-flow')
        base_run.assert_called_once_with('apply', 'approval', 'approval-sha', 'backup', 'backup-sha')
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue(self.c.require_operational_baseline()['verified'])

    def test_malformed_or_duplicate_json_never_reaches_apply(self):
        path = self.write_baseline()
        for body in (b'{', b'[]', b'{"version":1,"version":1}'):
            path.write_bytes(body); self.assert_no_apply()

    def test_revision_prepared_schema_manifest_sources_and_p1_mismatches_are_refused(self):
        changes = (lambda v: v.update(revision='foreign'), lambda v: v.update(prepared_sha256='0' * 64),
            lambda v: v['database'].update(schema=19), lambda v: v.update(source_manifest_sha256='0' * 64),
            lambda v: v['sources'].update({'operational-proof.py': '0' * 64}),
            lambda v: v['pre_upgrade'].update(phase='writer_ready'), lambda v: v['pre_upgrade'].update(configs='paused'),
            lambda v: v['pre_upgrade'].update(pods={'postgres': {'uid': 'replacement-p2'}}),
            lambda v: v.update(authority_sha256='0' * 64), lambda v: v.update(generation_sha256='0' * 64),
            lambda v: v['observed_preimage_collectors']['writer'].update(npm=True))
        for change in changes:
            value = copy.deepcopy(self.baseline); change(value)
            with self.subTest(change=change):
                self.write_baseline(value); self.assert_no_apply()

    def test_nonprivate_linked_or_source_changed_baseline_is_refused(self):
        path = self.write_baseline(); path.chmod(0o644); self.assert_no_apply(); path.chmod(0o600)
        os.link(path, self.top / 'external-baseline-link'); self.assert_no_apply(); (self.top / 'external-baseline-link').unlink()
        path.unlink(); path.symlink_to(self.bundle / 'prepared.json'); self.assert_no_apply(); path.unlink()
        self.write_baseline(); source = self.work / 'operational-proof.py'; source.write_bytes(b'changed source')
        self.assert_no_apply()

    def test_baseline_cannot_be_admitted_after_phase_or_pg_preimage_changes(self):
        self.write_baseline()
        for change in (lambda s: s.update(phase='applied'), lambda s: s.update(configs='paused'),
                       lambda s: s.update(pods={'postgres': {'uid': 'replacement-p2'}})):
            changed = copy.deepcopy(self.state); change(changed)
            with self.subTest(change=change), patch.object(self.c, 'state', return_value=changed):
                self.assert_no_apply()


if __name__ == '__main__':
    unittest.main()
