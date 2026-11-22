import base64
import copy
import pathlib
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/production'))
import rollout_5a865235_render as rollout
import rollout_5a865235_preflight as preflight


def baseline():
    result = {}
    for name, (api, kind, resource, _) in rollout.RESOURCE_FIELDS.items():
        result[name] = {'apiVersion': api, 'kind': kind, 'metadata': {
            'namespace': 'devres', 'name': resource, 'uid': name, 'resourceVersion': '42',
        }}
    for role, image in rollout.BASELINE_IMAGES.items():
        result[role]['spec'] = {'replicas': 1, 'strategy': {'type': 'Recreate'}, 'template': {
            'metadata': {'labels': {'app': role, 'maintain': 'unchanged'}},
            'spec': {
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532,
                                    'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'},
                                    'appArmorProfile': {'type': 'Localhost', 'localhostProfile': 'devres-runtime'}},
                'containers': [{'name': role, 'image': image, 'volumeMounts': [
                    {'name': 'tmp', 'mountPath': '/tmp'},
                    {'name': 'tls', 'mountPath': '/etc/devres/tls', 'readOnly': True},
                ]}],
                'volumes': [{'name': 'tmp', 'emptyDir': {'sizeLimit': '4Gi'}},
                            {'name': 'tls', 'secret': {'secretName': 'tls'}}],
                'automountServiceAccountToken': False,
            },
        }}
    result['service']['spec'] = {'type': 'NodePort', 'selector': {'app': 'backend'}, 'ports': [{'nodePort': 30081}]}
    config = f'''[source]
url = "{rollout.BASELINE_SOURCE_URL}"
[rfc] # keep original bytes
enabled = true
[storage]
backend = "s3"
database_url = "private-test-sentinel"
[storage.s3.credentials]
mode = "files"
'''.encode()
    for role, suffix in (('serving', b'[writer_client]\naccess = "full"\n'),
                         ('writer', b'[writer_listener]\naccess = "full"\n')):
        result[f'{role}_config'].update(type='Opaque', data={
            f'{role}.toml': base64.b64encode(config + suffix).decode(), 'other': 'b3RoZXI=',
        })
    return result


def evidence():
    return {name: name.encode() + b' synthetic test bytes\n' for name in rollout.EVIDENCE_FILES}


class RolloutRenderTests(unittest.TestCase):
    def test_forward_changes_are_limited_to_admitted_resources(self):
        original = baseline()
        result = rollout.render(original, evidence())
        self.assertEqual(original, baseline())
        variants = result['changes']
        expected_backend = copy.deepcopy(variants['backend']['before'])
        expected_backend['spec']['template']['spec']['containers'][0]['image'] = rollout.CANDIDATE_IMAGE
        self.assertEqual(variants['backend']['after'], expected_backend)
        expected_service = copy.deepcopy(variants['service']['before'])
        expected_service['spec']['selector'] = rollout.GATED_SELECTOR
        self.assertEqual(variants['service']['after'], expected_service)
        for role in ('writer', 'serving'):
            name = f'{role}_config'
            filename = f'{role}.toml'
            original_data = original[name]['data']
            self.assertEqual(variants[name]['before']['data'], original_data)
            expected_config = tomllib.loads(base64.b64decode(original_data[filename]).decode())
            self.assertEqual(expected_config['source']['url'], rollout.BASELINE_SOURCE_URL)
            expected_config['source']['url'] = rollout.CANDIDATE_SOURCE_URL
            if role == 'writer':
                expected_config['rfc'][rollout.EVIDENCE_SETTING] = rollout.EVIDENCE_DIRECTORY
            changed_config = variants[name]['after']['data']
            self.assertEqual(tomllib.loads(base64.b64decode(changed_config[filename]).decode()), expected_config)
            self.assertEqual(changed_config['other'], original_data['other'])
        self.assertNotIn('private-test-sentinel', str(result['digests']))

    def test_evidence_is_init_only_and_restricted(self):
        document = rollout.render(baseline(), evidence())
        secret = document['evidence_secret']
        self.assertEqual(secret['metadata'], {'name': rollout.EVIDENCE_SECRET, 'namespace': 'devres'})
        self.assertIs(secret['immutable'], True)
        self.assertEqual({key: base64.b64decode(value) for key, value in secret['data'].items()}, evidence())
        writer = document['changes']['writer']
        previous = writer['before']['spec']['template']['spec']
        pod = writer['after']['spec']['template']['spec']
        self.assertEqual(pod['volumes'][:-1], previous['volumes'])
        self.assertEqual(pod['securityContext'], previous['securityContext'])
        self.assertEqual(pod['containers'][0]['volumeMounts'], previous['containers'][0]['volumeMounts'])
        self.assertEqual(pod['volumes'][-1]['secret']['defaultMode'], 0o440)
        self.assertEqual(pod['volumes'][-1]['secret']['items'],
                         [{'key': name, 'path': name} for name in rollout.EVIDENCE_FILES])
        self.assertEqual(len(pod['initContainers']), 1)
        init = pod['initContainers'][0]
        self.assertEqual(init['image'], rollout.CANDIDATE_IMAGE)
        self.assertEqual(init['securityContext'], {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                                                   'capabilities': {'drop': ['ALL']}})
        self.assertEqual(init['volumeMounts'], [previous['containers'][0]['volumeMounts'][0], {
            'name': rollout.EVIDENCE_VOLUME, 'mountPath': rollout.EVIDENCE_PROJECTION, 'readOnly': True,
        }])

    def test_init_shell_creates_private_regular_copies_and_can_restart(self):
        writer = rollout.render(baseline(), evidence())['changes']['writer']['after']
        command = writer['spec']['template']['spec']['initContainers'][0]['command']
        with tempfile.TemporaryDirectory(dir='/tmp') as scratch:
            root = pathlib.Path(scratch)
            projection = root / 'projection'
            files = projection / '..data'
            files.mkdir(parents=True)
            output = root / 'writer-evidence'
            for name, contents in evidence().items():
                (files / name).write_bytes(contents)
                (projection / name).symlink_to(files / name)
            init = [*command[:-1], command[-1].replace(rollout.EVIDENCE_PROJECTION, str(projection))
                    .replace(rollout.EVIDENCE_DIRECTORY, str(output))]
            subprocess.run(init, check=True)
            subprocess.run(init, check=True)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(set(path.name for path in output.iterdir()), set(rollout.EVIDENCE_FILES))
            for name, contents in evidence().items():
                path = output / name
                status = path.lstat()
                self.assertTrue(stat.S_ISREG(status.st_mode))
                self.assertEqual(stat.S_IMODE(status.st_mode), 0o600)
                self.assertEqual(status.st_uid, output.stat().st_uid)
                self.assertEqual(status.st_nlink, 1)
                self.assertEqual(path.read_bytes(), contents)

    def test_patches_check_identity_scope_and_preimage_in_both_directions(self):
        rendered = rollout.render(baseline(), evidence())
        for name, change in rendered['changes'].items():
            for reverse in (False, True):
                with self.subTest(name=name, reverse=reverse):
                    live = copy.deepcopy(change['after' if reverse else 'before'])
                    live['metadata']['resourceVersion'] = '43'
                    if live['kind'] == 'Deployment':
                        with self.assertRaisesRegex(rollout.RenderError, '^application_replicas_must_be_zero$'):
                            rollout.guarded_patch(live, change, reverse=reverse)
                        preview = rollout.guarded_patch(live, change, reverse=reverse, dry_run=True)
                        self.assertEqual(preview[2], {'op': 'test', 'path': '/spec/replicas', 'value': 1})
                        live['spec']['replicas'] = 0
                    commands = rollout.guarded_patch(live, change, reverse=reverse)
                    self.assertEqual(commands[:2], [
                        {'op': 'test', 'path': '/metadata/uid', 'value': name},
                        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '43'},
                    ])
                    self.assertEqual([(entry['op'], entry['path']) for entry in commands[-2:]],
                                     [('test', change['path']), ('replace', change['path'])])
                    live['metadata']['uid'] = 'recreated'
                    with self.assertRaisesRegex(rollout.RenderError, '^resource_preimage_changed$'):
                        rollout.guarded_patch(live, change, reverse=reverse)

    def test_refuses_drift_and_does_not_echo_configuration(self):
        changed = baseline()
        changed['writer']['spec']['template']['spec']['volumes'][0]['hostPath'] = {'path': '/unowned'}
        with self.assertRaisesRegex(rollout.RenderError, '^writer_tmp_empty_dir_required$'):
            rollout.render(changed, evidence())
        changed = baseline()
        changed['service']['spec']['selector']['another'] = 'unexpected'
        with self.assertRaisesRegex(rollout.RenderError, '^backend_service_selector_changed$'):
            rollout.render(changed, evidence())
        changed = baseline()
        changed['writer_config']['data']['writer.toml'] = 'private-invalid-sentinel'
        with self.assertRaisesRegex(rollout.RenderError, '^invalid_runtime_configuration$'):
            rollout.render(changed, evidence())
        with self.assertRaisesRegex(rollout.RenderError, '^exact_rfc_evidence_files_required$'):
            rollout.render(baseline(), evidence() | {'not-admitted': b'bytes'})
        with self.assertRaisesRegex(rollout.RenderError, '^rfc_evidence_exceeds_secret_bounds$'):
            rollout.render(baseline(), evidence() | {'manifest.json': b'a' * (64 * 1024 + 1)})

    def test_refuses_unexpected_source_and_evidence_configuration_on_either_role(self):
        for role in ('writer', 'serving'):
            with self.subTest(role=role):
                filename = f'{role}.toml'
                original = baseline()
                data = original[f'{role}_config']['data']
                config = base64.b64decode(data[filename])
                data[filename] = base64.b64encode(config.replace(rollout.BASELINE_SOURCE_URL.encode(),
                                                                b'https://example.invalid/unknown')).decode()
                with self.assertRaisesRegex(rollout.RenderError, '^unexpected_baseline_source_url$'):
                    rollout.render(original, evidence())
                data[filename] = base64.b64encode(config.replace(b'enabled = true\n',
                    b'enabled = true\nerratum_8173_evidence_dir = "/tmp/unadmitted"\n', 1)).decode()
                with self.assertRaisesRegex(rollout.RenderError, '^existing_runtime_evidence_setting$'):
                    rollout.render(original, evidence())

    def test_preflight_requires_server_dry_run_and_compares_complete_admitted_spec(self):
        source = baseline()
        rendered = rollout.render(source, evidence())

        def run(*command, document):
            self.assertIn('--dry-run=server', command)
            if command[0] == 'create':
                self.assertEqual(document, rendered['evidence_secret'])
                return copy.deepcopy(document)
            key = next(name for name, (_, kind, resource, _) in rollout.RESOURCE_FIELDS.items()
                       if command[1:3] == (kind.lower(), resource))
            response = copy.deepcopy(rendered['changes'][key]['after'])
            if key == 'writer' and drift:
                response['spec']['template']['spec']['securityContext']['runAsUser'] = 0
            response['metadata']['resourceVersion'] = '43'
            return response

        with patch.object(preflight, 'kubectl', side_effect=run):
            drift = False
            self.assertEqual(preflight.dry_run(source, evidence()), rendered['digests'])
            drift = True
            with self.assertRaisesRegex(RuntimeError, '^dry_run_admission_changed_writer$'):
                preflight.dry_run(source, evidence())


if __name__ == '__main__':
    unittest.main()
