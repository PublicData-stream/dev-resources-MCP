"""Render the reviewable resource changes for the 5a865235 rollout."""

import base64
import copy
import hashlib
import json
import re
import tomllib


NAMESPACE = 'devres'
IMAGE_REPOSITORY = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:'
CANDIDATE_IMAGE = IMAGE_REPOSITORY + '5340e8cef95433c45c3218294a829dfba3cbece9828cbbb5fb17a9f23f24d0cb'
BASELINE_IMAGES = {
    'backend': IMAGE_REPOSITORY + '05f8880386d7e96ddc75d165475ac410800932eb0848dbde99174182a125ac1f',
    'writer': IMAGE_REPOSITORY + '307f2611a63f97ab355cd1ba9a7bfc901bcc63946d015ad0aaf1795077fae417',
}
SOURCE_OFFER = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/{}/source.tar.gz'
BASELINE_SOURCE_URL = SOURCE_OFFER.format('0.1.0-build.ce5745e0')
CANDIDATE_SOURCE_URL = SOURCE_OFFER.format('0.1.0-build.5a865235')
EVIDENCE_SECRET = 'devres-rfc-8173-5a865235'
EVIDENCE_VOLUME = 'rfc-erratum-evidence'
EVIDENCE_PROJECTION = '/run/devres-erratum-inputs'
EVIDENCE_DIRECTORY = '/tmp/devres-rfc-erratum-8173'
EVIDENCE_SETTING = 'erratum_8173_evidence_dir'
EVIDENCE_FILES = (
    'manifest.json',
    '2c99878171b6740dcb03827b84e24c2526086adc3b45fe990e9bb6aba162c156',
    '2d4e029e7867060c76753ffa66dacce46f952d79092a3b2236a8b269b291e62e',
    'd5674a6cbd8c0704bdb0e9d904f7d7cdd7b29453f3dda4feaa20d3fcb5ec9e6d',
    'cd59e39e350e1955ea292a8b90ac12c75dcb27c9387011dd65718146bfec1044',
    '019b66b321898048362808c751f031cdd264bbfb5af7c13b16e24629565466a3',
    '35759ed0fb10d9baa8d79db93ca107f778aba55cc5382b32223a90557d635d40',
)
GATED_SELECTOR = {'app': 'backend', 'devres.publicdata.stream/rollout-gate': '5a865235'}
RESOURCE_FIELDS = {
    'backend': ('apps/v1', 'Deployment', 'backend', '/spec/template/spec/containers/0/image'),
    'writer': ('apps/v1', 'Deployment', 'writer', '/spec/template'),
    'service': ('v1', 'Service', 'backend', '/spec/selector'),
    'writer_config': ('v1', 'Secret', 'devres-writer-config', '/data/writer.toml'),
    'serving_config': ('v1', 'Secret', 'devres-serving-config', '/data/serving.toml'),
}


class RenderError(ValueError):
    """A finite admission failure with no raw Kubernetes or TOML values."""


def _require(condition, reason):
    if not condition:
        raise RenderError(reason)


def _definition(value, key):
    api_version, kind, name, _ = RESOURCE_FIELDS[key]
    try:
        metadata = value['metadata']
        _require((value['apiVersion'], value['kind'], metadata['namespace'], metadata['name'])
                 == (api_version, kind, NAMESPACE, name), 'resource_name_or_kind_changed')
        _require(all(isinstance(metadata[field], str) and metadata[field]
                     for field in ('uid', 'resourceVersion')), 'resource_identity_required')
        fields = ('type', 'data') if kind == 'Secret' else ('spec',)
        result = {field: copy.deepcopy(value[field]) for field in fields}
    except (KeyError, TypeError):
        raise RenderError('resource_definition_missing') from None
    result.update(apiVersion=api_version, kind=kind, metadata={
        field: metadata[field] for field in ('name', 'namespace', 'uid', 'resourceVersion')
    })
    if kind == 'Secret':
        result['immutable'] = value.get('immutable', False)
    return result


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _definition_digest(value):
    stable = copy.deepcopy(value)
    stable['metadata'].pop('resourceVersion')
    return _digest(stable)


def _runtime_config(value, *, writer):
    _require(value['type'] == 'Opaque' and value['immutable'] is False, 'mutable_runtime_config_required')
    file = 'writer.toml' if writer else 'serving.toml'
    try:
        original = base64.b64decode(value['data'][file], validate=True).decode()
        parsed = tomllib.loads(original)
        _require(parsed['source']['url'] == BASELINE_SOURCE_URL and original.count(BASELINE_SOURCE_URL) == 1,
                 'unexpected_baseline_source_url')
        _require(EVIDENCE_SETTING not in parsed.get('rfc', {}), 'existing_runtime_evidence_setting')
        _require(parsed['storage']['backend'] == 's3'
                 and parsed['storage']['s3']['credentials']['mode'] == 'files', 'static_s3_runtime_config_required')
        if writer:
            _require(parsed['writer_listener'].get('access', 'full') == 'full', 'full_writer_config_required')
    except RenderError:
        raise
    except (KeyError, AttributeError, TypeError, ValueError):
        raise RenderError('invalid_runtime_configuration') from None

    def with_setting(match):
        newline = match.group(1)
        return f'{match[0]}{EVIDENCE_SETTING} = "{EVIDENCE_DIRECTORY}"{newline}'

    changed = original.replace(BASELINE_SOURCE_URL, CANDIDATE_SOURCE_URL)
    parsed['source']['url'] = CANDIDATE_SOURCE_URL
    if writer:
        changed, count = re.subn(r'(?m)^[ \t]*\[rfc\][ \t]*(?:#[^\r\n]*)?(\r?\n)', with_setting, changed)
        _require(count == 1, 'writer_rfc_section_required')
        parsed['rfc'][EVIDENCE_SETTING] = EVIDENCE_DIRECTORY
    try:
        _require(tomllib.loads(changed) == parsed, 'runtime_configuration_changed')
    except tomllib.TOMLDecodeError:
        raise RenderError('invalid_rendered_runtime_configuration') from None
    value['data'][file] = base64.b64encode(changed.encode()).decode('ascii')


def _evidence_secret(evidence_files):
    _require(set(evidence_files) == set(EVIDENCE_FILES), 'exact_rfc_evidence_files_required')
    maximum_secret_bytes = 1024 * 1024
    _require(all(isinstance(body, bytes) and 0 < len(body) <= maximum_secret_bytes
                 for body in evidence_files.values())
             and len(evidence_files['manifest.json']) <= 64 * 1024
             and sum(map(len, evidence_files.values())) <= maximum_secret_bytes,
             'rfc_evidence_exceeds_secret_bounds')
    return {
        'apiVersion': 'v1',
        'kind': 'Secret',
        'metadata': {'name': EVIDENCE_SECRET, 'namespace': NAMESPACE},
        'type': 'Opaque',
        'immutable': True,
        'data': {filename: base64.b64encode(evidence_files[filename]).decode('ascii')
                 for filename in EVIDENCE_FILES},
    }


def _add_writer_evidence(template):
    pod = template['spec']
    security = pod.get('securityContext', {})
    _require(security.get('runAsNonRoot') is True
             and all(security.get(field) == 65532 for field in ('runAsUser', 'runAsGroup', 'fsGroup'))
             and security.get('seccompProfile', {}).get('type') == 'RuntimeDefault'
             and security.get('appArmorProfile') == {'type': 'Localhost', 'localhostProfile': 'devres-runtime'},
             'restricted_writer_pod_required')
    volumes = pod['volumes']
    mounts = pod['containers'][0]['volumeMounts']
    tmp = [volume for volume in volumes if volume['name'] == 'tmp']
    mount = [entry for entry in mounts if entry['mountPath'] == '/tmp']
    _require(len(tmp) == 1 and set(tmp[0]) == {'name', 'emptyDir'} and mount == [{'name': 'tmp', 'mountPath': '/tmp'}],
             'writer_tmp_empty_dir_required')
    _require(not pod.get('initContainers') and all(volume['name'] != EVIDENCE_VOLUME for volume in volumes)
             and all(entry['name'] != EVIDENCE_VOLUME for entry in mounts), 'writer_evidence_mount_collision')
    volumes.append({'name': EVIDENCE_VOLUME, 'secret': {
        'secretName': EVIDENCE_SECRET,
        'defaultMode': 0o440,
        'items': [{'key': name, 'path': name} for name in EVIDENCE_FILES],
    }})
    script = '\n'.join((
        'umask 077',
        f'test ! -L {EVIDENCE_DIRECTORY}',
        f'install -d -m 0700 -- {EVIDENCE_DIRECTORY}',
        f'for name in {" ".join(EVIDENCE_FILES)}; do',
        f'    install -m 0600 -- "{EVIDENCE_PROJECTION}/$name" "{EVIDENCE_DIRECTORY}/$name"',
        'done',
    ))
    pod['initContainers'] = [{
        'name': 'stage-rfc-erratum-evidence',
        'image': CANDIDATE_IMAGE,
        'imagePullPolicy': 'IfNotPresent',
        'command': ['/bin/sh', '-ec', script],
        'resources': {'requests': {'cpu': '10m', 'memory': '8Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}},
        'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                            'capabilities': {'drop': ['ALL']}},
        'terminationMessagePath': '/dev/termination-log',
        'terminationMessagePolicy': 'File',
        'volumeMounts': [copy.deepcopy(mount[0]),
                         {'name': EVIDENCE_VOLUME, 'mountPath': EVIDENCE_PROJECTION, 'readOnly': True}],
    }]


def render(baseline, evidence_files):
    """Keep both private preimages and targets in memory for source-bound application.

    The caller must validate the exact evidence bytes with the release's evidence
    validator before rendering and verify the gate label matches no live Pod.
    """
    original = {name: _definition(baseline.get(name), name) for name in RESOURCE_FIELDS}
    desired = copy.deepcopy(original)
    for role, image in BASELINE_IMAGES.items():
        spec = desired[role]['spec']
        template = spec['template']
        containers = template['spec']['containers']
        _require(len(containers) == 1 and containers[0]['name'] == role and containers[0]['image'] == image
                 and template['metadata']['labels']['app'] == role and spec['strategy']['type'] == 'Recreate',
                 'unexpected_baseline_application_template')
        _require(not set(GATED_SELECTOR).difference({'app'}).intersection(template['metadata']['labels']),
                 'service_gate_label_collision')
        containers[0]['image'] = CANDIDATE_IMAGE
    _add_writer_evidence(desired['writer']['spec']['template'])
    _runtime_config(desired['writer_config'], writer=True)
    _runtime_config(desired['serving_config'], writer=False)
    _require(desired['service']['spec']['selector'] == {'app': 'backend'}
             and desired['service']['spec']['type'] == 'NodePort', 'backend_service_selector_changed')
    desired['service']['spec']['selector'] = GATED_SELECTOR.copy()
    evidence_secret = _evidence_secret(evidence_files)

    return {
        'changes': {name: {'resource': name, 'path': RESOURCE_FIELDS[name][3],
                           'before': original[name], 'after': desired[name]} for name in RESOURCE_FIELDS},
        'evidence_secret': evidence_secret,
        'digests': {
            name: {'before': _definition_digest(original[name]), 'after': _definition_digest(desired[name])}
            for name in RESOURCE_FIELDS
        } | {'evidence_secret': _digest(evidence_secret)},
    }


def _at_pointer(value, path):
    for key in path.removeprefix('/').split('/'):
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def guarded_patch(live, change, *, reverse=False, dry_run=False):
    """Produce a private guarded patch. Use dry_run only for server-side preview."""
    resource = change['resource']
    path = RESOURCE_FIELDS[resource][3]
    _require(change['path'] == path, 'unexpected_patch_path')
    current = _definition(live, resource)
    expected, target = (change['after'], change['before']) if reverse else (change['before'], change['after'])
    expected = _definition(expected, resource)
    expected['metadata']['resourceVersion'] = current['metadata']['resourceVersion']
    tests = [{'op': 'test', 'path': f'/metadata/{field}', 'value': current['metadata'][field]}
             for field in ('uid', 'resourceVersion')]
    if current['kind'] == 'Deployment':
        replicas = current['spec'].get('replicas')
        _require(replicas == 0 or (dry_run and replicas == 1), 'application_replicas_must_be_zero')
        expected['spec']['replicas'] = replicas
        tests.append({'op': 'test', 'path': '/spec/replicas', 'value': replicas})
    _require(current == expected, 'resource_preimage_changed')
    tests.append({'op': 'test', 'path': path, 'value': _at_pointer(current, path)})
    return [*tests, {'op': 'replace', 'path': path, 'value': copy.deepcopy(_at_pointer(target, path))}]
