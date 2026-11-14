#!/usr/bin/env python3
"""Guarded schema18 successor of the admitted Wikipedia production activation.

Permanent PostgreSQL/S3 evidence is preserved; this controller never restores or
downgrades data. Every mutation consumes a private fsynced single-use intent.
"""
import argparse
import base64
import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib

OLD_OPERATOR = '/usr/local/libexec/devres-production-candidate-a938112b-apparmor-v1/scripts/production-operator.py'
OLD_SHA = '58501767e3d130af1a05e1f6493f89ee8f287e1582f0f35fa2b1e74c23f5e3da'
OLD_BUNDLE = '/var/lib/devres-production-preparation/a938112b-7c7a24f'
PRIOR_BUNDLE = '/var/lib/devres-production-activations/wikipedia-65236494-20261113'
PRIOR_CONTROLLER = '/usr/local/libexec/devres-wikipedia-enable-65236494/activation-controller.py'
PRIOR_CONTROLLER_SHA = 'd9699971623a9d828ff119f80d6fe23055f7107427375957231015b17168dc56'
WORK = '/tmp/devres-upgrade-33f3c730-20261114'
PRIOR_REVISION = '65236494ad7a837243d16c7e92e177df77a7d226'
BUNDLE = '/var/lib/devres-production-upgrades/33f3c730-20261114'
REVISION = '33f3c730123319625fe3a25713988201eb5d82e0'
VERSION = '0.1.0-build.33f3c730'
OLD_IMAGE = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:efe9f706d82d535b89c18cfe9fbc68d7e7f586e014d534b00828cc8639b2c52d'
IMAGE = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:c13191678b2336f6594521dec7ca040cc97ea55313d098d87726f852eb3f1bde'
PG_IMAGE = 'postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395'
SOURCE_URL = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/' + VERSION + '/source.tar.gz'
SOURCE_SHA = '46491351a46d4518274982406bc66174908e7559a8a4d6e1bd3f787e2b9b1b0a'
PROBE_IMAGE = 'ghcr.io/publicdata-stream/dev-resources-probe@sha256:8239d387a0120049eef707a6cd474c2286545991bd7f246c8b7773c8f02a1473'
PROFILE_SHA = '99babcd17bef83cb21d96fb2e13fbe8b96bc4e1d5c638939ff9dc719f2706c97'
STORE_BINDING = '4a59576b1a2977f157ceaf72fbe404f660bd89a44c6246106b65f83989f5c529'
PROVIDERS = ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'npm', 'wikipedia')
ROLES = {'backend': ('devres-serving-config', 'serving.toml'),
         'writer': ('devres-writer-config', 'writer.toml')}
PROFILES = ('/serve/oxibelt-conf/10-tls.toml', OLD_BUNDLE + '/edge-conf/10-tls.toml')
FENCES = ('capacity_fenced', 'withdrawn', 'withdraw_incomplete', 'stopped', 'stop_failed')


class Error(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise Error(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def stamp():
    return utc_now().isoformat()


def read(path, maximum=8 * 1024**2):
    path = Path(path)
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and not info.st_mode & 0o077 and info.st_nlink == 1
                and info.st_size <= maximum, 'unsafe_private_file')
        value = stream.read(maximum + 1)
    require(len(value) <= maximum, 'private_file_bound')
    return value


def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value, replace=False):
    path = Path(path)
    raw = value if isinstance(value, bytes) else encoded(value)
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_refused')
    parent = path.parent.stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and not parent.st_mode & 0o077, 'unsafe_private_directory')
    temporary = path.parent / ('.' + path.name + '.tmp') if replace else path
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if replace:
        os.replace(temporary, path)
    syncdir(path.parent)
    syncdir(path.parent.parent)


def load(path):
    return json.loads(read(path))


def configuration(original, active):
    """Only explicit admission switches and source URL change; credentials are byte-carried."""
    before = tomllib.loads(original)
    expected = copy.deepcopy(before)
    text = original
    for provider in PROVIDERS:
        require(type(before.get(provider, {}).get('enabled')) is bool, 'explicit_flags_required')
        wanted = before[provider]['enabled'] if active else False
        pattern = rf'(?m)(^\[{provider}\][ \t]*\n(?:[ \t]*#[^\n]*\n)*[ \t]*enabled[ \t]*=[ \t]*)(?:true|false)([ \t]*(?:#[^\n]*)?$)'
        text, count = re.subn(pattern, lambda m: m[1] + str(wanted).lower() + m[2], text)
        require(count == 1, 'collector_shape')
        expected[provider]['enabled'] = wanted
    old_url = before.get('source', {}).get('url')
    require(old_url == 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.65236494/source.tar.gz', 'old_source_url')
    require(text.count(old_url) == 1, 'source_url_shape')
    text = text.replace(old_url, SOURCE_URL)
    expected['source']['url'] = SOURCE_URL
    require(tomllib.loads(text) == expected, 'configuration_semantic_drift')
    return text


def deployment_projection(value):
    spec = copy.deepcopy(value['spec'])
    spec.pop('replicas', None)
    containers = spec['template']['spec']['containers']
    require(len(containers) == 1, 'one_container_required')
    image = containers[0].pop('image')
    return {'uid': value['metadata']['uid'], 'spec': spec}, image


def secret_projection(value):
    return {'uid': value['metadata']['uid'], 'type': value.get('type'),
            'immutable': value.get('immutable', False), 'data': value.get('data', {})}


def pod_projection(value):
    require(value.get('status', {}).get('phase') == 'Running'
            and not value['metadata'].get('deletionTimestamp'), 'pod_not_running')
    statuses = value['status'].get('containerStatuses', [])
    require(len(statuses) == 1 and statuses[0].get('ready') is True, 'pod_not_ready')
    status = statuses[0]
    require(status.get('containerID') and status.get('imageID')
            and status.get('state', {}).get('running', {}).get('startedAt'), 'pod_process_missing')
    return {'uid': value['metadata']['uid'], 'container_id': status['containerID'],
            'image_id': status['imageID'], 'started_at': status['state']['running']['startedAt'],
            'restarts': status['restartCount'], 'owner': value['metadata'].get('ownerReferences', []),
            'name': value['metadata']['name'], 'pod_ip': value['status']['podIP']}


def foundation_projection(items):
    result = []
    for item in items:
        meta = item['metadata']
        # ServiceAccount token references may rotate independently; UID/labels remain protected.
        result.append({'kind': item['kind'], 'name': meta['name'], 'uid': meta['uid'],
                       'labels': meta.get('labels', {}), 'spec': item.get('spec'),
                       'rules': item.get('rules'), 'subjects': item.get('subjects'),
                       'roleRef': item.get('roleRef'), 'automountServiceAccountToken': item.get('automountServiceAccountToken')})
    return sorted(result, key=lambda v: (v['kind'], v['name']))


def target_identity():
    require(re.fullmatch('[0-9a-f]{40}', REVISION) and re.fullmatch('[0-9a-f]{64}', SOURCE_SHA)
            and re.fullmatch('ghcr.io/publicdata-stream/dev-resources-server@sha256:[0-9a-f]{64}', IMAGE)
            and re.fullmatch('ghcr.io/publicdata-stream/dev-resources-probe@sha256:[0-9a-f]{64}', PROBE_IMAGE), 'target_pins_unqualified')
    return {'revision': REVISION, 'version': VERSION, 'server': IMAGE,
            'probe': PROBE_IMAGE,
            'source_url': SOURCE_URL, 'source_sha256': SOURCE_SHA, 'schema': 18}


def predecessor(context):
    require(digest(read(PRIOR_CONTROLLER)) == PRIOR_CONTROLLER_SHA, 'prior_controller_changed')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('frozen_wikipedia_65236494', PRIOR_CONTROLLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Activation(PRIOR_BUNDLE, context)


def instant(value):
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0), 'utc_timestamp_required')
        return parsed
    except (ValueError, TypeError, AttributeError):
        raise Error('invalid_timestamp') from None


class Controller:
    def __init__(self, bundle, plan, context):
        require(str(Path(bundle)) == BUNDLE, 'fixed_bundle_required')
        self.root = Path(bundle)
        self.prior = Path(PRIOR_BUNDLE)
        self.context = context
        self.plan_raw = read(plan)
        self.plan = json.loads(self.plan_raw)
        require(set(self.plan) == {'version', 'context', 'store_binding_sha256', 'preserve_application_passwords', 'target', 'prior', 'inventory'}
                and self.plan.get('version') == 1 and self.plan.get('context') == context
                and self.plan.get('store_binding_sha256') == STORE_BINDING
                and self.plan.get('preserve_application_passwords') is True
                and self.plan.get('target') == target_identity(), 'plan_identity')
        self.activation = predecessor(context)
        self.base = self.activation.base
        self.module, self.old = self.base.module, self.base.old

    @contextlib.contextmanager
    def locked(self):
        with self.module.bundle_lock(self.old.bundle):
            with self.module.bundle_lock(self.old.bundle, '.certificate.lock'):
                yield

    def state(self):
        value = load(self.root / 'state.json')
        require(value['revision'] == REVISION and value['plan_sha256'] == digest(self.plan_raw)
                and value['source_sha256'] == digest(Path(__file__).read_bytes()), 'journal_identity')
        require(value.get('version') == 1 and value.get('configs') in ('old', 'paused', 'active')
                and value.get('chain_phase') in (None, 'runtime_upgrade_stopped', 'runtime_upgraded')
                and set(value.get('images', {})) == {'postgres', 'writer', 'backend'}
                and value['images']['postgres'] == PG_IMAGE
                and all(value['images'][role] in (OLD_IMAGE, IMAGE) for role in ('writer', 'backend'))
                and set(value.get('replicas', {})) == {'postgres', 'writer', 'backend'}
                and value['replicas']['postgres'] == 1
                and all(type(value['replicas'][role]) is int and value['replicas'][role] in (0, 1) for role in ('writer', 'backend'))
                and set(value.get('pods', {})) == {role for role, count in value['replicas'].items() if count}, 'journal_shape')
        return value

    def record(self, value):
        save(self.root / 'state.json', value, replace=True)

    def get(self, kind, name):
        return json.loads(self.old.k('get', kind, name, '-o', 'json'))

    def pods(self):
        values = json.loads(self.old.k('get', 'pods', '-o', 'json'))['items']
        images = (self.state()['images'] if (self.root / 'state.json').exists()
                  else {'postgres': PG_IMAGE, 'writer': OLD_IMAGE, 'backend': OLD_IMAGE})
        result = {}
        for name in ('postgres', 'writer', 'backend'):
            selected = [v for v in values if v['metadata'].get('labels', {}).get('app') == name]
            require(len(selected) <= 1, 'multiple_role_pods')
            if selected:
                spec = selected[0]['spec']
                require(len(spec['containers']) == 1 and spec['containers'][0]['image'] == images[name]
                        and spec.get('nodeName') == self.old.settings()['node_name'], 'pod_image_or_node_changed')
                result[name] = pod_projection(selected[0])
        require('postgres' in result, 'postgres_missing')
        require(len(values) == len(result), 'unexpected_namespace_pod')
        return result

    def edge(self):
        ids = self.module.call(['docker', 'compose', '-f', '/serve/docker-compose.yml', 'ps', '-q', 'oxibelt']).decode().split()
        require(len(ids) == 1, 'one_edge_required')
        value = json.loads(self.module.call(['docker', 'inspect', ids[0]]))[0]
        require(value['State']['Running'] and value['State']['Pid'] > 0, 'edge_not_running')
        pid = value['State']['Pid']
        fields = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()
        require(len(fields) > 19 and fields[19].isdigit(), 'edge_process_identity')
        return {'id': value['Id'], 'pid': pid, 'pid_start_ticks': fields[19], 'started': value['State']['StartedAt'],
                'restarts': value['RestartCount'], 'image': value['Image']}

    def foundation(self):
        raw = self.old.k('get', 'networkpolicies,roles,rolebindings,serviceaccounts,services,persistentvolumeclaims', '-o', 'json')
        return foundation_projection(json.loads(raw)['items'])

    def profiles(self):
        result = {}
        for name in PROFILES:
            path = Path(name)
            require(not any(p.is_symlink() for p in (path, *path.parents)), 'profile_symlink')
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe_profile')
            require(info.st_size <= 65536, 'profile_bound')
            raw = path.read_bytes()
            require(digest(raw) == PROFILE_SHA, 'edge_profile_changed')
            result[name] = raw
        return result

    def boot(self):
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        require(re.fullmatch('[a-f0-9-]{36}', boot_id), 'boot_identity')
        values = [line.split()[1] for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime ')]
        require(len(values) == 1 and values[0].isdigit(), 'boot_time')
        return {'boot_id': boot_id, 'boot_at': dt.datetime.fromtimestamp(int(values[0]), dt.timezone.utc).isoformat()}

    def prior_artifacts(self):
        paths = {'state': self.prior / 'state.json', 'prepared': self.prior / 'prepared.json',
                 'controller': Path(PRIOR_CONTROLLER), 'active': self.prior / 'configs-enabled.json',
                 'route': self.prior / 'route-candidate.toml', 'cidrs': self.prior / 'cidr-candidate.json',
                 'edge_check': self.prior / 'edge-config-check.json',
                 'cidr_receipt': self.prior / 'cidr-activation-receipt.json',
                 'cidr_validation': self.prior / 'cidr-activation-validation.json'}
        state = self.activation.state()
        if state.get('source_history') is not None:
            for name in ('resume-pre-state.json', 'edge-mac-admission.json', 'resume-approval.json', 'source-adoption.json'):
                paths[name] = self.prior / name
        return {name: {'path': str(path), 'sha256': digest(read(path))} for name, path in paths.items()}

    def admitted_prior(self, expected=None, allow_successor=False):
        artifacts = self.prior_artifacts()
        if expected is not None:
            require(set(artifacts) == set(expected), 'prior_artifact_set')
            for name, actual in artifacts.items():
                require(actual['path'] == expected[name]['path'], 'prior_artifact_path')
                if name != 'state' or not allow_successor:
                    require(actual['sha256'] == expected[name]['sha256'], 'prior_artifact_changed')
        require(artifacts['controller']['sha256'] == PRIOR_CONTROLLER_SHA, 'prior_controller_changed')
        state = self.activation.state()
        prepared = load(self.prior / 'prepared.json')
        require(state.get('revision') == PRIOR_REVISION and state.get('phase') == 'enabled'
                and state.get('configs') == 'enabled' and state.get('edge_phase') == 'published'
                and state.get('base_link_phase') == 'wikipedia_enabled'
                and state.get('source_sha256') == PRIOR_CONTROLLER_SHA
                and state.get('prepared_sha256') == artifacts['prepared']['sha256']
                and state.get('replicas') == {'postgres': 1, 'writer': 1, 'backend': 1}, 'prior_state_identity')
        require(allow_successor or not state.get('upgrade_successor'), 'prior_successor_exists')
        require(prepared.get('revision') == PRIOR_REVISION and prepared.get('kind') == 'wikipedia-activation'
                and prepared.get('enabled_config_sha256') == artifacts['active']['sha256'], 'prior_prepared_identity')
        # Preserve the independently admitted original -> upgrade -> activation chain.
        self.activation.admit()
        require(self.activation.artifact_hashes() == prepared['base_artifacts'], 'historical_artifact_changed')
        self.activation.cidr_copies(prepared, state)
        self.activation.edge_guard(prepared, state)
        return artifacts, state, prepared, {}

    def safety(self):
        # The frozen activation is the live predecessor; its pre-Wikipedia guard
        # cannot be reused after its deliberately admitted configuration changes.
        self.base.safety()
        prepared = load(self.prior / 'prepared.json')
        require(self.activation.artifact_hashes() == prepared['base_artifacts'], 'historical_artifact_changed')
        self.activation.admit()

    def snapshot(self):
        deployments = {}
        for name in ('postgres', 'writer', 'backend'):
            obj = self.get('deployment', name)
            projection, image = deployment_projection(obj)
            deployments[name] = {'projection': projection, 'image': image, 'replicas': obj['spec'].get('replicas', 1)}
        # Freeze every namespace Secret, including any separately mounted identity.
        secrets = json.loads(self.old.k('get', 'secrets', '-o', 'json'))['items']
        return {'boot': self.boot(), 'deployments': deployments,
                'secrets': {value['metadata']['name']: secret_projection(value) for value in secrets},
                'pods': self.pods(), 'edge': self.edge(), 'foundation': self.foundation(),
                'profiles': {name: digest(raw) for name, raw in self.profiles().items()}}

    def boundary_before_prepare(self, snapshot, prior_state, prior_prepared, completion):
        # Admission must prove the currently enabled/published Wikipedia state.
        self.activation.guard()
        require(set(snapshot['pods']) == {'postgres', 'writer', 'backend'}
                and snapshot['pods'] == prior_state['pods'], 'prior_process_changed')
        admitted = self.activation.snapshot()
        for key in ('boot', 'foundation', 'profiles', 'edge', 'deployments', 'pods'):
            require(snapshot[key] == admitted[key], 'prior_runtime_changed')
        require(all(snapshot['secrets'].get(name) == value for name, value in admitted['secrets'].items()),
                'prior_secret_boundary_changed')
        require(snapshot['deployments']['postgres']['image'] == PG_IMAGE
                and all(snapshot['deployments'][role]['image'] == OLD_IMAGE for role in ROLES), 'old_image_identity')

    def guard(self, pg_rebind=None):
        self.safety()
        if not self.root.exists():
            self.admitted_prior(self.plan['prior'])
            return
        state = self.state()
        prepared = load(self.root / 'prepared.json')
        require(digest(read(self.root / 'prepared.json')) == state['prepared_sha256'], 'prepared_changed')
        self.admitted_prior(prepared['prior_artifacts'], allow_successor=True)
        expected_prior = copy.deepcopy(prepared['prior_state'])
        if state['chain_phase'] is not None:
            expected_prior.update(upgrade_successor=str(self.root), upgrade_successor_phase=state['chain_phase'])
        require(load(self.prior / 'state.json') == expected_prior, 'prior_chain_changed')
        require(self.boot() == prepared['boot'], 'boot_changed')
        require(self.edge() == prepared['edge'] and self.foundation() == prepared['foundation']
                and {name: digest(raw) for name, raw in self.profiles().items()} == prepared['profiles'], 'protected_runtime_changed')
        for name in ('postgres', 'writer', 'backend'):
            current = self.get('deployment', name)
            projection, image = deployment_projection(current)
            require(projection == prepared['deployments'][name]['projection'], 'deployment_boundary_changed')
            require(image == state['images'][name] and current['spec'].get('replicas', 1) == state['replicas'][name], 'deployment_state_changed')
        current_secrets = json.loads(self.old.k('get', 'secrets', '-o', 'json'))['items']
        require({v['metadata']['name'] for v in current_secrets} == set(prepared['secrets']), 'namespace_secret_set_changed')
        for name, original in prepared['secrets'].items():
            current = secret_projection(self.get('secret', name))
            expected = copy.deepcopy(original)
            for role, (secret, key) in ROLES.items():
                if name == secret and state['configs'] != 'old':
                    configs = load(self.root / ('configs-' + state['configs'] + '.json'))
                    require(digest(read(self.root / ('configs-' + state['configs'] + '.json'))) == prepared['config_hashes'][state['configs']], 'candidate_changed')
                    expected['data'][key] = base64.b64encode(configs[role].encode()).decode()
            require(current == expected, 'secret_boundary_changed')
        require(self.module.read_json(self.old.bundle / 'state.json') == prepared['old_anchor'], 'original_anchor_changed')
        expected_pods = copy.deepcopy(state['pods'])
        if pg_rebind is not None:
            require(state['phase'] == 'stopped' and set(expected_pods) == {'postgres'}, 'pg_rebind_phase')
            expected_pods['postgres'] = pg_rebind
        require(self.pods() == expected_pods, 'process_identity_changed')

    def capture(self, inventory_path, plan_path):
        require(not self.root.exists(), 'bundle_already_exists')
        require(Path(inventory_path).is_absolute() and Path(inventory_path).parent == Path(WORK)
                and Path(plan_path).is_absolute() and Path(plan_path).parent == Path(WORK)
                and Path(inventory_path) != Path(plan_path), 'capture_output_path')
        require(not any(p.is_symlink() for p in (Path(WORK), *Path(WORK).parents)), 'symlink_refused')
        work = Path(WORK).stat()
        require(stat.S_ISDIR(work.st_mode) and work.st_uid == os.geteuid()
                and not work.st_mode & 0o077, 'unsafe_private_directory')
        self.safety()
        self.activation.guard()
        self.old.admit_storage_receipt()
        artifacts, state, prepared, completion = self.admitted_prior()
        snapshot = self.snapshot()
        self.boundary_before_prepare(snapshot, state, prepared, completion)
        require(self.snapshot() == snapshot, 'capture_runtime_changed')
        inventory = {'version': 1, 'revision': REVISION, 'context': self.context,
                     'captured_at': stamp(), 'snapshot': snapshot}
        plan = {'version': 1, 'context': self.context, 'store_binding_sha256': STORE_BINDING,
                'preserve_application_passwords': True, 'target': target_identity(), 'prior': artifacts,
                'inventory': {'path': str(inventory_path), 'sha256': digest(encoded(inventory))}}
        save(inventory_path, inventory)
        save(plan_path, plan)

    def prepare(self):
        require(not self.root.exists() and not self.root.is_symlink(), 'bundle_already_exists')
        self.guard()
        self.activation.guard()
        self.old.admit_storage_receipt()
        inventory_raw = read(self.plan['inventory']['path'])
        require(digest(inventory_raw) == self.plan['inventory']['sha256'], 'inventory_changed')
        inventory = json.loads(inventory_raw)
        require(inventory.get('version') == 1 and inventory.get('revision') == REVISION
                and inventory.get('context') == self.context, 'inventory_identity')
        age = (dt.datetime.now(dt.timezone.utc) - instant(inventory.get('captured_at'))).total_seconds()
        require(-5 <= age <= 300, 'inventory_stale')
        artifacts, prior_state, prior_prepared, completion = self.admitted_prior(self.plan['prior'])
        snapshot = self.snapshot()
        require(snapshot == inventory['snapshot'], 'inventory_runtime_changed')
        self.boundary_before_prepare(snapshot, prior_state, prior_prepared, completion)
        pods = snapshot['pods']
        deployments = {}
        for name in ('postgres', 'writer', 'backend'):
            obj = self.get('deployment', name)
            projection, image = deployment_projection(obj)
            require(snapshot['deployments'][name] == {'projection': projection, 'image': image, 'replicas': obj['spec'].get('replicas', 1)}, 'prepare_runtime_changed')
            deployments[name] = {'projection': projection, 'manifest': obj}
        secrets = snapshot['secrets']
        configs = {'paused': {}, 'active': {}}
        for role, (name, key) in ROLES.items():
            old_text = base64.b64decode(secrets[name]['data'][key], validate=True).decode()
            for variant in configs:
                configs[variant][role] = configuration(old_text, variant == 'active')
        prepared = {'version': 1, 'revision': REVISION, 'at': stamp(), 'deployments': deployments,
                    'secrets': secrets, 'edge': snapshot['edge'], 'foundation': snapshot['foundation'], 'boot': snapshot['boot'],
                    'old_anchor': self.module.read_json(self.old.bundle / 'state.json'), 'profiles': snapshot['profiles'],
                    'old_pods': pods, 'store_binding_sha256': STORE_BINDING,
                    'prior_artifacts': artifacts, 'prior_state': prior_state,
                    'config_hashes': {key: digest(encoded(value)) for key, value in configs.items()}}
        require(self.snapshot() == snapshot, 'prepare_runtime_changed')
        self.module.safe_directory(self.root.parent, create=True)
        self.root.mkdir(mode=0o700)
        syncdir(self.root.parent)
        save(self.root / 'plan.json', self.plan_raw)
        for key, value in configs.items():
            save(self.root / ('configs-' + key + '.json'), value)
        for index, raw in enumerate(self.profiles().values()):
            save(self.root / ('profile-' + str(index) + '.toml'), raw)
        save(self.root / 'prepared.json', prepared)
        state = {'version': 1, 'revision': REVISION, 'phase': 'prepared', 'chain_phase': None,
                 'plan_sha256': digest(self.plan_raw), 'source_sha256': digest(Path(__file__).read_bytes()),
                 'prepared_sha256': digest(encoded(prepared)), 'images': {'postgres': PG_IMAGE, 'writer': OLD_IMAGE, 'backend': OLD_IMAGE},
                 'replicas': {'postgres': 1, 'writer': 1, 'backend': 1}, 'configs': 'old', 'pods': pods}
        save(self.root / 'state.json', state)
        self.guard()

    def chain_record(self, phase):
        require(phase in ('runtime_upgrade_stopped', 'runtime_upgraded'), 'chain_phase')
        self.guard()
        prepared = load(self.root / 'prepared.json')
        current = load(self.prior / 'state.json')
        updated = copy.deepcopy(current)
        updated.update(upgrade_successor=str(self.root), upgrade_successor_phase=phase)
        self.mutate('chain-' + phase, lambda: save(self.prior / 'state.json', updated, replace=True))
        state = self.state()
        state['chain_phase'] = phase
        self.record(state)

    def receipt_fresh(self, value):
        observed = instant(value.get('observed_at'))
        age = (utc_now() - observed).total_seconds()
        require(instant(load(self.root / 'prepared.json')['at']) <= observed and -5 <= age <= 300, 'receipt_stale')

    def receipt(self, path, sha, kind, checks):
        raw = read(path)
        require(re.fullmatch('[a-f0-9]{64}', sha or '') and digest(raw) == sha, 'receipt_hash')
        value = json.loads(raw)
        state = self.state()
        require(value.get('version') == 1 and value.get('kind') == kind
                and value.get('prepared_sha256') == state['prepared_sha256']
                and value.get('revision') == REVISION and value.get('verified') is True
                and value.get('store_binding_sha256') == STORE_BINDING, 'receipt_identity')
        require(all(value.get('checks', {}).get(key) is True for key in checks), 'receipt_checks')
        self.receipt_fresh(value)
        artifacts = value.get('artifacts', [])
        require(isinstance(artifacts, list) and artifacts, 'receipt_artifacts_required')
        for item in artifacts:
            # Large backup artifacts are verified streaming without loading or exporting them.
            path = Path(item['path'])
            require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'artifact_path')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            h = hashlib.sha256()
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                        and not info.st_mode & 0o077 and info.st_nlink == 1 and info.st_size > 0, 'artifact_private')
                for block in iter(lambda: stream.read(1024**2), b''):
                    h.update(block)
            require(h.hexdigest() == item['sha256'], 'artifact_changed')
        self.receipt_fresh(value)
        return value, raw

    def approval(self, path, sha, operation):
        raw = read(path)
        require(digest(raw) == sha, 'approval_hash')
        value = json.loads(raw)
        state = self.state()
        require(value == {'version': 1, 'operation': operation, 'reviewed': True,
                          'source_sha256': state['source_sha256'], 'prepared_sha256': state['prepared_sha256']}, 'approval_binding')

    def mutate(self, label, function):
        path = self.root / (label + '-intent.json')
        save(path, {'version': 1, 'label': label, 'at': stamp(), 'maximum_attempts': 1})
        function()
        save(self.root / (label + '-completed.json'), {'known': True, 'at': stamp()})

    def scale(self, name, count, label):
        self.guard()
        before = self.state()
        require(name in ('writer', 'backend'), 'postgres_scaling_refused')
        require(name in before['replicas'] and count in (0, 1)
                and before['replicas'][name] == 1 - count, 'scale_transition')
        require(self.pods() == before['pods'], 'scale_preimage_process_changed')
        current = self.get('deployment', name)
        prepared = load(self.root / 'prepared.json')
        projection, image = deployment_projection(current)
        require(projection == prepared['deployments'][name]['projection'] and image == before['images'][name]
                and current['spec'].get('replicas', 1) == before['replicas'][name], 'scale_preimage_deployment_changed')
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': current['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/spec/replicas', 'value': count}]
        def execute():
            self.old.k('patch', 'deployment', name, '--type=json', '-p', json.dumps(patch))
            if count:
                self.old.k('rollout', 'status', 'deployment/' + name, '--timeout=180s', timeout=210, request_timeout=190)
            else:
                self.old.k('wait', '--for=delete', 'pod', '-l', 'app=' + name, '--timeout=180s', timeout=210, request_timeout=190)
        self.mutate(label, execute)
        current_pods = self.pods()
        expected_roles = set(before['pods']) - {name}
        if count:
            expected_roles.add(name)
        require(set(current_pods) == expected_roles, 'scale_result_role_set')
        require(all(current_pods[role] == projection for role, projection in before['pods'].items() if role != name),
                'unrelated_role_process_changed')
        state = self.state()
        require(state == before, 'scale_journal_changed')
        state['replicas'][name] = count
        state['pods'] = current_pods
        self.record(state)

    def change_config(self, variant, label):
        self.guard()
        require(set(self.pods()) == {'postgres'}, 'config_requires_quiescent_roles')
        prepared = load(self.root / 'prepared.json')
        raw = read(self.root / ('configs-' + variant + '.json'))
        require(digest(raw) == prepared['config_hashes'][variant], 'candidate_changed')
        configs = json.loads(raw)
        for role, (name, key) in ROLES.items():
            require(self.pods() == self.state()['pods'], 'config_process_changed')
            obj = self.get('secret', name)
            expected = copy.deepcopy(prepared['secrets'][name])
            current_variant = self.state()['configs']
            if current_variant != 'old':
                previous_raw = read(self.root / ('configs-' + current_variant + '.json'))
                require(digest(previous_raw) == prepared['config_hashes'][current_variant], 'candidate_changed')
                expected['data'][key] = base64.b64encode(json.loads(previous_raw)[role].encode()).decode()
            require(secret_projection(obj) == expected, 'secret_preimage_changed')
            data = copy.deepcopy(obj['data'])
            data[key] = base64.b64encode(configs[role].encode()).decode()
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                     {'op': 'replace', 'path': '/data', 'value': data}]
            # Secret data is supplied on stdin, never in argv or diagnostic text.
            self.mutate(label + '-' + role, lambda n=name, p=patch: self.old.k('patch', 'secret', n, '--type=json', '--patch-file=/dev/stdin', data=encoded(p)))
            expected['data'] = data
            require(secret_projection(self.get('secret', name)) == expected, 'secret_patch_readback')
        state = self.state()
        state['configs'] = variant
        self.record(state)

    def run(self, operation, approval, approval_sha, receipt=None, receipt_sha=None):
        if operation == 'prepare':
            self.prepare()
            return
        self.approval(approval, approval_sha, operation)
        if operation == 'withdraw':
            self.withdraw()
            return
        state = self.state()
        phases = {'stop': 'prepared', 'apply': 'stopped', 'start-writer': 'applied',
                  'start-reader': 'writer_ready', 'runtime-ready': 'reader_ready',
                  'activate-existing': 'runtime_ready', 'finish': 'collectors_active'}
        require(state['phase'] == phases[operation], 'operation_phase')
        accepted = None
        if operation == 'apply':
            accepted, raw = self.receipt(receipt, receipt_sha, 'coordinated-schema15-backup',
                ('coordinated_pg_s3', 'old_clone_verified', 'roles_stopped', 'pg_restarted_without_restore', 'credentials_preserved'))
            require(accepted.get('recovery_scope') == 'physical_pg_checkpoint_original_immutable_s3_retained'
                    and accepted.get('independent_s3_backup') is False, 'backup_scope')
            require(accepted.get('schema') == 15 and re.fullmatch('[0-9]+', str(accepted.get('system_identifier', ''))), 'backup_schema_identity')
            require(accepted.get('old_pg_pod') == state['pods']['postgres'], 'backup_old_pg_identity')
            require(accepted.get('postgres_deployment_sha256') == digest(encoded(load(self.root / 'prepared.json')['deployments']['postgres']['projection'])), 'backup_pg_template')
            new_pg = accepted.get('new_pg_pod')
            require(isinstance(new_pg, dict) and new_pg.get('uid') and new_pg.get('container_id')
                    and new_pg.get('image_id') and new_pg.get('started_at'), 'backup_new_pg_identity')
            require(set(new_pg) == set(state['pods']['postgres'])
                    and new_pg['owner'] == state['pods']['postgres']['owner']
                    and new_pg['image_id'] == state['pods']['postgres']['image_id'], 'backup_pg_runtime_boundary')
            self.guard(pg_rebind=new_pg)
            require(set(self.pods()) == {'postgres'}, 'backup_roles_not_stopped')
            state['pods']['postgres'] = new_pg
            self.record(state)
            save(self.root / 'accepted-backup.json', raw)
        else:
            self.guard()
        if operation in ('start-reader', 'runtime-ready', 'activate-existing'):
            kind, checks = {
                'start-reader': ('migration18', ('schema18', 'policy2', 'sole_writer', 'new_table_reader_grants', 'history_preserved', 'archive_binding_preserved', 'historical_notices_preserved')),
                'runtime-ready': ('target-private-acceptance', ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary', 'capture_notice_preserved', 'tool_contract98')),
                'activate-existing': ('target-activation-acceptance', ('schema18', 'policy2', 'sole_writer', 'private_boundary', 'public_http_both_families_revisions', 'public_wt_both_families_revisions', 'capture_notice_preserved'))}[operation]
            accepted, raw = self.receipt(receipt, receipt_sha, kind, checks)
            require(accepted.get('schema') == 18, 'target_schema_receipt')
            save(self.root / ('accepted-' + operation + '.json'), raw)
        if operation == 'finish':
            accepted, raw = self.receipt(receipt, receipt_sha, 'target-observation-acceptance',
                ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary',
                 'public_http_both_families_revisions', 'public_wt_both_families_revisions',
                 'nine_source_settings_preserved', 'capture_notice_preserved', 'timers_preserved', 'stable_processes'))
            require(accepted.get('schema') == 18
                    and type(accepted.get('duration_seconds')) in (int, float) and accepted['duration_seconds'] >= 600
                    and type(accepted.get('sample_count')) is int and accepted['sample_count'] >= 21
                    and type(accepted.get('maximum_gap_seconds')) in (int, float)
                    and 0 < accepted['maximum_gap_seconds'] <= 45, 'observation_interval')
            save(self.root / 'accepted-observation.json', raw)
        # Artifact verification may be slow; repeat live protection immediately before dispatch.
        self.guard()
        if accepted is not None:
            self.receipt_fresh(accepted)
        state = self.state()
        state['phase'] = operation + '_incomplete'
        self.record(state)
        if operation == 'stop':
            self.scale('backend', 0, 'stop-backend')
            self.scale('writer', 0, 'stop-writer')
            require(set(self.pods()) == {'postgres'}, 'owner_remaining')
            self.chain_record('runtime_upgrade_stopped')
        elif operation == 'apply':
            self.change_config('paused', 'paused-config')
            for name in ('writer', 'backend'):
                self.guard()
                obj = self.get('deployment', name)
                patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                         {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                         {'op': 'test', 'path': '/spec/template/spec/containers/0/image', 'value': OLD_IMAGE},
                         {'op': 'replace', 'path': '/spec/template/spec/containers/0/image', 'value': IMAGE}]
                self.mutate('target-image-' + name, lambda n=name, p=patch: self.old.k('patch', 'deployment', n, '--type=json', '-p', json.dumps(p)))
                require(self.get('deployment', name)['spec']['template']['spec']['containers'][0]['image'] == IMAGE, 'image_readback')
                state = self.state()
                state['images'][name] = IMAGE
                self.record(state)
            self.chain_record('runtime_upgraded')
        elif operation == 'start-writer':
            self.scale('writer', 1, 'start-paused-writer')
        elif operation == 'start-reader':
            self.scale('backend', 1, 'start-paused-reader')
        elif operation == 'activate-existing':
            self.scale('backend', 0, 'activation-stop-backend')
            self.scale('writer', 0, 'activation-stop-writer')
            require(set(self.pods()) == {'postgres'}, 'owner_remaining')
            self.change_config('active', 'active-config')
            self.scale('writer', 1, 'activation-start-writer')
            self.scale('backend', 1, 'activation-start-backend')
        final = {'stop': 'stopped', 'apply': 'applied', 'start-writer': 'writer_ready',
                 'start-reader': 'reader_ready', 'runtime-ready': 'runtime_ready',
                 'activate-existing': 'collectors_active', 'finish': 'complete'}[operation]
        self.guard()
        state = self.state()
        state['phase'] = final
        state['updated_at'] = stamp()
        self.record(state)


    def withdraw(self):
        """Fence admitted application Deployments without restoring permanent data.

        This path accepts an interrupted phase/partial known config or image
        transition; it never adopts unrecognized templates or credential bytes.
        Failed/Pending Pods need not be ready to stop their owning Deployment.
        """
        state = self.state()
        prepared = load(self.root / 'prepared.json')
        require(digest(read(self.root / 'prepared.json')) == state['prepared_sha256'], 'prepared_changed')
        self.safety()
        self.admitted_prior(prepared['prior_artifacts'], allow_successor=True)
        expected_prior = copy.deepcopy(prepared['prior_state'])
        if state['chain_phase'] is not None:
            expected_prior.update(upgrade_successor=str(self.root), upgrade_successor_phase=state['chain_phase'])
        require(load(self.prior / 'state.json') == expected_prior, 'prior_chain_changed')
        require(self.boot() == prepared['boot'] and self.foundation() == prepared['foundation'], 'protected_runtime_changed')
        require(self.module.read_json(self.old.bundle / 'state.json') == prepared['old_anchor'], 'original_anchor_changed')
        for name, original in prepared['secrets'].items():
            current = secret_projection(self.get('secret', name))
            candidates = [copy.deepcopy(original)]
            for role, (secret, key) in ROLES.items():
                if name == secret:
                    for variant in ('paused', 'active'):
                        raw = read(self.root / ('configs-' + variant + '.json'))
                        require(digest(raw) == prepared['config_hashes'][variant], 'candidate_changed')
                        candidate = copy.deepcopy(original)
                        candidate['data'][key] = base64.b64encode(json.loads(raw)[role].encode()).decode()
                        candidates.append(candidate)
            require(current in candidates, 'secret_boundary_changed')
        for role in ('postgres', 'writer', 'backend'):
            obj = self.get('deployment', role)
            projection, image = deployment_projection(obj)
            require(projection == prepared['deployments'][role]['projection'], 'deployment_boundary_changed')
            require(image == PG_IMAGE if role == 'postgres' else image in (OLD_IMAGE, IMAGE), 'deployment_image_changed')
            require(type(obj['spec'].get('replicas')) is int and obj['spec']['replicas'] in (0, 1), 'deployment_replica_changed')
        state['phase'] = 'withdraw_incomplete'
        self.record(state)
        for role in ('backend', 'writer'):
            obj = self.get('deployment', role)
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                     {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
            self.mutate('withdraw-' + role, lambda r=role, p=patch:
                self.old.k('patch', 'deployment', r, '--type=json', '-p', json.dumps(p)))
            self.old.k('wait', '--for=delete', 'pod', '-l', 'app=' + role, '--timeout=180s', timeout=210, request_timeout=190)
            state = self.state()
            state['replicas'][role] = 0
            state['pods'].pop(role, None)
            self.record(state)
        require(not any(v['metadata'].get('labels', {}).get('app') in ROLES
                        for v in json.loads(self.old.k('get', 'pods', '-o', 'json'))['items']), 'application_pod_remaining')
        state = self.state()
        state['phase'] = 'withdrawn'
        state['updated_at'] = stamp()
        self.record(state)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', default=BUNDLE)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--context', required=True)
    parser.add_argument('--inventory')
    parser.add_argument('--approval')
    parser.add_argument('--approval-sha256')
    parser.add_argument('--receipt')
    parser.add_argument('--receipt-sha256')
    parser.add_argument('operation', choices=('capture', 'prepare', 'stop', 'apply', 'start-writer', 'start-reader', 'runtime-ready', 'activate-existing', 'finish', 'withdraw'))
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, 'root_required')
        if args.operation == 'capture':
            require(args.bundle == BUNDLE and args.inventory, 'capture_inputs')
            controller = Controller.__new__(Controller)
            controller.root = Path(BUNDLE)
            controller.prior = Path(PRIOR_BUNDLE)
            controller.context = args.context
            controller.activation = predecessor(args.context)
            controller.base = controller.activation.base
            controller.module, controller.old = controller.base.module, controller.base.old
            with controller.locked():
                controller.capture(Path(args.inventory), Path(args.plan))
            print(json.dumps({'operation': 'capture', 'known_complete': True, 'private_data_export_allowed': False}))
        else:
            controller = Controller(args.bundle, args.plan, args.context)
            with controller.locked():
                controller.run(args.operation, args.approval, args.approval_sha256, args.receipt, args.receipt_sha256)
            print(json.dumps({'operation': args.operation, 'phase': controller.state()['phase'], 'known_complete': True}))
    except Exception as error:
        # Never print subprocess output, private configuration, SQL URLs or exception repr.
        code = str(error) if isinstance(error, Error) and re.fullmatch('[a-z0-9_]+', str(error)) else 'upgrade_operation_failed'
        print(json.dumps({'operation': args.operation, 'known_complete': False, 'code': code}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
