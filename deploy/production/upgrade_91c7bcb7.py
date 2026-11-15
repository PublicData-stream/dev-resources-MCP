#!/usr/bin/env python3
"""Same-schema upgrade from the immutable, admitted compression successor.

Original PostgreSQL and S3 evidence is never restored or deleted by this controller.
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

sys.dont_write_bytecode = True
REVISION = '91c7bcb7aed8eede1627bf87254c0567ef48ab7b'
VERSION = '0.1.0-build.91c7bcb7'
WORK = '/tmp/devres-upgrade-91c7bcb7-20261115'
BUNDLE = '/var/lib/devres-production-upgrades/91c7bcb7-20261115'
PRIOR_BUNDLE = '/var/lib/devres-production-upgrades/33f3c730-20261114'
PRIOR_CONTROLLER = '/usr/local/libexec/devres-upgrade-33f3c730/upgrade-controller.py'
PRIOR_SHA = '4491b9b05d42f0519be4928cc49bc2490dbc5519c0dc75a6d28310faa172986c'
OLD_IMAGE = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:c13191678b2336f6594521dec7ca040cc97ea55313d098d87726f852eb3f1bde'
IMAGE = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:1b1bf21d339920e8ddd69449d82c9895c3423509e8016a72b2df46a38d8e7b6c'
PG_IMAGE = 'postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395'
PROBE_IMAGE = 'ghcr.io/publicdata-stream/dev-resources-probe@sha256:a0ed3b468b3e7e23b395d2227b66878832cdf149aa4aac28738e8e5aca0cb588'
SOURCE_URL = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/'+VERSION+'/source.tar.gz'
STORE_BINDING = '4a59576b1a2977f157ceaf72fbe404f660bd89a44c6246106b65f83989f5c529'
PROVIDERS = ('rfc','crates','rustsec','mdn','whatwg','w3c','chromium','npm','wikipedia')
ROLES = {'backend':('devres-serving-config','serving.toml'),'writer':('devres-writer-config','writer.toml')}

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

def instant(value):
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0), 'utc_timestamp_required')
        return parsed
    except (ValueError, TypeError, AttributeError):
        raise Error('invalid_timestamp') from None

def configuration(original, active):
    before = tomllib.loads(original)
    expected = copy.deepcopy(before)
    text = original
    for section, key in [(p, 'enabled') for p in PROVIDERS] + [('npm', 'advisories_enabled')]:
        wanted = before[section][key] if active else False
        require(type(wanted) is bool, 'explicit_flags_required')
        pattern = rf'(?m)(^\[{section}\][^\n]*\n(?:(?!\[)[^\n]*\n)*?{key}\s*=\s*)(?:true|false)([ \t]*(?:#[^\n]*)?$)'
        text, count = re.subn(pattern, lambda m: m[1]+str(wanted).lower()+m[2], text)
        require(count == 1, 'collector_shape')
        expected[section][key] = wanted
    old_url = before['source']['url']
    require(old_url == 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.33f3c730/source.tar.gz', 'old_source_url')
    require(text.count(old_url) == 1, 'source_url_shape')
    text = text.replace(old_url, SOURCE_URL)
    expected['source']['url'] = SOURCE_URL
    require(tomllib.loads(text) == expected, 'configuration_semantic_drift')
    return text


def predecessor(context):
    require(digest(read(PRIOR_CONTROLLER)) == PRIOR_SHA, 'prior_controller_changed')
    spec = importlib.util.spec_from_file_location('frozen_compression_33f3c730', PRIOR_CONTROLLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Controller(PRIOR_BUNDLE, str(Path(PRIOR_BUNDLE)/'plan.json'), context)


class Controller:
    def __init__(self, bundle=BUNDLE, plan=None, context='default'):
        require(str(bundle) == BUNDLE and context == 'default', 'explicit_target_required')
        self.root, self.context = Path(bundle), context
        self.prior_controller = predecessor(context)
        self.module, self.old = self.prior_controller.module, self.prior_controller.old
        self.plan_raw = read(plan) if plan else None
        self.plan = json.loads(self.plan_raw) if self.plan_raw else None
        if self.plan:
            require(self.plan['revision'] == REVISION and self.plan['context'] == context
                    and self.plan['target_image'] == IMAGE and self.plan['store_binding_sha256'] == STORE_BINDING,
                    'plan_identity')

    def locked(self):
        return self.prior_controller.locked()

    def edge(self):
        return self.prior_controller.edge()

    def boot(self):
        return self.prior_controller.boot()

    def profiles(self):
        return self.prior_controller.profiles()

    def get(self, kind, name):
        return self.prior_controller.get(kind, name)

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

    def snapshot(self):
        deployments = {}
        for role in ('postgres', 'writer', 'backend'):
            obj = self.get('deployment', role)
            projection, image = deployment_projection(obj)
            deployments[role] = {'projection': projection, 'image': image,
                                 'replicas': obj['spec'].get('replicas', 1)}
        secrets = json.loads(self.old.k('get', 'secrets', '-o', 'json'))['items']
        return {**self.protected_snapshot(), 'deployments': deployments,
                'pods': self.pods(),
                'secrets': {v['metadata']['name']: secret_projection(v) for v in secrets}}

    def state(self):
        value = load(self.root/'state.json')
        require(value['revision'] == REVISION and value['source_sha256'] == digest(Path(__file__).read_bytes())
                and value['plan_sha256'] == digest(self.plan_raw), 'journal_identity')
        require(set(value['images']) == {'postgres','writer','backend'} and value['images']['postgres'] == PG_IMAGE
                and all(value['images'][r] in (OLD_IMAGE,IMAGE) for r in ROLES)
                and value['configs'] in ('old','paused','active') and value['replicas']['postgres'] == 1
                and all(type(value['replicas'][r]) is int and value['replicas'][r] in (0,1) for r in ROLES)
                and set(value['pods']) == {r for r,n in value['replicas'].items() if n}, 'journal_shape')
        return value

    def record(self, value):
        value['updated_at'] = stamp()
        save(self.root/'state.json',value,replace=True)

    def prior_hashes(self):
        paths = [Path(PRIOR_CONTROLLER)] + [Path(PRIOR_BUNDLE)/p for p in
            ('state.json','prepared.json','plan.json','configs-active.json','configs-paused.json')]
        return {str(p):digest(read(p)) for p in paths}

    def boundary_guard(self, check_pods=True, pg_rebind=None, withdrawing=False):
        self.prior_controller.safety()
        self.prior_controller.verify_edge_admission()
        state = self.state()
        raw = read(self.root/'prepared.json')
        require(digest(raw) == state['prepared_sha256'], 'prepared_changed')
        prepared = json.loads(raw)
        require(self.prior_hashes() == prepared['prior_artifacts'], 'prior_chain_changed')
        current = self.snapshot() if check_pods and not withdrawing else self.protected_snapshot()
        for key in ('boot','edge','foundation','profiles','edge_conf_tree'):
            require(current[key] == prepared[key], 'protected_runtime_changed')
        for role in ('postgres','writer','backend'):
            obj = self.get('deployment',role)
            projection, image = deployment_projection(obj)
            require(projection == prepared['deployments'][role]['projection'], 'deployment_boundary_changed')
            require(image in (OLD_IMAGE,IMAGE) if withdrawing and role in ROLES else image == state['images'][role], 'image_changed')
            if withdrawing:
                require(type(obj['spec'].get('replicas')) is int and obj['spec']['replicas'] in (0, 1), 'withdraw_replica_boundary')
            elif check_pods:
                require(obj['spec'].get('replicas',1) == state['replicas'][role], 'replicas_changed')
            else:
                wanted = state['replicas'][role]
                require(obj['spec'].get('replicas',1) in ((0,1) if role == 'postgres' else (wanted,)), 'checkpoint_replica_changed')
        secrets = {v['metadata']['name']:secret_projection(v) for v in json.loads(self.old.k('get','secrets','-o','json'))['items']}
        require(set(secrets) == set(prepared['secrets']), 'secret_set_changed')
        for name,original in prepared['secrets'].items():
            candidates = [copy.deepcopy(original)]
            for variant in ('paused','active'):
                configs = load(self.root/('configs-'+variant+'.json'))
                require(digest(read(self.root/('configs-'+variant+'.json'))) == prepared['config_hashes'][variant], 'candidate_changed')
                candidate = copy.deepcopy(original)
                for role,(secret,key) in ROLES.items():
                    if name == secret:
                        candidate['data'][key] = base64.b64encode(configs[role].encode()).decode()
                candidates.append(candidate)
            require(secrets[name] in candidates if withdrawing else secrets[name] == candidates[('old','paused','active').index(state['configs'])], 'secret_boundary_changed')
        if check_pods and not withdrawing:
            expected = copy.deepcopy(state['pods'])
            if pg_rebind is not None:
                require(state['phase'] == 'stopped' and set(expected) == {'postgres'}, 'pg_rebind_phase')
                expected['postgres'] = pg_rebind
            require(current['pods'] == expected, 'process_identity_changed')
        return prepared

    def protected_snapshot(self):
        p = self.prior_controller
        return {'boot':p.boot(),'edge':p.edge(),'foundation':p.foundation(),
                'profiles':{n:digest(v) for n,v in p.profiles().items()},
                'edge_conf_tree':p._native_conf_tree()}

    def guard(self, pg_rebind=None):
        return self.boundary_guard(pg_rebind=pg_rebind)

    def prepare(self):
        require(not self.root.exists(), 'bundle_already_exists')
        self.prior_controller.guard()
        prior_state = self.prior_controller.state()
        require(prior_state['phase'] == 'complete' and prior_state['configs'] == 'active'
                and prior_state['revision'] == '33f3c730123319625fe3a25713988201eb5d82e0'
                and prior_state.get('compression_source_history'), 'completed_predecessor_required')
        snap = self.snapshot()
        require(snap['pods'] == prior_state['pods'] and set(snap['pods']) == {'postgres','writer','backend'}, 'initial_process_changed')
        observed = stamp()
        configs = {'paused':{},'active':{}}
        deployments = {}
        for role in ('postgres','writer','backend'):
            obj = self.get('deployment',role)
            projection,image = deployment_projection(obj)
            require(image == (PG_IMAGE if role == 'postgres' else OLD_IMAGE), 'initial_image')
            deployments[role] = {'projection':projection,'manifest':obj}
        for role,(name,key) in ROLES.items():
            original = base64.b64decode(snap['secrets'][name]['data'][key],validate=True).decode()
            for variant in configs:
                configs[variant][role] = configuration(original,variant=='active')
        artifacts = self.prior_hashes()
        self.prior_controller.guard()
        require(self.snapshot() == snap and self.prior_hashes() == artifacts, 'prepare_runtime_changed')
        require((utc_now()-instant(observed)).total_seconds() <= 300, 'inventory_stale')
        self.plan = {'version':1,'revision':REVISION,'context':self.context,'target_image':IMAGE,
            'store_binding_sha256':STORE_BINDING,'captured_at':observed}
        self.plan_raw = encoded(self.plan)
        prepared = {**{k:v for k,v in snap.items() if k not in ('deployments','pods')},
            'version':1,'revision':REVISION,'at':observed,'deployments':deployments,'old_pods':snap['pods'],
            'store_binding_sha256':STORE_BINDING,'prior_artifacts':artifacts,
            'config_hashes':{k:digest(encoded(v)) for k,v in configs.items()}}
        self.root.mkdir(mode=0o700)
        syncdir(self.root.parent)
        save(self.root/'plan.json',self.plan_raw)
        for variant,value in configs.items(): save(self.root/('configs-'+variant+'.json'),value)
        save(self.root/'prepared.json',prepared)
        save(self.root/'state.json',{'version':1,'revision':REVISION,'phase':'prepared',
            'source_sha256':digest(Path(__file__).read_bytes()),'plan_sha256':digest(self.plan_raw),
            'prepared_sha256':digest(encoded(prepared)),'configs':'old','pods':snap['pods'],
            'images':{r:(PG_IMAGE if r=='postgres' else OLD_IMAGE) for r in ('postgres','writer','backend')},
            'replicas':{'postgres':1,'writer':1,'backend':1}})
        self.guard()

    def chain_record(self, phase):
        # The completed predecessor and its entire frozen source/history stay immutable.
        save(self.root/('chain-'+phase+'.json'),{'phase':phase,'prior_artifacts':self.prior_hashes(),'at':stamp()})

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
        if kind != 'coordinated-schema18-backup':
            require(value.get('processes') == state['pods'] and value.get('configs') == state['configs'],
                    'receipt_runtime_binding')
        if kind == 'target-observation-acceptance':
            observation = value.get('observation_artifact')
            require(isinstance(observation, str), 'observation_artifact_required')
            parsed = load(observation)
            rows = parsed.get('samples', [])
            require(len(rows) >= 31 and all(r.get('pods') == state['pods'] and r.get('configs') == 'active'
                    and r.get('schema') == 18 and r.get('policy') == 2 for r in rows), 'observation_runtime_binding')
            times = [r['monotonic'] for r in rows]
            gaps = [b-a for a,b in zip(times,times[1:])]
            require(times[-1]-times[0] >= 900 and gaps and all(0 < g <= 45 for g in gaps), 'observation_samples_interval')
            owners = [r.get('writer_owner') for r in rows]
            require(owners[0] is not None and all(o == owners[0] for o in owners), 'observation_owner_changed')
            require(any(a.get('path') == observation for a in value.get('artifacts', [])), 'observation_artifact_unbound')
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
            accepted, raw = self.receipt(receipt, receipt_sha, 'coordinated-schema18-backup',
                ('coordinated_pg_s3', 'old_clone_verified', 'roles_stopped', 'pg_restarted_without_restore', 'credentials_preserved'))
            require(accepted.get('recovery_scope') == 'physical_pg_checkpoint_original_immutable_s3_retained'
                    and accepted.get('independent_s3_backup') is False, 'backup_scope')
            require(accepted.get('schema') == 18 and re.fullmatch('[0-9]+', str(accepted.get('system_identifier', ''))), 'backup_schema_identity')
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
                'runtime-ready': ('target-private-acceptance', ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary', 'capture_notice_preserved', 'tool_contract')),
                'activate-existing': ('target-activation-acceptance', ('schema18', 'policy2', 'sole_writer', 'private_boundary', 'public_http_both_families_revisions', 'public_wt_both_families_revisions', 'public_compression_gzip_br_zstd', 'capture_notice_preserved'))}[operation]
            accepted, raw = self.receipt(receipt, receipt_sha, kind, checks)
            require(accepted.get('schema') == 18, 'target_schema_receipt')
            save(self.root / ('accepted-' + operation + '.json'), raw)
        if operation == 'finish':
            accepted, raw = self.receipt(receipt, receipt_sha, 'target-observation-acceptance',
                ('schema18', 'policy2', 'sole_writer', 'read_only_serving', 'private_boundary',
                 'public_http_both_families_revisions', 'public_wt_both_families_revisions', 'public_compression_gzip_br_zstd',
                 'nine_source_settings_preserved', 'capture_notice_preserved', 'timers_preserved', 'stable_processes'))
            require(accepted.get('schema') == 18
                    and type(accepted.get('duration_seconds')) in (int, float) and accepted['duration_seconds'] >= 900
                    and type(accepted.get('sample_count')) is int and accepted['sample_count'] >= 31
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
        self.boundary_guard(check_pods=False,withdrawing=True)
        state = self.state()
        state['phase']='withdraw_incomplete'
        self.record(state)
        for role in ('backend','writer'):
            obj = self.get('deployment',role)
            if obj['spec'].get('replicas',1):
                patch=[{'op':'test','path':'/metadata/uid','value':obj['metadata']['uid']},
                    {'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},
                    {'op':'replace','path':'/spec/replicas','value':0}]
                self.mutate('withdraw-'+role,lambda r=role,p=patch:self.old.k('patch','deployment',r,'--type=json','-p',json.dumps(p)))
            self.old.k('wait','--for=delete','pod','-l','app='+role,'--timeout=180s',timeout=210,request_timeout=190)
            state=self.state(); state['replicas'][role]=0; state['pods'].pop(role,None); self.record(state)
        require(not any(v['metadata'].get('labels',{}).get('app') in ROLES for v in json.loads(self.old.k('get','pods','-o','json'))['items']), 'application_pod_remaining')
        state=self.state(); state['phase']='withdrawn'; self.record(state)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context',required=True)
    parser.add_argument('--bundle',default=BUNDLE)
    parser.add_argument('--plan')
    parser.add_argument('--approval')
    parser.add_argument('--approval-sha256')
    parser.add_argument('--receipt')
    parser.add_argument('--receipt-sha256')
    parser.add_argument('operation',choices=('prepare','guard','stop','apply','start-writer','start-reader','runtime-ready','activate-existing','finish','withdraw'))
    args=parser.parse_args()
    try:
        require(os.geteuid()==0,'root_required')
        controller=Controller(args.bundle,args.plan,args.context)
        with controller.locked():
            if args.operation=='guard': controller.guard()
            else: controller.run(args.operation,args.approval,args.approval_sha256,args.receipt,args.receipt_sha256)
        print(json.dumps({'operation':args.operation,'phase':controller.state()['phase'],'known_complete':True}))
    except Exception as error:
        code=str(error) if isinstance(error,Error) and re.fullmatch('[a-z0-9_]+',str(error)) else 'upgrade_operation_failed'
        print(json.dumps({'operation':args.operation,'known_complete':False,'code':code}),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
