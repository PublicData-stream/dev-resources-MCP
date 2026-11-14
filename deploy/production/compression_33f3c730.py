#!/usr/bin/env python3
"""One explicit native SSE-compression transition and immutable source successor.

Only the named no-store SSE policy and its MCP route selection change. Permanent
storage, application credentials, historical controller/prepared/plan evidence,
and unrelated shared-edge configuration remain untouched.
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
import shutil
import stat
import sys
import time
import tomllib

sys.dont_write_bytecode = True
REVISION = '33f3c730123319625fe3a25713988201eb5d82e0'
BUNDLE = Path('/var/lib/devres-production-upgrades/33f3c730-20261114')
WORK = Path('/tmp/devres-upgrade-33f3c730-20261114')
CANONICAL = Path('/usr/local/libexec/devres-upgrade-33f3c730/upgrade-controller.py')
FROZEN = CANONICAL.with_name('upgrade-controller.v4-2b18ea9e.py')
FROZEN_SHA = '2b18ea9ee326eabbafa1398f0f065c639b9e70fe01962cca31e6d8fc86365a6e'
IMPLEMENTATION = CANONICAL.with_name('compression_33f3c730.py')
JOURNAL = BUNDLE / 'compression-sse-transition'
ADMISSION = JOURNAL / 'admission.json'
POLICY = 'devres-mcp-sse'
FILES = ('40-compression.toml', '62-route-devres.toml')
OLD_HASHES = {'40-compression.toml': 'cf0c5b06bd104166990173e6e3abd931b8f80dd2ae19dcb5c839110cbd585a29',
              '62-route-devres.toml': '31071b3d409cf2895356af672a5b0a0e0cb50aa243bdb2b3cd05dbba6dd4fa6c'}
EDGE_ID = '36e3ad39478bade960690a4bdb14e409b9899140fa6735ecca8400d79afeaeff'
EDGE_IMAGE = 'sha256:9f8aa1715586a5c15e26fe48ab982b43c28abe49dc2f09b78c1450ffa01b33d1'
KIND = 'explicit-no-store-mcp-sse-compression-source-successor'


class Error(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Error(code)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def enc(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def now():
    return dt.datetime.now(dt.timezone.utc)


def instant(value):
    v = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(v.tzinfo is not None and v.utcoffset() == dt.timedelta(0), 'utc_timestamp_required')
    return v


def raw(path, private=True, maximum=16 * 1024**2, owner=None):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        m = os.fstat(stream.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == (os.geteuid() if owner is None else owner) and m.st_nlink == 1
             and not m.st_mode & (0o077 if private else 0o022) and m.st_size <= maximum, 'bounded_owned_file_required')
        data = stream.read(maximum + 1)
        n = os.fstat(stream.fileno())
        need(len(data) == m.st_size and (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns) ==
             (n.st_dev, n.st_ino, n.st_size, n.st_mtime_ns), 'file_changed')
        return data


def load(path):
    return json.loads(raw(path))


def private_directory(path):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_refused')
    m = path.stat()
    need(stat.S_ISDIR(m.st_mode) and m.st_uid == os.geteuid() and not m.st_mode & 0o077, 'private_directory_required')


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value, replace=False):
    path = Path(path)
    private_directory(path.parent)
    body = value if isinstance(value, bytes) else enc(value)
    temporary = path.parent / ('.' + path.name + '.transition') if replace else path
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    if replace:
        os.replace(temporary, path)
    sync(path.parent)


def frozen():
    need(sha(raw(FROZEN)) == FROZEN_SHA, 'frozen_controller_changed')
    spec = importlib.util.spec_from_file_location('immutable_compression_predecessor', FROZEN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(module.REVISION == REVISION and module.BUNDLE == str(BUNDLE), 'frozen_revision_changed')
    return module


def policy_delta(compression, route):
    """Carry original bytes, append one policy, replace only routes[0].compression."""
    need(sha(compression) == OLD_HASHES[FILES[0]] and sha(route) == OLD_HASHES[FILES[1]], 'original_policy_bytes_required')
    before = tomllib.loads(compression.decode())
    global_policy = before['compression']
    need(global_policy.get('enabled') is True and not global_policy.get('policies'), 'original_default_policy_required')
    named = {'name': POLICY, 'enabled': True, 'gzip': True, 'deflate': False, 'zstd': True, 'br': True,
             'min_size_bytes': global_policy['min_size_bytes'], 'statuses': copy.deepcopy(global_policy['statuses']),
             'mime_types': ['text/event-stream'], 'level': global_policy['level'], 'vary': global_policy['vary'],
             'proxied': copy.deepcopy(global_policy['proxied']),
             'upstream_accept_encoding': global_policy['upstream_accept_encoding'],
             'allow_authenticated_sse': False, 'allow_no_store_sse': True}
    need(named['statuses'] == [200] and named['vary'] is True, 'native_sse_policy_requirements')
    lines = ['\n[[compression.policies]]\n']
    for key, value in named.items():
        lines.append(key + ' = ' + json.dumps(value, separators=(',', ':')) + '\n')
    proposed_compression = compression + ''.join(lines).encode()
    expected = copy.deepcopy(before)
    expected['compression']['policies'] = [named]
    need(tomllib.loads(proposed_compression.decode()) == expected, 'unlisted_global_compression_delta')
    old_route = tomllib.loads(route.decode())
    need(old_route['routes'][0]['compression'] == 'default', 'old_mcp_default_route_required')
    output = []
    index = -1
    changes = 0
    for line in route.decode().splitlines(keepends=True):
        if re.fullmatch(r'\s*\[\[routes\]\]\s*(?:#[^\r\n]*)?\r?\n?', line):
            index += 1
        if index == 0 and re.match(r'^\s*compression\s*=', line):
            line, count = re.subn(r'(^\s*compression\s*=\s*)"default"', lambda m: m[1] + '"' + POLICY + '"', line)
            changes += count
        output.append(line)
    proposed_route = ''.join(output).encode()
    expected_route = copy.deepcopy(old_route)
    expected_route['routes'][0]['compression'] = POLICY
    need(changes == 1 and tomllib.loads(proposed_route.decode()) == expected_route, 'unlisted_route_delta')
    return {FILES[0]: proposed_compression, FILES[1]: proposed_route}


def checked_delta(before, after, candidates, restart_at=None, completed_at=None):
    """Normalize only the two file bodies and this one same-container restart."""
    need(before['edge']['id'] == after['edge']['id'] == EDGE_ID
         and before['edge']['image'] == after['edge']['image'] == EDGE_IMAGE, 'same_native_edge_required')
    a, b = before['edge'], after['edge']
    need(a['restarts'] == b['restarts'] and b['pid'] > 0 and b['pid'] != a['pid']
         and int(b['pid_start_ticks']) > int(a['pid_start_ticks']) and instant(b['started']) > instant(a['started']), 'one_owned_edge_restart_required')
    if restart_at is not None:
        need(instant(restart_at) - dt.timedelta(seconds=5) <= instant(b['started']) <= instant(completed_at) + dt.timedelta(seconds=5), 'edge_restart_outside_intent')
    normalized = copy.deepcopy(after)
    normalized['edge'] = copy.deepcopy(before['edge'])
    need(set(before['conf_tree']) == set(after['conf_tree']), 'unlisted_conf_entry')
    need(set(candidates) == set(FILES), 'exact_two_config_candidates')
    for name in FILES:
        old, new = before['conf_tree'][name], after['conf_tree'][name]
        need(old['kind'] == new['kind'] == 'file' and old['uid'] == old['gid'] == new['uid'] == new['gid'] == 0
             and old['mode'] == new['mode'] == 0o644 and old['sha256'] == OLD_HASHES[name]
             and new['sha256'] == sha(candidates[name]) and new['size'] == len(candidates[name]), 'authorized_sse_config_delta')
        permitted = copy.deepcopy(old)
        for key in ('size', 'sha256', 'mtime_ns'):
            permitted[key] = new[key]
        need(new == permitted, 'unlisted_config_metadata_delta')
        normalized['conf_tree'][name] = copy.deepcopy(old)
        need(base64.b64decode(after['conf_contents'][name], validate=True) == candidates[name], 'live_candidate_bytes_changed')
        normalized['conf_contents'][name] = before['conf_contents'][name]
    # A docker restart may recreate only this container's endpoints. Keep both
    # network objects, addresses, aliases, mount/security configuration exact.
    need(set(before['docker']['networks']) == set(after['docker']['networks']) == {'devres-net', 'pdf2md-net'}, 'edge_network_set_changed')
    for name in before['docker']['networks']:
        old, new = before['docker']['networks'][name], after['docker']['networks'][name]
        mac = new['MacAddress']
        need(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac or '') is not None and not int(mac[:2], 16) & 1, 'unicast_edge_mac_required')
        normalized['docker']['networks'][name]['MacAddress'] = old['MacAddress']
        member = after['networks'][name]['edge_member']
        need(member['MacAddress'] == mac and re.fullmatch('[0-9a-f]{64}', member['EndpointID']) is not None, 'owned_edge_endpoint_required')
        normalized['networks'][name]['edge_member']['MacAddress'] = before['networks'][name]['edge_member']['MacAddress']
        normalized['networks'][name]['edge_member']['EndpointID'] = before['networks'][name]['edge_member']['EndpointID']
    need(normalized == before, 'unlisted_native_edge_delta')
    return copy.deepcopy(before)


def native_snapshot(controller, base, contents):
    """Read native reality directly, bypassing every compatibility adapter."""
    edge = base.Controller.edge(controller)
    value = json.loads(controller.module.call(['docker', 'inspect', edge['id']]))[0]
    status = value['State']
    need(value['Id'] == edge['id'] and status['Running'] is True and not status.get('Dead')
         and not status.get('Paused') and not status.get('Restarting'), 'edge_not_running')
    keys = ('IPAddress', 'IPPrefixLen', 'Gateway', 'GlobalIPv6Address', 'GlobalIPv6PrefixLen',
            'IPv6Gateway', 'MacAddress', 'Aliases', 'DNSNames', 'IPAMConfig', 'DriverOpts', 'Links')
    docker = {'id': value['Id'], 'image': value['Image'], 'config': value['Config'], 'host_config': value['HostConfig'],
              'mounts': value['Mounts'], 'restart_count': value['RestartCount'], 'health': status.get('Health', {}).get('Status'),
              'networks': {name: {key: network.get(key) for key in keys} for name, network in value['NetworkSettings']['Networks'].items()},
              'ports': value['NetworkSettings']['Ports']}
    networks = json.loads(controller.module.call(['docker', 'network', 'inspect', 'devres-net', 'pdf2md-net']))
    need(len(networks) == 2, 'native_network_inventory')
    networks = {n['Name']: {**{key: n.get(key) for key in base.NETWORK_FIELDS},
                           'edge_member': n.get('Containers', {}).get(edge['id'])} for n in networks}
    files = controller._native_edge_files()
    compose = raw(base.EDGE_COMPOSE, private=True)
    tree_reader = getattr(controller, '_raw_conf_tree', controller._native_conf_tree)
    tree = tree_reader()
    bodies = {}
    for name in ('20-proxy.toml', *FILES):
        expected = contents[name]
        body = raw(base.EDGE_CONF / name, private=False, maximum=65536)
        need(body == base64.b64decode(expected, validate=True), 'live_edge_content_changed')
        bodies[name] = base64.b64encode(body).decode()
    need(files == controller._native_edge_files() and tree == tree_reader(), 'native_edge_changed_during_read')
    return {'edge': edge, 'docker': docker, 'files': files, 'networks': networks, 'conf_tree': tree, 'conf_contents': bodies}, compose


def source_history(admission, admission_sha):
    return {'version': 1, 'kind': KIND, 'old_source_sha256': FROZEN_SHA,
            'old_state_sha256': admission['old_state_sha256'], 'admission_sha256': admission_sha}


def validate_admission(admission, wrapper_path):
    need(admission.get('version') == 1 and admission.get('kind') == KIND and admission.get('revision') == REVISION
         and admission.get('old_source_sha256') == FROZEN_SHA and admission.get('verified') is True,
         'compression_source_admission_identity')
    need(sha(raw(FROZEN)) == FROZEN_SHA and sha(raw(JOURNAL / 'old-controller.py')) == FROZEN_SHA
         and sha(raw(wrapper_path)) == admission['wrapper_sha256']
         and sha(raw(IMPLEMENTATION)) == admission['implementation_sha256'], 'successor_source_changed')
    for name, key in (('old-state.json', 'old_state_sha256'), ('old-prepared.json', 'prepared_sha256'), ('old-plan.json', 'plan_sha256')):
        need(sha(raw(JOURNAL / name)) == admission[key], 'immutable_source_preimage_changed')
    need(sha(raw(BUNDLE / 'prepared.json')) == admission['prepared_sha256']
         and sha(raw(BUNDLE / 'plan.json')) == admission['plan_sha256'], 'original_prepared_or_plan_changed')
    original = load(JOURNAL / 'old-state.json')
    need(original['source_sha256'] == FROZEN_SHA and original['phase'] == 'runtime_ready'
         and original['configs'] == 'paused' and original['prepared_sha256'] == admission['prepared_sha256']
         and original['plan_sha256'] == admission['plan_sha256'], 'source_handoff_original_phase')
    candidates = policy_delta(base64.b64decode(admission['before']['conf_contents'][FILES[0]], validate=True),
                              base64.b64decode(admission['before']['conf_contents'][FILES[1]], validate=True))
    checked_delta(admission['before'], admission['after'], candidates, admission['restart_at'], admission['observed_at'])
    for item in admission['artifacts']:
        need(Path(item['path']).parent == JOURNAL and sha(raw(item['path'])) == item['sha256'], 'compression_admission_artifact_changed')
    staged, live = load(JOURNAL / 'native-stage-check.json'), load(JOURNAL / 'native-live-check.json')
    expected = {name: sha(body) for name, body in candidates.items()}
    need(staged.get('version') == live.get('version') == 1 and staged.get('verified') is True and live.get('verified') is True
         and staged.get('image') == live.get('image') == EDGE_IMAGE and staged.get('no_network') is True
         and live.get('container') == EDGE_ID and staged.get('candidates') == live.get('candidates') == expected, 'native_compression_checks_required')
    return candidates


def controller_type(base, wrapper_path):
    """Build a polymorphic source successor without changing the frozen module."""
    class Controller(base.Controller):
        def __init__(self, bundle, plan, context):
            self._compat_depth = 0
            self._wrapper_path = Path(wrapper_path)
            self._admission_raw = raw(ADMISSION)
            self._admission = json.loads(self._admission_raw)
            self._candidates = validate_admission(self._admission, self._wrapper_path)
            super().__init__(bundle, plan, context)

        def attach_edge_admission(self, reference, value=None):
            # Original __init__ dispatches to this before its immediate virtual
            # verification. Save raw readers before it installs its old adapters.
            if not hasattr(self, '_raw_conf_tree'):
                self._raw_conf_tree = self.activation.conf_tree
            super().attach_edge_admission(reference, value)
            self._native_conf_tree = self._compat_conf_tree

        def _actual(self):
            need(raw(ADMISSION) == self._admission_raw, 'compression_admission_changed')
            validate_admission(self._admission, self._wrapper_path)
            actual, compose = native_snapshot(self, base, self._admission['after']['conf_contents'])
            need(actual == self._admission['after'] and sha(compose) == self._admission['compose_sha256'], 'admitted_sse_edge_changed')
            return actual, compose

        @contextlib.contextmanager
        def _old_boundary(self):
            outer = self._compat_depth == 0
            if outer:
                self._actual()
            self._compat_depth += 1
            try:
                yield
            finally:
                self._compat_depth -= 1
                if outer:
                    self._actual()

        def _compat_conf_tree(self):
            return copy.deepcopy(self._admission['before']['conf_tree']) if self._compat_depth else self._raw_conf_tree()

        def edge(self):
            if self._compat_depth:
                return copy.deepcopy(self._admission['before']['edge'])
            return base.Controller.edge(self)

        def native_edge_snapshot(self):
            if self._compat_depth:
                return copy.deepcopy(self._admission['before']), raw(base.EDGE_COMPOSE)
            return self._actual()

        def verify_edge_admission(self):
            with self._old_boundary():
                return super().verify_edge_admission()

        def safety(self):
            with self._old_boundary():
                return super().safety()

        def guard(self, pg_rebind=None):
            with self._old_boundary():
                return super().guard(pg_rebind)

        def state(self):
            validate_admission(self._admission, self._wrapper_path)
            value = load(self.root / 'state.json')
            need(value['revision'] == REVISION and value['plan_sha256'] == sha(self.plan_raw)
                 and value['prepared_sha256'] == self._admission['prepared_sha256']
                 and value['source_sha256'] == self._admission['wrapper_sha256']
                 and value.get('compression_source_history') == source_history(self._admission, sha(self._admission_raw)), 'successor_journal_identity')
            need(value.get('version') == 1 and value.get('configs') in ('old', 'paused', 'active')
                 and value.get('chain_phase') in (None, 'runtime_upgrade_stopped', 'runtime_upgraded')
                 and set(value.get('images', {})) == {'postgres', 'writer', 'backend'}
                 and value['images']['postgres'] == base.PG_IMAGE
                 and all(value['images'][role] in (base.OLD_IMAGE, base.IMAGE) for role in base.ROLES)
                 and set(value.get('replicas', {})) == {'postgres', 'writer', 'backend'}
                 and value['replicas']['postgres'] == 1
                 and all(type(value['replicas'][role]) is int and value['replicas'][role] in (0, 1) for role in base.ROLES)
                 and set(value.get('pods', {})) == {role for role, count in value['replicas'].items() if count}, 'successor_journal_shape')
            return value
    return Controller


def control_snapshot(controller):
    return controller.snapshot()


def approval(wrapper_sha, old_state_sha):
    return {'version': 1, 'operation': 'enable-no-store-mcp-sse-compression', 'reviewed': True,
            'old_source_sha256': FROZEN_SHA, 'implementation_sha256': sha(raw(IMPLEMENTATION)),
            'wrapper_sha256': wrapper_sha, 'old_state_sha256': old_state_sha,
            'prepared_sha256': sha(raw(BUNDLE / 'prepared.json')),
            'maximum_edge_restarts': 1, 'preserve_permanent_history': True}


def stage_tree(base, before, candidates):
    target = JOURNAL / 'staged-conf'
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    for name, meta in before['conf_tree'].items():
        if name == '.':
            continue
        relative = Path(name)
        need(not relative.is_absolute() and '..' not in relative.parts, 'relative_config_entry_required')
        source, destination = base.EDGE_CONF / relative, target / relative
        if meta['kind'] == 'directory':
            destination.mkdir(mode=0o755)
            destination.chmod(0o755)
        else:
            body = raw(source, private=False, maximum=65536, owner=meta['uid'])
            need(len(body) == meta['size'] and sha(body) == meta['sha256'], 'config_changed_during_stage')
            destination.write_bytes(candidates.get(name, body))
            destination.chmod(0o644)
    need(set(candidates) <= set(before['conf_tree']), 'existing_config_files_required')
    return target


def verify_stage(stage, before, candidates):
    root_info = stage.lstat()
    need(stat.S_ISDIR(root_info.st_mode) and root_info.st_uid == os.geteuid()
         and stat.S_IMODE(root_info.st_mode) == 0o755, 'staged_root_must_be_traversable')
    actual = {'.'}
    for directory, directories, files in os.walk(stage, followlinks=False):
        for name in sorted(directories + files):
            path = Path(directory) / name
            relative = str(path.relative_to(stage))
            need(relative in before['conf_tree'], 'unlisted_staged_config_entry')
            meta = before['conf_tree'][relative]
            info = path.lstat()
            need(not path.is_symlink() and info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'staged_configuration_permissions')
            if meta['kind'] == 'directory':
                need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o755, 'staged_directory_required')
            else:
                need(stat.S_IMODE(info.st_mode) == 0o644, 'staged_file_must_be_readable')
                body = raw(path, private=False, maximum=65536)
                expected = sha(candidates[relative]) if relative in candidates else meta['sha256']
                need(sha(body) == expected, 'staged_configuration_changed')
            actual.add(relative)
            need(len(actual) <= 256, 'staged_tree_bound')
    need(actual == set(before['conf_tree']), 'staged_configuration_entry_missing')


def stage_check(controller, base, before, stage, candidates):
    verify_stage(stage, before, candidates)
    name = 'devres-mcp-sse-check-' + os.urandom(8).hex()
    save(JOURNAL / 'native-stage-check-intent.json', {'version': 1, 'maximum_attempts': 1, 'name': name, 'image': EDGE_IMAGE})
    args = ['docker', 'run', '--rm', '--pull', 'never', '--name', name, '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--entrypoint', '/usr/local/bin/oxibelt']
    user = before['docker']['config'].get('User')
    need(isinstance(user, str) and re.fullmatch('[0-9]+(?::[0-9]+)?', user) is not None, 'native_checker_numeric_user_required')
    args += ['--user', user, '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777']
    replaced = 0
    for mount in before['docker']['mounts']:
        need(mount['Type'] == 'bind' and isinstance(mount['Source'], str) and isinstance(mount['Destination'], str)
             and not any(c in mount['Source'] + mount['Destination'] for c in (',', '\n', '\r')), 'native_checker_bind_mount_required')
        source = mount['Source']
        if source == str(base.EDGE_CONF):
            source = str(stage)
            replaced += 1
        args += ['--mount', 'type=bind,src=' + source + ',dst=' + mount['Destination'] + ',readonly']
    need(replaced == 1, 'one_staged_configuration_mount_required')
    args += [EDGE_IMAGE, '--config', '/etc/oxibelt/config/oxibelt.toml', '--check']
    output = controller.module.call(args, timeout=60)
    verify_stage(stage, before, candidates)
    save(JOURNAL / 'native-stage-check.json', {'version': 1, 'verified': True, 'image': EDGE_IMAGE,
          'no_network': True, 'candidates': {name: sha(body) for name, body in candidates.items()},
          'observed_at': now().isoformat(), 'stdout_sha256': sha(output)})


def prepare(base, args):
    need(sha(raw(CANONICAL)) == FROZEN_SHA and sha(raw(args.wrapper_candidate)) == args.wrapper_sha,
         'predecessor_or_candidate_source_changed')
    need(Path(args.wrapper_candidate).parent == WORK and re.fullmatch('[0-9a-f]{64}', args.wrapper_sha), 'private_wrapper_candidate_required')
    controller = base.Controller(str(BUNDLE), str(BUNDLE / 'plan.json'), 'default')
    with controller.locked():
        controller.guard()
        state = controller.state()
        need(state['phase'] == 'runtime_ready' and state['configs'] == 'paused' and not state.get('compression_source_history'), 'paused_runtime_ready_required')
        approved = raw(args.approval)
        need(sha(approved) == args.approval_sha and json.loads(approved) == approval(args.wrapper_sha, sha(raw(BUNDLE / 'state.json'))), 'explicit_compression_approval_required')
        need(not JOURNAL.exists(), 'fresh_compression_journal_required')
        JOURNAL.mkdir(mode=0o700)
        sync(JOURNAL.parent)
        save(JOURNAL / 'prepare-intent.json', {'version': 1, 'at': now().isoformat(), 'maximum_attempts': 1})
        for name, source in (('old-state.json', BUNDLE / 'state.json'), ('old-prepared.json', BUNDLE / 'prepared.json'),
                             ('old-plan.json', BUNDLE / 'plan.json'), ('old-controller.py', FROZEN), ('approval.json', args.approval)):
            save(JOURNAL / name, raw(source))
        snapshot = control_snapshot(controller)
        save(JOURNAL / 'old-control-snapshot.json', snapshot)
        before, compose = controller.native_edge_snapshot()
        candidates = policy_delta(base64.b64decode(before['conf_contents'][FILES[0]], validate=True),
                                  base64.b64decode(before['conf_contents'][FILES[1]], validate=True))
        for name, body in candidates.items():
            save(JOURNAL / (name + '.candidate'), body)
        stage = stage_tree(base, before, candidates)
        stage_check(controller, base, before, stage, candidates)
        controller.guard()
        need(control_snapshot(controller) == snapshot and controller.state() == state, 'runtime_changed_during_compression_stage')
        record = {'version': 1, 'revision': REVISION, 'prepared_at': now().isoformat(), 'before': before,
                  'compose_sha256': sha(compose), 'wrapper_sha256': args.wrapper_sha,
                  'implementation_sha256': sha(raw(IMPLEMENTATION)), 'old_state_sha256': sha(raw(JOURNAL / 'old-state.json')),
                  'prepared_sha256': sha(raw(JOURNAL / 'old-prepared.json')), 'plan_sha256': sha(raw(JOURNAL / 'old-plan.json')),
                  'snapshot_sha256': sha(raw(JOURNAL / 'old-control-snapshot.json')), 'approval_sha256': sha(approved),
                  'candidates': {name: sha(body) for name, body in candidates.items()}}
        save(JOURNAL / 'prepared.json', record)
    return {'prepared': True, 'native_staged_check_passed': True, 'live_files_changed': False}


def install_public(path, before, body):
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r+b') as stream:
        m = os.fstat(stream.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == m.st_gid == 0 and m.st_nlink == 1 and stat.S_IMODE(m.st_mode) == 0o644
             and (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns) == (before['device'], before['inode'], before['size'], before['mtime_ns']), 'live_config_preimage_changed')
        need(sha(stream.read(65537)) == before['sha256'], 'live_config_content_changed')
        stream.seek(0)
        stream.write(body)
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())


def fence_applications(controller, base):
    """Own a new emergency fence; never replay prior withdraw intents."""
    current = load(BUNDLE / 'state.json')
    before = load(JOURNAL / 'old-state.json')
    prepared = load(BUNDLE / 'prepared.json')
    need(sha(raw(BUNDLE / 'prepared.json')) == before['prepared_sha256'] and current['prepared_sha256'] == before['prepared_sha256'], 'fence_prepared_changed')
    for name, expected in prepared['secrets'].items():
        value = base.secret_projection(controller.get('secret', name))
        for role, (secret, key) in base.ROLES.items():
            if name == secret:
                expected = copy.deepcopy(expected)
                expected['data'][key] = base64.b64encode(base.load(BUNDLE / 'configs-paused.json')[role].encode()).decode()
        need(value == expected, 'fence_secret_changed')
    for role in ('postgres', 'backend', 'writer'):
        obj = controller.get('deployment', role)
        projection, image = base.deployment_projection(obj)
        need(projection == prepared['deployments'][role]['projection'] and image == before['images'][role]
             and obj['spec'].get('replicas') in (0, 1), 'fence_deployment_boundary_changed')
        if role == 'postgres':
            need(obj['spec']['replicas'] == 1, 'fence_postgres_must_remain_running')
            continue
        save(JOURNAL / ('fence-' + role + '-intent.json'), {'version': 1, 'uid': obj['metadata']['uid'], 'maximum_attempts': 1})
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
        controller.old.k('patch', 'deployment', role, '--type=json', '-p', json.dumps(patch))
        controller.old.k('wait', '--for=delete', 'pod', '-l', 'app=' + role, '--timeout=180s', timeout=210, request_timeout=190)
        current['replicas'][role] = 0
        current['pods'].pop(role, None)
        save(BUNDLE / 'state.json', current, replace=True)
        save(JOURNAL / ('fence-' + role + '-completed.json'), {'known_complete': True})
    current['phase'] = 'compression_transition_fenced'
    save(BUNDLE / 'state.json', current, replace=True)


def apply(base, args):
    need(not (JOURNAL / 'apply-intent.json').exists(), 'one_compression_transition_only')
    p = load(JOURNAL / 'prepared.json')
    need(sha(raw(CANONICAL)) == FROZEN_SHA and sha(raw(args.wrapper_candidate)) == p['wrapper_sha256'] == args.wrapper_sha
         and sha(raw(IMPLEMENTATION)) == p['implementation_sha256'], 'transition_sources_changed')
    need(sha(raw(args.approval)) == args.approval_sha == p['approval_sha256'], 'transition_approval_changed')
    need(-5 <= (now() - instant(p['prepared_at'])).total_seconds() <= 300, 'compression_preparation_stale')
    controller = base.Controller(str(BUNDLE), str(BUNDLE / 'plan.json'), 'default')
    with controller.locked():
        controller.guard()
        need(sha(raw(BUNDLE / 'state.json')) == p['old_state_sha256'] and control_snapshot(controller) == load(JOURNAL / 'old-control-snapshot.json'), 'pretransition_state_changed')
        candidates = {name: raw(JOURNAL / (name + '.candidate')) for name in FILES}
        need({name: sha(body) for name, body in candidates.items()} == p['candidates'], 'staged_candidate_changed')
        save(JOURNAL / 'apply-intent.json', {'version': 1, 'at': now().isoformat(), 'maximum_attempts': 1})
        touched = False
        try:
            for name in FILES:
                save(JOURNAL / ('install-' + name + '-intent.json'), {'version': 1, 'maximum_attempts': 1})
                touched = True
                install_public(base.EDGE_CONF / name, p['before']['conf_tree'][name], candidates[name])
                save(JOURNAL / ('install-' + name + '-completed.json'), {'sha256': sha(candidates[name])})
            restart_at = now().isoformat()
            save(JOURNAL / 'restart-intent.json', {'version': 1, 'container': EDGE_ID, 'at': restart_at, 'maximum_attempts': 1})
            controller.module.call(['docker', 'restart', '--time', '15', EDGE_ID], timeout=60)
            contents = copy.deepcopy(p['before']['conf_contents'])
            for name in FILES:
                contents[name] = base64.b64encode(candidates[name]).decode()
            after, compose = native_snapshot(controller, base, contents)
            health_deadline = time.monotonic() + 30
            while after['docker']['health'] != p['before']['docker']['health']:
                need(time.monotonic() < health_deadline, 'edge_health_restart_deadline')
                time.sleep(1)
                after, compose = native_snapshot(controller, base, contents)
            observed = now().isoformat()
            need(sha(compose) == p['compose_sha256'], 'unrelated_compose_changed')
            checked_delta(p['before'], after, candidates, restart_at, observed)
            save(JOURNAL / 'restart-completed.json', {'version': 1, 'edge': after['edge'], 'observed_at': observed})
            output = controller.module.call(['docker', 'exec', EDGE_ID, '/usr/local/bin/oxibelt', '--config', '/etc/oxibelt/config/oxibelt.toml', '--check'], timeout=45)
            save(JOURNAL / 'native-live-check.json', {'version': 1, 'verified': True, 'container': EDGE_ID, 'image': EDGE_IMAGE,
                 'candidates': {name: sha(body) for name, body in candidates.items()}, 'observed_at': now().isoformat(), 'stdout_sha256': sha(output)})
            need(sha(raw(BUNDLE / 'state.json')) == p['old_state_sha256'], 'source_state_changed_before_handoff')
            admission = {**p, 'kind': KIND, 'old_source_sha256': FROZEN_SHA, 'after': after,
                         'restart_at': restart_at, 'observed_at': observed, 'verified': True,
                         'artifacts': [{'path': str(JOURNAL / name), 'sha256': sha(raw(JOURNAL / name))} for name in
                            ('native-stage-check.json', 'native-live-check.json', 'restart-intent.json', 'restart-completed.json', 'approval.json')]}
            save(ADMISSION, admission)
            new_state = load(JOURNAL / 'old-state.json')
            new_state['source_sha256'] = p['wrapper_sha256']
            new_state['compression_source_history'] = source_history(admission, sha(raw(ADMISSION)))
            new_state['updated_at'] = now().isoformat()
            save(JOURNAL / 'new-state.json', new_state)
            save(JOURNAL / 'handoff-intent.json', {'version': 1, 'old_source_sha256': FROZEN_SHA,
                 'new_source_sha256': p['wrapper_sha256'], 'old_state_sha256': p['old_state_sha256'],
                 'new_state_sha256': sha(raw(JOURNAL / 'new-state.json')), 'maximum_attempts': 1})
            # Source and state cannot be one atomic filesystem operation. The
            # durable pair intent makes an interrupted handoff fail closed.
            save(CANONICAL, raw(args.wrapper_candidate), replace=True)
            save(BUNDLE / 'state.json', raw(JOURNAL / 'new-state.json'), replace=True)
            spec = importlib.util.spec_from_file_location('adopted_compression_controller', CANONICAL)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            successor = module.Controller(str(BUNDLE), str(BUNDLE / 'plan.json'), 'default')
            successor.guard()
            need(successor.edge() == after['edge'], 'observer_must_expose_actual_edge')
            save(JOURNAL / 'handoff-completed.json', {'version': 1, 'known_complete': True,
                 'source_sha256': p['wrapper_sha256'], 'state_sha256': sha(raw(BUNDLE / 'state.json')), 'observed_at': now().isoformat()})
        except Exception:
            if touched:
                try:
                    fence_applications(controller, base)
                    save(JOURNAL / 'failed-fenced.json', {'fenced': True, 'permanent_history_preserved': True})
                except Exception:
                    save(JOURNAL / 'failed-fence-reconciliation-required.json', {'manual_reconciliation_required': True, 'no_retry_authorized': True})
            raise
    return {'known_complete': True, 'native_sse_policy_selected': True, 'source_sha256': p['wrapper_sha256'],
            'permanent_storage_changed': False, 'actual_codec_acceptance_still_required': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'apply'))
    parser.add_argument('--wrapper-candidate', type=Path, required=True)
    parser.add_argument('--wrapper-sha', required=True)
    parser.add_argument('--approval', type=Path, required=True)
    parser.add_argument('--approval-sha', required=True)
    args = parser.parse_args()
    need(os.geteuid() == 0 and sha(raw(IMPLEMENTATION)) == sha(Path(__file__).read_bytes()), 'root_and_installed_source_required')
    base = frozen()
    print(json.dumps({'prepare': prepare, 'apply': apply}[args.operation](base, args), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'known_complete': False, 'code': str(error) if isinstance(error, Error) else 'compression_transition_failed',
                          'permanent_storage_not_restored': True}))
        raise SystemExit(1)
