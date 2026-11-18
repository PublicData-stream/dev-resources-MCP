#!/usr/bin/env python3
"""Owned synthetic Kubernetes recovery assessment; no public source requests.

The candidate server image is deliberately separate from the tooling harness.
No production configuration, retained incident, or provider credentials enter this
fixture. The only temporarily loaded host policy is the exact tracked AppArmor
asset, copied below /tmp and removed after the owned namespace is gone.
"""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = 'devres-assessment'
DATABASE = 'devres_assessment_fixture'
PROFILE = 'devres-runtime'
APPARMOR_SHA256 = '4375146629c956b8e63cc4b358ef52c6bcda458621b7dcf8601b0f3d922b3e7e'
PARSER_URL = 'https://deb.debian.org/debian/pool/main/a/apparmor/apparmor_3.0.8-3_amd64.deb'
PARSER_PACKAGE_SHA256 = '8185d7f9c14618bca0e0230f71b33f87a316182e35f569b4f25e1159904778b2'
PARSER_PACKAGE_SIZE = 616144
PARSER_SHA256 = '8e00d0f40bf623dd1244f962638db680c6ae6c9c868e04680a6481eeed0e5f26'
PARSER_SIZE = 1457264
MAX_METADATA = 2 * 1024 * 1024
IMAGE_DIGEST = r'sha256:[0-9a-f]{64}'
UUID_PATTERN = r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
OBSERVER_STAGES = frozenset(('saved_state', 'statistics', 'kind_inventory', 'evidence_page',
    'defaults', 'attribution', 'writer_token', 'writer_transport'))
OBSERVER_REASONS = frozenset(('none', 'ok', 'unavailable', 'integrity', 'capacity', 'invalid', 'unknown', 'cancelled'))
OBSERVER_PHASES = frozenset(('setup', 'stop', 'baseline', 'configure', 'startup', 'readiness',
    'fault-startup', 'fault-injection', 'fault-probe', 'fault-timing', 'public-status',
    'acquisition-denial', 'invariants', 'restore'))
OBSERVER_ERRORS = frozenset(('unknown', 'interrupted', 'fixture_command_failed',
    'fixture_command_output_bound', 'observer_command_timeout', 'observer_process_changed',
    'observer_process_unavailable', 'observer_timing_bound', 'observer_timing_schema',
    'observer_timing_count_bound', 'observer_timing_missing', 'observer_timing_overflow',
    'observer_timing_duplicate', 'observer_timing_unavailable', 'observer_earlier_storage_stage_missing',
    'observer_forwarded_after_storage_failure', 'observer_publication_owner_present',
    'observer_startup_mutated_metadata', 'observer_status_mutated_metadata',
    'observer_restoration_failed', 'fixture_evidence_retention_incomplete'))
OBSERVER_RESTORATIONS = frozenset(('sql-grant', 'objectstore-start', 'objectstore-ready',
    'backend-stop', 'writer-stop', 'policy-remove', 'writer-config', 'reader-config',
    'writer-template', 'reader-template', 'writer-start', 'backend-start', 'semantic-ready'))
SETUP_PHASES = frozenset(('admission', 'node-preparation', 'node-restoration', 'apparmor', 'namespace', 'identity', 'policy',
    'configuration', 'network', 'seed', 'baseline', 'positive', 'invariants', 'matrix', 'connect-readiness', 'cleanup'))
SETUP_CODES = OBSERVER_ERRORS | frozenset(('fixture_command_timeout', 'fixture_apply_objects_required',
    'fixture_apply_namespace_invalid', 'owned_tmp_fixture_required', 'fresh_assessment_namespace_required',
    'apparmor_lock_owner', 'apparmor_canonical_hash_mismatch', 'apparmor_profile_already_loaded',
    'apparmor_asset_changed', 'apparmor_not_enforcing', 'apparmor_cleanup_incomplete_profile_retained',
    'apparmor_task_check_invalid', 'one_fixture_database_required', 'one_fixture_provider_table_required',
    'assessment_positive_failed', 'assessment_mutated_retained_metadata', 'assessment_container_ended',
    'assessment_readiness_policy_changed', 'assessment_readiness_labels_changed', 'assessment_readiness_result',
    'assessment_supervision_deadline', 'assessment_namespace_cleanup_unconfirmed',
    'fixture_owned_docker_required', 'fixture_node_identity', 'fixture_node_mount_namespace',
    'fixture_host_mount_namespace_refused', 'fixture_host_mount_propagation_refused',
    'fixture_node_apparmor_kernel_disabled', 'fixture_postgres_process', 'fixture_node_kubelet_process',
    'fixture_node_identity_changed', 'fixture_host_mount_changed', 'fixture_node_securityfs_not_confined',
    'fixture_node_preparation_identity_changed', 'fixture_node_mountinfo_invalid', 'fixture_node_mountinfo_missing',
    'fixture_node_runtime_process', 'fixture_containerd_stop_mode', 'fixture_postgres_runtime_process',
    'fixture_docker_context_refused', 'fixture_owned_resource_kind', 'fixture_owned_resource_unavailable',
    'fixture_owned_resource_list', 'fixture_owned_resource_missing', 'fixture_owned_resource_foreign',
    'fixture_owned_resource_replaced', 'fixture_owned_resource_cleanup_unconfirmed', 'fixture_apply_operation_invalid'))
SETUP_CODES = SETUP_CODES | frozenset(('fixture_parser_package', 'fixture_parser_archive',
    'fixture_parser_member', 'fixture_parser_download', 'fixture_parser_node', 'fixture_parser_version',
    'fixture_parser_write_boundary', 'fixture_image_reference', 'fixture_image_identity',
    'fixture_image_storage', 'fixture_image_graph', 'fixture_image_architecture',
    'fixture_node_restoration_identity', 'fixture_node_restoration_cleanup', 'fixture_node_restoration_preimage'))
CONTROL_COMMANDS = frozenset(('unknown', 'apparmor-policy', 'apparmor-state', 'apparmor-tasks',
    'docker-metadata', 'docker-exec', 'kubectl.apply', 'kubectl.create', 'kubectl.exec',
    'kubectl.wait', 'kubectl.delete', 'kubectl.get', 'kubectl.logs', 'kubectl.patch', 'kubectl.rollout'))
PROBE_NETWORK_CODES = frozenset(('unknown', 'api_admitted', 'dns_failure', 'postgres_connection', 'apparmor_message'))
FIXTURE_OWNER_LABEL = 'devres.fixture-owner'
ASSESSMENT_APP = 'devres-npm-assessment'
OWNED_POLICIES = {'policy': 'postgres-owned-assessment', 'readiness_policy': 'postgres-owned-assessment-readiness'}
READINESS_CASES = ('cold-readiness', 'readiness-denied')
READINESS_FAULTS = {'malformed-config': 'invalid', 'bad-password': 'authentication',
                    'wrong-schema': 'schema', 'required-tls': 'unavailable'}
MAX_IMAGE_METADATA = 1024 * 1024
DATABASE_ADMIN = 'postgres://devres:fixture-only@postgres.devres-acceptance.svc.cluster.local/' + DATABASE
DATABASE_READER = 'postgres://devres_assessment_reader:assessment-fixture-only@postgres.devres-acceptance.svc.cluster.local/' + DATABASE


class FixtureError(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise FixtureError(code)


def command(args, *, data=None, timeout=60, check=True, maximum=MAX_METADATA):
    if args[:1] == ['docker']:
        need(not os.environ.get('DOCKER_CONTEXT'), 'fixture_docker_context_refused')
    try:
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        error.command_outcome = command_outcome(args, 'timeout')
        raise
    if len(result.stdout) > maximum or len(result.stderr) > MAX_METADATA:
        error = FixtureError('fixture_command_output_bound')
        error.command_outcome = command_outcome(args, 'output_bound', result)
        raise error
    if check:
        if result.returncode != 0:
            error = FixtureError('fixture_command_failed')
            error.command_outcome = command_outcome(args, 'nonzero', result)
            raise error
    return result


def command_outcome(args, outcome, result=None):
    """Keep only closed control-operation names and counters, never argv or output."""
    kind = 'unknown'
    if args[:2] == ['sudo', '-n']:
        kind = {'apparmor_parser': 'apparmor-policy', 'cat': 'apparmor-state',
                'python3': 'apparmor-tasks'}.get(args[2] if len(args) > 2 else '', 'unknown')
    elif args[:1] == ['docker']:
        kind = 'docker-exec' if args[1:2] == ['exec'] else 'docker-metadata'
    elif args[:1] == ['minikube'] and 'kubectl' in args:
        tail = args[args.index('kubectl') + 1:]
        operation = next((arg for arg in tail if 'kubectl.' + arg in CONTROL_COMMANDS), None)
        if operation is not None:
            kind = 'kubectl.' + operation
    code = None if result is None else result.returncode
    return {'command': kind, 'outcome': outcome,
        'exit_code': code if type(code) is int and -255 <= code <= 255 else None,
        'stdout_bytes': None if result is None else min(len(result.stdout), MAX_METADATA + 1),
        'stderr_bytes': None if result is None else min(len(result.stderr), MAX_METADATA + 1)}


def closed_failure(error):
    code = ('fixture_command_timeout' if isinstance(error, subprocess.TimeoutExpired)
            else str(error) if isinstance(error, FixtureError) else 'unknown')
    if code not in SETUP_CODES:
        code = 'unknown'
    command = getattr(error, 'command_outcome', None)
    try:
        validate_command_outcome(command)
    except Exception:
        command = None
    return {'code': code, 'command_outcome': command}


def validate_command_outcome(value):
    need(value is None or type(value) is dict and set(value) == {
        'command', 'outcome', 'exit_code', 'stdout_bytes', 'stderr_bytes'}, 'fixture_receipt_command')
    if value is None:
        return
    need(type(value['command']) is str and value['command'] in CONTROL_COMMANDS
         and value['outcome'] in ('nonzero', 'timeout', 'output_bound'),
         'fixture_receipt_command')


    need(value['exit_code'] is None or type(value['exit_code']) is int and -255 <= value['exit_code'] <= 255,
         'fixture_receipt_command')
    for name in ('stdout_bytes', 'stderr_bytes'):
        need(value[name] is None or type(value[name]) is int and 0 <= value[name] <= MAX_METADATA + 1,
             'fixture_receipt_command')


def validate_closed_failure(value):
    need(type(value) is dict and set(value) == {'code', 'command_outcome'}
         and type(value['code']) is str and value['code'] in SETUP_CODES, 'fixture_receipt_setup_failure')
    validate_command_outcome(value['command_outcome'])


def docker_config_digests(image, timeout=32):
    """Read bounded save metadata in a stream; never extract or retain layers."""
    need(not os.environ.get('DOCKER_CONTEXT'), 'fixture_docker_context_refused')
    need(type(timeout) in (int, float) and 0 < timeout <= 32, 'candidate_export_deadline')
    process = subprocess.Popen(['docker', 'image', 'save', '--', image], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    stopped = threading.Event()
    stderr_overflow = threading.Event()
    def kill():
        stopped.set()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    def discard_stderr():
        total = 0
        while True:
            data = process.stderr.read(1024)
            if not data:
                return
            total += len(data)
            if total > 4096:
                stderr_overflow.set()
                kill()
                return
    timer = threading.Timer(timeout, kill)
    timer.daemon = True
    drain = threading.Thread(target=discard_stderr, daemon=True)
    deadline = time.monotonic() + timeout
    timer.start()
    drain.start()
    metadata = {}
    metadata_bytes = 0
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            for count, member in enumerate(archive, 1):
                need(count <= 4096 and time.monotonic() < deadline, 'candidate_export_member_bound')
                name = member.name.removeprefix('./')
                if not member.isfile() or not (name == 'manifest.json' or re.fullmatch(r'(?:blobs/sha256/)?[0-9a-f]{64}(?:\.json)?', name)):
                    continue
                if member.size > MAX_IMAGE_METADATA:
                    continue
                stream = archive.extractfile(member)
                need(stream is not None, 'candidate_export_metadata_unavailable')
                with stream:
                    prefix = stream.read(min(64, member.size))
                    # A tar/gzip layer is skipped even if small. Only JSON
                    # descriptors/config metadata enter the bounded in-memory map.
                    if prefix.lstrip()[:1] not in (b'{', b'['):
                        continue
                    need(metadata_bytes + member.size <= MAX_IMAGE_METADATA, 'candidate_export_metadata_bound')
                    payload = prefix + stream.read(member.size - len(prefix))
                need(len(payload) == member.size and name not in metadata, 'candidate_export_metadata_invalid')
                metadata[name] = payload
                metadata_bytes += len(payload)
        remaining = deadline - time.monotonic()
        need(remaining > 0, 'candidate_export_deadline')
        need(process.wait(timeout=remaining) == 0 and not stopped.is_set()
             and not stderr_overflow.is_set(), 'candidate_export_failed')
        manifest = json.loads(metadata.get('manifest.json', b'null'))
        need(type(manifest) is list and 1 <= len(manifest) <= 16, 'candidate_export_manifest_invalid')
        configs = set()
        for entry in manifest:
            need(type(entry) is dict and type(entry.get('Config')) is str, 'candidate_export_manifest_invalid')
            path = entry['Config']
            match = re.fullmatch(r'(?:blobs/sha256/)?([0-9a-f]{64})(?:\.json)?', path)
            need(match is not None and path in metadata, 'candidate_export_config_missing')
            payload = metadata[path]
            need(hashlib.sha256(payload).hexdigest() == match[1], 'candidate_export_config_digest_mismatch')
            config = json.loads(payload)
            need(type(config) is dict and type(config.get('rootfs')) is dict, 'candidate_export_config_invalid')
            configs.add('sha256:' + match[1])
        return sorted(configs)
    except (OSError, ValueError, tarfile.TarError, subprocess.TimeoutExpired):
        raise FixtureError('candidate_export_metadata_unavailable') from None
    finally:
        timer.cancel()
        if process.poll() is None:
            kill()
        try:
            process.wait(timeout=.5)
        except subprocess.TimeoutExpired:
            pass
        process.stdout.close()
        drain.join(timeout=.5)
        process.stderr.close()


def expected_image_identity(image):
    raw = command(['docker', 'image', 'inspect', '--format', '{{.Id}}\n{{json .RepoDigests}}', '--', image], maximum=16384).stdout
    lines = raw.decode('ascii').splitlines()
    need(len(lines) == 2 and re.fullmatch(IMAGE_DIGEST, lines[0]), 'candidate_config_identity_invalid')
    repositories = json.loads(lines[1])
    need(type(repositories) is list and len(repositories) <= 32, 'candidate_manifest_identity_bound')
    manifests = set()
    for reference in repositories:
        need(type(reference) is str and len(reference) <= 512 and '@' in reference, 'candidate_manifest_identity_invalid')
        digest = reference.rsplit('@', 1)[1]
        need(re.fullmatch(IMAGE_DIGEST, digest), 'candidate_manifest_identity_invalid')
        manifests.add(digest)
    # Docker's image-store implementation may expose a config, manifest or OCI
    # index as .Id. Keep its meaning generic; never label it a config digest.
    # Export the inspected immutable object, avoiding a concurrent tag change
    # between metadata admission and the streaming config lookup.
    configs = docker_config_digests(lines[0])
    return {'artifact': lines[0], 'configs': configs, 'known_digests': sorted(manifests | {lines[0]} | set(configs))}


def image_reference_kind(image):
    need(type(image) is str and re.fullmatch(r'[A-Za-z0-9._:/@+\-]{1,256}', image), 'fixture_image_reference')
    if '@' in image:
        need(re.fullmatch(r'[A-Za-z0-9._:/+\-]+@' + IMAGE_DIGEST, image), 'fixture_image_reference')
        return 'digest'
    need(not image.startswith('sha256:') and re.fullmatch(r'[A-Za-z0-9._:/+\-]+:[A-Za-z0-9_.\-]+', image),
         'fixture_image_reference')
    return 'local-tag'


def verify_private_storage(state, directories):
    script = ('import os,pathlib,stat,sys\n'
              'root=pathlib.Path(sys.argv[1]);uid=int(sys.argv[2])\n'
              'for name in sys.argv[3:]:\n'
              ' path=pathlib.Path(name);assert root in path.parents and path==path.resolve(strict=True)\n'
              ' for item in [root,*reversed(list(path.parents)[:list(path.parents).index(root)]),path]:\n'
              '  info=item.lstat();assert stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)\n'
              '  assert info.st_uid in (0,uid) and not info.st_mode & 0o022\n')
    command(['sudo', '-n', 'python3', '-I', '-B', '-c', script, str(state), str(os.getuid()), *directories])


def image_cache_boundary(cluster, identity):
    """The node cache is the task's disposable named /var volume, never a host bind."""
    need(node_docker_identity(cluster) == identity, 'fixture_node_identity_changed')
    state = Path(os.environ['DOCKER_HOST'].removeprefix('unix://')).parent
    need(json.loads(command(['docker', 'info', '--format', '{{json .DockerRootDir}}']).stdout) == str(state / 'data'),
         'fixture_image_storage')
    inspected = json.loads(command(['docker', 'inspect', '--', identity['container_id']]).stdout)
    need(type(inspected) is list and len(inspected) == 1 and inspected[0]['Id'] == identity['container_id']
         and inspected[0]['State']['Pid'] == identity['container_pid'], 'fixture_node_identity_changed')
    mounts = inspected[0].get('Mounts', [])
    selected = [mount for mount in mounts if mount.get('Destination') == '/var']
    storage = state / 'data/volumes' / cluster.profile / '_data'
    need(len(selected) == 1 and selected[0].get('Type') == 'volume' and selected[0].get('Name') == cluster.profile
         and selected[0].get('Driver') == 'local' and selected[0].get('Source') == str(storage) and selected[0].get('RW') is True
         and not inspected[0].get('HostConfig', {}).get('VolumesFrom'),
         'fixture_image_storage')
    need(all(mount is selected[0] or not (str(mount.get('Destination', '')).startswith('/var/')
         or mount.get('Destination') == '/') for mount in mounts), 'fixture_image_storage')
    verify_private_storage(state, [str(storage)])
    host_cover, _rows, _shared = mount_projection(Path('/proc/self/mountinfo').read_bytes(), str(storage))
    expected_root = str(Path(host_cover['root']) / storage.relative_to(host_cover['target']))
    cover, related, _shared = mount_projection(node_exec(identity, 'cat', '/proc/self/mountinfo').stdout, '/var/lib/containerd')
    need(cover['target'] == '/var' and cover['device'] == host_cover['device'] and cover['root'] == expected_root
         and cover['filesystem'] == host_cover['filesystem'] and len(related) == 1,
         'fixture_image_storage')
    return hashlib.sha256(json.dumps({'volume': selected[0], 'mount': cover}, sort_keys=True).encode()).hexdigest()


def node_image_content(identity, digest):
    need(type(digest) is str and re.fullmatch(IMAGE_DIGEST, digest), 'fixture_image_graph')
    raw = node_exec(identity, 'ctr', '-n', 'k8s.io', 'content', 'get', digest).stdout
    need('sha256:' + hashlib.sha256(raw).hexdigest() == digest, 'fixture_image_graph')
    value = json.loads(raw)
    need(type(value) is dict, 'fixture_image_graph')
    return value


def validate_image_preparation(name, value):
    need(set(value) == {'version', 'synthetic', 'state', 'source_sha256', 'image', 'mode', 'identity',
         'storage_sha256', 'host_mounts_sha256', 'expected', 'graph'}, 'fixture_receipt_image_preparation')
    complete = name == 'npm-assessment-image-preparation.json'
    need(value['state'] == ('complete' if complete else 'prepared') and value['mode'] == image_reference_kind(value['image'])
         and all(type(value[key]) is str and re.fullmatch('[a-f0-9]{64}', value[key])
                 for key in ('source_sha256', 'storage_sha256', 'host_mounts_sha256')), 'fixture_receipt_image_preparation')
    identity = value['identity']
    need(type(identity) is dict and set(identity) == {'container_id', 'container_pid', 'profile', 'node_uid', 'node_mount_namespace'}
         and type(identity['container_id']) is str and re.fullmatch('[a-f0-9]{64}', identity['container_id'])
         and type(identity['container_pid']) is int and 1 < identity['container_pid'] < 2**31
         and type(identity['node_uid']) is str and re.fullmatch(UUID_PATTERN, identity['node_uid'])
         and type(identity['profile']) is str and re.fullmatch('devres-acceptance-[a-z0-9-]+', identity['profile'])
         and type(identity['node_mount_namespace']) is str and re.fullmatch(r'mnt:\[[0-9]{1,20}\]', identity['node_mount_namespace']),
         'fixture_receipt_image_preparation')
    expected = value['expected']
    need(type(expected) is dict and set(expected) == {'artifact', 'configs', 'known_digests'}
         and type(expected['known_digests']) is list and 1 <= len(expected['known_digests']) <= 49
         and all(type(item) is str and re.fullmatch(IMAGE_DIGEST, item) for item in expected['known_digests'])
         and expected['artifact'] in expected['known_digests'] and type(expected['configs']) is list
         and 1 <= len(expected['configs']) <= 16 and all(item in expected['known_digests'] for item in expected['configs']),
         'fixture_receipt_image_preparation')
    graph = value['graph']
    if complete:
        need(type(graph) is dict and set(graph) == {'root_digest', 'native_manifest', 'config', 'architecture', 'os'}
             and graph['architecture'] in ('amd64', 'arm64') and graph['os'] == 'linux'
             and graph['config'] in expected['configs'], 'fixture_receipt_image_preparation')
        if value['mode'] == 'digest':
            need(graph['root_digest'] == value['image'].rsplit('@', 1)[1]
                 and graph['root_digest'] in expected['known_digests']
                 and type(graph['native_manifest']) is str and re.fullmatch(IMAGE_DIGEST, graph['native_manifest']),
                 'fixture_receipt_image_preparation')
        else:
            need(graph['root_digest'] is None and graph['native_manifest'] is None, 'fixture_receipt_image_preparation')
    else:
        need(graph is None, 'fixture_receipt_image_preparation')


def admitted_image(identity, image, expected, architecture, kind):
    value = json.loads(node_exec(identity, 'crictl', 'inspecti', image).stdout)
    config = value.get('status', {}).get('id')
    need(config in expected['configs'], 'fixture_image_identity')
    graph = {'root_digest': None, 'native_manifest': None, 'config': config, 'architecture': architecture, 'os': 'linux'}
    if kind == 'digest':
        root = image.rsplit('@', 1)[1]
        need(root in expected['known_digests'] and image in value.get('status', {}).get('repoDigests', []),
             'fixture_image_identity')
        rows = node_exec(identity, 'ctr', '-n', 'k8s.io', 'images', 'ls').stdout.decode('ascii').splitlines()[1:]
        matches = [row.split()[2] for row in rows if len(row.split()) >= 3 and row.split()[0] == image]
        need(matches == [root], 'fixture_image_identity')
        descriptor = node_image_content(identity, root)
        native = root
        if 'manifests' in descriptor:
            manifests = descriptor['manifests']
            need(type(manifests) is list and len(manifests) <= 64, 'fixture_image_graph')
            selected = [item for item in manifests if type(item) is dict
                and item.get('platform', {}).get('architecture') == architecture
                and item.get('platform', {}).get('os') == 'linux']
            need(len(selected) == 1, 'fixture_image_architecture')
            native = selected[0].get('digest')
            descriptor = node_image_content(identity, native)
        need(descriptor.get('config', {}).get('digest') == config, 'fixture_image_graph')
        graph.update(root_digest=root, native_manifest=native)
    cfg = node_image_content(identity, config)
    need(cfg.get('architecture') == architecture and cfg.get('os') == 'linux', 'fixture_image_architecture')
    return graph


def prepare_image(arguments):
    scratch = Path(arguments.scratch).resolve(strict=True)
    need(Path('/tmp') in scratch.parents and scratch.stat().st_uid == os.getuid(), 'owned_tmp_fixture_required')
    need(not os.environ.get('DOCKER_CONTEXT'), 'fixture_docker_context_refused')
    cluster = Cluster(arguments.profile, scratch)
    try:
        prepare_image_fixture(arguments, cluster)
    except BaseException as error:
        receipt(cluster, 'npm-assessment-image-preparation-failure.json', {'version': 1, 'synthetic': True,
            'phase': getattr(cluster, 'image_preparation_phase', 'admission'), 'failure': closed_failure(error)})
        raise


def prepare_image_fixture(arguments, cluster):
    kind = image_reference_kind(arguments.server_image)
    identity = node_docker_identity(cluster)
    uid, namespace = node_uid(cluster), node_namespace(identity)
    host_namespace, host_hash, _shared = host_mount_state()
    need(namespace != host_namespace, 'fixture_host_mount_namespace_refused')
    architecture = {b'x86_64': 'amd64', b'aarch64': 'arm64'}.get(node_exec(identity, 'uname', '-m').stdout.strip())
    need(architecture is not None, 'fixture_image_architecture')
    source = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    expected = expected_image_identity(arguments.server_image)
    if kind == 'digest':
        need(arguments.server_image.rsplit('@', 1)[1] in expected['known_digests'], 'fixture_image_identity')
    storage = image_cache_boundary(cluster, identity)
    bound = {**identity, 'profile': cluster.profile, 'node_uid': uid, 'node_mount_namespace': namespace}
    record = {'version': 1, 'synthetic': True, 'state': 'prepared', 'source_sha256': source,
              'image': arguments.server_image, 'mode': kind, 'identity': bound, 'storage_sha256': storage,
              'host_mounts_sha256': host_hash, 'expected': expected, 'graph': None}
    need(receipt(cluster, 'npm-assessment-image-preparation-intent.json', record), 'fixture_evidence_retention_incomplete')
    need(node_docker_identity(cluster) == identity and node_uid(cluster) == uid and node_namespace(identity) == namespace
         and image_cache_boundary(cluster, identity) == storage, 'fixture_node_identity_changed')
    # Exactly one primary setup operation. A failure has no retry, alias or fallback.
    cluster.image_preparation_phase = 'operation'
    if kind == 'digest':
        node_exec(identity, 'crictl', 'pull', arguments.server_image, timeout=240)
    else:
        command(['minikube', '-p', cluster.profile, 'image', 'load', arguments.server_image], timeout=240)
    cluster.image_preparation_phase = 'identity'
    graph = admitted_image(identity, arguments.server_image, expected, architecture, kind)
    need(node_docker_identity(cluster) == identity and node_uid(cluster) == uid and node_namespace(identity) == namespace
         and image_cache_boundary(cluster, identity) == storage and host_mount_state()[:2] == (host_namespace, host_hash)
         and hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == source, 'fixture_node_identity_changed')
    need(receipt(cluster, 'npm-assessment-image-preparation.json', {**record, 'state': 'complete', 'graph': graph}),
         'fixture_evidence_retention_incomplete')


def resolved_image_identity(cluster, image_id, expected):
    """Match immutable Docker and CRI digests; tag equality is insufficient."""
    need(type(image_id) is str and len(image_id) <= 512, 'assessment_resolved_image_required')
    reference = image_id
    for prefix in ('docker-pullable://', 'docker://', 'containerd://'):
        reference = reference.removeprefix(prefix)
    match = re.search(r'(' + IMAGE_DIGEST + r')$', reference)
    need(match is not None, 'assessment_runtime_digest_invalid')
    runtime_digest = match[1]
    raw = command(['docker', 'exec', cluster.profile, 'crictl', 'inspecti', reference]).stdout
    inspected = json.loads(raw)
    runtime_id = inspected.get('status', {}).get('id')
    need(type(runtime_id) is str and re.fullmatch(IMAGE_DIGEST, runtime_id), 'assessment_cri_identity_invalid')
    repositories = inspected.get('status', {}).get('repoDigests', [])
    need(type(repositories) is list and len(repositories) <= 32, 'assessment_cri_manifest_bound')
    digests = {runtime_id}
    for repository in repositories:
        need(type(repository) is str and len(repository) <= 512 and '@' in repository, 'assessment_cri_manifest_invalid')
        digest = repository.rsplit('@', 1)[1]
        need(re.fullmatch(IMAGE_DIGEST, digest), 'assessment_cri_manifest_invalid')
        digests.add(digest)
    matching = sorted(set(expected['known_digests']) & digests)
    need(matching, 'assessment_candidate_image_mismatch')
    return {'expected_artifact': expected['artifact'], 'matched_artifact': matching[0],
            'runtime_reference_digest': runtime_digest, 'resolved_cri_id': runtime_id,
            'known_digests': expected['known_digests'], 'expected_configs': expected['configs'],
            'resolved_config': runtime_id if runtime_id in expected['configs'] else None}


def helper():
    name = 'devres_npm_assessment_helper'
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy/diagnostics/npm_assessment.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def private_json(path, value):
    payload = json.dumps(value, sort_keys=True).encode() + b'\n'
    need(len(payload) <= MAX_METADATA, 'fixture_receipt_bound')
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


CASES = frozenset(('success', 'malformed-config', 'wrong-dns', 'bad-password', 'existing-output',
    'output-symlink', 'output-wrong-mode', 'output-wrong-owner', 'ready-denied', 'wrong-schema',
    'restore-pending', 'corrupt-history', 'missing-grant', 'held-lifecycle', 'telemetry-unavailable',
    'required-tls', *READINESS_CASES))


def validate_readiness_result(record):
    denied = record['case'] == 'readiness-denied'
    code = 'assessment_readiness_result'
    if denied:
        need(record['phase'] == 'terminal' and record['exit_code'] == 1, code)
        events = record['diagnostics']
    else:
        need(record['case'] == 'cold-readiness' and record['phase'] == 'report_transferred', code)
        events = record['events']
    need(type(events) is list, code)
    interesting = {'cli_start', 'cli_exit', 'sql_connect', 'sql_connect_retry', 'sql_setup'}
    sequence = [(event['phase'], event['outcome'], event['reason'], event['child_exit'])
                for event in events if event['phase'] in interesting]
    expected = [('cli_start', 'start', 'none', None), ('sql_connect', 'start', 'none', None)]
    retries = [row for row in sequence if row[0] == 'sql_connect_retry']
    need((not denied or retries) and len(retries) <= 1
         and all(row[1] == 'error' and row[2] in ('connection', 'timeout') and row[3] is None
                 for row in retries), code)
    expected.extend(retries)
    if denied:
        expected.extend((('sql_connect', 'error', 'timeout', None), ('cli_exit', 'error', 'unknown', 1)))
    else:
        expected.extend((('sql_connect', 'ok', 'none', None), ('sql_setup', 'start', 'none', None),
                         ('sql_setup', 'ok', 'none', None), ('cli_exit', 'ok', 'none', 0)))
    need(sequence == expected, code)
    if denied:
        started, stopped = [event['elapsed_ms'] for event in events if event['phase'] == 'sql_connect']
        need(type(started) is int and type(stopped) is int and 29_000 <= stopped - started <= 45_000, code)


def validate_receipt(name, value):
    """Closed metadata schemas; raw error text, paths, source and logs have no field."""
    api = helper()
    def phases(events):
        need(events is None or isinstance(events, list) and len(events) <= api.MAX_PHASE_EVENTS, 'fixture_receipt_phases')
        for event in events or []:
            need(type(event) is dict and set(event) == {'ordinal', 'phase', 'outcome', 'reason', 'elapsed_ms', 'child_exit'}
                 and type(event['ordinal']) is int and 0 <= event['ordinal'] < api.MAX_PHASE_EVENTS
                 and event['phase'] in api.PHASES and event['outcome'] in ('start', 'ok', 'error')
                 and event['reason'] in api.REASONS, 'fixture_receipt_phases')
            need(event['elapsed_ms'] is None or type(event['elapsed_ms']) is int and 0 <= event['elapsed_ms'] < 2**63, 'fixture_receipt_phases')
            need(event['child_exit'] is None or type(event['child_exit']) is int and 0 <= event['child_exit'] <= 255, 'fixture_receipt_phases')
    def result(record):
        need(type(record) is dict and record.get('case') in CASES, 'fixture_receipt_case')
        if record.get('phase') == 'terminal':
            need(set(record) == {'case', 'phase', 'exit_code', 'diagnostics', 'image_identity'} and type(record['exit_code']) is int
                 and 0 <= record['exit_code'] <= 255, 'fixture_receipt_terminal')
            phases(record['diagnostics'])
        else:
            need(set(record) == {'case', 'phase', 'report', 'events', 'runtime', 'image_identity'}
                 and record['phase'] == 'report_transferred', 'fixture_receipt_result')
            report = record['report']
            api.validate_report(report, api.Selection(report.get('job_id'), report.get('revision')))
            phases(record['events'])
            validate_runtime(('\n'.join(key + '=' + item for key, item in record['runtime'].items()) + '\n').encode('ascii'))
        identity = record['image_identity']
        need(type(identity) is dict and set(identity) == {'expected_artifact', 'matched_artifact', 'runtime_reference_digest', 'resolved_cri_id', 'known_digests', 'expected_configs', 'resolved_config'}
             and all(type(identity[field]) is str and re.fullmatch(IMAGE_DIGEST, identity[field])
                     for field in ('expected_artifact', 'matched_artifact', 'runtime_reference_digest', 'resolved_cri_id')),
             'fixture_receipt_image')
        need(type(identity['known_digests']) is list and 1 <= len(identity['known_digests']) <= 49
             and all(type(digest) is str and re.fullmatch(IMAGE_DIGEST, digest) for digest in identity['known_digests'])
             and identity['expected_artifact'] in identity['known_digests']
             and identity['matched_artifact'] in identity['known_digests'], 'fixture_receipt_image')
        need(type(identity['expected_configs']) is list and 1 <= len(identity['expected_configs']) <= 16
             and all(digest in identity['known_digests'] for digest in identity['expected_configs'])
             and (identity['resolved_config'] is None or identity['resolved_config'] in identity['expected_configs']), 'fixture_receipt_image')
    need(type(value) is dict and value.get('version') == 1 and type(value.get('version')) is int
         and value.get('synthetic') is True, 'fixture_receipt_identity')
    if name in ('npm-assessment-node-preparation-intent.json', 'npm-assessment-node-preparation.json'):
        validate_node_preparation(name, value)
    elif name in ('npm-assessment-node-restoration-intent.json', 'npm-assessment-node-restoration.json'):
        validate_node_restoration(name, value)
    elif name == 'npm-assessment-node-restoration-failure.json':
        need(set(value) == {'version', 'synthetic', 'phase', 'failure'}
             and value['phase'] in ('admission', 'parser-remove', 'securityfs-restore', 'runtime-reset', 'verify'),
             'fixture_receipt_node_restoration')
        validate_closed_failure(value['failure'])
    elif name in ('npm-assessment-image-preparation-intent.json', 'npm-assessment-image-preparation.json'):
        validate_image_preparation(name, value)
    elif name == 'npm-assessment-image-preparation-failure.json':
        need(set(value) == {'version', 'synthetic', 'phase', 'failure'} and value['phase'] in ('admission', 'operation', 'identity'),
             'fixture_receipt_image_preparation')
        validate_closed_failure(value['failure'])
    elif name == 'npm-assessment-receipt.json':
        fields = {'version', 'synthetic', 'apparmor_sha256', 'server_image', 'provider_requests', 'selection',
                  'network', 'result', 'faults', 'metadata_unchanged'}
        need(set(value) in (fields, fields | {'readiness'}), 'fixture_receipt_fields')
        need(value['apparmor_sha256'] == APPARMOR_SHA256 and value['provider_requests'] == 0
             and value['metadata_unchanged'] is True and type(value['server_image']) is str
             and re.fullmatch(r'[A-Za-z0-9._:/@+\-]{1,256}', value['server_image']), 'fixture_receipt_assessment')
        selected = value['selection']
        need(type(selected) is dict and set(selected) == {'version', 'schema', 'job_id', 'revision', 'cause_authoritative', 'synthetic'}
             and selected['version'] == 1 and selected['schema'] == 19 and selected['revision'] == 1
             and selected['cause_authoritative'] is False and selected['synthetic'] is True, 'fixture_receipt_selection')
        api.Selection(selected['job_id'], selected['revision']).validate()
        need(value['network'] == {'dns': True, 'postgres_tcp': True, 'local_api_denied': True, 'public_requests': 0,
             'apparmor_enforcing': True, 'canonical_alias_read_denied': True}, 'fixture_receipt_network')
        result(value['result'])
        expect_faults = 15 if 'readiness' in value else 14
        need(type(value['faults']) is list and len(value['faults']) == expect_faults, 'fixture_receipt_faults')
        for record in value['faults']:
            result(record)
        if 'readiness' in value:
            readiness = value['readiness']
            need(type(readiness) is list and len(readiness) == len(READINESS_CASES), 'fixture_receipt_readiness')
            for expected_case, record in zip(READINESS_CASES, readiness):
                result(record)
                need(record['case'] == expected_case, 'fixture_receipt_readiness')
                validate_readiness_result(record)
    elif name == 'npm-assessment-setup-failure.json':
        fields = {'version', 'synthetic', 'phase', 'case', 'failure', 'cleanup_failure',
                  'namespace_cleanup', 'apparmor_cleanup'}
        need(set(value) in (fields, fields | {'probe'}), 'fixture_receipt_fields')
        need(value['phase'] in SETUP_PHASES and value['case'] in CASES | {'none'}
             and value['namespace_cleanup'] in ('not-created', 'removed', 'incomplete')
             and value['apparmor_cleanup'] in ('removed', 'unknown'), 'fixture_receipt_setup_failure')
        for record in (value['failure'], value['cleanup_failure']):
            if record is None:
                continue
            need(type(record) is dict and set(record) == {'code', 'command_outcome'}
                 and type(record['code']) is str and record['code'] in SETUP_CODES, 'fixture_receipt_setup_failure')
            validate_command_outcome(record['command_outcome'])
        need(value['failure'] is not None, 'fixture_receipt_setup_failure')
        if 'probe' in value:
            validate_probe_failure(value['probe'])
    elif name == 'paused-status-failure.json':
        need(set(value) == {'version', 'synthetic', 'phase', 'case', 'code', 'command_outcome',
            'exit_code', 'stages'}, 'fixture_receipt_fields')
        need(value['phase'] in OBSERVER_PHASES and value['case'] in ('none', 'sql-permission', 's3-unavailable')
             and value['code'] in OBSERVER_ERRORS and value['command_outcome'] in ('none', 'nonzero', 'timeout'),
             'fixture_receipt_observer_failure')
        need(value['exit_code'] is None or type(value['exit_code']) is int and 0 <= value['exit_code'] <= 255,
             'fixture_receipt_observer_exit')
        need(type(value['stages']) is list and len(value['stages']) <= 8, 'fixture_receipt_status_stages')
        seen = set()
        for stage in value['stages']:
            need(type(stage) is dict and set(stage) == {'stage', 'reason', 'calls', 'failed', 'cancelled'}
                 and stage['stage'] in OBSERVER_STAGES and stage['stage'] not in seen
                 and stage['reason'] in OBSERVER_REASONS
                 and all(type(stage[field]) is int and 0 <= stage[field] <= 1000000
                         for field in ('calls', 'failed', 'cancelled')), 'fixture_receipt_status_stages')
            seen.add(stage['stage'])
    elif name == 'paused-status-restoration.json':
        need(set(value) == {'version', 'synthetic', 'steps'} and type(value['steps']) is list
             and 1 <= len(value['steps']) <= 32, 'fixture_receipt_fields')
        for step in value['steps']:
            need(type(step) is dict and set(step) == {'step', 'restored'}
                 and step['step'] in OBSERVER_RESTORATIONS and type(step['restored']) is bool,
                 'fixture_receipt_observer_restoration')
    elif name == 'paused-status-receipt.json':
        need(set(value) == {'version', 'synthetic', 'public_status', 'provider_requests', 'startup_and_calls_metadata_unchanged',
            'publication_owner_absent', 'authenticated_acquisition_denied', 's3_readonly_identity', 'earlier_storage_faults'}, 'fixture_receipt_fields')
        need(value['provider_requests'] == 0 and all(value[field] is True for field in
            ('startup_and_calls_metadata_unchanged', 'publication_owner_absent', 'authenticated_acquisition_denied'))
            and type(value['s3_readonly_identity']) is bool, 'fixture_receipt_observer')
        need(type(value['public_status']) is list and len(value['public_status']) == 2, 'fixture_receipt_public_status')
        for status in value['public_status']:
            need(type(status) is dict and set(status) == {'revision', 'observation_state', 'scan_gap_count'}
                 and status['revision'] in ('2026-07-28', '2025-11-25')
                 and status['observation_state'] in ('pending', 'running', 'complete', 'gap', 'cancelled', 'invalidated')
                 and type(status['scan_gap_count']) is int and 0 <= status['scan_gap_count'] <= 9, 'fixture_receipt_public_status')
        need(type(value['earlier_storage_faults']) is list and 1 <= len(value['earlier_storage_faults']) <= 2, 'fixture_receipt_storage_faults')
        for fault in value['earlier_storage_faults']:
            need(type(fault) is dict and set(fault) == {'case', 'result', 'stages', 'attribution_entered'}
                 and fault['case'] in ('sql-permission', 's3-unavailable') and fault['attribution_entered'] is False
                 and fault['result'] == {'http': 200, 'structured_error': 'unavailable'}, 'fixture_receipt_storage_fault')
            need(type(fault['stages']) is list and 1 <= len(fault['stages']) <= 8, 'fixture_receipt_status_stages')
            for stage in fault['stages']:
                need(type(stage) is dict and set(stage) == {'stage', 'reason', 'calls', 'failed', 'cancelled'}
                     and stage['stage'] in ('saved_state', 'statistics', 'kind_inventory', 'evidence_page', 'defaults')
                     and stage['reason'] in ('none', 'ok', 'unavailable', 'integrity', 'capacity', 'invalid', 'unknown', 'cancelled')
                     and all(type(stage[field]) is int and 0 <= stage[field] <= 1000000 for field in ('calls', 'failed', 'cancelled')), 'fixture_receipt_status_stages')
    elif name.startswith('case-assessment-') and name.endswith('-result.json'):
        need(set(value) == {'version', 'synthetic', 'result'}, 'fixture_receipt_fields')
        result(value['result'])
    else:
        raise FixtureError('fixture_receipt_name')


def receipt(cluster, name, value):
    """Retain constructed metadata directly; never copy arbitrary scratch files."""
    try:
        validate_receipt(name, value)
        private_json(cluster.scratch / name, value)
        destination = os.environ.get('DEVRES_E2E_DIAGNOSTICS_DIR')
        if destination:
            root = Path(destination).resolve()
            need(Path('/tmp') in root.parents, 'fixture_evidence_requires_tmp')
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            need(root.stat().st_uid == os.getuid(), 'fixture_evidence_owner')
            directory = root / cluster.profile
            need(not directory.is_symlink(), 'fixture_evidence_symlink')
            directory.mkdir(exist_ok=True, mode=0o700)
            need(directory.stat().st_uid == os.getuid(), 'fixture_evidence_owner')
            private_json(directory / name, value)
        return True
    except Exception:
        failures = getattr(cluster, 'receipt_failures', [])
        failures.append('fixture_receipt_retention_incomplete')
        cluster.receipt_failures = failures[:32]
        print('fixture receipt retention incomplete; original assessment result preserved', file=sys.stderr)
        return False


def configuration(original, database=DATABASE_READER):
    """Preserve validation shape; unused TLS/cache/token paths stay unmounted."""
    text, count = re.subn(r'(?m)^database_url\s*=.*$', 'database_url = ' + json.dumps(database), original)
    need(count == 1, 'one_fixture_database_required')
    for provider in ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'wikipedia', 'npm'):
        header = re.compile(r'(?ms)(^\[' + provider + r'\]\s*\n)(.*?)(?=^\[|\Z)')
        def paused(match):
            body = re.sub(r'(?m)^enabled\s*=.*\n?', '', match[2])
            if provider == 'npm':
                body = re.sub(r'(?m)^advisories_enabled\s*=.*\n?', '', body)
                body = 'advisories_enabled = false\n' + body
            return match[1] + 'enabled = false\n' + body
        text, count = header.subn(paused, text)
        if count == 0:
            text += '\n[' + provider + ']\nenabled = false\n'
            if provider == 'npm':
                text += 'advisories_enabled = false\n'
        need(count <= 1, 'one_fixture_provider_table_required')
    return text


def template(image):
    return {'spec': {
        'serviceAccountName': 'assessment', 'automountServiceAccountToken': False,
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532,
                            'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}},
        'containers': [{'name': 'backend', 'image': image, 'imagePullPolicy': 'Never',
            'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'},
                          'limits': {'cpu': '1', 'memory': '512Mi'}},
            'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                'capabilities': {'drop': ['ALL']},
                'appArmorProfile': {'type': 'Localhost', 'localhostProfile': PROFILE}},
            'volumeMounts': [{'name': 'config', 'mountPath': '/etc/devres/config', 'readOnly': True},
                            {'name': 's3', 'mountPath': '/run/devres-s3', 'readOnly': True},
                            {'name': 'tmp', 'mountPath': '/tmp'}]}],
        'volumes': [{'name': 'config', 'secret': {'secretName': 'devres-assessment-config', 'defaultMode': 0o440}},
                    {'name': 's3', 'secret': {'secretName': 'devres-assessment-s3', 'defaultMode': 0o440}},
                    {'name': 'tmp', 'emptyDir': {'sizeLimit': '16Mi'}}]}}


def policies():
    dns = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
           'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}
    postgres = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'devres-acceptance'}},
                'podSelector': {'matchLabels': {'app': 'postgres'}}}
    return [
        {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
         'metadata': {'name': 'assessment-deny', 'namespace': NAMESPACE},
         'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']}},
        {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
         'metadata': {'name': 'assessment-dns-postgres-only', 'namespace': NAMESPACE},
         'spec': {'podSelector': {'matchLabels': {'app': 'backend'}}, 'policyTypes': ['Egress'],
                  'egress': [{'to': [dns], 'ports': [{'port': 53, 'protocol': 'UDP'}, {'port': 53, 'protocol': 'TCP'}]},
                             {'to': [postgres], 'ports': [{'port': 5432, 'protocol': 'TCP'}]}]}},
        {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
         'metadata': {'name': OWNED_POLICIES['policy'], 'namespace': 'devres-acceptance'},
         'spec': {'podSelector': {'matchLabels': {'app': 'postgres'}}, 'policyTypes': ['Ingress'],
                  'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': NAMESPACE}},
                                         'podSelector': {'matchLabels': {'app': 'backend'}}}],
                               'ports': [{'port': 5432, 'protocol': 'TCP'}]}]}}]


def readiness_policies():
    # Keep the same cross-namespace Service path as the synthetic baseline.
    # The denial case shares egress but has no matching PostgreSQL ingress.
    _default, outbound, inbound = policies()
    outbound['metadata']['name'] = 'assessment-readiness-dns-postgres-only'
    outbound['spec']['podSelector']['matchLabels'] = {'app': ASSESSMENT_APP}
    outbound['spec']['policyTypes'] = ['Ingress', 'Egress']
    inbound['metadata']['name'] = OWNED_POLICIES['readiness_policy']
    inbound['spec']['ingress'][0]['from'][0]['podSelector']['matchLabels'] = {
        'app': ASSESSMENT_APP, 'devres-assessment': 'cold-readiness'}
    return [outbound, inbound]


NODE_SECURITYFS = '/sys/kernel/security'


def mount_projection(raw, target=NODE_SECURITYFS):
    rows = []
    for line in raw.decode('utf-8').splitlines():
        fields = line.split()
        separator = fields.index('-')
        need(separator >= 6 and len(fields) >= separator + 4, 'fixture_node_mountinfo_invalid')
        rows.append({'id': fields[0], 'parent': fields[1], 'device': fields[2], 'root': fields[3],
            'target': fields[4], 'options': fields[5].split(','), 'propagation': fields[6:separator],
            'filesystem': fields[separator + 1], 'source': fields[separator + 2],
            'super_options': fields[separator + 3].split(',')})
    covering = [row for row in rows if target == row['target'] or target.startswith(row['target'].rstrip('/') + '/')]
    need(covering, 'fixture_node_mountinfo_missing')
    cover = max(covering, key=lambda row: len(row['target']))
    related = [row for row in rows if row is cover or row['target'].startswith(target + '/')]
    shared = {field for row in rows for field in row['propagation'] if field.startswith('shared:')}
    return cover, related, shared


def host_mount_state():
    namespace = os.readlink('/proc/self/ns/mnt')
    raw = Path('/proc/self/mountinfo').read_bytes()
    _cover, related, shared = mount_projection(raw)
    digest = hashlib.sha256(json.dumps(related, sort_keys=True).encode()).hexdigest()
    return namespace, digest, shared


def node_docker_identity(cluster):
    endpoint = os.environ.get('DOCKER_HOST', '')
    need(not os.environ.get('DOCKER_CONTEXT') and os.environ.get('DEVRES_TMP_STATE') == '1' and endpoint.startswith('unix:///tmp/'),
         'fixture_owned_docker_required')
    socket = Path(endpoint.removeprefix('unix://'))
    need(Path('/tmp') in socket.parents and socket.parent != Path('/tmp') and '..' not in socket.parts
         and not any(path.is_symlink() for path in (socket, *socket.parents))
         and stat.S_ISSOCK(socket.stat().st_mode) and socket.parent.stat().st_uid == os.getuid()
         and not socket.parent.stat().st_mode & 0o077, 'fixture_owned_docker_required')
    objects = json.loads(command(['docker', 'inspect', '--', cluster.profile]).stdout)
    need(type(objects) is list and len(objects) == 1, 'fixture_node_identity')
    value = objects[0]
    labels = value.get('Config', {}).get('Labels', {}) or {}
    state = value.get('State', {})
    need(value.get('Name') == '/' + cluster.profile
         and labels.get('created_by.minikube.sigs.k8s.io') == 'true'
         and labels.get('name.minikube.sigs.k8s.io') == cluster.profile
         and value.get('HostConfig', {}).get('Privileged') is True
         and value.get('HostConfig', {}).get('PidMode', '') != 'host'
         and value.get('HostConfig', {}).get('NetworkMode', '') != 'host'
         and state.get('Running') is True and type(state.get('Pid')) is int and state['Pid'] > 1
         and type(value.get('Id')) is str and re.fullmatch('[0-9a-f]{64}', value['Id']), 'fixture_node_identity')
    return {'container_id': value['Id'], 'container_pid': state['Pid']}


def node_exec(identity, *args, **kwargs):
    need(not os.environ.get('DOCKER_CONTEXT'), 'fixture_docker_context_refused')
    return command(['docker', 'exec', identity['container_id'], *args], **kwargs)


def node_namespace(identity):
    value = node_exec(identity, 'readlink', '/proc/self/ns/mnt').stdout.decode('ascii').strip()
    need(re.fullmatch(r'mnt:\[[0-9]{1,20}\]', value), 'fixture_node_mount_namespace')
    return value


def node_uid(cluster):
    value = json.loads(cluster.k('get', 'node', cluster.profile, '-o', 'json').stdout)
    labels = value.get('metadata', {}).get('labels', {})
    uid = value.get('metadata', {}).get('uid')
    need(value.get('metadata', {}).get('name') == cluster.profile
         and labels.get('kubernetes.io/hostname') == cluster.profile
         and labels.get('minikube.k8s.io/name') == cluster.profile
         and type(uid) is str and re.fullmatch(UUID_PATTERN, uid), 'fixture_node_identity')
    return uid


def postgres_process(cluster):
    rows = json.loads(cluster.k('get', 'pods', '-l', 'app=postgres', '-o', 'json', namespace='devres-acceptance').stdout)['items']
    need(len(rows) == 1, 'fixture_postgres_process')
    pod = rows[0]
    statuses = pod.get('status', {}).get('containerStatuses', [])
    uid = pod.get('metadata', {}).get('uid')
    need(len(statuses) == 1 and statuses[0].get('ready') is True
         and type(uid) is str and re.fullmatch(UUID_PATTERN, uid)
         and type(statuses[0].get('containerID')) is str
         and re.fullmatch('containerd://[0-9a-f]{64}', statuses[0]['containerID'])
         and type(statuses[0].get('restartCount')) is int and 0 <= statuses[0]['restartCount'] < 2**31,
         'fixture_postgres_process')
    return {'uid': uid, 'container_id': statuses[0]['containerID'],
            'restart_count': statuses[0]['restartCount']}


def kubelet_process(identity):
    value = node_exec(identity, 'systemctl', 'show', '--property=MainPID', '--value', 'kubelet').stdout.decode('ascii').strip()
    need(re.fullmatch('[0-9]{1,10}', value) and int(value) > 1, 'fixture_node_kubelet_process')
    return int(value)


def node_process(identity, pid, executable):
    need(type(pid) is int and 1 < pid < 2**31, 'fixture_node_runtime_process')
    path = '/proc/' + str(pid)
    name = node_exec(identity, 'readlink', path + '/exe').stdout.decode('ascii').strip()
    need(name in ('/usr/bin/' + executable, '/usr/local/bin/' + executable)
         or executable == 'kubelet' and re.fullmatch(r'/var/lib/minikube/binaries/v[0-9]+\.[0-9]+\.[0-9]+/kubelet', name),
         'fixture_node_runtime_process')
    raw = node_exec(identity, 'cat', path + '/stat').stdout.decode('ascii')
    head, tail = raw.rsplit(') ', 1)
    fields = tail.split()
    need(head.startswith(str(pid) + ' (') and len(fields) >= 20
         and re.fullmatch('[0-9]{1,20}', fields[19]), 'fixture_node_runtime_process')
    binary = node_exec(identity, 'sha256sum', path + '/exe').stdout.decode('ascii').split()[0]
    need(re.fullmatch('[0-9a-f]{64}', binary), 'fixture_node_runtime_process')
    return {'pid': pid, 'start_ticks': int(fields[19]), 'binary_sha256': binary}, int(fields[1])


def containerd_process(identity):
    mode = node_exec(identity, 'systemctl', 'show', '--property=KillMode', '--value', 'containerd').stdout.strip()
    need(mode == b'process', 'fixture_containerd_stop_mode')
    raw = node_exec(identity, 'systemctl', 'show', '--property=MainPID', '--value', 'containerd').stdout.decode('ascii').strip()
    need(re.fullmatch('[0-9]{1,10}', raw), 'fixture_node_runtime_process')
    process, _parent = node_process(identity, int(raw), 'containerd')
    return {**process, 'kill_mode': 'process'}


def postgres_runtime(identity, postgres):
    container = postgres['container_id'].removeprefix('containerd://')
    raw = json.loads(node_exec(identity, 'crictl', 'inspect', container).stdout)
    pid = raw.get('info', {}).get('pid')
    need(raw.get('status', {}).get('id') == container and type(pid) is int and 1 < pid < 2**31,
         'fixture_postgres_runtime_process')
    fields = node_exec(identity, 'cat', '/proc/' + str(pid) + '/stat').stdout.decode('ascii').rsplit(') ', 1)[1].split()
    need(len(fields) >= 20 and re.fullmatch('[0-9]{1,20}', fields[19]), 'fixture_postgres_runtime_process')
    shim, _parent = node_process(identity, int(fields[1]), 'containerd-shim-runc-v2')
    return {'pid': pid, 'start_ticks': int(fields[19]), 'shim': shim}


def parser_payload(package):
    """Read one pinned OS-tool member as data; never extract archive paths/scripts."""
    need(len(package) == PARSER_PACKAGE_SIZE and hashlib.sha256(package).hexdigest() == PARSER_PACKAGE_SHA256,
         'fixture_parser_package')
    need(package[:8] == b'!<arch>\n', 'fixture_parser_archive')
    offset, members = 8, []
    while offset < len(package):
        header = package[offset:offset + 60]
        need(len(header) == 60 and header[-2:] == b'`\n' and header[48:58].strip().isdigit(), 'fixture_parser_archive')
        size = int(header[48:58]); offset += 60
        need(size <= len(package) - offset and len(members) < 8, 'fixture_parser_archive')
        members.append((header[:16].strip().rstrip(b'/'), package[offset:offset + size]))
        offset += size + size % 2
    need(offset == len(package) and [name for name, _ in members] == [b'debian-binary', b'control.tar.xz', b'data.tar.xz']
         and members[0][1] == b'2.0\n', 'fixture_parser_archive')
    selected, total = [], 0
    try:
        with tarfile.open(fileobj=io.BytesIO(members[2][1]), mode='r|xz') as archive:
            for count, item in enumerate(archive, 1):
                total += item.size
                need(count <= 4096 and total <= 16 * 1024 * 1024, 'fixture_parser_archive')
                if item.name != './sbin/apparmor_parser':
                    continue
                need(item.isfile() and item.uid == 0 and item.gid == 0 and item.size == PARSER_SIZE
                     and item.mode == 0o755 and not selected, 'fixture_parser_member')
                stream = archive.extractfile(item)
                need(stream is not None, 'fixture_parser_member')
                with stream:
                    payload = stream.read(PARSER_SIZE + 1)
                need(len(payload) == PARSER_SIZE and hashlib.sha256(payload).hexdigest() == PARSER_SHA256,
                     'fixture_parser_member')
                selected.append(payload)
    except (tarfile.TarError, EOFError, ValueError):
        raise FixtureError('fixture_parser_archive') from None
    need(len(selected) == 1, 'fixture_parser_member')
    return selected[0]


def genuine_parser(scratch):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            raise FixtureError('fixture_parser_download')
    try:
        with urllib.request.build_opener(NoRedirect()).open(PARSER_URL, timeout=30) as response:
            need(response.geturl() == PARSER_URL, 'fixture_parser_download')
            package = response.read(PARSER_PACKAGE_SIZE + 1)
    except OSError:
        raise FixtureError('fixture_parser_download') from None
    payload = parser_payload(package)
    need(Path('/tmp') in scratch.resolve().parents, 'owned_tmp_fixture_required')
    descriptor = os.open(scratch / 'apparmor-native-package.deb', os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(package); output.flush(); os.fsync(output.fileno())
    return payload


def parser_admission(identity):
    # The pinned Debian-native ELF needs only libc/loader, maximum GLIBC_2.36.
    # Never install packages, replace libraries, alter ldconfig, or hide markers.
    script = ('set -eu\n'
              'test "$(uname -m)" = x86_64\n'
              'test "$(getconf GNU_LIBC_VERSION)" = "glibc 2.36"\n'
              'test "$(readlink -f /sbin)" = /usr/sbin\n'
              'test "$(stat -c %u:%g:%a /usr/sbin)" = 0:0:755\n'
              'test -f /lib/x86_64-linux-gnu/libc.so.6\n'
              'test -f /lib64/ld-linux-x86-64.so.2\n'
              'test ! -e /usr/sbin/apparmor_parser\n'
              'test ! -L /usr/sbin/apparmor_parser\n')
    node_exec(identity, '/bin/sh', '-c', script)
    return {'package_sha256': PARSER_PACKAGE_SHA256, 'package_size': PARSER_PACKAGE_SIZE,
            'binary_sha256': PARSER_SHA256, 'binary_size': PARSER_SIZE, 'libc': '2.36', 'preexisting': False}


def parser_write_projection(value, raw, state):
    """Refuse aliases and foreign physical storage at the parser write path."""
    targets = ('/usr/sbin',)
    def overlaps(path):
        need(type(path) is str and path.startswith('/') and '..' not in Path(path).parts
             and str(Path(path)) == path, 'fixture_parser_write_boundary')
        return any(path == target or path.startswith(target + '/') or target.startswith(path.rstrip('/') + '/')
                   for target in targets)
    host = value.get('HostConfig', {})
    need(not host.get('VolumesFrom'), 'fixture_parser_write_boundary')
    for bind in host.get('Binds') or []:
        need(type(bind) is str and len(bind.split(':')) in (2, 3)
             and not overlaps(bind.split(':')[1]), 'fixture_parser_write_boundary')
    mounts = value.get('Mounts', []) + (host.get('Mounts') or [])
    for mount in mounts:
        destination = mount.get('Destination', mount.get('Target'))
        need(not overlaps(destination), 'fixture_parser_write_boundary')
    for destination in host.get('Tmpfs') or {}:
        need(not overlaps(destination), 'fixture_parser_write_boundary')
    root, root_rows, _ = mount_projection(raw, '/usr/sbin')
    need(root['target'] == '/' and root['root'] == '/' and root['filesystem'] == 'overlay'
         and len(root_rows) == 1
         # Propagation flags govern mount events. Ordinary file writes must land
         # in the private overlay upper/work storage proved below.
         # Bind/submount aliases remain forbidden; retain peer IDs in the digest.
         and all(re.fullmatch(r'shared:[0-9]+', field) for field in root['propagation']), 'fixture_parser_write_boundary')
    # Root writes must land in this private daemon's disposable upper directory.
    directories = []
    for option_name in ('upperdir=', 'workdir='):
        paths = [option.removeprefix(option_name) for option in root['super_options'] if option.startswith(option_name)]
        need(len(paths) == 1 and any((state / child) in Path(paths[0]).parents for child in ('data', 'containerd'))
             and '..' not in Path(paths[0]).parts, 'fixture_parser_write_boundary')
        directories.append(paths[0])
    need(directories[0] != directories[1], 'fixture_parser_write_boundary')
    projection = {'docker': {'Mounts': value.get('Mounts', []), 'HostConfig': {key: host.get(key) for key in
                  ('Binds', 'Mounts', 'Tmpfs', 'VolumesFrom')}}, 'mounts': [root]}
    return hashlib.sha256(json.dumps(projection, sort_keys=True).encode()).hexdigest(), directories


def node_write_boundaries(cluster, identity, uid):
    need(node_docker_identity(cluster) == identity and node_uid(cluster) == uid, 'fixture_node_identity_changed')
    state = Path(os.environ['DOCKER_HOST'].removeprefix('unix://')).parent
    directory = json.loads(command(['docker', 'info', '--format', '{{json .DockerRootDir}}']).stdout)
    need(directory == str(state / 'data'), 'fixture_parser_write_boundary')
    values = json.loads(command(['docker', 'inspect', '--', identity['container_id']]).stdout)
    need(type(values) is list and len(values) == 1 and values[0]['Id'] == identity['container_id']
         and values[0]['State']['Pid'] == identity['container_pid'], 'fixture_node_identity_changed')
    need(node_exec(identity, 'readlink', '-f', '/', '/usr', '/usr/sbin').stdout.splitlines()
             == [b'/', b'/usr', b'/usr/sbin']
         and node_exec(identity, 'stat', '-c', '%u:%g:%a:%F', '/', '/usr', '/usr/sbin').stdout.splitlines()
             == [b'0:0:755:directory', b'0:0:755:directory', b'0:0:755:directory'],
         'fixture_parser_write_boundary')
    digest, directories = parser_write_projection(values[0], node_exec(identity, 'cat', '/proc/self/mountinfo').stdout, state)
    # Read-only host-side identity proof, including root-owned daemon directories
    # inaccessible to the invoking user. No host file is created or changed.
    verify_private_storage(state, directories)
    return {'projection_sha256': digest}


def install_parser(identity, namespace, payload, guard):
    need(len(payload) == PARSER_SIZE and hashlib.sha256(payload).hexdigest() == PARSER_SHA256, 'fixture_parser_member')
    parser_admission(identity)
    guard()
    script = ('set -eu\n'
              'test "$(readlink /proc/self/ns/mnt)" = "$1"\n'
              'test "$(id -u)" = 0\n'
              'test "$(readlink -f /sbin)" = /usr/sbin\n'
              'umask 077\n'
              'dd of=/usr/sbin/apparmor_parser conv=excl oflag=nofollow status=none\n'
              'chmod 500 /usr/sbin/apparmor_parser\n')
    command(['docker', 'exec', '-i', identity['container_id'], '/bin/sh', '-c', script,
             'fixture-parser-copy', namespace], data=payload)
    guard()
    file_identity = parser_placement_state(identity)
    version = node_exec(identity, '/sbin/apparmor_parser', '--version', maximum=4096).stdout.decode('ascii').splitlines()
    need(version and version[0] == 'AppArmor parser version 3.0.8', 'fixture_parser_version')
    guard()
    need(parser_placement_state(identity) == file_identity, 'fixture_parser_node')
    return {'path': '/usr/sbin/apparmor_parser', 'version': '3.0.8', 'mode': 0o500,
            'binary_sha256': PARSER_SHA256, 'file_identity': file_identity}


def parser_placement_state(identity):
    need(node_exec(identity, 'readlink', '-f', '/sbin/apparmor_parser').stdout.decode('ascii').strip() == '/usr/sbin/apparmor_parser'
         and node_exec(identity, 'sha256sum', '/sbin/apparmor_parser').stdout.decode('ascii').split()[0] == PARSER_SHA256,
         'fixture_parser_node')
    fields = node_exec(identity, 'env', 'LC_ALL=C', 'stat', '-c', '%F:%u:%g:%a:%s:%h:%d:%i',
                       '/usr/sbin/apparmor_parser').stdout.decode('ascii').strip().split(':')
    need(len(fields) == 8 and fields[:6] == ['regular file', '0', '0', '500', str(PARSER_SIZE), '1']
         and all(field.isdecimal() and 0 < int(field) < 2**64 for field in fields[6:]), 'fixture_parser_node')
    ctime = node_exec(identity, 'env', 'LC_ALL=C', 'stat', '-c', '%z', '/usr/sbin/apparmor_parser').stdout.decode('ascii').strip()
    value = {'device': int(fields[6]), 'inode': int(fields[7]), 'ctime': ctime}
    validate_parser_file_identity(value)
    return value


def validate_parser_file_identity(value):
    need(type(value) is dict and set(value) == {'device', 'inode', 'ctime'}
         and all(type(value[key]) is int and 0 < value[key] < 2**64 for key in ('device', 'inode'))
         and type(value['ctime']) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9} [+-][0-9]{4}', value['ctime']),
         'fixture_receipt_node_parser')


def securityfs_state(raw):
    cover, related, _shared = mount_projection(raw)
    # Stacked mounts at the exact path are ambiguous even when their cover is
    # identical. Never unmount an unrecorded replacement or a child mount.
    need(sum(line.split()[4] == NODE_SECURITYFS for line in raw.decode().splitlines()) <= 1
         and len(related) == 1, 'fixture_node_restoration_preimage')
    return cover, hashlib.sha256(json.dumps(related, sort_keys=True).encode()).hexdigest()


def prepare_node_apparmor(cluster, server_image):
    """Expose kernel policy only inside this newly owned Docker node namespace."""
    source = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    identity = node_docker_identity(cluster)
    uid = node_uid(cluster)
    namespace = node_namespace(identity)
    need(node_exec(identity, 'readlink', '/proc/1/ns/mnt').stdout.decode('ascii').strip() == namespace,
         'fixture_host_mount_namespace_refused')
    host_namespace, host_digest, host_shared = host_mount_state()
    need(namespace != host_namespace, 'fixture_host_mount_namespace_refused')
    cover, security_before = securityfs_state(node_exec(identity, 'cat', '/proc/self/mountinfo').stdout)
    need(not (set(cover['propagation']) & host_shared), 'fixture_host_mount_propagation_refused')
    module = node_exec(identity, 'cat', '/sys/module/apparmor/parameters/enabled').stdout.strip()
    need(module == b'Y', 'fixture_node_apparmor_kernel_disabled')
    present = cover['target'] == NODE_SECURITYFS and cover['filesystem'] == 'securityfs'
    postgres = postgres_process(cluster)
    kubelet = kubelet_process(identity)
    before = {'kubelet_pid': kubelet, 'kubelet_process': node_process(identity, kubelet, 'kubelet')[0],
              'containerd': containerd_process(identity),
              'postgres': postgres, 'postgres_runtime': postgres_runtime(identity, postgres),
              'host_mounts_sha256': host_digest}
    parser = parser_admission(identity)
    boundaries = node_write_boundaries(cluster, identity, uid)
    payload = genuine_parser(cluster.scratch)
    bound = {'profile': cluster.profile, 'node_uid': uid, **identity,
             'host_mount_namespace': host_namespace, 'node_mount_namespace': namespace}
    intent = {'version': 1, 'synthetic': True, 'state': 'prepared', 'identity': bound,
              'source_sha256': source, 'apparmor_sha256': APPARMOR_SHA256, 'before': before,
              'securityfs_preexisting': present, 'server_image': server_image, 'parser': parser,
              'write_boundaries': boundaries, 'securityfs_before_sha256': security_before}
    need(receipt(cluster, 'npm-assessment-node-preparation-intent.json', intent), 'fixture_evidence_retention_incomplete')
    need(node_docker_identity(cluster) == identity and node_uid(cluster) == uid, 'fixture_node_identity_changed')
    if not present:
        # The fixed command runs in the admitted container ID, not a host PID.
        # Refuse namespace drift immediately before the namespace-local mount.
        script = ('set -eu\n'
                  'test "$(readlink /proc/self/ns/mnt)" = "$1"\n'
                  'test "$(id -u)" = 0\n'
                  'mount -t securityfs -o ro,nosuid,nodev,noexec securityfs /sys/kernel/security\n')
        node_exec(identity, '/bin/sh', '-c', script, 'fixture-node-securityfs', namespace)
    current_host_namespace, current_host_digest, _ = host_mount_state()
    need((current_host_namespace, current_host_digest) == (host_namespace, host_digest),
         'fixture_host_mount_changed')
    mounted, security_after = securityfs_state(node_exec(identity, 'cat', '/proc/self/mountinfo').stdout)
    need(mounted['target'] == NODE_SECURITYFS and mounted['filesystem'] == 'securityfs'
         and (present or {'ro', 'nosuid', 'nodev', 'noexec'} <= set(mounted['options'])),
         'fixture_node_securityfs_not_confined')
    node_exec(identity, '/bin/sh', '-c', 'test -d /sys/kernel/security/apparmor')
    need(node_docker_identity(cluster) == identity and node_uid(cluster) == uid
         and node_namespace(identity) == namespace
         and hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == source, 'fixture_node_identity_changed')
    def guard():
        need(node_write_boundaries(cluster, identity, uid) == boundaries, 'fixture_parser_write_boundary')
    placement = install_parser(identity, namespace, payload, guard)
    need(node_docker_identity(cluster) == identity and node_uid(cluster) == uid
         and node_namespace(identity) == namespace and host_mount_state()[:2] == (host_namespace, host_digest)
         and postgres_process(cluster) == before['postgres']
         and postgres_runtime(identity, before['postgres']) == before['postgres_runtime'],
         'fixture_node_preparation_identity_changed')
    # Kubelet caches its first AppArmor support result. Restart only this owned
    # node's process after visibility changes, before any assessment participant.
    need(node_namespace(identity) == namespace, 'fixture_node_identity_changed')
    need(containerd_process(identity) == before['containerd'], 'fixture_node_runtime_process')
    node_exec(identity, 'systemctl', 'restart', 'containerd', timeout=60)
    node_exec(identity, 'systemctl', 'restart', 'kubelet', timeout=60)
    cluster.k('wait', '--for=condition=Ready', 'node/' + cluster.profile, '--timeout=180s', timeout=190)
    cluster.k('rollout', 'status', 'deployment/postgres', '--timeout=180s', namespace='devres-acceptance', timeout=190)
    postgres = postgres_process(cluster)
    kubelet = kubelet_process(identity)
    after = {'kubelet_pid': kubelet, 'kubelet_process': node_process(identity, kubelet, 'kubelet')[0],
             'containerd': containerd_process(identity),
             'postgres': postgres, 'postgres_runtime': postgres_runtime(identity, postgres),
             'host_mounts_sha256': host_mount_state()[1]}
    need(parser_placement_state(identity) == placement['file_identity'], 'fixture_parser_node')
    guard()
    need(node_docker_identity(cluster) == identity and node_uid(cluster) == uid
         and node_namespace(identity) == namespace and host_mount_state()[:2] == (host_namespace, host_digest)
         and after['postgres'] == before['postgres'] and after['postgres_runtime'] == before['postgres_runtime']
         and after['containerd']['binary_sha256'] == before['containerd']['binary_sha256']
         and after['kubelet_process']['binary_sha256'] == before['kubelet_process']['binary_sha256']
         and after['containerd']['pid'] != before['containerd']['pid']
         and after['kubelet_pid'] != before['kubelet_pid']
         and hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == source,
         'fixture_node_preparation_identity_changed')
    result = {**intent, 'state': 'complete', 'after': after, 'securityfs_created': not present,
              'kubelet_restarted': True, 'containerd_restarted': True, 'parser_placement': placement,
              'securityfs_after_sha256': security_after, 'securityfs_mount': mounted}
    need(receipt(cluster, 'npm-assessment-node-preparation.json', result), 'fixture_evidence_retention_incomplete')
    return result


def validate_node_preparation(name, value):
    need(type(value) is dict and type(value.get('version')) is int and value['version'] == 1
         and value.get('synthetic') is True, 'fixture_receipt_node_identity')
    fields = {'version', 'synthetic', 'state', 'identity', 'source_sha256', 'apparmor_sha256',
              'before', 'securityfs_preexisting', 'server_image', 'parser', 'write_boundaries', 'securityfs_before_sha256'}
    complete = name == 'npm-assessment-node-preparation.json'
    need(set(value) == fields | ({'after', 'securityfs_created', 'kubelet_restarted', 'containerd_restarted',
         'parser_placement', 'securityfs_after_sha256', 'securityfs_mount'} if complete else set()),
         'fixture_receipt_node_fields')
    need(value['state'] == ('complete' if complete else 'prepared')
         and type(value['securityfs_preexisting']) is bool
         and value['apparmor_sha256'] == APPARMOR_SHA256
         and type(value['source_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['source_sha256'])
         and type(value['server_image']) is str and re.fullmatch(r'[A-Za-z0-9._:/@+\-]{1,256}', value['server_image']),
         'fixture_receipt_node_identity')
    need(type(value['securityfs_before_sha256']) is str and re.fullmatch('[a-f0-9]{64}', value['securityfs_before_sha256']),
         'fixture_receipt_node_identity')
    need(value['parser'] == {'package_sha256': PARSER_PACKAGE_SHA256, 'package_size': PARSER_PACKAGE_SIZE,
         'binary_sha256': PARSER_SHA256, 'binary_size': PARSER_SIZE, 'libc': '2.36', 'preexisting': False},
         'fixture_receipt_node_parser')
    need(type(value['write_boundaries']) is dict and set(value['write_boundaries']) == {'projection_sha256'}
         and type(value['write_boundaries']['projection_sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', value['write_boundaries']['projection_sha256']), 'fixture_receipt_node_parser')
    identity = value['identity']
    need(type(identity) is dict and set(identity) == {'profile', 'node_uid', 'container_id', 'container_pid',
         'host_mount_namespace', 'node_mount_namespace'}, 'fixture_receipt_node_identity')
    need(type(identity['profile']) is str and re.fullmatch('devres-acceptance-[a-z0-9-]+', identity['profile'])
         and type(identity['node_uid']) is str and re.fullmatch(UUID_PATTERN, identity['node_uid'])
         and type(identity['container_id']) is str and re.fullmatch('[0-9a-f]{64}', identity['container_id'])
         and type(identity['container_pid']) is int and 1 < identity['container_pid'] < 2**31
         and all(type(identity[key]) is str and re.fullmatch(r'mnt:\[[0-9]{1,20}\]', identity[key])
                 for key in ('host_mount_namespace', 'node_mount_namespace'))
         and identity['host_mount_namespace'] != identity['node_mount_namespace'], 'fixture_receipt_node_identity')
    def process(record, daemon=False):
        need(type(record) is dict and set(record) == {'pid', 'start_ticks', 'binary_sha256'} | ({'kill_mode'} if daemon else set())
             and type(record['pid']) is int and 1 < record['pid'] < 2**31
             and type(record['start_ticks']) is int and 0 <= record['start_ticks'] < 2**64
             and type(record['binary_sha256']) is str and re.fullmatch('[0-9a-f]{64}', record['binary_sha256'])
             and (not daemon or record['kill_mode'] == 'process'), 'fixture_receipt_node_process')
    for snapshot in ([value['before'], value['after']] if complete else [value['before']]):
        need(type(snapshot) is dict and set(snapshot) == {'kubelet_pid', 'kubelet_process', 'containerd', 'postgres', 'postgres_runtime', 'host_mounts_sha256'}
             and type(snapshot['kubelet_pid']) is int and 1 < snapshot['kubelet_pid'] < 2**31
             and type(snapshot['host_mounts_sha256']) is str and re.fullmatch('[0-9a-f]{64}', snapshot['host_mounts_sha256']),
             'fixture_receipt_node_process')
        process(snapshot['containerd'], daemon=True)
        process(snapshot['kubelet_process'])
        need(snapshot['kubelet_process']['pid'] == snapshot['kubelet_pid'], 'fixture_receipt_node_process')
        postgres = snapshot['postgres']
        need(type(postgres) is dict and set(postgres) == {'uid', 'container_id', 'restart_count'}
             and type(postgres['uid']) is str and re.fullmatch(UUID_PATTERN, postgres['uid'])
             and type(postgres['container_id']) is str and re.fullmatch('containerd://[0-9a-f]{64}', postgres['container_id'])
             and type(postgres['restart_count']) is int and 0 <= postgres['restart_count'] < 2**31,
             'fixture_receipt_node_process')
        runtime = snapshot['postgres_runtime']
        need(type(runtime) is dict and set(runtime) == {'pid', 'start_ticks', 'shim'}
             and type(runtime['pid']) is int and 1 < runtime['pid'] < 2**31
             and type(runtime['start_ticks']) is int and 0 <= runtime['start_ticks'] < 2**64,
             'fixture_receipt_node_process')
        process(runtime['shim'])
    if complete:
        need(type(value['securityfs_created']) is bool and type(value['kubelet_restarted']) is bool
             and type(value['containerd_restarted']) is bool
             and value['securityfs_created'] == (not value['securityfs_preexisting'])
             and value['kubelet_restarted'] is True and value['containerd_restarted'] is True
             and value['before']['postgres'] == value['after']['postgres']
             and value['before']['postgres_runtime'] == value['after']['postgres_runtime']
             and value['before']['host_mounts_sha256'] == value['after']['host_mounts_sha256']
             and value['before']['containerd']['binary_sha256'] == value['after']['containerd']['binary_sha256']
             and value['before']['kubelet_process']['binary_sha256'] == value['after']['kubelet_process']['binary_sha256']
             and (not value['containerd_restarted'] or value['before']['containerd']['pid'] != value['after']['containerd']['pid'])
             and (not value['kubelet_restarted'] or value['before']['kubelet_pid'] != value['after']['kubelet_pid']),
             'fixture_receipt_node_preservation')
        placement = value['parser_placement']
        need(type(placement) is dict and set(placement) == {'path', 'version', 'mode', 'binary_sha256', 'file_identity'}
             and placement['path'] == '/usr/sbin/apparmor_parser'
             and placement['version'] == '3.0.8' and placement['mode'] == 0o500
             and placement['binary_sha256'] == PARSER_SHA256, 'fixture_receipt_node_parser')
        validate_parser_file_identity(placement['file_identity'])
        mounted = value['securityfs_mount']
        need(type(mounted) is dict and set(mounted) == {'id', 'parent', 'device', 'root', 'target', 'options',
             'propagation', 'filesystem', 'source', 'super_options'} and mounted['target'] == NODE_SECURITYFS
             and mounted['filesystem'] == 'securityfs' and mounted['root'] == '/'
             and all(type(mounted[key]) is str and re.fullmatch('[0-9]{1,20}', mounted[key]) for key in ('id', 'parent'))
             and type(mounted['device']) is str and re.fullmatch('[0-9]{1,20}:[0-9]{1,20}', mounted['device'])
             and type(mounted['source']) is str and re.fullmatch(r'[A-Za-z0-9._:/+\-]{1,128}', mounted['source'])
             and all(type(mounted[key]) is list and len(mounted[key]) <= 32
                 and all(type(item) is str and re.fullmatch(r'[A-Za-z0-9._:=/+\-]{1,256}', item) for item in mounted[key])
                 for key in ('options', 'propagation', 'super_options'))
             and (not value['securityfs_created'] or {'ro', 'nosuid', 'nodev', 'noexec'} <= set(mounted['options']))
             and value['securityfs_after_sha256'] == hashlib.sha256(json.dumps([mounted], sort_keys=True).encode()).hexdigest()
             and (value['securityfs_created'] or value['securityfs_after_sha256'] == value['securityfs_before_sha256']),
             'fixture_receipt_node_identity')


def validate_node_restoration(name, value):
    need(set(value) == {'version', 'synthetic', 'state', 'preparation', 'preparation_sha256', 'before', 'after',
         'parser_removed', 'securityfs_restored', 'securityfs_final_sha256'}, 'fixture_receipt_node_restoration')
    prepared = value['preparation']
    validate_node_preparation('npm-assessment-node-preparation.json', prepared)
    need(value['preparation_sha256'] == hashlib.sha256(json.dumps(prepared, sort_keys=True).encode() + b'\n').hexdigest()
         and value['before'] == prepared['after'], 'fixture_receipt_node_restoration')
    complete = name == 'npm-assessment-node-restoration.json'
    need(value['state'] == ('complete' if complete else 'prepared') and value['parser_removed'] is complete
         and value['securityfs_restored'] is complete, 'fixture_receipt_node_restoration')
    if complete:
        validate_node_preparation('npm-assessment-node-preparation.json',
                                  {**prepared, 'before': value['before'], 'after': value['after']})
        need(value['securityfs_final_sha256'] == prepared['securityfs_before_sha256'], 'fixture_receipt_node_restoration')
    else:
        need(value['after'] is None and value['securityfs_final_sha256'] is None, 'fixture_receipt_node_restoration')


def restore_node_apparmor(cluster, prepared):
    cluster.node_restoration_phase = 'admission'
    try:
        restore_node_apparmor_fixture(cluster, prepared)
    except BaseException as error:
        receipt(cluster, 'npm-assessment-node-restoration-failure.json', {'version': 1, 'synthetic': True,
            'phase': cluster.node_restoration_phase, 'failure': closed_failure(error)})
        raise


def restore_node_apparmor_fixture(cluster, prepared):
    """Return only this owned node's temporary prerequisites to their preimage."""
    validate_node_preparation('npm-assessment-node-preparation.json', prepared)
    bound = prepared['identity']
    need(bound['profile'] == cluster.profile, 'fixture_node_restoration_identity')
    identity = {key: bound[key] for key in ('container_id', 'container_pid')}
    def identity_guard():
        need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == prepared['source_sha256']
             and node_docker_identity(cluster) == identity and node_uid(cluster) == bound['node_uid']
             and node_namespace(identity) == bound['node_mount_namespace']
             and host_mount_state()[:2] == (bound['host_mount_namespace'], prepared['after']['host_mounts_sha256'])
             and node_write_boundaries(cluster, identity, bound['node_uid']) == prepared['write_boundaries'],
             'fixture_node_restoration_identity')
    def snapshot_processes():
        postgres = postgres_process(cluster)
        kubelet = kubelet_process(identity)
        return {'kubelet_pid': kubelet, 'kubelet_process': node_process(identity, kubelet, 'kubelet')[0],
                'containerd': containerd_process(identity),
                'postgres': postgres, 'postgres_runtime': postgres_runtime(identity, postgres),
                'host_mounts_sha256': host_mount_state()[1]}
    identity_guard()
    need(not cluster.owned_objects('namespace') and not cluster.owned_objects('policy') and no_attached_tasks(),
         'fixture_node_restoration_cleanup')
    profiles = command(['sudo', '-n', 'cat', '/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
    need(not any(line.startswith((b'devres-runtime ', b'devres-runtime//')) for line in profiles),
         'fixture_node_restoration_cleanup')
    need(parser_placement_state(identity) == prepared['parser_placement']['file_identity'], 'fixture_node_restoration_identity')
    mounted, security = securityfs_state(node_exec(identity, 'cat', '/proc/self/mountinfo').stdout)
    need(mounted == prepared['securityfs_mount'] and security == prepared['securityfs_after_sha256']
         and not (set(mounted['propagation']) & host_mount_state()[2]), 'fixture_node_restoration_preimage')
    before = snapshot_processes()
    need(before == prepared['after'], 'fixture_node_restoration_identity')
    intent = {'version': 1, 'synthetic': True, 'state': 'prepared', 'preparation': prepared,
        'preparation_sha256': hashlib.sha256(json.dumps(prepared, sort_keys=True).encode() + b'\n').hexdigest(),
        'before': before, 'after': None, 'parser_removed': False, 'securityfs_restored': False,
        'securityfs_final_sha256': None}
    need(receipt(cluster, 'npm-assessment-node-restoration-intent.json', intent), 'fixture_evidence_retention_incomplete')
    identity_guard()
    need(parser_placement_state(identity) == prepared['parser_placement']['file_identity'], 'fixture_node_restoration_identity')
    cluster.node_restoration_phase = 'parser-remove'
    node_exec(identity, 'unlink', '--', '/usr/sbin/apparmor_parser')
    node_exec(identity, '/bin/sh', '-c', 'test ! -e /usr/sbin/apparmor_parser && test ! -L /usr/sbin/apparmor_parser')
    cluster.node_restoration_phase = 'securityfs-restore'
    identity_guard()
    mounted, security = securityfs_state(node_exec(identity, 'cat', '/proc/self/mountinfo').stdout)
    need(mounted == prepared['securityfs_mount'] and security == prepared['securityfs_after_sha256']
         and not (set(mounted['propagation']) & host_mount_state()[2]),
         'fixture_node_restoration_preimage')
    if prepared['securityfs_created']:
        node_exec(identity, 'umount', '--', NODE_SECURITYFS)
    _cover, final_security = securityfs_state(node_exec(identity, 'cat', '/proc/self/mountinfo').stdout)
    need(final_security == prepared['securityfs_before_sha256'], 'fixture_node_restoration_preimage')
    cluster.node_restoration_phase = 'runtime-reset'
    identity_guard()
    need(snapshot_processes() == before, 'fixture_node_restoration_identity')
    node_exec(identity, 'systemctl', 'restart', 'containerd', timeout=60)
    node_exec(identity, 'systemctl', 'restart', 'kubelet', timeout=60)
    cluster.k('wait', '--for=condition=Ready', 'node/' + cluster.profile, '--timeout=180s', timeout=190)
    cluster.k('rollout', 'status', 'deployment/postgres', '--timeout=180s', namespace='devres-acceptance', timeout=190)
    cluster.node_restoration_phase = 'verify'
    identity_guard()
    after = snapshot_processes()
    node_exec(identity, '/bin/sh', '-c', 'test ! -e /usr/sbin/apparmor_parser && test ! -L /usr/sbin/apparmor_parser')
    _cover, final_security = securityfs_state(node_exec(identity, 'cat', '/proc/self/mountinfo').stdout)
    need(final_security == prepared['securityfs_before_sha256'] and after['postgres'] == before['postgres']
         and after['postgres_runtime'] == before['postgres_runtime']
         and after['containerd']['binary_sha256'] == before['containerd']['binary_sha256']
         and after['kubelet_process']['binary_sha256'] == before['kubelet_process']['binary_sha256']
         and after['containerd']['pid'] != before['containerd']['pid'] and after['kubelet_pid'] != before['kubelet_pid'],
         'fixture_node_restoration_identity')
    need(receipt(cluster, 'npm-assessment-node-restoration.json', {**intent, 'state': 'complete', 'after': after,
         'parser_removed': True, 'securityfs_restored': True, 'securityfs_final_sha256': final_security}),
         'fixture_evidence_retention_incomplete')


ATTACHED_TASKS = r'''
import errno,json,os,pathlib
attached=0
unknown=False
for entry in pathlib.Path('/proc').iterdir():
    if not entry.name.isdecimal():
        continue
    try:
        threads=list((entry/'task').iterdir())
        for thread in threads:
            try:
                with (thread/'attr/current').open('rb') as stream:
                    raw=stream.read(4097)
                if len(raw)>4096:
                    unknown=True
                    continue
                label=raw.decode('ascii').strip().split(' (',1)[0]
                if any(component=='devres-runtime' or component.startswith('devres-runtime//') for component in label.split('//&')):
                    attached+=1
            except OSError as error:
                if error.errno not in (errno.ENOENT,errno.ESRCH,errno.EINVAL):
                    unknown=True
            except UnicodeDecodeError:
                unknown=True
    except OSError as error:
        if error.errno not in (errno.ENOENT,errno.ESRCH,errno.EINVAL):
            unknown=True
    except UnicodeDecodeError:
        unknown=True
print(json.dumps({'attached':attached,'unknown':unknown}))
'''


def no_attached_tasks():
    value = json.loads(command(['sudo', '-n', 'python3', '-I', '-B', '-c', ATTACHED_TASKS], maximum=4096).stdout)
    need(set(value) == {'attached', 'unknown'} and type(value['attached']) is int
         and value['attached'] >= 0 and type(value['unknown']) is bool, 'apparmor_task_check_invalid')
    return value['attached'] == 0 and not value['unknown']


@contextlib.contextmanager
def apparmor(scratch, owned_tasks_stopped=lambda: True):
    """Exclusive temporary kernel admission, without changing host policy files."""
    lock = os.open('/tmp/devres-assessment-apparmor.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    path = scratch / 'devres-runtime'
    loaded = False
    try:
        need(os.fstat(lock).st_uid == os.getuid(), 'apparmor_lock_owner')
        fcntl.flock(lock, fcntl.LOCK_EX)
        original = (ROOT / 'deploy/production/apparmor/devres-runtime').read_bytes()
        need(hashlib.sha256(original).hexdigest() == APPARMOR_SHA256, 'apparmor_canonical_hash_mismatch')
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(original)
        digest = hashlib.sha256(original).hexdigest()
        profiles = command(['sudo', '-n', 'cat', '/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
        need(not any(line.startswith(b'devres-runtime ') for line in profiles), 'apparmor_profile_already_loaded')
        need(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'apparmor_asset_changed')
        command(['sudo', '-n', 'apparmor_parser', '-a', '-K', str(path)])
        loaded = True
        profiles = command(['sudo', '-n', 'cat', '/sys/kernel/security/apparmor/profiles']).stdout.splitlines()
        need(b'devres-runtime (enforce)' in profiles, 'apparmor_not_enforcing')
        yield digest
    finally:
        try:
            if loaded:
                need(owned_tasks_stopped() and no_attached_tasks(), 'apparmor_cleanup_incomplete_profile_retained')
                command(['sudo', '-n', 'apparmor_parser', '-R', '-K', str(path)])
        finally:
            os.close(lock)


class Cluster:
    def __init__(self, profile, scratch):
        need(re.fullmatch(r'devres-acceptance-[a-z0-9-]+', profile), 'owned_minikube_profile_required')
        self.profile = profile
        self.scratch = scratch

    def argv(self, *args, namespace=NAMESPACE):
        return ['minikube', '-p', self.profile, 'kubectl', '--',
            '--cache-dir=' + str(self.scratch / 'kube-cache'), '--context=' + self.profile,
            '--request-timeout=30s', '-n', namespace, *args]

    def k(self, *args, namespace=NAMESPACE, **kwargs):
        return command(self.argv(*args, namespace=namespace), **kwargs)

    def apply(self, objects):
        return self.write('apply', objects)

    def create(self, objects):
        return self.write('create', objects)

    def write(self, operation, objects):
        need(operation in ('apply', 'create'), 'fixture_apply_operation_invalid')
        if not isinstance(objects, list):
            objects = [objects]
        need(objects and all(type(value) is dict and type(value.get('metadata')) is dict for value in objects),
             'fixture_apply_objects_required')
        groups = {}
        for value in objects:
            namespace = value['metadata'].get('namespace', NAMESPACE)
            need(type(namespace) is str and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', namespace),
                 'fixture_apply_namespace_invalid')
            groups.setdefault(namespace, []).append(value)
        # kubectl's explicit namespace is enforced for every namespaced object.
        # Validate/group the whole list before I/O; policy grants stay unchanged.
        for namespace, items in groups.items():
            result = self.k(operation, '-f', '-', namespace=namespace,
                data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items}).encode())
        return result

    def owned_objects(self, kind):
        need(kind == 'namespace' or kind in OWNED_POLICIES, 'fixture_owned_resource_kind')
        name, version, expected, path = (NAMESPACE, 'v1', 'NamespaceList', '/api/v1/namespaces') if kind == 'namespace' else (
            OWNED_POLICIES[kind], 'networking.k8s.io/v1', 'NetworkPolicyList',
            '/apis/networking.k8s.io/v1/namespaces/devres-acceptance/networkpolicies')
        # Normal kubectl get rewrites typed API lists to a generic core List.
        # Keep the API schema for authoritative absence and identity admission.
        result = self.k('get', '--raw=' + path + '?fieldSelector=metadata.name%3D' + name,
                        namespace=NAMESPACE if kind == 'namespace' else 'devres-acceptance')
        need(result.returncode == 0, 'fixture_owned_resource_unavailable')
        value = json.loads(result.stdout)
        need(type(value) is dict and value.get('apiVersion') == version and value.get('kind') == expected
             and type(value.get('items')) is list
             and len(value['items']) <= 1 and all(type(item) is dict and type(item.get('metadata')) is dict
                 and item['metadata'].get('name') == name for item in value['items']), 'fixture_owned_resource_list')
        return value['items']

    def admit_owned(self, kind, objects=None):
        objects = self.owned_objects(kind) if objects is None else objects
        need(len(objects) == 1, 'fixture_owned_resource_missing')
        metadata = objects[0]['metadata']
        uid = metadata.get('uid')
        need(type(uid) is str and re.fullmatch(UUID_PATTERN, uid)
             and metadata.get('labels', {}).get(FIXTURE_OWNER_LABEL) == self.fixture_owner,
             'fixture_owned_resource_foreign')
        admitted = getattr(self, kind + '_uid', None)
        need(admitted is None or uid == admitted, 'fixture_owned_resource_replaced')
        setattr(self, kind + '_uid', uid)
        return uid

    def cleanup_owned(self, kind):
        objects = self.owned_objects(kind)
        if not objects:
            return
        uid = self.admit_owned(kind, objects)
        if kind == 'namespace':
            path = '/api/v1/namespaces/' + NAMESPACE
            resource, name, limit, namespace = 'namespace', NAMESPACE, 120, NAMESPACE
        else:
            resource, name, limit, namespace = 'networkpolicy', OWNED_POLICIES[kind], 60, 'devres-acceptance'
            path = '/apis/networking.k8s.io/v1/namespaces/devres-acceptance/networkpolicies/' + name
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}}
        self.k('delete', '--raw=' + path, '-f', '-', data=json.dumps(options).encode(), namespace=namespace)
        self.k('wait', '--for=delete', resource + '/' + name, '--timeout=' + str(limit) + 's',
               timeout=limit + 10, namespace=namespace)
        need(not self.owned_objects(kind), 'fixture_owned_resource_cleanup_unconfirmed')

    def sql(self, statement, *, database=DATABASE):
        return self.k('exec', 'deployment/postgres', '--', 'psql', '-X', '-q', '-At',
                      '-U', 'devres', '-d', database, '-v', 'ON_ERROR_STOP=1', '-c', statement,
                      namespace='devres-acceptance').stdout

    def pod(self, name):
        return json.loads(self.k('get', 'pod', name, '-o', 'json').stdout)

    def delete(self, name, uid):
        pod = self.pod(name)
        need(pod['metadata']['uid'] == uid, 'assessment_cleanup_uid_changed')
        # kubectl delete's raw API precondition is not exposed; use a source-bound
        # delete request with a UID precondition through the API raw endpoint.
        path = f'/api/v1/namespaces/{NAMESPACE}/pods/{name}'
        options = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}}
        self.k('delete', '--raw=' + path, '-f', '-', data=json.dumps(options).encode())
        self.k('wait', '--for=delete', 'pod/' + name, '--timeout=60s', timeout=70)


def seed(cluster, image, *, database_admin=DATABASE_ADMIN):
    cluster.sql('CREATE DATABASE ' + DATABASE, database='postgres')
    pod = template(image)
    pod.update({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'assessment-seed', 'namespace': NAMESPACE,
                'labels': {'app': 'backend'}}})
    spec = pod['spec']
    spec.update({'restartPolicy': 'Never', 'activeDeadlineSeconds': 120})
    spec['volumes'] = [{'name': 'tmp', 'emptyDir': {'sizeLimit': '64Mi'}}]
    container = spec['containers'][0]
    container['name'] = 'seed'
    container['command'] = ['npm-assessment-seed']
    container['env'] = [{'name': 'DATABASE_URL', 'value': database_admin}, {'name': 'DEVRES_SYNTHETIC_ASSESSMENT', 'value': '1'}]
    container['volumeMounts'] = [{'name': 'tmp', 'mountPath': '/tmp'}]
    cluster.apply(pod)
    cluster.k('wait', '--for=jsonpath={.status.phase}=Succeeded', 'pod/assessment-seed', '--timeout=130s', timeout=140)
    receipt = json.loads(cluster.k('logs', 'assessment-seed', maximum=4096).stdout)
    need(set(receipt) == {'version', 'schema', 'job_id', 'revision', 'cause_authoritative', 'synthetic'}
         and receipt['version'] == 1 and receipt['schema'] == 19 and receipt['revision'] == 1
         and receipt['cause_authoritative'] is False and receipt['synthetic'] is True
         and re.fullmatch('blake3:[0-9a-f]{64}', receipt['job_id']), 'synthetic_seed_receipt_invalid')
    cluster.delete('assessment-seed', cluster.pod('assessment-seed')['metadata']['uid'])
    cluster.sql("CREATE ROLE devres_assessment_reader LOGIN PASSWORD 'assessment-fixture-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT; GRANT CONNECT ON DATABASE devres_assessment_fixture TO devres_assessment_reader; GRANT USAGE ON SCHEMA public TO devres_assessment_reader; GRANT SELECT ON ALL TABLES IN SCHEMA public TO devres_assessment_reader; ALTER ROLE devres_assessment_reader SET default_transaction_read_only=on")
    return receipt


def probe_authority(cluster, expected, actual):
    """Compare the complete executable authority, allowing explicit API defaults."""
    metadata = actual.get('metadata', {})
    need(type(metadata.get('uid')) is str and re.fullmatch(UUID_PATTERN, metadata['uid'])
         and all(metadata.get(key) == expected['metadata'][key] for key in ('name', 'namespace', 'labels')),
         'assessment_egress_evidence_invalid')
    annotations = metadata.get('annotations') or {}
    need(type(annotations) is dict and set(annotations) <= {'cni.projectcalico.org/containerID',
         'cni.projectcalico.org/podIP', 'cni.projectcalico.org/podIPs'}, 'assessment_egress_evidence_invalid')
    for key, value in annotations.items():
        need(type(value) is str and len(value) <= 512, 'assessment_egress_evidence_invalid')
        if key.endswith('/containerID'):
            need(re.fullmatch('[a-f0-9]{64}', value), 'assessment_egress_evidence_invalid')
        elif value:
            try:
                addresses = value.split(',')
                need(len(addresses) <= 2 and all(ipaddress.ip_interface(item).network.prefixlen
                     == ipaddress.ip_interface(item).max_prefixlen for item in addresses), 'assessment_egress_evidence_invalid')
            except ValueError:
                raise FixtureError('assessment_egress_evidence_invalid') from None
    spec = dict(actual['spec'])
    defaults = {'hostNetwork': False, 'hostPID': False, 'hostIPC': False, 'hostUsers': True,
        'dnsPolicy': 'ClusterFirst', 'schedulerName': 'default-scheduler', 'priority': 0,
        'preemptionPolicy': 'PreemptLowerPriority', 'terminationGracePeriodSeconds': 30,
        'enableServiceLinks': True, 'serviceAccount': 'assessment', 'os': {'name': 'linux'},
        'initContainers': [], 'ephemeralContainers': [], 'imagePullSecrets': [], 'hostAliases': [],
        'readinessGates': [], 'schedulingGates': [], 'resourceClaims': [], 'overhead': {},
        'setHostnameAsFQDN': False, 'hostname': '', 'subdomain': ''}
    for key, value in defaults.items():
        if key in spec:
            need(type(spec[key]) is type(value) and spec.pop(key) == value, 'assessment_egress_evidence_invalid')
    if 'tolerations' in spec:
        tolerations = spec.pop('tolerations')
        need(type(tolerations) is list and all(type(item) is dict for item in tolerations)
             and sorted(tolerations, key=lambda item: item.get('key', '')) == [
            {'key': 'node.kubernetes.io/not-ready', 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300},
            {'key': 'node.kubernetes.io/unreachable', 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300}],
            'assessment_egress_evidence_invalid')
    need(type(spec.get('containers')) is list and len(spec['containers']) == 1, 'assessment_egress_evidence_invalid')
    container = dict(spec['containers'][0])
    for key, value in {'terminationMessagePath': '/dev/termination-log', 'terminationMessagePolicy': 'File',
                       'stdin': False, 'stdinOnce': False, 'tty': False, 'env': [], 'envFrom': [],
                       'args': [], 'ports': [], 'resizePolicy': [], 'volumeDevices': []}.items():
        if key in container:
            need(type(container[key]) is type(value) and container.pop(key) == value, 'assessment_egress_evidence_invalid')
    spec['containers'] = [container]
    need(spec == expected['spec'] and spec['nodeName'] == cluster.profile, 'assessment_egress_evidence_invalid')
    return metadata['uid']


def network_probe(cluster, image):
    """A denied destination is a local Kubernetes API, never a public provider."""
    pod = template(image)
    pod.update({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'assessment-network',
                'namespace': NAMESPACE, 'labels': {'app': 'backend'}}})
    pod['spec'].update({'restartPolicy': 'Never', 'activeDeadlineSeconds': 30, 'nodeName': cluster.profile})
    pod['spec']['volumes'] = [{'name': 'tmp', 'emptyDir': {'sizeLimit': '16Mi'}}]
    container = pod['spec']['containers'][0]
    container['name'] = 'probe'
    container['volumeMounts'] = [{'name': 'tmp', 'mountPath': '/tmp'},
                               {'name': 'tmp', 'mountPath': '/sys/kernel/security', 'readOnly': True}]
    container['command'] = ['python3', '-I', '-B', '-c', """
import errno,json,os,socket
with open('/proc/self/attr/current') as source:
    label=source.read(256).strip()
assert label in ('devres-runtime (enforce)','devres-runtime//&unconfined (enforce)')
with open('/tmp/apparmor-canary','xb') as output:
    output.write(b'owned-synthetic-apparmor-canary')
os.chmod('/tmp/apparmor-canary',0o600)
with open('/tmp/apparmor-canary','rb') as source:
    assert source.read()==b'owned-synthetic-apparmor-canary'
try:
    with open('/sys/kernel/security/apparmor-canary','rb') as source:
        source.read()
except OSError as error:
    assert error.errno==errno.EACCES
else:
    raise AssertionError('canonical AppArmor alias read unexpectedly admitted')
with socket.create_connection(('postgres.devres-acceptance.svc.cluster.local',5432),timeout=5):
    pass
addresses=socket.getaddrinfo('kubernetes.default.svc.cluster.local',443,type=socket.SOCK_STREAM)
assert addresses
denied=0
for family,kind,protocol,_name,address in addresses:
    connection=socket.socket(family,kind,protocol)
    connection.settimeout(2)
    try:
        connection.connect(address)
    except OSError:
        denied+=1
    else:
        raise AssertionError('assessment egress unexpectedly admitted local API')
    finally:
        connection.close()
assert denied==len(addresses)
print(json.dumps({'dns':True,'postgres_tcp':True,'local_api_denied':True,'public_requests':0,
                  'apparmor_enforcing':True,'canonical_alias_read_denied':True}))
"""]
    cluster.create(pod)
    admitted = cluster.pod('assessment-network')
    uid = admitted['metadata']['uid']
    primary = None
    try:
        need(probe_authority(cluster, pod, admitted) == uid, 'assessment_egress_evidence_invalid')
        cluster.k('wait', '--for=jsonpath={.status.phase}=Succeeded', 'pod/assessment-network', '--timeout=40s', timeout=50)
        value = json.loads(cluster.k('logs', 'assessment-network', maximum=4096).stdout)
        need(value == {'dns': True, 'postgres_tcp': True, 'local_api_denied': True, 'public_requests': 0,
             'apparmor_enforcing': True, 'canonical_alias_read_denied': True}, 'assessment_egress_evidence_invalid')
        return value
    except BaseException as error:
        primary = error
        # This Pod mounts no configuration, credentials or corpus. Inspect only
        # its fixed first-party probe output in memory before UID-fenced cleanup.
        try:
            error.probe_metadata = network_failure_metadata(cluster, uid)
        except BaseException:
            pass
        raise
    finally:
        try:
            cluster.delete('assessment-network', uid)
        except BaseException:
            if primary is not None:
                raise primary from None
            raise


def validate_probe_failure(value):
    need(type(value) is dict and set(value) == {'pod_phase', 'container_reason', 'exit_code', 'network'},
         'fixture_receipt_probe')
    need(type(value['pod_phase']) is str and value['pod_phase'] in ('Pending', 'Running', 'Succeeded', 'Failed', 'Unknown', 'unknown')
         and type(value['container_reason']) is str and value['container_reason'] in helper().POD_REASONS | {'none', 'unknown'}
         and type(value['network']) is str and value['network'] in PROBE_NETWORK_CODES, 'fixture_receipt_probe')
    need(value['exit_code'] is None or type(value['exit_code']) is int and 0 <= value['exit_code'] <= 255,
         'fixture_receipt_probe')


def network_failure_metadata(cluster, uid):
    value = {'pod_phase': 'unknown', 'container_reason': 'unknown', 'exit_code': None, 'network': 'unknown'}
    try:
        before = json.loads(cluster.k('get', 'pod', 'assessment-network', '-o', 'json', timeout=5).stdout)
        need(before['metadata']['uid'] == uid, 'assessment_process_changed')
        output = cluster.k('logs', 'assessment-network', '--limit-bytes=4096', check=False,
                           maximum=4096, timeout=5).stdout
        after = json.loads(cluster.k('get', 'pod', 'assessment-network', '-o', 'json', timeout=5).stdout)
        need(after['metadata']['uid'] == uid
             and before.get('status', {}).get('containerStatuses') == after.get('status', {}).get('containerStatuses'),
             'assessment_process_changed')
        status = after.get('status', {})
        phase = status.get('phase')
        if phase in ('Pending', 'Running', 'Succeeded', 'Failed', 'Unknown'):
            value['pod_phase'] = phase
        containers = status.get('containerStatuses', [])
        state = containers[0].get('state', {}) if len(containers) == 1 else {}
        detail = state.get('terminated', state.get('waiting', {}))
        reason = detail.get('reason', 'none')
        if reason in helper().POD_REASONS | {'none'}:
            value['container_reason'] = reason
        code = detail.get('exitCode')
        if type(code) is int and 0 <= code <= 255:
            value['exit_code'] = code
        # Only finite categories derived from the controlled probe are retained.
        # Runtime messages, traceback text, addresses and file paths have no field.
        if b'assessment egress unexpectedly admitted local API' in output:
            value['network'] = 'api_admitted'
        elif b'gaierror' in output:
            value['network'] = 'dns_failure'
        elif b'socket.create_connection' in output:
            value['network'] = 'postgres_connection'
        elif 'apparmor' in str(detail.get('message', '')).lower():
            value['network'] = 'apparmor_message'
    except Exception:
        return {'pod_phase': 'unknown', 'container_reason': 'unknown', 'exit_code': None, 'network': 'unknown'}
    return value


def retained_rows_snapshot(cluster):
    """Hash the complete small synthetic database without exporting row bodies."""
    tables = cluster.sql("SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY relname").decode().splitlines()
    need(tables and len(tables) <= 256 and all(re.fullmatch(r'devres_[a-z0-9_]+', table) for table in tables), 'observer_fixture_table_admission')
    rows = []
    for table in tables:
        rows.append("SELECT '" + table + "' AS name,count(*) AS rows,md5(coalesce(string_agg(md5(row_to_json(t)::text),'' ORDER BY md5(row_to_json(t)::text)),'')) AS digest FROM " + table + ' t')
    statement = "BEGIN READ ONLY; SET LOCAL statement_timeout='20s'; SELECT json_agg(row_to_json(v) ORDER BY name) FROM (" + ' UNION ALL '.join(rows) + ') v; COMMIT'
    return json.loads(cluster.sql(statement))


def snapshot(cluster):
    # Tiny synthetic fixture only: retain exact seals and counters, never JSON bodies.
    query = "SELECT json_build_object('schema',(SELECT version FROM devres_schema WHERE singleton),'history',(SELECT coalesce(json_agg(data_integrity ORDER BY job_id,revision),'[]'::json) FROM devres_npm_advisory_job_history),'state',(SELECT coalesce(json_agg(data_integrity ORDER BY key),'[]'::json) FROM devres_npm_state),'admissions',(SELECT count(*) FROM devres_npm_advisory_recoveries),'work',(SELECT count(*) FROM devres_npm_recovery_work),'publication_owners',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())))"
    value = json.loads(cluster.sql(query))
    need(value['publication_owners'] == 0, 'assessment_publication_owner_present')
    value['retained_rows'] = retained_rows_snapshot(cluster)
    return value


RUNTIME_SCRIPT = r'''set -eu
test "$(id -u):$(id -g)" = 65532:65532
test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token
test ! -e /run/devres-writer-identity/token
test ! -e /fixture/cert
printf 'APPARMOR='
cat /proc/self/attr/current
awk '/^Seccomp:/{print "SECCOMP=" $2} /^NoNewPrivs:/{print "NO_NEW_PRIVS=" $2} /^CapEff:/{print "CAP_EFF=" $2}' /proc/self/status
stat -Lc 'CONFIG=%u:%g:%a' /etc/devres/config/serving.toml
stat -c 'TMP=%u:%g:%a' /tmp
'''


def validate_runtime(payload):
    need(len(payload) <= 4096, 'assessment_runtime_bound')
    lines = payload.decode('ascii').splitlines()
    need(len(lines) == 6 and all(line.count('=') == 1 for line in lines), 'assessment_runtime_fields')
    fields = dict(line.split('=', 1) for line in lines)
    need(set(fields) == {'APPARMOR', 'SECCOMP', 'NO_NEW_PRIVS', 'CAP_EFF', 'CONFIG', 'TMP'}, 'assessment_runtime_fields')
    need(fields['APPARMOR'] in ('devres-runtime (enforce)', 'devres-runtime//&unconfined (enforce)'), 'assessment_effective_apparmor')
    need(fields['SECCOMP'] == '2' and fields['NO_NEW_PRIVS'] == '1'
         and fields['CAP_EFF'] == '0000000000000000', 'assessment_effective_restrictions')
    need(fields['CONFIG'] in ('0:65532:440', '0:65532:2440'), 'assessment_config_projection')
    need(re.fullmatch(r'0:65532:2?77[057]', fields['TMP']), 'assessment_tmp_metadata')
    return fields


def assess(cluster, server_image, selected, api, case='success', *, connect_readiness=False):
    cluster.assessment_case = case
    name = 'assessment-' + case
    readiness_policy = case in READINESS_CASES
    selection = api.Selection(selected['job_id'], selected['revision'])
    expected = getattr(cluster, 'expected_image', None)
    if expected is None:
        expected = expected_image_identity(server_image)
        cluster.expected_image = expected
    pod = api.build_assessment_pod(template(server_image), server_image, selection,
                                   name=name, namespace=NAMESPACE, scope=case if readiness_policy else 'fixture',
                                   connect_readiness=connect_readiness or readiness_policy)
    if readiness_policy:
        pod['metadata']['labels']['app'] = ASSESSMENT_APP
    injections = {
        'existing-output': 'mkdir -m 700 /tmp/npm-assessment\n: > /tmp/npm-assessment/report.json\n',
        'ready-denied': 'mkdir -m 700 /tmp/npm-assessment\nmkdir -m 700 /tmp/npm-assessment/ready\n',
        'output-symlink': 'ln -s /run/devres-s3 /tmp/npm-assessment\n',
        'output-wrong-mode': 'mkdir -m 755 /tmp/npm-assessment\n',
        'telemetry-unavailable': 'mkdir -m 000 /tmp/npm-assessment-phases\n',
    }
    if case in injections:
        container = pod['spec']['containers'][0]
        container['command'][-1] = container['command'][-1].replace('umask 077\n', 'umask 077\n' + injections[case], 1)
    if case == 'output-wrong-owner':
        # A root-owned read-only Secret directory is supplied by kubelet without
        # adding root, capabilities, a writable corpus or an init container.
        pod['spec']['containers'][0]['volumeMounts'].append(
            {'name': 's3', 'mountPath': '/tmp/npm-assessment', 'readOnly': True})
    if readiness_policy:
        cluster.create(pod)
    else:
        cluster.apply(pod)
    uid = cluster.pod(name)['metadata']['uid']
    observed = {}
    failures = []
    def get_pod():
        value = cluster.pod(name)
        if readiness_policy:
            metadata = value['metadata']
            need(metadata.get('name') == name and metadata.get('namespace') == NAMESPACE
                 and metadata.get('labels') == pod['metadata']['labels'], 'assessment_readiness_labels_changed')
        statuses = value.get('status', {}).get('containerStatuses', [])
        if len(statuses) == 1:
            observed['image_id'] = statuses[0].get('imageID')
        return value
    def read_report(timeout):
        deadline = time.monotonic() + timeout
        body = api.report_exchange(cluster.argv('exec', name, '--', '/bin/sh', '-c', api.read_script()), timeout=timeout)
        if body is not None:
            remaining = deadline - time.monotonic()
            need(remaining > 0, 'assessment_runtime_deadline')
            runtime = api.report_exchange(cluster.argv('exec', name, '--', '/bin/sh', '-c', RUNTIME_SCRIPT), timeout=min(5, remaining))
            need(runtime is not None, 'assessment_runtime_unavailable')
            observed['runtime'] = validate_runtime(runtime)
        return body
    try:
        _raw, report, events = api.supervise(get_pod=get_pod, read_report=read_report,
            cleanup=lambda: cluster.delete(name, uid), persist=lambda _body: None,
            selection=selection, uid=uid, image=server_image,
            persist_failure=failures.append, timeout=330)
    except api.AssessmentError as error:
        if str(error) != 'assessment_container_ended' or len(failures) != 1:
            raise
        metadata = failures[0].get('last_pod') or {}
        containers = metadata.get('containers', [])
        need(len(containers) == 1, 'assessment_terminal_metadata_missing')
        result = {'case': case, 'phase': 'terminal', 'exit_code': containers[0]['exit_code'],
                  'diagnostics': failures[0]['phases'],
                  'image_identity': resolved_image_identity(cluster, observed.get('image_id'), expected)}
        receipt(cluster, 'case-' + name + '-result.json', {'version': 1, 'synthetic': True, 'result': result})
        return result
    need(report['reason'] == 'legacy_unknown' and report['eligible'] is False, 'synthetic_legacy_reason_required')
    result = {'case': case, 'phase': 'report_transferred', 'report': report,
              'events': events, 'runtime': observed['runtime'],
              'image_identity': resolved_image_identity(cluster, observed.get('image_id'), expected)}
    receipt(cluster, 'case-' + name + '-result.json', {'version': 1, 'synthetic': True, 'result': result})
    return result


def set_config(cluster, text):
    cluster.apply({'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
                   'metadata': {'name': 'devres-assessment-config', 'namespace': NAMESPACE},
                   'data': {'serving.toml': base64.b64encode(text.encode()).decode()}})


@contextlib.contextmanager
def lifecycle_exclusion(cluster, harness_image):
    pod = template(harness_image)
    pod.update({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'assessment-lifecycle-holder',
                'namespace': NAMESPACE, 'labels': {'app': 'backend'}}})
    pod['spec'].update({'restartPolicy': 'Never', 'activeDeadlineSeconds': 150})
    pod['spec']['volumes'] = [{'name': 'tmp', 'emptyDir': {'sizeLimit': '16Mi'}}]
    container = pod['spec']['containers'][0]
    container['name'] = 'holder'
    container['volumeMounts'] = [{'name': 'tmp', 'mountPath': '/tmp'}]
    container['env'] = [{'name': 'PGPASSWORD', 'value': 'fixture-only'},
                        {'name': 'PGAPPNAME', 'value': 'devres-assessment-lifecycle-fixture'}]
    # Keep the server session idle while a trusted local psql shell command
    # sleeps. Closing the owned Pod then releases an idle session immediately,
    # rather than leaving a server-side pg_sleep running after client death.
    holder = ("printf '%s\\n' 'SELECT pg_advisory_lock(1835365490,2);' '\\! sleep 120' "
              "'SELECT pg_advisory_unlock(1835365490,2);' | "
              "psql -X -q -h postgres.devres-acceptance.svc.cluster.local -U devres -d "
              + DATABASE + ' -v ON_ERROR_STOP=1')
    container['command'] = ['/bin/sh', '-c', holder]
    cluster.apply(pod)
    uid = cluster.pod('assessment-lifecycle-holder')['metadata']['uid']
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            raw = cluster.sql("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=2 AND mode='ExclusiveLock' AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")
            if raw.strip() == b'1':
                yield
                return
            time.sleep(.25)
        raise FixtureError('fixture_lifecycle_holder_not_ready')
    finally:
        cluster.delete('assessment-lifecycle-holder', uid)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            sessions = cluster.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name='devres-assessment-lifecycle-fixture'")
            locks = cluster.sql("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=2 AND mode='ExclusiveLock' AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")
            if sessions.strip() == locks.strip() == b'0':
                break
            time.sleep(.25)
        else:
            raise FixtureError('fixture_lifecycle_holder_cleanup_incomplete')


def failure_matrix(cluster, server_image, selected, api, config, harness_image, *, connect_readiness=False):
    cluster.assessment_case = 'none'
    seal = cluster.sql('SELECT data_integrity FROM devres_npm_advisory_job_history').decode().strip()
    need(re.fullmatch('blake3:[0-9a-f]{64}', seal), 'synthetic_original_history_seal_required')
    def history_seal(value):
        return ("BEGIN; ALTER TABLE devres_npm_advisory_job_history DISABLE TRIGGER devres_npm_history_immutable; "
                "UPDATE devres_npm_advisory_job_history SET data_integrity='" + value
                + "'; ALTER TABLE devres_npm_advisory_job_history ENABLE TRIGGER devres_npm_history_immutable; COMMIT")
    cases = (
        ('malformed-config', 'config_load', config + '\ninvalid toml = [\n', None, None),
        ('wrong-dns', 'sql_connect', config.replace('postgres.devres-acceptance.svc.cluster.local', 'absent.devres-assessment.svc.cluster.local'), None, None),
        ('bad-password', 'sql_connect', config.replace('assessment-fixture-only@', 'wrong-synthetic-password@'), None, None),
        ('existing-output', 'output_create', config, None, None),
        ('output-symlink', 'output_create', config, None, None),
        ('output-wrong-mode', 'output_create', config, None, None),
        ('output-wrong-owner', 'output_create', config, None, None),
        ('ready-denied', 'ready_write', config, None, None),
        ('wrong-schema', 'schema', config, 'UPDATE devres_schema SET version=18 WHERE singleton', 'UPDATE devres_schema SET version=19 WHERE singleton'),
        ('restore-pending', 'schema', config, 'CREATE TABLE devres_archive_restore_pending(singleton boolean)', 'DROP TABLE devres_archive_restore_pending'),
        ('corrupt-history', 'history_select', config, history_seal('blake3:' + '0' * 64), history_seal(seal)),
        ('missing-grant', 'history_select', config, 'REVOKE SELECT ON devres_npm_advisory_job_history FROM devres_assessment_reader', 'GRANT SELECT ON devres_npm_advisory_job_history TO devres_assessment_reader'),
        ('held-lifecycle', 'lifecycle', config, None, None),
        ('telemetry-unavailable', None, config, None, None),
    )
    if connect_readiness:
        need(cluster.sql('SHOW ssl').strip() == b'off', 'assessment_readiness_result')
        cases += (('required-tls', 'sql_connect', configuration(config, DATABASE_READER + '?sslmode=require'), None, None),)
    results = []
    before = snapshot(cluster)
    for case, expected, candidate, setup, restore in cases:
        cluster.assessment_case = case
        readiness_fault = connect_readiness and case in READINESS_FAULTS
        set_config(cluster, candidate)
        try:
            if setup:
                cluster.sql(setup)
            with lifecycle_exclusion(cluster, harness_image) if case == 'held-lifecycle' else contextlib.nullcontext():
                result = assess(cluster, server_image, selected, api, case, connect_readiness=readiness_fault)
            if case == 'telemetry-unavailable':
                need(result['phase'] == 'report_transferred' and result['events'] is None,
                     'assessment_telemetry_changed_original_success')
                results.append(result)
                need(snapshot(cluster) == before, 'assessment_fault_mutated_retained_metadata')
                continue
            need(result['phase'] == 'terminal' and type(result['exit_code']) is int
                 and result['exit_code'] != 0, 'assessment_fault_not_observed')
            events = result['diagnostics']
            need(isinstance(events, list) and any(event['phase'] == expected and event['outcome'] == 'error'
                                                 for event in events), 'assessment_fault_phase_unknown')
            if readiness_fault:
                need(not any(event['phase'] == 'sql_connect_retry' for event in events)
                     and any(event['phase'] == expected and event['outcome'] == 'error'
                             and event['reason'] == READINESS_FAULTS[case] for event in events),
                     'assessment_readiness_result')
            starts = [event for event in events if event['phase'] == 'cli_start']
            exits = [event for event in events if event['phase'] == 'cli_exit']
            need(len(starts) == len(exits) == 1, 'assessment_attempt_count_changed')
            need((exits[0]['child_exit'] == 0) == (case == 'ready-denied'), 'assessment_child_wrapper_status_confused')
            results.append(result)
        finally:
            if restore:
                cluster.sql(restore)
            set_config(cluster, config)
        need(snapshot(cluster) == before, 'assessment_fault_mutated_retained_metadata')
    return results


def run(arguments):
    scratch = Path(arguments.scratch).resolve(strict=True)
    need(Path('/tmp') in scratch.parents and scratch.stat().st_uid == os.getuid(), 'owned_tmp_fixture_required')
    need(not os.environ.get('DOCKER_CONTEXT'), 'fixture_docker_context_refused')
    cluster = Cluster(arguments.profile, scratch)
    progress = {'phase': 'admission', 'namespace_cleanup': 'not-created',
                'apparmor_cleanup': 'unknown', 'primary': None, 'primary_phase': None}
    try:
        run_fixture(arguments, cluster, progress)
    except BaseException as error:
        primary = progress['primary'] or error
        if error is primary and progress['primary'] is not None and progress['namespace_cleanup'] == 'removed':
            # The original exception survived the AppArmor context's finally
            # block, so its checked unload also completed successfully.
            progress['apparmor_cleanup'] = 'removed'
        record = {'version': 1, 'synthetic': True,
            'phase': progress['primary_phase'] or progress['phase'],
            'case': getattr(cluster, 'assessment_case', 'none'), 'failure': closed_failure(primary),
            'cleanup_failure': None if error is primary else closed_failure(error),
            'namespace_cleanup': progress['namespace_cleanup'], 'apparmor_cleanup': progress['apparmor_cleanup']}
        probe = getattr(primary, 'probe_metadata', None)
        if probe is not None:
            try:
                validate_probe_failure(probe)
                record['probe'] = probe
            except BaseException:
                pass
        # Cleanup attempts precede persistence; lost diagnostics never replace
        # the primary failure or keep a credential-bearing participant alive.
        try:
            receipt(cluster, 'npm-assessment-setup-failure.json', record)
        except BaseException:
            pass
        raise primary from None


def run_fixture(arguments, cluster, progress):
    scratch = cluster.scratch
    api = helper()
    connect_readiness = getattr(arguments, 'connect_readiness', False)
    need(not cluster.owned_objects('namespace') and not cluster.owned_objects('policy'),
         'fresh_assessment_namespace_required')
    if connect_readiness:
        need(not cluster.owned_objects('readiness_policy'), 'fresh_assessment_namespace_required')
    cluster.fixture_owner = secrets.token_hex(16)
    cluster.namespace_uid = cluster.policy_uid = cluster.readiness_policy_uid = None
    namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NAMESPACE,
        'labels': {FIXTURE_OWNER_LABEL: cluster.fixture_owner,
                   'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'latest'}}}
    progress['phase'] = 'node-preparation'
    prepared_node = prepare_node_apparmor(cluster, arguments.server_image)
    cleanup_confirmed = [True]
    progress['phase'] = 'apparmor'
    with apparmor(scratch, lambda: cleanup_confirmed[0]) as profile_hash:
        created = False
        policy_attempted = False
        readiness_policy_attempted = False
        try:
            progress['phase'] = 'namespace'
            # An uncertain apply response still requires owned-namespace cleanup.
            created = True
            cleanup_confirmed[0] = False
            progress['namespace_cleanup'] = 'incomplete'
            cluster.create(namespace)
            cluster.admit_owned('namespace')
            progress['phase'] = 'identity'
            cluster.apply({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'assessment', 'namespace': NAMESPACE}, 'automountServiceAccountToken': False})
            progress['phase'] = 'policy'
            documents = policies()
            for document in documents:
                document['metadata'].setdefault('labels', {})[FIXTURE_OWNER_LABEL] = cluster.fixture_owner
            policy_attempted = True
            cluster.create(documents)
            cluster.admit_owned('policy')
            progress['phase'] = 'configuration'
            config = configuration((scratch / 'fixture/backend.toml').read_text())
            config_path = scratch / 'assessment-serving.toml'
            descriptor = os.open(config_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(config)
            cluster.k('create', 'secret', 'generic', 'devres-assessment-config', '--from-file=serving.toml=' + str(config_path))
            cluster.k('create', 'secret', 'generic', 'devres-assessment-s3', '--from-literal=access-key=synthetic-unused', '--from-literal=secret-key=synthetic-unused')
            progress['phase'] = 'network'
            network = network_probe(cluster, arguments.harness_image)
            progress['phase'] = 'seed'
            selected = seed(cluster, arguments.harness_image)
            progress['phase'] = 'baseline'
            before = snapshot(cluster)
            progress['phase'] = 'positive'
            result = assess(cluster, arguments.server_image, selected, api)
            need(result['phase'] == 'report_transferred', 'assessment_positive_failed')
            progress['phase'] = 'invariants'
            need(snapshot(cluster) == before, 'assessment_mutated_retained_metadata')
            progress['phase'] = 'matrix'
            faults = failure_matrix(cluster, arguments.server_image, selected, api, config, arguments.harness_image,
                                    connect_readiness=connect_readiness)
            result_receipt = {'version': 1, 'synthetic': True, 'apparmor_sha256': profile_hash,
                       'server_image': arguments.server_image, 'provider_requests': 0,
                       'selection': selected, 'network': network, 'result': result, 'faults': faults, 'metadata_unchanged': True}
            if connect_readiness:
                progress['phase'] = 'connect-readiness'
                cluster.assessment_case = 'none'
                documents = readiness_policies()
                for document in documents:
                    document['metadata']['labels'] = {FIXTURE_OWNER_LABEL: cluster.fixture_owner}
                readiness_policy_attempted = True
                cluster.create(documents)
                outbound_spec = documents[0]
                outbound = json.loads(cluster.k('get', 'networkpolicy', outbound_spec['metadata']['name'], '-o', 'json').stdout)
                inbound = cluster.owned_objects('readiness_policy')
                cluster.admit_owned('readiness_policy', inbound)
                need(outbound.get('spec') == outbound_spec['spec']
                     and all(outbound.get('metadata', {}).get(key) == value
                             for key, value in outbound_spec['metadata'].items())
                     and inbound[0].get('spec') == documents[1]['spec'], 'assessment_readiness_policy_changed')
                readiness = []
                for case in READINESS_CASES:
                    readiness_result = assess(cluster, arguments.server_image, selected, api, case)
                    validate_readiness_result(readiness_result)
                    need(snapshot(cluster) == before, 'assessment_mutated_retained_metadata')
                    readiness.append(readiness_result)
                result_receipt['readiness'] = readiness
        except BaseException as error:
            progress['primary'] = error
            progress['primary_phase'] = progress['phase']
            raise
        finally:
            # Never keep a credential-bearing Pod alive for receipt persistence.
            if created:
                progress['phase'] = 'cleanup'
                failures = []

                def cleanup(kind):
                    try:
                        cluster.cleanup_owned(kind)
                    except BaseException as error:
                        failures.append(error)

                ingress = []
                if policy_attempted:
                    ingress.append('policy')
                if readiness_policy_attempted:
                    ingress.append('readiness_policy')
                cleanup('namespace')
                if not connect_readiness:
                    for kind in ingress:
                        cleanup(kind)
                try:
                    need(not cluster.owned_objects('namespace'), 'assessment_namespace_cleanup_unconfirmed')
                    progress['namespace_cleanup'] = 'removed'
                except BaseException as error:
                    failures.append(error)
                if connect_readiness and progress['namespace_cleanup'] == 'removed':
                    for kind in ingress:
                        cleanup(kind)
                if failures:
                    if progress['primary'] is None:
                        progress['primary'] = failures[0]
                        progress['primary_phase'] = 'cleanup'
                    raise failures[0]
                cleanup_confirmed[0] = True
    progress['apparmor_cleanup'] = 'removed'
    progress['phase'] = 'node-restoration'
    restore_node_apparmor(cluster, prepared_node)
    need(not getattr(cluster, 'receipt_failures', []), 'fixture_evidence_retention_incomplete')
    need(receipt(cluster, 'npm-assessment-receipt.json', result_receipt), 'fixture_evidence_retention_incomplete')
    print('Synthetic real-image Kubernetes npm recovery assessment passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--scratch', required=True)
    parser.add_argument('--harness-image', required=True)
    parser.add_argument('--server-image', required=True)
    parser.add_argument('--prepare-image-only', action='store_true')
    parser.add_argument('--connect-readiness', action='store_true',
                        help='also test cold and denied connections using a readiness-capable server image')
    try:
        arguments = parser.parse_args()
        if arguments.prepare_image_only and arguments.connect_readiness:
            parser.error('--connect-readiness requires running the assessment fixture')
        if arguments.prepare_image_only:
            prepare_image(arguments)
        else:
            run(arguments)
    except FixtureError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('npm assessment fixture failed; no raw command output retained', file=sys.stderr)
        sys.exit(1)
