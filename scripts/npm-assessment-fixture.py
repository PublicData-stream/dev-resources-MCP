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
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tarfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = 'devres-assessment'
DATABASE = 'devres_assessment_fixture'
PROFILE = 'devres-runtime'
APPARMOR_SHA256 = '4375146629c956b8e63cc4b358ef52c6bcda458621b7dcf8601b0f3d922b3e7e'
MAX_METADATA = 2 * 1024 * 1024
IMAGE_DIGEST = r'sha256:[0-9a-f]{64}'
MAX_IMAGE_METADATA = 1024 * 1024
DATABASE_ADMIN = 'postgres://devres:fixture-only@postgres.devres-acceptance.svc.cluster.local/' + DATABASE
DATABASE_READER = 'postgres://devres_assessment_reader:assessment-fixture-only@postgres.devres-acceptance.svc.cluster.local/' + DATABASE


class FixtureError(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise FixtureError(code)


def command(args, *, data=None, timeout=60, check=True, maximum=MAX_METADATA):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout, check=False)
    need(len(result.stdout) <= maximum and len(result.stderr) <= MAX_METADATA, 'fixture_command_output_bound')
    if check:
        need(result.returncode == 0, 'fixture_command_failed')
    return result


def docker_config_digests(image, timeout=32):
    """Read bounded save metadata in a stream; never extract or retain layers."""
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
    'restore-pending', 'corrupt-history', 'missing-grant', 'held-lifecycle', 'telemetry-unavailable'))


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
    if name == 'npm-assessment-receipt.json':
        need(set(value) == {'version', 'synthetic', 'apparmor_sha256', 'server_image', 'provider_requests', 'selection',
                            'network', 'result', 'faults', 'metadata_unchanged'}, 'fixture_receipt_fields')
        need(value['apparmor_sha256'] == APPARMOR_SHA256 and value['provider_requests'] == 0
             and value['metadata_unchanged'] is True and type(value['server_image']) is str
             and re.fullmatch(r'[A-Za-z0-9._:/@+\-]{1,256}', value['server_image']), 'fixture_receipt_assessment')
        selected = value['selection']
        need(type(selected) is dict and set(selected) == {'version', 'schema', 'job_id', 'revision', 'cause_authoritative', 'synthetic'}
             and selected['version'] == 1 and selected['schema'] == 19 and selected['revision'] == 1
             and selected['cause_authoritative'] is False and selected['synthetic'] is True, 'fixture_receipt_selection')
        api.Selection(selected['job_id'], selected['revision']).validate()
        need(value['network'] == {'dns': True, 'postgres_tcp': True, 'local_api_denied': True, 'public_requests': 0}, 'fixture_receipt_network')
        result(value['result'])
        need(type(value['faults']) is list and len(value['faults']) == 14, 'fixture_receipt_faults')
        for record in value['faults']:
            result(record)
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
         'metadata': {'name': 'postgres-owned-assessment', 'namespace': 'devres-acceptance'},
         'spec': {'podSelector': {'matchLabels': {'app': 'postgres'}}, 'policyTypes': ['Ingress'],
                  'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': NAMESPACE}},
                                         'podSelector': {'matchLabels': {'app': 'backend'}}}],
                               'ports': [{'port': 5432, 'protocol': 'TCP'}]}]}}]


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
        if not isinstance(objects, list):
            objects = [objects]
        return self.k('apply', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}).encode())

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


def seed(cluster, image):
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
    container['env'] = [{'name': 'DATABASE_URL', 'value': DATABASE_ADMIN}, {'name': 'DEVRES_SYNTHETIC_ASSESSMENT', 'value': '1'}]
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


def network_probe(cluster, image):
    """A denied destination is a local Kubernetes API, never a public provider."""
    pod = template(image)
    pod.update({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'assessment-network',
                'namespace': NAMESPACE, 'labels': {'app': 'backend'}}})
    pod['spec'].update({'restartPolicy': 'Never', 'activeDeadlineSeconds': 30})
    pod['spec']['volumes'] = [{'name': 'tmp', 'emptyDir': {'sizeLimit': '16Mi'}}]
    container = pod['spec']['containers'][0]
    container['name'] = 'probe'
    container['volumeMounts'] = [{'name': 'tmp', 'mountPath': '/tmp'}]
    container['command'] = ['python3', '-I', '-B', '-c', """
import json,socket
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
print(json.dumps({'dns':True,'postgres_tcp':True,'local_api_denied':True,'public_requests':0}))
"""]
    cluster.apply(pod)
    uid = cluster.pod('assessment-network')['metadata']['uid']
    try:
        cluster.k('wait', '--for=jsonpath={.status.phase}=Succeeded', 'pod/assessment-network', '--timeout=40s', timeout=50)
        value = json.loads(cluster.k('logs', 'assessment-network', maximum=4096).stdout)
        need(value == {'dns': True, 'postgres_tcp': True, 'local_api_denied': True, 'public_requests': 0}, 'assessment_egress_evidence_invalid')
        return value
    finally:
        cluster.delete('assessment-network', uid)


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


def assess(cluster, server_image, selected, api, case='success'):
    name = 'assessment-' + case
    selection = api.Selection(selected['job_id'], selected['revision'])
    expected = getattr(cluster, 'expected_image', None)
    if expected is None:
        expected = expected_image_identity(server_image)
        cluster.expected_image = expected
    pod = api.build_assessment_pod(template(server_image), server_image, selection,
                                   name=name, namespace=NAMESPACE, scope='fixture')
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
    cluster.apply(pod)
    uid = cluster.pod(name)['metadata']['uid']
    observed = {}
    failures = []
    def get_pod():
        value = cluster.pod(name)
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


def failure_matrix(cluster, server_image, selected, api, config, harness_image):
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
    results = []
    before = snapshot(cluster)
    for case, expected, candidate, setup, restore in cases:
        set_config(cluster, candidate)
        try:
            if setup:
                cluster.sql(setup)
            with lifecycle_exclusion(cluster, harness_image) if case == 'held-lifecycle' else contextlib.nullcontext():
                result = assess(cluster, server_image, selected, api, case)
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
    cluster = Cluster(arguments.profile, scratch)
    api = helper()
    namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NAMESPACE,
        'labels': {'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'latest'}}}
    need(cluster.k('get', 'namespace', NAMESPACE, '-o', 'name', check=False).returncode != 0, 'fresh_assessment_namespace_required')
    cleanup_confirmed = [True]
    with apparmor(scratch, lambda: cleanup_confirmed[0]) as profile_hash:
        created = False
        try:
            cluster.apply(namespace)
            created = True
            cleanup_confirmed[0] = False
            cluster.apply({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'assessment', 'namespace': NAMESPACE}, 'automountServiceAccountToken': False})
            cluster.apply(policies())
            config = configuration((scratch / 'fixture/backend.toml').read_text())
            config_path = scratch / 'assessment-serving.toml'
            descriptor = os.open(config_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(config)
            cluster.k('create', 'secret', 'generic', 'devres-assessment-config', '--from-file=serving.toml=' + str(config_path))
            cluster.k('create', 'secret', 'generic', 'devres-assessment-s3', '--from-literal=access-key=synthetic-unused', '--from-literal=secret-key=synthetic-unused')
            network = network_probe(cluster, arguments.harness_image)
            selected = seed(cluster, arguments.harness_image)
            before = snapshot(cluster)
            result = assess(cluster, arguments.server_image, selected, api)
            need(result['phase'] == 'report_transferred', 'assessment_positive_failed')
            need(snapshot(cluster) == before, 'assessment_mutated_retained_metadata')
            faults = failure_matrix(cluster, arguments.server_image, selected, api, config, arguments.harness_image)
            result_receipt = {'version': 1, 'synthetic': True, 'apparmor_sha256': profile_hash,
                       'server_image': arguments.server_image, 'provider_requests': 0,
                       'selection': selected, 'network': network, 'result': result, 'faults': faults, 'metadata_unchanged': True}
            receipt(cluster, 'npm-assessment-receipt.json', result_receipt)
        finally:
            # Never keep a credential-bearing Pod alive for receipt persistence.
            if created:
                cluster.k('delete', 'namespace', NAMESPACE, '--wait=true', '--timeout=120s', timeout=130)
                cluster.k('delete', 'networkpolicy', 'postgres-owned-assessment', '--ignore-not-found', namespace='devres-acceptance')
                namespaces = json.loads(cluster.k('get', 'namespaces', '-o', 'json').stdout)
                need(not any(item['metadata']['name'] == NAMESPACE for item in namespaces['items']), 'assessment_namespace_cleanup_unconfirmed')
                cleanup_confirmed[0] = True
    need(not getattr(cluster, 'receipt_failures', []), 'fixture_evidence_retention_incomplete')
    print('Synthetic real-image Kubernetes npm recovery assessment passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--scratch', required=True)
    parser.add_argument('--harness-image', required=True)
    parser.add_argument('--server-image', required=True)
    try:
        run(parser.parse_args())
    except FixtureError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('npm assessment fixture failed; no raw command output retained', file=sys.stderr)
        sys.exit(1)
