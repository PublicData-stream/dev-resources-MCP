#!/usr/bin/env python3
"""Exercise the exact server image against the B130E K3s policy controller offline."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
K3S_VERSION = 'v1.37.2+k3s1'
K3S_IMAGE = 'docker.io/rancher/k3s@sha256:21ea6e0fac4e3930c2ce8aa40ddd41a8b18cb3e9a0222c030dc005e7e88c4332'
AIRGAP_SHA256 = '35a5af1e69b57b8b627a4f6b1c29ea104209b661067b8c97fd40dc3f860bfcd2'
AIRGAP_SIZE = 198293778
POSTGRES_IMAGE = 'postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395'
POSTGRES_AMD64 = 'sha256:300ebd02c6d4de9ee27ad7f6855d5d21b4d3a4a5117767c1197d284c635d9736'
POSTGRES_CONFIG = 'sha256:38b9ffe2d4c13d7c445b66306be6763dfa6f503689ea0c5b9f84544ccf3ca8e4'
POSTGRES_LOCAL_TAG = 'docker.io/library/postgres:devres-fixture-native'
APPARMOR_PARSER = '/usr/sbin/apparmor_parser'
APP = 'devres-npm-assessment'
INGRESS = 'assessment-postgres-ingress'
EGRESS = 'assessment-dns-postgres-egress'
OBSERVER = 'status-observer'
OBSERVER_SECRET = 'status-observer-config'
OBSERVER_POLICIES = ('observer-postgres-ingress', 'observer-dns-postgres-egress')
NATURAL_TRIALS = 10
NODE = 'k3s-fixture'
CONTAINERD = '/run/k3s/containerd/containerd.sock'
GIB = 1024 ** 3
NODEFS_BYTES = GIB
IMAGEFS_BYTES = 8 * GIB
# This pinned K3s release sets its own kubelet defaults in agent.go.
DEFAULT_HARD_EVICTION = {'nodefs.available': '5%', 'imagefs.available': '5%'}
DEFAULT_RECLAIM = {'nodefs.available': '10%', 'imagefs.available': '10%'}
BOOT = '''
ip link add eth0 type dummy
ip address add 192.0.2.2/24 dev eth0
ip link set eth0 up
ip route add default via 192.0.2.1 dev eth0
exec /bin/k3s server --node-name k3s-fixture --node-ip 192.0.2.2 \
  --flannel-iface eth0 --flannel-backend vxlan --kube-proxy-arg proxy-mode=iptables \
  --disable traefik --disable servicelb --disable metrics-server --disable local-storage \
  --disable gateway-api-crd --snapshotter overlayfs
'''
_spec = importlib.util.spec_from_file_location('npm_readiness_fixture', ROOT / 'scripts/npm-assessment-fixture.py')
fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fixture)
_proof_spec = importlib.util.spec_from_file_location(
    'observer_retained_rows', ROOT / 'deploy/production/observer_retained_rows.py')
proof = importlib.util.module_from_spec(_proof_spec)
_proof_spec.loader.exec_module(proof)
# The synthetic seed binary admits only this fixture database's Service DNS name.
NAMESPACE = fixture.DATABASE_NAMESPACE
APPARMOR_PROFILE = fixture.PROFILE
assessment = fixture.helper()


def command(args, *, code, data=None, timeout=15, maximum=fixture.MAX_METADATA):
    """Print no child output. Even synthetic configuration stays in the fixture."""
    try:
        return fixture.command(args, data=data, timeout=timeout, maximum=maximum).stdout
    except (fixture.FixtureError, OSError, subprocess.SubprocessError):
        raise fixture.FixtureError(code) from None


def scratch_path(path):
    path = Path(path).absolute()
    parent = path.parent.resolve(strict=True)
    fixture.need(path.parent == parent and Path('/tmp') in parent.parents
                 and parent.stat().st_uid == os.getuid() and not parent.stat().st_mode & 0o022,
                 'private_k3s_input_path_required')
    return path


def copy_airgap(path, output):
    descriptor = os.open(scratch_path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source, output.open('xb') as target:
        info = os.fstat(source.fileno())
        fixture.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                     and info.st_size == AIRGAP_SIZE, 'official_k3s_archive_required')
        digest = hashlib.sha256()
        remaining = AIRGAP_SIZE
        while remaining:
            payload = source.read(min(remaining, 1024 * 1024))
            fixture.need(bool(payload), 'official_k3s_archive_required')
            target.write(payload)
            digest.update(payload)
            remaining -= len(payload)
        fixture.need(not source.read(1) and digest.hexdigest() == AIRGAP_SHA256,
                     'official_k3s_archive_required')


def verify_postgres_archive(path, *, normalized=False):
    """Read only the pinned single-platform OCI graph, without extracting it."""
    code = 'official_postgres_oci_archive_required'
    with tarfile.open(path, mode='r:') as archive:
        members = {}
        directories = set()
        for member in archive:
            if member.isdir():
                fixture.need(member.name in ('blobs', 'blobs/sha256') and member.name not in directories, code)
                directories.add(member.name)
                continue
            fixture.need(member.isfile() and not member.sparse and member.name not in members and len(members) < 20
                         and (member.name in ('index.json', 'oci-layout')
                              or re.fullmatch(r'blobs/sha256/[a-f0-9]{64}', member.name)), code)
            members[member.name] = member

        def metadata(name):
            member = members[name]
            fixture.need(0 < member.size <= 64 * 1024, code)
            with archive.extractfile(member) as stream:
                return stream.read()

        layout = json.loads(metadata('oci-layout'))
        index = json.loads(metadata('index.json'))
        fixture.need(layout == {'imageLayoutVersion': '1.0.0'} and set(index) == {'schemaVersion', 'manifests'}
                     and index['schemaVersion'] == 2
                     and len(index['manifests']) == 1, code)
        entry = index['manifests'][0]
        annotations = {'org.opencontainers.image.ref.name': 'postgres'}
        if normalized:
            annotations['io.containerd.image.name'] = POSTGRES_LOCAL_TAG
        fixture.need(set(entry) == {'digest', 'size', 'mediaType', 'annotations'}
                     and entry['digest'] == POSTGRES_AMD64
                     and entry['mediaType'] == 'application/vnd.oci.image.manifest.v1+json'
                     and entry['annotations'] == annotations, code)
        manifest_name = 'blobs/sha256/' + POSTGRES_AMD64.split(':', 1)[1]
        manifest_raw = metadata(manifest_name)
        fixture.need(len(manifest_raw) == entry['size'] and
                     'sha256:' + hashlib.sha256(manifest_raw).hexdigest() == POSTGRES_AMD64, code)
        manifest = json.loads(manifest_raw)
        fixture.need(manifest['schemaVersion'] == 2 and manifest['config']['digest'] == POSTGRES_CONFIG
                     and 1 <= len(manifest['layers']) <= 12, code)
        referenced = {'index.json', 'oci-layout', manifest_name}
        for item in [manifest['config'], *manifest['layers']]:
            fixture.need(re.fullmatch(fixture.IMAGE_DIGEST, item['digest']), code)
            name = 'blobs/sha256/' + item['digest'].split(':', 1)[1]
            member = members[name]
            fixture.need(member.size == item['size'] and name not in referenced, code)
            with archive.extractfile(member) as stream:
                fixture.need('sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() == item['digest'], code)
            referenced.add(name)
        config = json.loads(metadata('blobs/sha256/' + POSTGRES_CONFIG.split(':', 1)[1]))
        fixture.need(referenced == members.keys() and config['architecture'] == 'amd64'
                     and config['os'] == 'linux', code)
        return index


def copy_postgres_archive(input_path, output):
    code = 'official_postgres_oci_archive_required'
    descriptor = os.open(scratch_path(input_path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source, output.open('xb') as target:
        info = os.fstat(source.fileno())
        fixture.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                     and 0 < info.st_size <= 256 * 1024 * 1024, code)
        remaining = info.st_size
        while remaining:
            payload = source.read(min(remaining, 1024 * 1024))
            fixture.need(bool(payload), code)
            target.write(payload)
            remaining -= len(payload)
        fixture.need(not source.read(1), code)
    index = verify_postgres_archive(output)
    # The outer tar index is transport metadata. Name the verified descriptor
    # before CRI observes it, keeping every image blob and its digest intact.
    index['manifests'][0]['annotations']['io.containerd.image.name'] = POSTGRES_LOCAL_TAG
    index_bytes = json.dumps(index).encode()
    named = output.with_name('postgres-named.oci.tar')
    with tarfile.open(output, 'r:') as source, tarfile.open(named, 'x:', format=tarfile.USTAR_FORMAT) as target:
        for member in source:
            clean = tarfile.TarInfo(member.name)
            if member.name == 'index.json':
                clean.size = len(index_bytes)
                target.addfile(clean, io.BytesIO(index_bytes))
            elif member.isfile():
                clean.size = member.size
                with source.extractfile(member) as stream:
                    target.addfile(clean, stream)
    verify_postgres_archive(named, normalized=True)
    named.replace(output)


def object_spec(kind, name, *, version='v1', **content):
    return {'apiVersion': version, 'kind': kind,
            'metadata': {'name': name, 'namespace': NAMESPACE}, **content}


def selector(app):
    return {'matchLabels': {'app': app}}


def policy(name, app, **spec):
    return object_spec('NetworkPolicy', name, version='networking.k8s.io/v1',
                       spec={'podSelector': {} if app is None else selector(app), **spec})


def ingress(name, destination, source):
    return policy(name, destination, policyTypes=['Ingress'],
                  ingress=[{'from': [{'podSelector': selector(source)}],
                            'ports': [{'port': 5432, 'protocol': 'TCP'}]}])


def egress(name, app):
    dns = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
           'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}
    return policy(name, app, policyTypes=['Ingress', 'Egress'], egress=[
        {'to': [dns], 'ports': [{'port': 53, 'protocol': value} for value in ('UDP', 'TCP')]},
        {'to': [{'podSelector': selector('postgres')}], 'ports': [{'port': 5432, 'protocol': 'TCP'}]},
    ])


def postgres(name, image):
    label = {'app': name}
    pg = {'name': 'postgres', 'image': image, 'imagePullPolicy': 'Never',
          'env': [{'name': 'POSTGRES_USER', 'value': 'devres'},
                  {'name': 'PGDATA', 'value': '/var/lib/postgresql/18/docker'},
                  {'name': 'POSTGRES_PASSWORD_FILE', 'value': '/run/postgres-fixture/password'}],
          'ports': [{'containerPort': 5432, 'name': 'pg'}],
          'readinessProbe': {'exec': {'command': ['pg_isready', '-q', '-h', '127.0.0.1']}, 'periodSeconds': 1},
          'volumeMounts': [{'name': 'data', 'mountPath': '/var/lib/postgresql'},
                           {'name': 'password', 'mountPath': '/run/postgres-fixture', 'readOnly': True}],
          'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'memory': '512Mi'}},
          'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']},
                              'appArmorProfile': apparmor_profile()}}
    pod = {'automountServiceAccountToken': False,
           'securityContext': {'runAsNonRoot': True, 'runAsUser': 70, 'runAsGroup': 70, 'fsGroup': 70,
                               'seccompProfile': {'type': 'RuntimeDefault'}},
           'volumes': [{'name': 'data', 'emptyDir': {'sizeLimit': '256Mi'}},
                       {'name': 'password', 'secret': {'secretName': 'postgres-fixture', 'defaultMode': 0o440}}],
           'containers': [pg]}
    deployment = object_spec('Deployment', name, version='apps/v1', spec={
        'replicas': 1, 'selector': selector(name), 'template': {'metadata': {'labels': label}, 'spec': pod}})
    service = object_spec('Service', name, spec={
        'selector': label, 'ports': [{'port': 5432, 'protocol': 'TCP', 'targetPort': 'pg'}]})
    return [deployment, service]


def match_sets(rules):
    """Project only the source and destination sets for the exact test allow rule."""
    comment = f'{NAMESPACE}/{INGRESS} ingress pods'
    pairs = set()
    for line in rules.decode('ascii').splitlines():
        if not line.startswith('-A KUBE-NWPLCY-') or INGRESS not in line:
            continue
        fields = shlex.split(line)
        if '--comment' not in fields or fields[fields.index('--comment') + 1] != comment:
            continue
        if ('-p' not in fields or fields[fields.index('-p') + 1] != 'tcp'
                or '--dport' not in fields or fields[fields.index('--dport') + 1] != '5432'):
            continue
        names = {fields[i + 2]: fields[i + 1] for i, field in enumerate(fields[:-2]) if field == '--match-set'}
        source, destination = names.get('src', ''), names.get('dst', '')
        if re.fullmatch(r'KUBE-SRC-[A-Z0-9]{1,24}', source) and re.fullmatch(r'KUBE-DST-[A-Z0-9]{1,24}', destination):
            pairs.add((source, destination))
    fixture.need(len(pairs) <= 1, 'ambiguous_k3s_postgres_rule')
    return next(iter(pairs), None)


def pod_admission(actual, expected, uid):
    metadata = actual['metadata']
    wanted = expected['metadata']
    fixture.need(re.fullmatch(fixture.UUID_PATTERN, uid) and metadata.get('uid') == uid
                 and {key: metadata.get(key) for key in ('name', 'namespace', 'labels')}
                  == {key: wanted.get(key) for key in ('name', 'namespace', 'labels')},
                 'k3s_assessment_pod_identity_changed')
    spec = actual['spec'].copy()
    node = spec.pop('nodeName', None)
    pending = actual.get('status', {}).get('phase') in (None, 'Pending')
    fixture.need((node == NODE or node is None and pending) and spec == expected['spec'],
                 'k3s_assessment_pod_authority_changed')


class Cluster:
    def __init__(self, identity):
        self.identity = identity

    def node_argv(self, *args):
        return ['docker', 'exec', '-i', self.identity, *args]

    def node(self, *args, code='k3s_node_command', **kwargs):
        return command(self.node_argv(*args), code=code, **kwargs)

    def argv(self, *args, namespace=NAMESPACE, request_timeout=8):
        return self.node_argv('/bin/kubectl', f'--request-timeout={request_timeout}s', '-n', namespace, *args)

    def k(self, *args, namespace=NAMESPACE, request_timeout=8, code='k3s_fixture_api', **kwargs):
        result = command(self.argv(*args, namespace=namespace, request_timeout=request_timeout), code=code, **kwargs)
        # Match the small result interface of the shared fixtures.
        return subprocess.CompletedProcess(args, 0, stdout=result)

    def write(self, operation, *items):
        return self.k(operation, '-f', '-', data=json.dumps({
            'apiVersion': 'v1', 'kind': 'List', 'items': items,
        }).encode())

    def apply(self, item):
        if item.get('kind') == 'Pod':
            sandbox_apparmor(item)
            if item['metadata']['name'] == 'assessment-seed':
                # Bootstrap synthetic history independently of the trial being
                # timed. The seed does not run with the assessment label.
                wait = ('import socket,time\n'
                        'until = time.monotonic() + 20\n'
                        'while time.monotonic() < until:\n'
                        '    try:\n'
                        '        with socket.create_connection(("postgres", 5432), timeout=1): break\n'
                        '    except OSError: time.sleep(.25)\n'
                        'else: raise SystemExit(1)\n')
                item['spec']['containers'][0]['command'] = [
                    '/bin/sh', '-ec', 'python3 -I -c "$1"; exec npm-assessment-seed', 'sh', wait,
                ]
        return self.write('apply', item)

    def dry_run_pod(self, item):
        return json.loads(self.k('create', '--dry-run=server', '-f', '-', '-o', 'json',
                                 data=json.dumps(item).encode()).stdout)

    def create_policy(self, item):
        self.write('create', item)
        name = item['metadata']['name']
        observed = json.loads(self.k('get', 'networkpolicy', name, '-o', 'json').stdout)
        uid = observed['metadata']['uid']
        fixture.need(observed.get('kind') == 'NetworkPolicy' and observed['metadata']['name'] == name
                     and observed['metadata']['namespace'] == NAMESPACE and observed['spec'] == item['spec']
                     and re.fullmatch(fixture.UUID_PATTERN, uid), 'k3s_assessment_policy_admission')
        return name, uid

    def sql(self, statement, *, database=fixture.DATABASE):
        return self.k('exec', '-i', 'deployment/postgres', '--', 'psql', '-X', '-q', '-At',
                      '-U', 'devres', '-d', database, '-v', 'ON_ERROR_STOP=1', '-f', '-',
                      data=statement.encode()).stdout

    def pod(self, name):
        return json.loads(self.k('get', 'pod', name, '-o', 'json').stdout)

    def delete(self, name, uid):
        fixture.need(re.fullmatch(fixture.UUID_PATTERN, uid) and self.pod(name)['metadata']['uid'] == uid,
                     'k3s_assessment_uid_changed')
        path = f'/api/v1/namespaces/{NAMESPACE}/pods/{name}'
        self.k('delete', '--raw=' + path, '-f', '-', data=json.dumps({
            'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid},
        }).encode())
        self.k('wait', '--for=delete', 'pod/' + name, '--timeout=45s', timeout=50)

    def delete_policy(self, name, uid):
        path = f'/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies/{name}'
        self.k('delete', '--raw=' + path, '-f', '-', data=json.dumps({
            'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid},
        }).encode())

    def image_config(self, reference):
        return self.image_status(reference)['id']

    def image_status(self, reference):
        return self.cri('inspecti', reference)['status']

    def cri(self, *args):
        endpoint = 'unix://' + CONTAINERD
        return json.loads(self.node('/bin/crictl', '--runtime-endpoint', endpoint,
                                    '--image-endpoint', endpoint, *args))

    def policy_enforced(self, pod_ip, database_ip):
        rules = self.node('/bin/sh', '-ec', 'iptables-save -t filter')
        sets = match_sets(rules)
        if sets is None:
            return False
        for name, address in zip(sets, (pod_ip, database_ip), strict=True):
            key = ipaddress.IPv4Address(address)
            membership = self.node('/bin/sh', '-ec', 'ipset save "$1"', 'sh', name)
            if not any(words[:3] == ['add', name, str(key)]
                       for words in (line.split() for line in membership.decode('ascii').splitlines())):
                return False
        return True


def apparmor_profile():
    return {'type': 'Localhost', 'localhostProfile': APPARMOR_PROFILE}


def enforced_apparmor(label):
    return label in (f'{APPARMOR_PROFILE} (enforce)', f'{APPARMOR_PROFILE}//&unconfined (enforce)')


def isolation_evidence(output, probe_peer):
    lines = output.decode('ascii').splitlines()
    fixture.need(len(lines) == (2 if probe_peer else 1) and enforced_apparmor(lines[0]),
                 'k3s_assessment_apparmor_unenforced')
    if probe_peer:
        fixture.need(lines[1] not in ('peer_exit=0', 'peer_exit=1'), 'k3s_unrelated_peer_reachable')
        fixture.need(lines[1] == 'peer_exit=2', 'k3s_unrelated_peer_probe_invalid')
    return lines[0]


def sandbox_apparmor(pod):
    # Use the same verified temporary enforcing profile as the Minikube fixture.
    for container in pod['spec']['containers']:
        container['securityContext']['appArmorProfile'] = apparmor_profile()


def prepare_coredns(cluster):
    namespace = 'kube-system'
    cluster.k('wait', '--for=create', 'deployment/coredns', '--timeout=30s', namespace=namespace,
              timeout=35, code='k3s_coredns_manifest')
    expected_image = 'rancher/mirrored-coredns-coredns:1.14.7'
    existing = json.loads(cluster.k('get', 'deployment/coredns', '-o', 'json', namespace=namespace).stdout)
    containers = existing['spec']['template']['spec']['containers']
    fixture.need(len(containers) == 1 and containers[0]['name'] == 'coredns'
                 and containers[0]['image'] in (expected_image, 'docker.io/' + expected_image), 'k3s_coredns_manifest')
    profile = {'containers': [{'name': 'coredns', 'securityContext': {'appArmorProfile': apparmor_profile()}}]}
    patch = json.dumps({'spec': {'template': {'spec': profile}}})
    cluster.k('patch', 'deployment/coredns', '--type=strategic', '-p', patch, namespace=namespace,
              code='k3s_coredns_apparmor')
    cluster.k('rollout', 'status', 'deployment/coredns', '--timeout=100s', namespace=namespace,
              timeout=108, code='k3s_coredns_ready')
    pods = json.loads(cluster.k('get', 'pods', '-l', 'k8s-app=kube-dns', '-o', 'json', namespace=namespace).stdout)
    active = [item for item in pods['items'] if item['status']['phase'] == 'Running'
              and not item['metadata'].get('deletionTimestamp')]
    fixture.need(len(active) == 1, 'k3s_coredns_identity')
    pod = active[0]
    container = pod['spec']['containers'][0]
    reference = pod['status']['containerStatuses'][0]['containerID']
    fixture.need(container['securityContext']['appArmorProfile'] == apparmor_profile()
                 and re.fullmatch(r'containerd://[a-f0-9]{64}', reference), 'k3s_coredns_identity')
    pid = cluster.cri('inspect', reference.removeprefix('containerd://'))['info']['pid']
    fixture.need(type(pid) is int and pid > 1, 'k3s_coredns_identity')
    label = cluster.node('cat', f'/proc/{pid}/attr/current', maximum=128, code='k3s_coredns_apparmor').decode().strip()
    fixture.need(enforced_apparmor(label), 'k3s_coredns_apparmor')
    return label


def phase_evidence(events, case):
    fixture.need(case in ('natural', 'delayed', 'denied') and isinstance(events, list) and events,
                 'k3s_assessment_phases_missing')
    pairs = [(event['phase'], event['outcome']) for event in events]
    connect = pairs.count(('sql_connect', 'start'))
    retry = [event for event in events if event['phase'] == 'sql_connect_retry']
    terminal = [event for event in events if event['phase'] == 'sql_connect' and event['outcome'] in ('ok', 'error')]
    fixture.need(connect == 1 and len(terminal) == 1 and pairs.count(('cli_start', 'start')) == 1
                 and len(retry) <= 1 and (not retry or events.index(retry[0]) < events.index(terminal[0])),
                 'k3s_assessment_repeated')
    if case == 'denied':
        elapsed = terminal[0]['elapsed_ms'] - events[pairs.index(('sql_connect', 'start'))]['elapsed_ms']
        fixture.need(len(retry) == 1 and terminal[0]['outcome'] == 'error' and terminal[0]['reason'] == 'timeout'
                     and 29_000 <= elapsed <= 45_000
                     and pairs.count(('cli_exit', 'error')) == 1
                     and all(phase not in ('sql_setup', 'transaction', 'report_write') for phase, _ in pairs),
                     'k3s_denied_assessment_reached_sql')
    else:
        fixture.need(pairs.count(('sql_connect', 'ok')) == 1 and pairs.count(('sql_setup', 'start')) == 1
                     and pairs.count(('transaction', 'start')) == 1 and pairs.count(('report_write', 'ok')) == 1
                     and pairs.count(('cli_exit', 'ok')) == 1 and (case != 'delayed' or len(retry) == 1),
                     'k3s_assessment_report_not_single')
    return {'first_retry': retry[0]['reason'] if retry else None,
            'first_retry_cli_elapsed_ms': retry[0]['elapsed_ms'] if retry else None,
            'connect_elapsed_ms': terminal[0]['elapsed_ms']}


def assess(cluster, api, name, case, image, config, selected, database_ip, peer_service_ip):
    selection = api.Selection(selected['job_id'], selected['revision'])
    pod = api.build_assessment_pod(fixture.template(image), image, selection, name, NAMESPACE,
                                   connect_readiness=True)
    pod['metadata']['labels']['app'] = APP
    sandbox_apparmor(pod)
    expected = cluster.dry_run_pod(pod)
    start = time.monotonic()
    timeline = {}
    policies = []

    def note(label):
        timeline.setdefault(label, int((time.monotonic() - start) * 1000))

    def allow():
        policies.append(cluster.create_policy(ingress(INGRESS, 'postgres', APP)))
        note('ingress_api_seen_ms')

    policies.append(cluster.create_policy(egress(EGRESS, APP)))
    note('egress_api_seen_ms')
    if case == 'natural':
        allow()
    cluster.write('create', pod)
    uid = cluster.pod(name)['metadata']['uid']
    note('pod_api_seen_ms')
    last = {}
    failures = []
    apparmor = None

    def observe():
        current = cluster.pod(name)
        pod_admission(current, expected, uid)
        last.clear()
        last.update(current)
        status = current.get('status', {})
        pod_ip = status.get('podIP')
        if pod_ip:
            note('pod_ip_seen_ms')
        if status.get('phase') == 'Running' and case == 'delayed' and 'ingress_api_seen_ms' not in timeline:
            phases = api.report_exchange(cluster.argv('exec', name, '--', '/bin/cat', api.PHASE_FILE), timeout=2)
            if phases is not None and phases.endswith(b'\n') and any(
                    event['phase'] == 'sql_connect_retry' for event in api.parse_phases(phases)):
                note('retry_seen_ms')
                allow()
        if pod_ip and 'ingress_api_seen_ms' in timeline and 'ingress_rule_seen_ms' not in timeline \
                and cluster.policy_enforced(pod_ip, database_ip):
            note('ingress_rule_seen_ms')
        return current

    def read_report(timeout):
        nonlocal apparmor
        deadline = time.monotonic() + timeout
        report = api.report_exchange(cluster.argv('exec', name, '--', '/bin/sh', '-c', api.read_script()), timeout=timeout)
        if report is not None:
            note('report_seen_ms')
            probe = '/bin/cat /proc/self/attr/current'
            if case == 'delayed':
                probe += ('\nif /usr/lib/postgresql/18/bin/pg_isready -q -t 2 -h "$1" -p 5432 -U devres -d postgres; '
                          'then result=0; else result=$?; fi\nprintf "peer_exit=%s\\n" "$result"')
            remaining = deadline - time.monotonic()
            fixture.need(remaining > 0, 'k3s_isolation_probe_deadline')
            output = cluster.k('exec', name, '--', '/bin/sh', '-ec', probe, 'sh', str(peer_service_ip),
                               timeout=remaining, maximum=128, code='k3s_isolation_probe').stdout
            apparmor = isolation_evidence(output, case == 'delayed')
        return report

    try:
        try:
            _, report, phases = api.supervise(get_pod=observe, read_report=read_report,
                cleanup=lambda: cluster.delete(name, uid), persist=lambda _: None, persist_failure=failures.append,
                selection=selection, uid=uid, image=image, timeout=70)
        except api.AssessmentError as error:
            fixture.need(case == 'denied' and str(error) == 'assessment_container_ended' and len(failures) == 1,
                         'k3s_assessment_failed')
            failure = failures[0]
            statuses = failure['last_pod']['containers']
            fixture.need(len(statuses) == 1 and statuses[0]['exit_code'] == 1, 'k3s_denial_exit_status')
            phases = failure['phases']
        else:
            fixture.need(case != 'denied' and report['reason'] == 'legacy_unknown' and report['eligible'] is False,
                         'k3s_assessment_outcome')
        statuses = last['status']['containerStatuses']
        fixture.need(len(statuses) == 1 and statuses[0]['restartCount'] == 0, 'k3s_assessment_restarted')
        reference = statuses[0]['imageID'].removeprefix('containerd://').removeprefix('docker-pullable://')
        fixture.need(cluster.image_config(reference) == config, 'k3s_assessment_image_changed')
        evidence = phase_evidence(phases, case)
        if case != 'denied':
            fixture.need('ingress_rule_seen_ms' in timeline, 'k3s_postgres_rule_unobserved')
        return {'pod_uid': uid, 'case': case, 'timeline': timeline, 'effective_apparmor': apparmor, **evidence}
    finally:
        # Refuse to remove policy if the same name still resolves to any Pod.
        absent = cluster.k('get', 'pod', name, '--ignore-not-found', '-o', 'name').stdout
        fixture.need(not absent.strip(), 'k3s_assessment_cleanup_unconfirmed')
        for policy_name, policy_uid in reversed(policies):
            cluster.delete_policy(policy_name, policy_uid)


def retained_snapshot(cluster):
    def exec_psql(*args, **kwargs):
        command = list(args)
        command[command.index('-U') + 1] = 'devres'
        command[command.index('-d') + 1] = fixture.DATABASE
        return cluster.k(*command, **kwargs).stdout

    try:
        return proof.retained_row_manifest(exec_psql)
    except proof.RetainedRowsError as error:
        raise fixture.FixtureError(str(error)) from None


def observer_workload(image):
    spec = fixture.template(image)['spec']
    spec.update({'restartPolicy': 'Never', 'activeDeadlineSeconds': 360})
    spec['volumes'] = [volume for volume in spec['volumes'] if volume['name'] != 's3']
    next(volume for volume in spec['volumes'] if volume['name'] == 'config')['secret']['secretName'] = OBSERVER_SECRET
    spec['volumes'].append({'name': 'archive', 'emptyDir': {'sizeLimit': '1Mi'}})
    container = spec['containers'][0]
    container['volumeMounts'] = [mount for mount in container['volumeMounts'] if mount['name'] != 's3']
    container['volumeMounts'].append({'name': 'archive', 'mountPath': '/data/blobs', 'readOnly': True})
    container.update({'name': OBSERVER, 'command': ['devres-server', 'collect', '/etc/devres/config/observer.toml'],
                      'readinessProbe': {'httpGet': {'path': '/ready', 'port': 9090}, 'periodSeconds': 1}})
    pod = object_spec('Pod', OBSERVER, spec=spec)
    pod['metadata']['labels'] = {'app': OBSERVER}
    return pod


def observer_configuration(original):
    return fixture.configuration(original).replace('[storage]\n', '[storage]\nscratch_dir = "/tmp/observer-scratch"\n', 1) + '''
[writer_listener]
access = "status_only"
bind = "127.0.0.1:9443"
certificate = "/etc/devres/config/tls.crt"
private_key = "/etc/devres/config/tls.key"
allowed_clients = [{namespace = "devres-acceptance", service_account = "assessment"}]
[writer_listener.auth]
audience = "devres-writer"
kube_api_url = "https://kubernetes.default.svc"
kube_token_file = "/run/devres-kube/token"
'''


def observer_locks(cluster):
    return json.loads(cluster.sql("SELECT json_build_array(count(*) FILTER (WHERE objid=1),"
        "count(*) FILTER (WHERE objid=2 AND mode='ShareLock'),"
        "count(*) FILTER (WHERE objid=2 AND mode='ExclusiveLock')) FROM pg_locks WHERE locktype='advisory'"
        " AND classid=1835365490 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database"
        " WHERE datname=current_database())"))


def observe_after_assessment(cluster, server, server_config, directory):
    assessment_left = cluster.k('get', 'pods', '-l', 'app=' + APP, '-o', 'name').stdout
    assessment_policies = cluster.k('get', 'networkpolicy', INGRESS, EGRESS, '--ignore-not-found', '-o', 'name').stdout
    fixture.need(not assessment_left.strip() and not assessment_policies.strip() and observer_locks(cluster) == [0, 0, 0],
                 'k3s_observer_requires_closed_assessment')
    baseline = retained_snapshot(cluster)
    certificate, key = directory / 'observer.crt', directory / 'observer.key'
    command(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
             '-days', '1', '-subj', '/CN=' + OBSERVER, '-keyout', str(key), '-out', str(certificate)],
            code='k3s_observer_tls_fixture')
    original = (ROOT / 'deploy/oxibelt/backend.toml').read_text()
    cluster.write('create', object_spec('Secret', OBSERVER_SECRET, stringData={
        'observer.toml': observer_configuration(original), 'tls.crt': certificate.read_text(), 'tls.key': key.read_text(),
    }))
    ingress_name, egress_name = OBSERVER_POLICIES
    policies = [cluster.create_policy(ingress(ingress_name, 'postgres', OBSERVER)),
                cluster.create_policy(egress(egress_name, OBSERVER))]
    pod = observer_workload(server)
    expected = cluster.dry_run_pod(pod)
    cluster.write('create', pod)
    uid = cluster.pod(OBSERVER)['metadata']['uid']
    cluster.k('wait', '--for=condition=Ready', 'pod/' + OBSERVER, '--timeout=90s',
              timeout=95, request_timeout=92, code='k3s_observer_startup')
    actual = cluster.pod(OBSERVER)
    pod_admission(actual, expected, uid)
    status, = actual['status']['containerStatuses']
    reference = status['imageID'].removeprefix('containerd://').removeprefix('docker-pullable://')
    fixture.need(status['ready'] and status['restartCount'] == 0 and 'running' in status['state']
                 and cluster.image_config(reference) == server_config and observer_locks(cluster) == [0, 1, 0],
                 'k3s_observer_authority_changed')
    apparmor = isolation_evidence(cluster.k('exec', OBSERVER, '--', '/bin/cat', '/proc/self/attr/current',
                                            maximum=128, code='k3s_observer_apparmor').stdout, False)
    fixture.need(retained_snapshot(cluster) == baseline, 'k3s_observer_retained_rows_changed')
    cluster.delete(OBSERVER, uid)
    for name, policy_uid in reversed(policies):
        cluster.delete_policy(name, policy_uid)
    cluster.k('delete', 'secret', OBSERVER_SECRET)
    remaining = cluster.k('get', 'pod/' + OBSERVER, *('networkpolicy/' + name for name in OBSERVER_POLICIES),
                          'secret/' + OBSERVER_SECRET, '--ignore-not-found', '-o', 'name').stdout
    fixture.need(not remaining.strip() and observer_locks(cluster) == [0, 0, 0], 'k3s_observer_cleanup_unconfirmed')
    return {'assessment_cleanup': 'verified', 'observer_pod_uid': uid, 'effective_apparmor': apparmor,
            'read_only_lifecycle_lock': True, 'retained_rows_unchanged': True, 'cleanup': 'complete'}


def run_cases(cluster, server, server_config, harness, database, directory):
    cluster.k('create', 'namespace', NAMESPACE)
    cluster.write('create', object_spec('ServiceAccount', 'assessment', automountServiceAccountToken=False),
        object_spec('Secret', 'postgres-fixture', stringData={'password': 'fixture-only'}),
        object_spec('Secret', 'devres-assessment-s3', stringData={'access-key': 'unused', 'secret-key': 'unused'}),
        policy('default-deny', None, policyTypes=['Ingress', 'Egress']),
        egress('seed-egress', 'backend'), ingress('seed-postgres-ingress', 'postgres', 'backend'),
        ingress('ready-peer-ingress', 'denied-peer', APP),
        *postgres('postgres', database), *postgres('denied-peer', database))
    cluster.k('rollout', 'status', 'deployment/postgres', '--timeout=70s', timeout=75, code='k3s_postgres_ready')
    cluster.k('rollout', 'status', 'deployment/denied-peer', '--timeout=70s', timeout=75, code='k3s_unrelated_peer_ready')
    peer_service_ip = ipaddress.IPv4Address(cluster.k('get', 'service', 'denied-peer', '-o',
                                                     'jsonpath={.spec.clusterIP}').stdout.decode())
    fixture.need(peer_service_ip in ipaddress.IPv4Network('10.43.0.0/16'),
                 'k3s_unrelated_service_unready')
    cluster.k('wait', '--for=jsonpath={.endpoints[0].conditions.ready}=true', 'endpointslice', '-l',
              'kubernetes.io/service-name=denied-peer', '--timeout=15s', timeout=20)
    config = fixture.configuration((ROOT / 'deploy/oxibelt/backend.toml').read_text())
    fixture.set_config(cluster, config, namespace=NAMESPACE)
    selected = fixture.seed(cluster, harness, namespace=NAMESPACE)
    database_ip = cluster.k('get', 'pod', '-l', 'app=postgres', '-o', 'jsonpath={.items[0].status.podIP}').stdout.decode()
    fixture.need(ipaddress.IPv4Address(database_ip).is_private, 'k3s_postgres_ip_invalid')
    baseline = fixture.snapshot(cluster)
    results = [assess(cluster, assessment, f'natural-{i}', 'natural', server, server_config, selected,
                      database_ip, peer_service_ip)
               for i in range(1, NATURAL_TRIALS + 1)]
    for kind in ('delayed', 'denied'):
        results.append(assess(cluster, assessment, kind, kind, server, server_config, selected,
                              database_ip, peer_service_ip))
    fixture.need(len({value['pod_uid'] for value in results}) == len(results), 'k3s_assessment_uid_reuse')
    fixture.need(fixture.snapshot(cluster) == baseline, 'k3s_assessment_mutated_database')
    return results, observe_after_assessment(cluster, server, server_config, directory)


@contextlib.contextmanager
def import_image(cluster, image, directory, marker, role):
    fixture.image_reference_kind(image)
    expected = fixture.expected_image_identity(image)
    if '@' in image:
        fixture.need(image.rsplit('@', 1)[1] in expected['known_digests'], 'k3s_input_image_digest')
    alias = f'docker.io/{marker}/{role}:fixture'
    archive = directory / f'{role}.tar'
    command(['docker', 'image', 'tag', expected['artifact'], alias], code='k3s_image_tag')
    try:
        command(['docker', 'image', 'save', '--platform=linux/amd64', '-o', str(archive), alias],
                code='k3s_image_save', timeout=180)
        cluster.node('/bin/ctr', '--address', CONTAINERD, '-n', 'k8s.io', 'images', 'import', '--platform', 'linux/amd64',
                     '--snapshotter', 'overlayfs', '/fixture/' + archive.name, timeout=180, code='k3s_image_import')
        config = cluster.image_config(alias)
        fixture.need(config in expected['configs'], 'k3s_image_config_mismatch')
        yield alias, config
    finally:
        command(['docker', 'image', 'rm', alias], code='k3s_image_untag')


def import_postgres_archive(cluster, archive):
    images = ('/bin/ctr', '--address', CONTAINERD, '-n', 'k8s.io', 'images')
    cluster.node(*images, 'import', '--platform', 'linux/amd64', '--snapshotter', 'overlayfs', '/fixture/' + archive.name,
                 timeout=180, code='k3s_postgres_archive_import')
    rows = [line.split() for line in cluster.node(*images, 'ls').decode().splitlines()]
    fixture.need([row[2] for row in rows if len(row) >= 3 and row[0] == POSTGRES_LOCAL_TAG] == [POSTGRES_AMD64],
                 'k3s_postgres_manifest_identity')
    status = cluster.image_status(POSTGRES_LOCAL_TAG)
    fixture.need(status['id'] == POSTGRES_CONFIG and status['repoTags'] == [POSTGRES_LOCAL_TAG],
                 'k3s_postgres_archive_identity')
    return POSTGRES_LOCAL_TAG, POSTGRES_CONFIG


def owned_container(name):
    rows = command(['docker', 'container', 'ls', '-a', '--no-trunc', '--filter', f'name=^/{name}$',
                    '--filter', 'label=devres.fixture-owner=' + name, '--format', '{{.ID}}'],
                   code='k3s_node_cleanup_lookup').decode().splitlines()
    fixture.need(len(rows) <= 1 and all(re.fullmatch('[a-f0-9]{64}', value) for value in rows),
                 'k3s_node_cleanup_identity')
    return rows[0] if rows else None


def local_docker_root(path):
    code = 'local_rootful_k3s_docker_storage_required'
    reported = Path(path)
    fixture.need(reported.is_absolute(), code)
    try:
        resolved = reported.resolve(strict=True)
    except PermissionError:
        # A rootful Docker store can deny traversal to the Docker group while
        # remaining under /tmp. Resolve only that reported path as root.
        output = command(['sudo', '-n', 'realpath', '-e', '--', str(reported)], code=code, maximum=4096)
        resolved = Path(output.decode().removesuffix('\n'))
    fixture.need(resolved.is_absolute() and '..' not in resolved.parts and Path('/tmp') in resolved.parents, code)
    return resolved


def storage_evidence(cluster):
    """Qualify the disposable filesystems while keeping default eviction active."""
    api = '/api/v1/nodes/' + NODE + '/proxy/'
    stats = json.loads(cluster.k('get', '--raw=' + api + 'stats/summary', code='k3s_storage_stats').stdout)['node']
    config = json.loads(cluster.k('get', '--raw=' + api + 'configz', code='k3s_eviction_config').stdout)['kubeletconfig']
    node = json.loads(cluster.k('get', 'node', NODE, '-o', 'json', code='k3s_storage_node').stdout)
    nodefs, imagefs = stats['fs'], stats['runtime']['imageFs']
    fixture.need(nodefs['capacityBytes'] == NODEFS_BYTES and imagefs['capacityBytes'] == IMAGEFS_BYTES,
                 'k3s_fixture_filesystems_not_isolated')
    fixture.need(config['evictionHard'] == DEFAULT_HARD_EVICTION
                 and config['evictionMinimumReclaim'] == DEFAULT_RECLAIM, 'k3s_fixture_eviction_changed')
    pressure = [row['status'] for row in node['status']['conditions'] if row['type'] == 'DiskPressure']
    fixture.need(pressure == ['False'], 'k3s_fixture_disk_pressure')
    return {'nodefs_capacity_bytes': nodefs['capacityBytes'], 'imagefs_capacity_bytes': imagefs['capacityBytes'],
            'disk_pressure': False, 'eviction_hard': DEFAULT_HARD_EVICTION, 'eviction_reclaim': DEFAULT_RECLAIM}


def run(args):
    requested = os.environ.get('DEVRES_DOCKER_HOST', 'unix:///var/run/docker.sock')
    fixture.need(requested.startswith('unix:///'), 'local_rootful_k3s_docker_required')
    socket = Path(requested.removeprefix('unix://')).resolve(strict=True)
    fixture.need(stat.S_ISSOCK(socket.stat().st_mode), 'local_rootful_k3s_docker_required')
    os.environ.pop('DOCKER_CONTEXT', None)
    os.environ['DOCKER_HOST'] = 'unix://' + str(socket)
    info = command(['docker', 'info', '--format', '{{json .DockerRootDir}}\n{{json .Architecture}}\n{{json .SecurityOptions}}'],
                   code='k3s_docker_info')
    root_dir, architecture, security = (json.loads(line) for line in info.splitlines())
    fixture.need(architecture == 'x86_64' and not any('rootless' in item for item in security),
                 'local_rootful_k3s_docker_storage_required')
    local_docker_root(root_dir)
    parser_info = Path(APPARMOR_PARSER).lstat()
    fixture.need(stat.S_ISREG(parser_info.st_mode) and parser_info.st_uid == 0 and parser_info.st_mode & 0o111
                 and not parser_info.st_mode & 0o022, 'installed_k3s_apparmor_parser_required')
    marker = 'devres-k3s-' + secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix=marker + '-', dir='/tmp') as temporary, contextlib.ExitStack() as profile_scope:
        directory = Path(temporary)
        archive = directory / 'airgap.tar.zst'
        copy_airgap(args.airgap_images, archive)
        postgres_archive = directory / 'postgres.oci.tar'
        if args.postgres_oci:
            copy_postgres_archive(args.postgres_oci, postgres_archive)
        apparmor_digest = profile_scope.enter_context(fixture.apparmor(directory, lambda: owned_container(marker) is None))
        identity = None
        try:
            created = command(['docker', 'create', '--name', marker, '--label', 'devres.fixture-owner=' + marker,
                '--pull=never', '--privileged', '--network=none', '--cgroupns=private',
                # Kubelet measures these mounts. Small private filesystems
                # preserve the original eviction thresholds on a shared host.
                '--tmpfs', f'/var/lib/kubelet:rw,size={NODEFS_BYTES},mode=0755',
                '--tmpfs', f'/var/lib/rancher/k3s/agent/containerd:rw,exec,size={IMAGEFS_BYTES},mode=0755',
                '--mount', 'type=bind,src=/sys/kernel/security,dst=/sys/kernel/security,readonly,'
                          'bind-propagation=rprivate,bind-recursive=readonly',
                '--mount', f'type=bind,src={APPARMOR_PARSER},dst=/sbin/apparmor_parser,readonly',
                '--mount', f'type=bind,src={directory},dst=/fixture,readonly',
                '--mount', f'type=bind,src={archive},dst=/var/lib/rancher/k3s/agent/images/base.tar.zst,readonly',
                '--entrypoint', '/bin/sh', K3S_IMAGE, '-ec', BOOT], code='k3s_node_create').decode().strip()
            identity = owned_container(marker)
            fixture.need(identity is not None and created == identity, 'k3s_node_identity')
            cluster = Cluster(identity)
            command(['docker', 'start', identity], code='k3s_node_start')
            fixture.need(cluster.node('readlink', '/proc/self/ns/net').decode().strip()
                         != os.readlink('/proc/self/ns/net'), 'k3s_host_network_namespace')
            mounts = cluster.node('cat', '/proc/self/mountinfo').decode().splitlines()
            securityfs = [line.split() for line in mounts if line.split()[4] == '/sys/kernel/security']
            fixture.need(len(securityfs) == 1 and 'ro' in securityfs[0][5].split(',')
                         and securityfs[0][securityfs[0].index('-') + 1] == 'securityfs', 'k3s_apparmor_view_not_read_only')
            deadline = time.monotonic() + 120
            while True:
                try:
                    node = json.loads(cluster.k('get', 'node', NODE, '-o', 'json').stdout)
                except fixture.FixtureError:
                    fixture.need(time.monotonic() < deadline, 'k3s_node_ready_timeout')
                    time.sleep(1)
                    continue
                backend = node['metadata'].get('annotations', {}).get('flannel.alpha.coreos.com/backend-type')
                ready = any(item['type'] == 'Ready' and item['status'] == 'True'
                            for item in node.get('status', {}).get('conditions', []))
                if ready and backend is not None:
                    break
                fixture.need(time.monotonic() < deadline, 'k3s_node_ready_timeout')
                time.sleep(1)
            fixture.need(node['status']['nodeInfo']['kubeletVersion'] == K3S_VERSION
                         and node['status']['nodeInfo']['architecture'] == 'amd64'
                         and backend == 'vxlan',
                         'k3s_node_version_or_network')
            coredns_apparmor = prepare_coredns(cluster)
            storage = storage_evidence(cluster)
            deadline = time.monotonic() + 30
            while not (b':KUBE-SERVICES ' in cluster.node('/bin/sh', '-ec', 'iptables-save -t nat')
                       and b':KUBE-ROUTER-FORWARD ' in cluster.node('/bin/sh', '-ec', 'iptables-save -t filter')):
                fixture.need(time.monotonic() < deadline, 'k3s_policy_controller_or_kube_proxy_missing')
                time.sleep(1)
            with contextlib.ExitStack() as scope:
                server, config = scope.enter_context(import_image(cluster, args.server_image, directory, marker, 'server'))
                harness, _ = scope.enter_context(import_image(cluster, args.harness_image, directory, marker, 'harness'))
                if args.postgres_oci:
                    database, database_config = import_postgres_archive(cluster, postgres_archive)
                else:
                    database, database_config = scope.enter_context(import_image(cluster, POSTGRES_IMAGE, directory, marker, 'postgres'))
                    fixture.need(database_config == POSTGRES_CONFIG, 'k3s_postgres_config_mismatch')
                cases, observer = run_cases(cluster, server, config, harness, database, directory)
            fixture.need(storage_evidence(cluster) == storage, 'k3s_fixture_storage_changed')
        finally:
            if identity is None:
                # A disconnected create response can arrive after the API has
                # accepted it. Reconcile only this run's exact name and label.
                for _ in range(4):
                    identity = owned_container(marker)
                    if identity is not None:
                        break
                    time.sleep(.5)
            if identity is not None:
                command(['docker', 'rm', '--force', '--volumes', identity], code='k3s_node_cleanup', timeout=40)
                fixture.need(owned_container(marker) is None, 'k3s_node_cleanup_unconfirmed')
    return {'version': 1, 'synthetic': True, 'k3s_version': K3S_VERSION, 'k3s_image': K3S_IMAGE,
            'airgap_sha256': AIRGAP_SHA256, 'server_image': args.server_image, 'server_config_digest': config,
            'assessment_apparmor': 'Localhost/' + APPARMOR_PROFILE, 'apparmor_sha256': apparmor_digest,
            'coredns_apparmor': coredns_apparmor, 'postgres_config_digest': database_config,
            'storage': storage, 'cases': cases, 'observer': observer, 'database_unchanged': True,
            'unrelated_destination_denied': True, 'cleanup': 'complete'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-image', required=True, help='preloaded exact candidate in the local rootful daemon')
    parser.add_argument('--harness-image', required=True, help='preloaded repository harness with the synthetic npm seed')
    parser.add_argument('--airgap-images', required=True, help='official pinned amd64 air-gap archive under /tmp')
    parser.add_argument('--postgres-oci', help='optional pinned PostgreSQL amd64 OCI archive under /tmp')
    parser.add_argument('--receipt', required=True, help='fresh private JSON path under /tmp')
    args = parser.parse_args()
    def interrupt(signum, _frame):
        signal.signal(signum, signal.SIG_IGN)
        raise SystemExit(128 + signum)

    previous = {item: signal.signal(item, interrupt) for item in (signal.SIGTERM, signal.SIGINT)}
    try:
        receipt = scratch_path(args.receipt)
        fixture.need(not receipt.exists() and not receipt.is_symlink(), 'fresh_k3s_receipt_required')
        fixture.private_json(receipt, run(args))
    except (fixture.FixtureError, OSError, KeyError, ValueError, TypeError, IndexError, tarfile.TarError,
            assessment.AssessmentError) as error:
        category = str(error) if type(error) is fixture.FixtureError else 'k3s_fixture_unavailable'
        print(category, file=sys.stderr)
        return 1
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)
    print('Offline K3s npm PostgreSQL readiness qualification passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
