#!/usr/bin/env python3
"""Exercise the exact server image against the B130E K3s policy controller offline."""

import argparse
import contextlib
import hashlib
import importlib.util
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
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
K3S_VERSION = 'v1.37.2+k3s1'
K3S_IMAGE = 'docker.io/rancher/k3s@sha256:21ea6e0fac4e3930c2ce8aa40ddd41a8b18cb3e9a0222c030dc005e7e88c4332'
AIRGAP_SHA256 = '35a5af1e69b57b8b627a4f6b1c29ea104209b661067b8c97fd40dc3f860bfcd2'
AIRGAP_SIZE = 198293778
POSTGRES_IMAGE = 'postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395'
APP = 'devres-npm-assessment'
INGRESS = 'assessment-postgres-ingress'
EGRESS = 'assessment-dns-postgres-egress'
NATURAL_TRIALS = 10
NODE = 'k3s-fixture'
CONTAINERD = '/run/k3s/containerd/containerd.sock'
BOOT = '''
ip link add eth0 type dummy
ip address add 192.0.2.2/24 dev eth0
ip link set eth0 up
ip route add default via 192.0.2.1 dev eth0
exec /bin/k3s server --node-name k3s-fixture --node-ip 192.0.2.2 \
  --flannel-iface eth0 --flannel-backend vxlan --kube-proxy-arg proxy-mode=iptables \
  --disable traefik --disable servicelb --disable metrics-server --disable local-storage \
  --disable gateway-api-crd --snapshotter native
'''

_spec = importlib.util.spec_from_file_location('npm_readiness_fixture', ROOT / 'scripts/npm-assessment-fixture.py')
fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fixture)
NAMESPACE = fixture.NAMESPACE
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
                  {'name': 'POSTGRES_PASSWORD',
                   'valueFrom': {'secretKeyRef': {'name': 'postgres-fixture', 'key': 'password'}}}],
          'ports': [{'containerPort': 5432, 'name': 'pg'}],
          'readinessProbe': {'exec': {'command': ['pg_isready', '-q', '-h', '127.0.0.1']}, 'periodSeconds': 1},
          'volumeMounts': [{'name': 'data', 'mountPath': '/var/lib/postgresql'}],
          'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'memory': '512Mi'}},
          'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}}
    pod = {'automountServiceAccountToken': False,
           'securityContext': {'runAsNonRoot': True, 'runAsUser': 70, 'runAsGroup': 70, 'fsGroup': 70,
                               'seccompProfile': {'type': 'RuntimeDefault'}},
           'volumes': [{'name': 'data', 'emptyDir': {'sizeLimit': '256Mi'}}], 'containers': [pg]}
    deployment = object_spec('Deployment', name, version='apps/v1', spec={
        'replicas': 1, 'selector': selector(name), 'template': {'metadata': {'labels': label}, 'spec': pod}})
    service = object_spec('Service', name, spec={
        'selector': label, 'ports': [{'port': 5432, 'protocol': 'TCP', 'targetPort': 'pg'}]})
    return [deployment, service]


def match_sets(rules):
    """Project only the source and destination sets for the exact test allow rule."""
    comment = re.compile(r'\bpolicy name:? ' + re.escape(INGRESS) + r' namespace ' + re.escape(NAMESPACE) + r'$')
    pairs = set()
    for line in rules.decode('ascii').splitlines():
        if not line.startswith('-A KUBE-NWPLCY-') or INGRESS not in line:
            continue
        fields = shlex.split(line)
        if '--comment' not in fields or not comment.search(fields[fields.index('--comment') + 1]):
            continue
        if '--dport' not in fields or fields[fields.index('--dport') + 1] != '5432':
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

    def argv(self, *args, namespace=NAMESPACE):
        return self.node_argv('/bin/kubectl', '--request-timeout=8s', '-n', namespace, *args)

    def k(self, *args, namespace=NAMESPACE, **kwargs):
        result = command(self.argv(*args, namespace=namespace), code='k3s_fixture_api', **kwargs)
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
        endpoint = 'unix://' + CONTAINERD
        return json.loads(self.node('/bin/crictl', '--runtime-endpoint', endpoint,
                                    '--image-endpoint', endpoint, 'inspecti', reference))['status']['id']

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


def sandbox_apparmor(pod):
    # Qualify K3s policy without installing a host profile. Calico separately
    # exercises the exact image with effective production AppArmor enforcement.
    for container in pod['spec']['containers']:
        container['securityContext']['appArmorProfile'] = {'type': 'RuntimeDefault'}


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
        deadline = time.monotonic() + timeout
        report = api.report_exchange(cluster.argv('exec', name, '--', '/bin/sh', '-c', api.read_script()), timeout=timeout)
        if report is not None:
            note('report_seen_ms')
            if case == 'delayed':
                probe = ('if /usr/bin/pg_isready -q -t 2 -h "$1" -p 5432; then exit 1; '
                         'else test "$?" -eq 2; fi')
                remaining = deadline - time.monotonic()
                fixture.need(remaining > 0, 'k3s_isolation_probe_deadline')
                cluster.k('exec', name, '--', '/bin/sh', '-ec', probe, 'sh', str(peer_service_ip), timeout=remaining)
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
        return {'pod_uid': uid, 'case': case, 'timeline': timeline, **evidence}
    finally:
        # Refuse to remove policy if the same name still resolves to any Pod.
        absent = cluster.k('get', 'pod', name, '--ignore-not-found', '-o', 'name').stdout
        fixture.need(not absent.strip(), 'k3s_assessment_cleanup_unconfirmed')
        for policy_name, policy_uid in reversed(policies):
            cluster.delete_policy(policy_name, policy_uid)


def run_cases(cluster, server, server_config, harness, database):
    cluster.k('create', 'namespace', NAMESPACE)
    cluster.write('create', object_spec('ServiceAccount', 'assessment', automountServiceAccountToken=False),
        object_spec('Secret', 'postgres-fixture', stringData={'password': 'fixture-only'}),
        object_spec('Secret', 'devres-assessment-s3', stringData={'access-key': 'unused', 'secret-key': 'unused'}),
        policy('default-deny', None, policyTypes=['Ingress', 'Egress']),
        egress('seed-egress', 'backend'), ingress('seed-postgres-ingress', 'postgres', 'backend'),
        ingress('ready-peer-ingress', 'denied-peer', APP),
        *postgres('postgres', database), *postgres('denied-peer', database))
    cluster.k('rollout', 'status', 'deployment/postgres', '--timeout=70s', timeout=75)
    cluster.k('rollout', 'status', 'deployment/denied-peer', '--timeout=70s', timeout=75)
    peer_service_ip = ipaddress.IPv4Address(cluster.k('get', 'service', 'denied-peer', '-o',
                                                     'jsonpath={.spec.clusterIP}').stdout.decode())
    fixture.need(peer_service_ip in ipaddress.IPv4Network('10.43.0.0/16'),
                 'k3s_unrelated_service_unready')
    cluster.k('wait', '--for=jsonpath={.endpoints[0].conditions.ready}=true', 'endpointslice', '-l',
              'kubernetes.io/service-name=denied-peer', '--timeout=15s', timeout=20)
    prefix = 'postgres://'
    endpoint = '@postgres:5432/' + fixture.DATABASE
    config = fixture.configuration((ROOT / 'deploy/oxibelt/backend.toml').read_text(),
                                   database=prefix + 'devres_assessment_reader:assessment-fixture-only' + endpoint)
    fixture.set_config(cluster, config)
    selected = fixture.seed(cluster, harness, database_admin=prefix + 'devres:fixture-only' + endpoint)
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
    return results


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
                     '/fixture/' + archive.name, timeout=180, code='k3s_image_import')
        config = cluster.image_config(alias)
        fixture.need(config in expected['configs'], 'k3s_image_config_mismatch')
        yield alias, config
    finally:
        command(['docker', 'image', 'rm', alias], code='k3s_image_untag')


def owned_container(name):
    rows = command(['docker', 'container', 'ls', '-a', '--no-trunc', '--filter', f'name=^/{name}$',
                    '--filter', 'label=devres.fixture-owner=' + name, '--format', '{{.ID}}'],
                   code='k3s_node_cleanup_lookup').decode().splitlines()
    fixture.need(len(rows) <= 1 and all(re.fullmatch('[a-f0-9]{64}', value) for value in rows),
                 'k3s_node_cleanup_identity')
    return rows[0] if rows else None


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
    root = Path(root_dir).resolve(strict=True)
    fixture.need(architecture == 'x86_64' and not any('rootless' in item for item in security)
                 and Path('/tmp') in root.parents, 'local_rootful_k3s_docker_storage_required')
    marker = 'devres-k3s-' + secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix=marker + '-', dir='/tmp') as temporary:
        directory = Path(temporary)
        archive = directory / 'airgap.tar.zst'
        copy_airgap(args.airgap_images, archive)
        identity = None
        try:
            created = command(['docker', 'create', '--name', marker, '--label', 'devres.fixture-owner=' + marker,
                '--pull=never', '--privileged', '--network=none', '--cgroupns=private',
                '--mount', f'type=bind,src={directory},dst=/fixture,readonly',
                '--mount', f'type=bind,src={archive},dst=/var/lib/rancher/k3s/agent/images/base.tar.zst,readonly',
                '--entrypoint', '/bin/sh', K3S_IMAGE, '-ec', BOOT], code='k3s_node_create').decode().strip()
            identity = owned_container(marker)
            fixture.need(identity is not None and created == identity, 'k3s_node_identity')
            cluster = Cluster(identity)
            command(['docker', 'start', identity], code='k3s_node_start')
            fixture.need(cluster.node('readlink', '/proc/self/ns/net').decode().strip()
                         != os.readlink('/proc/self/ns/net'), 'k3s_host_network_namespace')
            deadline = time.monotonic() + 120
            while True:
                try:
                    node = json.loads(cluster.k('get', 'node', NODE, '-o', 'json').stdout)
                except fixture.FixtureError:
                    fixture.need(time.monotonic() < deadline, 'k3s_node_ready_timeout')
                    time.sleep(1)
                    continue
                if any(item['type'] == 'Ready' and item['status'] == 'True' for item in node['status']['conditions']):
                    break
                fixture.need(time.monotonic() < deadline, 'k3s_node_ready_timeout')
                time.sleep(1)
            fixture.need(node['status']['nodeInfo']['kubeletVersion'] == K3S_VERSION
                         and node['status']['nodeInfo']['architecture'] == 'amd64'
                         and node['metadata']['annotations']['flannel.alpha.coreos.com/backend-type'] == 'vxlan',
                         'k3s_node_version_or_network')
            cluster.k('rollout', 'status', 'deployment/coredns', '--timeout=100s', namespace='kube-system', timeout=108)
            fixture.need(b':KUBE-SERVICES ' in cluster.node('/bin/sh', '-ec', 'iptables-save -t nat')
                         and b':KUBE-ROUTER-FORWARD ' in cluster.node('/bin/sh', '-ec', 'iptables-save -t filter'),
                         'k3s_policy_controller_or_kube_proxy_missing')
            with contextlib.ExitStack() as scope:
                server, config = scope.enter_context(import_image(cluster, args.server_image, directory, marker, 'server'))
                harness, _ = scope.enter_context(import_image(cluster, args.harness_image, directory, marker, 'harness'))
                database, _ = scope.enter_context(import_image(cluster, POSTGRES_IMAGE, directory, marker, 'postgres'))
                cases = run_cases(cluster, server, config, harness, database)
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
            'assessment_apparmor': 'RuntimeDefault',
            'cases': cases, 'database_unchanged': True, 'unrelated_destination_denied': True, 'cleanup': 'complete'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-image', required=True, help='preloaded exact candidate in the local rootful daemon')
    parser.add_argument('--harness-image', required=True, help='preloaded repository harness with the synthetic npm seed')
    parser.add_argument('--airgap-images', required=True, help='official pinned amd64 air-gap archive under /tmp')
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
    except (fixture.FixtureError, OSError, KeyError, ValueError, TypeError, IndexError, assessment.AssessmentError) as error:
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
