#!/usr/bin/env python3
"""Host-specific staged deployment. Run from the reviewed installed assets as root.

No command prints credentials, request bodies or external-command error output.
The shared edge is changed only by the explicit edge-activate command.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

HERE = Path(__file__).resolve().parent
STATE = Path('/var/lib/devres-staging')
PRIVATE = Path('/etc/devres-staging')
EDGE = Path('/mnt/http')
CERTS = EDGE / 'lego/data/certificates'
HOST = 'dev-resources.staged.mcp.publicdata.stream'
NS = 'devres-staging'
PG = 'postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a'
SERVER = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:02977361122a11d7f0a9eedea97437b15f2fccc17f82d2331f859d388359179e'
PROBE = 'ghcr.io/publicdata-stream/dev-resources-probe:0.1.0-build.27d35cd6'
SNIPPETS = ('52-upstream-devres-staging.toml', '62-route-devres-staging.toml')
OWNER = 'devres-staging-v1'
COLLECTORS = ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'npm')


class OperatorError(RuntimeError):
    pass


def run(args, data=None, timeout=240):
    try:
        p = subprocess.run([str(a) for a in args], input=data, text=True,
                           capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise OperatorError('command_unavailable_or_timed_out:' + str(args[0])) from e
    if p.returncode:
        raise OperatorError('command_failed:' + str(args[0]))
    if len(p.stdout) > 4 * 1024 * 1024:
        raise OperatorError('command_output_too_large')
    return p.stdout


def k(*args, data=None):
    return run(['k3s', 'kubectl', '--request-timeout=120s', '-n', NS, *args], data)


def write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise OperatorError('refuse_symlink')
    previous = path.stat() if path.exists() else None
    fd, name = tempfile.mkstemp(prefix='.devres-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        if previous is not None and os.geteuid() == 0:
            os.fchown(fd, previous.st_uid, previous.st_gid)
        with os.fdopen(fd, 'w') as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def append_array(text, table, key, value):
    parsed = tomllib.loads(text)
    values = parsed[table][key]
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise OperatorError('unexpected_shared_array')
    if value in values:
        return text
    # The existing host configuration uses single-line arrays; fail on drift.
    pattern = r'(?m)^' + re.escape(key) + r'\s*=\s*\[[^\n]*\]\s*$'
    replacement = key + ' = ' + json.dumps(values + [value])
    result, count = re.subn(pattern, lambda _: replacement, text)
    if count != 1:
        raise OperatorError('shared_config_layout_changed')
    if tomllib.loads(result)[table][key] != values + [value]:
        raise OperatorError('shared_array_update_failed')
    return result


def add_host(text):
    alias = '    - openlegal-k8s:10.0.0.1\n'
    addition = '    - devres-k8s:10.0.0.1\n'
    if addition in text:
        return text
    if text.count(alias) != 1:
        raise OperatorError('compose_layout_changed')
    return text.replace(alias, alias + addition, 1)


def private_dirs():
    for p in (STATE, PRIVATE):
        p.mkdir(mode=0o700, parents=True, exist_ok=True)
        s = p.lstat()
        if p.is_symlink() or s.st_uid != 0 or s.st_mode & 0o077:
            raise OperatorError('unsafe_private_directory')


def dataset(name, mountpoint, **properties):
    p = subprocess.run(['zfs', 'list', '-H', '-o', 'name', name], capture_output=True)
    if p.returncode == 0:
        if run(['zfs', 'get', '-H', '-o', 'value', 'org.publicdata:owner', name]).strip() != OWNER:
            raise OperatorError('dataset_not_owned')
        for prop, expected in {'mountpoint': mountpoint, **properties}.items():
            actual = run(['zfs', 'get', '-Hp', '-o', 'value', prop, name]).strip()
            # Numeric quotas are checked by maintenance before activation.
            if prop == 'mountpoint' and actual != expected:
                raise OperatorError('dataset_mountpoint_changed')
        return
    command = ['zfs', 'create', '-o', 'org.publicdata:owner=' + OWNER,
               '-o', 'mountpoint=' + mountpoint, '-o', 'compression=zstd',
               '-o', 'atime=off', '-o', 'exec=off', '-o', 'setuid=off', '-o', 'devices=off']
    for prop, value in properties.items():
        command += ['-o', prop + '=' + value]
    run(command + [name])


def certificate(name, ca=None, san=None, usage=None):
    key, crt = PRIVATE / (name + '-key.pem'), PRIVATE / (name + '.pem')
    if crt.exists():
        if not key.exists():
            raise OperatorError('partial_certificate_state')
        run(['openssl', 'x509', '-in', crt, '-checkend', '604800', '-noout'])
        return
    if key.exists():
        raise OperatorError('partial_certificate_state')
    run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key])
    os.chmod(key, 0o600)
    if ca is None:
        run(['openssl', 'req', '-new', '-x509', '-sha256', '-days', '3650', '-key', key,
             '-out', crt, '-subj', '/CN=' + name, '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    else:
        csr = PRIVATE / (name + '.csr')
        ext = PRIVATE / (name + '.ext')
        write(ext, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
              + 'extendedKeyUsage=' + usage + '\nsubjectAltName=DNS:' + san + '\n')
        run(['openssl', 'req', '-new', '-key', key, '-out', csr, '-subj', '/CN=' + name])
        run(['openssl', 'x509', '-req', '-in', csr, '-CA', PRIVATE / (ca + '.pem'),
             '-CAkey', PRIVATE / (ca + '-key.pem'), '-set_serial', str(secrets.randbits(127)),
             '-days', '365', '-sha256', '-extfile', ext, '-out', crt])
        csr.unlink()
        ext.unlink()
    os.chmod(crt, 0o600)


def secret(name, files):
    obj = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': NS},
           'type': 'Opaque', 'data': {key: base64.b64encode(Path(p).read_bytes()).decode()
                                    for key, p in files.items()}}
    # Server-side apply keeps populated secrets out of last-applied annotations.
    k('apply', '--server-side', '--field-manager=devres-staging', '-f', '-', data=json.dumps(obj))


def config_secret():
    secret('devres-config', {'backend.toml': PRIVATE / 'backend.toml',
                            'postgres-password': PRIVATE / 'postgres-password',
                            'init.sql': PRIVATE / 'init.sql'})


def firewall(strict=True):
    expected = False
    try:
        details = json.loads(run(['docker', 'inspect', 'oxibelt']))[0]
        expected = details['NetworkSettings']['Networks']['openlegal4everyone-net']['IPAddress'] == '10.0.0.3'
        network = json.loads(run(['docker', 'network', 'inspect', 'openlegal4everyone-net']))[0]
        expected = expected and network['Options'].get('com.docker.network.bridge.name') == 'openlegal-edge0'
    except (OperatorError, KeyError, ValueError):
        pass
    exists = subprocess.run(['nft', 'list', 'table', 'inet', 'devres_nodeport_guard'],
                            capture_output=True).returncode == 0
    rules = 'delete table inet devres_nodeport_guard\n' if exists else ''
    rules += 'table inet devres_nodeport_guard { chain prerouting { type filter hook prerouting priority -151; policy accept;\n'
    for proto, port in (('tcp', 30081), ('udp', 30434)):
        if expected:
            rules += f'ip daddr 10.0.0.1 ip saddr 10.0.0.3 iifname "openlegal-edge0" {proto} dport {port} accept\n'
        rules += f'fib daddr type local {proto} dport {port} drop\n'
    rules += '} }\n'
    run(['nft', '-f', '-'], rules)
    if not expected and strict:
        raise OperatorError('edge_topology_changed_ports_fenced')


def prepare():
    private_dirs()
    # Inventory failures and terminating Pods must not permit a Secret rewrite.
    existing_namespace = run(['k3s', 'kubectl', 'get', 'namespace', NS,
                              '--ignore-not-found', '-o', 'name']).strip()
    if existing_namespace:
        deployments = json.loads(k('get', 'deploy', '-o', 'json'))
        if any(d['spec'].get('replicas', 1) for d in deployments.get('items', [])):
            raise OperatorError('prepare_requires_all_writers_stopped')
        pods = json.loads(k('get', 'pods', '-l', 'app in (backend,postgres)', '-o', 'json'))
        if pods.get('items'):
            raise OperatorError('prepare_requires_writer_termination')
    if run(['hostname']).strip() != 'piqua-serve':
        raise OperatorError('wrong_host')
    if run(['zpool', 'status', '-x', 'cachepool']).strip() != "pool 'cachepool' is healthy":
        raise OperatorError('pool_not_healthy')
    dataset('cachepool/devres-staging', '/mnt/devres-staging', quota='1536G')
    dataset('cachepool/devres-staging/postgres', '/mnt/devres-staging/postgres', refquota='256G')
    dataset('cachepool/devres-staging/evidence', '/mnt/devres-staging/evidence', refquota='768G')
    os.chown('/mnt/devres-staging/postgres', 999, 999)
    os.chown('/mnt/devres-staging/evidence', 65532, 65532)
    for ca in ('backend-ca', 'client-ca'):
        certificate(ca)
    certificate('backend', 'backend-ca', 'devres-k8s', 'serverAuth')
    certificate('edge-client', 'client-ca', 'devres-edge.internal', 'clientAuth')
    if not (PRIVATE / 'backend.toml').exists():
        if (PRIVATE / 'postgres-password').exists() or (PRIVATE / 'init.sql').exists():
            raise OperatorError('partial_credential_state')
        admin, app = secrets.token_hex(32), secrets.token_hex(32)
        text = (HERE / 'backend.toml.example').read_text().replace('REPLACE_WITH_PRIVATE_POSTGRES_URL',
                          'postgres://devres:' + app + '@postgres:5432/devres')
        write(PRIVATE / 'postgres-password', admin)
        write(PRIVATE / 'init.sql', "CREATE ROLE devres LOGIN PASSWORD '" + app + "' NOSUPERUSER NOCREATEDB NOCREATEROLE;\n"
              + 'ALTER DATABASE devres OWNER TO devres;\n\\connect devres\nALTER SCHEMA public OWNER TO devres;\nREVOKE CREATE ON SCHEMA public FROM PUBLIC;\n')
        write(PRIVATE / 'backend.toml', text)
    for image in (PG, SERVER, PROBE):
        run(['docker', 'pull', image], timeout=600)
    firewall()
    # Namespace creation precedes secret and namespaced object admission.
    k('create', 'namespace', NS, '--dry-run=client', '-o', 'json')  # availability check
    ns = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS}}
    k('apply', '-f', '-', data=json.dumps(ns))
    config_secret()
    secret('devres-tls', {'backend.pem': PRIVATE / 'backend.pem',
                         'backend-key.pem': PRIVATE / 'backend-key.pem',
                         'client-ca.pem': PRIVATE / 'client-ca.pem'})
    k('apply', '--dry-run=server', '-f', HERE / 'kubernetes.yaml')
    k('apply', '-f', HERE / 'kubernetes.yaml')
    for source, destination in (('backend-ca.pem', 'devres-backend-ca.pem'),
                                ('edge-client.pem', 'devres-client.pem'),
                                ('edge-client-key.pem', 'devres-client-key.pem')):
        target = CERTS / destination
        if target.exists() and target.read_bytes() != (PRIVATE / source).read_bytes():
            raise OperatorError('edge_certificate_conflict')
        shutil.copyfile(PRIVATE / source, target)
        os.chown(target, 10001, 10001)
        os.chmod(target, 0o400 if 'key' in destination else 0o644)
    install_services()
    print('prepared: writers paused; private credentials installed')


def install_services():
    executable = str(HERE / 'operator.py')
    maintenance = str(HERE / 'maintenance.py')
    services = {
        'devres-staging-firewall.service': f'[Unit]\nDescription=Devres staging NodePort isolation\nAfter=docker.service network-online.target\nRequires=docker.service\nBefore=k3s.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {executable} firewall-bootstrap\n',
        'devres-staging-firewall.timer': '[Unit]\nDescription=Reconcile devres NodePort isolation\n[Timer]\nOnBootSec=15s\nOnUnitActiveSec=15s\n[Install]\nWantedBy=timers.target\n',
        'devres-staging-capacity.service': f'[Unit]\nDescription=Devres staging capacity fence\nAfter=k3s.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {maintenance} guard\nSuccessExitStatus=75\n',
        'devres-staging-capacity.timer': '[Unit]\nDescription=Monitor devres staging storage\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=1min\n[Install]\nWantedBy=timers.target\n',
        'devres-staging-backup.service': f'[Unit]\nDescription=Coordinated devres snapshot and restore verification\nAfter=k3s.service\n[Service]\nType=oneshot\nTimeoutStartSec=1800\nExecStart=/usr/bin/python3 {executable} backup\n',
        'devres-staging-backup.timer': '[Unit]\nDescription=Daily devres backup at 03 UTC\n[Timer]\nOnCalendar=*-*-* 03:00:00 UTC\nPersistent=true\n[Install]\nWantedBy=timers.target\n'}
    for name, text in services.items():
        write(Path('/etc/systemd/system') / name, text, 0o644)
    write('/etc/systemd/system/k3s.service.d/devres-staging-guard.conf',
          '[Unit]\nRequires=devres-staging-firewall.service\nAfter=devres-staging-firewall.service\n', 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'devres-staging-firewall.timer', 'devres-staging-capacity.timer'])
    # The daily timer is enabled after a successful real-evidence restore drill.


def edge_inventory(root=EDGE):
    paths = [root / 'oxibelt.toml', root / 'docker-compose.yml',
             *sorted((root / 'oxibelt-conf').glob('*.toml'))]
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise OperatorError('unsafe_edge_configuration_path')
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths}


def edge_prepare():
    baseline = edge_inventory()
    candidate = STATE / 'edge-candidate'
    if candidate.exists():
        raise OperatorError('candidate_already_exists')
    candidate.mkdir(mode=0o755)
    conf = candidate / 'oxibelt-conf'
    shutil.copytree(EDGE / 'oxibelt-conf', conf)
    shutil.copyfile(EDGE / 'oxibelt.toml', candidate / 'oxibelt.toml')
    os.chmod(candidate / 'oxibelt.toml', 0o644)
    old = {}
    for file, table, key, item in (('10-tls.toml', 'tls', 'server_names', HOST),
                                 ('20-proxy.toml', 'proxy', 'trusted_ca_certs', 'devres-backend-ca.pem')):
        old[file] = (conf / file).read_text()
        write(conf / file, append_array(old[file], table, key, item), 0o644)
    for name in SNIPPETS:
        if (conf / name).exists():
            raise OperatorError('shared_snippet_conflict')
        shutil.copyfile(HERE / name, conf / name)
    compose = (EDGE / 'docker-compose.yml').read_text()
    write(candidate / 'docker-compose.yml', add_host(compose), 0o600)
    before = json.loads(run(['docker', 'compose', '-f', EDGE / 'docker-compose.yml', 'config', '--format', 'json']))
    after = json.loads(run(['docker', 'compose', '--project-directory', EDGE, '-f', candidate / 'docker-compose.yml', 'config', '--format', 'json']))
    before_hosts = before['services']['oxibelt'].get('extra_hosts', [])
    after_hosts = after['services']['oxibelt'].get('extra_hosts', [])
    if set(after_hosts) != set(before_hosts) | {'devres-k8s=10.0.0.1'}:
        raise OperatorError('compose_host_update_invalid')
    before['services']['oxibelt']['extra_hosts'] = after_hosts
    if before != after:
        raise OperatorError('unexpected_compose_change')
    identity = json.loads(run(['docker', 'inspect', 'oxibelt']))[0]
    if identity['Config']['Labels'].get('org.opencontainers.image.revision') != '4f3154d8db0e0a49bce7a528c0a0f4c36d169040':
        raise OperatorError('unexpected_edge_revision')
    image = identity['Image']
    run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001', '--entrypoint', 'oxibelt',
         '-v', str(candidate) + ':/etc/oxibelt/config:ro',
         '-v', str(CERTS) + ':/etc/oxibelt/cert:ro', image,
         '--config', '/etc/oxibelt/config/oxibelt.toml', '--check'])
    if edge_inventory() != baseline:
        raise OperatorError('shared_edge_changed_during_validation')
    write(candidate / 'baseline.json', json.dumps(baseline))
    write(candidate / 'candidate.json', json.dumps(edge_inventory(candidate)))
    print('edge candidate validated with exact running image; live configuration unchanged')


def edge_activate(rollback=False):
    candidate, previous = STATE / 'edge-candidate', STATE / 'edge-previous'
    owned = ('oxibelt-conf/10-tls.toml', 'oxibelt-conf/20-proxy.toml',
             *('oxibelt-conf/' + n for n in SNIPPETS), 'docker-compose.yml')
    if rollback:
        marker = previous / 'activated.json'
        if not marker.exists():
            raise OperatorError('no_edge_rollback')
        record = json.loads(marker.read_text())
        for name in owned:
            path = EDGE / name
            actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
            allowed = [record['installed'][name]]
            if record['phase'] in ('activating', 'rolled-back'):
                allowed.append(record['baseline'].get(name))
            if actual not in allowed:
                raise OperatorError('shared_edge_changed_manual_rollback_required')
        for name in owned:
            target = EDGE / name
            if name in record['baseline']:
                write(target, (previous / name).read_text(), target.stat().st_mode & 0o777)
            else:
                target.unlink(missing_ok=True)
        record['phase'] = 'rolled-back'
        write(marker, json.dumps(record))
    else:
        if previous.exists():
            raise OperatorError('edge_already_activated_or_partial')
        baseline = json.loads((candidate / 'baseline.json').read_text())
        installed = json.loads((candidate / 'candidate.json').read_text())
        if edge_inventory() != baseline:
            raise OperatorError('shared_edge_changed_since_validation')
        if edge_inventory(candidate) != installed:
            raise OperatorError('edge_candidate_changed_since_validation')
        previous.mkdir(mode=0o700)
        for name in owned:
            if name in baseline:
                target = previous / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(EDGE / name, target)
        record = {'baseline': baseline, 'installed': installed, 'phase': 'activating'}
        write(previous / 'activated.json', json.dumps(record))
        for name in owned:
            target = EDGE / name
            mode = (target.stat().st_mode & 0o777) if target.exists() else 0o644
            write(target, (candidate / name).read_text(), mode)
        record['phase'] = 'activated'
        write(previous / 'activated.json', json.dumps(record))
    run(['docker', 'compose', '-f', EDGE / 'docker-compose.yml', 'up', '-d', '--no-deps', 'oxibelt'], timeout=180)
    firewall()
    print('shared edge ' + ('restored' if rollback else 'activated') + '; public acceptance required')


def start():
    m = maintenance_module()
    with m.State().locked():
        tool = m.Maintenance(m.State())
        value = tool.state.load()
        if value.get('fence') or value.get('operation') or tool.capacity_reason(tool.metrics()):
            raise OperatorError('admission_fenced')
        tool.start('postgres', 1)
        tool.start('backend', 1)
    print('backend ready with configured collector state')


def maintenance_module():
    spec = importlib.util.spec_from_file_location('devres_maintenance', HERE / 'maintenance.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collectors_on():
    m = maintenance_module()
    state = m.State()
    with state.locked():
        tool = m.Maintenance(state)
        value = state.load()
        if value.get('fence') or value.get('operation') or not value.get('verified'):
            raise OperatorError('verified_restore_required')
        if tool.capacity_reason(tool.metrics()):
            tool.guard()
            raise OperatorError('capacity_fence_active')
        text = (PRIVATE / 'backend.toml').read_text()
        parsed = tomllib.loads(text)
        if any(parsed[c]['enabled'] for c in COLLECTORS):
            raise OperatorError('collectors_already_or_partially_enabled')
        changed = text.replace('enabled = false', 'enabled = true')
        if sum(tomllib.loads(changed)[c]['enabled'] for c in COLLECTORS) != 8:
            raise OperatorError('collector_update_invalid')
        tool.scale('backend', 0)
        tool.stopped('backend')
        write(PRIVATE / 'backend.toml', changed)
        config_secret()
        tool.start('backend', 1)
    print('all eight collector families activated with unchanged provider limits')


def backup():
    # Guard remains able to fence foreground writes during the isolated drill.
    from restore import verify
    m = maintenance_module()
    state = m.State()
    with state.locked():
        tool = m.Maintenance(state)
        result = tool.snapshot(label='daily')
        name = result['snapshot']
        run(['zfs', 'hold', '-r', 'devres-restore-pending', m.DATASET + '@' + name])
    try:
        verify(name)
        with state.locked():
            m.Maintenance(state).mark_verified(name)
    finally:
        run(['zfs', 'release', '-r', 'devres-restore-pending', m.DATASET + '@' + name])
    print('coordinated snapshot and isolated restore verified: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'firewall', 'firewall-bootstrap', 'start', 'edge-prepare',
                        'edge-activate', 'edge-rollback', 'collectors-on', 'backup'])
    command = parser.parse_args().command
    if os.geteuid() != 0:
        raise OperatorError('root_required')
    os.umask(0o077)
    commands = {'prepare': prepare, 'firewall': firewall, 'firewall-bootstrap': lambda: firewall(False), 'start': start,
                'edge-prepare': edge_prepare, 'edge-activate': edge_activate,
                'edge-rollback': lambda: edge_activate(True), 'collectors-on': collectors_on,
                'backup': backup}
    commands[command]()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Fixed code only. The exception chain may hold secret external output.
        print('devres-staging operator failed: ' + (str(error) if isinstance(error, OperatorError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
