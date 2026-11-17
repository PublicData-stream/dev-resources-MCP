#!/usr/bin/env python3
"""Qualify the unchanged edge before a separately admitted metadata bridge.

No serving process or configuration is changed.  Only one task-owned, networkless
offline checker may be created.  Full MCP/WebTransport and live backend isolation
remain mandatory later deployment gates.
"""
from __future__ import annotations

import argparse
import copy
import errno
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time

REVISION = '3dae7d914baa9379abc402c5a3bcf311e0db01bf'
INSTALL = Path('/usr/local/libexec/devres-upgrade-3dae7d91')
BRIDGE = INSTALL / 'edge-readmission.py'
SCOPE = Path('/var/lib/devres-production-edge-admissions/3dae7d91-20261117')
WORK = Path('/tmp/devres-edge-qualification-3dae7d91-20261117')
HOST = 'dev-resources.mcp.publicdata.stream'
ADDRESSES = {'ipv4': '62.210.240.40', 'ipv6': '2001:bc8:701:65:56fb:66ff:fe00:da0d'}
CHECKS = frozenset(('native_image_config_check', 'edge_process_listener_binding', 'public_tls_ipv4', 'public_tls_ipv6',
    'public_withdrawn_http_ipv4', 'public_withdrawn_http_ipv6', 'private_nodeport_ipv4', 'private_nodeport_ipv6',
    'retained_firewall_and_private_routes'))
MAX_OUTPUT = 1024 * 1024
K = ['k3s', 'kubectl', '--context', 'default', '--namespace', 'devres', '--request-timeout=15s']


class Refused(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def raw(path, *, private=True, maximum=16 * 1024 ** 2):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'owned_path_required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
            and not before.st_mode & (0o077 if private else 0o022) and before.st_size <= maximum, 'owned_file_required')
        body = stream.read(maximum + 1); after = os.fstat(stream.fileno())
        need(len(body) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'file_changed')
    return body


def save(path, value):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'owned_output_required')
    parent = path.parent.stat()
    need(parent.st_uid == os.geteuid() and not parent.st_mode & 0o077, 'private_output_parent_required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value if type(value) is bytes else encode(value)); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def command(argv, *, timeout=30, limit=MAX_OUTPUT):
    """Bound bytes while reading; never print child arguments or diagnostics."""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, close_fds=True)
    selector = selectors.DefaultSelector(); buffers = {name: bytearray() for name in ('stdout', 'stderr')}
    deadline = time.monotonic() + timeout
    try:
        for name in buffers:
            stream = getattr(process, name); os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            need(time.monotonic() < deadline, 'qualification_command_deadline')
            for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(chunk)
                need(sum(len(v) for v in buffers.values()) <= limit, 'qualification_command_output_bound')
        return {'returncode': process.returncode, **{name: bytes(value) for name, value in buffers.items()}}
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        selector.close()
        process.stdout.close(); process.stderr.close()


def output(argv, *, timeout=30):
    result = command(argv, timeout=timeout)
    need(result['returncode'] == 0, 'qualification_read_command_failed')
    return result['stdout']


def checked_bridge(expected):
    need(re.fullmatch('[0-9a-f]{64}', expected or '') and sha(raw(BRIDGE)) == expected, 'bridge_source_pin_required')
    spec = importlib.util.spec_from_file_location('cycle4_qualification_edge_bridge', BRIDGE)
    value = importlib.util.module_from_spec(spec); sys.modules[spec.name] = value; spec.loader.exec_module(value)
    return value


def checker_arguments(snapshot, name):
    docker = snapshot['docker']; image = docker['image']; user = docker['config'].get('User')
    need(re.fullmatch('sha256:[0-9a-f]{64}', image or '') and image == snapshot['edge']['image'], 'immutable_edge_image_required')
    need(type(user) is str and re.fullmatch('[0-9]+(?::[0-9]+)?', user), 'numeric_native_checker_user_required')
    args = ['docker', 'create', '--pull', 'never', '--name', name, '--label', 'devres.edge-qualification=3dae7d91',
        '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--user', user, '--memory', '512m', '--cpus', '1', '--pids-limit', '64',
        '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777,size=16m', '--entrypoint', '/usr/local/bin/oxibelt']
    mounts = []
    for mount in docker['mounts']:
        source, destination = mount.get('Source'), mount.get('Destination')
        need(mount.get('Type') == 'bind' and type(source) is type(destination) is str
            and source.startswith('/') and destination.startswith('/')
            and not any(v in source + destination for v in (',', '\n', '\r', '\0')), 'retained_bind_mount_required')
        need(not Path(source).is_socket() and not any(p.is_symlink() for p in (Path(source), *Path(source).parents)), 'checker_socket_or_symlink_refused')
        mounts.append((source, destination))
        args += ['--mount', 'type=bind,src=' + source + ',dst=' + destination + ',readonly']
    need(len(mounts) == len({target for _, target in mounts}) and mounts, 'unique_retained_mounts_required')
    return args + [image, '--config', '/etc/oxibelt/config/oxibelt.toml', '--check']


def checker_identity(value, snapshot, name, uid=None):
    need(type(value) is dict and re.fullmatch('[0-9a-f]{64}', value.get('Id', ''))
        and (uid is None or value['Id'] == uid) and value.get('Name') == '/' + name
        and value.get('Image') == snapshot['docker']['image']
        and value.get('Config', {}).get('Labels', {}).get('devres.edge-qualification') == '3dae7d91'
        and value['Config'].get('User') == snapshot['docker']['config']['User']
        and value['Config'].get('Entrypoint') == ['/usr/local/bin/oxibelt']
        and value['Config'].get('Cmd') == ['--config', '/etc/oxibelt/config/oxibelt.toml', '--check'], 'owned_checker_identity_required')
    host = value['HostConfig']
    need(host.get('NetworkMode') == 'none' and host.get('ReadonlyRootfs') is True
        and host.get('CapDrop') == ['ALL'] and host.get('Privileged') is False
        and not host.get('CapAdd') and not host.get('PidMode') and host.get('Memory') == 512 * 1024 ** 2
        and host.get('PidsLimit') == 64
        and any(v in ('no-new-privileges', 'no-new-privileges:true') for v in host.get('SecurityOpt', [])), 'owned_checker_authority_required')
    expected = {(v['Source'], v['Destination']) for v in snapshot['docker']['mounts']}
    observed = {(v['Source'], v['Destination']) for v in value['Mounts'] if v['Type'] == 'bind'}
    need(expected == observed and all(v.get('RW') is False for v in value['Mounts'] if v['Type'] == 'bind')
        and all(v['Type'] == 'bind' or v['Type'] == 'tmpfs' and v['Destination'] == '/tmp' for v in value['Mounts']), 'checker_mount_authority_required')
    return value['Id']


def inspect_checker(reference):
    result = command(['docker', 'inspect', reference])
    if result['returncode']:
        need(result['returncode'] == 1 and any(value in result['stderr'] for value in (b'No such object:', b'No such container:')),
            'checker_inspection_unavailable')
        return None
    values = json.loads(result['stdout']); need(type(values) is list and len(values) == 1, 'single_checker_required')
    return values[0]


def offline_check(snapshot, work):
    name = 'devres-edge-check-3dae7d91'
    argv = checker_arguments(snapshot, name); uid = None; created = False; cleanup = False
    save(work / 'offline-intent.json', {'maximum_attempts': 1, 'name': name, 'image': snapshot['docker']['image'], 'argv_sha256': sha(encode(argv))})
    try:
        need(inspect_checker(name) is None, 'fresh_checker_name_required')
        created = True
        made = command(argv, timeout=60)
        save(work / 'offline-create.stdout', made['stdout']); save(work / 'offline-create.stderr', made['stderr'])
        need(made['returncode'] == 0 and re.fullmatch(b'[0-9a-f]{64}\n?', made['stdout']), 'checker_create_failed')
        uid = made['stdout'].decode().strip()
        inspected = inspect_checker(uid)
        checker_identity(inspected, snapshot, name, uid)
        result = command(['docker', 'start', '--attach', uid], timeout=60)
        save(work / 'offline-check.stdout', result['stdout']); save(work / 'offline-check.stderr', result['stderr'])
        need(result['returncode'] == 0, 'native_image_config_check_failed')
        after = inspect_checker(uid)
        checker_identity(after, snapshot, name, uid)
        need(after['State']['Status'] == 'exited' and after['State']['ExitCode'] == 0, 'native_checker_exit_required')
        return {'verified': True, 'image': snapshot['docker']['image'], 'no_network': True,
            'readonly_mounts': True, 'stdout_sha256': sha(result['stdout']), 'stderr_sha256': sha(result['stderr'])}
    finally:
        if created:
            found = inspect_checker(uid or name)
            if found is not None:
                owned = checker_identity(found, snapshot, name, uid)
                need(command(['docker', 'rm', '--force', owned])['returncode'] == 0, 'checker_cleanup_failed')
                need(inspect_checker(owned) is None, 'checker_cleanup_incomplete')
            cleanup = True
        save(work / 'offline-cleanup.json', {'known_complete': cleanup or not created, 'uid': uid, 'owned_only': True})


def validate_listeners(snapshot, tcp, udp):
    pid = snapshot['edge']['pid']; need(type(pid) is int and pid > 0, 'live_edge_pid_required')
    for body in (tcp, udp):
        matches = []
        for line in body.decode('ascii').splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[3].endswith(':443'):
                matches.append(line)
        need(matches and all(str(pid) in re.findall(r'pid=([0-9]+)', line) for line in matches), 'edge_listener_process_binding_required')
    return {'verified': True, 'tcp443': True, 'udp443': True, 'pid': pid}


def public_probe(family):
    address = ADDRESSES[family]; kind = socket.AF_INET if family == 'ipv4' else socket.AF_INET6
    ctx = ssl.create_default_context(); ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(['http/1.1'])
    with socket.socket(kind, socket.SOCK_STREAM) as connection:
        connection.settimeout(15); connection.connect((address, 443))
        with ctx.wrap_socket(connection, server_hostname=HOST) as tls:
            need(tls.version() == 'TLSv1.3' and tls.selected_alpn_protocol() == 'http/1.1', 'edge_public_tls_contract')
            certificate = tls.getpeercert()
            need(ssl.cert_time_to_seconds(certificate['notAfter']) - time.time() >= 86400, 'public_certificate_expiring')
            cert_sha = sha(tls.getpeercert(binary_form=True))
            tls.sendall(('GET /mcp HTTP/1.1\r\nHost: ' + HOST + '\r\nOrigin: https://' + HOST + '\r\nConnection: close\r\n\r\n').encode())
            answer = http.client.HTTPResponse(tls); answer.begin(); body = answer.read(65537)
            need(answer.status == 502 and len(body) <= 65536 and b'upstream request failed' in body, 'withdrawn_public_route_required')
    return {'tls_verified': True, 'withdrawn_http_verified': True, 'family': family, 'certificate_sha256': cert_sha,
        'http_status': 502, 'body_sha256': sha(body), 'full_mcp_acceptance': False}


def negative_connect(address, port):
    family = socket.AF_INET if ipaddress.ip_address(address).version == 4 else socket.AF_INET6
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        result = connection.connect_ex((address, port))
    need(result in (errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES), 'private_endpoint_connected')
    return {'connected': False, 'errno': result}


def nft_expressions(value):
    rows = value.get('nftables'); need(type(rows) is list, 'nft_inventory_required')
    tables = [v['table'] for v in rows if 'table' in v]; chains = [v['chain'] for v in rows if 'chain' in v]
    rules = [v['rule'] for v in rows if 'rule' in v]
    need(len(tables) == len(chains) == 1 and len(rules) == 4
        and all(set(v) <= {'metainfo', 'table', 'chain', 'rule'} for v in rows), 'exact_nodeport_rules_required')
    need(tables[0]['family'] == 'inet' and tables[0]['name'] == 'devres_guard'
        and all(chains[0].get(k) == v for k, v in {'family': 'inet', 'table': 'devres_guard', 'name': 'nodeports',
            'type': 'filter', 'hook': 'prerouting', 'prio': -310, 'policy': 'accept'}.items()), 'retained_nodeport_chain_required')
    match = lambda left, right: {'match': {'op': '==', 'left': left, 'right': right}}
    expected = []
    for protocol, port in (('tcp', 30081), ('udp', 30434)):
        expected.append([match({'meta': {'key': 'iifname'}}, 'devres-edge0'),
            match({'payload': {'protocol': 'ip', 'field': 'saddr'}}, '10.0.0.3'),
            match({'payload': {'protocol': 'ip', 'field': 'daddr'}}, '10.0.0.1'),
            match({'payload': {'protocol': protocol, 'field': 'dport'}}, port), {'accept': None}])
    expected += [[match({'payload': {'protocol': protocol, 'field': 'dport'}}, port), {'drop': None}]
        for protocol, port in (('tcp', 30081), ('udp', 30434))]
    need(all(v.get('family') == 'inet' and v.get('table') == 'devres_guard' and v.get('chain') == 'nodeports' for v in rules)
        and [v['expr'] for v in rules] == expected, 'retained_nodeport_expressions_changed')
    return sha(encode(expected))


def validate_timer_entrypoint(text, operation, context):
    match = re.search(r'argv\[\]=(.*?)\s*;', text)
    need(match is not None, 'timer_entrypoint_unavailable')
    args = shlex.split(match.group(1)); sources = context['sources']; script = Path(args[1]) if len(args) >= 2 else Path('/')
    expected = context['sources'][str(context['operator_module'].__file__)]
    need(len(args) == 7 and args[0] in ('/usr/bin/python3', '/usr/bin/python3.14')
        and str(script) in sources and sha(raw(script, private=False)) == sources[str(script)]
        and sources[str(script)] == expected
        and args[2:] == ['--context', 'default', '--bundle', str(context['operator_bundle']), operation], 'retained_timer_entrypoint_required')
    return {'operation': operation, 'script_sha256': sources[str(script)], 'bundle': str(context['operator_bundle'])}


def control_snapshot(context, candidate):
    base = context['controller_module']; prepared = context['prepared']
    boot = base.Controller.boot(object()); need(boot == prepared['boot'], 'retained_boot_changed')
    current = json.loads(output([*K, 'get', 'networkpolicies,roles,rolebindings,serviceaccounts,services,persistentvolumeclaims', '-o', 'json']))['items']
    need(base.foundation_projection(current) == prepared['foundation'], 'retained_private_foundation_changed')
    inventory = json.loads(output([*K, 'get', 'deployments,pods', '-o', 'json']))['items']
    deployments = {v['metadata']['name']: v for v in inventory if v['kind'] == 'Deployment'}
    pods = [v for v in inventory if v['kind'] == 'Pod']
    need(set(deployments) == {'postgres', 'writer', 'backend'}
        and {k: v['spec'].get('replicas', 1) for k, v in deployments.items()} == {'postgres': 1, 'writer': 0, 'backend': 0}
        and len(pods) == 1 and pods[0]['metadata'].get('labels', {}).get('app') == 'postgres', 'withdrawn_runtime_required')
    postgres = pods[0]; need(postgres['status']['phase'] == 'Running'
        and len(postgres['status'].get('containerStatuses', [])) == 1
        and postgres['status']['containerStatuses'][0]['ready'] is True, 'running_postgres_control_required')
    need(command([*K, 'exec', 'deployment/postgres', '--', 'pg_isready', '-h', '127.0.0.1', '-U', 'devres_admin', '-d', 'devres'])['returncode'] == 0,
        'postgres_positive_control_failed')
    guard = context['operator_module'].firewall_rules().encode()
    need(raw(Path('/etc/devres-production/nodeports.nft')) == b'destroy table inet devres_guard\n' + guard, 'retained_boot_firewall_file_changed')
    firewall = nft_expressions(json.loads(output(['nft', '-j', 'list', 'table', 'inet', 'devres_guard'])))
    boot_receipt = json.loads(raw(Path(context['operator_bundle']) / 'boot-guard-acceptance.json'))
    need(boot_receipt.get('fixture') is False and boot_receipt.get('release_revision') == context['operator_module'].REVISION
        and all(boot_receipt.get(k) is True for k in ('k3s_start_denied_when_guard_fails', 'docker_start_denied_when_guard_fails', 'guard_restored')),
        'retained_negative_boot_acceptance_required')
    for service in ('k3s.service', 'docker.service'):
        for property_ in ('Requires', 'After'):
            value = output(['systemctl', 'show', service, '--property=' + property_, '--value']).decode().split()
            need('devres-nodeport-guard.service' in value, 'retained_failclosed_boot_dependency_missing')
    need(output(['systemctl', 'is-active', 'devres-nodeport-guard.service']).strip() == b'active', 'nodeport_guard_inactive')
    timers = {}
    for name, operation in (('devres-capacity', 'capacity'), ('devres-cert-renew', 'cert-renew')):
        need(output(['systemctl', 'is-active', name + '.timer']).strip() == b'active', 'retained_timer_inactive')
        timers[name] = validate_timer_entrypoint(output(['systemctl', 'show', name + '.service', '--property=ExecStart', '--value']).decode(), operation, context)
    pg_address = postgres['status']['podIP']; need(ipaddress.ip_address(pg_address).is_private, 'private_postgres_address_required')
    denied = command(['docker', 'exec', candidate['after']['edge']['id'], '/usr/bin/nc', '-z', '-w', '3', pg_address, '5432'], timeout=10)
    need(denied['returncode'] == 1, 'edge_postgres_isolation_failed')
    return {'boot': boot, 'foundation_sha256': sha(encode(prepared['foundation'])), 'firewall_sha256': firewall,
        'negative_boot_receipt_sha256': sha(encode(boot_receipt)),
        'timers': timers, 'postgres_uid': postgres['metadata']['uid'], 'postgres_address': pg_address,
        'postgres_positive_control': True, 'edge_postgres_denied': True,
        'live_backend_isolation': 'deferred_until_backend_running', 'no_source_requests': True}


def optional_quic_probe(work):
    help_ = command(['openssl', 's_client', '-help'])
    if b'-quic' not in help_['stdout'] + help_['stderr']:
        return {'status': 'deferred', 'reason': 'openssl_quic_unavailable', 'native_webtransport_acceptance': False}
    cells = {}
    for family, address in ADDRESSES.items():
        remote = address + ':443' if family == 'ipv4' else '[' + address + ']:443'
        result = command(['openssl', 's_client', '-quic', '-connect', remote, '-servername', HOST,
            '-alpn', 'h3', '-verify_hostname', HOST, '-verify_return_error', '-CAfile', '/etc/ssl/certs/ca-certificates.crt', '-brief'], timeout=20)
        save(work / ('quic-' + family + '.stdout'), result['stdout']); save(work / ('quic-' + family + '.stderr'), result['stderr'])
        body = result['stdout'] + result['stderr']
        need(result['returncode'] == 0 and b'Verification: OK' in body, 'available_quic_tls_probe_failed')
        cells[family] = {'transport_tls_verified': True, 'diagnostics_sha256': sha(body)}
    return {'status': 'transport_tls_only', 'cells': cells, 'native_webtransport_acceptance': False}


def qualify(candidate_sha, bridge_sha, *, bridge=None, work=WORK):
    bridge = checked_bridge(bridge_sha) if bridge is None else bridge
    body = raw(SCOPE / 'candidate.json'); need(sha(body) == candidate_sha, 'external_candidate_hash_required')
    candidate = json.loads(body); producer_sha = sha(Path(__file__).read_bytes())
    need(candidate.get('qualification_producer_sha256') == producer_sha
        and candidate.get('bridge_source_sha256') == bridge_sha and candidate.get('revision') == REVISION, 'qualification_source_binding_required')
    need(bridge.candidate_matches_current(candidate), 'candidate_changed_before_qualification')
    context = bridge.qualification_context(candidate)
    work = Path(work); need(work.is_absolute() and Path('/tmp') in work.parents and not work.exists()
        and not any(p.is_symlink() for p in (work, *work.parents)), 'fresh_qualification_work_required')
    work.mkdir(mode=0o700, parents=True)
    save(work / 'intent.json', {'candidate_sha256': candidate_sha, 'producer_sha256': producer_sha, 'maximum_attempts': 1})
    before = control_snapshot(context, candidate)
    native = offline_check(candidate['after'], work)
    pid = candidate['after']['edge']['pid']
    listeners = validate_listeners(candidate['after'], output(['nsenter', '-t', str(pid), '-n', '--', 'ss', '-H', '-ltnp']),
        output(['nsenter', '-t', str(pid), '-n', '--', 'ss', '-H', '-lunp']))
    public = {family: public_probe(family) for family in ADDRESSES}
    need(native.get('verified') is True and native.get('no_network') is True and listeners.get('verified') is True
        and all(v.get('tls_verified') is True and v.get('withdrawn_http_verified') is True for v in public.values()),
        'complete_available_edge_checks_required')
    need(public['ipv4']['certificate_sha256'] == public['ipv6']['certificate_sha256'], 'dualstack_public_certificate_changed')
    nodeport = {family: negative_connect(address, 30081) for family, address in ADDRESSES.items()}
    quic = optional_quic_probe(work)
    after = control_snapshot(context, candidate)
    need(before == after and bridge.candidate_matches_current(candidate)
        and bridge.qualification_context(candidate)['bindings'] == context['bindings']
        and sha(Path(__file__).read_bytes()) == producer_sha, 'qualification_runtime_bookend_changed')
    detail = {'version': 1, 'candidate_sha256': candidate_sha, 'producer_sha256': producer_sha,
        'before': before, 'after': after, 'offline': native, 'listeners': listeners, 'public': public,
        'nodeport': nodeport, 'nodeport_scope': 'retained_tcp_udp_policy_and_negative_tcp_with_backend_withdrawn',
        'quic': quic, 'native_webtransport_acceptance': False, 'full_public_mcp_acceptance': False,
        'live_backend_private_isolation': 'mandatory_after_activation'}
    artifact = SCOPE / 'qualification-detail.json'; save(artifact, detail)
    receipt = {'version': 1, 'kind': 'cycle4-native-edge-qualification', 'candidate_sha256': candidate_sha,
        'producer_sha256': producer_sha, 'fixture': False, 'verified': True, 'checks': {name: True for name in CHECKS},
        'full_public_mcp_acceptance': False, 'native_webtransport_acceptance': False,
        'artifacts': [{'path': str(artifact), 'sha256': sha(raw(artifact))}]}
    save(SCOPE / 'qualification.json', receipt)
    return {'verified': True, 'qualification_sha256': sha(raw(SCOPE / 'qualification.json')),
        'full_public_mcp_acceptance': False, 'native_webtransport_acceptance': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-sha256', required=True); parser.add_argument('--bridge-sha256', required=True)
    args = parser.parse_args(); need(os.geteuid() == 0, 'root_required')
    print(json.dumps(qualify(args.candidate_sha256, args.bridge_sha256), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'verified': False, 'code': 'native_edge_qualification_failed'})); sys.exit(1)
