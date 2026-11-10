#!/usr/bin/env python3
"""Explicit-context production lifecycle; configuration and credentials stay private.

This tool never provisions a passing provider receipt or grants deployment authority.
The immutable runtime remains the published release. Start/collector admission uses
independently obtained private acceptance evidence, not fixture receipts.
"""
import argparse
import base64
import contextlib
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from urllib.parse import quote
import uuid


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0-build.172d528d"
REVISION = "172d528d88d16c9ec4fd83a16674280815178930"
OXIBELT_REVISION = "4f3154d8db0e0a49bce7a528c0a0f4c36d169040"
NAMESPACE = "devres"
WORKLOADS = ("postgres", "broker-postgres", "credential-broker", "writer", "backend")
COLLECTORS = ("rfc", "crates", "rustsec", "mdn", "whatwg", "w3c", "chromium", "npm")
MIN_FREE = 128 * 1024**3
EDGE = Path('/serve')
RUNTIME_SECRETS = ('devres-serving-config', 'devres-writer-config', 'devres-credential-broker-config',
                   'devres-backend-tls', 'devres-writer-tls', 'devres-broker-trust',
                   'devres-credential-broker-private')


class OperatorError(RuntimeError):
    """Only fixed diagnostic codes are exposed to callers."""


def call(args, data=None, timeout=180):
    try:
        result = subprocess.run([str(x) for x in args], input=data,
                                capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperatorError("command_unavailable_or_timed_out") from error
    if result.returncode or len(result.stdout) > 4 * 1024**2:
        raise OperatorError("command_failed_or_output_too_large")
    return result.stdout


def safe_directory(path, create=False):
    path = Path(path).absolute()
    for item in (*reversed(path.parents), path):
        if item.is_symlink():
            raise OperatorError("symlink_directory_refused")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise OperatorError("unsafe_private_directory")
    return path


def private_read(path, limit=1024**2):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > limit):
            raise OperatorError("unsafe_private_file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            value = source.read(limit + 1)
        if len(value) > limit:
            raise OperatorError("private_file_too_large")
        return value
    finally:
        os.close(descriptor)


def private_write(path, value):
    path = Path(path)
    safe_directory(path.parent, create=True)
    if path.exists() or path.is_symlink():
        raise OperatorError("private_output_already_exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value if isinstance(value, bytes) else value.encode())
        output.flush()
        os.fsync(output.fileno())


def private_replace(path, value):
    """Atomic replacement of operator-owned metadata; never follow links."""
    path = Path(path)
    safe_directory(path.parent)
    if path.exists() or path.is_symlink():
        private_read(path, 8 * 1024**2)
    temporary = path.parent / ('.' + path.name + '.' + secrets.token_hex(8))
    try:
        private_write(temporary, value)
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


@contextlib.contextmanager
def bundle_lock(bundle, name='.operator.lock'):
    if name not in ('.operator.lock', '.certificate.lock'):
        raise OperatorError('unexpected_operator_lock')
    descriptor = os.open(Path(bundle) / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
            raise OperatorError('unsafe_operator_lock')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise OperatorError('another_operation_is_active') from error
        yield
    finally:
        os.close(descriptor)


def renderer():
    spec = importlib.util.spec_from_file_location('devres_production', ROOT / 'deploy/production/production.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path):
    try:
        value = json.loads(private_read(path))
    except (ValueError, UnicodeError) as error:
        raise OperatorError("invalid_private_json") from error
    if not isinstance(value, dict):
        raise OperatorError("invalid_private_json")
    return value


def secret_manifest(name, fields):
    if not re.fullmatch(r"devres-[a-z0-9-]+", name):
        raise OperatorError("unexpected_secret_name")
    return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": name, "namespace": NAMESPACE,
                         "labels": {"app.kubernetes.io/part-of": "devres-production"}},
            "data": {key: base64.b64encode(value if isinstance(value, bytes)
                                           else value.encode()).decode()
                     for key, value in fields.items()}}


def postgres_inputs():
    """Generate passwords locally; no secret appears in argv or normal output."""
    values = {key: secrets.token_hex(24) for key in ("corpus_admin", "writer", "reader",
                                                   "broker_admin", "broker")}
    corpus = (f"CREATE ROLE devres_writer LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '{values['writer']}';\n"
              f"CREATE ROLE devres_reader LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '{values['reader']}';\n"
              "ALTER DATABASE devres OWNER TO devres_writer;\n"
              "REVOKE CONNECT ON DATABASE devres FROM PUBLIC;\n"
              "GRANT CONNECT ON DATABASE devres TO devres_writer, devres_reader;\n"
              "\\connect devres\n"
              "ALTER SCHEMA public OWNER TO devres_writer;\n"
              "REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n"
              "GRANT USAGE ON SCHEMA public TO devres_reader;\n"
              "ALTER DEFAULT PRIVILEGES FOR ROLE devres_writer IN SCHEMA public GRANT SELECT ON TABLES TO devres_reader;\n"
              "ALTER ROLE devres_reader SET default_transaction_read_only = on;\n")
    broker = (f"CREATE ROLE devres_broker LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '{values['broker']}';\n"
              "ALTER DATABASE devres_broker OWNER TO devres_broker;\n"
              "REVOKE CONNECT ON DATABASE devres_broker FROM PUBLIC;\n"
              "GRANT CONNECT ON DATABASE devres_broker TO devres_broker;\n"
              "\\connect devres_broker\n"
              "ALTER SCHEMA public OWNER TO devres_broker;\n"
              "REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n")
    return values, [secret_manifest("devres-corpus-postgres", {
                       "postgres-password": values["corpus_admin"], "init.sql": corpus}),
                    secret_manifest("devres-broker-postgres", {
                       "postgres-password": values["broker_admin"], "init.sql": broker})]


def prepare_tls(bundle):
    """Create private service/edge identities; public wildcard TLS is retained."""
    tls = safe_directory(Path(bundle) / 'tls', create=True)
    with tempfile.TemporaryDirectory(prefix='devres-tls-', dir='/tmp') as temporary:
        scratch = Path(temporary)

        def key(name):
            result = tls / (name + '.key')
            call(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', result])
            result.chmod(0o600)
            return result

        for name in ('backend-ca', 'edge-client-ca', 'coordination-ca'):
            signing_key = key(name)
            call(['openssl', 'req', '-new', '-x509', '-sha256', '-days', '3650', '-key', signing_key,
                  '-subj', '/CN=devres-production-' + name,
                  '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                  '-out', tls / (name + '.crt')])
            (tls / (name + '.crt')).chmod(0o600)
        for name, ca, names, usage in (
                ('backend', 'backend-ca', ['devres-k8s'], 'serverAuth'),
                ('edge-client', 'edge-client-ca', ['devres-edge.internal'], 'clientAuth'),
                ('writer', 'coordination-ca', ['writer', 'writer.devres.svc', 'writer.devres.svc.cluster.local'], 'serverAuth'),
                ('credential-broker', 'coordination-ca', ['credential-broker', 'credential-broker.devres.svc',
                                                         'credential-broker.devres.svc.cluster.local'], 'serverAuth')):
            private_key = key(name)
            request = scratch / (name + '.csr')
            extensions = scratch / (name + '.ext')
            extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                                  'extendedKeyUsage=' + usage + '\nsubjectAltName=' +
                                  ','.join('DNS:' + value for value in names) + '\n')
            call(['openssl', 'req', '-new', '-sha256', '-key', private_key,
                  '-subj', '/CN=' + names[0], '-out', request])
            call(['openssl', 'x509', '-req', '-sha256', '-days', '365', '-in', request,
                  '-CA', tls / (ca + '.crt'), '-CAkey', tls / (ca + '.key'),
                  '-set_serial', '0x' + secrets.token_hex(16), '-extfile', extensions,
                  '-out', tls / (name + '.crt')])
            (tls / (name + '.crt')).chmod(0o600)


def collector_config(text, enabled):
    """Change only the eight explicit admission switches, preserving all budgets."""
    before = tomllib.loads(text)
    for name in COLLECTORS:
        if type(before.get(name, {}).get('enabled')) is not bool:
            raise OperatorError('explicit_collector_settings_required')
        expression = rf'(?m)(^\[{name}\]\s*\n(?:[ \t]*#[^\n]*\n)*[ \t]*enabled\s*=\s*)(?:true|false)([ \t]*(?:#[^\n]*)?$)'
        text, count = re.subn(expression, lambda match: match[1] + str(enabled).lower() + match[2], text)
        if count != 1:
            raise OperatorError('collector_configuration_shape_invalid')
    expected = json.loads(json.dumps(before))
    for name in COLLECTORS:
        expected[name]['enabled'] = enabled
    if tomllib.loads(text) != expected:
        raise OperatorError('unexpected_collector_configuration_change')
    return text


def merge_edge_compose(existing, candidate):
    """Keep lego and its private mount/secret references intact on this host."""
    result = json.loads(json.dumps(existing))
    services = result.setdefault('services', {})
    if set(services) - {'oxibelt', 'lego'}:
        raise OperatorError('unexpected_colocated_compose_service')
    services['oxibelt'] = candidate['services']['oxibelt']
    result['networks'] = json.loads(json.dumps(candidate['networks']))
    # Docker's canonical model attaches an unused default network to lego.
    if 'lego' in services:
        if services['lego'].get('image') not in ('goacme/lego:latest', 'docker.io/goacme/lego:latest', renderer().LEGO):
            raise OperatorError('unexpected_existing_lego_image')
        services['lego']['image'] = renderer().LEGO
        for name in services['lego'].get('networks', {}):
            if name != 'default':
                raise OperatorError('unexpected_lego_network')
            result['networks'][name] = existing.get('networks', {}).get(name, {})
    return result


def lego_service_identity(compose):
    """Admit the existing config-file workflow without exposing DNS credentials."""
    service = compose.get('services', {}).get('lego', {})
    if (service.get('image') != renderer().LEGO or service.get('command') != ['--config', '/.lego.yaml']
            or service.get('user') != '10001:10001'
            or compose.get('secrets', {}).get('lego_cf_token', {}).get('file') != str(EDGE / 'lego/lego_cf_token')):
        raise OperatorError('unexpected_lego_configuration')
    mounts = {value.get('target'): value for value in service.get('volumes', []) if isinstance(value, dict)}
    for target, source, readonly in (('/.lego.yaml', EDGE / 'lego/.lego.yaml', True),
                                      ('/var/lib/lego', EDGE / 'lego/data', False)):
        value = mounts.get(target, {})
        if value.get('source') != str(source) or value.get('read_only', False) != readonly:
            raise OperatorError('unexpected_lego_mount')
    tokens = service.get('secrets', [])
    if (len(tokens) != 1 or tokens[0].get('source') != 'lego_cf_token'
            or tokens[0].get('target', 'lego_cf_token') not in ('lego_cf_token', '/run/secrets/lego_cf_token')):
        raise OperatorError('unexpected_lego_secret_reference')
    return hashlib.sha256(json.dumps(service, sort_keys=True).encode()).hexdigest()


def validate_lego_certificate_list(encoded):
    """Reject lego's successful empty/default-store fallback on invalid YAML."""
    try:
        certificates = json.loads(encoded)
    except (ValueError, UnicodeError) as error:
        raise OperatorError('lego_certificate_inventory_invalid') from error
    if not isinstance(certificates, list):
        raise OperatorError('lego_configured_certificate_not_found')
    matching = [item for item in certificates if isinstance(item, dict)
                and item.get('name') == 'publicdata-stream'
                and item.get('path') == '/var/lib/lego/certificates/publicdata-stream.crt'
                and item.get('expired') is False
                and isinstance(item.get('domains'), list)
                and {'publicdata.stream', '*.mcp.publicdata.stream'}.issubset(item['domains'])]
    if len(matching) != 1:
        raise OperatorError('lego_configured_certificate_not_found')


def edge_file_bytes(path, limit=1024**2):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit
                or info.st_uid not in (0, 10001, os.geteuid()) or info.st_mode & 0o002):
            raise OperatorError('unsafe_edge_metadata_file')
        value = os.read(descriptor, limit + 1)
        if len(value) > limit:
            raise OperatorError('edge_metadata_too_large')
        return value
    finally:
        os.close(descriptor)


def comment_unrelated(text):
    """Retain an inactive copied snippet without leaving any active TOML table."""
    return "# Disabled: unrelated to dev-resources production deployment.\n" + "".join(
        "# " + line if line.strip() and not line.lstrip().startswith("#") else line
        for line in text.splitlines(keepends=True))


def firewall_rules():
    # Raw prerouting precedes kube-proxy DNAT; match the actual Docker bridge.
    # Do not flush unrelated tables or change SSH/control-plane host policy.
    return '''table inet devres_guard {
  chain nodeports {
    type filter hook prerouting priority -310; policy accept;
    iifname "devres-edge0" ip saddr 10.0.0.3 ip daddr 10.0.0.1 tcp dport 30081 accept
    iifname "devres-edge0" ip saddr 10.0.0.3 ip daddr 10.0.0.1 udp dport 30434 accept
    tcp dport 30081 drop
    udp dport 30434 drop
  }
}
'''


def source_receipt(value):
    if value.get("release_revision") != REVISION or value.get("fixture") is not False:
        raise OperatorError("source_acceptance_identity_mismatch")
    providers = value.get("providers")
    if not isinstance(providers, dict) or set(providers) != set(COLLECTORS):
        raise OperatorError("source_acceptance_incomplete")
    for provider in providers.values():
        if (not isinstance(provider, dict) or provider.get("passed") is not True
                or type(provider.get("attempts")) is not int
                or not 0 < provider["attempts"] <= 20):
            raise OperatorError("source_acceptance_incomplete")
    if type(value.get("github_attempts")) is not int or not 0 <= value["github_attempts"] <= 20:
        raise OperatorError("source_acceptance_budget_invalid")


def edge_receipt(value):
    required = ("http_2025_11_25", "http_2026_07_28", "wt_2025_11_25", "wt_2026_07_28",
                "ipv4", "ipv6", "nodeport_denied", "private_services_denied",
                "representative_writer_s3_readback", "sql_readonly", "s3_readonly",
                "boot_guard_failure_denied")
    if value.get("release_revision") != REVISION or value.get("fixture") is not False:
        raise OperatorError("edge_acceptance_identity_mismatch")
    if any(value.get(name) is not True for name in required):
        raise OperatorError("edge_acceptance_incomplete")


def provider_receipt(value, now=None):
    """Admit real operator evidence; never manufacture a passing receipt."""
    now = now or datetime.now(timezone.utc)
    required = ("unrelated_application_denied", "policy_management_denied", "expiry_accepted")
    if value.get("fixture") is not False or any(value.get(k) is not True for k in required):
        raise OperatorError("real_provider_acceptance_required")
    profiles = value.get("profile_fingerprints", {})
    admitted = value.get("confined_application_ids", [])
    if (not isinstance(profiles, dict) or len(profiles) != 2
            or not isinstance(admitted, list) or sorted(profiles) != sorted(admitted)
            or len(set(admitted)) != 2 or value.get("ttl_secs") != 900
            or any(not isinstance(item, str) or not re.fullmatch('[0-9a-f]{64}', item) for item in profiles.values())
            or type(value.get("broker_key_budget")) is not int
            or value["broker_key_budget"] < 40):
        raise OperatorError("provider_acceptance_scope_invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", value.get("issuer_secret_fingerprint", "")):
        raise OperatorError("provider_acceptance_scope_invalid")
    try:
        verified = datetime.fromisoformat(value["verified_at"].replace("Z", "+00:00"))
        expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
        if (verified.utcoffset() is None or expiry.utcoffset() is None or verified > now
                or (now - verified).total_seconds() > 31 * 86400 or expiry <= now):
            raise ValueError()
    except (KeyError, ValueError, TypeError, AttributeError) as error:
        raise OperatorError("provider_acceptance_expired_or_invalid") from error


def verify_broker_fingerprints(config, issuer_secret, receipt):
    """Use the deployed binary's offline canonical hashes before any Secret write."""
    with tempfile.TemporaryDirectory(prefix='devres-broker-admission-', dir='/tmp') as temporary:
        root = Path(temporary)
        private_write(root / 'config.toml', config)
        private_write(root / 'issuer-secret-key', issuer_secret)
        base = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges:true', '--user', '0:0',
                '-v', str(root) + ':/run/devres-broker:ro', renderer().BROKER]
        profiles = json.loads(call([*base, 'profile-fingerprints', '/run/devres-broker/config.toml']))
        issuer = call([*base, 'issuer-fingerprint', '/run/devres-broker/config.toml']).decode().strip()
        if profiles != receipt['profile_fingerprints'] or issuer != receipt['issuer_secret_fingerprint']:
            raise OperatorError('broker_offline_receipt_binding_mismatch')


def contains_expected(actual, expected):
    """Permit API-defaulted fields while requiring every intended runtime field."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and contains_expected(actual[key], value)
                                                for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(
            contains_expected(left, right) for left, right in zip(actual, expected))
    return actual == expected


class Operator:
    def __init__(self, context, bundle):
        if not context or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", context):
            raise OperatorError("explicit_context_required")
        self.context = context
        self.bundle = safe_directory(bundle)

    def k(self, *args, data=None, timeout=180):
        return call(["k3s", "kubectl", "--context", self.context, "--namespace", NAMESPACE,
                     "--request-timeout=30s", *args], data=data, timeout=timeout)

    def scale(self, name, count):
        self.k("scale", "deployment/" + name, "--replicas=" + str(count))
        if count:
            self.k("rollout", "status", "deployment/" + name, "--timeout=120s")
        else:
            self.k("wait", "--for=delete", "pod", "-l", "app=" + name, "--timeout=120s")

    def status(self):
        raw = json.loads(self.k("get", "deploy", "-o", "json"))
        return {d["metadata"]["name"]: {"desired": d["spec"].get("replicas", 1),
                "ready": d.get("status", {}).get("readyReplicas", 0)}
                for d in raw["items"] if d["metadata"]["name"] in WORKLOADS}

    def record(self, **changes):
        path = self.bundle / 'state.json'
        state = read_json(path) if path.exists() else {'version': 1, 'revision': REVISION, 'phase': 'prepared'}
        if state.get('revision') != REVISION:
            raise OperatorError('operator_state_identity_mismatch')
        state.update(changes)
        private_replace(path, json.dumps(state, sort_keys=True))
        return state

    def validate_identity(self):
        identity = read_json(self.bundle / "release.json")
        module = renderer()
        expected = {'version': VERSION, 'revision': REVISION, 'server': module.SERVER,
                    'broker': module.BROKER, 'probe': module.PROBE, 'postgres': module.POSTGRES,
                    'source_sha256': module.SOURCE_SHA256}
        if identity != expected:
            raise OperatorError("bundle_release_identity_mismatch")
        return identity

    def validate_cluster(self, bind=False):
        self.validate_identity()
        state = read_json(self.bundle / 'state.json')
        if state.get('revision') != REVISION:
            raise OperatorError('operator_state_identity_mismatch')
        uid = json.loads(self.k('get', 'namespace', 'kube-system', '-o', 'json'))['metadata']['uid']
        if not uid or (state.get('cluster_uid') != uid and not (bind and state.get('cluster_uid') is None)):
            raise OperatorError('cluster_identity_mismatch')
        settings = read_json(self.bundle / 'settings.json')
        if hashlib.sha256(private_read(self.bundle / 'settings.json')).hexdigest() != state.get('settings_sha256'):
            raise OperatorError('bundle_settings_changed')
        node = json.loads(self.k('get', 'node', settings['node_name'], '-o', 'json'))
        addresses = [value['address'] for value in node['status']['addresses']]
        if settings['node_ipv4'] not in addresses:
            raise OperatorError('node_identity_mismatch')
        namespace_uid = json.loads(self.k('get', 'namespace', NAMESPACE, '-o', 'json'))['metadata']['uid']
        node_uid = node['metadata']['uid']
        for key, observed in (('node_uid', node_uid), ('namespace_uid', namespace_uid)):
            if not observed or (state.get(key) != observed and not (bind and state.get(key) is None)):
                raise OperatorError('runtime_identity_recreated')
        if bind and state.get('cluster_uid') is None:
            self.record(cluster_uid=uid, node_uid=node_uid, namespace_uid=namespace_uid)

    def validate_runtime_state(self):
        manifest = read_json(self.bundle / 'kubernetes.json')
        if manifest != renderer().manifests(renderer().settings_checked(read_json(self.bundle / 'settings.json'))):
            raise OperatorError('rendered_manifest_changed')
        expected = {item['metadata']['name']: item for item in manifest['items']
                    if item['kind'] == 'Deployment'}
        live = json.loads(self.k('get', 'deployments', '-o', 'json'))['items']
        actual = {item['metadata']['name']: item for item in live if item['metadata']['name'] in WORKLOADS}
        if set(actual) != set(expected):
            raise OperatorError('runtime_deployment_set_mismatch')
        for name, item in expected.items():
            desired = item['spec']['template']['spec']
            observed = actual[name]['spec']['template']['spec']
            if (any(observed.get(key) for key in ('hostNetwork', 'hostPID', 'hostIPC', 'initContainers'))
                    or any(container.get('securityContext', {}).get('privileged')
                           for container in observed.get('containers', []))):
                raise OperatorError('unexpected_runtime_privilege')
            if not contains_expected(observed, desired):
                raise OperatorError('runtime_deployment_identity_mismatch')
            expected_container = desired['containers'][0]
            observed_container = observed['containers'][0]
            for key in ('command', 'args', 'env', 'envFrom'):
                if expected_container.get(key, []) != observed_container.get(key, []):
                    raise OperatorError('runtime_invocation_changed')
        for name in RUNTIME_SECRETS:
            observed = json.loads(self.k('get', 'secret', name, '-o', 'json'))
            expected_secret = read_json(self.bundle / (name + '.json'))
            if observed.get('data') != expected_secret.get('data'):
                raise OperatorError('runtime_secret_changed')

    def apply_secret(self, name, encoded):
        value = json.loads(encoded)
        if (value.get('kind') != 'Secret' or value.get('metadata', {}).get('name') != name
                or value['metadata'].get('namespace') != NAMESPACE or value.get('type') != 'Opaque'):
            raise OperatorError('unexpected_secret_manifest')
        self.k('apply', '-f', '-', data=encoded)

    def install_firewall(self):
        desired = private_read(self.bundle / 'devres-guard.nft')
        # Destroy/recreate only this owned table, atomically; never flush global rules.
        desired = b'destroy table inet devres_guard\n' + desired
        call(['nft', '--check', '-f', '-'], data=desired)
        call(['nft', '-f', '-'], data=desired)
        destination = Path('/etc/devres-production')
        safe_directory(destination, create=True)
        private_replace(destination / 'nodeports.nft', desired)
        unit = ('[Unit]\nDescription=Devres private NodePort boundary\nBefore=k3s.service docker.service\n'
                'After=local-fs.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                'ExecStart=/usr/sbin/nft -f /etc/devres-production/nodeports.nft\n'
                '[Install]\nWantedBy=multi-user.target\n')
        self.system_file(Path('/etc/systemd/system/devres-nodeport-guard.service'), unit)
        call(['systemctl', 'daemon-reload'])
        call(['systemctl', 'enable', 'devres-nodeport-guard.service'])
        call(['systemctl', 'start', 'devres-nodeport-guard.service'])

    def system_file(self, path, content, mode=0o644):
        path = Path(path)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise OperatorError('unsafe_system_configuration')
        if path.exists() and path.stat().st_uid != os.geteuid():
            raise OperatorError('unowned_system_configuration')
        temporary = path.parent / ('.' + path.name + '.devres-' + secrets.token_hex(8))
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(content if isinstance(content, bytes) else content.encode())
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def install(self):
        self.validate_cluster(bind=True)
        # Installation is initial-only: applying zero replicas to a live runtime
        # would be a topology change rather than a safe declarative update.
        state = self.status()
        if any(v["desired"] or v["ready"] for v in state.values()):
            raise OperatorError("initial_install_requires_stopped_runtime")
        manifest = private_read(self.bundle / "kubernetes.json", 4 * 1024**2)
        value = json.loads(manifest)
        if any(item.get("spec", {}).get("replicas", 0) != 0 for item in value["items"]
               if item.get("kind") == "Deployment"):
            raise OperatorError("install_requires_zero_replicas")
        expected = renderer().manifests(renderer().settings_checked(read_json(self.bundle / 'settings.json')))
        if value != expected:
            raise OperatorError('rendered_manifest_changed')
        encryption = call(['k3s', 'secrets-encrypt', 'status']).decode()
        if 'Encryption Status: Enabled' not in encryption or 'All hashes match' not in encryption:
            raise OperatorError('native_secret_encryption_required')
        self.prepare_local_volumes()
        self.install_firewall()
        foundation = [item for item in value['items'] if item['kind'] in ('Namespace', 'NetworkPolicy')]
        self.k('apply', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': foundation}).encode())
        self.k("apply", "--dry-run=server", "-f", "-", data=manifest)
        self.k("apply", "-f", "-", data=manifest)
        # Only the PostgreSQL initialization secrets may exist before live IAM
        # admission. Other secrets are provisioned after independent acceptance.
        for name in ("devres-corpus-postgres", "devres-broker-postgres"):
            secret = private_read(self.bundle / (name + ".json"))
            self.apply_secret(name, secret)
        self.record(phase='installed')
        return {"installed": True, "runtime_stopped": True}

    def prepare_local_volumes(self):
        for directory, uid in (('/database/devres/corpus', 70), ('/database/devres/broker', 70),
                               ('/var/cache/devres/serving', 65532), ('/var/cache/devres/writer', 65532)):
            path = Path(directory)
            if any(item.is_symlink() for item in (path, *path.parents)):
                raise OperatorError('unsafe_local_volume')
            path.mkdir(parents=True, mode=0o750, exist_ok=True)
            if read_json(self.bundle / 'state.json')['phase'] == 'prepared' and any(path.iterdir()):
                raise OperatorError('initial_storage_is_not_empty')
            os.chown(path, uid, uid)
            path.chmod(0o750)

    def start_postgres(self):
        self.validate_cluster()
        for name in WORKLOADS[2:]:
            if self.status().get(name, {}).get("desired", 0):
                raise OperatorError("postgres_bootstrap_requires_stopped_runtime")
        for name in WORKLOADS[:2]:
            self.scale(name, 1)
        self.record(phase='postgres_ready')
        return {"postgres_started": True}

    def provision_runtime(self, inputs_file):
        self.validate_cluster()
        if any(self.status().get(name, {}).get('desired', 0) for name in WORKLOADS[2:]):
            raise OperatorError('runtime_secret_update_requires_stopped_roles')
        inputs = read_json(inputs_file)
        for name in ('organization_id', 'project_id', 'issuer_application_id',
                     'reader_application_id', 'writer_application_id'):
            try:
                if str(uuid.UUID(inputs[name])) != inputs[name]:
                    raise ValueError()
            except (KeyError, ValueError, AttributeError) as error:
                raise OperatorError('invalid_private_identity') from error
        if len({inputs[name] for name in ('issuer_application_id', 'reader_application_id', 'writer_application_id')}) != 3:
            raise OperatorError('application_identities_must_differ')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', inputs.get('issuer_access_key', '')):
            raise OperatorError('invalid_private_identity')
        for name in ('reader_policy_sha256', 'writer_policy_sha256'):
            if not re.fullmatch('[0-9a-f]{64}', inputs.get(name, '')):
                raise OperatorError('invalid_private_policy_fingerprint')
        receipt_bytes = private_read(inputs['acceptance_receipt_file'], 65536)
        receipt = json.loads(receipt_bytes)
        provider_receipt(receipt)
        if (receipt.get('issuer_access_key') != inputs['issuer_access_key']
                or receipt.get('issuer_application_id') != inputs['issuer_application_id']
                or set(receipt['confined_application_ids']) != {inputs['reader_application_id'], inputs['writer_application_id']}):
            raise OperatorError('provider_receipt_identity_mismatch')
        issuer_secret = private_read(inputs['issuer_secret_file'], 16384).strip()
        if not issuer_secret or len(issuer_secret) > 4096:
            raise OperatorError('invalid_issuer_secret')
        passwords = read_json(self.bundle / 'database-passwords.json')
        substitutions = {'@CORPUS_READER_PASSWORD@': quote(passwords['reader'], safe=''),
                         '@CORPUS_WRITER_PASSWORD@': quote(passwords['writer'], safe='')}
        for name in ('organization_id', 'project_id', 'issuer_access_key', 'issuer_application_id',
                     'reader_application_id', 'writer_application_id', 'reader_policy_sha256', 'writer_policy_sha256'):
            substitutions['@' + name.upper() + '@'] = inputs[name]
        configs = {}
        for name in ('serving', 'writer', 'credential-broker'):
            text = private_read(self.bundle / (name + '.toml.example')).decode()
            for marker, replacement in substitutions.items():
                text = text.replace(marker, replacement)
            if re.search(r'@[A-Z_]+@', text):
                raise OperatorError('unresolved_private_configuration')
            parsed = tomllib.loads(text)
            if name != 'credential-broker':
                if any(parsed[provider]['enabled'] for provider in COLLECTORS):
                    raise OperatorError('initial_collectors_must_be_disabled')
            elif parsed.get('fixture_mode') is not False or parsed.get('organization_id') != inputs['organization_id']:
                raise OperatorError('production_broker_configuration_required')
            configs[name] = text
        tls = self.bundle / 'tls'
        keyring = private_read(inputs.get('keyring_file', self.bundle / 'broker-keyring.json'), 16384)
        ring = json.loads(keyring)
        if (ring.get('active_key_id') not in ring.get('keys', {}) or not 1 <= len(ring['keys']) <= 8
                or any(not re.fullmatch('[0-9a-f]{64}', value) for value in ring['keys'].values())):
            raise OperatorError('invalid_broker_keyring')
        verify_broker_fingerprints(configs['credential-broker'], issuer_secret, receipt)
        manifests = {name: secret_manifest(name, fields) for name, fields in (
            ('devres-serving-config', {'serving.toml': configs['serving']}),
            ('devres-writer-config', {'writer.toml': configs['writer']}),
            ('devres-credential-broker-config', {'credential-broker.toml': configs['credential-broker']}),
            ('devres-backend-tls', {'backend.pem': private_read(tls / 'backend.crt'),
                                   'backend-key.pem': private_read(tls / 'backend.key'),
                                   'client-ca.pem': private_read(tls / 'edge-client-ca.crt')}),
            ('devres-writer-tls', {'tls.crt': private_read(tls / 'writer.crt'),
                                 'tls.key': private_read(tls / 'writer.key'),
                                 'ca.crt': private_read(tls / 'coordination-ca.crt')}),
            ('devres-broker-trust', {'ca.crt': private_read(tls / 'coordination-ca.crt')}),
            ('devres-credential-broker-private', {'tls.crt': private_read(tls / 'credential-broker.crt'),
                'tls.key': private_read(tls / 'credential-broker.key'),
                'database-url': f"postgres://devres_broker:{passwords['broker']}@broker-postgres/devres_broker",
                'keyring.json': keyring, 'issuer-secret-key': issuer_secret, 'acceptance-receipt.json': receipt_bytes}))}
        # All private inputs pass admission before the first cluster Secret write.
        private_replace(self.bundle / 'acceptance-receipt.json', receipt_bytes)
        for name, manifest in manifests.items():
            encoded = json.dumps(manifest).encode()
            private_replace(self.bundle / (name + '.json'), encoded)
            self.apply_secret(name, encoded)
        for name, text in configs.items():
            private_replace(self.bundle / (name + '.toml'), text)
        self.record(phase='runtime_provisioned', runtime_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest())
        return {'runtime_secrets_provisioned': True, 'collectors_enabled': False}

    def admit_start(self):
        self.validate_cluster()
        self.validate_runtime_state()
        provider_receipt(read_json(self.bundle / "acceptance-receipt.json"))
        # Runtime Secret/configuration provisioning is an independent prerequisite.
        # Presence alone is not proof; the broker verifies exact profile/secret
        # fingerprints and the trusted live cluster UID before issuing a key.
        if read_json(self.bundle / 'state.json').get('phase') not in ('runtime_provisioned', 'stopped', 'start_failed'):
            raise OperatorError('runtime_provisioning_required')
        for role in ('serving', 'writer'):
            config = tomllib.loads(private_read(self.bundle / (role + '.toml')).decode())
            if any(config[name]['enabled'] for name in COLLECTORS):
                raise OperatorError('initial_collectors_must_be_disabled')
        for name in RUNTIME_SECRETS:
            self.k("get", "secret", name, "-o", "name")
        if shutil.disk_usage('/database/devres').free < MIN_FREE:
            raise OperatorError('capacity_reserve_required')
        try:
            for name in WORKLOADS:
                self.scale(name, 1)
        except OperatorError:
            self.record(phase='start_failed')
            self.stop()
            raise
        self.record(phase='runtime_ready')
        return {"runtime_started": True, "collectors_require_separate_acceptance": True}

    def stop(self):
        self.validate_cluster()
        current = self.status()
        failures = []
        for name in ("backend", "writer"):
            if name in current:
                try:
                    self.scale(name, 0)
                except OperatorError:
                    failures.append(name)
        self.record(phase='stop_incomplete' if failures else 'stopped')
        if failures:
            raise OperatorError('role_stop_incomplete')
        return {"serving_stopped": True, "writer_stopped": True, "history_preserved": True}

    def capacity(self):
        self.validate_cluster()
        free = shutil.disk_usage("/database/devres").free
        if free < MIN_FREE:
            self.withdraw()
            self.record(phase='capacity_fenced')
            return {"capacity_fenced": True, "history_preserved": True}
        return {"capacity_fenced": False, "free_bytes": free}

    def install_capacity_timer(self):
        executable = Path(__file__).resolve()
        # Values are validated identifiers/private absolute paths; use systemd's quoted argv.
        argv = ' '.join('"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'
                        for value in ('/usr/bin/python3', executable, '--context', self.context,
                                      '--bundle', self.bundle, 'capacity'))
        service = ('[Unit]\nDescription=Devres capacity safety fence\nAfter=k3s.service docker.service\n'
                   '[Service]\nType=oneshot\nUMask=0077\nExecStart=' + argv + '\n')
        timer = ('[Unit]\nDescription=Devres capacity reserve monitor\n[Timer]\nOnBootSec=1min\n'
                 'OnUnitActiveSec=1min\nAccuracySec=5s\n[Install]\nWantedBy=timers.target\n')
        self.system_file(Path('/etc/systemd/system/devres-capacity.service'), service)
        self.system_file(Path('/etc/systemd/system/devres-capacity.timer'), timer)
        call(['systemctl', 'daemon-reload'])
        call(['systemctl', 'enable', '--now', 'devres-capacity.timer'])

    def install_certificate_timer(self):
        """Configure renewal only after the separately admitted edge installation."""
        compose = json.loads(call(['docker', 'compose', '--profile', 'run-lego', '-f', EDGE / 'docker-compose.yml',
                                   'config', '--format', 'json']))
        identity = lego_service_identity(compose)
        image = renderer().LEGO
        call(['docker', 'pull', image], timeout=600)
        help_text = call(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                          '--security-opt', 'no-new-privileges:true', image, '--help'])
        if b'--config' not in help_text or b'configuration' not in help_text.lower():
            raise OperatorError('lego_config_file_cli_required')
        # Exit zero is insufficient: lego silently falls back to its default
        # store when YAML loading fails. Require the actual configured public
        # certificate and absolute storage path, without mounting the DNS token.
        listed = call(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
              '-v', str(EDGE / 'lego/.lego.yaml') + ':/.lego.yaml:ro',
              '-v', str(EDGE / 'lego/data') + ':/var/lib/lego:ro', image,
              'certificates', 'list', '--json', '--config', '/.lego.yaml'])
        validate_lego_certificate_list(listed)
        private_replace(self.bundle / 'lego-renewal.json', json.dumps({
            'revision': REVISION, 'image': image, 'lego_service_sha256': identity,
            'config_sha256': hashlib.sha256(edge_file_bytes(EDGE / 'lego/.lego.yaml')).hexdigest()}))
        argv = ' '.join('"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'
                        for value in ('/usr/bin/python3', Path(__file__).resolve(), '--context', self.context,
                                      '--bundle', self.bundle, 'cert-renew'))
        service = ('[Unit]\nDescription=Devres wildcard DNS01 certificate renewal\nAfter=docker.service\n'
                   '[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=75min\nExecStart=' + argv + '\n')
        timer = ('[Unit]\nDescription=Devres twice-daily certificate renewal\n[Timer]\n'
                 'OnCalendar=*-*-* 00,12:00:00\nRandomizedDelaySec=1h\nPersistent=true\n'
                 '[Install]\nWantedBy=timers.target\n')
        self.system_file(Path('/etc/systemd/system/devres-cert-renew.service'), service)
        self.system_file(Path('/etc/systemd/system/devres-cert-renew.timer'), timer)
        call(['systemctl', 'daemon-reload'])
        call(['systemctl', 'enable', '--now', 'devres-cert-renew.timer'])

    def cert_renew(self):
        self.validate_cluster()
        if read_json(self.bundle / 'state.json').get('phase') not in ('edge_ready', 'collectors_active'):
            raise OperatorError('certificate_renewal_requires_admitted_edge')
        accepted = read_json(self.bundle / 'lego-renewal.json')
        compose = json.loads(call(['docker', 'compose', '--profile', 'run-lego', '-f', EDGE / 'docker-compose.yml',
                                   'config', '--format', 'json']))
        if (accepted.get('revision') != REVISION or accepted.get('image') != renderer().LEGO
                or accepted.get('lego_service_sha256') != lego_service_identity(compose)
                or accepted.get('config_sha256') != hashlib.sha256(edge_file_bytes(EDGE / 'lego/.lego.yaml')).hexdigest()):
            raise OperatorError('certificate_renewal_configuration_changed')
        certificate = EDGE / 'lego/data/certificates/publicdata-stream.crt'
        previous = hashlib.sha256(edge_file_bytes(certificate)).hexdigest()
        token = secrets.token_hex(12)
        name = 'devres-lego-' + token
        try:
            # lego v5's root config command obtains/renews automatically. No
            # legacy `renew` subcommand, forced renewal, or token argv is used.
            call(['docker', 'compose', '--profile', 'run-lego', '-f', EDGE / 'docker-compose.yml', 'run',
                  '--rm', '--no-deps', '--name', name, '--label', 'devres.renewal=' + token, 'lego'], timeout=3600)
        except OperatorError:
            # A timed-out compose client can leave its one-off container alive.
            # Clean up only this invocation's exact ownership-labelled process.
            try:
                owner = call(['docker', 'inspect', '--format', '{{index .Config.Labels "devres.renewal"}}', name]).decode().strip()
                if owner == token:
                    call(['docker', 'stop', '--time', '10', name], timeout=30)
            except OperatorError:
                pass
            raise
        call(['openssl', 'x509', '-in', certificate, '-noout', '-checkhost', renderer().HOST])
        call(['openssl', 'x509', '-in', certificate, '-noout', '-checkend', '86400'])
        current = hashlib.sha256(edge_file_bytes(certificate)).hexdigest()
        changed = current != previous
        if changed:
            image = read_json(self.bundle / 'edge-compose.json')['services']['oxibelt']['image']
            call(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                  '--entrypoint', 'oxibelt', '-v', str(EDGE) + ':/etc/oxibelt/config:ro',
                  '-v', str(EDGE / 'lego/data/certificates') + ':/etc/oxibelt/cert:ro', image,
                  '--config', '/etc/oxibelt/config/oxibelt.toml', '--check'])
        private_replace(self.bundle / 'certificate-renewal-state.json', json.dumps({
            'revision': REVISION, 'checked_at': datetime.now(timezone.utc).isoformat(),
            'certificate_sha256': current, 'changed': changed}))
        # OxiBelt's qualified downstream_tls mode polls the same mounted paths.
        # Never restart a withdrawn edge or disrupt serving for a failed renewal.
        return {'certificate_checked': True, 'changed': changed, 'edge_restarted': False,
                'tls_reload_mode': 'downstream_tls'}

    def adopt_serve(self):
        """Adopt only the inventoried legacy edge files, preserving exact preimages."""
        self.validate_cluster()
        if os.geteuid() != 0:
            raise OperatorError('root_operator_required')
        running = call(['docker', 'ps', '--filter', 'name=^/oxibelt$', '--format', '{{.ID}}']).strip()
        if running:
            raise OperatorError('legacy_adoption_requires_stopped_edge')
        directories = (EDGE, EDGE / 'oxibelt-conf')
        paths = [EDGE / 'docker-compose.yml', EDGE / 'oxibelt.toml',
                 *sorted((EDGE / 'oxibelt-conf').glob('*.toml'))]
        inventory = []
        snapshots = safe_directory(self.bundle / 'edge-previous', create=True)
        for path in (*directories, *paths):
            if any(parent.is_symlink() for parent in (path, *path.parents)):
                raise OperatorError('unsafe_legacy_edge_path')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                directory = path in directories
                if (info.st_uid not in (0, 1000) or (directory and not stat.S_ISDIR(info.st_mode))
                        or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024**2))):
                    raise OperatorError('unexpected_legacy_edge_identity')
                contents = b'' if directory else os.read(descriptor, 1024**2 + 1)
                record = {'path': str(path.relative_to(EDGE)) or '.', 'directory': directory,
                          'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid,
                          'mode': stat.S_IMODE(info.st_mode), 'sha256': hashlib.sha256(contents).hexdigest()}
                inventory.append(record)
                if not directory:
                    filename = ('conf-' if path.parent.name == 'oxibelt-conf' else '') + path.name
                    previous = snapshots / filename
                    if previous.exists():
                        if private_read(previous) != contents:
                            raise OperatorError('legacy_edge_preimage_changed')
                    else:
                        private_write(previous, contents)
            finally:
                os.close(descriptor)
        inventory_file = snapshots / 'inventory.json'
        if not inventory_file.exists():
            private_write(inventory_file, json.dumps(inventory, sort_keys=True))
        # Directories become root controlled before replacing any file. Every
        # opened inode/content must still match the exact saved preimage.
        for item in inventory:
            path = EDGE / item['path']
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                if (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
                        item['device'], item['inode'], item['uid'], item['gid'], item['mode']):
                    raise OperatorError('legacy_edge_changed_during_adoption')
                contents = b'' if item['directory'] else os.read(descriptor, 1024**2 + 1)
                if hashlib.sha256(contents).hexdigest() != item['sha256']:
                    raise OperatorError('legacy_edge_changed_during_adoption')
                os.fchown(descriptor, 0, 0)
                os.fchmod(descriptor, 0o755 if item['directory'] else (0o600 if path.name == 'docker-compose.yml' else 0o644))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        self.record(legacy_edge_adopted=True)
        return {'legacy_edge_adopted': True, 'prior_configuration_preserved': True, 'edge_started': False}

    def edge_install(self):
        self.validate_cluster()
        self.validate_runtime_state()
        if read_json(self.bundle / 'state.json').get('phase') not in ('runtime_ready', 'edge_ready'):
            raise OperatorError('private_runtime_acceptance_required')
        if read_json(self.bundle / 'state.json').get('legacy_edge_adopted') is not True:
            raise OperatorError('explicit_legacy_edge_adoption_required')
        boot = read_json(self.bundle / 'boot-guard-acceptance.json')
        if (boot.get('release_revision') != REVISION or boot.get('fixture') is not False
                or boot.get('k3s_start_denied_when_guard_fails') is not True
                or boot.get('docker_start_denied_when_guard_fails') is not True
                or boot.get('guard_restored') is not True):
            raise OperatorError('failed_guard_boot_acceptance_required')
        candidate = read_json(self.bundle / 'edge-compose.json')
        image = candidate['services']['oxibelt']['image']
        if not re.fullmatch(r'ghcr\.io/oxibelt/oxibelt@sha256:[0-9a-f]{64}', image):
            raise OperatorError('immutable_edge_identity_required')
        call(['docker', 'pull', image], timeout=600)
        metadata = json.loads(call(['docker', 'image', 'inspect', image]))[0]
        if metadata.get('Config', {}).get('Labels', {}).get('org.opencontainers.image.revision') != OXIBELT_REVISION:
            raise OperatorError('unexpected_edge_revision')
        existing = json.loads(call(['docker', 'compose', '--profile', 'run-lego', '-f', EDGE / 'docker-compose.yml',
                                    'config', '--format', 'json']))
        merged = merge_edge_compose(existing, candidate)
        certs = EDGE / 'lego/data/certificates'
        # Private backend identities are additional files; the existing wildcard key is never read/copied.
        additions = {'devres-backend-ca.pem': 'backend-ca.crt', 'devres-client.pem': 'edge-client.crt',
                     'devres-client-key.pem': 'edge-client.key'}
        snapshots = safe_directory(self.bundle / 'edge-previous', create=True)
        targets = [EDGE / 'docker-compose.yml', EDGE / 'oxibelt.toml', *(EDGE / 'oxibelt-conf').glob('*.toml')]
        for path in targets:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2:
                raise OperatorError('unsafe_existing_edge_configuration')
            filename = ('conf-' if path.parent.name == 'oxibelt-conf' else '') + path.name
            if not (snapshots / filename).exists():
                private_write(snapshots / filename, path.read_bytes())
        self.record(edge_installing=True)
        for destination, source in additions.items():
            path = certs / destination
            expected = private_read(self.bundle / 'tls' / source)
            if path.exists() or path.is_symlink():
                if (path.is_symlink() or not path.is_file() or path.stat().st_uid != 10001
                        or path.stat().st_mode & 0o077 or path.stat().st_nlink != 1 or path.read_bytes() != expected):
                    raise OperatorError('existing_private_edge_identity_conflicts')
            else:
                self.system_file(path, expected, 0o600)
                os.chown(path, 10001, 10001)
        with tempfile.TemporaryDirectory(prefix='devres-edge-', dir='/tmp') as temporary:
            staging = Path(temporary)
            staging.chmod(0o755)
            conf = staging / 'oxibelt-conf'
            conf.mkdir(mode=0o755)
            for path in (EDGE / 'oxibelt-conf').glob('*.toml'):
                self.system_file(conf / path.name, comment_unrelated(path.read_text()))
            for path in (self.bundle / 'edge-conf').glob('*.toml'):
                self.system_file(conf / path.name, private_read(path))
            self.system_file(staging / 'oxibelt.toml', private_read(self.bundle / 'edge.toml'))
            call(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '10001:10001',
                  '--entrypoint', 'oxibelt', '-v', str(staging) + ':/etc/oxibelt/config:ro',
                  '-v', str(certs) + ':/etc/oxibelt/cert:ro', image,
                  '--config', '/etc/oxibelt/config/oxibelt.toml', '--check'])
            try:
                retained = comment_unrelated((snapshots / 'docker-compose.yml').read_text())
                self.system_file(EDGE / 'docker-compose.yml', retained + '\n' + json.dumps(merged, indent=2), 0o600)
                for path in conf.glob('*.toml'):
                    self.system_file(EDGE / 'oxibelt-conf' / path.name, path.read_bytes())
                self.system_file(EDGE / 'oxibelt.toml', (staging / 'oxibelt.toml').read_bytes())
                call(['docker', 'compose', '-f', EDGE / 'docker-compose.yml', 'config', '--quiet'])
                call(['docker', 'compose', '-f', EDGE / 'docker-compose.yml', 'up', '-d', '--no-deps', 'oxibelt'], timeout=180)
                self.install_capacity_timer()
                self.install_certificate_timer()
            except OperatorError:
                self.withdraw()
                self.record(phase='edge_install_failed')
                raise
        self.record(phase='edge_ready', edge_installing=False)
        return {'edge_started': True, 'public_acceptance_required': True}

    def withdraw(self):
        self.validate_cluster()
        failures = []
        try:
            call(['docker', 'compose', '-f', EDGE / 'docker-compose.yml', 'stop', 'oxibelt'])
        except OperatorError:
            failures.append('edge')
        try:
            self.stop()
        except OperatorError:
            failures.append('roles')
        self.record(phase='withdraw_incomplete' if failures else 'withdrawn')
        if failures:
            raise OperatorError('withdraw_incomplete')
        return {'edge_stopped': True, 'serving_stopped': True, 'writer_stopped': True, 'history_preserved': True}

    def activate(self, source_file, edge_file):
        self.validate_cluster()
        self.validate_runtime_state()
        if read_json(self.bundle / 'state.json').get('phase') != 'edge_ready':
            raise OperatorError('edge_acceptance_phase_required')
        source = read_json(source_file)
        edge = read_json(edge_file)
        source_receipt(source)
        edge_receipt(edge)
        provider_receipt(read_json(self.bundle / 'acceptance-receipt.json'))
        if shutil.disk_usage('/database/devres').free < MIN_FREE:
            self.withdraw()
            raise OperatorError('capacity_reserve_required')
        originals = {role: private_read(self.bundle / (role + '.toml')).decode() for role in ('writer', 'serving')}
        activated = {role: collector_config(text, True) for role, text in originals.items()}
        try:
            # Stop the public reader first and keep the sole writer nonoverlapping.
            self.stop()
            for role, text in activated.items():
                encoded = json.dumps(secret_manifest('devres-' + role + '-config', {role + '.toml': text})).encode()
                self.apply_secret('devres-' + role + '-config', encoded)
            for name in ('writer', 'backend'):
                self.scale(name, 1)
            for role, text in activated.items():
                private_replace(self.bundle / (role + '.toml'), text)
                private_replace(self.bundle / ('devres-' + role + '-config.json'),
                                json.dumps(secret_manifest('devres-' + role + '-config', {role + '.toml': text})))
            private_replace(self.bundle / 'source-acceptance.json', json.dumps(source))
            private_replace(self.bundle / 'edge-acceptance.json', json.dumps(edge))
            self.record(phase='collectors_active')
        except (OperatorError, OSError, ValueError):
            # Restore the disabled admission config while preserving all evidence.
            failures = []
            try:
                self.stop()
            except (OperatorError, OSError):
                failures.append('stop')
            for role, text in originals.items():
                try:
                    manifest = secret_manifest('devres-' + role + '-config', {role + '.toml': text})
                    self.apply_secret('devres-' + role + '-config',
                                      json.dumps(manifest).encode())
                    private_replace(self.bundle / (role + '.toml'), text)
                    private_replace(self.bundle / ('devres-' + role + '-config.json'), json.dumps(manifest))
                except (OperatorError, OSError):
                    failures.append(role)
            try:
                self.record(phase='activation_failed')
            except (OperatorError, OSError):
                failures.append('journal')
            if failures:
                raise OperatorError('activation_recovery_incomplete') from None
            raise
        return {'collectors_enabled': list(COLLECTORS), 'ten_minute_observation_required': True}


def prepare(output, settings_file):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise OperatorError("output_already_exists")
    settings = renderer().settings_checked(read_json(settings_file))
    # Keep generated configuration private even when imported renderers use
    # ordinary file creation. No secret is written by the renderer itself.
    output.mkdir(mode=0o700)
    old_umask = os.umask(0o077)
    try:
        renderer().render(output, settings)
        encoded_settings = json.dumps(settings, sort_keys=True)
        private_write(output / 'settings.json', encoded_settings)
        passwords, manifests = postgres_inputs()
        private_write(output / "database-passwords.json", json.dumps(passwords))
        for item in manifests:
            private_write(output / (item["metadata"]["name"] + ".json"), json.dumps(item))
        private_write(output / "devres-guard.nft", firewall_rules())
        private_write(output / 'broker-keyring.json', json.dumps({'active_key_id': 'initial', 'keys': {'initial': secrets.token_hex(32)}}))
        prepare_tls(output)
        private_write(output / 'state.json', json.dumps({'version': 1, 'revision': REVISION, 'phase': 'prepared',
                      'settings_sha256': hashlib.sha256(encoded_settings.encode()).hexdigest()}))
    finally:
        os.umask(old_umask)
    return {"prepared": True, "version": VERSION, "contains_private_bootstrap_inputs": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--settings", type=Path)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--source-receipt', type=Path)
    parser.add_argument('--edge-receipt', type=Path)
    parser.add_argument("operation", choices=("prepare", "install", "start-postgres", "provision-runtime", "start",
                        "adopt-serve", "edge-install", "cert-renew", "activate-collectors", "withdraw", "stop", "status", "capacity"))
    args = parser.parse_args()
    if args.operation == "prepare":
        if args.settings is None:
            parser.error("prepare requires --settings")
        result = prepare(args.bundle, args.settings)
    else:
        operator = Operator(args.context, args.bundle)
        method = {"install": operator.install, "start-postgres": operator.start_postgres,
                  "start": operator.admit_start, "stop": operator.stop,
                  "status": operator.status, "capacity": operator.capacity,
                  'adopt-serve': operator.adopt_serve, 'edge-install': operator.edge_install, 'cert-renew': operator.cert_renew,
                  'withdraw': operator.withdraw}.get(args.operation)
        # Certificate propagation waits must not hold the capacity/lifecycle lock.
        with bundle_lock(operator.bundle, '.certificate.lock' if args.operation == 'cert-renew' else '.operator.lock'):
            if args.operation == 'provision-runtime':
                if args.inputs is None:
                    parser.error('provision-runtime requires --inputs')
                result = operator.provision_runtime(args.inputs)
            elif args.operation == 'activate-collectors':
                if args.source_receipt is None or args.edge_receipt is None:
                    parser.error('activate-collectors requires both acceptance receipts')
                result = operator.activate(args.source_receipt, args.edge_receipt)
            else:
                result = method()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OperatorError, OSError, ValueError, KeyError, TypeError):
        # Do not echo external process diagnostics, input values or file paths.
        print("Production operation failed; inspect private state before retrying.", file=sys.stderr)
        raise SystemExit(1) from None
