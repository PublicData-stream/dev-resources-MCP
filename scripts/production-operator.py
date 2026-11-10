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
VERSION = "0.1.0-build.a938112b"
REVISION = "a938112b5af87996661ddd91ae68755dc0d579b9"
OXIBELT_REVISION = "4f3154d8db0e0a49bce7a528c0a0f4c36d169040"
NAMESPACE = "devres"
WORKLOADS = ("postgres", "broker-postgres", "credential-broker", "writer", "backend")
COLLECTORS = ("rfc", "crates", "rustsec", "mdn", "whatwg", "w3c", "chromium", "npm")
MIN_FREE = 128 * 1024**3
EDGE = Path('/serve')
APPARMOR_FILE = Path('/etc/apparmor.d/devres-runtime')
APPARMOR_PROFILES = Path('/sys/kernel/security/apparmor/profiles')
APPARMOR_SHA256 = '4375146629c956b8e63cc4b358ef52c6bcda458621b7dcf8601b0f3d922b3e7e'
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


def validate_apparmor(settings):
    """Check an explicitly selected host policy; never install or load it."""
    if 'apparmor_profile' not in settings:
        return
    if settings['apparmor_profile'] != 'devres-runtime':
        raise OperatorError('unsupported_apparmor_profile')
    try:
        if any(path.is_symlink() for path in (APPARMOR_FILE, *APPARMOR_FILE.parents)):
            raise OperatorError('unsafe_apparmor_profile_file')
        descriptor = os.open(APPARMOR_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > 65536):
                raise OperatorError('unsafe_apparmor_profile_file')
            with os.fdopen(descriptor, 'rb', closefd=False) as source:
                value = source.read(65537)
            if hashlib.sha256(value).hexdigest() != APPARMOR_SHA256:
                raise OperatorError('apparmor_profile_hash_mismatch')
        finally:
            os.close(descriptor)
        descriptor = os.open(APPARMOR_PROFILES, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            loaded = source.read(1024**2 + 1)
        if len(loaded) > 1024**2 or b'devres-runtime (enforce)' not in loaded.splitlines():
            raise OperatorError('apparmor_profile_not_enforcing')
    except OSError as error:
        raise OperatorError('apparmor_profile_unavailable') from error


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


def postgres_inputs(storage_auth="broker"):
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
    manifests = [secret_manifest("devres-corpus-postgres", {
                       "postgres-password": values["corpus_admin"], "init.sql": corpus}),
                    secret_manifest("devres-broker-postgres", {
                       "postgres-password": values["broker_admin"], "init.sql": broker})]
    if storage_auth == "scaleway_static":
        values = {key: values[key] for key in ("corpus_admin", "writer", "reader")}
        manifests = manifests[:1]
    return values, manifests


def prepare_tls(bundle, storage_auth="broker"):
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
            if storage_auth == "scaleway_static" and name == "credential-broker":
                continue
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


STATIC_STORAGE_CHECKS = (
    'reader_read_list', 'reader_mutations_denied', 'writer_read_conditional_put',
    'writer_multipart_complete_abort', 'permanent_deletion_denied',
    'other_bucket_prefix_denied', 'administration_denied', 'rotation_revocation_verified',
)


def static_storage_receipt(value, binding, now=None):
    """Admit independently obtained real evidence, never a fixture or broker receipt."""
    now = now or datetime.now(timezone.utc)
    if (value.get('version') != 1 or value.get('mode') != 'scaleway_static'
            or value.get('fixture') is not False or value.get('binding') != binding
            or any(value.get('checks', {}).get(name) is not True for name in STATIC_STORAGE_CHECKS)):
        raise OperatorError('real_static_storage_acceptance_required')
    try:
        verified = datetime.fromisoformat(value['verified_at'].replace('Z', '+00:00'))
        expires = datetime.fromisoformat(value['expires_at'].replace('Z', '+00:00'))
        if (verified.utcoffset() is None or expires.utcoffset() is None or verified > now
                or (now - verified).total_seconds() > 31 * 86400 or expires <= now or expires <= verified):
            raise ValueError()
    except (KeyError, ValueError, TypeError, AttributeError) as error:
        raise OperatorError('static_storage_acceptance_expired_or_invalid') from error


def static_key_pair(access, secret):
    """Bound private input reads; accept the same trailing newline convention as S3."""
    values = []
    for path in (access, secret):
        try:
            value = private_read(path, 65536).decode().rstrip('\r\n')
        except UnicodeError as error:
            raise OperatorError('invalid_static_storage_key') from error
        if not value or not value.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise OperatorError('invalid_static_storage_key')
        values.append(value)
    return {'access-key': values[0], 'secret-key': values[1]}


def static_binding(config, identity, pairs):
    storage = config['storage']['s3']
    binding = {key: storage[key] for key in ('endpoint', 'region', 'bucket', 'prefix', 'path_style')}
    for name in ('organization_id', 'project_id', 'reader_application_id', 'writer_application_id'):
        try:
            if str(uuid.UUID(identity[name])) != identity[name]:
                raise ValueError()
        except (KeyError, ValueError, TypeError, AttributeError) as error:
            raise OperatorError('invalid_private_identity') from error
        binding[name] = identity[name]
    if identity['reader_application_id'] == identity['writer_application_id']:
        raise OperatorError('application_identities_must_differ')
    if pairs['reader']['access-key'] == pairs['writer']['access-key']:
        raise OperatorError('static_storage_keys_must_differ')
    for role in ('reader', 'writer'):
        digest = identity.get(role + '_policy_sha256', '')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise OperatorError('invalid_private_policy_fingerprint')
        binding[role + '_policy_sha256'] = digest
        # Hash a canonical pair; never persist the input files or raw secret in evidence.
        encoded = json.dumps(pairs[role], sort_keys=True, separators=(',', ':')).encode()
        binding[role + '_credential_sha256'] = hashlib.sha256(encoded).hexdigest()
    return binding


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

    def settings(self):
        settings = read_json(self.bundle / 'settings.json')
        state = read_json(self.bundle / 'state.json')
        if hashlib.sha256(private_read(self.bundle / 'settings.json')).hexdigest() != state.get('settings_sha256'):
            raise OperatorError('bundle_settings_changed')
        return renderer().settings_checked(settings)

    def auth_mode(self):
        return renderer().storage_auth(self.settings())

    def workloads(self):
        return renderer().workload_names(self.settings())

    def runtime_secrets(self):
        return renderer().runtime_secret_names(self.settings())

    def database_workloads(self):
        return tuple(name for name in self.workloads() if name in ('postgres', 'broker-postgres'))

    def runtime_workloads(self):
        return tuple(name for name in self.workloads() if name not in self.database_workloads())

    def require_static_release(self):
        if self.auth_mode() == 'scaleway_static' and not renderer().STATIC_AUTH_RELEASE_QUALIFIED:
            raise OperatorError('qualified_static_storage_release_required')

    def admit_storage_receipt(self):
        self.require_static_release()
        value = read_json(self.bundle / 'acceptance-receipt.json')
        if self.auth_mode() == 'broker':
            provider_receipt(value)
        else:
            static_storage_receipt(value, self.static_runtime_binding())

    def k(self, *args, data=None, timeout=180, request_timeout=30):
        return call(["k3s", "kubectl", "--context", self.context, "--namespace", NAMESPACE,
                     f"--request-timeout={request_timeout}s", *args], data=data, timeout=timeout)

    def scale(self, name, count):
        self.k("scale", "deployment/" + name, "--replicas=" + str(count))
        if count:
            if name in self.database_workloads():
                self.k("rollout", "status", "deployment/" + name, "--timeout=660s",
                       timeout=700, request_timeout=670)
            else:
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

    def validate_cluster(self, bind=False, require_host_policy=True):
        # Start/install check policy before API access. Safety shutdowns retain
        # every identity check while remaining possible after host-policy drift.
        settings = self.settings()
        if require_host_policy:
            validate_apparmor(settings)
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

    def validate_workload_templates(self, names=None):
        settings = self.settings()
        manifest = read_json(self.bundle / 'kubernetes.json')
        if manifest != renderer().manifests(renderer().settings_checked(read_json(self.bundle / 'settings.json'))):
            raise OperatorError('rendered_manifest_changed')
        expected = {item['metadata']['name']: item for item in manifest['items']
                    if item['kind'] == 'Deployment'}
        live = json.loads(self.k('get', 'deployments', '-o', 'json'))['items']
        actual = {item['metadata']['name']: item for item in live if item['metadata']['name'] in WORKLOADS}
        if names is not None:
            selected = set(names)
            if not selected or not selected <= set(expected):
                raise OperatorError('unexpected_workload_selection')
            expected = {name: item for name, item in expected.items() if name in selected}
            actual = {name: item for name, item in actual.items() if name in selected}
        elif self.auth_mode() == 'scaleway_static':
            for name in ('credential-broker', 'broker-postgres'):
                retired = actual.pop(name, None)
                if retired and (retired['spec'].get('replicas', 1) != 0 or retired.get('status', {}).get('replicas', 0) != 0):
                    raise OperatorError('broker_runtime_not_retired')
        if set(actual) != set(expected):
            raise OperatorError('runtime_deployment_set_mismatch')
        for name, item in expected.items():
            desired = item['spec']['template']['spec']
            observed = actual[name]['spec']['template']['spec']
            if (any(observed.get(key) for key in ('hostNetwork', 'hostPID', 'hostIPC', 'initContainers'))
                    or any(container.get('securityContext', {}).get('privileged')
                           for container in observed.get('containers', []))):
                raise OperatorError('unexpected_runtime_privilege')
            if 'apparmor_profile' in settings:
                annotations = actual[name]['spec']['template']['metadata'].get('annotations', {})
                if (any('appArmorProfile' in container.get('securityContext', {})
                        for container in observed.get('containers', []))
                        or any(key.startswith('container.apparmor.security.beta.kubernetes.io/')
                               for key in annotations)):
                    raise OperatorError('unexpected_apparmor_override')
            if not contains_expected(observed, desired):
                raise OperatorError('runtime_deployment_identity_mismatch')
            expected_container = desired['containers'][0]
            observed_container = observed['containers'][0]
            for key in ('command', 'args', 'env', 'envFrom'):
                if expected_container.get(key, []) != observed_container.get(key, []):
                    raise OperatorError('runtime_invocation_changed')

    def validate_runtime_state(self):
        self.validate_workload_templates()
        for name in self.runtime_secrets():
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

    def provision_secret(self, name, encoded):
        if not read_json(self.bundle / 'state.json').get('auth_switch_pending', False):
            self.apply_secret(name, encoded)

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
        for name in ("devres-corpus-postgres",) + (("devres-broker-postgres",) if self.auth_mode() == "broker" else ()):
            secret = private_read(self.bundle / (name + ".json"))
            self.apply_secret(name, secret)
        self.record(phase='installed')
        return {"installed": True, "runtime_stopped": True}

    def prepare_local_volumes(self):
        directories = [('/database/devres/corpus', 70), ('/var/cache/devres/serving', 65532), ('/var/cache/devres/writer', 65532)]
        if self.auth_mode() == 'broker':
            directories.append(('/database/devres/broker', 70))
        for directory, uid in directories:
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
        state = read_json(self.bundle / 'state.json')
        if state.get('auth_switch_pending') or state.get('auth_successor'):
            raise OperatorError('active_authentication_bundle_required')
        for name in self.runtime_workloads():
            if self.status().get(name, {}).get("desired", 0):
                raise OperatorError("postgres_bootstrap_requires_stopped_runtime")
        self.validate_workload_templates(self.database_workloads())
        for name in self.database_workloads():
            self.scale(name, 1)
        if state.get('phase') not in ('runtime_provisioned', 'stopped', 'start_failed'):
            self.record(phase='postgres_ready')
        return {"postgres_started": True}

    def provision_runtime(self, inputs_file):
        self.validate_cluster()
        if any(self.status().get(name, {}).get('desired', 0) for name in self.runtime_workloads()):
            raise OperatorError('runtime_secret_update_requires_stopped_roles')
        self.require_static_release()
        if self.auth_mode() == 'scaleway_static':
            return self.provision_static_runtime(inputs_file)
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
            self.provision_secret(name, encoded)
        for name, text in configs.items():
            private_replace(self.bundle / (name + '.toml'), text)
        self.record(phase='runtime_provisioned', runtime_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest())
        return {'runtime_secrets_provisioned': True, 'collectors_enabled': False}

    def static_inputs(self, inputs_file):
        inputs = read_json(inputs_file)
        identity_fields = {'organization_id', 'project_id', 'reader_application_id', 'writer_application_id',
                           'reader_policy_sha256', 'writer_policy_sha256'}
        paths = {role + '_' + kind + '_file' for role in ('reader', 'writer') for kind in ('access_key', 'secret_key')}
        if set(inputs) != identity_fields | paths | {'acceptance_receipt_file'}:
            raise OperatorError('invalid_static_storage_inputs')
        pairs = {role: static_key_pair(inputs[role + '_access_key_file'], inputs[role + '_secret_key_file'])
                 for role in ('reader', 'writer')}
        config = tomllib.loads(private_read(self.bundle / 'serving.toml.example').decode())
        binding = static_binding(config, inputs, pairs)
        return inputs, pairs, binding

    def static_runtime_binding(self):
        identity = read_json(self.bundle / 'static-storage-identity.json')
        configs = {role: tomllib.loads(private_read(self.bundle / (role + '.toml')).decode())
                   for role in ('serving', 'writer')}
        for role, config in configs.items():
            expected = renderer().runtime_config(writer=role == 'writer', auth='scaleway_static')
            expected_storage = tomllib.loads(expected)['storage']['s3']
            if config['storage']['s3'] != expected_storage:
                raise OperatorError('static_storage_configuration_changed')
        pairs = {}
        for role, name in (('reader', 'devres-serving-s3'), ('writer', 'devres-writer-s3')):
            secret = read_json(self.bundle / (name + '.json'))
            if set(secret.get('data', {})) != {'access-key', 'secret-key'}:
                raise OperatorError('static_storage_secret_invalid')
            try:
                pairs[role] = {key: base64.b64decode(value, validate=True).decode() for key, value in secret['data'].items()}
            except (ValueError, UnicodeError) as error:
                raise OperatorError('static_storage_secret_invalid') from error
        return static_binding(configs['serving'], identity, pairs)

    def provision_static_runtime(self, inputs_file):
        self.require_roles_stopped()
        inputs, pairs, binding = self.static_inputs(inputs_file)
        receipt_bytes = private_read(inputs['acceptance_receipt_file'], 65536)
        static_storage_receipt(json.loads(receipt_bytes), binding)
        passwords = read_json(self.bundle / 'database-passwords.json')
        configs = {}
        for role, password in (('serving', 'reader'), ('writer', 'writer')):
            text = private_read(self.bundle / (role + '.toml.example')).decode()
            text = text.replace('@CORPUS_' + password.upper() + '_PASSWORD@', quote(passwords[password], safe=''))
            if re.search(r'@[A-Z_]+@', text):
                raise OperatorError('unresolved_private_configuration')
            parsed = tomllib.loads(text)
            expected = tomllib.loads(renderer().runtime_config(writer=role == 'writer', auth='scaleway_static'))
            if parsed['storage']['s3'] != expected['storage']['s3']:
                raise OperatorError('static_storage_configuration_changed')
            if (parsed['storage']['s3']['credentials']['mode'] != 'files'
                    or any(parsed[provider]['enabled'] for provider in COLLECTORS)):
                raise OperatorError('invalid_static_storage_configuration')
            configs[role] = text
        tls = self.bundle / 'tls'
        manifests = {name: secret_manifest(name, fields) for name, fields in (
            ('devres-serving-config', {'serving.toml': configs['serving']}),
            ('devres-writer-config', {'writer.toml': configs['writer']}),
            ('devres-serving-s3', pairs['reader']), ('devres-writer-s3', pairs['writer']),
            ('devres-backend-tls', {'backend.pem': private_read(tls / 'backend.crt'),
                                   'backend-key.pem': private_read(tls / 'backend.key'),
                                   'client-ca.pem': private_read(tls / 'edge-client-ca.crt')}),
            ('devres-writer-tls', {'tls.crt': private_read(tls / 'writer.crt'),
                                 'tls.key': private_read(tls / 'writer.key'),
                                 'ca.crt': private_read(tls / 'coordination-ca.crt')}))}
        identity = {key: inputs[key] for key in ('organization_id', 'project_id', 'reader_application_id',
                                                'writer_application_id', 'reader_policy_sha256', 'writer_policy_sha256')}
        # Validate every private input before the first cluster write. Partial writes remain stopped.
        private_replace(self.bundle / 'static-storage-identity.json', json.dumps(identity))
        private_replace(self.bundle / 'acceptance-receipt.json', receipt_bytes)
        for role, text in configs.items():
            private_replace(self.bundle / (role + '.toml'), text)
        for name, manifest in manifests.items():
            encoded = json.dumps(manifest).encode()
            private_replace(self.bundle / (name + '.json'), encoded)
            self.provision_secret(name, encoded)
        self.record(phase='runtime_provisioned', runtime_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest())
        return {'runtime_secrets_provisioned': True, 'collectors_enabled': False}

    def require_roles_stopped(self):
        current = self.status()
        if any(current.get(name, {}).get('desired', 0) or current.get(name, {}).get('ready', 0)
               for name in ('backend', 'writer')):
            raise OperatorError('authentication_switch_requires_stopped_roles')
        for name in ('backend', 'writer'):
            self.k('wait', '--for=delete', 'pod', '-l', 'app=' + name, '--timeout=120s')

    def pause_collectors(self):
        """Disable only scheduling switches while both roles are stopped; leave broker keys alone."""
        self.validate_cluster()
        self.require_roles_stopped()
        self.validate_runtime_state()
        originals = {role: private_read(self.bundle / (role + '.toml')).decode() for role in ('serving', 'writer')}
        disabled = {role: collector_config(text, False) for role, text in originals.items()}

        def store(configs):
            for role, text in configs.items():
                name = 'devres-' + role + '-config'
                encoded = json.dumps(secret_manifest(name, {role + '.toml': text}))
                self.apply_secret(name, encoded.encode())
                private_replace(self.bundle / (role + '.toml'), text)
                private_replace(self.bundle / (name + '.json'), encoded)
        try:
            store(disabled)
        except (OperatorError, OSError, ValueError):
            try:
                store(originals)
            except (OperatorError, OSError, ValueError):
                self.record(phase='collector_pause_recovery_incomplete')
                raise OperatorError('collector_pause_recovery_incomplete') from None
            raise
        self.record(phase='stopped')
        return {'collectors_paused': True, 'runtime_stopped': True, 'history_preserved': True}

    def prepare_auth_switch(self, target_bundle, settings_file):
        """Prepare a separate private bundle without initializing or changing storage."""
        self.validate_cluster()
        self.require_roles_stopped()
        target = Path(target_bundle).absolute()
        if target.exists() or target.is_symlink():
            raise OperatorError('output_already_exists')
        settings = renderer().settings_checked(read_json(settings_file))
        old = self.settings()
        mode = renderer().storage_auth(settings)
        if mode == self.auth_mode():
            raise OperatorError('authentication_mode_must_change')
        if mode != 'scaleway_static':
            raise OperatorError('rollback_requires_original_broker_bundle')
        if {key: value for key, value in old.items() if key not in ('storage_auth', 'iam_cidrs')} != {
                key: value for key, value in settings.items() if key not in ('storage_auth', 'iam_cidrs')}:
            raise OperatorError('authentication_switch_settings_changed')
        self.validate_runtime_state()
        for role in ('serving', 'writer'):
            config = tomllib.loads(private_read(self.bundle / (role + '.toml')).decode())
            if any(config[name]['enabled'] for name in COLLECTORS):
                raise OperatorError('authentication_switch_requires_disabled_collectors')
        target.mkdir(mode=0o700)
        previous = os.umask(0o077)
        try:
            renderer().render(target, settings)
            # Keep original PostgreSQL identity and TLS; never invoke fresh bootstrap.
            for name in ('database-passwords.json', 'devres-corpus-postgres.json', 'devres-guard.nft'):
                private_replace(target / name, private_read(self.bundle / name))
            tls = safe_directory(target / 'tls', create=True)
            for path in (self.bundle / 'tls').iterdir():
                if mode == 'scaleway_static' and path.name.startswith('credential-broker.'):
                    continue
                private_write(tls / path.name, private_read(path))
            encoded = json.dumps(settings, sort_keys=True)
            private_replace(target / 'settings.json', encoded)
            for name in ('boot-guard-acceptance.json', 'lego-renewal.json', 'certificate-renewal-state.json',
                         'source-acceptance.json', 'edge-acceptance.json'):
                if (self.bundle / name).exists():
                    private_replace(target / name, private_read(self.bundle / name))
            if (self.bundle / 'edge-previous').exists():
                snapshots = safe_directory(target / 'edge-previous', create=True)
                for path in (self.bundle / 'edge-previous').iterdir():
                    private_write(snapshots / path.name, private_read(path))
            source_state = read_json(self.bundle / 'state.json')
            state = {key: source_state[key] for key in ('version', 'revision', 'cluster_uid', 'node_uid', 'namespace_uid',
                                                        'legacy_edge_adopted', 'edge_admitted')
                     if key in source_state}
            state.update(phase='auth_switch_prepared', settings_sha256=hashlib.sha256(encoded.encode()).hexdigest(),
                         auth_switch_source=str(self.bundle), auth_switch_pending=True)
            private_replace(target / 'state.json', json.dumps(state))
        finally:
            os.umask(previous)
        return {'authentication_switch_prepared': True, 'runtime_stopped': True, 'history_preserved': True}

    def broker_drained(self):
        # Read only aggregate private journal state. The running broker owns reconciliation/revocation.
        raw = self.k('exec', 'deployment/broker-postgres', '--', 'psql', '-U', 'devres_admin',
                     '-d', 'devres_broker', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
                     "SELECT count(*) FROM devres_credential_broker_keys WHERE state <> 'revoked'")
        if raw.strip() != b'0':
            raise OperatorError('broker_issuance_or_revocation_unresolved')

    def switch_storage_auth(self, target_bundle):
        """Activate staged auth assets while stopped; never start roles or delete state."""
        target = Operator(self.context, target_bundle)
        if target.bundle == self.bundle:
            raise OperatorError('separate_authentication_bundle_required')
        with bundle_lock(target.bundle):
            self.validate_cluster()
            target.validate_cluster()
            target.require_static_release()
            target.admit_storage_receipt()
            self.require_roles_stopped()
            self.validate_runtime_state()
            if target.auth_mode() == self.auth_mode():
                raise OperatorError('authentication_mode_must_change')
            source_state = read_json(self.bundle / 'state.json')
            target_state = read_json(target.bundle / 'state.json')
            if target_state.get('auth_switch_pending'):
                if target_state.get('auth_switch_source') != str(self.bundle):
                    raise OperatorError('authentication_switch_source_mismatch')
            elif source_state.get('auth_switch_source') != str(target.bundle):
                raise OperatorError('authentication_rollback_source_mismatch')
            for name in ('database-passwords.json', 'devres-corpus-postgres.json'):
                if private_read(self.bundle / name) != private_read(target.bundle / name):
                    raise OperatorError('authentication_switch_database_changed')
            for role in ('serving', 'writer'):
                left = tomllib.loads(private_read(self.bundle / (role + '.toml')).decode())
                right = tomllib.loads(private_read(target.bundle / (role + '.toml')).decode())
                left_s3 = dict(left['storage']['s3'])
                right_s3 = dict(right['storage']['s3'])
                left_s3.pop('credentials')
                right_s3.pop('credentials')
                if left['storage']['database_url'] != right['storage']['database_url'] or left_s3 != right_s3:
                    raise OperatorError('authentication_switch_archive_binding_changed')
            broker = self if self.auth_mode() == 'broker' else target
            static = target if target.auth_mode() == 'scaleway_static' else self
            old_apps = set(read_json(broker.bundle / 'acceptance-receipt.json')['confined_application_ids'])
            static_identity = read_json(static.bundle / 'static-storage-identity.json')
            if old_apps & {static_identity['reader_application_id'], static_identity['writer_application_id']}:
                raise OperatorError('static_applications_must_be_outside_broker_management')
            if self.auth_mode() == 'broker':
                self.broker_drained()
            manifest = private_read(target.bundle / 'kubernetes.json', 4 * 1024**2)
            if json.loads(manifest) != renderer().manifests(target.settings()):
                raise OperatorError('rendered_manifest_changed')
            self.k('apply', '--dry-run=server', '-f', '-', data=manifest)
            self.record(phase='auth_switch_in_progress', auth_switch_target=str(target.bundle))
            try:
                if self.auth_mode() == 'broker':
                    self.scale('credential-broker', 0)
                    self.scale('broker-postgres', 0)
                for name in target.runtime_secrets():
                    target.apply_secret(name, private_read(target.bundle / (name + '.json')))
                self.k('apply', '-f', '-', data=manifest)
                if target.auth_mode() == 'scaleway_static':
                    # Explicit allowlist only. Keep broker Deployment/DB/PV/Secrets and journal/keyring for rollback.
                    for kind, names in (
                            ('service', ('credential-broker', 'broker-postgres')),
                            ('networkpolicy', ('credential-broker-boundary', 'broker-postgres-boundary')),
                            ('rolebinding', ('devres-credential-broker-reviewer',)),
                            ('role', ('devres-credential-broker-reviewer',)),
                            ('clusterrolebinding', ('devres-credential-broker-reviewer',)),
                            ('clusterrole', ('devres-credential-broker-reviewer',))):
                        self.k('delete', kind, *names, '--ignore-not-found=true')
                target.record(phase='runtime_provisioned', auth_switch_pending=False, auth_successor=None,
                              auth_switch_source=str(self.bundle))
                target.validate_runtime_state()
                self.record(phase='auth_retired', auth_switch_target=str(target.bundle), auth_successor=str(target.bundle))
            except (OperatorError, OSError, ValueError, KeyError):
                try:
                    for name in self.runtime_secrets():
                        self.apply_secret(name, private_read(self.bundle / (name + '.json')))
                    self.k('apply', '-f', '-', data=private_read(self.bundle / 'kubernetes.json', 4 * 1024**2))
                    self.record(phase='stopped', auth_successor=None)
                    target.record(phase='auth_switch_failed', auth_switch_pending=True)
                except (OperatorError, OSError, ValueError):
                    self.record(phase='auth_switch_recovery_incomplete')
                    raise OperatorError('authentication_switch_recovery_incomplete') from None
                raise
            return {'authentication_switched': True, 'runtime_stopped': True, 'history_preserved': True,
                    'startup_and_storage_acceptance_required': True}

    def admit_start(self):
        self.validate_cluster()
        if read_json(self.bundle / 'state.json').get('auth_switch_pending'):
            raise OperatorError('authentication_switch_not_applied')
        self.validate_runtime_state()
        self.admit_storage_receipt()
        # Runtime Secret/configuration provisioning is an independent prerequisite.
        # Presence alone is not proof; the broker verifies exact profile/secret
        # fingerprints and the trusted live cluster UID before issuing a key.
        if read_json(self.bundle / 'state.json').get('phase') not in ('runtime_provisioned', 'stopped', 'start_failed'):
            raise OperatorError('runtime_provisioning_required')
        for role in ('serving', 'writer'):
            config = tomllib.loads(private_read(self.bundle / (role + '.toml')).decode())
            if any(config[name]['enabled'] for name in COLLECTORS):
                raise OperatorError('initial_collectors_must_be_disabled')
        for name in self.runtime_secrets():
            self.k("get", "secret", name, "-o", "name")
        if shutil.disk_usage('/database/devres').free < MIN_FREE:
            raise OperatorError('capacity_reserve_required')
        try:
            for name in self.workloads():
                self.scale(name, 1)
        except OperatorError:
            self.record(phase='start_failed')
            self.stop()
            raise
        self.record(phase='edge_ready' if read_json(self.bundle / 'state.json').get('edge_admitted') else 'runtime_ready')
        return {"runtime_started": True, "collectors_require_separate_acceptance": True}

    def stop(self):
        self.validate_cluster(require_host_policy=False)
        current = self.status()
        failures = []
        for name in ("backend", "writer"):
            if name in current:
                try:
                    self.scale(name, 0)
                except OperatorError:
                    failures.append(name)
        state = read_json(self.bundle / 'state.json')
        admitted_edge = state.get('edge_admitted', False) or state.get('phase') in ('edge_ready', 'collectors_active')
        self.record(phase='stop_incomplete' if failures else 'stopped', edge_admitted=admitted_edge)
        if failures:
            raise OperatorError('role_stop_incomplete')
        return {"serving_stopped": True, "writer_stopped": True, "history_preserved": True}

    def active_auth_operator(self):
        current = self
        visited = set()
        for _ in range(8):
            if current.bundle in visited:
                raise OperatorError('authentication_successor_cycle')
            visited.add(current.bundle)
            state = read_json(current.bundle / 'state.json')
            successor = state.get('auth_successor')
            if not successor:
                return current
            if state.get('phase') != 'auth_retired':
                raise OperatorError('authentication_successor_not_retired')
            following = Operator(self.context, successor)
            if read_json(following.bundle / 'state.json').get('auth_switch_source') != str(current.bundle):
                raise OperatorError('authentication_successor_binding_invalid')
            current = following
        raise OperatorError('authentication_successor_chain_exceeds_bound')

    def capacity(self):
        active = self.active_auth_operator()
        if active is not self:
            with bundle_lock(active.bundle):
                return active.capacity()
        self.validate_cluster(require_host_policy=False)
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
        active = self.active_auth_operator()
        if active is not self:
            with bundle_lock(active.bundle, '.certificate.lock'):
                return active.cert_renew()
        self.validate_cluster()
        state = read_json(self.bundle / 'state.json')
        if state.get('phase') not in ('edge_ready', 'collectors_active') and not state.get('edge_admitted'):
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
        self.record(phase='edge_ready', edge_installing=False, edge_admitted=True)
        return {'edge_started': True, 'public_acceptance_required': True}

    def withdraw(self):
        self.validate_cluster(require_host_policy=False)
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
        self.admit_storage_receipt()
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
        mode = renderer().storage_auth(settings)
        passwords, manifests = postgres_inputs(mode)
        private_write(output / "database-passwords.json", json.dumps(passwords))
        for item in manifests:
            private_write(output / (item["metadata"]["name"] + ".json"), json.dumps(item))
        private_write(output / "devres-guard.nft", firewall_rules())
        if mode == 'broker':
            private_write(output / 'broker-keyring.json', json.dumps({'active_key_id': 'initial', 'keys': {'initial': secrets.token_hex(32)}}))
        prepare_tls(output, mode)
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
    parser.add_argument("--target-bundle", type=Path)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--source-receipt', type=Path)
    parser.add_argument('--edge-receipt', type=Path)
    parser.add_argument("operation", choices=("prepare", "install", "start-postgres", "provision-runtime", "start",
                        "adopt-serve", "edge-install", "cert-renew", "activate-collectors", "withdraw", "stop", "status", "capacity",
                        "prepare-auth-switch", "switch-storage-auth", "static-fingerprints", "pause-collectors"))
    args = parser.parse_args()
    if args.operation == "prepare":
        if args.settings is None:
            parser.error("prepare requires --settings")
        result = prepare(args.bundle, args.settings)
    else:
        operator = Operator(args.context, args.bundle)
        method = {"install": operator.install, "start-postgres": operator.start_postgres,
                  "start": operator.admit_start, "stop": operator.stop, "pause-collectors": operator.pause_collectors,
                  "status": operator.status, "capacity": operator.capacity,
                  'adopt-serve': operator.adopt_serve, 'edge-install': operator.edge_install, 'cert-renew': operator.cert_renew,
                  'withdraw': operator.withdraw}.get(args.operation)
        # Certificate propagation waits must not hold the capacity/lifecycle lock.
        with bundle_lock(operator.bundle, '.certificate.lock' if args.operation == 'cert-renew' else '.operator.lock'):
            if args.operation == 'prepare-auth-switch':
                if args.target_bundle is None or args.settings is None:
                    parser.error('prepare-auth-switch requires --target-bundle and --settings')
                result = operator.prepare_auth_switch(args.target_bundle, args.settings)
            elif args.operation == 'switch-storage-auth':
                if args.target_bundle is None:
                    parser.error('switch-storage-auth requires --target-bundle')
                result = operator.switch_storage_auth(args.target_bundle)
            elif args.operation == 'static-fingerprints':
                if args.inputs is None or operator.auth_mode() != 'scaleway_static':
                    parser.error('static-fingerprints requires static mode and --inputs')
                result = {'binding': operator.static_inputs(args.inputs)[2]}
            elif args.operation == 'provision-runtime':
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
