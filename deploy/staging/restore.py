#!/usr/bin/env python3
"""Verify an owned coordinated snapshot in isolated, disposable ZFS clones.

The caller holds the source snapshots while verification runs and uses the
maintenance lock for snapshot creation and marking only. The capacity guard stays
active during the drill. Only retained RFC data is fetched; no provider work occurs.
"""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import tomllib

HERE = Path(__file__).resolve().parent
PRIVATE = Path('/etc/devres-staging')
DATASET = 'cachepool/devres-staging'
PG = 'postgres@sha256:ae6c78831cbc35fa3a4aaf4d763ddacf6183d6004774cc2dc28b3920410d1d1a'
OLD_SERVER = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:02977361122a11d7f0a9eedea97437b15f2fccc17f82d2331f859d388359179e'
SERVER = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:3665625d149316567f127c9098143089155dd4ac6e5e04f9b2029c3370cfe325'
PROFILES = {9: (OLD_SERVER, '0.1.0-build.27d35cd6'), 10: (SERVER, '0.1.0-build.ed3c13f2')}
SOURCE_PREFIX = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/'
COLLECTORS = ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'npm')
OWNER_KEY = 'org.publicdata:restore-owner'
LABEL_KEY = 'devres.restore-owner'
TOKEN_RE = re.compile(r'[0-9a-f]{24}\Z')
HASH_RE = re.compile(r'[0-9a-f]{64}\Z')
CONTENT_RE = re.compile(r'(?:blake3:)?[0-9a-f]{64}\Z')
MAX_RESPONSE = 1024 * 1024
MAX_FIXED_BODY = 16 * 1024 * 1024
RECORD_SQL = "SELECT id, body_hash FROM devres_captures WHERE source_url='https://www.rfc-editor.org/rfc/rfc9000.txt' AND media_type='text/plain' ORDER BY retrieved_at DESC,id LIMIT 1"


class RestoreError(RuntimeError):
    """Fixed diagnostic code; provider content and command stderr stay private."""


def execute(args):
    try:
        p = subprocess.run([str(a) for a in args], capture_output=True, text=True,
                           timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RestoreError('restore_command_unavailable_or_timed_out') from error
    if p.returncode:
        raise RestoreError('restore_command_failed')
    if len(p.stdout) > MAX_RESPONSE:
        raise RestoreError('restore_command_output_exceeds_bound')
    return p.stdout.strip()


def validate_snapshot(value):
    spec = importlib.util.spec_from_file_location('devres_restore_maintenance', HERE / 'maintenance.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.snapshot_name(value)
    except module.MaintenanceError as error:
        raise RestoreError('invalid_snapshot_name') from error


def paused_config(text):
    """Change only the eight scheduling booleans; retain all runtime identity."""
    before = tomllib.loads(text)
    if any(not isinstance(before.get(c, {}).get('enabled'), bool) for c in COLLECTORS):
        raise RestoreError('explicit_collector_configuration_required')
    changed = text
    for collector in COLLECTORS:
        pattern = (r'(?ms)(^\[' + re.escape(collector) + r'\][ \t]*\n)'
                   r'((?:(?!^\[).)*?)(^enabled[ \t]*=[ \t]*)(?:true|false)([ \t]*(?:#.*)?$)')
        changed, count = re.subn(pattern, lambda m: m[1] + m[2] + m[3] + 'false' + m[4], changed)
        if count != 1:
            raise RestoreError('collector_configuration_layout_changed')
    after = tomllib.loads(changed)
    expected = json.loads(json.dumps(before))
    for c in COLLECTORS:
        expected[c]['enabled'] = False
    if after != expected:
        raise RestoreError('unexpected_restore_configuration_change')
    return changed


def blob_path(root, value):
    if not CONTENT_RE.fullmatch(value):
        raise RestoreError('invalid_capture_hash')
    root = Path(root)
    path = root / 'blake3' / value[7:] if value.startswith('blake3:') else root / value
    for parent in (root, path.parent):
        try:
            info = parent.lstat()
        except OSError as error:
            raise RestoreError('capture_blob_unavailable') from error
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RestoreError('capture_blob_unavailable')
    return path


def open_blob(root, value):
    path = blob_path(root, value)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise RestoreError('capture_blob_unavailable') from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RestoreError('capture_blob_not_regular')
        if not 0 < info.st_size <= MAX_FIXED_BODY:
            raise RestoreError('fixed_capture_size_exceeds_bound')
        return fd, info.st_size
    except BaseException:
        os.close(fd)
        raise


def hash_blob(root, value, *, integrity_verified=False):
    # Tagged BLAKE3 and legacy independent descriptors are verified by the exact
    # schema-ten binary, avoiding a second cryptography implementation here.
    if value.startswith('blake3:') and not integrity_verified:
        raise RestoreError('independent_integrity_verification_required')
    fd, size = open_blob(root, value)
    try:
        if value.startswith('blake3:'):
            return size
        digest = hashlib.sha256()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            while part := stream.read(1024 * 1024):
                digest.update(part)
        if digest.hexdigest() != value:
            raise RestoreError('capture_blob_hash_mismatch')
        return size
    finally:
        os.close(fd)


def rpc(ip, method, params, private=PRIVATE):
    """One modern stateless RPC over the production backend mTLS contract."""
    context = ssl.create_default_context(cafile=Path(private) / 'backend-ca.pem')
    context.load_cert_chain(Path(private) / 'edge-client.pem', Path(private) / 'edge-client-key.pem')
    params = dict(params)
    params['_meta'] = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                       'io.modelcontextprotocol/clientInfo': {'name': 'devres-restore', 'version': '1'},
                       'io.modelcontextprotocol/clientCapabilities': {}}
    headers = {'Host': 'devres-k8s:30081', 'Content-Type': 'application/json',
               'Accept': 'application/json, text/event-stream',
               'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method}
    if 'name' in params:
        headers['Mcp-Name'] = params['name']
    elif 'uri' in params:
        headers['Mcp-Name'] = params['uri']
    connection = http.client.HTTPConnection('devres-k8s', 30081, timeout=10)
    try:
        connection.sock = context.wrap_socket(socket.create_connection((ip, 8080), timeout=10),
                                              server_hostname='devres-k8s')
        connection.request('POST', '/mcp', json.dumps({'jsonrpc': '2.0', 'id': 1,
                                                       'method': method, 'params': params}), headers)
        response = connection.getresponse()
        if response.status != 200:
            raise RestoreError('restored_rpc_http_failure')
        if response.getheader('content-type', '').startswith('text/event-stream'):
            remaining = MAX_RESPONSE
            value = None
            while remaining > 0:
                line = response.readline(remaining + 1)
                remaining -= len(line)
                if remaining < 0:
                    raise RestoreError('restored_rpc_output_exceeds_bound')
                if not line:
                    break
                if line.startswith(b'data:'):
                    candidate = json.loads(line[5:].strip())
                    if candidate.get('id') == 1:
                        value = candidate
                        break
        else:
            body = response.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise RestoreError('restored_rpc_output_exceeds_bound')
            value = json.loads(body)
        if not isinstance(value, dict) or 'error' in value or 'result' not in value:
            raise RestoreError('restored_rpc_rejected')
        return value['result']
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise RestoreError('restored_rpc_unavailable') from error
    finally:
        connection.close()


class Drill:
    def __init__(self, snapshot, run=execute, root=None, private=PRIVATE,
                 token=None, sleep=time.sleep, call=rpc, server=None, schema=None,
                 config_text=None, source_dataset=None):
        self.snapshot = validate_snapshot(snapshot)
        if schema is not None and (type(schema) is not int or schema not in PROFILES):
            raise RestoreError('restored_schema_mismatch')
        if server is not None and server not in (OLD_SERVER, SERVER):
            raise RestoreError('unreviewed_restore_image')
        if server is not None and schema is not None and server != PROFILES[schema][0]:
            raise RestoreError('restore_profile_mismatch')
        self.server, self.schema, self.config_text = server, schema, config_text
        self.run, self.private, self.sleep, self.call = run, Path(private), sleep, call
        self.token = token or secrets.token_hex(12)
        if not TOKEN_RE.fullmatch(self.token):
            raise RestoreError('invalid_restore_token')
        self.name = 'devres-staging-restore-' + self.token
        self.dataset = 'cachepool/' + self.name
        self.source_dataset = DATASET if source_dataset is None else source_dataset
        if (self.source_dataset != DATASET
                and not re.fullmatch(r'cachepool/devres-staging-restore-[0-9a-f]{24}', self.source_dataset)):
            raise RestoreError('unsafe_restore_source_dataset')
        if self.source_dataset == self.dataset:
            raise RestoreError('restore_source_matches_destination')
        self.root = Path(root) if root is not None else Path('/tmp') / self.name
        if not self.root.is_absolute() or self.root == Path('/tmp') or Path('/tmp') not in self.root.parents:
            raise RestoreError('restore_path_must_be_below_tmp')
        self.datasets = []
        self.containers = []
        self.network = False
        self.runtime_owned = False
        self.postgres_started = False
        self.offline_sequence = 0
        self.backend_started = False

    def owned(self, dataset):
        if dataset not in (self.dataset, self.dataset + '/postgres', self.dataset + '/evidence'):
            raise RestoreError('unsafe_restore_dataset')
        if self.run(['zfs', 'get', '-H', '-o', 'value', OWNER_KEY, dataset]) != self.token:
            raise RestoreError('restore_dataset_ownership_changed')

    def prepare(self):
        if self.source_dataset != DATASET:
            source_owner = self.source_dataset.rsplit('-', 1)[1]
            for child in ('', '/postgres', '/evidence'):
                if self.run(['zfs', 'get', '-H', '-o', 'value', OWNER_KEY,
                             self.source_dataset + child]).strip() != source_owner:
                    raise RestoreError('restore_source_ownership_changed')
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        (self.root / 'owner').write_text(self.token)
        self.runtime_owned = True
        self.datasets.append(self.dataset)
        self.run(['zfs', 'create', '-o', OWNER_KEY + '=' + self.token,
                  '-o', 'mountpoint=none', '-o', 'canmount=off', '-o', 'quota=64G',
                  '-o', 'exec=off', '-o', 'setuid=off', '-o', 'devices=off', self.dataset])
        for child in ('postgres', 'evidence'):
            self.datasets.append(self.dataset + '/' + child)
            self.run(['zfs', 'clone', '-o', OWNER_KEY + '=' + self.token,
                      '-o', 'mountpoint=' + str(self.root / child), '-o', 'canmount=on',
                      self.source_dataset + '/' + child + '@' + self.snapshot, self.dataset + '/' + child])
        self.network = True
        self.run(['docker', 'network', 'create', '--internal', '--label', LABEL_KEY + '=' + self.token, self.name])
        for folder in ('config', 'tls'):
            path = self.root / folder
            path.mkdir(mode=0o750)
            os.chmod(path, 0o750)
            os.chown(path, 0, 65532)
        config = paused_config(self.config_text if self.config_text is not None
                               else (self.private / 'backend.toml').read_text())
        # Keep PostgreSQL alias/credentials and all transport identity unchanged.
        parsed = tomllib.loads(config)
        if not re.fullmatch(r'postgres://devres:[0-9a-f]+@postgres:5432/devres', parsed['storage']['database_url']):
            raise RestoreError('unexpected_private_database_authority')
        (self.root / 'config/backend.toml').write_text(config)
        os.chown(self.root / 'config/backend.toml', 0, 65532)
        os.chmod(self.root / 'config/backend.toml', 0o640)
        for name in ('backend.pem', 'backend-key.pem', 'client-ca.pem'):
            path = self.root / 'tls' / name
            shutil.copyfile(self.private / name, path)
            os.chown(path, 0, 65532)
            os.chmod(path, 0o640)

    def docker_run(self, role, image, args):
        name = self.name + '-' + role
        self.containers.append(name)
        self.run(['docker', 'run', '-d', '--name', name, '--label', LABEL_KEY + '=' + self.token,
                  '--network', self.name, '--network-alias', role, '--read-only',
                  '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128',
                  *args, image, *([] if role == 'postgres' else ['/etc/devres/config/backend.toml'])])
        return name

    def psql(self, query):
        return self.run(['docker', 'exec', self.name + '-postgres', 'psql', '-X', '-A', '-t',
                         '-F', '\t', '-h', '/tmp', '-U', 'devres_admin', '-d', 'devres', '-v', 'ON_ERROR_STOP=1', '-c', query])

    def start_postgres(self):
        if not self.runtime_owned or self.postgres_started:
            raise RestoreError('restore_postgres_state_invalid')
        pg = self.name + '-postgres'
        self.containers.append(pg)
        self.run(['docker', 'run', '-d', '--name', pg, '--label', LABEL_KEY + '=' + self.token,
                  '--network', self.name, '--network-alias', 'postgres', '--read-only',
                  '--user', '999:999', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                  '--pids-limit=128', '--memory=2g', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,uid=999,gid=999',
                  '-v', str(self.root / 'postgres') + ':/var/lib/postgresql',
                  '--entrypoint', 'postgres', PG, '-D', '/var/lib/postgresql/18/docker',
                  '-c', 'listen_addresses=*', '-c', 'unix_socket_directories=/tmp'])
        for attempt in range(60):
            try:
                self.run(['docker', 'exec', pg, 'pg_isready', '-h', '127.0.0.1', '-U', 'devres_admin', '-d', 'devres'])
                break
            except RestoreError:
                if attempt == 59:
                    raise RestoreError('restored_postgres_not_ready')
                self.sleep(1)
        self.postgres_started = True

    def backend_args(self, memory='16g', scratch='1g'):
        return ['--user', '65532:65532', '--memory=' + memory,
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=' + scratch + ',uid=65532,gid=65532',
                '-v', str(self.root / 'evidence') + ':/data',
                '-v', str(self.root / 'config') + ':/etc/devres/config:ro',
                '-v', str(self.root / 'tls') + ':/etc/devres/tls:ro']

    def offline(self, command, target=SERVER, timeout=86400):
        """Run one reviewed offline command; stop/remove its writer on every exit."""
        if command not in ('migrate-storage', 'verify-storage', 'activate-storage') or target != SERVER:
            raise RestoreError('invalid_offline_command_or_image')
        if type(timeout) not in (int, float) or not 0 < timeout <= 86400:
            raise RestoreError('invalid_offline_timeout')
        if (not self.postgres_started or self.backend_started
                or any(name.startswith(self.name + '-offline-') for name in self.containers)):
            raise RestoreError('offline_writer_exclusion_required')
        self.offline_sequence += 1
        name = self.name + '-offline-' + str(self.offline_sequence)
        self.containers.append(name)
        args = [command, '/etc/devres/config/backend.toml']
        if command == 'migrate-storage':
            args.extend(['--to', 'blake3'])
        try:
            self.run(['docker', 'run', '-d', '--name', name, '--label', LABEL_KEY + '=' + self.token,
                      '--network', self.name, '--read-only', '--cap-drop=ALL',
                      '--security-opt=no-new-privileges', '--pids-limit=128',
                      *self.backend_args(memory='64g', scratch='32g'), '--entrypoint', '/usr/local/bin/devres-server', target, *args])
            # Count bounded polling intervals too, so injectable test clocks do
            # not turn a stalled command into an unbounded loop.
            started = time.monotonic()
            for attempt in range(int(timeout) + 1):
                state = json.loads(self.run(['docker', 'inspect', '--format', '{{json .State}}', name]))
                if not state.get('Running'):
                    if state.get('ExitCode') != 0:
                        raise RestoreError('offline_command_failed')
                    return {'command': command, 'completed': True}
                if time.monotonic() - started >= timeout or attempt >= timeout:
                    raise RestoreError('offline_command_timed_out')
                self.sleep(min(1, timeout))
            raise RestoreError('offline_command_timed_out')
        finally:
            # Docker removal waits for container termination before dropping the
            # writer; failed cleanup deliberately prevents the next command.
            self.run(['docker', 'rm', '-f', name])
            self.containers.remove(name)

    def select_profile(self, schema):
        server, version = PROFILES[schema]
        if self.server is not None and self.server != server:
            raise RestoreError('restore_profile_mismatch')
        source = SOURCE_PREFIX + version + '/source.tar.gz'
        path = self.root / 'config/backend.toml'
        text = path.read_text()
        before = tomllib.loads(text)
        pattern = r'(?ms)(^\[source\][ \t]*\n)((?:(?!^\[).)*?)(^url[ \t]*=[ \t]*)[^\n]*$'
        changed, count = re.subn(pattern, lambda m: m[1] + m[2] + m[3] + json.dumps(source), text)
        after = tomllib.loads(changed)
        before.setdefault('source', {})['url'] = source
        if count != 1 or before != after:
            raise RestoreError('restore_source_configuration_invalid')
        path.write_text(changed)
        return server, version, source

    def check(self, prepared=False, timeout=86400):
        if not prepared:
            self.prepare()
            self.start_postgres()
        elif not self.postgres_started:
            raise RestoreError('restore_postgres_state_invalid')
        actual = self.psql('SELECT version FROM devres_schema WHERE singleton')
        if actual not in ('9', '10') or (self.schema is not None and str(self.schema) != actual):
            raise RestoreError('restored_schema_mismatch')
        schema = int(actual)
        server, version, source = self.select_profile(schema)
        if schema == 10:
            if self.psql('SELECT active FROM devres_integrity_control WHERE singleton') != 't':
                raise RestoreError('restored_integrity_not_active')
            self.offline('verify-storage', timeout=timeout)
        count = self.psql('SELECT count(*) FROM devres_captures')
        if not count.isdigit() or int(count) < 1:
            raise RestoreError('real_capture_required')
        row = self.psql(RECORD_SQL).split('\t')
        identity_pattern = HASH_RE if schema == 9 else CONTENT_RE
        if len(row) != 2 or not all(identity_pattern.fullmatch(v) for v in row):
            raise RestoreError('retained_fixed_rfc_required')
        capture, body_hash = row
        blob_root = self.root / 'evidence/blobs'
        size = hash_blob(blob_root, body_hash, integrity_verified=schema == 10)
        backend = self.docker_run('backend', server, self.backend_args('4g'))
        self.backend_started = True
        info = json.loads(self.run(['docker', 'inspect', backend]))[0]
        ip = info['NetworkSettings']['Networks'][self.name]['IPAddress']
        for attempt in range(60):
            try:
                result = self.call(ip, 'tools/call', {'name': 'server.info', 'arguments': {}}, self.private)
                identity = result.get('structuredContent', {})
                if (result.get('isError') or identity.get('product') != 'dev-resources-MCP'
                        or identity.get('version') != version or identity.get('sourceUrl') != source):
                    raise RestoreError('restored_identity_mismatch')
                break
            except RestoreError:
                if attempt == 59:
                    raise RestoreError('restored_backend_not_ready')
                self.sleep(1)
        resource = self.call(ip, 'resources/read', {'uri': 'devres://capture/' + capture}, self.private)
        contents = resource.get('contents', [])
        if not contents or not isinstance(contents[0].get('text'), str) or not contents[0]['text']:
            raise RestoreError('restored_capture_read_failed')
        page = contents[0]['text'].encode('utf-8')
        if len(page) > 32768:
            raise RestoreError('restored_capture_page_exceeds_bound')
        fd, _ = open_blob(blob_root, body_hash)
        with os.fdopen(fd, 'rb') as stream:
            if stream.read(len(page)) != page:
                raise RestoreError('restored_capture_page_mismatch')
        return {'snapshot': self.snapshot, 'schema': schema, 'server': server,
                'version': version, 'source_url': source, 'captures': int(count),
                'verified_capture_id': capture,
                'verified_body_hash': body_hash, 'verified_body_bytes': size,
                'verified_resource_bytes': len(page)}

    def cleanup(self):
        # Stop every clone writer before unmounting/destroying its storage.
        for name in reversed(self.containers):
            found = self.run(['docker', 'ps', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'])
            if not found:
                continue
            if found != name:
                raise RestoreError('restore_container_inventory_changed')
            info = json.loads(self.run(['docker', 'inspect', name]))[0]
            if info.get('Config', {}).get('Labels', {}).get(LABEL_KEY) != self.token:
                raise RestoreError('restore_container_ownership_changed')
            self.run(['docker', 'rm', '-f', name])
        if self.network:
            found = self.run(['docker', 'network', 'ls', '--filter', 'name=^' + self.name + '$', '--format', '{{.Name}}'])
            if found and found != self.name:
                raise RestoreError('restore_network_inventory_changed')
            if found:
                info = json.loads(self.run(['docker', 'network', 'inspect', self.name]))[0]
                if info.get('Labels', {}).get(LABEL_KEY) != self.token:
                    raise RestoreError('restore_network_ownership_changed')
                self.run(['docker', 'network', 'rm', self.name])
        if self.datasets:
            inventory = self.run(['zfs', 'list', '-H', '-o', 'name']).splitlines()
            listed = [v for v in inventory if v == self.dataset or v.startswith(self.dataset + '/')]
            if not set(listed).issubset(set(self.datasets)):
                raise RestoreError('restore_dataset_tree_changed')
        for dataset in reversed(self.datasets):
            if dataset not in listed:
                continue
            self.owned(dataset)
            self.run(['zfs', 'destroy', dataset])
        if self.runtime_owned:
            if self.root.is_symlink() or (self.root / 'owner').read_text() != self.token:
                raise RestoreError('restore_runtime_ownership_changed')
            shutil.rmtree(self.root)


def verify(snapshot, *, timeout=86400, **kwargs):
    """Return bounded metadata only after real capture recovery and cleanup pass."""
    drill = Drill(snapshot, **kwargs)
    try:
        return drill.check(timeout=timeout)
    finally:
        drill.cleanup()
