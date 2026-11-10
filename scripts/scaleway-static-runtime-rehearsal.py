#!/usr/bin/env python3
"""Render INERT synthetic rotation candidates; never read keys or run workloads."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def production():
    spec = importlib.util.spec_from_file_location('rotation_production', ROOT / 'deploy/production/production.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def s3(scope, key_path):
    return f'''endpoint = "https://s3.fr-par.scw.cloud"
bucket = "dev-resources-mcp"
region = "fr-par"
prefix = "production/.acceptance/runtime-{scope}"
path_style = true
storage_class = "ONEZONE_IA"
cache_max_bytes = 67108864
''', f'''mode = "files"
access_key_file = "{key_path}/access-key"
secret_key_file = "{key_path}/secret-key"
'''


def runtime(scope, writer):
    release = production()
    role = 'writer' if writer else 'reader'
    text = f'''# INERT PRIVATE TEMPLATE: fill only a disposable PostgreSQL password.
[source]
url = "https://github.com/PublicData-stream/dev-resources-MCP/releases/download/{release.VERSION}/source.tar.gz"
'''
    for provider in release.PROVIDERS:
        text += f'[{provider}]\nenabled = false\n'
        if provider == 'npm':
            text += 'packages = []\nadvisories_enabled = false\n'
    text += f'''[http]
bind = "127.0.0.1:8080"
allowed_hosts = ["localhost:8080"]
allowed_origins = ["https://rotation.invalid"]
[webtransport]
bind = "127.0.0.1:4433"
certificate = "/tmp/rotation/fixture-auth/server.crt"
private_key = "/tmp/rotation/fixture-auth/server.key"
allowed_hosts = ["localhost:4433"]
allowed_origins = ["https://rotation.invalid"]
[health]
bind = "0.0.0.0:9090"
[storage]
database_url = "postgres://devres_rotation_{role}:@{role.upper()}_DATABASE_PASSWORD@@postgres/devres_rotation_{scope}"
blob_dir = "/tmp/rotation/cache/{'writer' if writer else 'serving'}"
backend = "s3"
'''
    if not writer:
        text += 'scratch_dir = "/tmp/rotation/scratch"\n'
    settings, credentials = s3(scope, '/tmp/rotation/keys/current')
    text += '[storage.s3]\n' + settings + '[storage.s3.credentials]\n' + credentials
    if writer:
        text += '''[writer_listener]
bind = "0.0.0.0:9443"
certificate = "/tmp/rotation/fixture-auth/server.crt"
private_key = "/tmp/rotation/fixture-auth/server.key"
allowed_clients = [{namespace = "synthetic-rotation", service_account = "synthetic-reader"}]
[writer_listener.auth]
kube_api_url = "https://127.0.0.1:9"
kube_token_file = "/tmp/rotation/fixture-auth/token"
kube_ca_file = "/tmp/rotation/fixture-auth/ca.crt"
audience = "synthetic-unused-writer"
'''
    else:
        text += '''[writer_client]
endpoint = "https://writer:9443/v1/acquire"
token_file = "/tmp/rotation/fixture-auth/token"
ca_file = "/tmp/rotation/fixture-auth/ca.crt"
'''
    return text


def seed(scope, role, phase, cold='final'):
    key_role = 'writer' if role == 'write' else 'serving'
    db_role = 'writer' if role == 'write' else 'reader'
    cache = 'seed-writer' if role == 'write' else f'cold-reader-{cold}'
    settings, credentials = s3(scope, f'/tmp/rotation/keys/{phase}-{key_role}')
    return f'''# INERT PRIVATE TEMPLATE: credentials are file paths, never inline S3 values.
role = "{role}"
scope = "{scope}"
database_url = "postgres://devres_rotation_{db_role}:@{db_role.upper()}_DATABASE_PASSWORD@@postgres/devres_rotation_{scope}"
cache_dir = "/tmp/rotation/cache/{cache}"
state_dir = "/tmp/rotation/evidence"
[s3]
{settings}[s3.credentials]
{credentials}'''


def compose(root, scope, phase):
    release = production()
    services = {}
    for role in ('writer', 'serving'):
        services[role] = {
            'image': release.SERVER, 'profiles': ['explicit-rehearsal'], 'scale': 0,
            'entrypoint': ['devres-server'],
            'command': ['collect' if role == 'writer' else 'serve', '/tmp/rotation/config.toml'],
            'user': '65532:65532', 'read_only': True, 'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges:true'], 'restart': 'no',
            'mem_limit': '2g', 'cpus': 1,
            'environment': {'TMPDIR': '/tmp/work', 'TMP': '/tmp/work', 'TEMP': '/tmp/work'},
            'volumes': [
                f'{root}/private/runtime/{role}.toml:/tmp/rotation/config.toml:ro',
                f'{root}/private/keys/{phase}-{role}:/tmp/rotation/keys/current:ro',
                f'{root}/private/fixture-auth:/tmp/rotation/fixture-auth:ro',
                f'{root}/cache/{role}:/tmp/rotation/cache/{role}:rw',
                f'{root}/scratch/{role}:/tmp/rotation/scratch:rw',
            ],
            'tmpfs': ['/tmp/work:rw,noexec,nosuid,size=64m,uid=65532,gid=65532'],
            'networks': ['rotation'],
        }
    services['postgres'] = {
        'image': release.POSTGRES, 'profiles': ['explicit-rehearsal'], 'scale': 0,
        'user': '70:70', 'read_only': True, 'restart': 'no', 'mem_limit': '2g', 'cpus': 1,
        'environment': {'POSTGRES_USER': 'postgres',
                        'POSTGRES_DB': 'postgres',
                        'POSTGRES_PASSWORD_FILE': '/run/fixture-db/password',
                        'PGDATA': '/var/lib/postgresql/18/docker'},
        'volumes': [f'{root}/postgres:/var/lib/postgresql:rw',
                    f'{root}/private/postgres-admin-password:/run/fixture-db/password:ro',
                    f'{root}/private/postgres-init.sql:/run/init.sql:ro'],
        'tmpfs': ['/tmp:rw,noexec,nosuid,size=64m', '/var/run/postgresql:rw,noexec,nosuid,size=16m,uid=70,gid=70'],
        'networks': ['rotation'],
    }
    return {'name': f'devres-rotation-{scope}', 'services': services,
            'networks': {'rotation': {'driver': 'bridge'}}}


PLAN = '''INERT CANDIDATE: no execution or production receipt. All candidates start at scale zero.

The operator must obtain explicit scope for two fresh temporary 900-second role keys,
no more than 16 object keys / 4 MiB total beneath the one declared child prefix,
and an isolated Docker daemon whose state, PostgreSQL data, caches and fixtures are
all below this directory in /tmp. Preserve existing operating keys and archives.
Do not run compose with another daemon or publish any host ports.

1. Privately supply distinct temporary/final serving/writer key directories. Final
   files are copies of the approved operating pairs. No Scaleway administrator
   key enters any container. Keep each role's key directory mounted read-only.
   Materialize private TOML templates and disposable PostgreSQL passwords; create
   isolated fixture TLS and an inert token. Grant runtime UID65532 access only to
   its config, role keys/cache and fixture auth files. The helper config is private
   mode0400/0600 and owned by its process UID. Set TMPDIR=/tmp/work in containers.
2. Start only PostgreSQL explicitly at scale1. Its postgres bootstrap administrator
   uses ONLY private/postgres-admin-password, mounted into PostgreSQL alone. Before
   phase1, execute privately materialized SQL from /run/init.sql to CREATE ROLE
   devres_rotation_writer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
   NOINHERIT with a separate disposable password, then CREATE DATABASE
   devres_rotation_<scope> OWNER devres_rotation_writer. Never use postgres admin
   credentials in the runtime or seeder configs. SQL enters only through the
   private mounted file; do not pass passwords through command arguments.
   Build static-rotation-probe from
   exact a938 library/dependency sources (only example additions permitted), mount
   the binary read-only into the exact pinned server image with network 'rotation'.
   While collect and serve are BOTH STOPPED, run:
   static-rotation-probe write --config PRIVATE_TEMP_WRITER.toml --phase 1
   Its publication fence must drop before collect starts. The helper journals
   intent before connections and emits only synthetic phase evidence.
3. After phase1 schema creation, privately create devres_rotation_reader LOGIN
   NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT, with its own private
   password, SELECT-only grants on public tables, and default_transaction_read_only=on.
   Set ALTER DEFAULT PRIVILEGES FOR ROLE devres_rotation_writer IN SCHEMA public
   GRANT SELECT ON TABLES TO devres_rotation_reader for future migrations.
   Grant no role membership or write/schema authority. Start collect then serve
   with temporary role files. Check BOTH private /ready endpoints return200 from
   inside their containers; record image/container identity and binding/epoch.
   Every collector and therefore attribution family list remains disabled/empty.
4. Stop BOTH runtime containers and verify they exited. Run phase2 once using the
   FINAL WRITER private config. It uses the SAME PostgreSQL database and S3 prefix.
   The helper verifies phase1 binding/epoch before publishing the second body.
   Replace role mounts using compose-final.json; start collect final, then serve
   final. Verify both /ready return200. No production startup receipt is bypassed:
   these are direct pinned binaries against the isolated synthetic database only.
5. Run static-rotation-probe read --config PRIVATE_FINAL_READER.toml with a brand
   NEW cold-reader cache. It must verify both capture IDs/body hashes, phase2 head,
   unchanged archive binding/epoch, and actual connect_reader mode. Do not seed a
   full storage-probe graph. Two bodies are at most32KiB each; known remote keys
   are store.json, two objects/blake3/<bodyhash> bodies, and two bindings/<hash>.json
   descriptors (five keys total), all named by private publication intents.
   Observe ALL prefix objects/bytes after every step and stop before exceeding
   16 keys or4MiB; the released runtime has no per-rehearsal key-count limiter.
   Unexplained additional objects block acceptance. Never widen the budget.
6. Revoke ONLY the two temporary test keys administratively outside containers.
   Independently prove those exact keys now403 and BOTH final processes remain
   ready200. Repeat cold historical reads using postrevocation-reader config and
   a separate NEW cache; keep final operating keys untouched.
7. Stop isolated processes. Use recorded exact owned prefix/object inventory for
   separately authorized administrative cleanup; never recursively delete an
   unverified prefix, permanent captures, existing buckets or production database.

This plan exercises static file-key process replacement, SDK publication and cold
history reads. Synthetic WriterRPC TLS/token material proves NO Kubernetes identity,
MCP acquisition delegation, public HTTP/WebTransport or production deployment gate.
No helper or renderer emits a production acceptance receipt. Failures retain intent;
never retry a failed/ambiguous phase or silently relabel it as passing.
'''


def verify_libraries():
    revision = production().REVISION
    subprocess.run(['git', '-C', str(ROOT), 'diff', '--exit-code', revision, '--',
        'crates/adapters/src', 'crates/application/src', 'crates/domain/src',
        'Cargo.lock', 'Cargo.toml', 'crates/domain/Cargo.toml', 'crates/application/Cargo.toml'],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    baseline = tomllib.loads(subprocess.check_output(['git', '-C', str(ROOT), 'show',
        f'{revision}:crates/adapters/Cargo.toml'], text=True))
    current = tomllib.loads((ROOT / 'crates/adapters/Cargo.toml').read_text())
    baseline.pop('example', None)
    current.pop('example', None)
    if baseline != current:
        raise ValueError('Released SDK features/dependencies changed')


def render(output, scope):
    verify_libraries()
    output = Path(output)
    if (not re.fullmatch('[0-9a-f]{24}', scope) or not output.is_absolute()
            or output == Path('/tmp') or Path('/tmp') not in output.parents
            or '..' in output.parts or output.exists()
            or any(parent.is_symlink() for parent in output.parents)):
        raise ValueError('Use a new non-symlink directory below /tmp and a 24-hex scope')
    for parent in output.parents:
        if parent == Path('/tmp'):
            break
        metadata = parent.stat()
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError('Nested output parents must be private and owned')
    output.mkdir(mode=0o700)
    files = {'PLAN.txt': PLAN,
             'writer.toml.example': runtime(scope, True),
             'serving.toml.example': runtime(scope, False),
             'seed-temporary.toml.example': seed(scope, 'write', 'temporary'),
             'seed-final.toml.example': seed(scope, 'write', 'final'),
             'reader-final.toml.example': seed(scope, 'read', 'final'),
             'reader-postrevocation.toml.example': seed(scope, 'read', 'final', 'postrevocation'),
             'scope.json': json.dumps({'release_revision': production().REVISION,
                 'scope': scope, 'prefix': f'production/.acceptance/runtime-{scope}',
                 'maximum_object_keys': 16, 'maximum_object_bytes': 4 * 1024 * 1024,
                 'maximum_synthetic_body_bytes': 32768, 'publication_phases': [1, 2],
                 'production_receipt': False, 'inert': True}, indent=2)}
    for phase in ('temporary', 'final'):
        files[f'compose-{phase}.json'] = json.dumps(compose(output, scope, phase), indent=2)
    for name, text in files.items():
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(text + '\n')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--scope', required=True)
    args = parser.parse_args()
    print(render(args.output, args.scope))
