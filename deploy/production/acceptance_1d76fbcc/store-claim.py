#!/usr/bin/env python3
"""Exactly one native reader GET of the admitted permanent S3 store claim.

Credentials remain in memory. An exclusive fsynced intent precedes all network
work; no redirects, retries, IAM changes, or object mutations are implemented.
"""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
import tomllib

WORK = Path('/tmp/devres-upgrade-1d76fbcc-20261115')
BUNDLE = Path('/var/lib/devres-production-preparation/a938112b-7c7a24f')
OPERATOR = Path('/usr/local/libexec/devres-production-candidate-a938112b-apparmor-v1/scripts/production-operator.py')
OPERATOR_SHA = '58501767e3d130af1a05e1f6493f89ee8f287e1582f0f35fa2b1e74c23f5e3da'
CHECKPOINT = Path('/usr/local/libexec/devres-upgrade-1d76fbcc/physical-checkpoint.py')
UPGRADE = Path('/var/lib/devres-production-upgrades/1d76fbcc-20261115')
REVISION = '1d76fbcc5693efc9ca927fd05f942078f667f056'
BIND = '4a59576b1a2977f157ceaf72fbe404f660bd89a44c6246106b65f83989f5c529'
SYSTEM_ID = '7706567225121447965'
ARCHIVE_BINDING = 'blake3:7cf193132e3e32eb53c877dfcce166453e5bbb1b0d3f9a39f922f194f82f38e3'
HOST = 's3.fr-par.scw.cloud'
ENDPOINT = 'https://' + HOST
REGION = 'fr-par'
BUCKET = 'dev-resources-mcp'
KEY = 'production/store.json'
PATH = '/' + BUCKET + '/' + KEY
URL = ENDPOINT + PATH
MAX_BODY = 16384
ROLES = {'reader': ('backend', 'serving', 'devres-serving-s3', 'devres-serving-config'),
         'writer': ('writer', 'writer', 'devres-writer-s3', 'devres-writer-config')}


class Stop(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Stop(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return dt.datetime.now(dt.timezone.utc)


def decode(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, 'duplicate_json_key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=unique)


def private_directory(path):
    need(path.is_absolute() and '..' not in path.parts, 'private_directory_path')
    for item in (path, *path.parents):
        need(not item.is_symlink(), 'private_directory_symlink')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
         'private_directory_permissions')


def private_read(path, maximum=4 * 1024**2, source=False):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'private_input_path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
             and info.st_size <= maximum and not info.st_mode & (0o022 if source else 0o077), 'private_input_permissions')
        raw = stream.read(maximum + 1)
        need(len(raw) == info.st_size, 'private_input_changed')
        return raw


def write_exclusive(path, value):
    private_directory(path.parent)
    raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def source_context(expected):
    need(re.fullmatch('[0-9a-f]{64}', expected or '') and sha(private_read(CHECKPOINT, source=True)) == expected,
         'checkpoint_source_changed')
    spec = importlib.util.spec_from_file_location('withdrawn_claim_checkpoint', CHECKPOINT)
    checkpoint = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = checkpoint
    spec.loader.exec_module(checkpoint)
    need(checkpoint.REV == REVISION and checkpoint.UPGRADE == UPGRADE and checkpoint.N == WORK,
         'fixed_withdrawn_checkpoint_required')
    module = checkpoint.controller_module()
    controller = module.Controller(str(UPGRADE), str(UPGRADE / 'plan.json'), 'default')
    return module, controller

def secret_pair(value):
    need(value.get('type') == 'Opaque' and set(value.get('data', {})) == {'access-key', 'secret-key'}, 'credential_secret_shape')
    out = {}
    for key, raw in value['data'].items():
        decoded = base64.b64decode(raw, validate=True).decode()
        need(0 < len(decoded) <= 65536 and decoded.isascii()
             and not any(ord(c) < 32 or ord(c) == 127 for c in decoded), 'credential_bytes_invalid')
        out[key] = decoded
    return out


def check_mount(pod, secret, path, keys):
    spec = pod['spec']
    containers = spec.get('containers', [])
    need(len(containers) == 1, 'one_container_required')
    mounts = [m for m in containers[0].get('volumeMounts', []) if m.get('mountPath') == path]
    need(len(mounts) == 1 and mounts[0].get('readOnly') is True
         and 'subPath' not in mounts[0] and 'subPathExpr' not in mounts[0], 'private_mount_shape')
    selected = [v for v in spec.get('volumes', []) if v['name'] == mounts[0]['name']]
    need(len(selected) == 1 and selected[0].get('secret', {}).get('secretName') == secret, 'private_mount_secret')
    items = selected[0]['secret'].get('items')
    if items is not None:
        need(sorted((i['key'], i['path']) for i in items) == sorted((k, k) for k in keys), 'private_mount_items')
    need(sum(m.get('name') == mounts[0]['name'] for m in containers[0].get('volumeMounts', [])) == 1,
         'private_mount_alias')
    # A nested mount may not replace either credential/configuration file.
    need(not any(m.get('mountPath', '').startswith(path + '/') for m in containers[0].get('volumeMounts', [])),
         'nested_private_mount')


def withdrawn_binding(module, controller):
    """Observe stopped role templates and API Secrets; no mounted file is claimed."""
    controller.guard()
    state = controller.state()
    need(state['revision'] == REVISION and state.get('runtime') == 'target'
         and state['phase'] in ('prepared', 'stopped') and state['configs'] == 'old'
         and state['replicas'] == {'postgres': 1, 'backend': 0, 'writer': 0}
         and set(state['pods']) == {'postgres'}, 'exact_withdrawn_source_required')
    database = controller.storage_guard(18, owner=False)
    need(database.get('schema') == 18 and database.get('owners') == 0
         and database.get('system_id') == SYSTEM_ID, 'withdrawn_database_identity')
    archive = database['archive']
    need({k: archive[k] for k in ('backend', 'binding', 'epoch', 'pending_binding', 'initializing_s3')} ==
         {'backend': 's3', 'binding': ARCHIVE_BINDING, 'epoch': 2, 'pending_binding': None, 'initializing_s3': False}
         and re.fullmatch('[0-9a-f]{32}', archive['store_id']), 'withdrawn_archive_identity')
    all_pods = decode(controller.old.k('get', 'pods', '-o', 'json'))['items']
    need(len(all_pods) == 1 and all_pods[0]['metadata'].get('labels', {}).get('app') == 'postgres',
         'withdrawn_application_pod_present')
    prepared_bytes = private_read(controller.root / 'prepared.json')
    need(sha(prepared_bytes) == state['prepared_sha256'], 'withdrawn_preparation_changed')
    prepared = decode(prepared_bytes)
    original = controller.module
    operator = controller.old
    operator.validate_cluster()
    need(operator.auth_mode() == 'scaleway_static', 'static_auth_required')
    operator.admit_storage_receipt()
    archived_binding = operator.static_runtime_binding()
    need(sha(encoded(archived_binding)) == BIND, 'admitted_storage_binding_changed')
    identity = original.read_json(BUNDLE / 'static-storage-identity.json')
    expected_configs = controller.configurations(state)
    pairs, configs, boundaries = {}, {}, {}
    for role, (app, config_role, secret_name, config_secret) in ROLES.items():
        deployment = controller.get('deployment', app)
        projection, image = module.deployment_projection(deployment)
        need(projection == prepared['deployments'][app]['projection'] and image == state['images'][app]
             and deployment['spec'].get('replicas') == 0, 'withdrawn_deployment_changed')
        secret = controller.get('secret', secret_name)
        need(module.secret_projection(secret) == prepared['secrets'][secret_name], 'withdrawn_prepared_credentials_changed')
        archived = original.read_json(BUNDLE / (secret_name + '.json'))
        need(secret.get('data') == archived.get('data') and secret.get('type') == archived.get('type'),
             'withdrawn_credentials_changed')
        pairs[role] = secret_pair(secret)
        cfg = controller.get('secret', config_secret)
        need(module.secret_projection(cfg) == prepared['secrets'][config_secret], 'withdrawn_config_secret_changed')
        config_key = config_role + '.toml'
        need(set(cfg.get('data', {})) == {config_key}, 'config_secret_shape')
        raw_config = base64.b64decode(cfg['data'][config_key], validate=True)
        need(len(raw_config) <= 1024**2 and raw_config.decode() == expected_configs[app], 'withdrawn_config_changed')
        configs[role] = tomllib.loads(raw_config.decode())
        stored = tomllib.loads(original.private_read(BUNDLE / (config_role + '.toml')).decode())
        s3 = configs[role]['storage']['s3']
        need(configs[role]['storage'].get('backend') == 's3' and s3 == stored['storage']['s3'], 'withdrawn_s3_config_changed')
        need(s3.get('path_style') is True and {k: s3[k] for k in ('endpoint', 'region', 'bucket', 'prefix', 'path_style')} ==
             {'endpoint': ENDPOINT, 'region': REGION, 'bucket': BUCKET, 'prefix': 'production', 'path_style': True},
             'fixed_s3_endpoint_required')
        need(s3['credentials'] == {'mode': 'files', 'access_key_file': '/run/devres-s3/access-key',
             'secret_key_file': '/run/devres-s3/secret-key'}, 'credential_source_changed')
        template = deployment['spec']['template']
        container = template['spec']['containers'][0]
        need(container.get('command') == ['devres-server', 'collect' if app == 'writer' else 'serve',
             '/etc/devres/config/' + config_key] and not container.get('args'), 'withdrawn_invocation_changed')
        check_mount(template, secret_name, '/run/devres-s3', ('access-key', 'secret-key'))
        check_mount(template, config_secret, '/etc/devres/config', (config_key,))
        opposite = ROLES['writer' if role == 'reader' else 'reader'][2]
        need(not any(v.get('secret', {}).get('secretName') == opposite for v in template['spec']['volumes']),
             'cross_role_credential_mount')
        boundaries[role] = {'deployment_uid': deployment['metadata']['uid'],
            'deployment_sha256': sha(encoded(projection)), 'secret_sha256': sha(encoded(module.secret_projection(secret))),
            'config_sha256': sha(raw_config)}
    actual = original.static_binding(configs['reader'], identity, pairs)
    need(actual == archived_binding and sha(encoded(actual)) == BIND, 'stopped_role_pairs_not_admitted')
    controller.guard()
    need(controller.state() == state and controller.storage_guard(18, owner=False) == database,
         'withdrawn_state_changed')
    return pairs['reader'], {'roles': boundaries, 'database': database,
        'state_sha256': sha(private_read(controller.root / 'state.json'))}

def signed_headers(access, secret, instant=None):
    instant = instant or now()
    need(instant.utcoffset() == dt.timedelta(0), 'utc_clock_required')
    stamp = instant.strftime('%Y%m%dT%H%M%SZ')
    fields = {'host': HOST, 'x-amz-date': stamp, 'x-amz-content-sha256': sha(b'')}
    names = ';'.join(sorted(fields))
    canonical = '\n'.join(('GET', PATH, '', ''.join(k + ':' + fields[k] + '\n' for k in sorted(fields)), names, sha(b'')))
    scope = stamp[:8] + '/' + REGION + '/s3/aws4_request'
    message = '\n'.join(('AWS4-HMAC-SHA256', stamp, scope, sha(canonical.encode())))
    key = ('AWS4' + secret).encode()
    for part in (stamp[:8], REGION, 's3', 'aws4_request'):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    fields['authorization'] = 'AWS4-HMAC-SHA256 Credential=' + access + '/' + scope + ', SignedHeaders=' + names + ', Signature=' + signature
    return fields


def native_get(reader):
    connection = http.client.HTTPSConnection(HOST, port=443, timeout=20, context=ssl.create_default_context())
    started = time.monotonic()
    try:
        connection.request('GET', PATH, headers=signed_headers(reader['access-key'], reader['secret-key']))
        transport_socket = connection.sock
        response = connection.getresponse()
        need(response.status == 200, 'store_claim_http_status')
        request_id = response.getheader('x-amz-request-id', '')
        need(re.fullmatch('[!-~]{1,256}', request_id), 'store_request_id_missing')
        length = response.getheader('Content-Length')
        need(length is None or (length.isdigit() and 0 < int(length) <= MAX_BODY), 'store_claim_response_bound')
        body = bytearray()
        while True:
            remaining = 20 - (time.monotonic() - started)
            need(remaining > 0, 'store_claim_deadline')
            if transport_socket is not None:
                transport_socket.settimeout(remaining)
            block = response.read1(min(4096, MAX_BODY + 1 - len(body)))
            if not block:
                break
            body.extend(block)
            need(len(body) <= MAX_BODY, 'store_claim_response_bound')
        return bytes(body), request_id
    finally:
        connection.close()


def run(module, controller, get=native_get):
    private_directory(WORK)
    need(not (WORK / 'source-store-claim-qualified.json').exists(), 'qualified_store_claim_already_exists')
    with controller.locked():
        intent = {'version': 1, 'method': 'GET', 'url': URL, 'maximum_attempts': 1,
                  'reader_only': True, 'boundary_mode': 'withdrawn',
                  'source_sha256': sha(private_read(Path(__file__), source=True)), 'created_at': now().isoformat()}
        write_exclusive(WORK / 'store-claim-withdrawn-intent.json', intent)
        try:
            reader, before = withdrawn_binding(module, controller)
            body, request_id = get(reader)
            claim = decode(body)
            need(set(claim) == {'version', 'store_id'} and type(claim['version']) is int and claim['version'] == 1
                 and claim['store_id'] == before['database']['archive']['store_id'], 'store_claim_database_mismatch')
            again_reader, after = withdrawn_binding(module, controller)
            need(reader == again_reader and after == before, 'withdrawn_store_read_boundary_changed')
            receipt = {'version': 1, 'status': 200, 'key': KEY, 'storage_binding_sha256': BIND,
                'boundary_mode': 'withdrawn', 'source_sha256': intent['source_sha256'],
                'prepared_sha256': controller.state()['prepared_sha256'],
                'stopped_role_secret_templates_match_admitted_binding': True,
                'actual_operating_files_match_admitted_binding': False,
                'body_base64': base64.b64encode(body).decode(), 'body_sha256': sha(body),
                'request_id': request_id, 'observed_at': now().isoformat()}
            write_exclusive(WORK / 'source-store-claim-qualified.json', receipt)
            return receipt
        except Exception as error:
            code = str(error) if isinstance(error, Stop) and re.fullmatch('[a-z0-9_]+', str(error)) else 'store_claim_read_failed'
            write_exclusive(WORK / 'store-claim-withdrawn-failed.json', {'version': 1, 'known_complete': False,
                'code': code, 'maximum_attempts': 1, 'boundary_mode': 'withdrawn', 'observed_at': now().isoformat()})
            raise Stop(code) from None


def main():
    try:
        need(os.geteuid() == 0, 'root_required')
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--checkpoint-sha256', required=True)
        args = parser.parse_args()
        module, controller = source_context(args.checkpoint_sha256)
        receipt = run(module, controller)
        print(json.dumps({'known_complete': True, 'status': receipt['status'], 'single_get': True}))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, Stop) and re.fullmatch('[a-z0-9_]+', str(error)) else 'store_claim_read_failed'
        print(json.dumps({'known_complete': False, 'code': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
