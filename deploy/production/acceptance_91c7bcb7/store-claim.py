#!/usr/bin/env python3
"""Exactly one native reader GET of the admitted permanent S3 store claim.

Credentials remain in memory. An exclusive fsynced intent precedes all network
work; no redirects, retries, IAM changes, or object mutations are implemented.
"""
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

WORK = Path('/tmp/devres-upgrade-91c7bcb7-20261115')
BUNDLE = Path('/var/lib/devres-production-preparation/a938112b-7c7a24f')
OPERATOR = Path('/usr/local/libexec/devres-production-candidate-a938112b-apparmor-v1/scripts/production-operator.py')
OPERATOR_SHA = '58501767e3d130af1a05e1f6493f89ee8f287e1582f0f35fa2b1e74c23f5e3da'
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


def original_operator():
    need(sha(private_read(OPERATOR, source=True)) == OPERATOR_SHA, 'original_operator_changed')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('store_claim_original_operator', OPERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, module.Operator('default', BUNDLE)


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


def pod_process(value):
    statuses = value.get('status', {}).get('containerStatuses', [])
    need(value.get('status', {}).get('phase') == 'Running' and not value['metadata'].get('deletionTimestamp')
         and len(statuses) == 1 and statuses[0].get('ready') is True, 'operating_pod_not_ready')
    s = statuses[0]
    need(s.get('state', {}).get('running', {}).get('startedAt') and s.get('containerID'), 'operating_process_missing')
    return {k: s.get(k) for k in ('containerID', 'imageID', 'restartCount', 'state')}


def operating_binding(module, operator):
    operator.validate_cluster()
    need(operator.auth_mode() == 'scaleway_static', 'static_auth_required')
    operator.admit_storage_receipt()
    archived_binding = operator.static_runtime_binding()
    need(sha(encoded(archived_binding)) == BIND, 'admitted_storage_binding_changed')
    identity = module.read_json(BUNDLE / 'static-storage-identity.json')
    configs, pairs, boundaries = {}, {}, {}
    for role, (app, config_role, secret_name, config_secret) in ROLES.items():
        deployment = decode(operator.k('get', 'deployment', app, '-o', 'json'))
        secret = decode(operator.k('get', 'secret', secret_name, '-o', 'json'))
        archived = module.read_json(BUNDLE / (secret_name + '.json'))
        need(secret.get('data') == archived.get('data') and secret.get('type') == archived.get('type'), 'operating_credentials_changed')
        pairs[role] = secret_pair(secret)
        cfg = decode(operator.k('get', 'secret', config_secret, '-o', 'json'))
        config_key = config_role + '.toml'
        need(set(cfg.get('data', {})) == {config_key}, 'config_secret_shape')
        raw_config = base64.b64decode(cfg['data'][config_key], validate=True)
        need(len(raw_config) <= 1024**2, 'config_bound')
        configs[role] = tomllib.loads(raw_config.decode())
        stored = tomllib.loads(module.private_read(BUNDLE / (config_role + '.toml')).decode())
        s3 = configs[role]['storage']['s3']
        need(configs[role]['storage'].get('backend') == 's3' and s3 == stored['storage']['s3'], 'operating_s3_config_changed')
        need(s3.get('path_style') is True and {k: s3[k] for k in ('endpoint', 'region', 'bucket', 'prefix', 'path_style')} ==
             {'endpoint': ENDPOINT, 'region': REGION, 'bucket': BUCKET, 'prefix': 'production', 'path_style': True},
             'fixed_s3_endpoint_required')
        need(s3['credentials'] == {'mode': 'files', 'access_key_file': '/run/devres-s3/access-key',
             'secret_key_file': '/run/devres-s3/secret-key'}, 'credential_source_changed')
        template = deployment['spec']['template']
        command = ['devres-server', 'collect' if app == 'writer' else 'serve', '/etc/devres/config/' + config_key]
        container = template['spec']['containers'][0]
        need(container.get('command') == command and not container.get('args'), 'operating_invocation_changed')
        for pod in (template,):
            check_mount(pod, secret_name, '/run/devres-s3', ('access-key', 'secret-key'))
            check_mount(pod, config_secret, '/etc/devres/config', (config_key,))
        opposite = ROLES['writer' if role == 'reader' else 'reader'][2]
        need(not any(v.get('secret', {}).get('secretName') == opposite for v in template['spec']['volumes']), 'cross_role_credential_mount')
        pods = decode(operator.k('get', 'pods', '-l', 'app=' + app, '-o', 'json'))['items']
        need(len(pods) == 1, 'one_operating_pod_required')
        pod = pods[0]
        before = pod_process(pod)
        actual_container = pod['spec']['containers'][0]
        need(all(actual_container.get(k) == container.get(k) for k in
                 ('name', 'image', 'command', 'args', 'volumeMounts', 'securityContext')), 'operating_container_changed')
        owners = pod['metadata'].get('ownerReferences', [])
        need(len(owners) == 1 and owners[0].get('kind') == 'ReplicaSet' and owners[0].get('uid')
             and owners[0].get('name'), 'operating_pod_owner')
        rs = decode(operator.k('get', 'replicaset', owners[0]['name'], '-o', 'json'))
        need(rs['metadata']['uid'] == owners[0]['uid']
             and len(rs['metadata'].get('ownerReferences', [])) == 1
             and rs['metadata']['ownerReferences'][0].get('kind') == 'Deployment'
             and rs['metadata']['ownerReferences'][0].get('uid') == deployment['metadata']['uid'], 'operating_deployment_owner')
        need(pod['spec'].get('nodeName') == operator.settings()['node_name'], 'operating_node_changed')
        # The actual mounted content must match the live Secret as well as its
        # archived admitted bytes; API objects alone do not prove a running file.
        check_mount(pod, secret_name, '/run/devres-s3', ('access-key', 'secret-key'))
        check_mount(pod, config_secret, '/etc/devres/config', (config_key,))
        pod_name = pod['metadata']['name']
        for key in ('access-key', 'secret-key'):
            actual = operator.k('exec', pod_name, '--', 'cat', '/run/devres-s3/' + key)
            need(actual == base64.b64decode(secret['data'][key], validate=True), 'operating_key_file_changed')
        actual_config = operator.k('exec', pod_name, '--', 'cat', '/etc/devres/config/' + config_key)
        need(actual_config == raw_config, 'operating_config_file_changed')
        again = decode(operator.k('get', 'pod', pod_name, '-o', 'json'))
        need(again['metadata']['uid'] == pod['metadata']['uid'] and pod_process(again) == before
             and again['spec'] == pod['spec'], 'operating_process_changed')
        for kind, name, previous in (('deployment', app, deployment), ('secret', secret_name, secret), ('secret', config_secret, cfg)):
            need(decode(operator.k('get', kind, name, '-o', 'json')) == previous, 'operating_api_boundary_changed')
        boundaries[role] = {'pod_uid': pod['metadata']['uid'], 'process': before,
                            'deployment_sha256': sha(encoded(deployment)), 'secret_sha256': sha(encoded(secret)),
                            'config_sha256': sha(raw_config)}
    actual_binding = module.static_binding(configs['reader'], identity, pairs)
    need(sha(encoded(actual_binding)) == BIND and actual_binding == archived_binding, 'actual_role_pairs_not_admitted')
    return pairs['reader'], boundaries


def database_identity(operator):
    sql = "BEGIN READ ONLY; SET LOCAL statement_timeout='5s'; SELECT json_build_object('system_identifier',(SELECT system_identifier::text FROM pg_control_system()),'schema',(SELECT version FROM devres_schema WHERE singleton),'archive',(SELECT json_build_object('backend',backend,'binding',binding,'epoch',epoch,'pending_binding',pending_binding,'initializing_s3',initializing_s3,'store_id',store_id) FROM devres_archive_control WHERE singleton)); COMMIT;"
    value = decode(operator.k('exec', 'deployment/postgres', '--', 'psql', '-X', '-qAt', '-U', 'devres_admin',
        '-d', 'devres', '-v', 'ON_ERROR_STOP=1', '-c', sql))
    need(value.get('system_identifier') == SYSTEM_ID and value.get('schema') == 18, 'original_database_identity_changed')
    archive = value['archive']
    need({k: archive[k] for k in ('backend', 'binding', 'epoch', 'pending_binding', 'initializing_s3')} ==
         {'backend': 's3', 'binding': ARCHIVE_BINDING, 'epoch': 2, 'pending_binding': None, 'initializing_s3': False}
         and re.fullmatch('[0-9a-f]{32}', archive['store_id']), 'original_archive_identity_changed')
    return value


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


def run(module, operator, get=native_get):
    private_directory(WORK)
    with module.bundle_lock(BUNDLE), module.bundle_lock(BUNDLE, '.certificate.lock'):
        intent = {'version': 1, 'method': 'GET', 'url': URL, 'maximum_attempts': 1,
                  'reader_only': True, 'source_sha256': sha(private_read(Path(__file__), source=True)),
                  'created_at': now().isoformat()}
        write_exclusive(WORK / 'store-claim-intent.json', intent)
        try:
            reader, before = operating_binding(module, operator)
            database = database_identity(operator)
            body, request_id = get(reader)
            claim = decode(body)
            need(set(claim) == {'version', 'store_id'} and type(claim['version']) is int and claim['version'] == 1
                 and claim['store_id'] == database['archive']['store_id'], 'store_claim_database_mismatch')
            again_reader, after = operating_binding(module, operator)
            need(reader == again_reader and after == before and database_identity(operator) == database, 'store_read_boundary_changed')
            receipt = {'version': 1, 'status': 200, 'key': KEY, 'storage_binding_sha256': BIND,
                'actual_operating_files_match_admitted_binding': True, 'body_base64': base64.b64encode(body).decode(),
                'body_sha256': sha(body), 'request_id': request_id, 'observed_at': now().isoformat()}
            write_exclusive(WORK / 'source-store-claim-qualified.json', receipt)
            return receipt
        except Exception as error:
            code = str(error) if isinstance(error, Stop) and re.fullmatch('[a-z0-9_]+', str(error)) else 'store_claim_read_failed'
            write_exclusive(WORK / 'store-claim-failed.json', {'version': 1, 'known_complete': False,
                'code': code, 'maximum_attempts': 1, 'observed_at': now().isoformat()})
            raise Stop(code) from None


def main():
    try:
        need(os.geteuid() == 0, 'root_required')
        module, operator = original_operator()
        receipt = run(module, operator)
        print(json.dumps({'known_complete': True, 'status': receipt['status'], 'single_get': True}))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, Stop) and re.fullmatch('[a-z0-9_]+', str(error)) else 'store_claim_read_failed'
        print(json.dumps({'known_complete': False, 'code': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
