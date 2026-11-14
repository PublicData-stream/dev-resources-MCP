#!/usr/bin/env python3
"""One root-only physical PG rollback checkpoint; original immutable S3 is retained.
No production restore, schema update, IAM change or upstream acquisition is offered.
"""
import argparse, base64, contextlib, copy, datetime, fcntl, hashlib, http.client, importlib.util, ipaddress, json, os, pathlib, re, shutil, socket, ssl, stat, subprocess, sys, time, tomllib
P = pathlib.Path
N = P('/tmp/devres-upgrade-33f3c730-20261114')
S = N / 'checkpoint-state'
PUBLIC = N / 'public-upgrade-identity.json'
APPROVAL = N / 'checkpoint-approval.json'
CLAIM = N / 'source-store-claim-qualified.json'
UPGRADE = P('/var/lib/devres-production-upgrades/33f3c730-20261114')
PREPARED = UPGRADE / 'prepared.json'
PREDECESSOR = P('/var/lib/devres-production-upgrades/5196c629-20261112')
ACTIVATION = P('/var/lib/devres-production-activations/wikipedia-65236494-20261113')
B = P('/var/lib/devres-production-preparation/a938112b-7c7a24f')
OP = P('/usr/local/libexec/devres-production-candidate-a938112b-apparmor-v1/scripts/production-operator.py')
OP_SHA = '58501767e3d130af1a05e1f6493f89ee8f287e1582f0f35fa2b1e74c23f5e3da'
ACTIVATION_SOURCE = P('/usr/local/libexec/devres-wikipedia-enable-65236494/activation-controller.py')
ACTIVATION_SHA = 'd9699971623a9d828ff119f80d6fe23055f7107427375957231015b17168dc56'
REV = '33f3c730123319625fe3a25713988201eb5d82e0'
OLD_REV = '65236494ad7a837243d16c7e92e177df77a7d226'
OLD = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:efe9f706d82d535b89c18cfe9fbc68d7e7f586e014d534b00828cc8639b2c52d'
PG = 'postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395'
PV = P('/database/devres/corpus')
BIND = '4a59576b1a2977f157ceaf72fbe404f660bd89a44c6246106b65f83989f5c529'
SYSID = '7706567225121447965'
ARCHIVE = {'backend': 's3', 'binding': 'blake3:7cf193132e3e32eb53c877dfcce166453e5bbb1b0d3f9a39f922f194f82f38e3', 'epoch': 2, 'pending_binding': None, 'initializing_s3': False}
CID = 'blake3:f561023b34507798258530bff923c41bab5d092d71b2cae7da484e6d5ce6d0e0'
BODY = 'blake3:58f50168dc03a034edf54305bbf7dd71e1e1f91cb942d5e8e401ab8939890c1a'
GENERATION = 'blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81'
NOTICE = 'e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156'
PROVIDERS = ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'npm', 'wikipedia')
MAX_PG_BYTES = 64 * 1024 ** 3
MAX_FILES = 1000000
MAX_MANIFEST = 1024 ** 3
RESERVE = 128 * 1024 ** 3
MAX_COMMAND = 4 * 1024 ** 2
LABEL = 'devres.upgrade.checkpoint'
SECRET_NAMES = ('devres-corpus-postgres', 'devres-serving-config', 'devres-writer-config', 'devres-backend-tls', 'devres-writer-tls', 'devres-serving-s3', 'devres-writer-s3')

class Stop(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Stop(code)

def sha(v):
    return hashlib.sha256(v).hexdigest()

def enc(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':')).encode()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def decode(v):

    def unique(pairs):
        out = {}
        for k, v in pairs:
            need(k not in out, 'duplicate_json_key')
            out[k] = v
        return out
    return json.loads(v, object_pairs_hook=unique)

def private_dir(path):
    need(path.is_absolute() and '..' not in path.parts, 'absolute_private_directory_required')
    for q in (path, *path.parents):
        m = q.lstat()
        need(stat.S_ISDIR(m.st_mode), 'private_directory_symlink_or_non_directory')
        if q == P('/tmp'):
            need(m.st_uid == 0 and m.st_mode & stat.S_ISVTX, 'unsafe_tmp')
            return
        need(m.st_uid == os.geteuid() and (not m.st_mode & 63), 'unsafe_private_directory')
    raise Stop('private_directory_outside_tmp')

def raw(path, limit=4 * 1024 ** 2, private=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        m = os.fstat(fd)
        need(stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and (m.st_size <= limit), 'bounded_regular_file_required')
        if private:
            need(m.st_uid == os.geteuid() and (not m.st_mode & 63), 'unsafe_private_file')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            v = f.read(limit + 1)
        need(len(v) == m.st_size, 'input_changed')
        return v
    finally:
        os.close(fd)

def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def new(path, value, uid=None, mode=384):
    v = value if isinstance(value, bytes) else enc(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(v)
        f.flush()
        os.fsync(f.fileno())
        if uid is not None:
            os.fchown(f.fileno(), uid, uid)
    sync(path.parent)

def load(name):
    return decode(raw(S / name))

def save(name, value):
    need(re.fullmatch('[a-z0-9-]+\\.json', name), 'record_basename_required')
    new(S / name, value)

def run(args, timeout=60, data=None):
    r = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    need(len(r.stdout) <= MAX_COMMAND and len(r.stderr) <= MAX_COMMAND, 'command_output_bound')
    need(r.returncode == 0, 'command_failed_' + P(args[0]).name)
    return r.stdout
K = ['k3s', 'kubectl', '--context', 'default', '--namespace', 'devres', '--request-timeout=30s']

def k(*args, timeout=60):
    return run([*K, *args], timeout)

def get(kind, name):
    return decode(k('get', kind, name, '-o', 'json'))

def pgsql(query, timeout=40):
    need(query.lstrip().startswith('SELECT '), 'readonly_select_required')
    return decode(k('exec', 'deployment/postgres', '-c', 'postgres', '--', 'psql', '-X', '-q', '-U', 'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c', "BEGIN READ ONLY; SET LOCAL statement_timeout='20s'; SET LOCAL lock_timeout='250ms'; " + query + '; COMMIT;', timeout=timeout))

def role_pods(role):
    return decode(k('get', 'pods', '-l', 'app=' + role, '-o', 'json'))['items']

def pod_projection(v):
    need(v.get('status', {}).get('phase') == 'Running' and (not v['metadata'].get('deletionTimestamp')), 'running_pod_required')
    a = v['status'].get('containerStatuses', [])
    need(len(a) == 1 and a[0].get('ready') is True and a[0].get('state', {}).get('running'), 'one_ready_container_required')
    a = a[0]
    return {'name': v['metadata']['name'], 'pod_ip': v['status']['podIP'], 'uid': v['metadata']['uid'], 'container_id': a['containerID'], 'image_id': a['imageID'], 'started_at': a['state']['running']['startedAt'], 'restarts': a['restartCount'], 'owner': v['metadata'].get('ownerReferences', [])}

def deployment_projection(v):
    v = copy.deepcopy(v)
    s = v['spec']
    s.pop('replicas', None)
    return {'uid': v['metadata']['uid'], 'spec': s}

def schema_identity():
    return pgsql("SELECT json_build_object('system_id',(SELECT system_identifier::text FROM pg_control_system()),'schema',(SELECT version FROM devres_schema WHERE singleton),'data_directory',current_setting('data_directory'),'recovery',pg_is_in_recovery(),'external_tablespaces',(SELECT count(*) FROM pg_tablespace WHERE pg_tablespace_location(oid)<>''),'wikipedia_tables',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_wikipedia_evidence')),(to_regclass('public.devres_wikipedia_state'))) t(oid) WHERE oid IS NOT NULL),'schema15_objects',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_crate_enrichment_v2')),(to_regclass('public.devres_crate_enrichment_heads_v2')),(to_regclass('public.devres_crate_dump_failures')),(to_regclass('public.devres_crate_enrichment_all'))) t(oid) WHERE oid IS NOT NULL),'archive',(SELECT json_build_object('backend',backend,'binding',binding,'epoch',epoch,'pending_binding',pending_binding,'initializing_s3',initializing_s3,'store_id',store_id) FROM devres_archive_control WHERE singleton),'publication_owners',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())))")

def checked_identity(v, stopped=False):
    need(v['wikipedia_tables'] == 2 and v['schema15_objects'] == 4, 'schema15_object_set_required')
    need(v['system_id'] == SYSID and v['schema'] == 15 and (v['recovery'] is False) and (v['external_tablespaces'] == 0), 'schema15_primary_identity_required')
    need({k: v['archive'][k] for k in ARCHIVE} == ARCHIVE and re.fullmatch('[0-9a-f]{32}', v['archive']['store_id']), 'unchanged_archive_required')
    if stopped:
        need(v['publication_owners'] == 0, 'publication_owner_remains')

def source_layout(deploy, identity):
    containers = deploy['spec']['template']['spec']['containers']
    need(len(containers) == 1 and containers[0]['name'] == 'postgres' and (containers[0]['image'] == PG), 'pinned_pg_template_required')
    directory = P(identity['data_directory'])
    matches = []
    for mount in containers[0]['volumeMounts']:
        target = P(mount['mountPath'])
        if directory.is_relative_to(target):
            matches.append((mount, target))
    need(len(matches) == 1, 'unambiguous_pgdata_mount_required')
    mount, target = matches[0]
    need(not mount.get('subPath') and (not mount.get('subPathExpr')), 'pg_subpath_not_supported')
    volume = next((v for v in deploy['spec']['template']['spec']['volumes'] if v['name'] == mount['name']))
    pvc = get('pvc', volume['persistentVolumeClaim']['claimName'])
    pv = get('pv', pvc['spec']['volumeName'])
    need(pv['spec'].get('local', {}).get('path') == str(PV), 'exact_production_pv_required')
    relative = directory.relative_to(target)
    need(relative.as_posix() == '18/docker', 'qualified_pg18_data_layout_required')
    source = PV / relative
    for q in (source, *source.parents):
        need(not q.is_symlink(), 'pg_source_symlink_refused')
    need(source.is_dir() and raw(source / 'PG_VERSION', 64, False) == b'18\n', 'pg18_source_required')
    return {'pv_uid': pv['metadata']['uid'], 'pv_name': pv['metadata']['name'], 'pvc_uid': pvc['metadata']['uid'], 'pvc_name': pvc['metadata']['name'], 'pv_path': str(PV), 'relative': relative.as_posix(), 'container_data_directory': str(directory), 'source': str(source)}

def scan_tree(root, hash_files=False):
    started = time.monotonic()
    rows = []
    total = 0
    need(root.is_dir() and (not root.is_symlink()), 'pg_tree_directory_required')
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            p = P(folder) / name
            m = p.lstat()
            need(stat.S_ISDIR(m.st_mode) or stat.S_ISREG(m.st_mode), 'pg_symlink_special_or_external_path_refused')
            rel = p.relative_to(root).as_posix()
            row = {'path': rel, 'kind': 'directory' if stat.S_ISDIR(m.st_mode) else 'file', 'mode': stat.S_IMODE(m.st_mode), 'uid': m.st_uid, 'gid': m.st_gid, 'bytes': m.st_size if stat.S_ISREG(m.st_mode) else 0}
            if stat.S_ISREG(m.st_mode):
                need(m.st_nlink == 1, 'pg_hardlink_refused')
                total += m.st_size
                if hash_files:
                    h = hashlib.sha256()
                    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd, 'rb') as f:
                        while True:
                            part = f.read(1024 ** 2)
                            if not part:
                                break
                            h.update(part)
                            need(time.monotonic() - started < 1800, 'pg_hash_deadline')
                        after = os.fstat(f.fileno())
                        need((m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'pg_checkpoint_file_changed')
                    row['sha256'] = h.hexdigest()
            rows.append(row)
            need(len(rows) <= MAX_FILES and total <= MAX_PG_BYTES, 'pg_checkpoint_bound')
    need(not (root / 'standby.signal').exists() and (not (root / 'recovery.signal').exists()), 'primary_only_checkpoint_required')
    return (sorted(rows, key=lambda r: r['path']), total)

def dest_checked(path):
    need(path in (S / 'pg-checkpoint', S / 'pg-clone'), 'only_exact_owned_copy_destination')
    private_dir(S)
    owner = load('owner.json')
    need(re.fullmatch('[0-9a-f]{24}', owner['token']), 'checkpoint_owner_required')
    need(path.exists() and path.is_dir() and (not path.is_symlink()) and (path.parent == S), 'owned_copy_destination_required')
    scan_tree(path)

def flush_owned_copy(destination):
    dest_checked(destination)
    rows, _ = scan_tree(destination)
    started = time.monotonic()
    # Flush copied regular files AND directory entries before admitting recovery.
    for row in rows:
        if row['kind'] == 'file':
            fd = os.open(destination / row['path'], os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'flush_regular_owned_file_required')
                os.fsync(fd)
            finally:
                os.close(fd)
            need(time.monotonic() - started < 1800, 'checkpoint_flush_deadline')
    for row in sorted((r for r in rows if r['kind'] == 'directory'), key=lambda r: len(P(r['path']).parts), reverse=True):
        sync(destination / row['path'])
    sync(destination)
    sync(destination.parent)

def copy_tree(source, destination, live=False):
    dest_checked(destination)
    need(source.resolve() != destination.resolve() and (not source.resolve().is_relative_to(destination.resolve())) and (not destination.resolve().is_relative_to(source.resolve())), 'overlapping_copy_refused')
    args = ['/usr/bin/rsync', '-aHAX', '--numeric-ids', '--one-file-system', '--no-devices', '--no-specials', '--delete', '--', str(source) + '/', str(destination) + '/']
    if not live:
        # Running precopy can contain same-size changes inside one mtime second.
        # A stopped-source checksum comparison must replace mtime quick-check.
        args.insert(2, '--checksum')
    r = subprocess.run(args, capture_output=True, timeout=1200)
    need(len(r.stdout) + len(r.stderr) <= MAX_COMMAND, 'copy_diagnostics_bound')
    need(r.returncode == 0 or (live and r.returncode == 24), 'physical_copy_failed')
    if not live:
        flush_owned_copy(destination)
    return {'exit_status': r.returncode, 'untrusted_live_precopy': live, 'durable_files_and_directories': not live, 'diagnostic_sha256': sha(r.stdout + r.stderr)}

def prepared_input():
    approval = decode(raw(APPROVAL))
    body = raw(PREPARED)
    need(sha(body) == approval['controller_prepared_sha256'], 'accepted_controller_prepared_changed')
    value = decode(body)
    need(value['revision'] == REV and value['store_binding_sha256'] == BIND, 'prepared_upgrade_identity_changed')
    return value

def foundation_projection(items):
    result = []
    for item in items:
        meta = item['metadata']
        result.append({'kind': item['kind'], 'name': meta['name'], 'uid': meta['uid'], 'labels': meta.get('labels', {}), 'spec': item.get('spec'), 'rules': item.get('rules'), 'subjects': item.get('subjects'), 'roleRef': item.get('roleRef'), 'automountServiceAccountToken': item.get('automountServiceAccountToken')})
    return sorted(result, key=lambda value: (value['kind'], value['name']))

def secret_projection(value):
    return {'uid': value['metadata']['uid'], 'type': value.get('type'), 'immutable': value.get('immutable', False), 'data': value.get('data', {})}

def successor_anchor(anchor):
    need(anchor.get('edge_admitted') is True and not anchor.get('auth_successor') and not anchor.get('auth_switch_pending') and anchor.get('phase') in ('runtime_upgraded', 'runtime_upgrade_stopped') and anchor.get('upgrade_successor') == str(PREDECESSOR), 'current_successor_anchor_required')

def prepared_boundary():
    prepared = prepared_input()
    state = decode(raw(UPGRADE / 'state.json'))
    need(state['revision'] == REV and state['prepared_sha256'] == sha(raw(PREPARED)) and state['phase'] in ('prepared', 'stopped'), 'checkpoint_only_before_target_mutation')
    for role in ('postgres', 'backend', 'writer'):
        current = get('deployment', role)
        projection = deployment_projection(current)
        image = projection['spec']['template']['spec']['containers'][0].pop('image')
        need(projection == prepared['deployments'][role]['projection'] and image == (PG if role == 'postgres' else OLD), 'prepared_workload_boundary_changed')
    for name, expected in prepared['secrets'].items():
        need(secret_projection(get('secret', name)) == expected, 'prepared_secret_boundary_changed')
    actual = decode(k('get', 'networkpolicies,roles,rolebindings,serviceaccounts,services,persistentvolumeclaims', '-o', 'json'))['items']
    need(foundation_projection(actual) == prepared['foundation'], 'prepared_cluster_foundation_changed')
    return prepared

def source_guard():
    need(sha(raw(OP, private=False)) == OP_SHA, 'frozen_old_operator_required')
    sp = importlib.util.spec_from_file_location('checkpoint_old_operator', OP)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    o = m.Operator('default', B)
    o.validate_cluster()
    o.admit_storage_receipt()
    need(o.auth_mode() == 'scaleway_static' and sha(enc(o.static_runtime_binding())) == BIND, 'current_static_binding_required')
    anchor = m.read_json(B / 'state.json')
    successor_anchor(anchor)
    prepared = prepared_boundary()
    need(sha(raw(ACTIVATION_SOURCE)) == ACTIVATION_SHA, 'frozen_activation_controller_required')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('checkpoint_current_activation', ACTIVATION_SOURCE)
    activation_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(activation_module)
    activation = activation_module.Activation(ACTIVATION, 'default')
    activation.base.safety()
    need(decode(raw(ACTIVATION / 'prepared.json'))['revision'] == OLD_REV, 'current_activation_revision_required')
    need(activation.base.edge() == prepared['edge'] and activation.base.boot() == prepared['boot'], 'prepared_edge_or_boot_changed')
    need({name: sha(value) for name, value in activation.base.profiles().items()} == prepared['profiles'], 'prepared_profiles_changed')
    return (m, o)

def authorize():
    need(os.geteuid() == 0, 'root_required')
    private_dir(N)
    v = decode(raw(APPROVAL))
    pub = decode(raw(PUBLIC))
    claim = decode(raw(CLAIM))
    source = sha(raw(P(__file__), private=False))
    need(pub['revision'] == REV and pub['old_image'] == OLD and (pub['pg_image'] == PG) and (pub['pg_pv_path'] == str(PV)) and (pub['old_operator_sha256'] == OP_SHA) and (pub['schema_before'] == 15), 'public_upgrade_identity_changed')
    expected = {'version': 1, 'approved': True, 'scope': 'physical-pg-checkpoint-33f3c730', 'source_sha256': source, 'public_identity_sha256': sha(raw(PUBLIC)), 'store_claim_sha256': sha(raw(CLAIM)), 'controller_prepared_sha256': sha(raw(PREPARED)), 'operations': ['prepare', 'run', 'proof'], 'maximum_checkpoints': 1, 'maximum_rehearsals': 1, 'independent_s3_backup': False}
    need(v == expected, 'explicit_exact_checkpoint_approval_required')
    need(claim['version'] == 1 and claim['status'] == 200 and (claim['key'] == 'production/store.json') and (claim['storage_binding_sha256'] == BIND) and (claim['actual_operating_files_match_admitted_binding'] is True), 'current_store_claim_required')
    body = base64.b64decode(claim['body_base64'], validate=True)
    need(len(body) <= 16384 and sha(body) == claim['body_sha256'] and (0 < len(claim['request_id']) <= 256), 'store_claim_readback_required')
    d = decode(body)
    need(set(d) == {'version', 'store_id'} and d['version'] == 1 and re.fullmatch('[0-9a-f]{32}', d['store_id']), 'store_claim_descriptor_identity')
    return {'source_sha256': source, 'approval_sha256': sha(raw(APPROVAL)), 'public_identity_sha256': sha(raw(PUBLIC)), 'store_claim_sha256': sha(raw(CLAIM)), 'controller_prepared_sha256': sha(raw(PREPARED)), 'store_id': d['store_id']}

def prepare(pins):
    need(not S.exists() and (not S.is_symlink()), 'fresh_checkpoint_scope_required')
    S.mkdir(mode=448)
    sync(N)
    token = os.urandom(12).hex()
    save('owner.json', {'token': token, 'pins': pins, 'created_at': now()})
    m, o = source_guard()
    with m.bundle_lock(B), m.bundle_lock(B, '.certificate.lock'):
        # Recheck after acquiring both locks; the admission read before lock acquisition
        # cannot authorize an operation if a timer changed its boundary meanwhile.
        source_guard()
        qualified_images = {'pg': image_id(PG), 'old_server': image_id(OLD, OLD_REV)}
        deploy = get('deployment', 'postgres')
        need(deploy['spec'].get('replicas') == 1, 'original_pg_running_required')
        pods = role_pods('postgres')
        need(len(pods) == 1, 'one_pg_pod_required')
        projection = pod_projection(pods[0])
        need(projection == prepared_input()['old_pods']['postgres'], 'fresh_prepared_pg_process_required')
        identity = schema_identity()
        checked_identity(identity)
        need(identity['archive']['store_id'] == pins['store_id'], 'sql_store_claim_mismatch')
        layout = source_layout(deploy, identity)
        rows, total = scan_tree(P(layout['source']))
        need(shutil.disk_usage(N).free >= 3 * max(total, 1) + RESERVE, 'checkpoint_and_clone_headroom')
        need(any(v.get('secret', {}).get('secretName') == 'devres-corpus-postgres' for v in deploy['spec']['template']['spec']['volumes']), 'actual_corpus_postgres_secret_required')
        private = S / 'private'
        private.mkdir(mode=448)
        originals = {}
        accepted = prepared_input()
        new(private / 'controller-prepared.json', raw(PREPARED))
        for role, secret_name, filename in [('backend', 'devres-serving-config', 'serving.toml'), ('writer', 'devres-writer-config', 'writer.toml')]:
            v = base64.b64decode(accepted['secrets'][secret_name]['data'][filename], validate=True)
            value = tomllib.loads(v.decode())
            need(value['source']['url'].endswith('/0.1.0-build.65236494/source.tar.gz') and value['storage']['backend'] == 's3' and type(value['wikipedia']['enabled']) is bool, 'current_schema15_configuration_required')
            new(private / filename, v)
            originals['prepared-config/' + filename] = sha(v)
        # Preserve current admission metadata; the a938 config files contain obsolete passwords.
        for name in ('settings.json', 'state.json', 'static-storage-identity.json', 'acceptance-receipt.json'):
            v = m.private_read(B / name)
            new(private / name, v)
            originals[name] = sha(v)
        secrets = []
        for name in accepted['secrets']:
            secret = get('secret', name)
            new(private / (name + '.json'), secret)
            secrets.append({'name': name, 'uid': secret['metadata']['uid'], 'data_sha256': sha(enc(secret.get('data', {})))})
        tls = private / 'tls'
        tls.mkdir(mode=448)
        for name in ('backend.crt', 'backend.key', 'backend-ca.crt', 'edge-client-ca.crt', 'edge-client.crt', 'edge-client.key', 'coordination-ca.crt'):
            v = m.private_read(B / 'tls' / name)
            new(tls / name, v)
            originals['tls/' + name] = sha(v)
        for field, src in [('access-key', P('/etc/devres/static-bootstrap/devres-serving.id')), ('secret-key', P('/etc/devres/static-bootstrap/devres-serving.key'))]:
            new(private / field, raw(src, 16384))
        source_secret = decode(raw(private / 'devres-serving-s3.json'))['data']
        need(all((raw(private / k).decode().rstrip('\r\n') == base64.b64decode(source_secret[k]).decode().rstrip('\r\n') for k in ('access-key', 'secret-key'))), 'actual_reader_pair_differs_from_admitted_secret')
        namespaces = {name: get('namespace', name)['metadata']['uid'] for name in ('devres', 'kube-system')}
        need(len({p['spec']['nodeName'] for p in pods}) == 1, 'one_node_required')
        node = pods[0]['spec']['nodeName']
        node_uid = get('node', node)['metadata']['uid']
        baseline = {'pins': pins, 'old_pg_pod': projection, 'postgres_deployment': deployment_projection(deploy), 'layout': layout, 'identity': identity, 'namespace_uids': namespaces, 'node_name': node, 'node_uid': node_uid, 'secret_bindings': secrets, 'original_files_sha256': originals, 'qualified_local_images': qualified_images, 'live_pg_bytes': total, 'live_pg_files': sum((r['kind'] == 'file' for r in rows))}
        save('baseline.json', baseline)
        (S / 'pg-checkpoint').mkdir(mode=448)
        save('precopy-intent.json', {'source': layout['source'], 'destination': str(S / 'pg-checkpoint'), 'not_a_valid_checkpoint': True})
        result = copy_tree(P(layout['source']), S / 'pg-checkpoint', True)
        save('prepared.json', {'baseline_sha256': sha(raw(S / 'baseline.json')), 'precopy': result, 'not_a_valid_checkpoint': True, 'prepared_at': now()})
    return {'prepared': True, 'untrusted_precopy_only': True, 'source_sha256': pins['source_sha256'], 'private_data_export_allowed': False}

def private_sources_unchanged(b):
    accepted = prepared_input()
    for name, digest in b['original_files_sha256'].items():
        if name.startswith('prepared-config/'):
            filename = name.split('/', 1)[1]
            secret_name = 'devres-serving-config' if filename == 'serving.toml' else 'devres-writer-config'
            need(sha(base64.b64decode(accepted['secrets'][secret_name]['data'][filename], validate=True)) == digest, 'current_rotated_config_changed')
        elif name != 'state.json':
            need(sha(raw(B / name)) == digest, 'original_private_config_changed')
    for known in b['secret_bindings']:
        value = get('secret', known['name'])
        need(value['metadata']['uid'] == known['uid'] and sha(enc(value.get('data', {}))) == known['data_sha256'], 'original_secret_identity_or_data_changed')

def controller_deployment_hash(projection):
    value = copy.deepcopy(projection)
    containers = value['spec']['template']['spec']['containers']
    need(len(containers) == 1 and containers[0]['image'] == PG, 'exact_old_pg_image_required')
    containers[0].pop('image')
    return sha(enc(value))

def stable_foundation(b):
    prepared_boundary()
    need({name: get('namespace', name)['metadata']['uid'] for name in b['namespace_uids']} == b['namespace_uids'] and get('node', b['node_name'])['metadata']['uid'] == b['node_uid'], 'cluster_foundation_changed')
    private_sources_unchanged(b)
    d = get('deployment', 'postgres')
    need(deployment_projection(d) == b['postgres_deployment'], 'pg_deployment_changed')
    return d

def roles_stopped():
    for role in ('backend', 'writer'):
        need(get('deployment', role)['spec'].get('replicas') == 0 and role_pods(role) == [], 'both_source_roles_must_be_stopped')

def stream_manifest(kind='archive'):
    need(kind in ('archive', 'captures'), 'fixed_manifest_kind_required')
    target = S / ('archive-bindings.jsonl' if kind == 'archive' else 'capture-bindings.jsonl')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
    query = 'BEGIN READ ONLY; SET LOCAL statement_timeout=\'300s\'; SET LOCAL lock_timeout=\'250ms\'; SELECT json_build_object(\'path\',path,\'digest\',digest,\'bytes\',bytes,\'device\',device,\'inode\',inode,\'evidence\',evidence,\'epoch\',epoch,\'complete\',complete) FROM devres_archive_file ORDER BY path COLLATE "C"; COMMIT;'
    if kind == 'captures':
        query = 'BEGIN READ ONLY; SET LOCAL statement_timeout=\'300s\'; SET LOCAL lock_timeout=\'250ms\'; SELECT row_to_json(c) FROM devres_captures c ORDER BY id COLLATE "C"; COMMIT;'
    args = [*K, 'exec', 'deployment/postgres', '-c', 'postgres', '--', 'psql', '-X', '-q', '-U', 'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c', query]
    err = S / ('manifest-command.stderr' if kind == 'archive' else 'capture-manifest-command.stderr')
    efd = os.open(err, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
    start = time.monotonic()
    count = 0
    total = 0
    object_bytes = 0
    previous = None
    digest = hashlib.sha256()
    with os.fdopen(fd, 'wb') as out, os.fdopen(efd, 'wb') as errors:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errors)
        try:
            import selectors
            selector = selectors.DefaultSelector()
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ)
            pending = bytearray()
            eof = False
            while not eof:
                need(time.monotonic() - start < 330, 'manifest_deadline')
                for key, _ in selector.select(0.5):
                    block = os.read(key.fd, 65536)
                    if not block:
                        eof = True
                        break
                    pending.extend(block)
                    need(len(pending) <= 131072, 'manifest_line_bound')
                    while b'\n' in pending:
                        line, _, rest = pending.partition(b'\n')
                        pending = bytearray(rest)
                        v = decode(line)
                        path = v['path'] if kind == 'archive' else v['id']
                        need(isinstance(path, str) and path and (not previous or path.encode() > previous.encode()), 'ordered_unique_manifest_required')
                        if kind == 'archive':
                            need(v['complete'] is True and v['epoch'] == ARCHIVE['epoch'], 'complete_same_epoch_archive_required')
                            need(type(v['bytes']) is int and v['bytes'] >= 0 and re.fullmatch('blake3:[0-9a-f]{64}', v['digest']), 'archive_manifest_identity')
                            evidence = decode(v['evidence'])
                            need(all((str(evidence[k]) == str(v[k]) for k in ('path', 'digest', 'bytes', 'device', 'inode'))), 'archive_descriptor_mismatch')
                        else:
                            need(re.fullmatch('(?:blake3:)?[0-9a-f]{64}', path) and re.fullmatch('(?:blake3:)?[0-9a-f]{64}', v['body_hash']), 'capture_manifest_identity')
                        previous = path
                        count += 1
                        object_bytes += v['bytes'] if kind == 'archive' else 0
                        total += len(line) + 1
                        need(count <= MAX_FILES and total <= MAX_MANIFEST, 'manifest_total_bound')
                        out.write(line + b'\n')
                        digest.update(line + b'\n')
            need(not pending, 'manifest_missing_final_newline')
            need(proc.wait(timeout=10) == 0, 'manifest_command_failed')
            out.flush()
            os.fsync(out.fileno())
            need(err.stat().st_size <= MAX_COMMAND, 'manifest_stderr_bound')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            proc.stdout.close()
            selector.close()
    sync(S)
    return {'path': str(target), 'sha256': digest.hexdigest(), 'files': count, 'manifest_bytes': total, 'logical_file_bytes': object_bytes, 'remote_objects_independently_copied': False, 'all_remote_hashes_rechecked': False}

def image_id(reference, revision=None):
    row = decode(run(['docker', 'image', 'inspect', reference]))[0]
    need(row['Architecture'] == 'amd64' and row['Os'] == 'linux', 'native_qualified_image_required')
    need(any(v.rsplit('@', 1)[-1] == reference.rsplit('@', 1)[-1] for v in row.get('RepoDigests', [])), 'pinned_release_repository_digest_required')
    need(re.fullmatch('sha256:[0-9a-f]{64}', row.get('Id', '')), 'local_config_id_required')
    if revision:
        need(row.get('Config', {}).get('Entrypoint') == ['/usr/local/bin/devres-server'], 'old_server_entrypoint_required')
        need(row.get('Config', {}).get('Labels', {}).get('org.opencontainers.image.revision') == revision, 'old_server_revision_required')
    return row['Id']

def reader_command(image):
    # The qualified OCI ENTRYPOINT already invokes devres-server.
    return [image, 'serve', '/etc/devres/config/serving.toml']

def control(source, pgimage):
    out = run(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--user', '70:70', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount', 'type=bind,src=' + str(source) + ',dst=/check,readonly', pgimage, 'pg_controldata', '/check'], 60).decode()
    values = dict((line.split(':', 1) for line in out.splitlines() if ':' in line))
    need(values.get('Database system identifier', '').strip() == SYSID and values.get('Database cluster state', '').strip() == 'shut down', 'clean_original_pg_shutdown_required')
    return {'system_id': SYSID, 'cluster_state': 'shut down', 'output_sha256': sha(out.encode())}

def restore_original_pg(b):
    d = stable_foundation(b)
    need(d['spec'].get('replicas') in (0, 1), 'pg_replicas_changed')
    if d['spec'].get('replicas') == 0:
        k('scale', 'deployment/postgres', '--replicas=1')
    k('rollout', 'status', 'deployment/postgres', '--timeout=600s', timeout=630)
    pods = role_pods('postgres')
    need(len(pods) == 1, 'one_resumed_pg_required')
    p = pod_projection(pods[0])
    identity = schema_identity()
    checked_identity(identity, True)
    need({k: identity[k] for k in ('system_id', 'schema', 'archive', 'data_directory')} == {k: b['identity'][k] for k in ('system_id', 'schema', 'archive', 'data_directory')}, 'resumed_original_pg_changed')
    need(source_layout(d, identity) == b['layout'], 'resumed_pg_pv_or_layout_changed')
    roles_stopped()
    save('original-pg-resumed.json', {'new_pg_pod': p, 'identity': identity, 'postgres_deployment': deployment_projection(stable_foundation(b)), 'production_pg_restarted_without_restore': True, 'observed_at': now()})
    return p

def checkpoint(pins):
    b = load('baseline.json')
    need(b['pins'] == pins and load('prepared.json')['baseline_sha256'] == sha(raw(S / 'baseline.json')), 'prepared_checkpoint_changed')
    need(not (S / 'stop-postgres-intent.json').exists(), 'one_checkpoint_attempt_only')
    m, o = source_guard()
    with m.bundle_lock(B), m.bundle_lock(B, '.certificate.lock'):
        # Recheck after acquiring both locks; the admission read before lock acquisition
        # cannot authorize an operation if a timer changed its boundary meanwhile.
        source_guard()
        d = stable_foundation(b)
        roles_stopped()
        need(d['spec'].get('replicas') == 1, 'original_pg_running_required')
        pods = role_pods('postgres')
        need(len(pods) == 1 and pod_projection(pods[0]) == b['old_pg_pod'], 'original_pg_process_changed')
        v = schema_identity()
        checked_identity(v, True)
        need(source_layout(d, v) == b['layout'], 'pg_layout_changed')
        need(v['archive']['store_id'] == pins['store_id'], 'current_store_id_changed')
        manifest = stream_manifest()
        save('archive-manifest-receipt.json', manifest)
        capture_manifest = stream_manifest('captures')
        save('capture-manifest-receipt.json', capture_manifest)
        save('quiescent-identity.json', v)
        pgimage = image_id(PG)
        need(pgimage == b['qualified_local_images']['pg'], 'qualified_pg_image_changed')
        source = P(b['layout']['source'])
        save('stop-postgres-intent.json', {'observed_at': now(), 'old_pg_pod': b['old_pg_pod'], 'no_production_restore': True})
        stopped = time.monotonic()
        success = False
        try:
            k('scale', 'deployment/postgres', '--replicas=0')
            k('wait', '--for=delete', 'pod', '-l', 'app=postgres', '--timeout=180s', timeout=200)
            need(role_pods('postgres') == [] and (not (source / 'postmaster.pid').exists()), 'original_pg_not_stopped')
            clean = control(source, pgimage)
            save('clean-pg-control.json', clean)
            save('final-copy-intent.json', {'source': str(source), 'destination': str(S / 'pg-checkpoint'), 'checkpoint_only_delete': True})
            copied = copy_tree(source, S / 'pg-checkpoint')
            need(not (S / 'pg-checkpoint/postmaster.pid').exists(), 'checkpoint_not_clean')
            control(S / 'pg-checkpoint', pgimage)
            save('final-copy-completed.json', {'copy': copied, 'pg_stopped_seconds_before_restart': time.monotonic() - stopped})
            success = True
        finally:
            try:
                restore_original_pg(b)
            except Exception:
                save('original-pg-recovery-required.json', {'manual_reconciliation_required': True, 'no_database_restore_attempted': True})
                raise
        need(success, 'checkpoint_copy_incomplete')
        rows, total = scan_tree(S / 'pg-checkpoint', True)
        new(S / 'pg-file-manifest.jsonl', b''.join((enc(r) + b'\n' for r in rows)))
        save('checkpoint-completed.json', {'pins': pins, 'schema': 15, 'system_identifier': SYSID, 'archive': ARCHIVE, 'store_id': pins['store_id'], 'archive_manifest': manifest, 'capture_manifest': capture_manifest, 'pg_files_sha256': sha(raw(S / 'pg-file-manifest.jsonl', MAX_MANIFEST)), 'pg_files': sum((r['kind'] == 'file' for r in rows)), 'pg_bytes': total, 'old_pg_pod': b['old_pg_pod'], 'new_pg_pod': load('original-pg-resumed.json')['new_pg_pod'], 'postgres_deployment_sha256': controller_deployment_hash(b['postgres_deployment']), 'postgres_full_deployment_sha256': sha(enc(b['postgres_deployment'])), 'original_pg_restarted_without_restore': True, 'roles_stopped': True, 'independent_s3_backup': False, 'completed_at': now()})
    return {'physical_checkpoint_created': True, 'original_pg_restarted_without_restore': True, 'old_reader_rehearsal_required': True, 'independent_s3_backup': False}

def replace_scalar(text,section,key,value):
    """Recognize headers only as whole lines; inline arrays are ordinary values."""
    lines=text.splitlines(keepends=True)
    current=None
    count=0
    result=[]
    for line in lines:
        header=re.fullmatch(r'[ \t]*\[([A-Za-z0-9_.-]+)\][ \t]*(?:#[^\r\n]*)?(?:\r?\n)?',line)
        if header:current=header[1]
        match=re.fullmatch(r'([ \t]*'+re.escape(key)+r'[ \t]*=[ \t]*)([^\r\n]*)(\r?\n)?',line)
        if current==section and match:
            count+=1
            line=match[1]+json.dumps(value)+(match[3] or '')
        result.append(line)
    need(count==1,'single_clone_config_scalar_required')
    return ''.join(result)

def reader_config(original):
    before = tomllib.loads(original)
    text = original
    expected = copy.deepcopy(before)
    need(before['storage']['backend'] == 's3' and before['storage']['s3']['credentials']['mode'] == 'files' and (before['storage']['s3']['prefix'] == 'production') and before['source']['url'].endswith('/0.1.0-build.65236494/source.tar.gz'), 'old_static_reader_config_required')
    need(type(before.get('wikipedia', {}).get('enabled')) is bool and 'writer_listener' not in before and (before['storage']['blob_dir'] == '/data/cache'), 'old_reader_only_config_required')
    for provider in PROVIDERS:
        text = replace_scalar(text, provider, 'enabled', False)
        expected[provider]['enabled'] = False
    text = replace_scalar(text, 'npm', 'advisories_enabled', False)
    expected['npm']['advisories_enabled'] = False
    text = replace_scalar(text, 'storage.s3', 'cache_max_bytes', 64 * 1024 ** 2)
    expected['storage']['s3']['cache_max_bytes'] = 64 * 1024 ** 2
    text = replace_scalar(text, 'writer_client', 'endpoint', 'https://127.0.0.1:9/v1/acquire')
    expected['writer_client']['endpoint'] = 'https://127.0.0.1:9/v1/acquire'
    need(tomllib.loads(text) == expected, 'unexpected_clone_configuration_change')
    need(__import__('urllib.parse', fromlist=['urlsplit']).urlsplit(before['storage']['database_url']).username == 'devres_reader', 'clone_requires_actual_reader_role')
    return text

def choose_subnet(routes, networks):
    used = []
    for r in routes:
        dst = r.get('dst', 'default')
        if dst != 'default':
            used.append(ipaddress.ip_network(dst, strict=False))
    for n in networks:
        need(isinstance(n, dict) and isinstance(n.get('IPAM', {}), dict), 'network_ipam_object_required')
        config = n.get('IPAM', {}).get('Config')
        if config is None:
            config = []
        need(isinstance(config, list) and all(isinstance(v, dict) for v in config), 'network_ipam_config_list_required')
        used.extend(ipaddress.ip_network(v['Subnet'], strict=False) for v in config if v.get('Subnet'))
    for cidr in ('172.30.253.0/24', '172.30.252.0/24', '10.229.252.0/24'):
        net = ipaddress.ip_network(cidr)
        if all((u.version != net.version or not net.overlaps(u) for u in used)):
            return cidr
    raise Stop('no_nonoverlapping_private_clone_subnet')

def owned_container(identifier, token):
    row = decode(run(['docker', 'inspect', identifier]))[0]
    need(row['Id'] == identifier and row['Config'].get('Labels', {}).get(LABEL) == token, 'foreign_clone_container')
    return row

def cleanup_clone(containers, network, token):
    for identifier in reversed(containers):
        row = owned_container(identifier, token)
        if row['State']['Running']:
            run(['docker', 'stop', '--time', '15', identifier], 30)
        need(not owned_container(identifier, token)['State']['Running'], 'clone_did_not_stop')
        run(['docker', 'rm', identifier])
    if network:
        row = decode(run(['docker', 'network', 'inspect', network]))[0]
        need(row['Name'] == network and row.get('Labels') == {LABEL: token} and (row.get('Containers') == {}), 'foreign_or_nonempty_clone_network')
        run(['docker', 'network', 'rm', row['Id']])

def rpc(ip, method, params, number, tls):
    revision = '2026-07-28'
    params = copy.deepcopy(params)
    params['_meta'] = {'io.modelcontextprotocol/protocolVersion': revision, 'io.modelcontextprotocol/clientInfo': {'name': 'devres-old-ro-checkpoint', 'version': '1'}, 'io.modelcontextprotocol/clientCapabilities': {}}
    body = enc({'jsonrpc': '2.0', 'id': number, 'method': method, 'params': params})
    headers = {'Host': 'devres-k8s:30081', 'Origin': 'https://dev-resources.mcp.publicdata.stream', 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': revision, 'Mcp-Method': method, 'Mcp-Name': params.get('name', params.get('uri', '')), 'Content-Length': str(len(body)), 'Connection': 'close'}
    ctx = ssl.create_default_context(cafile=str(tls / 'backend-ca.crt'))
    ctx.load_cert_chain(str(tls / 'edge-client.crt'), str(tls / 'edge-client.key'))
    with socket.create_connection((ip, 8080), timeout=15) as sock:
        with ctx.wrap_socket(sock, server_hostname='devres-k8s') as conn:
            conn.settimeout(30)
            conn.sendall(('POST /mcp HTTP/1.1\r\n' + ''.join((k + ': ' + v + '\r\n' for k, v in headers.items())) + '\r\n').encode() + body)
            answer = http.client.HTTPResponse(conn)
            answer.begin()
            need(answer.status == 200, 'clone_rpc_status')
            if answer.getheader('content-type', '').startswith('text/event-stream'):
                remaining = 2 * 1024 ** 2
                value = None
                while remaining > 0:
                    line = answer.readline(remaining + 1)
                    remaining -= len(line)
                    need(remaining >= 0, 'clone_rpc_bound')
                    if not line:
                        break
                    if line.startswith(b'data:'):
                        candidate = decode(line[5:].strip())
                        if candidate.get('id') == number:
                            value = candidate
                            break
                need(value is not None, 'clone_rpc_sse_result_required')
            else:
                raw_body = answer.read(2 * 1024 ** 2 + 1)
                need(len(raw_body) <= 2 * 1024 ** 2, 'clone_rpc_bound')
                value = decode(raw_body)
    need(value.get('id') == number and 'error' not in value, 'clone_rpc_failed')
    return value['result']

def proof(pins):
    c = load('checkpoint-completed.json')
    need(c['pins'] == pins and (not (S / 'proof-intent.json').exists()), 'one_owned_clone_rehearsal_only')
    b = load('baseline.json')
    m, o = source_guard()
    with m.bundle_lock(B), m.bundle_lock(B, '.certificate.lock'):
        # Recheck after acquiring both locks; the admission read before lock acquisition
        # cannot authorize an operation if a timer changed its boundary meanwhile.
        source_guard()
        stable_foundation(b)
        roles_stopped()
        current = schema_identity()
        checked_identity(current, True)
        need(current['archive']['store_id'] == pins['store_id'], 'original_store_id_changed')
        need(pod_projection(role_pods('postgres')[0]) == load('original-pg-resumed.json')['new_pg_pod'], 'resumed_pg_process_changed_before_proof')
        rows, total = scan_tree(S / 'pg-checkpoint', True)
        need(sha(b''.join((enc(r) + b'\n' for r in rows))) == c['pg_files_sha256'], 'physical_checkpoint_changed')
        need(shutil.disk_usage(N).free >= total + RESERVE, 'clone_headroom_required')
        (S / 'pg-clone').mkdir(mode=448)
        copy_tree(S / 'pg-checkpoint', S / 'pg-clone')
        pgimage = image_id(PG)
        oldimage = image_id(OLD, OLD_REV)
        need(pgimage == b['qualified_local_images']['pg'] and oldimage == b['qualified_local_images']['old_server'], 'qualified_clone_images_changed')
        token = load('owner.json')['token']
        private = S / 'private'
        clone = S / 'rehearsal'
        clone.mkdir(mode=448)
        files = clone / 'files'
        files.mkdir(mode=448)
        cfg = reader_config(raw(private / 'serving.toml').decode())
        new(files / 'serving.toml', cfg.encode(), 65532, 256)
        tls_mapping = {'backend.pem': 'backend.crt', 'backend-key.pem': 'backend.key', 'client-ca.pem': 'edge-client-ca.crt'}
        for name, source in tls_mapping.items():
            new(files / name, raw(private / 'tls' / source), 65532, 256)
        for name in ('access-key', 'secret-key'):
            new(files / name, raw(private / name), 65532, 256)
        new(files / 'writer-ca.crt', raw(private / 'tls/coordination-ca.crt'), 65532, 256)
        new(files / 'no-authority-token', b'checkpoint-has-no-writer-authority', 65532, 256)
        cache = clone / 'cache'
        cache.mkdir(mode=448)
        os.chown(cache, 65532, 65532)
        allnetids = run(['docker', 'network', 'ls', '-q']).decode().split()
        networks = decode(run(['docker', 'network', 'inspect', *allnetids])) if allnetids else []
        subnet = choose_subnet(decode(run(['ip', '-j', 'route', 'show', 'table', 'all'])), networks)
        name = 'devres-checkpoint-' + token
        containers = []
        network = None
        save('proof-intent.json', {'token': token, 'maximum_rehearsals': 1, 'old_server_image_id': oldimage, 'pg_image_id': pgimage, 'separate_copy': str(S / 'pg-clone'), 'no_production_mount': True, 'reader_only': True, 'observed_at': now()})
        success = False
        result = None
        creation_uncertain = False
        try:
            save('clone-network-create-intent.json', {'name': name, 'token': token})
            creation_uncertain = True
            network = name
            run(['docker', 'network', 'create', '--driver', 'bridge', '--subnet', subnet, '--label', LABEL + '=' + token, name])
            creation_uncertain = False
            common = ['docker', 'run', '--detach', '--pull', 'never', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--security-opt', 'apparmor=devres-runtime', '--label', LABEL + '=' + token, '--network', name]
            args = [*common, '--name', name + '-postgres', '--network-alias', 'postgres', '--user', '70:70', '--tmpfs', '/tmp:rw,nosuid,nodev,mode=1777', '--tmpfs', '/var/run/postgresql:rw,nosuid,nodev,uid=70,gid=70,mode=0777', '--mount', 'type=bind,src=' + str(S / 'pg-clone') + ',dst=' + b['layout']['container_data_directory'], pgimage, 'postgres', '-D', b['layout']['container_data_directory'], '-c', 'archive_mode=off', '-c', 'archive_command=', '-c', 'restore_command=', '-c', 'primary_conninfo=', '-c', 'ssl=off', '-c', 'listen_addresses=*']
            save('clone-postgres-create-intent.json', {'name': name + '-postgres', 'token': token})
            creation_uncertain = True
            pgid = run(args).decode().strip()
            need(re.fullmatch('[0-9a-f]{64}', pgid), 'clone_container_id_required')
            containers.append(pgid)
            creation_uncertain = False
            deadline = time.monotonic() + 180
            while True:
                row = owned_container(pgid, token)
                need(row['State']['Running'], 'clone_postgres_exited')
                r = subprocess.run(['docker', 'exec', pgid, 'pg_isready', '-h', '127.0.0.1', '-U', 'devres_reader', '-d', 'devres'], capture_output=True, timeout=10)
                if r.returncode == 0:
                    break
                need(time.monotonic() < deadline, 'clone_postgres_deadline')
                time.sleep(1)
            query = "SELECT json_build_object('system_id',(SELECT system_identifier::text FROM pg_control_system()),'schema',(SELECT version FROM devres_schema WHERE singleton),'wikipedia_tables',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_wikipedia_evidence')),(to_regclass('public.devres_wikipedia_state'))) t(oid) WHERE oid IS NOT NULL),'schema15_objects',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_crate_enrichment_v2')),(to_regclass('public.devres_crate_enrichment_heads_v2')),(to_regclass('public.devres_crate_dump_failures')),(to_regclass('public.devres_crate_enrichment_all'))) t(oid) WHERE oid IS NOT NULL),'store_id',(SELECT store_id FROM devres_archive_control WHERE singleton),'reader_default_readonly',(SELECT rolconfig @> ARRAY['default_transaction_read_only=on'] FROM pg_roles WHERE rolname='devres_reader'),'reader_writer_memberships',(SELECT count(*) FROM pg_auth_members WHERE member='devres_reader'::regrole),'tables_without_reader_select',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','p','v','m') AND NOT has_table_privilege('devres_reader',c.oid,'SELECT')),'reader_mutation_tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','p','v','m') AND has_table_privilege('devres_reader',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))"
            clone_sql = decode(run(['docker', 'exec', pgid, 'env', 'PGOPTIONS=-c default_transaction_read_only=on', 'psql', '-X', '-q', '-U', 'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c', query]))
            need(clone_sql == {'system_id': SYSID, 'schema': 15, 'wikipedia_tables': 2, 'schema15_objects': 4, 'store_id': pins['store_id'], 'reader_default_readonly': True, 'reader_writer_memberships': 0, 'tables_without_reader_select': 0, 'reader_mutation_tables': 0}, 'clone_original_sql_authority_not_preserved')
            args = [*common, '--name', name + '-reader', '--user', '65532:65532', '--tmpfs', '/tmp:rw,nosuid,nodev,uid=65532,gid=65532,mode=1777', '--mount', 'type=bind,src=' + str(cache) + ',dst=/data/cache']
            mounts = {'serving.toml': '/etc/devres/config/serving.toml', 'backend.pem': '/etc/devres/tls/backend.pem', 'backend-key.pem': '/etc/devres/tls/backend-key.pem', 'client-ca.pem': '/etc/devres/tls/client-ca.pem', 'access-key': '/run/devres-s3/access-key', 'secret-key': '/run/devres-s3/secret-key', 'writer-ca.crt': '/run/devres-writer-tls/ca.crt', 'no-authority-token': '/run/devres-writer-identity/token'}
            for src, dst in mounts.items():
                args += ['--mount', 'type=bind,src=' + str(files / src) + ',dst=' + dst + ',readonly']
            args += reader_command(oldimage)
            save('clone-reader-create-intent.json', {'name': name + '-reader', 'token': token})
            creation_uncertain = True
            reader = run(args).decode().strip()
            need(re.fullmatch('[0-9a-f]{64}', reader), 'clone_reader_id_required')
            containers.append(reader)
            creation_uncertain = False
            deadline = time.monotonic() + 120
            while True:
                row = owned_container(reader, token)
                need(row['State']['Running'], 'old_clone_reader_exited')
                need(all((P(v['Source']).is_relative_to(S) for v in row['Mounts'] if v['Type'] == 'bind')) and (not row['HostConfig'].get('PortBindings')), 'clone_production_mount_or_public_port')
                ip = row['NetworkSettings']['Networks'][name]['IPAddress']
                need(ipaddress.ip_address(ip) in ipaddress.ip_network(subnet), 'clone_private_ip_required')
                try:
                    with socket.create_connection((ip, 9090), timeout=2) as sock:
                        sock.sendall(b'GET /ready HTTP/1.1\r\nHost: checkpoint\r\nConnection: close\r\n\r\n')
                        answer = http.client.HTTPResponse(sock)
                        answer.begin()
                        ready = answer.status == 200
                except OSError:
                    ready = False
                if ready:
                    break
                need(time.monotonic() < deadline, 'old_clone_reader_deadline')
                time.sleep(1)
            call = rpc(ip, 'tools/call', {'name': 'rfc.format_get', 'arguments': {'number': 9000, 'format': 'txt', 'capture': CID, 'offset': 0, 'limit': 1024}}, 1, private / 'tls')
            need(call.get('isError') is False, 'old_clone_pinned_content_failed')
            v = call['structuredContent']
            a = v['attribution']
            need(v['capture']['id'] == CID and v['capture']['body_hash'] == BODY and (a['status'] == 'ready') and (a['policy_epoch'] == 1) and (len(a['generations']) == 1) and (a['generations'][0]['id'] == GENERATION) and (sha(a['readable_notice'].encode()) == NOTICE), 'old_clone_exact_capture_or_notice_changed')
            need(sha(v['page']['text'].encode()) == '6026989d1430343743b2c712d7cea16e0fd7a600110623a7a2f9e9cc6944d190', 'old_clone_exact_first_page_changed')
            notice = rpc(ip, 'resources/read', {'uri': a['resource_uri']}, 2, private / 'tls')
            parts = notice['contents']
            need(len(parts) == 1 and parts[0]['text'] == a['readable_notice'] and (parts[0]['_meta']['next_offset'] is None) and (parts[0]['_meta']['attribution']['id'] == GENERATION), 'old_clone_immutable_notice_roundtrip')
            result = {'clone_sql': clone_sql, 'old_reader_image_id': oldimage, 'pg_image_id': pgimage, 'capture': CID, 'body_hash': BODY, 'first_page_sha256': sha(v['page']['text'].encode()), 'notice_generation': GENERATION, 'notice_sha256': NOTICE, 'notice_bytes': len(a['readable_notice'].encode()), 'reader_only': True, 'writer_client_loopback_without_authority': True, 'no_production_mount': True, 'all_collectors_disabled': True, 'provider_source_requests': 0, 'isolated_clone_only': True}
            save('clone-proof-result.json', result)
            success = True
        finally:
            try:
                cleanup_clone(containers, network, token)
                need(not creation_uncertain, 'clone_creation_outcome_unknown_manual_reconciliation')
                save('clone-cleanup-completed.json', {'all_owned_containers_removed': True, 'owned_network_removed': True, 'physical_checkpoint_retained': True})
            except Exception:
                save('clone-cleanup-required.json', {'manual_reconciliation_required': True, 'remaining_owned_scope': token})
                raise
        need(success, 'old_clone_rehearsal_incomplete')
        stable_foundation(b)
        roles_stopped()
        need(pod_projection(role_pods('postgres')[0]) == load('original-pg-resumed.json')['new_pg_pod'], 'production_pg_drift_during_rehearsal')
        final = schema_identity()
        checked_identity(final, True)
        need(final['archive'] == b['identity']['archive'], 'production_archive_changed_during_rehearsal')
        need(source_layout(stable_foundation(b), final) == b['layout'], 'production_pv_changed_during_rehearsal')
        save('completed.json', {'version': 1, 'kind': 'physical-pg-retained-immutable-s3-upgrade-checkpoint', 'revision': REV, 'pins': pins, 'schema': 15, 'system_identifier': SYSID, 'archive': ARCHIVE, 'store_id': pins['store_id'], 'store_binding_sha256': BIND, 'old_pg_pod': b['old_pg_pod'], 'new_pg_pod': load('original-pg-resumed.json')['new_pg_pod'], 'postgres_deployment_sha256': controller_deployment_hash(b['postgres_deployment']), 'postgres_full_deployment_sha256': sha(enc(b['postgres_deployment'])), 'checkpoint_receipt_sha256': sha(raw(S / 'checkpoint-completed.json')), 'manifest_sha256': c['archive_manifest']['sha256'], 'capture_manifest_sha256': c['capture_manifest']['sha256'], 'pg_files_sha256': c['pg_files_sha256'], 'clone_proof_sha256': sha(raw(S / 'clone-proof-result.json')), 'production_pg_restarted_without_restore': True, 'roles_stopped': True, 'old_clone_verified': True, 'credentials_preserved': True, 'independent_s3_backup': False, 'all_remote_hashes_rechecked': False, 'original_s3_retained': True, 'no_automatic_production_restore': True, 'completed_at': now()})
    write_backup_receipt()
    return {'coordinated_upgrade_rollback_checkpoint': True, 'old_readonly_clone_verified': True, 'independent_s3_backup': False, 'completed_receipt_sha256': sha(raw(S / 'completed.json')), 'private_data_export_allowed': False}

def write_backup_receipt():
    completed = load('completed.json')
    checkpoint = load('checkpoint-completed.json')
    need(completed['revision'] == REV and completed['schema'] == 15
         and completed['old_clone_verified'] is True and completed['roles_stopped'] is True
         and completed['credentials_preserved'] is True
         and completed['original_s3_retained'] is True
         and completed['independent_s3_backup'] is False, 'completed_backup_identity')
    need(completed['checkpoint_receipt_sha256'] == sha(raw(S / 'checkpoint-completed.json'))
         and completed['clone_proof_sha256'] == sha(raw(S / 'clone-proof-result.json'))
         and completed['pg_files_sha256'] == sha(raw(S / 'pg-file-manifest.jsonl', MAX_MANIFEST)), 'completed_backup_artifact_changed')
    need(checkpoint['archive_manifest']['sha256'] == completed['manifest_sha256']
         and checkpoint['capture_manifest']['sha256'] == completed['capture_manifest_sha256'], 'completed_manifest_receipt_changed')
    names = ('completed.json', 'checkpoint-completed.json', 'clone-proof-result.json',
             'clone-cleanup-completed.json', 'original-pg-resumed.json',
             'clean-pg-control.json', 'archive-manifest-receipt.json',
             'capture-manifest-receipt.json', 'pg-file-manifest.jsonl',
             'archive-bindings.jsonl', 'capture-bindings.jsonl')
    artifacts = []
    for name in names:
        path = S / name
        body = raw(path, MAX_MANIFEST)
        artifacts.append({'path': str(path), 'sha256': sha(body)})
    need(next(a['sha256'] for a in artifacts if a['path'].endswith('/archive-bindings.jsonl')) == completed['manifest_sha256']
         and next(a['sha256'] for a in artifacts if a['path'].endswith('/capture-bindings.jsonl')) == completed['capture_manifest_sha256'], 'completed_manifest_bytes_changed')
    receipt = {'version': 1, 'kind': 'coordinated-schema15-backup', 'revision': REV,
               'prepared_sha256': completed['pins']['controller_prepared_sha256'],
               'store_binding_sha256': BIND, 'verified': True, 'observed_at': now(),
               'schema': 15, 'system_identifier': SYSID,
               'recovery_scope': 'physical_pg_checkpoint_original_immutable_s3_retained',
               'independent_s3_backup': False,
               'old_pg_pod': completed['old_pg_pod'], 'new_pg_pod': completed['new_pg_pod'],
               'postgres_deployment_sha256': completed['postgres_deployment_sha256'],
               'checks': {'coordinated_pg_s3': True, 'old_clone_verified': True,
                          'roles_stopped': True, 'pg_restarted_without_restore': True,
                          'credentials_preserved': True}, 'artifacts': artifacts}
    save('backup-receipt.json', receipt)
    return receipt

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('prepare', 'run', 'proof'))
    a = p.parse_args()
    pins = authorize()
    if S.exists():
        private_dir(S)
    lock = os.open(N / '.checkpoint.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 384)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = {'prepare': prepare, 'run': checkpoint, 'proof': proof}[a.operation](pins)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(lock)
if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'failed': 'checkpoint_or_rehearsal_stopped', 'no_automatic_production_restore': True, 'inspect_private_owned_journal': True}))
        sys.exit(1)
