#!/usr/bin/env python3
"""One root-only physical PG rollback checkpoint; original immutable S3 is retained.
This helper creates a schema18 recovery checkpoint; restoration uses its separately reviewed successor.
"""
import argparse, base64, contextlib, copy, datetime, fcntl, hashlib, http.client, importlib.util, ipaddress, json, os, pathlib, re, shutil, socket, ssl, stat, subprocess, sys, time, tomllib
P = pathlib.Path
N = P('/tmp/devres-upgrade-1d76fbcc-20261115')
S = N / 'checkpoint-state'
PUBLIC = N / 'public-upgrade-identity.json'
APPROVAL = N / 'checkpoint-approval.json'
CLAIM = N / 'source-store-claim-qualified.json'
UPGRADE = P('/var/lib/devres-production-upgrades/1d76fbcc-20261115')
PREPARED = UPGRADE / 'prepared.json'
B = P('/var/lib/devres-production-preparation/a938112b-7c7a24f')
OP = P('/usr/local/libexec/devres-production-candidate-a938112b-apparmor-v1/scripts/production-operator.py')
OP_SHA = '58501767e3d130af1a05e1f6493f89ee8f287e1582f0f35fa2b1e74c23f5e3da'
CHECKPOINT_VOLUME = UPGRADE / 'checkpoint-volume'
POLICY = {'format_version': 1, 'required_policy_epoch': 2,
          'required_policy_fingerprint': 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'}
REV = '1d76fbcc5693efc9ca927fd05f942078f667f056'
OLD_REV = '91c7bcb7aed8eede1627bf87254c0567ef48ab7b'
OLD = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:1b1bf21d339920e8ddd69449d82c9895c3423509e8016a72b2df46a38d8e7b6c'
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
CONTROLLER = P('/usr/local/libexec/devres-upgrade-1d76fbcc/upgrade-controller.py')
CACHE_ROOTS = {'serving': P('/var/cache/devres/serving'), 'writer': P('/var/cache/devres/writer')}
MAX_CACHE_BYTES = 256 * 1024**3

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
    return decode(raw(S / name, MAX_MANIFEST if name == 'cache-baselines.json' else MAX_COMMAND))

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

def disk_identity():
    """A dedicated durable bind mount, never the host's /tmp tmpfs."""
    private_dir(S)
    need(CHECKPOINT_VOLUME.is_absolute() and not CHECKPOINT_VOLUME.is_relative_to(P('/tmp')),
         'durable_checkpoint_volume_required')
    for path in (CHECKPOINT_VOLUME, *CHECKPOINT_VOLUME.parents):
        need(not path.is_symlink(), 'checkpoint_volume_symlink_refused')
    info = CHECKPOINT_VOLUME.stat()
    mounted = S.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077
         and (info.st_dev, info.st_ino) == (mounted.st_dev, mounted.st_ino),
         'checkpoint_bind_mount_identity_required')
    entries = decode(run(['findmnt', '--json', '--target', str(S), '--output',
                          'TARGET,SOURCE,FSTYPE,OPTIONS,ID']))['filesystems']
    need(len(entries) == 1 and entries[0]['target'] == str(S)
         and entries[0]['fstype'] not in ('tmpfs', 'ramfs', 'rootfs', 'overlay')
         and 'rw' in entries[0]['options'].split(','), 'disk_backed_checkpoint_mount_required')
    return {'device': info.st_dev, 'inode': info.st_ino, 'mount': entries[0]}

def attribution_query():
    """Only fixed sealed control and explicitly selected exact identities."""
    targets = decode(raw(PUBLIC))['attribution_target_ids']
    need(isinstance(targets, list) and 1 <= len(targets) <= 16 and len(set(targets)) == len(targets)
         and all(isinstance(v, str) and re.fullmatch(r'(?:blake3:)?[0-9a-f]{64}', v) for v in targets),
         'bounded_exact_attribution_targets_required')
    values = ','.join("'" + target + "'" for target in targets) or 'NULL'
    generations = "SELECT data->>'generation' FROM devres_attribution_targets WHERE id IN (" + values + ')'
    return ("json_build_object('control',(SELECT row_to_json(c) FROM devres_attribution_control c WHERE singleton),"
            "'origin_table',(to_regclass('public.devres_attribution_origins') IS NOT NULL),"
            "'targets',(SELECT COALESCE(json_agg(row_to_json(t) ORDER BY id),'[]'::json) "
            "FROM devres_attribution_targets t WHERE id IN (" + values + ")),"
            "'generations',(SELECT COALESCE(json_agg(row_to_json(g) ORDER BY id),'[]'::json) "
            "FROM devres_attribution_generations g WHERE id IN (" + generations + ") "
            "OR id IN ('" + GENERATION + "','" + GENERATION.removeprefix('blake3:') + "')))")

def checked_attribution(value):
    need(value['origin_table'] is True and value['control']['data'] == POLICY,
         'current_schema18_policy2_required')
    seal = value['control']['data_integrity']
    need(isinstance(seal, str) and re.fullmatch(r'(?:blake3:)?[0-9a-f]{64}', seal),
         'sealed_attribution_control_required')
    targets = decode(raw(PUBLIC))['attribution_target_ids']
    need(sorted(row['id'] for row in value['targets']) == sorted(targets),
         'selected_attribution_targets_missing')
    need(any(row['id'].removeprefix('blake3:') == GENERATION.removeprefix('blake3:')
             for row in value['generations']), 'historical_generation_missing')
    need(any(row['data'].get('policy_epoch') == 2 for row in value['generations']),
         'selected_current_policy_generation_missing')

def cold_body_readback(ip, control, tls, attribution):
    """One capture-fixed positive original-byte control through the cold RO reader."""
    need(set(control) == {'kind', 'capture', 'body_hash', 'format', 'offset', 'limit',
                          'expected_bytes', 'sha256'}
         and control['kind'] == 'rfc-format-page'
         and control['format'] == 'txt' and control['capture'] == CID and control['body_hash'] == BODY
         and all(isinstance(control[k], str) and re.fullmatch(r'blake3:[0-9a-f]{64}', control[k])
                 for k in ('capture', 'body_hash'))
         and type(control['offset']) is int and control['offset'] == 0
         and type(control['limit']) is int and control['limit'] == 1024
         and type(control['expected_bytes']) is int and control['expected_bytes'] == 1024
         and isinstance(control['sha256'], str) and re.fullmatch('[0-9a-f]{64}', control['sha256']),
         'fixed_cold_read_control_required')
    arguments = {'number': 9000, 'format': control['format'], 'capture': control['capture'],
                 'offset': control['offset'], 'limit': control['limit']}
    answer = rpc(ip, 'tools/call', {'name': 'rfc.format_get', 'arguments': arguments}, 100, tls)
    need(answer.get('isError') is False, 'cold_capture_read_failed')
    value = answer['structuredContent']
    need(value['capture']['id'] == control['capture'] and value['capture']['body_hash'] == control['body_hash']
         and value['format'] == control['format'] and value['page']['offset'] == control['offset'],
         'cold_capture_identity_changed')
    body = value['page']['text'].encode()
    need(len(body) == control['expected_bytes'] and sha(body) == control['sha256'],
         'cold_capture_original_bytes_changed')
    qualified = value['attribution']
    need(qualified['status'] == 'ready' and qualified['policy_epoch'] == 2
         and qualified['policy_fingerprint'] == POLICY['required_policy_fingerprint']
         and len(qualified['generations']) == 1, 'cold_capture_current_policy_not_ready')
    generation = qualified['generations'][0]['id']
    need(any(row['id'].removeprefix('blake3:') == generation.removeprefix('blake3:')
             and row['data'].get('policy_epoch') == 2
             for row in attribution['generations']), 'cold_capture_generation_changed')
    notice = qualified['readable_notice'].encode()
    need(0 < len(notice) <= 65536, 'cold_capture_notice_bound')
    current_notice = notice_readback(ip, generation, sha(notice), tls)
    return {'capture': control['capture'], 'body_hash': control['body_hash'],
            'format': control['format'], 'offset': control['offset'], 'bytes': len(body),
            'sha256': control['sha256'], 'empty_disposable_cache': True,
            'current_notice': current_notice,
            'whole_archive_verified': False}

def notice_readback(ip, generation, expected_sha256, tls):
    """Reassemble immutable UTF-8 notice pages without asserting current rights."""
    uri = 'devres://attribution/' + generation
    offset = 0
    text = bytearray()
    total_bytes = None
    for number in range(1, 66):
        value = rpc(ip, 'resources/read', {'uri': uri + '?offset=' + str(offset) + '&limit=1024'},
                    number, tls)
        parts = value['contents']
        need(len(parts) == 1, 'one_historical_notice_page_required')
        part = parts[0]
        meta = part['_meta']
        body = part['text'].encode()
        if total_bytes is None:
            total_bytes = meta['total_bytes']
        need(meta['offset'] == offset and meta['attribution']['id'] == generation
             and type(meta['total_bytes']) is int and 0 < meta['total_bytes'] <= 65536
             and meta['total_bytes'] == total_bytes
             and 0 < len(body) <= 1024, 'historical_notice_page_identity')
        text.extend(body)
        next_offset = meta['next_offset']
        if next_offset is None:
            need(len(text) == meta['total_bytes'] and sha(bytes(text)) == expected_sha256,
                 'historical_notice_bytes_changed')
            return {'generation': generation, 'sha256': expected_sha256,
                    'bytes': len(text), 'pages': number}
        need(type(next_offset) is int and next_offset == offset + len(body)
             and next_offset < meta['total_bytes'], 'historical_notice_pagination_changed')
        offset = next_offset
    raise Stop('historical_notice_page_bound')

def schema_identity():
    query = "SELECT json_build_object('system_id',(SELECT system_identifier::text FROM pg_control_system()),'schema',(SELECT version FROM devres_schema WHERE singleton),'data_directory',current_setting('data_directory'),'recovery',pg_is_in_recovery(),'external_tablespaces',(SELECT count(*) FROM pg_tablespace WHERE pg_tablespace_location(oid)<>''),'wikipedia_tables',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_wikipedia_evidence')),(to_regclass('public.devres_wikipedia_state'))) t(oid) WHERE oid IS NOT NULL),'schema18_objects',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_crate_enrichment_v2')),(to_regclass('public.devres_crate_enrichment_heads_v2')),(to_regclass('public.devres_crate_dump_failures')),(to_regclass('public.devres_crate_enrichment_all'))) t(oid) WHERE oid IS NOT NULL),'archive',(SELECT json_build_object('backend',backend,'binding',binding,'epoch',epoch,'pending_binding',pending_binding,'initializing_s3',initializing_s3,'store_id',store_id) FROM devres_archive_control WHERE singleton),'publication_owners',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())),'attribution'," + attribution_query() + ')'
    return pgsql(query)

def checked_identity(v, stopped=False):
    checked_attribution(v['attribution'])
    need(v['wikipedia_tables'] == 2 and v['schema18_objects'] == 4, 'schema18_object_set_required')
    need(v['system_id'] == SYSID and v['schema'] == 18 and (v['recovery'] is False) and (v['external_tablespaces'] == 0), 'schema18_primary_identity_required')
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
        dirs.sort()
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

def cache_manifest(root):
    """Complete cache/workspace contents, including internal links and hardlinks."""
    need(root.is_dir() and not root.is_symlink(), 'cache_directory_required')
    mounts = decode(run(['findmnt', '--json', '--submounts', '--target', str(root), '--output', 'TARGET']))
    def walk_mounts(entries):
        for entry in entries:
            yield P(entry['target'])
            yield from walk_mounts(entry.get('children', []))
    need(not any(path != root and path.is_relative_to(root) for path in walk_mounts(mounts.get('filesystems', []))),
         'cache_nested_mount_refused')
    device = root.stat().st_dev
    rows, links, total = [], {}, 0
    started = time.monotonic()
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(dirs + files):
            path = P(folder) / name
            info = path.lstat()
            need(info.st_dev == device, 'cache_nested_mount_refused')
            relative = path.relative_to(root).as_posix()
            row = {'path': relative, 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                need(not P(target).is_absolute() and path.resolve().is_relative_to(root.resolve()), 'external_cache_symlink_refused')
                row.update(kind='symlink', target=target)
            elif stat.S_ISDIR(info.st_mode):
                row['kind'] = 'directory'
            else:
                need(stat.S_ISREG(info.st_mode), 'cache_special_file_refused')
                identity = (info.st_dev, info.st_ino)
                previous = links.get(identity)
                if previous:
                    row.update(kind='hardlink', target=previous[0])
                    previous[1] += 1
                else:
                    with path.open('rb') as f:
                        digest = hashlib.file_digest(f, 'sha256').hexdigest()
                        after = os.fstat(f.fileno())
                    need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                         == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                         'cache_file_changed')
                    row.update(kind='file', bytes=info.st_size, sha256=digest)
                    links[identity] = [relative, 1, info.st_nlink]
                    total += info.st_size
            rows.append(row)
            need(len(rows) <= MAX_FILES and total <= MAX_CACHE_BYTES and time.monotonic() - started < 1800,
                 'cache_inventory_bound')
    need(all(count == expected for _, count, expected in links.values()), 'external_cache_hardlink_refused')
    rows.sort(key=lambda r: r['path'])
    return {'sha256': sha(b''.join(enc(row) + b'\n' for row in rows)), 'bytes': total, 'rows': rows,
            'root_mode': stat.S_IMODE(root.stat().st_mode), 'root_uid': root.stat().st_uid, 'root_gid': root.stat().st_gid}

def copy_cache(source, destination, expected):
    need(source.resolve() != destination.resolve() and not destination.is_symlink(), 'distinct_cache_copy_required')
    need(destination.is_dir(), 'owned_cache_destination_required')
    result = subprocess.run(['/usr/bin/rsync', '-aHAX', '--checksum', '--numeric-ids', '--one-file-system',
                             '--no-devices', '--no-specials', '--delete', '--', str(source) + '/', str(destination) + '/'],
                            capture_output=True, timeout=1800)
    need(result.returncode == 0 and len(result.stderr) + len(result.stdout) <= MAX_COMMAND, 'cache_copy_failed')
    actual = cache_manifest(destination)
    need(actual == expected, 'copied_cache_manifest_changed')
    for row in actual['rows']:
        if row['kind'] == 'file':
            fd = os.open(destination / row['path'], os.O_RDONLY | os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
    for row in sorted((r for r in actual['rows'] if r['kind'] == 'directory'), key=lambda r: len(P(r['path']).parts), reverse=True):
        sync(destination / row['path'])
    sync(destination); sync(destination.parent)
    need(tree_inode(source) != tree_inode(destination), 'cache_copy_must_have_distinct_inode')

def tree_inode(path):
    info = path.stat()
    return {'device': info.st_dev, 'inode': info.st_ino}

def cache_layouts():
    result = {}
    for role, root in CACHE_ROOTS.items():
        deployment = get('deployment', 'backend' if role == 'serving' else role)
        spec = deployment['spec']['template']['spec']
        mounts = [m for m in spec['containers'][0]['volumeMounts'] if m['mountPath'] == '/data/cache']
        need(len(mounts) == 1 and not mounts[0].get('subPath') and not mounts[0].get('subPathExpr'), 'exact_cache_mount_required')
        volume = next(v for v in spec['volumes'] if v['name'] == mounts[0]['name'])
        pvc = get('pvc', volume['persistentVolumeClaim']['claimName'])
        pv = get('pv', pvc['spec']['volumeName'])
        need(pv['spec'].get('local', {}).get('path') == str(root), 'exact_cache_pv_path_required')
        need(not any(p.is_symlink() for p in (root, *root.parents)), 'cache_root_symlink_refused')
        result[role] = {'path': str(root), 'identity': tree_inode(root), 'pv_uid': pv['metadata']['uid'],
                        'pv_name': pv['metadata']['name'], 'pvc_uid': pvc['metadata']['uid'], 'pvc_name': pvc['metadata']['name']}
    return result

def capture_cache_baselines(pg_bytes):
    roles_stopped()
    layouts = cache_layouts()
    manifests = {role: cache_manifest(root) for role, root in CACHE_ROOTS.items()}
    total = sum(value['bytes'] for value in manifests.values())
    need(shutil.disk_usage(S).free >= 4 * max(pg_bytes, 1) + 2 * total + RESERVE, 'database_and_cache_recovery_headroom')
    parent = S / 'fallback-cache'
    parent.mkdir(mode=0o700)
    save('cache-baselines-intent.json', {'layouts': layouts, 'bytes': total})
    for role, source in CACHE_ROOTS.items():
        target = parent / role
        target.mkdir(mode=0o700)
        copy_cache(source, target, manifests[role])
        need(cache_manifest(source) == manifests[role], 'source_cache_changed_during_checkpoint')
    value = {'layouts': layouts, 'manifests': manifests, 'bytes': total}
    save('cache-baselines.json', value)
    return value

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


def checked_dependencies(public):
    """Verify every admitted executable dependency before importing the controller."""
    sources = public.get('dependency_sources')
    need(isinstance(sources, dict) and 2 <= len(sources) <= 32
         and str(OP) in sources and sources[str(OP)] == OP_SHA,
         'complete_dependency_source_manifest_required')
    for name, expected in sources.items():
        path = P(name)
        need(path.is_absolute() and path.is_relative_to('/usr/local/libexec')
             and path.suffix == '.py' and re.fullmatch('[0-9a-f]{64}', expected),
             'fixed_dependency_source_required')
        need(not any(p.is_symlink() for p in (path, *path.parents)), 'dependency_symlink_refused')
        info = path.stat()
        need(info.st_uid == 0 and not info.st_mode & 0o022
             and sha(raw(path, private=False)) == expected, 'dependency_source_changed')
    return sources

def controller_module():
    public = decode(raw(PUBLIC))
    need(not any(p.is_symlink() for p in (CONTROLLER, *CONTROLLER.parents)), 'controller_source_symlink_refused')
    need(sha(raw(CONTROLLER)) == public['controller_source_sha256'], 'frozen_successor_controller_required')
    checked_dependencies(public)
    spec = importlib.util.spec_from_file_location('checkpoint_schema19_successor', CONTROLLER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    return module

def source_guard():
    """Use only the exactly approved new controller's stopped-role boundary."""
    public = decode(raw(PUBLIC))
    module = controller_module()
    controller = module.Controller(str(UPGRADE), str(UPGRADE / 'plan.json'), 'default')
    controller.boundary_guard(check_pods=False)
    prepared_boundary()
    return controller.module, controller.old

def checked_store_claim(claim, public):
    manifest_body = raw(N / 'source-manifest.json')
    need(sha(manifest_body) == public.get('source_manifest_sha256'), 'current_source_manifest_required')
    manifest = decode(manifest_body)
    producer = manifest.get('store-claim.py')
    need(isinstance(producer, str) and re.fullmatch('[0-9a-f]{64}', producer)
         and claim.get('source_sha256') == producer
         and sha(raw(N / 'store-claim.py')) == producer, 'store_claim_producer_source_changed')
    need(claim.get('version') == 1 and claim.get('status') == 200
         and claim.get('key') == 'production/store.json' and claim.get('storage_binding_sha256') == BIND
         and claim.get('boundary_mode') == 'withdrawn'
         and claim.get('stopped_role_secret_templates_match_admitted_binding') is True
         and claim.get('actual_operating_files_match_admitted_binding') is False,
         'withdrawn_store_claim_required')

def authorize():
    need(os.geteuid() == 0, 'root_required')
    private_dir(N)
    v = decode(raw(APPROVAL))
    pub = decode(raw(PUBLIC))
    claim = decode(raw(CLAIM))
    source = sha(raw(P(__file__), private=False))
    need(pub['revision'] == REV and pub['old_image'] == OLD and (pub['pg_image'] == PG) and (pub['pg_pv_path'] == str(PV)) and (pub['old_operator_sha256'] == OP_SHA) and (pub['schema_before'] == 18), 'public_upgrade_identity_changed')
    expected = {'version': 1, 'approved': True, 'scope': 'physical-pg-checkpoint-1d76fbcc', 'source_sha256': source, 'public_identity_sha256': sha(raw(PUBLIC)), 'store_claim_sha256': sha(raw(CLAIM)), 'controller_prepared_sha256': sha(raw(PREPARED)), 'operations': ['prepare', 'run', 'proof'], 'maximum_checkpoints': 1, 'maximum_rehearsals': 1, 'independent_s3_backup': False}
    need(v == expected, 'explicit_exact_checkpoint_approval_required')
    checked_store_claim(claim, pub)
    body = base64.b64decode(claim['body_base64'], validate=True)
    need(len(body) <= 16384 and sha(body) == claim['body_sha256'] and (0 < len(claim['request_id']) <= 256), 'store_claim_readback_required')
    d = decode(body)
    need(set(d) == {'version', 'store_id'} and d['version'] == 1 and re.fullmatch('[0-9a-f]{32}', d['store_id']), 'store_claim_descriptor_identity')
    # A stopped configuration/Secret claim is not proof of mounted files. Recheck
    # the exact prepared controller boundary and stopped roles before admission.
    source_guard()
    roles_stopped()
    return {'source_sha256': source, 'approval_sha256': sha(raw(APPROVAL)), 'public_identity_sha256': sha(raw(PUBLIC)), 'store_claim_sha256': sha(raw(CLAIM)), 'controller_prepared_sha256': sha(raw(PREPARED)), 'store_id': d['store_id']}

def prepare(pins):
    private_dir(S)
    mount = disk_identity()
    need(not any(S.iterdir()), 'fresh_checkpoint_scope_required')
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
        # Golden18, clone, optional golden19 and rollback staging must all fit.
        need(shutil.disk_usage(S).free >= 4 * max(total, 1) + RESERVE, 'checkpoint_and_clone_headroom')
        need(any(v.get('secret', {}).get('secretName') == 'devres-corpus-postgres' for v in deploy['spec']['template']['spec']['volumes']), 'actual_corpus_postgres_secret_required')
        private = S / 'private'
        private.mkdir(mode=448)
        originals = {}
        accepted = prepared_input()
        new(private / 'controller-prepared.json', raw(PREPARED))
        for role, secret_name, filename in [('backend', 'devres-serving-config', 'serving.toml'), ('writer', 'devres-writer-config', 'writer.toml')]:
            v = base64.b64decode(accepted['secrets'][secret_name]['data'][filename], validate=True)
            value = tomllib.loads(v.decode())
            need(value['source']['url'].endswith('/0.1.0-build.91c7bcb7/source.tar.gz') and value['storage']['backend'] == 's3' and type(value['wikipedia']['enabled']) is bool, 'current_schema18_configuration_required')
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
        baseline = {'disk_identity': mount, 'pins': pins, 'old_pg_pod': projection, 'postgres_deployment': deployment_projection(deploy), 'layout': layout, 'identity': identity, 'namespace_uids': namespaces, 'node_name': node, 'node_uid': node_uid, 'secret_bindings': secrets, 'original_files_sha256': originals, 'qualified_local_images': qualified_images, 'live_pg_bytes': total, 'live_pg_files': sum((r['kind'] == 'file' for r in rows))}
        save('baseline.json', baseline)
        (S / 'pg-checkpoint').mkdir(mode=448)
        save('precopy-intent.json', {'source': layout['source'], 'destination': str(S / 'pg-checkpoint'), 'not_a_valid_checkpoint': True})
        result = copy_tree(P(layout['source']), S / 'pg-checkpoint', True)
        capture_cache_baselines(total)
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
    need(disk_identity() == b['disk_identity'], 'checkpoint_mount_changed')
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
        save('checkpoint-completed.json', {'pins': pins, 'schema': 18, 'system_identifier': SYSID, 'archive': ARCHIVE, 'store_id': pins['store_id'], 'archive_manifest': manifest, 'capture_manifest': capture_manifest, 'pg_files_sha256': sha(raw(S / 'pg-file-manifest.jsonl', MAX_MANIFEST)), 'pg_files': sum((r['kind'] == 'file' for r in rows)), 'pg_bytes': total, 'old_pg_pod': b['old_pg_pod'], 'new_pg_pod': load('original-pg-resumed.json')['new_pg_pod'], 'postgres_deployment_sha256': controller_deployment_hash(b['postgres_deployment']), 'postgres_full_deployment_sha256': sha(enc(b['postgres_deployment'])), 'original_pg_restarted_without_restore': True, 'roles_stopped': True, 'independent_s3_backup': False, 'completed_at': now()})
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
    need(before['storage']['backend'] == 's3' and before['storage']['s3']['credentials']['mode'] == 'files' and (before['storage']['s3']['prefix'] == 'production') and before['source']['url'].endswith('/0.1.0-build.91c7bcb7/source.tar.gz'), 'old_static_reader_config_required')
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

def archive_hosts(config):
    from urllib.parse import urlsplit
    value = config['storage']['s3']
    endpoint = urlsplit(value['endpoint'])
    need(endpoint.scheme == 'https' and endpoint.hostname and endpoint.port in (None, 443)
         and not endpoint.username and not endpoint.password and not endpoint.query,
         'qualified_s3_https_endpoint_required')
    host = endpoint.hostname if value.get('path_style', False) else value['bucket'] + '.' + endpoint.hostname
    addresses = sorted({row[4][0] for row in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
    need(1 <= len(addresses) <= 16 and all(ipaddress.ip_address(a).is_global for a in addresses),
         'bounded_public_s3_addresses_required')
    return host, addresses

def network_fence(token, subnet, config):
    """Deny clone source egress before its first process starts; allow only S3."""
    host, addresses = archive_hosts(config)
    table = 'devres_cp_' + token
    rules = ('add table inet ' + table + '\nadd chain inet ' + table
             + ' forward { type filter hook forward priority -200; policy accept; }\n'
             + 'add rule inet ' + table + ' forward ip saddr ' + subnet + ' ip daddr ' + subnet + ' accept\n'
             + 'add rule inet ' + table + ' forward ip saddr ' + subnet
             + ' ip daddr { ' + ', '.join(addresses) + ' } tcp dport 443 accept\n'
             + 'add rule inet ' + table + ' forward ip saddr ' + subnet + ' drop\n')
    # New table creation fails if a conflicting table exists. An uncertain creation
    # leaves its intent for reconciliation; it never weakens another policy.
    save('clone-network-fence-intent.json', {'table': table, 'token': token, 'rules_sha256': sha(rules.encode()),
                                           'subnet': subnet, 's3_host': host, 's3_ipv4': addresses})
    run(['nft', '-f', '-'], data=rules.encode())
    current = decode(run(['nft', '--json', 'list', 'table', 'inet', table]))
    save('clone-network-fence.json', {'table': table, 'token': token, 'snapshot': current})
    return ['--add-host=' + host + ':' + a for a in addresses]

def remove_network_fence(token):
    path = S / 'clone-network-fence.json'
    if not path.exists():
        need(not (S / 'clone-network-fence-intent.json').exists(), 'clone_network_fence_creation_uncertain')
        return
    record = load('clone-network-fence.json')
    need(record['token'] == token and record['table'] == 'devres_cp_' + token, 'owned_clone_network_fence_required')
    actual = decode(run(['nft', '--json', 'list', 'table', 'inet', record['table']]))
    need(actual == record['snapshot'], 'clone_network_fence_changed')
    run(['nft', 'delete', 'table', 'inet', record['table']])
    save('clone-network-fence-removed.json', {'token': token, 'removed': True})

def writer_config(original):
    before = tomllib.loads(original)
    need(before['storage']['backend'] == 's3' and before['storage']['s3']['credentials']['mode'] == 'files'
         and before['source']['url'].endswith('/0.1.0-build.91c7bcb7/source.tar.gz')
         and 'writer_listener' in before and 'writer_client' not in before,
         'fallback_writer_configuration_required')
    from urllib.parse import urlsplit
    need(urlsplit(before['storage']['database_url']).username == 'devres_writer', 'clone_requires_writer_sql_role')
    expected = copy.deepcopy(before)
    text = original
    fields = [(p, 'enabled', False) for p in PROVIDERS] + [('npm', 'advisories_enabled', False),
              ('storage.s3', 'cache_max_bytes', 64 * 1024**2),
              ('writer_listener', 'bind', '127.0.0.1:9443'),
              ('writer_listener.auth', 'kube_api_url', 'https://127.0.0.1:9'),
              ('writer_listener.auth', 'kube_token_file', '/run/checkpoint/no-authority-token'),
              ('writer_listener.auth', 'kube_ca_file', '/run/checkpoint/coordination-ca.crt')]
    for section, key, value in fields:
        text = replace_scalar(text, section, key, value)
        item = expected
        for part in section.split('.'):
            item = item[part]
        item[key] = value
    need(tomllib.loads(text) == expected, 'unexpected_clone_writer_configuration_change')
    return text

def fallback_writer_proof(common, clone, files, private, pgid, oldimage, token, containers):
    """Use cloned writer SQL authority and ONLY the admitted reader S3 keypair."""
    original = raw(private / 'writer.toml').decode()
    new(files / 'writer.toml', writer_config(original).encode(), 65532, 256)
    tls = decode(raw(private / 'devres-writer-tls.json'))['data']
    for key in ('tls.crt', 'tls.key'):
        new(files / ('writer-' + key), base64.b64decode(tls[key], validate=True), 65532, 256)
    cache = clone / 'writer-cache'
    cache.mkdir(mode=0o700)
    baseline_cache = load('cache-baselines.json')['manifests']['writer']
    copy_cache(S / 'fallback-cache/writer', cache, baseline_cache)
    args = [*common, '--name', 'devres-checkpoint-' + token + '-writer', '--user', '65532:65532',
            '--tmpfs', '/tmp:rw,nosuid,nodev,uid=65532,gid=65532,mode=1777',
            '--mount', 'type=bind,src=' + str(cache) + ',dst=/data/cache']
    mounts = {'writer.toml': '/etc/devres/config/writer.toml', 'writer-tls.crt': '/run/devres-writer-tls/tls.crt',
              'writer-tls.key': '/run/devres-writer-tls/tls.key', 'writer-ca.crt': '/run/checkpoint/coordination-ca.crt',
              'no-authority-token': '/run/checkpoint/no-authority-token',
              'access-key': '/run/devres-s3/access-key', 'secret-key': '/run/devres-s3/secret-key'}
    for src, dst in mounts.items():
        args += ['--mount', 'type=bind,src=' + str(files / src) + ',dst=' + dst + ',readonly']
    args += [oldimage, 'collect', '/etc/devres/config/writer.toml']
    # Compare exact data before/after writer initialization; no source or public
    # request is made. Operational sweep metadata alone may progress in the clone.
    query = "SELECT json_build_object('schema',(SELECT version FROM devres_schema WHERE singleton),'captures',(SELECT count(*) FROM devres_captures),'archive',(SELECT count(*) FROM devres_archive_file),'npm',(SELECT coalesce(json_object_agg(key,data),'{}'::json) FROM devres_npm_state WHERE key IN ('advisory-job','default-advisories') OR starts_with(key,'source-cache:') OR starts_with(key,'source-response:')))"
    def identity():
        return decode(run(['docker', 'exec', pgid, 'psql', '-X', '-q', '-U', 'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c', query]))
    before = identity()
    save('clone-writer-create-intent.json', {'token': token, 'reader_s3_credentials_only': True, 'cloned_sql_only': True})
    cid = run(args).decode().strip()
    need(re.fullmatch('[0-9a-f]{64}', cid), 'clone_writer_id_required')
    containers.append(cid)
    deadline = time.monotonic() + 120
    while True:
        row = owned_container(cid, token)
        need(row['State']['Running'] and not row['HostConfig'].get('PortBindings')
             and all(P(v['Source']).is_relative_to(S) for v in row['Mounts'] if v['Type'] == 'bind'),
             'clone_writer_mount_or_process_boundary')
        ip = next(iter(row['NetworkSettings']['Networks'].values()))['IPAddress']
        try:
            with socket.create_connection((ip, 9090), timeout=2) as sock:
                sock.sendall(b'GET /ready HTTP/1.1\r\nHost: checkpoint\r\nConnection: close\r\n\r\n')
                response = http.client.HTTPResponse(sock)
                response.begin()
                ready = response.status == 200
        except OSError:
            ready = False
        if ready:
            break
        need(time.monotonic() < deadline, 'clone_writer_readiness_deadline')
        time.sleep(1)
    run(['docker', 'stop', '--time', '30', cid], 45)
    need(not owned_container(cid, token)['State']['Running'], 'clone_writer_not_stopped')
    need(identity() == before and before['schema'] == 18, 'clone_writer_changed_retained_current_state')
    result = {'ready': True, 'reader_s3_credentials_only': True, 'source_egress_fenced': True,
              'retained_current_state_preserved': True, 'schema': 18, 'stopped': True}
    save('clone-writer-proof.json', result)
    return result

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
        need(shutil.disk_usage(S).free >= total + RESERVE, 'clone_headroom_required')
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
            description = decode(run(['docker', 'network', 'inspect', name]))[0]
            need(description.get('EnableIPv6') is False, 'ipv4_only_clone_network_required')
            host_args = network_fence(token, subnet, tomllib.loads(raw(private / 'serving.toml').decode()))
            common = ['docker', 'run', '--detach', '--pull', 'never', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--security-opt', 'apparmor=devres-runtime', '--label', LABEL + '=' + token, '--network', name, *host_args]
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
            query = "SELECT json_build_object('system_id',(SELECT system_identifier::text FROM pg_control_system()),'schema',(SELECT version FROM devres_schema WHERE singleton),'wikipedia_tables',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_wikipedia_evidence')),(to_regclass('public.devres_wikipedia_state'))) t(oid) WHERE oid IS NOT NULL),'schema18_objects',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_crate_enrichment_v2')),(to_regclass('public.devres_crate_enrichment_heads_v2')),(to_regclass('public.devres_crate_dump_failures')),(to_regclass('public.devres_crate_enrichment_all'))) t(oid) WHERE oid IS NOT NULL),'store_id',(SELECT store_id FROM devres_archive_control WHERE singleton),'reader_default_readonly',(SELECT rolconfig @> ARRAY['default_transaction_read_only=on'] FROM pg_roles WHERE rolname='devres_reader'),'reader_writer_memberships',(SELECT count(*) FROM pg_auth_members WHERE member='devres_reader'::regrole),'tables_without_reader_select',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','p','v','m') AND NOT has_table_privilege('devres_reader',c.oid,'SELECT')),'reader_mutation_tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','p','v','m') AND has_table_privilege('devres_reader',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))"
            query = query[:-1] + ",'attribution'," + attribution_query() + ')'
            clone_sql = decode(run(['docker', 'exec', pgid, 'env', 'PGOPTIONS=-c default_transaction_read_only=on', 'psql', '-X', '-q', '-U', 'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c', query]))
            need(clone_sql == {'system_id': SYSID, 'schema': 18, 'wikipedia_tables': 2, 'schema18_objects': 4, 'store_id': pins['store_id'], 'reader_default_readonly': True, 'reader_writer_memberships': 0, 'tables_without_reader_select': 0, 'reader_mutation_tables': 0, 'attribution': load('quiescent-identity.json')['attribution']}, 'clone_original_sql_authority_not_preserved')
            writer_proof = fallback_writer_proof(common, clone, files, private, pgid, oldimage, token, containers)
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
            cold_control = decode(raw(PUBLIC))['cold_read_control']
            cold_body = cold_body_readback(ip, cold_control, private / 'tls', clone_sql['attribution'])
            historical_notice = notice_readback(ip, GENERATION, NOTICE, private / 'tls')
            result = {'clone_sql': clone_sql, 'old_reader_image_id': oldimage, 'pg_image_id': pgimage,
                      'historical_notice': historical_notice,
                      'cold_body': cold_body,
                      'current_attribution_sha256': sha(enc(clone_sql['attribution'])),
                      'current_policy_epoch': 2, 'selected_generations_preserved': True,
                      'reader_only': False, 'fallback_writer': writer_proof, 'writer_client_loopback_without_authority': True,
                      'no_production_mount': True, 'all_collectors_disabled': True,
                      'provider_source_requests': 0, 'isolated_clone_only': True,
                      'current_content_readability_not_inferred': True}
            save('clone-proof-result.json', result)
            success = True
        finally:
            try:
                cleanup_clone(containers, network, token)
                need(not creation_uncertain, 'clone_creation_outcome_unknown_manual_reconciliation')
                remove_network_fence(token)
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
        need(final['attribution'] == load('quiescent-identity.json')['attribution'], 'quiescent_attribution_changed_during_rehearsal')
        need(source_layout(stable_foundation(b), final) == b['layout'], 'production_pv_changed_during_rehearsal')
        completed = {'version': 1, 'kind': 'physical-pg-retained-immutable-s3-upgrade-checkpoint', 'revision': REV, 'pins': pins, 'schema': 18, 'system_identifier': SYSID, 'archive': ARCHIVE, 'store_id': pins['store_id'], 'store_binding_sha256': BIND, 'old_pg_pod': b['old_pg_pod'], 'new_pg_pod': load('original-pg-resumed.json')['new_pg_pod'], 'postgres_deployment_sha256': controller_deployment_hash(b['postgres_deployment']), 'postgres_full_deployment_sha256': sha(enc(b['postgres_deployment'])), 'checkpoint_receipt_sha256': sha(raw(S / 'checkpoint-completed.json')), 'manifest_sha256': c['archive_manifest']['sha256'], 'capture_manifest_sha256': c['capture_manifest']['sha256'], 'pg_files_sha256': c['pg_files_sha256'], 'clone_proof_sha256': sha(raw(S / 'clone-proof-result.json')), 'production_pg_restarted_without_restore': True, 'roles_stopped': True, 'old_clone_verified': True, 'fallback_writer_verified': True, 'credentials_preserved': True, 'independent_s3_backup': False, 'all_remote_hashes_rechecked': False, 'original_s3_retained': True, 'completed_at': now()}
        completed['cache_baselines_sha256'] = sha(raw(S / 'cache-baselines.json', MAX_MANIFEST))
        save('completed.json', completed)
    write_backup_receipt()
    return {'coordinated_upgrade_rollback_checkpoint': True, 'old_readonly_clone_verified': True, 'independent_s3_backup': False, 'completed_receipt_sha256': sha(raw(S / 'completed.json')), 'private_data_export_allowed': False}

def write_backup_receipt():
    completed = load('completed.json')
    checkpoint = load('checkpoint-completed.json')
    need(completed['revision'] == REV and completed['schema'] == 18
         and completed['old_clone_verified'] is True and completed['roles_stopped'] is True
         and completed['fallback_writer_verified'] is True
         and completed['credentials_preserved'] is True
         and completed['original_s3_retained'] is True
         and completed['independent_s3_backup'] is False, 'completed_backup_identity')
    need(completed['checkpoint_receipt_sha256'] == sha(raw(S / 'checkpoint-completed.json'))
         and completed['clone_proof_sha256'] == sha(raw(S / 'clone-proof-result.json'))
         and completed['pg_files_sha256'] == sha(raw(S / 'pg-file-manifest.jsonl', MAX_MANIFEST)), 'completed_backup_artifact_changed')
    need(completed['cache_baselines_sha256'] == sha(raw(S / 'cache-baselines.json', MAX_MANIFEST)), 'cache_baselines_changed')
    need(checkpoint['archive_manifest']['sha256'] == completed['manifest_sha256']
         and checkpoint['capture_manifest']['sha256'] == completed['capture_manifest_sha256'], 'completed_manifest_receipt_changed')
    names = ('completed.json', 'checkpoint-completed.json', 'clone-proof-result.json',
             'clone-cleanup-completed.json', 'original-pg-resumed.json',
             'clean-pg-control.json', 'baseline.json', 'quiescent-identity.json',
             'archive-manifest-receipt.json', 'capture-manifest-receipt.json', 'pg-file-manifest.jsonl',
             'archive-bindings.jsonl', 'capture-bindings.jsonl', 'cache-baselines.json', 'clone-writer-proof.json',
             'clone-network-fence.json', 'clone-network-fence-removed.json')
    artifacts = []
    for name in names:
        path = S / name
        body = raw(path, MAX_MANIFEST)
        artifacts.append({'path': str(path), 'sha256': sha(body)})
    need(next(a['sha256'] for a in artifacts if a['path'].endswith('/archive-bindings.jsonl')) == completed['manifest_sha256']
         and next(a['sha256'] for a in artifacts if a['path'].endswith('/capture-bindings.jsonl')) == completed['capture_manifest_sha256'], 'completed_manifest_bytes_changed')
    receipt = {'version': 1, 'kind': 'coordinated-schema18-backup', 'revision': REV,
               'prepared_sha256': completed['pins']['controller_prepared_sha256'],
               'store_binding_sha256': BIND, 'verified': True, 'observed_at': now(),
               'schema': 18, 'system_identifier': SYSID,
               'recovery_scope': 'physical_pg_checkpoint_original_immutable_s3_retained',
               'independent_s3_backup': False,
               'old_pg_pod': completed['old_pg_pod'], 'new_pg_pod': completed['new_pg_pod'],
               'postgres_deployment_sha256': completed['postgres_deployment_sha256'],
               'checks': {'coordinated_pg_s3': True, 'old_clone_verified': True,
                          'roles_stopped': True, 'pg_restarted_without_restore': True,
                          'credentials_preserved': True, 'fallback_writer_verified': True}, 'artifacts': artifacts}
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
