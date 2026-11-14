#!/usr/bin/env python3
"""Preserve the whole failed writer cache, copy Git state, resume the same target.

No permanent object, SQL state, policy, credential, configuration or limit is
modified. All mutation intents are exclusive and durable; uncertain work is never
replayed. The original cache remains inside a root-private preservation journal.
"""
import argparse
import base64
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tomllib

BUNDLE = Path('/var/lib/devres-production-upgrades/33f3c730-20261114')
JOURNAL = BUNDLE / 'cache-recovery'
CACHE = Path('/var/cache/devres/writer')
ORIGINAL = JOURNAL / 'writer-original'
CONTROLLER = Path('/usr/local/libexec/devres-upgrade-33f3c730/upgrade-controller.py')
CONTROLLER_SHA = '2b18ea9ee326eabbafa1398f0f065c639b9e70fe01962cca31e6d8fc86365a6e'
CHECKPOINT = Path('/usr/local/libexec/devres-upgrade-33f3c730/physical-checkpoint.py')
CHECKPOINT_SHA = '25ce3324cad52cd6018e3411e169119bbbb18652bc1901138780b55f758c1501'
REVISION = '33f3c730123319625fe3a25713988201eb5d82e0'
ROOT_UID, ROOT_GID, ROOT_MODE, ROOT_DEVICE, ROOT_INODE = 65532, 65532, 0o2770, 2305, 12062131
PVC_UID = '9f1b60cd-a5b1-4b62-8db7-2ab10cd23f64'
PV_UID = 'be522e81-630e-4d5e-a728-8ff4691c4e37'
POLICY2 = 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'
SYSTEM_ID = '7706567225121447965'
ARCHIVE_BINDING = 'blake3:7cf193132e3e32eb53c877dfcce166453e5bbb1b0d3f9a39f922f194f82f38e3'
GIT_NAMES = {'history.git', 'registry.git'}
GIT_ROOT_COUNT = 32
EXPECTED_ORDINARY_FILES = 262147
MAX_ENTRIES = 1500000
MAX_BYTES = 64 * 1024**3
RESERVE = 128 * 1024**3
PROVIDERS = ('rfc', 'crates', 'rustsec', 'mdn', 'whatwg', 'w3c', 'chromium', 'npm', 'wikipedia')


IDENTITY_SQL = r"""SELECT json_build_object('system_id',(SELECT system_identifier::text FROM pg_control_system()),'schema',(SELECT version FROM devres_schema WHERE singleton),'archive',(SELECT row_to_json(a) FROM devres_archive_control a WHERE singleton),'control',(SELECT data FROM devres_attribution_control WHERE singleton),'owners',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND mode='ExclusiveLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())),'generation_count',(SELECT count(*) FROM devres_attribution_generations),'generations_sha256',(SELECT encode(sha256(convert_to(coalesce(string_agg(encode(sha256(convert_to(row_to_json(g)::text,'UTF8')),'hex'),E'\n' ORDER BY id COLLATE "C"),''),'UTF8')),'hex') FROM devres_attribution_generations g))"""


class Stop(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Stop(code)


def enc(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def no_symlinks(path):
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'absolute_nosymlink_path_required')


def private_dir(path):
    no_symlinks(path)
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'private_directory_required')


def raw(path, maximum=8 * 1024**2, source=False):
    path = Path(path); no_symlinks(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
             and not info.st_mode & (0o022 if source else 0o077) and info.st_size <= maximum, 'private_file_required')
        data = stream.read(maximum + 1)
        need(len(data) == info.st_size, 'private_file_changed')
        return data


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def save(path, value, replace=False):
    path = Path(path); private_dir(path.parent)
    target = path.parent / ('.' + path.name + '.tmp') if replace else path
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(enc(value)); stream.flush(); os.fsync(stream.fileno())
    if replace: os.replace(target, path)
    sync_dir(path.parent)


def load(path):
    return json.loads(raw(path))


def file_sha(path):
    no_symlinks(path)
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
    with os.fdopen(fd, 'rb') as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'regular_file_required')
        for block in iter(lambda: stream.read(1024**2), b''): h.update(block)
    return h.hexdigest()


def module_at(name, path, expected):
    need(sha(raw(path, source=True)) == expected, 'frozen_source_changed')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def meta(info, relative, kind):
    out = {'path': relative, 'kind': kind, 'mode': stat.S_IMODE(info.st_mode),
           'uid': info.st_uid, 'gid': info.st_gid, 'device': info.st_dev, 'inode': info.st_ino,
           'mtime_ns': info.st_mtime_ns, 'links': info.st_nlink}
    if kind == 'file': out['bytes'] = info.st_size
    return out


def inspect_tree(root, manifest):
    """No-follow, no-atime complete byte inventory; Git is counted separately."""
    no_symlinks(root); private_dir(manifest.parent)
    fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    state = {'entries': 0, 'files': 0, 'bytes': 0, 'ordinary_files': 0,
             'git_bytes': 0, 'git_roots': [], 'git_sha256': None}
    whole, git = hashlib.sha256(), hashlib.sha256()
    root_device = root.stat().st_dev
    with os.fdopen(fd, 'wb') as out:
        def emit(row, in_git):
            line = enc(row) + b'\n'; out.write(line); whole.update(line)
            if in_git:
                logical = {k: v for k, v in row.items() if k not in ('device', 'inode', 'links')}
                git.update(enc(logical) + b'\n')
        def walk(directory, relative, depth, in_git=False):
            need(depth <= 128, 'cache_depth_bound')
            info = os.fstat(directory)
            need(stat.S_ISDIR(info.st_mode) and info.st_dev == root_device, 'cache_nested_mount_or_nondirectory')
            emit(meta(info, relative or '.', 'directory'), in_git)
            with os.scandir(directory) as it: names = sorted((e.name for e in it), key=os.fsencode)
            for name in names:
                need(name not in ('.', '..') and '/' not in name and not any(ord(c) < 32 for c in name), 'cache_path_invalid')
                name.encode('utf-8')
                child = name if not relative else relative + '/' + name
                need(len(child.encode()) <= 4096, 'cache_path_bound')
                state['entries'] += 1; need(state['entries'] <= MAX_ENTRIES, 'cache_entry_bound')
                before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                need(before.st_dev == root_device and not stat.S_ISLNK(before.st_mode), 'cache_symlink_or_mount')
                if stat.S_ISDIR(before.st_mode):
                    git_root = name in GIT_NAMES and not in_git
                    if git_root: state['git_roots'].append(child)
                    childfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, dir_fd=directory)
                    try: walk(childfd, child, depth + 1, in_git or git_root)
                    finally: os.close(childfd)
                else:
                    need(stat.S_ISREG(before.st_mode), 'cache_special_file')
                    filefd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME, dir_fd=directory)
                    digest = hashlib.sha256()
                    with os.fdopen(filefd, 'rb') as source:
                        opened = os.fstat(source.fileno())
                        need((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                             == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns), 'cache_file_changed')
                        total = 0
                        for block in iter(lambda: source.read(1024**2), b''): total += len(block); digest.update(block)
                        after = os.fstat(source.fileno())
                        need(total == before.st_size and (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                             == (before.st_size, before.st_mtime_ns, before.st_ctime_ns), 'cache_file_changed')
                    row = meta(before, child, 'file'); row['sha256'] = digest.hexdigest(); emit(row, in_git)
                    state['files'] += 1; state['bytes'] += total
                    need(state['bytes'] <= MAX_BYTES, 'cache_byte_bound')
                    if in_git: state['git_bytes'] += total
                    else: state['ordinary_files'] += 1
            after = os.fstat(directory)
            need((after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
                 == (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns), 'cache_directory_changed')
        rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME)
        try: walk(rootfd, '', 0)
        finally: os.close(rootfd)
        out.flush(); os.fsync(out.fileno())
    sync_dir(manifest.parent)
    state.update(sha256=whole.hexdigest(), git_sha256=git.hexdigest(), manifest=str(manifest))
    return state


def safe_relative(value):
    path = PurePosixPath(value)
    need(value and not path.is_absolute() and '..' not in path.parts and '.' not in path.parts
         and path.as_posix() == value, 'git_path_traversal')
    return path


def copy_git_roots(source, destination, roots):
    """Copy bytes to new inodes; never execute Git or link old and new files."""
    directories = set()
    def create_directory(relative):
        target = destination / relative
        if target == destination: return
        source_path = source / relative
        no_symlinks(source_path); info = source_path.lstat()
        need(stat.S_ISDIR(info.st_mode), 'git_source_directory_required')
        if not target.exists(): target.mkdir(mode=0o700)
        need(target.is_dir() and not target.is_symlink(), 'git_destination_directory_required')
        directories.add(relative)
    for value in roots:
        relative = safe_relative(value)
        need(relative.name in GIT_NAMES, 'git_root_name')
        parts = list(relative.parents)[::-1] + [relative]
        for part in parts:
            if part != PurePosixPath('.'): create_directory(part)
        def copy_directory(rel):
            src = source / rel; no_symlinks(src)
            directoryfd = os.open(src, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME)
            try:
                with os.scandir(directoryfd) as it: entries = sorted((e.name for e in it), key=os.fsencode)
            finally: os.close(directoryfd)
            for name in entries:
                child = rel / name; safe_relative(child.as_posix())
                source_path, target = source / child, destination / child
                info = source_path.lstat()
                need(not stat.S_ISLNK(info.st_mode), 'git_symlink_refused')
                if stat.S_ISDIR(info.st_mode): create_directory(child); copy_directory(child)
                else:
                    need(stat.S_ISREG(info.st_mode), 'git_special_file_refused')
                    fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
                    outfd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'rb') as srcfile, os.fdopen(outfd, 'wb') as dstfile:
                        while block := srcfile.read(1024**2): dstfile.write(block)
                        dstfile.flush(); os.fchown(dstfile.fileno(), info.st_uid, info.st_gid)
                        os.fchmod(dstfile.fileno(), stat.S_IMODE(info.st_mode))
                        os.utime(dstfile.fileno(), ns=(info.st_atime_ns, info.st_mtime_ns))
                        os.fsync(dstfile.fileno())
                        new = os.fstat(dstfile.fileno())
                        need((new.st_dev, new.st_ino) != (info.st_dev, info.st_ino), 'git_copy_must_have_new_inode')
            directories.add(rel)
        copy_directory(relative)
    for rel in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        info = (source / rel).lstat(); target = destination / rel
        os.chown(target, info.st_uid, info.st_gid, follow_symlinks=False)
        os.chmod(target, stat.S_IMODE(info.st_mode), follow_symlinks=False)
        os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns), follow_symlinks=False)
        sync_dir(target)
    sync_dir(destination)


class Recovery:
    def __init__(self, controller, checkpoint, approval, approval_sha):
        self.c, self.checkpoint = controller, checkpoint
        self.root = JOURNAL; self.approval_path, self.approval_sha = Path(approval), approval_sha
        self.source_sha = sha(Path(__file__).read_bytes())

    def state(self):
        value = load(self.root / 'state.json')
        need(value['source_sha256'] == self.source_sha and value['approval_sha256'] == self.approval_sha,
             'recovery_journal_identity')
        return value

    def record(self, value): save(self.root / 'state.json', value, replace=True)

    def approval(self):
        encoded = raw(self.approval_path)
        need(sha(encoded) == self.approval_sha, 'recovery_approval_hash')
        cstate = self.c.state()
        withdrawn_sha = (load(self.root / 'prepared.json')['withdrawn_state_sha256'] if self.root.exists()
                         else sha(raw(BUNDLE / 'state.json')))
        expected = {'version': 1, 'kind': 'preserving-writer-cache-recovery', 'approved': True,
            'source_sha256': self.source_sha, 'controller_sha256': CONTROLLER_SHA,
            'controller_prepared_sha256': cstate['prepared_sha256'], 'withdrawn_state_sha256': withdrawn_sha,
            'operations': ['prepare', 'rotate', 'start'], 'maximum_rotations': 1, 'maximum_start_attempts': 1,
            'preserve_original_cache': True, 'preserve_git_copies': True, 'new_permanent_mutations': False}
        need(json.loads(encoded) == expected, 'recovery_approval_binding')

    def intent(self, name, function):
        save(self.root / (name + '-intent.json'), {'version': 1, 'operation': name,
            'source_sha256': self.source_sha, 'maximum_attempts': 1, 'observed_at': now()})
        result = function()
        save(self.root / (name + '-completed.json'), {'known_complete': True, 'observed_at': now()})
        return result

    def guard(self):
        self.c.guard(); state = self.c.state()
        need(state['phase'] == 'withdrawn' and state['configs'] == 'paused'
             and state['replicas'] == {'postgres': 1, 'writer': 0, 'backend': 0}
             and set(state['pods']) == {'postgres'}, 'withdrawn_paused_roles_required')
        need(state['images']['writer'] == state['images']['backend'] == self.c.plan['target']['server'], 'same_target_image_required')
        texts = load(BUNDLE / 'configs-paused.json')
        for text in texts.values():
            config = tomllib.loads(text)
            need(all(config[p]['enabled'] is False for p in PROVIDERS), 'nine_paused_sources_required')
        deploy = self.c.get('deployment', 'writer')
        container = deploy['spec']['template']['spec']['containers'][0]
        mounts = [m for m in container['volumeMounts'] if m['mountPath'] == '/data/cache']
        need(len(mounts) == 1 and not mounts[0].get('readOnly') and not mounts[0].get('subPath')
             and not mounts[0].get('subPathExpr'), 'exact_writer_cache_mount')
        volumes = [v for v in deploy['spec']['template']['spec']['volumes'] if v['name'] == mounts[0]['name']]
        need(len(volumes) == 1 and volumes[0]['persistentVolumeClaim']['claimName'] == 'writer-cache'
             and not volumes[0]['persistentVolumeClaim'].get('readOnly'), 'exact_writer_cache_claim')
        pvc = self.c.get('pvc', 'writer-cache'); pv = self.c.get('pv', 'devres-writer-cache')
        need(pvc['metadata']['uid'] == PVC_UID and pvc['spec']['volumeName'] == 'devres-writer-cache'
             and pv['metadata']['uid'] == PV_UID and pv['spec']['local']['path'] == str(CACHE)
             and pv['spec']['claimRef']['uid'] == PVC_UID and pv['spec']['claimRef']['namespace'] == 'devres'
             and pv['spec']['claimRef']['name'] == 'writer-cache', 'exact_writer_cache_pv')
        return {'pvc_uid': PVC_UID, 'pvc_spec': pvc['spec'], 'pv_uid': PV_UID, 'pv_spec': pv['spec'],
                'deployment_uid': deploy['metadata']['uid'], 'mount': mounts[0]}

    def sql_identity(self, stopped=True):
        query = IDENTITY_SQL
        result = json.loads(self.c.old.k('exec', 'deployment/postgres', '-c', 'postgres', '--', 'psql', '-X', '-q', '-U',
            'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
            "BEGIN READ ONLY; SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='250ms'; " + query + '; COMMIT;', timeout=90))
        need(result['system_id'] == SYSTEM_ID and result['schema'] == 18
             and result['control'] == {'format_version': 1, 'required_policy_epoch': 2, 'required_policy_fingerprint': POLICY2},
             'same_schema18_policy2_required')
        need(result['archive']['backend'] == 's3' and result['archive']['epoch'] == 2
             and result['archive']['binding'] == ARCHIVE_BINDING
             and re.fullmatch('[a-f0-9]{32}', result['archive']['store_id'])
             and result['archive']['pending_binding'] is None and result['archive']['initializing_s3'] is False,
             'same_archive_required')
        need(result['owners'] == (0 if stopped else 1), 'publication_owner_count')
        return result

    def durable_proof(self, label, stopped=True):
        directory = self.root / label; directory.mkdir(mode=0o700); sync_dir(self.root)
        identity = self.sql_identity(stopped)
        old = self.checkpoint.S
        try:
            self.checkpoint.S = directory
            manifests = {kind: self.checkpoint.stream_manifest(kind) for kind in ('archive', 'captures')}
        finally: self.checkpoint.S = old
        normalized = {'identity': {k: v for k, v in identity.items() if k != 'owners'},
            'manifests': {k: {field: value[field] for field in ('sha256', 'files', 'manifest_bytes', 'logical_file_bytes')}
                          for k, value in manifests.items()}}
        save(directory / 'proof.json', {'observed_at': now(), 'identity': identity, 'manifests': manifests})
        return normalized

    def prepare(self):
        need(not self.root.exists(), 'fresh_recovery_journal_required')
        self.approval(); boundary = self.guard()
        no_symlinks(CACHE); info = CACHE.lstat()
        need(stat.S_ISDIR(info.st_mode) and not os.path.ismount(CACHE)
             and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_dev, info.st_ino)
             == (ROOT_UID, ROOT_GID, ROOT_MODE, ROOT_DEVICE, ROOT_INODE), 'original_cache_root_identity')
        private_dir(BUNDLE); need(BUNDLE.stat().st_dev == info.st_dev, 'same_filesystem_required')
        self.root.mkdir(mode=0o700); sync_dir(BUNDLE)
        save(self.root / 'state.json', {'version': 1, 'phase': 'preparing', 'source_sha256': self.source_sha,
             'approval_sha256': self.approval_sha})
        save(self.root / 'prepare-intent.json', {'version': 1, 'maximum_attempts': 1, 'observed_at': now()})
        inventory = inspect_tree(CACHE, self.root / 'original-cache.jsonl')
        need(inventory['ordinary_files'] == EXPECTED_ORDINARY_FILES and len(inventory['git_roots']) == GIT_ROOT_COUNT,
             'diagnosed_cache_inventory_changed')
        need(shutil.disk_usage(CACHE).free >= RESERVE + inventory['git_bytes'], 'copy_capacity_reserve')
        durable = self.durable_proof('before')
        need(self.guard() == boundary, 'cache_boundary_changed')
        prepared = {'version': 1, 'revision': REVISION, 'source_sha256': self.source_sha,
            'controller_sha256': CONTROLLER_SHA, 'checkpoint_sha256': CHECKPOINT_SHA,
            'controller_prepared_sha256': self.c.state()['prepared_sha256'],
            'controller_prepared_file_sha256': sha(raw(BUNDLE / 'prepared.json')),
            'withdrawn_state_sha256': sha(raw(BUNDLE / 'state.json')), 'withdrawn_state': self.c.state(),
            'boundary': boundary, 'root_metadata': meta(info, '.', 'directory'),
            'inventory': inventory, 'durable': durable, 'observed_at': now()}
        save(self.root / 'prepared.json', prepared)
        state = self.state(); state['phase'] = 'prepared'; state['prepared_sha256'] = sha(enc(prepared)); self.record(state)
        save(self.root / 'prepare-completed.json', {'known_complete': True})

    def prepared(self):
        state = self.state(); value = load(self.root / 'prepared.json')
        need(sha(raw(self.root / 'prepared.json')) == state['prepared_sha256']
             and value['source_sha256'] == self.source_sha and value['controller_sha256'] == CONTROLLER_SHA
             and value['controller_prepared_file_sha256'] == sha(raw(BUNDLE / 'prepared.json')),
             'recovery_prepared_changed')
        return value

    def rotate(self):
        self.approval(); need(self.state()['phase'] == 'prepared', 'recovery_phase')
        prepared = self.prepared(); need(self.guard() == prepared['boundary'], 'cache_boundary_changed')
        need(sha(raw(BUNDLE / 'state.json')) == prepared['withdrawn_state_sha256'], 'withdrawn_state_changed')
        current = inspect_tree(CACHE, self.root / 'pre-rename-cache.jsonl')
        need(current['sha256'] == prepared['inventory']['sha256'], 'cache_changed_after_prepare')
        state = self.state(); state['phase'] = 'rotate_incomplete'; self.record(state)
        def rotate_root():
            need(not ORIGINAL.exists() and not ORIGINAL.is_symlink()
                 and CACHE.stat().st_dev == self.root.stat().st_dev, 'atomic_rotation_preimage')
            os.rename(CACHE, ORIGINAL); sync_dir(CACHE.parent); sync_dir(self.root)
        self.intent('rotate-original-cache', rotate_root)
        def create_and_copy():
            need(not CACHE.exists() and not CACHE.is_symlink(), 'fresh_cache_root_required')
            CACHE.mkdir(mode=0o700)
            os.chown(CACHE, ROOT_UID, ROOT_GID); os.chmod(CACHE, ROOT_MODE)
            copy_git_roots(ORIGINAL, CACHE, prepared['inventory']['git_roots'])
            os.utime(CACHE, ns=(ORIGINAL.stat().st_atime_ns, prepared['root_metadata']['mtime_ns']))
            sync_dir(CACHE); sync_dir(CACHE.parent)
        self.intent('recreate-cache-copy-git', create_and_copy)
        original = inspect_tree(ORIGINAL, self.root / 'preserved-cache.jsonl')
        fresh = inspect_tree(CACHE, self.root / 'fresh-cache.jsonl')
        need(original['sha256'] == prepared['inventory']['sha256'] and fresh['ordinary_files'] == 0
             and fresh['git_roots'] == prepared['inventory']['git_roots']
             and fresh['git_sha256'] == prepared['inventory']['git_sha256'], 'cache_preservation_verification')
        need(self.durable_proof('after-rotation') == prepared['durable'] and self.guard() == prepared['boundary'],
             'rotation_changed_permanent_boundary')
        save(self.root / 'rotation-proof.json', {'original': original, 'fresh': fresh, 'observed_at': now()})
        state = self.state(); state['phase'] = 'rotated'; state['new_root_inode'] = CACHE.stat().st_ino; self.record(state)

    def fence_guard(self, prepared):
        """Prove every boundary while allowing only the known attempted writer."""
        state = self.c.state(); cp = load(BUNDLE / 'prepared.json')
        need(sha(raw(BUNDLE / 'prepared.json')) == prepared['controller_prepared_file_sha256']
             == state['prepared_sha256'], 'fence_prepared_changed')
        self.c.safety(); self.c.admitted_prior(cp['prior_artifacts'], allow_successor=True)
        prior = copy.deepcopy(cp['prior_state'])
        if state['chain_phase'] is not None:
            prior.update(upgrade_successor=str(BUNDLE), upgrade_successor_phase=state['chain_phase'])
        need(load(self.c.prior / 'state.json') == prior, 'fence_predecessor_changed')
        need(self.c.boot() == cp['boot'] and self.c.edge() == cp['edge']
             and self.c.foundation() == cp['foundation']
             and {p: sha(v) for p, v in self.c.profiles().items()} == cp['profiles']
             and self.c.module.read_json(self.c.old.bundle / 'state.json') == cp['old_anchor'], 'fence_protected_runtime_changed')
        need(state['configs'] == 'paused' and state['images']['writer'] == state['images']['backend']
             == self.c.plan['target']['server'], 'fence_target_config_changed')
        configs_raw = raw(BUNDLE / 'configs-paused.json')
        need(sha(configs_raw) == cp['config_hashes']['paused'], 'fence_paused_config_changed')
        expected_secrets = copy.deepcopy(cp['secrets']); configs = json.loads(configs_raw)
        for role, (name, key) in self.c.ROLES.items() if hasattr(self.c, 'ROLES') else (
                ('backend', ('devres-serving-config', 'serving.toml')), ('writer', ('devres-writer-config', 'writer.toml'))):
            expected_secrets[name]['data'][key] = base64.b64encode(configs[role].encode()).decode()
        secrets = json.loads(self.c.old.k('get', 'secrets', '-o', 'json'))['items']
        actual = {v['metadata']['name']: {'uid': v['metadata']['uid'], 'type': v.get('type'),
                  'immutable': v.get('immutable', False), 'data': v.get('data', {})} for v in secrets}
        need(actual == expected_secrets, 'fence_secret_boundary_changed')
        deployments = {}
        for role in ('postgres', 'backend', 'writer'):
            obj = self.c.get('deployment', role)
            spec = copy.deepcopy(obj['spec']); count = spec.pop('replicas', 1)
            image = spec['template']['spec']['containers'][0].pop('image')
            need({'uid': obj['metadata']['uid'], 'spec': spec} == cp['deployments'][role]['projection']
                 and image == state['images'][role]
                 and count in ((0, 1) if role == 'writer' else (1,) if role == 'postgres' else (0,)),
                 'fence_deployment_boundary_changed')
            deployments[role] = obj
        pods = json.loads(self.c.old.k('get', 'pods', '-o', 'json'))['items']
        pg = [p for p in pods if p['metadata'].get('labels', {}).get('app') == 'postgres']
        need(len(pg) == 1, 'fence_postgres_missing')
        value = pg[0]; statuses = value.get('status', {}).get('containerStatuses', [])
        need(len(statuses) == 1 and statuses[0].get('ready') is True
             and statuses[0].get('state', {}).get('running'), 'fence_postgres_not_ready')
        a = statuses[0]
        pg_projection = {'uid': value['metadata']['uid'], 'container_id': a['containerID'], 'image_id': a['imageID'],
            'started_at': a['state']['running']['startedAt'], 'restarts': a['restartCount'],
            'owner': value['metadata'].get('ownerReferences', []), 'name': value['metadata']['name'], 'pod_ip': value['status']['podIP']}
        need(pg_projection == state['pods']['postgres'], 'fence_postgres_changed')
        writers = [p for p in pods if p['metadata'].get('labels', {}).get('app') == 'writer']
        need(len(writers) <= 1 and len(pods) == 1 + len(writers), 'fence_unrelated_pod')
        for pod in writers:
            containers = pod['spec']['containers']; owners = pod['metadata'].get('ownerReferences', [])
            need(len(containers) == 1 and containers[0]['image'] == state['images']['writer']
                 and pod['spec']['nodeName'] == self.c.old.settings()['node_name'] and len(owners) == 1
                 and owners[0].get('kind') == 'ReplicaSet' and owners[0].get('name')
                 and owners[0].get('uid'), 'fence_writer_identity')
            rs = self.c.get('replicaset', owners[0]['name'])
            need(rs['metadata']['uid'] == owners[0]['uid']
                 and len(rs['metadata'].get('ownerReferences', [])) == 1
                 and rs['metadata']['ownerReferences'][0].get('uid') == deployments['writer']['metadata']['uid'],
                 'fence_writer_owner_changed')
        return deployments['writer']

    def fence_failed_writer(self, prepared):
        """Fresh stop intent works even if rollout lost readiness/state adoption."""
        obj = self.fence_guard(prepared)
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
        def stop():
            self.c.old.k('patch', 'deployment', 'writer', '--type=json', '-p', json.dumps(patch))
            self.c.old.k('wait', '--for=delete', 'pod', '-l', 'app=writer', '--timeout=180s', timeout=210, request_timeout=190)
        self.intent('failed-cache-recovery-stop-writer', stop)
        need(set(self.c.pods()) == {'postgres'}, 'failed_writer_still_present')
        state = self.c.state(); state['replicas']['writer'] = 0; state['pods'].pop('writer', None); state['phase'] = 'withdrawn'
        self.c.record(state); self.c.guard()
        need(self.durable_proof('failed-start-preservation') == prepared['durable'], 'failed_start_changed_permanent_data')
        state = self.state(); state['phase'] = 'start_failed_fenced'; self.record(state)

    def start(self):
        self.approval(); need(self.state()['phase'] == 'rotated', 'recovery_phase')
        prepared = self.prepared(); need(self.guard() == prepared['boundary'], 'cache_boundary_changed')
        rotation = load(self.root / 'rotation-proof.json')
        need(CACHE.stat().st_ino == self.state()['new_root_inode']
             and inspect_tree(CACHE, self.root / 'pre-start-cache.jsonl')['sha256'] == rotation['fresh']['sha256'], 'fresh_cache_changed')
        need(self.durable_proof('before-start') == prepared['durable'], 'prestart_permanent_data_changed')
        state = self.state(); state['phase'] = 'start_incomplete'; self.record(state)
        try:
            self.intent('start-same-target-writer', lambda: self.c.scale('writer', 1, 'cache-recovery-start-writer'))
            need(self.durable_proof('after-start', stopped=False) == prepared['durable'], 'startup_changed_permanent_data')
            need(inspect_tree(ORIGINAL, self.root / 'post-start-original-cache.jsonl')['sha256']
                 == prepared['inventory']['sha256'], 'startup_changed_preserved_cache')
            self.c.guard()
            state = self.c.state(); need(state['phase'] == 'withdrawn' and set(state['pods']) == {'postgres', 'writer'}, 'target_writer_ready_required')
            save(self.root / 'forward-phase-intent.json', {'version': 1, 'old_phase': 'withdrawn', 'new_phase': 'writer_ready',
                 'source_sha256': self.source_sha, 'prepared_sha256': prepared['controller_prepared_sha256'], 'observed_at': now()})
            state['phase'] = 'writer_ready'; self.c.record(state); self.c.guard()
            save(self.root / 'forward-phase-completed.json', {'known_complete': True})
            state = self.state(); state['phase'] = 'writer_ready'; self.record(state)
        except Exception:
            self.fence_failed_writer(prepared)
            raise Stop('cache_recovery_writer_start_failed_fenced') from None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--controller', type=Path, default=CONTROLLER)
    parser.add_argument('--approval', type=Path, required=True)
    parser.add_argument('--approval-sha256', required=True)
    parser.add_argument('operation', choices=('prepare', 'rotate', 'start'))
    args = parser.parse_args()
    try:
        need(os.geteuid() == 0 and args.controller == CONTROLLER, 'fixed_root_controller_required')
        module = module_at('cache_recovery_controller', args.controller, CONTROLLER_SHA)
        checkpoint = module_at('cache_recovery_checkpoint', CHECKPOINT, CHECKPOINT_SHA)
        controller = module.Controller(str(BUNDLE), BUNDLE / 'plan.json', 'default')
        recovery = Recovery(controller, checkpoint, args.approval, args.approval_sha256)
        with controller.locked(): getattr(recovery, args.operation)()
        print(json.dumps({'known_complete': True, 'operation': args.operation, 'phase': recovery.state()['phase']}))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, Stop) and re.fullmatch('[a-z0-9_]+', str(error)) else 'cache_recovery_failed'
        print(json.dumps({'known_complete': False, 'operation': args.operation, 'code': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
