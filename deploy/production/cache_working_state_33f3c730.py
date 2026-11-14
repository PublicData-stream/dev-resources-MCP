#!/usr/bin/env python3
"""Preserve both cache generations and restore complete owned working state.

Only the fixed known working/projection directories are copied. Canonical body
materializations and their disposable integrity descriptors remain cold. Nothing
executes copied data, invents ownership, edits old journals, or restores SQL/S3.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

BUNDLE = Path('/var/lib/devres-production-upgrades/33f3c730-20261114')
ROOT = BUNDLE / 'cache-working-state-recovery'
PREVIOUS = BUNDLE / 'cache-recovery'
ORIGINAL = PREVIOUS / 'writer-original'
CACHE = Path('/var/cache/devres/writer')
FAILED = ROOT / 'failed-generation'
CONTROLLER = Path('/usr/local/libexec/devres-upgrade-33f3c730/upgrade-controller.py')
CONTROLLER_SHA = '2b18ea9ee326eabbafa1398f0f065c639b9e70fe01962cca31e6d8fc86365a6e'
LEGACY = Path('/usr/local/libexec/devres-upgrade-33f3c730/cache-resume.py')
LEGACY_SHA = '0d105ebd3cbf7a0967d621e589fb43188bbace4aea880612f41057ce3292ff74'
CHECKPOINT = Path('/usr/local/libexec/devres-upgrade-33f3c730/physical-checkpoint.py')
CHECKPOINT_SHA = '25ce3324cad52cd6018e3411e169119bbbb18652bc1901138780b55f758c1501'
START_INODE = 12745248
FAILED_SHA = '34179cd505575e8efce4f9a044b62d21eb8ecb110db25ed2183462e463a9fca1'
STARTUP_ADDED_ENTRIES = 20
TOP = frozenset(('.devres-integrity', 'blake3', 'chromium', 'chromium-search', 'crate-git',
    'mdn', 'mdn-indexes', 'npm', 'npm-search', 'rfc-indexes', 'rustsec-history', 'w3c',
    'w3c-search', 'whatwg', 'whatwg-search', 'wikipedia'))
RESTORE = TOP - {'.devres-integrity', 'blake3'}
EXPECTED_ORDINARY = 84087
MAX_ORDINARY = 131072
EXPECTED_GIT = 32
EXPECTED_WHATWG = 28


class Stop(RuntimeError):
    pass


def need(value, code):
    if not value: raise Stop(code)


def enc(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def sha(value): return hashlib.sha256(value).hexdigest()


def small_data(path, maximum=8192):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'ownership_regular_file_required')
        value = stream.read(maximum + 1)
        need(len(value) == info.st_size, 'ownership_file_changed')
    return value


def owners(root, git_roots, legacy):
    """Reproduce the exact target's retained-parent ownership requirements."""
    need(len(git_roots) == EXPECTED_GIT, 'retained_git_root_count')
    counts = {'mdn': 0, 'whatwg': 0, 'rustsec-history': 0, 'crate-git': 0}
    for name in git_roots:
        relative = legacy.safe_relative(name); parts = relative.parts
        parent = root / relative.parent
        legacy.no_symlinks(parent)
        need(parent.is_dir() and (root / relative).is_dir() and not (root / relative).is_symlink(), 'retained_git_real_directory')
        family = parts[0]
        if family == 'mdn':
            need(len(parts) == 3 and parts[1] in ('content', 'compat') and parts[2] == 'history.git', 'mdn_retained_parent')
            marker = b'devres-mdn-' + parts[1].encode() + b'-v1\n'
        elif family == 'whatwg':
            need(len(parts) == 5 and parts[1] == 'git' and parts[-1] == 'history.git'
                 and all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', p) for p in parts[2:4]), 'whatwg_retained_parent')
            marker = ('devres-whatwg-' + parts[2] + '/' + parts[3] + '-v1\n').encode()
        elif family == 'rustsec-history':
            need(parts == ('rustsec-history', 'history.git'), 'rustsec_retained_parent')
            marker = b'devres-rustsec-history-v1\n'
        elif family == 'crate-git':
            need(parts == ('crate-git', 'registry.git'), 'registry_retained_parent')
            need(small_data(parent / '.devres-git-owned') == b'devres registry git v1\n', 'registry_ownership_mismatch')
            counts[family] += 1
            continue
        else:
            raise Stop('unlisted_retained_git_family')
        need(small_data(parent / 'owner-v1') == marker, 'retained_ownership_mismatch')
        artifacts = parent / 'artifacts'
        need(artifacts.is_dir() and not artifacts.is_symlink(), 'registered_artifacts_directory_required')
        counts[family] += 1
    whatwg_root = root / 'whatwg/git'
    need(whatwg_root.is_dir() and not whatwg_root.is_symlink(), 'whatwg_registration_root')
    registered = 0
    def entries(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME)
        try:
            with os.scandir(fd) as listing:
                return [(e.name, e.is_dir(follow_symlinks=False)) for e in listing]
        finally: os.close(fd)
    owner_dirs = entries(whatwg_root)
    need(len(owner_dirs) <= 4096, 'whatwg_owner_bound')
    for owner_name, real_owner in owner_dirs:
        need(real_owner and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', owner_name), 'whatwg_owner_identity')
        for repo_name, real_repo in entries(whatwg_root / owner_name):
            registered += 1; need(registered <= 4096, 'whatwg_repository_bound')
            need(real_repo and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', repo_name), 'whatwg_repository_identity')
            parent = whatwg_root / owner_name / repo_name
            expected = ('devres-whatwg-' + owner_name + '/' + repo_name + '-v1\n').encode()
            need(small_data(parent / 'owner-v1') == expected, 'registered_whatwg_ownership_mismatch')
            need((parent / 'artifacts').is_dir() and not (parent / 'artifacts').is_symlink(), 'registered_whatwg_artifacts_missing')
    need(counts == {'mdn': 2, 'whatwg': EXPECTED_WHATWG, 'rustsec-history': 1, 'crate-git': 1}, 'retained_parent_coverage')
    return counts


def working_fingerprint(manifest):
    digest = hashlib.sha256(); roots = set(); files = 0; total = 0; ordinary = 0
    with manifest.open('rb') as source:
        for line in source:
            need(len(line) <= 16384, 'inventory_line_bound')
            row = json.loads(line)
            if row['path'] == '.': continue
            parts = PurePosixPath(row['path']).parts
            if len(parts) == 1:
                need(row['kind'] == 'directory', 'top_level_directory_required')
                roots.add(parts[0])
            if parts[0] not in RESTORE: continue
            logical = {k: v for k, v in row.items() if k not in ('device', 'inode', 'links')}
            digest.update(enc(logical) + b'\n')
            if row['kind'] == 'file':
                files += 1; total += row['bytes']
                if not any(p in ('history.git', 'registry.git') for p in parts): ordinary += 1
    return {'sha256': digest.hexdigest(), 'files': files, 'bytes': total, 'ordinary_files': ordinary, 'top': sorted(roots)}


def copy_working(source, destination, legacy):
    """Copy all fixed working families to distinct inodes without following links."""
    directories = []
    def visit(relative):
        src, dst = source / relative, destination / relative
        legacy.no_symlinks(src); before = src.lstat()
        need(stat.S_ISDIR(before.st_mode), 'working_source_directory_required')
        dst.mkdir(mode=0o700)
        directories.append(relative)
        fd = os.open(src, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME)
        try:
            with os.scandir(fd) as it: names = sorted((e.name for e in it), key=os.fsencode)
        finally: os.close(fd)
        for name in names:
            child = relative / name; legacy.safe_relative(child.as_posix())
            old, new = source / child, destination / child; info = old.lstat()
            need(not stat.S_ISLNK(info.st_mode), 'working_symlink_refused')
            if stat.S_ISDIR(info.st_mode): visit(child)
            else:
                need(stat.S_ISREG(info.st_mode), 'working_special_file_refused')
                srcfd = os.open(old, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
                try: dstfd = os.open(new, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                except Exception:
                    os.close(srcfd); raise
                with os.fdopen(srcfd, 'rb') as a, os.fdopen(dstfd, 'wb') as b:
                    while block := a.read(1024**2): b.write(block)
                    b.flush(); os.fchown(b.fileno(), info.st_uid, info.st_gid)
                    os.fchmod(b.fileno(), stat.S_IMODE(info.st_mode))
                    os.utime(b.fileno(), ns=(info.st_atime_ns, info.st_mtime_ns)); os.fsync(b.fileno())
                    new_info = os.fstat(b.fileno())
                    need((new_info.st_dev, new_info.st_ino) != (info.st_dev, info.st_ino), 'working_copy_inode_alias')
    for name in sorted(RESTORE):
        need((source / name).is_dir() and not (source / name).is_symlink(), 'working_family_missing')
        visit(PurePosixPath(name))
    for relative in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        info = (source / relative).lstat(); target = destination / relative
        os.chown(target, info.st_uid, info.st_gid, follow_symlinks=False)
        os.chmod(target, stat.S_IMODE(info.st_mode), follow_symlinks=False)
        os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns), follow_symlinks=False)
        legacy.sync_dir(target)
    legacy.sync_dir(destination)


class Recovery:
    def __init__(self, controller, checkpoint, legacy, approval, approval_sha):
        self.c, self.checkpoint, self.legacy = controller, checkpoint, legacy
        self.root, self.approval_path, self.approval_sha = ROOT, Path(approval), approval_sha
        self.source_sha = sha(Path(__file__).read_bytes())
        self.base = legacy.Recovery(controller, checkpoint, approval, approval_sha)
        self.base.root = self.root; self.base.source_sha = self.source_sha

    def state(self): return self.base.state()
    def record(self, value): self.base.record(value)

    def approval(self):
        raw = self.legacy.raw(self.approval_path)
        need(sha(raw) == self.approval_sha, 'working_approval_hash')
        before = self.legacy.load(self.root / 'prepared.json') if self.root.exists() else None
        expected = {'version': 1, 'kind': 'preserving-writer-working-state-recovery', 'approved': True,
            'source_sha256': self.source_sha, 'controller_sha256': CONTROLLER_SHA, 'previous_recovery_sha256': LEGACY_SHA,
            'controller_prepared_sha256': self.c.state()['prepared_sha256'],
            'previous_recovery_state_sha256': before['previous_state_sha256'] if before else sha(self.legacy.raw(PREVIOUS / 'state.json')),
            'withdrawn_state_sha256': before['withdrawn_state_sha256'] if before else sha(self.legacy.raw(BUNDLE / 'state.json')),
            'operations': ['prepare', 'restore', 'start'], 'maximum_restores': 1, 'maximum_start_attempts': 1,
            'preserve_all_previous_generations': True, 'new_permanent_mutations': False}
        need(json.loads(raw) == expected, 'working_approval_binding')

    def previous(self, expected=None):
        state_raw = self.legacy.raw(PREVIOUS / 'state.json'); state = json.loads(state_raw)
        prepared_raw = self.legacy.raw(PREVIOUS / 'prepared.json'); prepared = json.loads(prepared_raw)
        rotation_raw = self.legacy.raw(PREVIOUS / 'rotation-proof.json'); rotation = json.loads(rotation_raw)
        need(state['phase'] == 'start_failed_fenced' and state['source_sha256'] == LEGACY_SHA
             and state['prepared_sha256'] == sha(prepared_raw)
             and prepared['controller_sha256'] == CONTROLLER_SHA
             and prepared['controller_prepared_file_sha256'] == sha(self.legacy.raw(BUNDLE / 'prepared.json')),
             'previous_recovery_identity')
        need(self.legacy.file_sha(Path(prepared['inventory']['manifest'])) == prepared['inventory']['sha256'], 'original_inventory_changed')
        binding = {'state': sha(state_raw), 'prepared': sha(prepared_raw), 'rotation': sha(rotation_raw)}
        need(expected is None or expected == binding, 'previous_recovery_history_changed')
        return binding, prepared, rotation

    def prepare(self):
        need(not self.root.exists(), 'fresh_working_recovery_required')
        self.approval(); boundary = self.base.guard()
        binding, previous, rotation = self.previous()
        info = CACHE.lstat()
        need(stat.S_ISDIR(info.st_mode) and not CACHE.is_symlink() and not os.path.ismount(CACHE)
             and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_dev, info.st_ino)
             == (self.legacy.ROOT_UID, self.legacy.ROOT_GID, self.legacy.ROOT_MODE, self.legacy.ROOT_DEVICE, START_INODE),
             'failed_generation_root_identity')
        self.root.mkdir(mode=0o700); self.legacy.sync_dir(BUNDLE)
        self.legacy.save(self.root / 'state.json', {'version': 1, 'phase': 'preparing',
            'source_sha256': self.source_sha, 'approval_sha256': self.approval_sha})
        self.legacy.save(self.root / 'prepare-intent.json', {'version': 1, 'maximum_attempts': 1})
        original = self.legacy.inspect_tree(ORIGINAL, self.root / 'original-cache.jsonl')
        failed = self.legacy.inspect_tree(CACHE, self.root / 'failed-cache.jsonl')
        need(original['sha256'] == previous['inventory']['sha256'], 'original_generation_changed')
        # The failed target eagerly created twenty empty registration directories.
        # Bind its explicitly inspected post-failure generation, while proving all
        # file bytes and mutable Git state remain those of the first rotation.
        need(failed['sha256'] == FAILED_SHA and failed['ordinary_files'] == 0
             and failed['files'] == rotation['fresh']['files'] and failed['bytes'] == rotation['fresh']['bytes']
             and failed['git_sha256'] == rotation['fresh']['git_sha256']
             and failed['entries'] == rotation['fresh']['entries'] + STARTUP_ADDED_ENTRIES, 'failed_generation_changed')
        working = working_fingerprint(Path(original['manifest']))
        need(set(working['top']) == TOP, 'fixed_working_family_boundary')
        ordinary = working['ordinary_files']
        need(ordinary == EXPECTED_ORDINARY and ordinary < MAX_ORDINARY, 'working_file_headroom')
        owner_proof = owners(ORIGINAL, original['git_roots'], self.legacy)
        need(self.legacy.shutil.disk_usage(CACHE).free >= self.legacy.RESERVE + working['bytes'], 'working_copy_capacity')
        durable = self.base.durable_proof('before')
        need(durable == previous['durable'] and self.base.guard() == boundary, 'permanent_boundary_changed')
        prepared = {'version': 1, 'source_sha256': self.source_sha, 'controller_sha256': CONTROLLER_SHA,
            'controller_prepared_file_sha256': sha(self.legacy.raw(BUNDLE / 'prepared.json')),
            'controller_prepared_sha256': self.c.state()['prepared_sha256'], 'previous_state_sha256': binding['state'],
            'previous_binding': binding, 'withdrawn_state_sha256': sha(self.legacy.raw(BUNDLE / 'state.json')),
            'original': original, 'failed': failed, 'working': working, 'ordinary_files': ordinary,
            'owner_proof': owner_proof, 'boundary': boundary, 'durable': durable}
        self.legacy.save(self.root / 'prepared.json', prepared)
        state = self.state(); state.update(phase='prepared', prepared_sha256=sha(enc(prepared))); self.record(state)
        self.legacy.save(self.root / 'prepare-completed.json', {'known_complete': True})

    def prepared(self):
        value = self.base.prepared(); self.previous(value['previous_binding'])
        return value

    def restore(self):
        self.approval(); need(self.state()['phase'] == 'prepared', 'working_phase')
        prepared = self.prepared(); need(self.base.guard() == prepared['boundary'], 'working_boundary_changed')
        need(sha(self.legacy.raw(BUNDLE / 'state.json')) == prepared['withdrawn_state_sha256'], 'withdrawn_state_changed')
        original = self.legacy.inspect_tree(ORIGINAL, self.root / 'pre-restore-original.jsonl')
        failed = self.legacy.inspect_tree(CACHE, self.root / 'pre-restore-failed.jsonl')
        need(original['sha256'] == prepared['original']['sha256'] and failed['sha256'] == prepared['failed']['sha256'],
             'previous_generation_changed')
        state = self.state(); state['phase'] = 'restore_incomplete'; self.record(state)
        def retain():
            need(not FAILED.exists() and CACHE.stat().st_dev == self.root.stat().st_dev, 'same_filesystem_preservation')
            os.rename(CACHE, FAILED); self.legacy.sync_dir(CACHE.parent); self.legacy.sync_dir(self.root)
        self.base.intent('retain-first-failed-generation', retain)
        def restore():
            need(not CACHE.exists() and not CACHE.is_symlink(), 'fresh_working_cache_required')
            CACHE.mkdir(mode=0o700)
            os.chown(CACHE, self.legacy.ROOT_UID, self.legacy.ROOT_GID); os.chmod(CACHE, self.legacy.ROOT_MODE)
            copy_working(ORIGINAL, CACHE, self.legacy)
            self.legacy.sync_dir(CACHE); self.legacy.sync_dir(CACHE.parent)
        self.base.intent('restore-complete-working-state', restore)
        actual = self.legacy.inspect_tree(CACHE, self.root / 'restored-cache.jsonl')
        restored = working_fingerprint(Path(actual['manifest']))
        need(set(restored['top']) == RESTORE and restored['sha256'] == prepared['working']['sha256']
             and actual['ordinary_files'] == EXPECTED_ORDINARY and actual['ordinary_files'] < MAX_ORDINARY,
             'complete_working_state_mismatch')
        need(owners(CACHE, actual['git_roots'], self.legacy) == prepared['owner_proof'], 'restored_ownership_mismatch')
        self.verify_preserved('after-restore', prepared)
        need(self.base.durable_proof('after-restore') == prepared['durable']
             and self.base.guard() == prepared['boundary'], 'restore_changed_permanent_boundary')
        self.legacy.save(self.root / 'restoration-proof.json', actual)
        state = self.state(); state.update(phase='restored', new_root_inode=CACHE.stat().st_ino); self.record(state)

    def verify_preserved(self, label, prepared):
        for name, source, expected in (('original', ORIGINAL, prepared['original']['sha256']),
                                       ('failed', FAILED, prepared['failed']['sha256'])):
            current = self.legacy.inspect_tree(source, self.root / (label + '-' + name + '.jsonl'))
            need(current['sha256'] == expected, 'preserved_generation_changed')

    def fence(self, prepared):
        obj = self.base.fence_guard(prepared)
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                 {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                 {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
        def stop():
            self.c.old.k('patch', 'deployment', 'writer', '--type=json', '-p', json.dumps(patch))
            self.c.old.k('wait', '--for=delete', 'pod', '-l', 'app=writer', '--timeout=180s', timeout=210, request_timeout=190)
        self.base.intent('failed-working-state-stop-writer', stop)
        need(set(self.c.pods()) == {'postgres'}, 'working_writer_remaining')
        state = self.c.state(); state['replicas']['writer'] = 0; state['pods'].pop('writer', None); state['phase'] = 'withdrawn'
        self.c.record(state); self.c.guard()
        need(self.base.durable_proof('failed-start-preservation') == prepared['durable'], 'failed_start_permanent_change')
        self.verify_preserved('failed-start', prepared)
        state = self.state(); state['phase'] = 'start_failed_fenced'; self.record(state)

    def start(self):
        self.approval(); need(self.state()['phase'] == 'restored', 'working_phase')
        prepared = self.prepared(); need(self.base.guard() == prepared['boundary'], 'working_boundary_changed')
        actual = self.legacy.inspect_tree(CACHE, self.root / 'pre-start-working.jsonl')
        need(actual['sha256'] == self.legacy.load(self.root / 'restoration-proof.json')['sha256']
             and CACHE.stat().st_ino == self.state()['new_root_inode'], 'restored_generation_changed')
        need(set(working_fingerprint(Path(actual['manifest']))['top']) == RESTORE, 'restored_top_level_changed')
        owners(CACHE, actual['git_roots'], self.legacy)
        need(self.base.durable_proof('before-start') == prepared['durable'], 'prestart_permanent_change')
        state = self.state(); state['phase'] = 'start_incomplete'; self.record(state)
        try:
            self.base.intent('start-working-state-writer', lambda:
                self.c.scale('writer', 1, 'cache-working-state-start-writer'))
            need(self.base.durable_proof('after-start', stopped=False) == prepared['durable'], 'startup_permanent_change')
            self.verify_preserved('after-start', prepared)
            self.c.guard(); state = self.c.state()
            need(state['phase'] == 'withdrawn' and set(state['pods']) == {'postgres', 'writer'}, 'working_writer_not_ready')
            self.legacy.save(self.root / 'forward-phase-intent.json', {'version': 1, 'source_sha256': self.source_sha,
                'old_phase': 'withdrawn', 'new_phase': 'writer_ready'})
            state['phase'] = 'writer_ready'; self.c.record(state); self.c.guard()
            self.legacy.save(self.root / 'forward-phase-completed.json', {'known_complete': True})
            state = self.state(); state['phase'] = 'writer_ready'; self.record(state)
        except Exception:
            self.fence(prepared)
            raise Stop('working_state_start_failed_fenced') from None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--approval', type=Path, required=True)
    parser.add_argument('--approval-sha256', required=True)
    parser.add_argument('operation', choices=('prepare', 'restore', 'start'))
    args = parser.parse_args()
    try:
        need(os.geteuid() == 0, 'root_required')
        need(not any(p.is_symlink() for p in (LEGACY, *LEGACY.parents)), 'previous_source_symlink')
        fd = os.open(LEGACY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                 and not info.st_mode & 0o022 and info.st_size <= 1024**2, 'previous_source_permissions')
            source = stream.read(1024**2 + 1)
        need(sha(source) == LEGACY_SHA, 'frozen_previous_source_changed')
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location('frozen_cache_recovery_0d105', LEGACY)
        legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)
        # Revalidate ownership and permissions using the now-qualified pure reader.
        need(sha(legacy.raw(LEGACY, source=True)) == LEGACY_SHA, 'frozen_previous_source_changed')
        controller_module = legacy.module_at('working_state_controller', CONTROLLER, CONTROLLER_SHA)
        checkpoint = legacy.module_at('working_state_checkpoint', CHECKPOINT, CHECKPOINT_SHA)
        controller = controller_module.Controller(str(BUNDLE), BUNDLE / 'plan.json', 'default')
        recovery = Recovery(controller, checkpoint, legacy, args.approval, args.approval_sha256)
        with controller.locked(): getattr(recovery, args.operation)()
        print(json.dumps({'known_complete': True, 'operation': args.operation, 'phase': recovery.state()['phase']}))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, Stop) and re.fullmatch('[a-z0-9_]+', str(error)) else 'working_state_recovery_failed'
        print(json.dumps({'known_complete': False, 'operation': args.operation, 'code': code}), file=sys.stderr)
        return 1


if __name__ == '__main__': raise SystemExit(main())
