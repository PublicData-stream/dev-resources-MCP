#!/usr/bin/env python3
"""One guarded physical schema18 restore; original immutable S3 is never rewound.

The caller subsequently prepares and qualifies fallback91. Post-task SQL preservation
is best effort, while identity, exclusivity and golden-checkpoint proof are mandatory.
"""
import argparse
import contextlib
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
WORK = Path('/tmp/devres-upgrade-1d76fbcc-20261115')
BUNDLE = Path('/var/lib/devres-production-upgrades/1d76fbcc-20261115')
CONTROLLER = Path('/usr/local/libexec/devres-upgrade-1d76fbcc/upgrade-controller.py')
CHECKPOINT = CONTROLLER.with_name('physical-checkpoint.py')
REVISION = '1d76fbcc5693efc9ca927fd05f942078f667f056'
RESERVE = 128 * 1024**3

class Stop(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Stop(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def sha(body):
    return hashlib.sha256(body).hexdigest()

def private_read(path, maximum=1024**3):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'private_source_symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        meta = os.fstat(f.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid() and meta.st_nlink == 1
             and not meta.st_mode & 0o077 and meta.st_size <= maximum, 'unsafe_private_source')
        body = f.read(maximum + 1)
    need(len(body) == meta.st_size, 'source_changed')
    return body

def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def private_dir(path):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'restore_directory_symlink')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
         'private_restore_directory_required')

def save(path, value, replace=False):
    private_dir(path.parent)
    target = path.with_name('.' + path.name + '.tmp') if replace else path
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(encoded(value)); f.flush(); os.fsync(f.fileno())
    if replace:
        os.replace(target, path)
    sync(path.parent)

def load(path):
    return json.loads(private_read(path))

def checked_module(path, expected, name):
    need(re.fullmatch('[0-9a-f]{64}', expected or '') and sha(private_read(path)) == expected,
         'pinned_module_changed')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def tree_identity(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and not path.is_symlink(), 'database_directory_required')
    return {'device': info.st_dev, 'inode': info.st_ino}

def maybe_identity(path):
    return tree_identity(path) if path.exists() else None

def manifest(cp, path):
    rows, size = cp.scan_tree(path, True)
    return {'sha256': sha(b''.join(encoded(row) + b'\n' for row in rows)), 'bytes': size, 'files': len(rows)}

def checked_golden(cp):
    cp.disk_identity()
    completed = cp.load('completed.json')
    checkpoint = cp.load('checkpoint-completed.json')
    need(completed['revision'] == REVISION and completed['schema'] == 18
         and completed['old_clone_verified'] is True and completed['fallback_writer_verified'] is True
         and completed['original_s3_retained'] is True and completed['independent_s3_backup'] is False,
         'verified_current_schema18_checkpoint_required')
    need(completed['checkpoint_receipt_sha256'] == sha(cp.raw(cp.S / 'checkpoint-completed.json'))
         and completed['clone_proof_sha256'] == sha(cp.raw(cp.S / 'clone-proof-result.json')),
         'golden_proof_changed')
    cache_data = cp.raw(cp.S / 'cache-baselines.json', cp.MAX_MANIFEST)
    need(sha(cache_data) == completed['cache_baselines_sha256'], 'golden_cache_manifest_changed')
    for role, expected in json.loads(cache_data)['manifests'].items():
        need(role in ('serving', 'writer') and cp.cache_manifest(cp.S / 'fallback-cache' / role) == expected,
             'golden_cache_changed')
    for name, key in (('archive-bindings.jsonl', 'manifest_sha256'), ('capture-bindings.jsonl', 'capture_manifest_sha256'),
                      ('pg-file-manifest.jsonl', 'pg_files_sha256')):
        need(sha(cp.raw(cp.S / name, cp.MAX_MANIFEST)) == completed[key], 'golden_manifest_changed')
    golden = cp.S / 'pg-checkpoint'
    need(manifest(cp, golden)['sha256'] == completed['pg_files_sha256']
         and checkpoint['pg_files_sha256'] == completed['pg_files_sha256'], 'golden_database_changed')
    cp.control(golden, cp.image_id(cp.PG))
    return completed

class Restore:
    def __init__(self, cp, controller, root=None):
        self.cp, self.c = cp, controller
        self.root = Path(root) if root is not None else BUNDLE / 'restore'
        self.baseline = cp.load('baseline.json')
        self.source = Path(self.baseline['layout']['source'])
        need(self.source == cp.PV / '18/docker', 'qualified_original_pgdata_path_required')
        self.golden = cp.S / 'pg-checkpoint'

    def record(self, state):
        save(self.root / 'state.json', state, replace=(self.root / 'state.json').exists())

    def state(self):
        value = load(self.root / 'state.json')
        need(value['revision'] == REVISION and value['source'] == str(self.source)
             and value['source_sha256'] == sha(Path(__file__).read_bytes()), 'restore_journal_changed')
        need(re.fullmatch('[0-9a-f]{24}', value['token']), 'restore_token_required')
        return value

    def receipt(self, name, value):
        path = self.root / name
        if path.exists():
            need(load(path) == value, 'existing_restore_receipt_changed')
        else:
            save(path, value)

    def paths(self, state):
        token = state['token']
        return self.source.with_name('.restore-' + token), self.source.with_name('.failed-' + token)

    def guard(self, stage):
        self.c.restore_guard(stage=stage)
        self.cp.roles_stopped()
        layout = self.baseline['layout']
        pvc = self.cp.get('pvc', layout['pvc_name'])
        pv = self.cp.get('pv', layout['pv_name'])
        need(pvc['metadata']['uid'] == layout['pvc_uid'] and pvc['spec']['volumeName'] == layout['pv_name']
             and pv['metadata']['uid'] == layout['pv_uid'] and pv['spec'].get('local', {}).get('path') == str(self.cp.PV),
             'original_pv_or_layout_changed')
        need(not any(p.is_symlink() for p in (self.source, *self.source.parents)), 'pgdata_symlink_refused')

    def checked_current(self):
        value = self.cp.schema_identity()
        need(value['system_id'] == self.cp.SYSID and value['schema'] in (18, 19)
             and not value['recovery'] and value['external_tablespaces'] == 0
             and value['publication_owners'] == 0, 'current_database_identity_or_owner_changed')
        need(value['archive'] == self.baseline['identity']['archive'], 'original_s3_archive_binding_changed')
        need(value['attribution']['control']['data'] == self.cp.POLICY, 'attribution_policy_changed')
        return value

    def admit(self, pins):
        need(not self.root.exists() and not self.root.is_symlink(), 'single_restore_attempt_required')
        self.guard('admit')
        controller_state = self.c.state()
        intent = load(self.c.root / 'rollback-intent.json')
        need(controller_state['runtime'] == 'target' and controller_state['phase'] == 'withdrawn'
             and intent['source_sha256'] == pins['controller'] and intent['maximum_attempts'] == 1,
             'withdrawn_target_single_rollback_intent_required')
        self.checked_current()
        golden = checked_golden(self.cp)
        need(shutil.disk_usage(self.source.parent).free >= golden_size(self.cp) + RESERVE,
             'restore_staging_headroom_required')
        self.root.mkdir(mode=0o700)
        sync(self.root.parent)
        private_dir(self.root)
        state = {'revision': REVISION, 'source_sha256': sha(Path(__file__).read_bytes()),
                 'pins': pins, 'phase': 'admitted', 'token': os.urandom(12).hex(),
                 'source': str(self.source), 'original_identity': tree_identity(self.source),
                 'golden_sha256': golden['pg_files_sha256'], 'preservation': 'not_attempted'}
        self.record(state)
        return state

    def stage(self, state):
        staging, _ = self.paths(state)
        self.guard('stage')
        need(tree_identity(self.source) == state['original_identity'], 'live_pgdata_identity_changed')
        checked_golden(self.cp)
        if 'staging_identity' not in state:
            self.receipt('stage-create-intent.json', {'path': str(staging), 'token': state['token']})
            need(not staging.exists() and not staging.is_symlink(), 'fresh_restore_staging_required')
            staging.mkdir(mode=0o700)
            sync(staging.parent)
            state['staging_identity'] = tree_identity(staging)
            self.record(state)
        need(tree_identity(staging) == state['staging_identity']
             and staging.stat().st_dev == self.source.stat().st_dev, 'same_filesystem_owned_staging_required')
        self.receipt('stage-copy-intent.json', {'golden_sha256': state['golden_sha256'], 'staging_identity': state['staging_identity']})
        result = subprocess.run(['/usr/bin/rsync', '-aHAX', '--checksum', '--numeric-ids', '--one-file-system',
                                 '--no-devices', '--no-specials', '--delete', '--', str(self.golden) + '/', str(staging) + '/'],
                                capture_output=True, timeout=1800)
        need(result.returncode == 0, 'restore_stage_copy_failed')
        need(manifest(self.cp, staging)['sha256'] == state['golden_sha256'], 'restore_stage_hash_changed')
        flush_tree(self.cp, staging)
        self.cp.control(staging, self.cp.image_id(self.cp.PG))
        state['phase'] = 'staged'; self.record(state)

    def stop(self, state):
        self.guard('stop')
        current = self.checked_current()
        self.receipt('pre-restore-identity.json', current)
        self.receipt('stop-postgres-intent.json', {'token': state['token'], 'original_identity': state['original_identity']})
        self.cp.k('scale', 'deployment/postgres', '--replicas=0')
        self.cp.k('wait', '--for=delete', 'pod', '-l', 'app=postgres', '--timeout=180s', timeout=210)
        self.cold_guard(state)
        state['phase'] = 'stopped'; self.record(state)

    def cold_guard(self, state):
        self.guard('cold')
        need(self.cp.get('deployment', 'postgres')['spec'].get('replicas') == 0
             and not self.cp.role_pods('postgres'), 'postgres_must_be_stopped')
        need(not (self.source / 'postmaster.pid').exists(), 'postgres_pid_remains')
        self.cp.control(self.source, self.cp.image_id(self.cp.PG))
        need(tree_identity(self.source) == state['original_identity'], 'stopped_pgdata_identity_changed')

    def preserve_and_install(self, state):
        staging, preserved = self.paths(state)
        self.cold_guard(state)
        need(tree_identity(staging) == state['staging_identity']
             and manifest(self.cp, staging)['sha256'] == state['golden_sha256'], 'verified_staging_changed')
        checked_golden(self.cp)
        if 'preservation' not in state or state['preservation'] == 'not_attempted':
            try:
                info = manifest(self.cp, self.source)
                self.receipt('post-task-database-manifest.json', info)
                state['preservation'] = 'manifest_verified'
            except Exception:
                state['preservation'] = 'manifest_incomplete'
            self.record(state)
        self.receipt('rename-original-intent.json', {'from': str(self.source), 'to': str(preserved),
                                                   'original_identity': state['original_identity']})
        need(not preserved.exists() and not preserved.is_symlink(), 'fresh_preserved_path_required')
        try:
            os.rename(self.source, preserved)
            sync(self.source.parent)
            need(tree_identity(preserved) == state['original_identity'], 'preserved_database_identity_changed')
            state['preserved_directory'] = True
        except OSError:
            # An uncertain rename is reconciled before considering best-effort loss.
            if maybe_identity(preserved) == state['original_identity'] and not self.source.exists():
                state['preserved_directory'] = True
            else:
                need(maybe_identity(self.source) == state['original_identity'] and not preserved.exists(),
                     'original_rename_outcome_uncertain')
                # Explicitly authorized loss fallback: deletion is restricted to the
                # exact cold PGDATA inode after rejecting external mounts/symlinks.
                self.cp.scan_tree(self.source)
                need(no_nested_mounts(self.source), 'pgdata_nested_mount_refused')
                self.receipt('discard-original-intent.json', {'path': str(self.source), 'identity': state['original_identity'],
                                                             'accepted_post_task_sql_loss': True})
                shutil.rmtree(self.source)
                sync(self.source.parent)
                state['preserved_directory'] = False
                state['preservation'] = 'post_task_sql_lost'
        state['phase'] = 'original_removed'; self.record(state)
        self.install(state)

    def install(self, state):
        staging, _ = self.paths(state)
        self.guard('install')
        need(not self.cp.role_pods('postgres') and self.cp.get('deployment', 'postgres')['spec'].get('replicas') == 0,
             'postgres_must_be_stopped')
        need(not self.source.exists() and not self.source.is_symlink()
             and tree_identity(staging) == state['staging_identity'], 'install_directory_preimage_changed')
        need(manifest(self.cp, staging)['sha256'] == state['golden_sha256'], 'verified_staging_changed')
        self.receipt('install-checkpoint-intent.json', {'staging_identity': state['staging_identity'], 'golden_sha256': state['golden_sha256']})
        os.rename(staging, self.source); sync(self.source.parent)
        state['phase'] = 'installed'; self.record(state)

    def restart(self, state):
        need(state['phase'] == 'caches_restored', 'baseline_caches_must_be_restored_before_pg_restart')
        self.guard('restart')
        need(tree_identity(self.source) == state['staging_identity'], 'installed_directory_identity_changed')
        if not (self.root / 'restart-postgres-intent.json').exists():
            need(manifest(self.cp, self.source)['sha256'] == state['golden_sha256'], 'installed_checkpoint_hash_changed')
            self.cp.control(self.source, self.cp.image_id(self.cp.PG))
            self.receipt('restart-postgres-intent.json', {'token': state['token'], 'installed_identity': state['staging_identity']})
        self.cp.k('scale', 'deployment/postgres', '--replicas=1')
        self.cp.k('rollout', 'status', 'deployment/postgres', '--timeout=600s', timeout=630)
        self.guard('verify-restored')
        identity = self.checked_current()
        need(identity['schema'] == 18, 'restored_schema18_required')
        self.cp.checked_identity(identity, True)
        pods = self.cp.role_pods('postgres')
        need(len(pods) == 1, 'one_restored_postgres_required')
        receipt = {'revision': REVISION, 'kind': 'restored-current-schema18-original-s3', 'verified': True,
                   'database_restored': True,
                   'schema': 18, 'new_pg_pod': self.cp.pod_projection(pods[0]), 'identity': identity,
                   'checkpoint_sha256': state['golden_sha256'], 'preservation': state['preservation'],
                   'baseline_caches_restored': True,
                   'preserved_directory': state.get('preserved_directory', False), 'application_roles_stopped': True,
                   's3_rewound': False, 'fallback_accepted': False}
        self.receipt('restored.json', receipt)
        self.c.restore_record(receipt)
        state['phase'] = 'restored'; self.record(state)
        return receipt

    def restore_caches(self, state):
        self.guard('restore-caches')
        self.cp.roles_stopped()
        checked_golden(self.cp)
        cached = self.cp.load('cache-baselines.json')
        state.setdefault('caches', {})
        for role, layout in cached['layouts'].items():
            source = Path(layout['path'])
            need(role in self.cp.CACHE_ROOTS and source == self.cp.CACHE_ROOTS[role], 'fixed_cache_root_required')
            need(not any(p.is_symlink() for p in (source, *source.parents)), 'cache_root_symlink_refused')
            pvc, pv = self.cp.get('pvc', layout['pvc_name']), self.cp.get('pv', layout['pv_name'])
            need(pvc['metadata']['uid'] == layout['pvc_uid'] and pvc['spec']['volumeName'] == layout['pv_name']
                 and pv['metadata']['uid'] == layout['pv_uid'] and pv['spec'].get('local', {}).get('path') == str(source),
                 'cache_volume_identity_changed')
            staging = source.with_name('.restore-' + role + '-' + state['token'])
            preserved = source.with_name('.failed-' + role + '-' + state['token'])
            expected = cached['manifests'][role]
            item = state['caches'].get(role)
            if item is None:
                need(maybe_identity(source) == layout['identity'] and not staging.exists() and not preserved.exists(),
                     'original_cache_root_identity_changed')
                self.receipt('cache-' + role + '-create-intent.json', {'path': str(staging), 'original': layout['identity']})
                staging.mkdir(mode=0o700); sync(staging.parent)
                item = {'original': layout['identity'], 'staging': tree_identity(staging), 'phase': 'created'}
                state['caches'][role] = item; self.record(state)
            if item['phase'] == 'created':
                need(maybe_identity(staging) == item['staging'] and maybe_identity(source) == item['original'],
                     'cache_copy_preimage_changed')
                self.cp.copy_cache(self.cp.S / 'fallback-cache' / role, staging, expected)
                item['phase'] = 'copied'; self.record(state)
            if maybe_identity(source) == item['staging'] and not staging.exists():
                need(maybe_identity(preserved) == item['original'], 'preserved_task_cache_missing')
                item['phase'] = 'installed'; self.record(state)
            if item['phase'] == 'copied':
                need(self.cp.cache_manifest(staging) == expected, 'cache_staging_changed')
                if maybe_identity(source) == item['original'] and not preserved.exists():
                    need(no_nested_mounts(source), 'cache_nested_mount_refused')
                    self.receipt('cache-' + role + '-preserve-intent.json', {'original': item['original'], 'destination': str(preserved)})
                    os.rename(source, preserved); sync(source.parent)
                need(not source.exists() and maybe_identity(preserved) == item['original'], 'cache_preservation_outcome_uncertain')
                self.receipt('cache-' + role + '-install-intent.json', {'staging': item['staging'], 'destination': str(source)})
                os.rename(staging, source); sync(source.parent)
                item['phase'] = 'installed'; self.record(state)
            need(item['phase'] == 'installed' and self.cp.cache_manifest(source) == expected,
                 'baseline_cache_restore_not_verified')
        state['phase'] = 'caches_restored'; self.record(state)

    def reconcile(self, state):
        staging, preserved = self.paths(state)
        live, stage, old = maybe_identity(self.source), maybe_identity(staging), maybe_identity(preserved)
        if live == state.get('staging_identity') and stage is None:
            need(old in (None, state['original_identity']), 'unexpected_preserved_identity')
            need((self.root / 'install-checkpoint-intent.json').exists(), 'installed_without_intent')
            state['phase'] = 'installed'
        elif live is None and stage == state.get('staging_identity'):
            need(old == state['original_identity'] or (self.root / 'discard-original-intent.json').exists(),
                 'removed_original_without_proof')
            state['preserved_directory'] = old == state['original_identity']
            state['phase'] = 'original_removed'
        elif live == state['original_identity']:
            need(old is None, 'duplicate_original_directory')
            if (self.root / 'discard-original-intent.json').exists():
                self.guard('resume-discard')
                need(not self.cp.role_pods('postgres')
                     and self.cp.get('deployment', 'postgres')['spec'].get('replicas') == 0
                     and stage == state.get('staging_identity')
                     and manifest(self.cp, staging)['sha256'] == state['golden_sha256']
                     and no_nested_mounts(self.source), 'discard_resume_fence_failed')
                self.cp.scan_tree(self.source)
                shutil.rmtree(self.source); sync(self.source.parent)
                state['preserved_directory'] = False
                state['preservation'] = 'post_task_sql_lost'
                state['phase'] = 'original_removed'
                self.record(state)
                return state
            if (self.root / 'stop-postgres-intent.json').exists() and not self.cp.role_pods('postgres'):
                self.cold_guard(state)
                state['phase'] = 'stopped'
        else:
            raise Stop('restore_directory_outcome_uncertain')
        self.record(state)
        return state

    def run(self, pins, resume=False):
        if resume:
            private_dir(self.root)
            state = self.state()
            need(state['pins'] == pins, 'restore_source_pins_changed')
            if state['phase'] == 'restored':
                receipt = load(self.root / 'restored.json')
                self.c.restore_guard(stage='completed')
                self.c.restore_record(receipt)
                return receipt
            state = self.reconcile(state)
        else:
            state = self.admit(pins)
        if state['phase'] == 'admitted': self.stage(state)
        if state['phase'] == 'staged': self.stop(state)
        if state['phase'] == 'stopped': self.preserve_and_install(state)
        if state['phase'] == 'original_removed': self.install(state)
        if state['phase'] == 'installed': self.restore_caches(state)
        if state['phase'] == 'caches_restored': return self.restart(state)
        raise Stop('restore_phase_unrecognized')

def golden_size(cp):
    return cp.load('checkpoint-completed.json')['pg_bytes']

def no_nested_mounts(path):
    body = subprocess.check_output(['findmnt', '--json', '--submounts', '--target', str(path), '--output', 'TARGET'], timeout=30)
    value = json.loads(body)
    def walk(rows):
        for row in rows:
            yield Path(row['target'])
            yield from walk(row.get('children', []))
    return not any(p != path and p.is_relative_to(path) for p in walk(value.get('filesystems', [])))

def flush_tree(cp, root):
    rows, _ = cp.scan_tree(root)
    for row in rows:
        if row['kind'] == 'file':
            fd = os.open(root / row['path'], os.O_RDONLY | os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
    for row in sorted((r for r in rows if r['kind'] == 'directory'), key=lambda r: len(Path(r['path']).parts), reverse=True):
        sync(root / row['path'])
    sync(root); sync(root.parent)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--controller-sha256', required=True)
    p.add_argument('--checkpoint-sha256', required=True)
    p.add_argument('--resume', action='store_true')
    p.add_argument('operation', choices=('restore',))
    args = p.parse_args()
    need(os.geteuid() == 0, 'root_required')
    cp = checked_module(CHECKPOINT, args.checkpoint_sha256, 'restore_checkpoint_1d76fbcc')
    public = cp.decode(cp.raw(cp.PUBLIC))
    need(public['controller_source_sha256'] == args.controller_sha256, 'controller_admission_pin_changed')
    mod = cp.controller_module()
    c = mod.Controller(str(BUNDLE), str(BUNDLE / 'plan.json'), 'default')
    pins = {'controller': args.controller_sha256, 'checkpoint': args.checkpoint_sha256,
            'prepared': sha(private_read(BUNDLE / 'prepared.json'))}
    private_dir(BUNDLE)
    fd = os.open(BUNDLE / '.restore.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # The controller owns the outer upgrade lock; the helper also excludes
        # original capacity/certificate operators for the whole cold transition.
        with c.module.bundle_lock(cp.B), c.module.bundle_lock(cp.B, '.certificate.lock'):
            receipt = Restore(cp, c).run(pins, args.resume)
        print(json.dumps({'known_complete': True, 'schema18_restored': True,
                          'fallback_accepted': False, 'preservation': receipt['preservation']}))
    finally:
        os.close(fd)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'known_complete': False, 'restore_incomplete': True, 'applications_must_remain_stopped': True}))
        sys.exit(1)
