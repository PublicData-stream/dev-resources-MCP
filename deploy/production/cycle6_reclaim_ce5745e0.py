#!/usr/bin/env python3
"""Preview and retire only the reviewed ce5745e0 isolated proof copy bodies."""

import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import types


sys.dont_write_bytecode = True
UPGRADES = Path('/var/lib/devres-production-upgrades')
INSTALLS = Path('/usr/local/libexec')
RECLAIM = Path('/var/lib/devres-production-reclaim/ce5745e0-cycle6')
OPERATOR = Path('/var/lib/devres-production-preparation/a938112b-7c7a24f')
CACHE = Path('/tmp/devres-reclaim-discovery-3dae7d91-20261117')
KUBECONFIG = Path('/etc/rancher/k3s/k3s.yaml')
C5 = '3dae7d91-cycle5-20261118'
C6 = 'ce5745e0-cycle6'
PHASES = ('historical-completed', 'candidate-checkpoint-proof')
KIND = 'cycle6-completed-copy-retirement'
ENGINE_SHA = 'c4ada7103566b5844b0c8aa08f5a2c5c61f6ab7a49abc7b31eee33e85f997bd8'
C5_MANIFEST = '607307c4dc64c90b9efedc14b709012843e1ee14d1842cb5e2b562b9a089d491'
C5_STATE = '7462e62c802d12bb9bf929956265a3cec63e9249f5944104e389fe4be066855d'
C5_RESTORE = '3cfa88baff2a2c4f074c066626c2f1bdad5bf3c699603a1733f9c28b3ccad0eb'
EDGE_SHA = 'e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a'
RESERVE = 128 * 1024**3
PGDATA = Path('/database/devres/corpus/18/docker')
CACHES = (Path('/var/cache/devres/serving'), Path('/var/cache/devres/writer'))
LEGACY = (
    ('91c7bcb7-20261115', INSTALLS/'devres-upgrade-91c7bcb7/physical-checkpoint.py', False,
     '9d7c3976b9d4ba2d19fd7fa2b22070ff7d5954d481bf2cc8743b4390499b70dc',
     '1bafda6bac0f3d7916a3806c895ae9c80b6144f70b83e5a9d22ca41ac88663fe'),
    ('33f3c730-20261114', INSTALLS/'devres-upgrade-33f3c730/physical-checkpoint.py', True,
     '25ce3324cad52cd6018e3411e169119bbbb18652bc1901138780b55f758c1501',
     'c7ea40d9e0e03684bafc252a8224d2d234dcd6aa4fa6f40b303dd5c1c4be0a36'),
    ('60e10624-20261113', UPGRADES/'60e10624-20261113/checkpoint-volume/physical-checkpoint.py', True,
     'c64fb74e6137858d82eb81b2cbbb76fa1f59fc7132039f35d1c4fea22e6cb02c',
     '4a6f514f0fc43ed885635e54db0fb469daaa44851fa7d99129510daf058af247'),
)
C5_REHEARSAL_PINS = {
    'owner.json': 'e837b651688176c611b7881e43384491b902fc263406f340fb2c70525105afca',
    'cleanup-completed.json': 'd32aeb7d4a96c9804f46fc42349a39e8296d474c1f06446210cf02db4a7ff31c',
    'real-pg-proof.json': '4686cbb94cfcf0792c74858f78dab7b9bc155caf766454241c87346961fa5d0f',
    'runtime/restore/state.json': '865e4227781eaa48d2d14fe6e635a96e7de8c52df1b99fe611f9d82bfd823da6',
}
C5_REHEARSAL_SHA = 'f8b4ea9a0d8c3e4c61d018e79fbe0594f6f042ae05d2a153fb3f0732fccaed02'
TOKEN = re.compile('[a-f0-9]{24}')
SHA = re.compile('[a-f0-9]{64}')


class Refused(RuntimeError):
    """An exact reclamation prerequisite was not established."""


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def work(cycle):
    return Path('/tmp') / ('devres-upgrade-' + cycle)


def installed(cycle):
    return INSTALLS / ('devres-upgrade-' + ('3dae7d91-cycle5' if cycle == C5 else cycle))


def read_private(path, maximum=1024**2):
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'private_input_path')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and not before.st_mode & 0o077 and 0 < before.st_size <= maximum, 'private_input_required')
        body = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        need(len(body) == before.st_size and stable(before) == stable(after) == stable(path.lstat()),
             'private_input_changed')
    return body


def stable(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def module_from_pin(path, expected, name):
    need(bool(SHA.fullmatch(expected)), 'source_pin_required')
    body = read_private(path)
    need(digest(body) == expected, 'pinned_source_changed')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(body, str(path), 'exec'), module.__dict__)
    return module


@dataclass(frozen=True)
class Leaf:
    path: Path
    alias: Path


class Inventory:
    def __init__(self, engine):
        self.engine = engine
        self.leaves = []
        self.files = {}
        self.bodies = {}
        self.directories = {}
        self.tokens = set()
        self.backups = []
        self.resume_process = None
        self.database = None
        self.baseline_bytes = None

    def directory(self, path):
        value = self.engine.directory_record(path)
        self.directories[str(path)] = value
        return value

    def file(self, path, expected=None):
        if str(path) not in self.files:
            self.files[str(path)] = self.engine.file_record(path)
        value = self.files[str(path)]
        need(expected is None or value['sha256'] == expected, 'pinned_producer_receipt_changed')
        return value

    def record(self, path, expected=None, *, maximum=1024**2):
        body = read_private(path, maximum=maximum)
        self.file(path, expected)
        need(digest(body) == self.files[str(path)]['sha256'], 'producer_receipt_read_changed')
        value = json.loads(body)
        need(type(value) is dict, 'producer_receipt_object_required')
        return value

    def token(self, value):
        need(type(value) is str and bool(TOKEN.fullmatch(value)), 'producer_token_required')
        self.tokens.add(value)
        return value

    def alias(self, path, alias):
        original = self.directory(path)
        need(self.directory(alias) == original, 'work_bind_alias_identity')

    def leaf(self, path, alias):
        self.alias(path, alias)
        for parent in (path.parent, alias.parent):
            self.directory(parent)
        self.leaves.append(Leaf(path, alias))

    def body(self, path, alias=None):
        identity = self.engine.directory_record(path)
        if alias is not None:
            need(self.engine.directory_record(alias) == identity, 'protected_body_alias_identity')
        self.bodies[str(path)] = {'identity': identity, 'alias': str(alias) if alias else None}

    def backup(self, path, expected=None):
        record = self.record(path, expected)
        need(record.get('verified') is True and type(record.get('artifacts')) is list
             and 1 <= len(record['artifacts']) <= 64, 'verified_backup_required')
        self.backups.extend(record['artifacts'])

    def check_backup_dependencies(self):
        total = 0
        for item in self.backups:
            artifact = self.engine.safe_path(Path(item['path']))
            selected = [value for leaf in self.leaves for value in (leaf.path, leaf.alias)]
            protected_bodies = [Path(path) for path in self.bodies]
            protected_bodies += [Path(entry['alias']) for entry in self.bodies.values() if entry['alias']]
            need(not any(artifact == path or artifact.is_relative_to(path)
                         for path in selected + protected_bodies), 'backup_artifact_is_copy_body')
            record = self.file(artifact, item['sha256'])
            total += record['size']
            need(total <= self.engine.MAX_METADATA_BYTES, 'backup_metadata_bound')

    def recheck(self):
        for spelling, expected in self.files.items():
            need(self.engine.file_record(Path(spelling)) == expected, 'protected_metadata_changed')
        for spelling, expected in self.directories.items():
            need(self.engine.directory_record(Path(spelling)) == expected, 'retained_directory_identity_changed')
        for spelling, value in self.bodies.items():
            for path in (spelling, value['alias']):
                if path:
                    need(self.engine.directory_record(Path(path)) == value['identity'],
                         'protected_body_identity_changed')


def checkpoint(inventory, cycle, source, pin, *, nested=False, completed_pin=None, candidate=False):
    bundle = UPGRADES / cycle
    root = bundle / ('checkpoint-volume/checkpoint-state' if nested else 'checkpoint-volume')
    alias = work(cycle) / 'checkpoint-state'
    inventory.alias(root, alias)
    inventory.directory(bundle)
    expected_source = inventory.file(source, pin)['sha256']
    owner = inventory.record(root/'owner.json')
    complete = inventory.record(root/'completed.json', completed_pin)
    mid = inventory.record(root/'checkpoint-completed.json', complete['checkpoint_receipt_sha256'])
    proof = inventory.record(root/'clone-proof-result.json', complete['clone_proof_sha256'])
    cleanup = inventory.record(root/'clone-cleanup-completed.json')
    intent = inventory.record(root/'proof-intent.json')
    token = inventory.token(owner['token'])
    need(owner['pins']['source_sha256'] == expected_source and owner['pins'] == complete['pins'] == mid['pins']
         and intent['token'] == token and complete.get('old_clone_verified') is True
         and complete.get('original_s3_retained') is True and proof.get('no_production_mount') is True
         and proof.get('isolated_clone_only') is True and proof.get('provider_source_requests') == 0
         and all(cleanup.get(key) is True for key in
                 ('all_owned_containers_removed', 'owned_network_removed', 'physical_checkpoint_retained')),
         'completed_isolated_checkpoint_required')
    inventory.body(root/'pg-checkpoint', alias/'pg-checkpoint')
    inventory.file(root/'pg-file-manifest.jsonl', complete['pg_files_sha256'])
    for backup_path in (root/'backup-receipt.json', root/'backup-receipt-after-rehearsal.json'):
        if os.path.lexists(backup_path):
            inventory.backup(backup_path)
    if not candidate:
        inventory.backup(bundle/'accepted-backup.json')
    if candidate or cycle == C5:
        manifest = inventory.record(root/'cache-baselines.json', complete['cache_baselines_sha256'],
                                    maximum=inventory.engine.MAX_BYTES)
        need(type(manifest['bytes']) is int and manifest['bytes'] > 0, 'full_cache_baseline_required')
        for role in ('serving', 'writer'):
            part = Path('fallback-cache')/role
            inventory.body(root/part, alias/part)
    if candidate:
        need(not os.path.lexists(bundle/'restore-rehearsal-volume/owner.json')
             and not os.path.lexists(work(cycle)/'restore-rehearsal-receipt.json')
             and os.path.lexists(root/'backup-receipt.json'), 'candidate_proof_retirement_timing')
        need(type(mid['pg_bytes']) is int and 0 < mid['pg_bytes'] <= 64*1024**3, 'checkpoint_pg_bytes_bound')
        inventory.baseline_bytes = mid['pg_bytes'], manifest['bytes']
        inventory.resume_process = inventory.record(root/'original-pg-resumed.json')['new_pg_pod']
        inventory.file(work(cycle)/'operational-baseline.json')
        for part in ('pg-clone', 'rehearsal/cache', 'rehearsal/writer-cache'):
            inventory.leaf(root/part, alias/part)
    elif cycle != C5:
        inventory.leaf(root/'pg-clone', alias/'pg-clone')
        inventory.body(root/'rehearsal/cache', alias/'rehearsal/cache')


def historical_rehearsal(inventory):
    bundle = UPGRADES / C5
    scope = bundle / 'restore-rehearsal-volume'
    alias = work(C5) / 'restore-rehearsal-state'
    inventory.alias(scope, alias)
    records = {part: inventory.record(scope/part, pin) for part, pin in C5_REHEARSAL_PINS.items()}
    owner, cleanup = records['owner.json'], records['cleanup-completed.json']
    proof, state = records['real-pg-proof.json'], records['runtime/restore/state.json']
    receipt = inventory.record(work(C5)/'restore-rehearsal-receipt.json', C5_REHEARSAL_SHA)
    inventory.token(owner['token'])
    token = inventory.token(state['token'])
    identity = inventory.directories[str(scope)]
    need(owner['scope'] == {'device': identity['dev'], 'inode': identity['ino']}
         and cleanup['token'] == owner['token'] and state['token'] != owner['token'], 'rehearsal_owner_identity')
    need(receipt.get('verified') is True and receipt.get('kind') == 'isolated-real-pg-restore-rehearsal'
         and receipt['sources'] == owner['sources']
         and set(owner['sources']) == {'restore-rehearsal.py', 'restore-controller.py', 'physical-checkpoint.py'}
         and cleanup['owned_container_removed'] is True and cleanup['golden_retained'] is True
         and all(proof.get(key) is True for key in
                 ('no_production_credentials', 'no_network', 'no_kubernetes_commands', 'marker_removed'))
         and state['phase'] == 'restored' and state['preserved_directory'] is True,
         'completed_historical_rehearsal_required')
    for name, pin in owner['sources'].items():
        inventory.file(installed(C5)/name, pin)
    artifacts = {str(alias/part): C5_REHEARSAL_PINS[part] for part in ('cleanup-completed.json', 'real-pg-proof.json')}
    need(len(receipt['artifacts']) == 2 and {v['path']: v['sha256'] for v in receipt['artifacts']} == artifacts,
         'rehearsal_receipt_artifacts_changed')
    for part in ('isolated-pv', 'cache-serving', 'cache-writer', '.failed-serving-'+token, '.failed-writer-'+token):
        inventory.leaf(scope/'runtime'/part, alias/'runtime'/part)
    restored = inventory.record(bundle/'restore/restored.json', C5_RESTORE)
    restore_state = inventory.record(bundle/'restore/state.json')
    need(restored['verified'] is True and restored['schema'] == 18 and restored['s3_rewound'] is False
         and restore_state['phase'] == 'restored' and restore_state['preserved_directory'] is True,
         'historical_restoration_required')
    actual_token = restore_state['token']
    need(type(actual_token) is str and bool(TOKEN.fullmatch(actual_token)), 'preserved_generation_token_required')
    inventory.body(PGDATA.with_name('.failed-' + actual_token))
    for role, cache in zip(('serving', 'writer'), CACHES, strict=True):
        inventory.body(cache.with_name('.failed-' + role + '-' + actual_token))


def scope_inventory(engine, phase, candidate_manifest):
    inventory = Inventory(engine)
    inventory.file(UPGRADES/C5/'state.json', C5_STATE)
    restored = inventory.record(UPGRADES/C5/'restore/restored.json', C5_RESTORE)
    inventory.resume_process = restored['new_pg_pod']
    inventory.database = {k: restored['identity'][k] for k in ('system_id', 'archive')}
    manifest = inventory.record(work(C5)/'source-manifest.json', C5_MANIFEST)
    inventory.file(installed(C5)/'edge-readmission.py', manifest['edge-readmission.py'])
    inventory.file(installed(C5)/'edge-qualification.py', manifest['edge-qualification.py'])
    if phase == PHASES[0]:
        need(candidate_manifest is None, 'historical_phase_has_fixed_source')
        historical_rehearsal(inventory)
        checkpoint(inventory, C5, installed(C5)/'physical-checkpoint.py', manifest['physical-checkpoint.py'],
                   completed_pin='0bc9cf95ac9f669946ae1826ff854ed0c974d486517bfe174b394095cab7ba43')
        for cycle, source, nested, pin, completed in LEGACY:
            checkpoint(inventory, cycle, source, pin, nested=nested, completed_pin=completed)
        need(len(inventory.leaves) == 8, 'eight_exact_historical_copy_paths_required')
    else:
        need(phase == PHASES[1] and type(candidate_manifest) is str and bool(SHA.fullmatch(candidate_manifest)),
             'candidate_source_manifest_pin_required')
        current = inventory.record(work(C6)/'source-manifest.json', candidate_manifest)
        checkpoint(inventory, C6, installed(C6)/'physical-checkpoint.py',
                   current['physical-checkpoint.py'], candidate=True)
        need(len(inventory.leaves) == 3, 'exact_candidate_copy_paths_required')
    for body in (PGDATA, *CACHES):
        inventory.body(body)
    inventory.check_backup_dependencies()
    selected = [leaf.path for leaf in inventory.leaves]
    device = UPGRADES.stat().st_dev
    need({inventory.directories[str(path)]['dev'] for path in selected} == {device}
         and len(set(selected)) == len(selected)
         and not any(a.is_relative_to(b) for a in selected for b in selected if a != b),
         'one_disjoint_target_filesystem_required')
    for path in selected:
        need(not any(path.is_relative_to(Path(body)) or Path(body).is_relative_to(path)
                     for body in inventory.bodies), 'protected_body_overlap')
    return inventory, manifest['edge-readmission.py']


@contextmanager
def locks():
    with ExitStack() as stack:
        for lock in ('.operator.lock', '.certificate.lock'):
            path = OPERATOR/lock
            need(not any(p.is_symlink() for p in (path, *path.parents)), 'unsafe_operator_lock')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            stack.callback(os.close, fd)
            value = os.fstat(fd)
            need(value.st_uid == 0 and value.st_nlink == 1 and not value.st_mode & 0o077
                 and stat.S_ISREG(value.st_mode) and stable(value) == stable(path.lstat()), 'unsafe_operator_lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def kubernetes(*args):
    file = KUBECONFIG.lstat()
    need(stat.S_ISREG(file.st_mode) and file.st_uid == 0 and file.st_nlink == 1 and not file.st_mode & 0o077
         and not any(p.is_symlink() for p in KUBECONFIG.parents), 'fixed_kubeconfig_authority_required')
    command = ['/usr/local/bin/kubectl', '--kubeconfig', str(KUBECONFIG), '--context', 'default',
               '--namespace', 'devres',
               '--cache-dir', str(CACHE), '--request-timeout=20s', *args]
    process = subprocess.run(command, capture_output=True, timeout=35, check=False)
    need(process.returncode == 0 and len(process.stdout) <= 2*1024**2, 'withdrawn_kubernetes_boundary_unavailable')
    return json.loads(process.stdout)


def quiet_state(edge, inventory):
    need(not os.path.lexists(UPGRADES/C6/'launch-intent.json'), 'candidate_deployment_intent_already_exists')
    deployments = kubernetes('get', 'deployment', '-o', 'json')['items']
    replicas = {item['metadata']['name']: item['spec']['replicas'] for item in deployments}
    need(replicas == {'postgres': 1, 'writer': 0, 'backend': 0}, 'withdrawn_replicas_required')
    pods = kubernetes('get', 'pod', '-o', 'json')['items']
    need(len(pods) == 1 and pods[0]['metadata']['labels'].get('app') == 'postgres'
         and not pods[0]['metadata'].get('deletionTimestamp') and pods[0]['status']['phase'] == 'Running',
         'single_ready_postgres_required')
    pod = pods[0]
    containers = pod['status']['containerStatuses']
    need(len(containers) == 1 and containers[0]['ready'] is True and 'running' in containers[0]['state'],
         'single_ready_postgres_required')
    item = containers[0]
    identity = {'uid': pod['metadata']['uid'], 'container_id': item['containerID'],
                'image_id': item['imageID'], 'restarts': item['restartCount'],
                'started_at': item['state']['running']['startedAt']}
    if inventory.resume_process is not None:
        need(all(inventory.resume_process.get(k) == value for k, value in identity.items()),
             'checkpoint_resumed_postgres_changed')
    query = ("BEGIN READ ONLY; SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='250ms'; "
             "SELECT json_build_object('schema',(SELECT version FROM devres_schema WHERE singleton),"
             "'system_id',(SELECT system_identifier::text FROM pg_control_system()),"
             "'data',current_setting('data_directory'),'recovery',pg_is_in_recovery(),"
             "'archive',(SELECT json_build_object('backend',backend,'epoch',epoch,'binding',binding,"
             "'pending_binding',pending_binding,'initializing_s3',initializing_s3,'store_id',store_id)"
             " FROM devres_archive_control WHERE singleton),"
             "'owners',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND "
             "classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND "
             "database=(SELECT oid FROM pg_database WHERE datname=current_database()))); COMMIT;")
    sql = kubernetes('exec', 'deployment/postgres', '-c', 'postgres', '--', 'psql',
                     '-X', '-q', '-U', 'devres_admin', '-d', 'devres', '-At', '-v', 'ON_ERROR_STOP=1', '-c', query)
    expected = {'schema': 18, 'data': '/var/lib/postgresql/18/docker', 'recovery': False, 'owners': 0}
    need(sql == expected | inventory.database,
         'withdrawn_schema18_archive_required')
    running = subprocess.run(['systemctl', 'is-active', 'devres-capacity.timer', 'devres-cert-renew.timer'],
                             capture_output=True, timeout=10, check=False)
    need(running.returncode == 0 and running.stdout.splitlines() == [b'active', b'active'],
         'operational_timers_required')
    return {'postgres': identity, 'replicas': replicas, 'schema': sql['schema'],
            'native_edge_sha256': digest(json.dumps(edge.native_guard(EDGE_SHA), sort_keys=True).encode())}


def body_bytes(path, cache):
    records = {}
    total = 0
    started = time.monotonic()
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and not any(p.is_symlink() for p in path.parents), 'live_body_scope_changed')
    command = ['findmnt', '--json', '--submounts', '--target', str(path), '--output', 'TARGET']
    output = subprocess.check_output(command, timeout=10)
    def mount_targets(rows):
        for row in rows:
            yield Path(row['target'])
            yield from mount_targets(row.get('children', []))
    mounts = mount_targets(json.loads(output)['filesystems'])
    need(not any(target != path and target.is_relative_to(path) for target in mounts), 'live_body_nested_mount')
    def raise_error(error):
        raise error
    count = 0
    for directory, dirs, files, fd in os.fwalk(path, follow_symlinks=False, onerror=raise_error):
        for name in dirs + files:
            count += 1
            value = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need(value.st_dev == info.st_dev and count <= 1_000_000 and time.monotonic()-started < 35,
                 'live_capacity_inventory_bound')
            if stat.S_ISREG(value.st_mode):
                if cache:
                    key = value.st_dev, value.st_ino
                    if key not in records:
                        total += value.st_size
                        records[key] = [1, value.st_nlink, value.st_size]
                    else:
                        records[key][0] += 1
                        need(records[key][1:] == [value.st_nlink, value.st_size], 'cache_links_changed')
                else:
                    need(value.st_nlink == 1, 'postgres_hardlink_refused')
                    total += value.st_size
            elif stat.S_ISLNK(value.st_mode):
                target = os.readlink(name, dir_fd=fd)
                need(cache and not Path(target).is_absolute() and
                     (Path(directory)/name).resolve().is_relative_to(path), 'external_live_body_link')
            else:
                need(stat.S_ISDIR(value.st_mode), 'live_body_special_entry')
    need(not cache or all(count == expected for count, expected, _ in records.values()), 'external_cache_links')
    return total


def required_free(phase, pg, caches):
    if phase == PHASES[0]:
        # Admission must remain feasible after retaining the fresh golden and
        # full-cache copies and after retiring the new isolated proof copies.
        return 4*(pg + caches) + RESERVE
    return 3*pg + 3*caches + RESERVE


def capacity(phase, baseline_bytes):
    postgres = body_bytes(PGDATA, False)
    caches = sum(body_bytes(path, True) for path in CACHES)
    need(0 < postgres <= 64*1024**3 and 0 < caches <= 256*1024**3, 'live_capacity_bytes_bound')
    need(len({p.stat().st_dev for p in (UPGRADES, PGDATA, *CACHES)}) == 1, 'one_live_capacity_filesystem_required')
    durable = baseline_bytes or (postgres, caches)
    planned_pg, planned_cache = max(postgres, durable[0]), max(caches, durable[1])
    info = os.statvfs(UPGRADES)
    return {'free_bytes': info.f_bavail*info.f_frsize, 'free_inodes': info.f_favail,
            'postgres_bytes': postgres, 'cache_bytes': caches,
            'required_after_retirement': required_free(phase, planned_pg, planned_cache)}


def tree_records(engine, inventory):
    trees = {}
    inodes = {}
    for leaf in inventory.leaves:
        rows = engine.tree(leaf.path)
        need(len(rows) > 1, 'completed_copy_already_empty')
        for item in rows:
            need(item['uid'] in (0, 70, 65532) and item['gid'] in (0, 70, 65532),
                 'unexpected_copy_entry_owner')
            if item['kind'] == 'link':
                target = Path(item['target'])
                link = leaf.path / item['path']
                need(not target.is_absolute() and (link.parent/target).resolve().is_relative_to(leaf.path),
                     'external_disposable_copy_link')
            key = item['dev'], item['ino']
            if key in inodes:
                need(inodes[key]['blocks'] == item['blocks'], 'copy_hardlink_identity_changed')
            else:
                inodes[key] = item
        trees[str(leaf.path)] = rows
    owners = Counter((r['dev'], r['ino']) for rows in trees.values() for r in rows if r['kind'] == 'file')
    need(all(inodes[key]['links'] == count for key, count in owners.items()), 'external_hardlink_refused')
    entries = sum(len(rows) for rows in trees.values())
    need(entries <= engine.MAX_ENTRIES, 'aggregate_inventory_bound')
    allocated = sum(r['blocks']*512 for r in inodes.values() if r['path'])
    return trees, set(inodes), allocated, entries


def preview(engine, phase, source_sha, candidate_manifest):
    inventory, edge_pin = scope_inventory(engine, phase, candidate_manifest)
    edge = module_from_pin(installed(C5)/'edge-readmission.py', edge_pin, 'cycle6_reclaim_frozen_edge')
    observed = quiet_state(edge, inventory)
    trees, inodes, allocated, entries = tree_records(engine, inventory)
    roots = [leaf.path for leaf in inventory.leaves]
    aliases = [leaf.alias for leaf in inventory.leaves]
    runtime = engine.environment(roots, aliases, sorted(inventory.tokens), inodes, runtime=True)
    engine.environment_binding(runtime)
    quota = capacity(phase, inventory.baseline_bytes)
    need(quota['free_bytes'] + allocated >= quota['required_after_retirement']
         and quota['free_inodes'] > entries, 'retirement_does_not_meet_capacity_gate')
    inventory.recheck()
    need(quiet_state(edge, inventory) == observed, 'withdrawn_boundary_changed')
    return {'version': 1, 'kind': KIND, 'phase': phase, 'source_sha256': source_sha,
            'engine_sha256': ENGINE_SHA, 'candidate_manifest_sha256': candidate_manifest,
            'roots': [str(p) for p in roots], 'aliases': [str(p) for p in aliases],
            'trees': trees, 'tokens': sorted(inventory.tokens), 'entries': entries,
            'allocated_bytes': allocated, 'protected_files': inventory.files,
            'protected_bodies': inventory.bodies, 'protected_directories': inventory.directories,
            'quiet': observed, 'environment': runtime, 'capacity': quota}


def binding(engine, record):
    value = dict(record)
    value['environment'] = engine.environment_binding(record['environment'])
    value['capacity'] = {key: amount for key, amount in record['capacity'].items()
                         if key not in ('free_bytes', 'free_inodes')}
    return value


def validate_approval(approval, phase, source, preview_sha, now):
    expected = {'version': 1, 'kind': KIND, 'approved': True, 'phase': phase, 'operations': ['apply'],
                'maximum_applies': 1, 'source_sha256': source, 'engine_sha256': ENGINE_SHA,
                'preview_sha256': preview_sha}
    declared = {k: v for k, v in approval.items() if k != 'expires_at'}
    need(json.dumps(declared, sort_keys=True) == json.dumps(expected, sort_keys=True),
         'exact_retirement_approval_required')
    expiry = datetime.datetime.fromisoformat(approval['expires_at'])
    need(expiry.utcoffset() == datetime.timedelta(0) and
         0 < (expiry-now).total_seconds() <= 900, 'finite_retirement_approval_required')


def apply(engine, args, manifest, journal):
    raw_preview = read_private(args.preview, maximum=engine.MAX_BYTES)
    need(digest(raw_preview) == args.preview_sha256, 'external_preview_pin_required')
    original = json.loads(raw_preview)
    raw_approval = read_private(args.approval)
    need(digest(raw_approval) == args.approval_sha256, 'external_approval_pin_required')
    validate_approval(json.loads(raw_approval), args.phase, args.source_sha256, args.preview_sha256,
                      datetime.datetime.now(datetime.timezone.utc))
    need(not os.path.lexists(journal), 'retirement_intent_already_consumed')
    before = preview(engine, args.phase, args.source_sha256, manifest)
    need(binding(engine, before) == binding(engine, original), 'retirement_preview_stale')
    quota = before['capacity']
    need(quota['free_bytes'] < quota['required_after_retirement'], 'retirement_no_longer_required')
    validate_approval(json.loads(raw_approval), args.phase, args.source_sha256, args.preview_sha256,
                      datetime.datetime.now(datetime.timezone.utc))
    parent = engine.directory_record(journal.parent)
    need(parent['uid'] == 0 and not parent['mode'] & 0o077 and parent['dev'] == UPGRADES.stat().st_dev,
         'quiet_private_disk_journal_required')
    journal.mkdir(mode=0o700)
    engine.sync(journal.parent)
    engine.new(journal/'intent.json', {k: before[k] for k in ('phase', 'roots', 'source_sha256', 'engine_sha256')}
               | {'approval_sha256': args.approval_sha256, 'preview_sha256': args.preview_sha256, 'maximum_applies': 1})
    deleter = engine.Engine(None)
    deleter.removed_links = Counter()
    deleter.link_ctimes = {}
    try:
        for path in before['roots']:
            deleter.clear(Path(path), before['trees'][path])
        inventory, edge_pin = scope_inventory(engine, args.phase, manifest)
        inventory.recheck()
        need(inventory.files == before['protected_files'] and inventory.directories == before['protected_directories']
             and inventory.bodies == before['protected_bodies'], 'protected_evidence_changed')
        edge = module_from_pin(installed(C5)/'edge-readmission.py', edge_pin, 'cycle6_reclaim_frozen_edge')
        need(quiet_state(edge, inventory) == before['quiet'], 'withdrawn_boundary_changed')
        roots, aliases = ([Path(path) for path in before[key]] for key in ('roots', 'aliases'))
        after_runtime = engine.environment(roots, aliases, before['tokens'], set(), runtime=True)
        need(engine.environment_binding(after_runtime) == engine.environment_binding(before['environment']),
             'runtime_boundary_changed')
        after = capacity(args.phase, inventory.baseline_bytes)
        need(all(not any(root.iterdir()) for root in roots), 'copy_children_remain')
        need(after['free_bytes'] >= after['required_after_retirement'], 'retirement_headroom_insufficient')
        result = {'verified': True, 'phase': args.phase, 'preview_sha256': args.preview_sha256,
                  'free_before': before['capacity']['free_bytes'], 'free_after': after['free_bytes'],
                  'roots_preserved': True, 'protected_unchanged': True,
                  'firewall_audit': [original['environment']['firewall'], before['environment']['firewall'],
                                     after_runtime['firewall']]}
        engine.new(journal/'completed.json', result)
        return result
    except BaseException:
        try:
            engine.new(journal/'failed.json',
                       {'verified': False, 'no_retry': True, 'manual_reconciliation_required': True})
        except (OSError, RuntimeError):
            # The durable intent still fences a repeat if a failure receipt cannot be saved.
            pass
        raise


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='operation', required=True)
    for mode in ('inspect', 'apply'):
        command = modes.add_parser(mode)
        command.add_argument('--phase', choices=PHASES, required=True)
        command.add_argument('--source-sha256', required=True)
        command.add_argument('--source-manifest-sha256')
        if mode == 'inspect':
            command.add_argument('--output', type=Path, required=True)
        else:
            command.add_argument('--preview', type=Path, required=True)
            command.add_argument('--preview-sha256', required=True)
            command.add_argument('--approval', type=Path, required=True)
            command.add_argument('--approval-sha256', required=True)
    args = parser.parse_args()
    script = installed(C6)/'reclaim.py'
    need(os.geteuid() == 0 and Path(__file__) == script
         and digest(read_private(script)) == args.source_sha256, 'exact_root_owned_retirement_source_required')
    engine = module_from_pin(script.with_name('reclaim-engine.py'), ENGINE_SHA, 'cycle6_reclaim_frozen_engine')
    manifest = args.source_manifest_sha256
    journal = RECLAIM/args.phase
    with locks():
        if args.operation == 'inspect':
            need(args.output.is_absolute() and Path('/tmp') in args.output.parents
                 and not os.path.lexists(journal), 'fresh_private_tmp_preview_required')
            record = preview(engine, args.phase, args.source_sha256, manifest)
            engine.new(args.output, record)
            result = {k: record[k] for k in ('phase', 'roots', 'entries', 'allocated_bytes', 'capacity')}
            result['preview_sha256'] = digest(engine.encode(record))
        else:
            result = apply(engine, args, manifest, journal)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RuntimeError):
        print('retirement_admission_or_execution_failed', file=sys.stderr)
        raise SystemExit(1)
