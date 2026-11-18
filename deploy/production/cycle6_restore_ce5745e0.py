"""Render the ce5745e0 restore policy into the frozen predecessor's successor."""

from __future__ import annotations

import ast
import hashlib


class RenderError(RuntimeError):
    pass


REPLACED_METHODS = {
    'preserve_and_install': 'ef05f3a761957ccce9b62f982b69ce8c1c784c57c0762382075c2a34b399a66f',
    'restore_caches': '5be71b843525c25a85aca5975c32552df5bdae28f2fbd8084f9c14c4660f9521',
    'reconcile': '2136ec57038df87b28f6fc8ef1d35e7602a073a9efd79abbd7d31cc36e52232d',
}


DATABASE = r'''    def reject_sql_loss(self, state=None):
        need(not os.path.lexists(self.root / 'discard-original-intent.json')
             and (state is None or state.get('preservation') != 'post_task_sql_lost'),
             'sql_discard_forbidden')
        need(not os.path.lexists(self.root / 'sql-preservation-failed.json'),
             'sql_preservation_failed_reconciliation_required')

    def database_rename_intent(self, state):
        _, preserved = self.paths(state)
        return {'from': str(self.source), 'to': str(preserved),
                'original_identity': state['original_identity']}

    def require_preserved_database(self, state):
        self.reject_sql_loss(state)
        _, preserved = self.paths(state)
        need(path_identity(preserved) == state['original_identity']
             and state.get('preservation') == 'manifest_verified'
             and load(self.root / 'rename-original-intent.json') == self.database_rename_intent(state),
             'post_task_database_preservation_required')
        proof = load(self.root / 'post-task-database-manifest.json')
        need(set(proof) == {'sha256', 'bytes', 'files'} and re.fullmatch('[0-9a-f]{64}', proof['sha256'])
             and type(proof['bytes']) is int and proof['bytes'] > 0
             and type(proof['files']) is int and proof['files'] > 0,
             'post_task_database_manifest_required')

    def preserve_and_install(self, state):
        self.reject_sql_loss(state)
        staging, preserved = self.paths(state)
        self.cold_guard(state)
        need(path_identity(staging) == state['staging_identity']
             and manifest(self.cp, staging)['sha256'] == state['golden_sha256'],
             'verified_staging_changed')
        checked_golden(self.cp)
        try:
            self.receipt('post-task-database-manifest.json', manifest(self.cp, self.source))
        except Exception:
            self.receipt('sql-preservation-failed.json', {
                'reason': 'manifest', 'token': state['token'], 'original_identity': state['original_identity']})
            raise
        state['preservation'] = 'manifest_verified'
        self.record(state)
        need(path_identity(preserved) is None and not os.path.lexists(self.root / 'rename-original-intent.json'),
             'fresh_preserved_path_and_intent_required')
        self.cold_guard(state)
        self.receipt('rename-original-intent.json', self.database_rename_intent(state))
        try:
            os.rename(self.source, preserved)
        except OSError:
            live, old = path_identity(self.source), path_identity(preserved)
            if live == state['original_identity'] and old is None:
                self.receipt('sql-preservation-failed.json', {
                    'reason': 'rename', 'token': state['token'], 'original_identity': state['original_identity']})
                raise Stop('sql_preservation_failed_reconciliation_required') from None
            need(live is None and old == state['original_identity'], 'original_rename_outcome_uncertain')
        sync(self.source.parent)
        need(path_identity(self.source) is None, 'database_source_not_removed')
        self.require_preserved_database(state)
        state['preserved_directory'] = True
        state['phase'] = 'original_removed'
        self.record(state)
        self.install(state)
'''


RECONCILE = r'''    def reconcile(self, state):
        self.reject_sql_loss(state)
        self.guard('reconcile')
        staging, preserved = self.paths(state)
        live, stage, old = (path_identity(path) for path in (self.source, staging, preserved))
        wanted = state.get('staging_identity')
        if wanted is not None and live == wanted and stage is None:
            self.require_preserved_database(state)
            need(load(self.root / 'install-checkpoint-intent.json') == {
                'staging_identity': wanted, 'golden_sha256': state['golden_sha256']}, 'installed_without_intent')
            sync(self.source.parent)
            state['preserved_directory'] = True
            if state['phase'] != 'caches_restored':
                state['phase'] = 'installed'
        elif wanted is not None and live is None and stage == wanted:
            self.require_preserved_database(state)
            sync(self.source.parent)
            state['preserved_directory'] = True
            state['phase'] = 'original_removed'
        elif live == state['original_identity'] and old is None:
            need(not os.path.lexists(self.root / 'rename-original-intent.json'),
                 'original_rename_outcome_uncertain')
            if os.path.lexists(self.root / 'stop-postgres-intent.json') and not self.cp.role_pods('postgres'):
                self.cold_guard(state)
                state['phase'] = 'stopped'
        else:
            raise Stop('restore_directory_outcome_uncertain')
        self.record(state)
        return state
'''


CACHES = r'''    def cache_boundary(self, state, role, layout):
        self.guard('restore-caches')
        self.require_preserved_database(state)
        need(not self.cp.role_pods('postgres')
             and self.cp.get('deployment', 'postgres')['spec'].get('replicas') == 0,
             'postgres_must_be_stopped')
        need(path_identity(self.source) == state['staging_identity'], 'installed_directory_identity_changed')
        source = Path(layout['path'])
        protected = (self.cp.PV, self.cp.S, self.root, self.c.root,
                     *(path for name, path in self.cp.CACHE_ROOTS.items() if name != role))
        need(role in ('serving', 'writer') and source == self.cp.CACHE_ROOTS[role]
             and source.is_absolute() and '..' not in source.parts
             and not any(source.is_relative_to(path) or path.is_relative_to(source) for path in protected),
             'fixed_distinct_cache_root_required')
        need(not any(path.is_symlink() for path in (source, *source.parents)), 'cache_root_symlink_refused')
        parent = source.parent.stat()
        need(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022,
             'cache_parent_authority_changed')
        pvc = self.cp.get('pvc', layout['pvc_name'])
        pv = self.cp.get('pv', layout['pv_name'])
        need(pvc['metadata']['uid'] == layout['pvc_uid'] and pvc['spec']['volumeName'] == layout['pv_name']
             and pv['metadata']['uid'] == layout['pv_uid'] and pv['spec'].get('local', {}).get('path') == str(source),
             'cache_volume_identity_changed')
        return source

    def cache_discard_record(self, state, role, source, staging, preserved, item, layout, expected):
        return {'version': 1, 'token': state['token'], 'role': role,
                'source': str(source), 'original': item['original'], 'pvc_uid': layout['pvc_uid'],
                'pv_uid': layout['pv_uid'], 'staging': str(staging), 'staging_identity': item['staging'],
                'baseline_sha256': sha(encoded(expected)), 'preserve_destination': str(preserved),
                'accepted_post_task_cache_loss': True}

    def cache_discard_complete(self, role, discard):
        intent_path = self.root / 'candidate-cache-discard-intent.json'
        complete_path = self.root / 'candidate-cache-discard-completed.json'
        if not os.path.lexists(intent_path):
            need(not os.path.lexists(complete_path), 'cache_discard_completion_without_intent')
            return None
        intent = load(intent_path)
        need(type(intent) is dict and set(intent) == set(discard) | {'candidate_inventory_sha256'}
             and type(intent['candidate_inventory_sha256']) is str
             and re.fullmatch('[0-9a-f]{64}', intent['candidate_inventory_sha256'])
             and intent['role'] in ('serving', 'writer'), 'candidate_cache_discard_intent_changed')
        if intent['role'] != role:
            need(os.path.lexists(complete_path)
                 and load(complete_path) == {'role': intent['role'], 'intent_sha256': sha(encoded(intent)),
                                             'original_root_absent': True}, 'unresolved_candidate_cache_discard')
            return None
        need(all(intent[key] == value for key, value in discard.items()), 'candidate_cache_discard_intent_changed')
        completion = {'role': role, 'intent_sha256': sha(encoded(intent)), 'original_root_absent': True}
        if os.path.lexists(complete_path):
            need(load(complete_path) == completion, 'candidate_cache_discard_completion_changed')
        return completion

    def discard_cache(self, state, role, source, staging, preserved, item, layout, expected, discard):
        intent_path = self.root / 'candidate-cache-discard-intent.json'
        need(not os.path.lexists(intent_path), 'single_candidate_cache_discard_required')
        need(path_identity(source) == item['original'] and path_identity(preserved) is None
             and path_identity(staging) == item['staging'], 'candidate_cache_discard_preimage_changed')
        need(self.cp.cache_manifest(staging) == expected, 'cache_staging_changed')
        need(no_nested_mounts(source), 'cache_nested_mount_refused')
        with cache_parent(source) as fd:
            inventory, inodes = discard_inventory(source, fd, item['original'])
            cache_process_guard(source, inodes)
            self.cache_boundary(state, role, layout)
            need(path_identity(staging) == item['staging'] and path_identity(preserved) is None
                 and path_identity(source.parent) == fd_identity(fd)
                 and no_nested_mounts(source)
                 and self.cp.cache_manifest(staging) == expected
                 and discard_inventory(source, fd, item['original'])[0] == inventory,
                 'candidate_cache_discard_preimage_changed')
            self.receipt('candidate-cache-discard-intent.json', {**discard, 'candidate_inventory_sha256': inventory})
            need(shutil.rmtree.avoids_symlink_attacks and path_identity(source) == item['original']
                 and path_identity(staging) == item['staging'] and path_identity(preserved) is None,
                 'candidate_cache_delete_authority_changed')
            shutil.rmtree(source.name, dir_fd=fd)
            os.fsync(fd)
        need(path_identity(source) is None and path_identity(preserved) is None, 'candidate_cache_discard_outcome_uncertain')

    def restore_cache(self, state, role, layout, expected):
        source = self.cache_boundary(state, role, layout)
        staging = source.with_name('.restore-' + role + '-' + state['token'])
        preserved = source.with_name('.failed-' + role + '-' + state['token'])
        item = state['caches'].get(role)
        if item is None:
            need((path_identity(source), path_identity(staging), path_identity(preserved)) == (layout['identity'], None, None),
                 'original_cache_root_identity_changed')
            self.receipt('cache-' + role + '-create-intent.json', {'path': str(staging), 'original': layout['identity']})
            staging.mkdir(mode=0o700)
            sync(staging.parent)
            item = {'original': layout['identity'], 'staging': tree_identity(staging), 'phase': 'created'}
            state['caches'][role] = item
            self.record(state)
        need(item['original'] == layout['identity'] and item['staging'] != item['original']
             and item['staging']['device'] == item['original']['device'], 'cache_restore_identity_changed')
        if item['phase'] == 'created':
            need(path_identity(staging) == item['staging'] and path_identity(source) == item['original']
                 and path_identity(preserved) is None, 'cache_copy_preimage_changed')
            self.cp.copy_cache(self.cp.S / 'fallback-cache' / role, staging, expected)
            item['phase'] = 'copied'
            self.record(state)
        install_name = 'cache-' + role + '-install-intent.json'
        preserve_name = 'cache-' + role + '-preserve-intent.json'
        preserve = {'original': item['original'], 'destination': str(preserved)}
        install = {'staging': item['staging'], 'destination': str(source)}
        discard = self.cache_discard_record(state, role, source, staging, preserved, item, layout, expected)
        completion = self.cache_discard_complete(role, discard)
        live, stage, old = (path_identity(path) for path in (source, staging, preserved))
        if live == item['staging'] and stage is None:
            need(item['phase'] in ('copied', 'installed') and load(self.root / install_name) == install
                 and load(self.root / preserve_name) == preserve, 'cache_installed_without_intent')
            if completion is not None:
                need(old is None and load(self.root / 'candidate-cache-discard-completed.json') == completion,
                     'candidate_cache_discard_outcome_uncertain')
            else:
                need(old == item['original'], 'preserved_task_cache_missing')
        else:
            need(item['phase'] == 'copied' and stage == item['staging'] and self.cp.cache_manifest(staging) == expected,
                 'cache_staging_changed')
            if live == item['original'] and old is None:
                need(completion is None and not os.path.lexists(self.root / preserve_name)
                     and not os.path.lexists(self.root / install_name), 'cache_preservation_outcome_uncertain')
                need(no_nested_mounts(source), 'cache_nested_mount_refused')
                self.receipt(preserve_name, preserve)
                try:
                    os.rename(source, preserved)
                except OSError:
                    live, old = path_identity(source), path_identity(preserved)
                    if live == item['original'] and old is None:
                        self.discard_cache(state, role, source, staging, preserved, item, layout, expected, discard)
                        completion = self.cache_discard_complete(role, discard)
            live, old = path_identity(source), path_identity(preserved)
            need(live is None and load(self.root / preserve_name) == preserve, 'cache_preservation_outcome_uncertain')
            sync(source.parent)
            if completion is not None:
                need(old is None, 'candidate_cache_discard_outcome_uncertain')
                self.receipt('candidate-cache-discard-completed.json', completion)
            else:
                need(old == item['original'], 'cache_preservation_outcome_uncertain')
            need(path_identity(staging) == item['staging'] and path_identity(source) is None,
                 'cache_install_preimage_changed')
            self.receipt(install_name, install)
            os.rename(staging, source)
        sync(source.parent)
        need(path_identity(source) == item['staging'] and path_identity(staging) is None
             and self.cp.cache_manifest(source) == expected, 'baseline_cache_restore_not_verified')
        item['phase'] = 'installed'
        self.record(state)

    def restore_caches(self, state):
        checked_golden(self.cp)
        cached = self.cp.load('cache-baselines.json')
        roles = ('serving', 'writer')
        need(set(self.cp.CACHE_ROOTS) == set(cached['layouts']) == set(cached['manifests']) == set(roles),
             'exact_cache_baselines_required')
        state.setdefault('caches', {})
        for role in roles:
            self.restore_cache(state, role, cached['layouts'][role], cached['manifests'][role])
        state['phase'] = 'caches_restored'
        self.record(state)

    def discarded_caches(self, state):
        cached = self.cp.load('cache-baselines.json')
        for role in ('serving', 'writer'):
            item = state['caches'][role]
            source = self.cp.CACHE_ROOTS[role]
            need(item['phase'] == 'installed' and path_identity(source) == item['staging']
                 and self.cp.cache_manifest(source) == cached['manifests'][role],
                 'baseline_cache_restore_not_verified')
        intent = self.root / 'candidate-cache-discard-intent.json'
        if not os.path.lexists(intent):
            need(not os.path.lexists(self.root / 'candidate-cache-discard-completed.json'),
                 'cache_discard_completion_without_intent')
            return []
        value = load(intent)
        role = value['role']
        need(role in ('serving', 'writer') and load(self.root / 'candidate-cache-discard-completed.json') == {
            'role': role, 'intent_sha256': sha(encoded(value)), 'original_root_absent': True},
            'candidate_cache_discard_completion_changed')
        return [role]
'''


GUARDS = r'''def path_identity(path):
    try:
        return tree_identity(path)
    except FileNotFoundError:
        return None


def fd_identity(fd):
    info = os.fstat(fd)
    return {'device': info.st_dev, 'inode': info.st_ino}


@contextlib.contextmanager
def cache_parent(source):
    fd = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'cache_parent_authority_changed')
        yield fd
    finally:
        os.close(fd)


def discard_inventory(source, parent_fd, expected):
    import time

    started = time.monotonic()
    inventory = hashlib.sha256()
    inodes = set()
    links = {}
    count = 0

    def record(name, info):
        nonlocal count
        count += 1
        need(count <= 1_000_000 and time.monotonic() - started < 300, 'candidate_cache_inventory_bound')
        need(info.st_dev == expected['device'] and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)),
             'candidate_cache_unsafe_entry')
        identity = (info.st_dev, info.st_ino)
        inodes.add(identity)
        if stat.S_ISREG(info.st_mode):
            link = links.setdefault(identity, [0, info.st_nlink])
            need(link[1] == info.st_nlink, 'candidate_cache_hardlink_changed')
            link[0] += 1
        inventory.update(encoded((name, *identity, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                                  info.st_size, info.st_mtime_ns, info.st_ctime_ns)) + b'\n')

    original = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
    need(stat.S_ISDIR(original.st_mode)
         and (original.st_dev, original.st_ino) == (expected['device'], expected['inode']),
         'candidate_cache_root_changed')
    record('', original)

    def inaccessible(error):
        raise error

    walked = False
    for path, directories, files, fd in os.fwalk(source.name, follow_symlinks=False, dir_fd=parent_fd,
                                                 onerror=inaccessible):
        if not walked:
            need(fd_identity(fd) == expected, 'candidate_cache_root_changed')
            walked = True
        directories.sort()
        for name in sorted(directories + files):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            record(str(Path(path) / name), info)
    need(walked and path_identity(source) == expected, 'candidate_cache_root_changed')
    need(all(observed == expected for observed, expected in links.values()), 'external_candidate_cache_hardlink')
    return inventory.hexdigest(), inodes


def cache_process_guard(source, inodes, proc=Path('/proc')):
    """Refuse cache mounts, bind aliases, open handles and active mappings."""
    import time

    started = time.monotonic()

    def mounts(path):
        with path.open('rb') as stream:
            body = stream.read(8 * 1024**2 + 1)
        need(0 < len(body) <= 8 * 1024**2, 'cache_mount_inventory_bound')
        for line in os.fsdecode(body).splitlines():
            fields = line.split()
            need(len(fields) >= 10 and '-' in fields and re.fullmatch(r'\d+:\d+', fields[2]),
                 'cache_mount_inventory_invalid')
            def unescape(field):
                return Path(re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), field))
            yield fields[2], unescape(fields[3]), unescape(fields[4])

    current = list(mounts(proc / 'self/mountinfo'))
    info = source.stat()
    device = f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}'
    ancestors = [(root, target) for dev, root, target in current if dev == device and source.is_relative_to(target)]
    need(ancestors and not any(target.is_relative_to(source) for _, _, target in current), 'candidate_cache_mount_present')
    root, target = max(ancestors, key=lambda item: len(item[1].parts))
    physical = root / source.relative_to(target)
    namespaces = set()
    references = 0
    for index, pid in enumerate(path for path in proc.iterdir() if path.name.isdecimal()):
        need(index < 100_000 and time.monotonic() - started < 120, 'cache_process_inventory_bound')
        try:
            namespace = os.readlink(pid / 'ns/mnt')
            if namespace not in namespaces:
                need(not any(dev == device and mounted.is_relative_to(physical) for dev, mounted, _ in mounts(pid / 'mountinfo')),
                     'candidate_cache_bind_mount_present')
                namespaces.add(namespace)
            for path in (pid / 'cwd', pid / 'root', pid / 'exe', *(pid / 'fd').iterdir()):
                references += 1
                need(references <= 200_000 and time.monotonic() - started < 120, 'cache_process_inventory_bound')
                try:
                    info = path.stat()
                except (FileNotFoundError, ProcessLookupError):
                    continue
                need((info.st_dev, info.st_ino) not in inodes, 'active_candidate_cache_reference')
            with (pid / 'maps').open() as stream:
                for line in stream:
                    references += 1
                    need(references <= 200_000 and time.monotonic() - started < 120, 'cache_process_inventory_bound')
                    fields = line.split(None, 5)
                    need(len(fields) >= 5, 'cache_process_mapping_invalid')
                    major, minor = (int(part, 16) for part in fields[3].split(':'))
                    need((os.makedev(major, minor), int(fields[4])) not in inodes, 'active_candidate_cache_mapping')
            need(os.readlink(pid / 'ns/mnt') == namespace, 'cache_process_namespace_changed')
        except (FileNotFoundError, ProcessLookupError):
            continue
'''


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise RenderError('exact_restore_source_anchor_required')
    return source.replace(old, new, 1)


def patch_restore(text: str) -> str:
    """Replace only audited restore methods and require the source's unique anchors."""
    tree = ast.parse(text)
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Restore']
    if len(classes) != 1 or text.count('shutil.rmtree(self.source)') != 2:
        raise RenderError('cycle5_restore_source_required')
    replacements = {'preserve_and_install': DATABASE, 'restore_caches': CACHES, 'reconcile': RECONCILE}
    lines = text.splitlines(keepends=True)
    for name, replacement in replacements.items():
        nodes = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(nodes) != 1:
            raise RenderError('exact_restore_method_required')
        node = nodes[0]
        old = ''.join(lines[node.lineno - 1:node.end_lineno])
        if hashlib.sha256(old.encode()).hexdigest() != REPLACED_METHODS[name]:
            raise RenderError('frozen_restore_method_changed')
        text = replace_once(text, old, replacement)
    if 'shutil.rmtree(self.source)' in text or "'post_task_sql_lost'" not in text:
        raise RenderError('unsafe_sql_discard_branch_retained')
    text = replace_once(text, '\ndef golden_size(cp):', '\n' + GUARDS + '\n\ndef golden_size(cp):')
    text = replace_once(text, "        staging, _ = self.paths(state)\n        self.guard('install')",
                        "        self.require_preserved_database(state)\n        staging, _ = self.paths(state)\n        self.guard('install')")
    text = replace_once(text, "    def run(self, pins, resume=False):\n        if resume:",
                        "    def run(self, pins, resume=False):\n        self.reject_sql_loss()\n        if resume:")
    text = replace_once(text, "            state = self.state()\n            need(state['pins'] == pins",
                        "            state = self.state()\n            self.reject_sql_loss(state)\n            need(state['pins'] == pins")
    text = replace_once(text, "            if state['phase'] == 'restored':\n                receipt",
                        "            if state['phase'] == 'restored':\n                self.require_preserved_database(state)\n                receipt")
    text = replace_once(text, "        self.guard('restart')\n        need(tree_identity(self.source)",
                        "        self.require_preserved_database(state)\n        self.guard('restart')\n        discarded = self.discarded_caches(state)\n        need(tree_identity(self.source)")
    text = replace_once(text, "        self.cp.k('scale', 'deployment/postgres', '--replicas=1')",
                        "        replicas = self.cp.get('deployment', 'postgres')['spec'].get('replicas')\n"
                        "        need(type(replicas) is int and replicas in (0, 1), 'unexpected_postgres_replica_state')\n"
                        "        if replicas == 0:\n"
                        "            self.cp.k('scale', 'deployment/postgres', '--replicas=1')")
    text = replace_once(text, "                   'baseline_caches_restored': True,",
                        "                   'baseline_caches_restored': True, 'discarded_candidate_caches': discarded,")
    text = replace_once(text, 'The caller subsequently prepares and qualifies fallback91. Post-task SQL preservation\nis best effort, while identity, exclusivity and golden-checkpoint proof are mandatory.',
                        'Preserve post-task PostgreSQL. At most one candidate cache may be discarded\nunder a separate exact-identity receipt. Restore leaves application roles withdrawn.')
    ast.parse(text)
    return text
