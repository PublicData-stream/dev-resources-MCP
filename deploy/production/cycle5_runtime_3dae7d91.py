"""C5 source fragment: retain frozen C4 history and admit its restored template."""
import types

C5_PREVIOUS_WORK = Path('/tmp/devres-upgrade-3dae7d91-20261117')
C5_PREVIOUS_INSTALL = Path('/usr/local/libexec/devres-upgrade-3dae7d91')
C5_PREVIOUS_BUNDLE = Path('/var/lib/devres-production-upgrades/3dae7d91-20261117')
C5_PREVIOUS_CONTROLLER_SHA = '8290b5388a4a02391d441dd56bd803830389e01d3037bb30916de487559c8a4e'
C5_PREVIOUS_MANIFEST_SHA = 'a23b1015e38926627bfe2d8883d3ebe46d9c23dadcbe68ba1695529f0808be5e'
C5_PREVIOUS_PUBLIC_SHA = 'e102b153c9ab638ecaa1deaf3f5326129ed38f20a57cdcc37e03842da0f3ccf7'
C5_EDGE_SHA = 'e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a'
C5_SPECIAL_NAMES = ('edge-qualification.py', 'edge-readmission.py', 'npm-recovery.py',
    'physical-checkpoint.py', 'restore-controller.py', 'restore-rehearsal.py', 'safety-supervisor.py', 'upgrade-controller.py')


def cycle5_source_bytes(path, private=True):
    path = Path(path)
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'cycle5_source_path_changed')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
            and not before.st_mode & (0o077 if private else 0o022) and before.st_size <= 8*1024**2, 'cycle5_source_authority_changed')
        body = stream.read(8*1024**2+1); after = os.fstat(stream.fileno())
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_gid', 'st_mode', 'st_nlink')
        require(len(body) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in keys), 'cycle5_source_changed')
    return body


def cycle5_historical_closure():
    manifest_body = cycle5_source_bytes(C5_PREVIOUS_WORK / 'source-manifest.json')
    require(digest(manifest_body) == C5_PREVIOUS_MANIFEST_SHA, 'fixed_cycle4_manifest_required')
    manifest = json.loads(manifest_body)
    require(set(manifest) == set(HISTORY_SPECIAL_NAMES['cycle4']) | set(HISTORY_SOURCE_NAMES['cycle4'])
        and len(manifest) == 29 and manifest['upgrade-controller.py'] == C5_PREVIOUS_CONTROLLER_SHA,
        'fixed_cycle4_source_inventory_required')
    for name, wanted in manifest.items():
        path = (C5_PREVIOUS_INSTALL if name in C5_SPECIAL_NAMES else C5_PREVIOUS_WORK) / name
        require(re.fullmatch('[0-9a-f]{64}', wanted or '') and digest(cycle5_source_bytes(path)) == wanted,
            'fixed_cycle4_source_changed')
    public_body = cycle5_source_bytes(C5_PREVIOUS_WORK / 'public-upgrade-identity.json')
    require(digest(public_body) == C5_PREVIOUS_PUBLIC_SHA, 'fixed_cycle4_public_required')
    dependencies = json.loads(public_body)['dependency_sources']
    require(type(dependencies) is dict and len(dependencies) == 29, 'fixed_cycle4_dependencies_required')
    dependencies = dict(dependencies)
    for name in C5_SPECIAL_NAMES:
        path = str(C5_PREVIOUS_INSTALL / name)
        require(path not in dependencies, 'cycle5_dependency_collision')
        dependencies[path] = manifest[name]
    require(len(dependencies) == 37, 'exact_cycle5_dependency_union_required')
    for name, wanted in dependencies.items():
        path = Path(name)
        require(path.is_relative_to('/usr/local/libexec') and path.suffix == '.py'
            and re.fullmatch('[0-9a-f]{64}', wanted or '') and digest(cycle5_source_bytes(path, False)) == wanted,
            'cycle5_historical_dependency_changed')
    return manifest, dependencies


def cycle5_bound_frozen_edge():
    manifest, _ = cycle5_historical_closure()
    bridge, receipt_sha = cycle4_edge_bridge()
    require(receipt_sha == C5_EDGE_SHA and digest(cycle5_source_bytes(Path(bridge.__file__))) == manifest['edge-readmission.py'],
        'fixed_reused_edge_admission_required')
    return bridge, receipt_sha


def cycle5_clone(function, replacements):
    namespace = dict(function.__globals__); namespace.update(replacements)
    cloned = types.FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
    cloned.__kwdefaults__ = function.__kwdefaults__
    return cloned


def cycle5_previous_controller(context):
    require(context == 'default', 'explicit_target_required')
    bridge, receipt_sha = cycle5_bound_frozen_edge()
    bridge.native_guard(receipt_sha)
    path = C5_PREVIOUS_INSTALL / 'upgrade-controller.py'
    body = cycle5_source_bytes(path)
    require(digest(body) == C5_PREVIOUS_CONTROLLER_SHA, 'fixed_cycle4_controller_required')
    spec = importlib.util.spec_from_file_location('cycle5_frozen_consumed_cycle4', path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    exec(compile(body, str(path), 'exec'), module.__dict__)
    original = module.Controller
    require('predecessor' in original.__init__.__code__.co_names, 'fixed_cycle4_constructor_required')
    sites = {name for name, fn in original.__dict__.items() if isinstance(fn, types.FunctionType)
        and 'cycle4_edge_bridge' in fn.__code__.co_names}
    require(sites == {'edge', 'boundary_guard'}, 'fixed_cycle4_edge_call_sites_required')
    def predecessor(context):
        require(context == 'default', 'explicit_target_required')
        return bridge.load_controller(Path(module.PRIOR_CONTROLLER), module.PRIOR_SHA, module.PRIOR_BUNDLE,
            context, receipt_sha=receipt_sha)
    attributes = {'__module__': original.__module__, '__init__': cycle5_clone(original.__init__, {'predecessor': predecessor})}
    for name in sites:
        attributes[name] = cycle5_clone(getattr(original, name), {'cycle4_edge_bridge': cycle5_bound_frozen_edge})
    adapted = type('Cycle5BoundFrozenCycle4', (original,), attributes)
    # The original implementation is retained, with projections scoped by the
    # existing edge bridge. No historical module globals or environment change.
    facade = bridge._read_only_facade(adapted)
    for name in ('start_observer', 'stop_observer', 'renew_active_migration', 'npm_assess', 'cleanup_maintenance'):
        if hasattr(facade, name):setattr(facade, name, bridge._refuse_mutation)
    with bridge.historical_projection():
        previous = facade(str(C5_PREVIOUS_BUNDLE), str(C5_PREVIOUS_BUNDLE / 'plan.json'), context)
    require(cycle5_source_bytes(path) == body, 'fixed_cycle4_controller_changed')
    return previous


_Cycle5BaseController = Controller


class Controller(_Cycle5BaseController):
    def prepare(self):
        require(not self.root.exists(), 'bundle_already_exists')
        previous = previous_cycle(self.context)
        previous.guard(); before = previous.state()
        initial_images = {'postgres': PG_IMAGE, 'writer': IMAGE, 'backend': IMAGE}
        require(before['revision'] == REVISION and before['runtime'] == 'restored'
            and before['phase'] == 'withdrawn' and before['configs'] == 'old'
            and before['replicas'] == {'postgres': 1, 'writer': 0, 'backend': 0}
            and set(before['pods']) == {'postgres'} and before['images'] == initial_images,
            'restored_cycle4_predecessor_required')
        snap = self.snapshot(); historical = previous.snapshot()
        require(snap == historical and snap['pods'] == before['pods'], 'previous_cycle_runtime_changed')
        require({role: snap['deployments'][role]['image'] for role in initial_images} == initial_images,
            'admitted_initial_templates_changed')
        self.storage_guard(18, owner=False); observed = stamp()
        original = read(C5_PREVIOUS_BUNDLE / 'configs-fallback-active.json')
        previous_prepared = load(C5_PREVIOUS_BUNDLE / 'prepared.json')
        require(digest(original) == previous_prepared['config_hashes']['fallback-active'], 'previous_desired_active_config_changed')
        desired = json.loads(original); require(set(desired) == set(ROLES), 'desired_runtime_role_set')
        variants = {key: {} for key in ('paused', 'active', 'fallback-paused', 'fallback-active')}
        deployments = {}
        for role in initial_images:
            obj = self.get('deployment', role); projection, image = deployment_projection(obj)
            require(image == initial_images[role], 'admitted_initial_templates_changed')
            deployments[role] = {'projection': projection, 'manifest': obj}
        for role in ROLES:
            for variant in variants:
                text = configuration(desired[role], variant.endswith('active'))
                if variant.startswith('fallback-'):text = text.replace(SOURCE_URL, fallback_source_url())
                variants[variant][role] = text
        observer_variants(variants); artifacts = self.prior_hashes()
        previous.guard()
        require(self.snapshot() == snap and self.prior_hashes() == artifacts, 'prepare_runtime_changed')
        require((utc_now() - instant(observed)).total_seconds() <= 300, 'inventory_stale')
        self.plan = {'version': 1, 'revision': REVISION, 'context': self.context, 'target_image': IMAGE,
            'store_binding_sha256': STORE_BINDING, 'captured_at': observed, 'cycle': 5}
        self.plan_raw = encoded(self.plan)
        prepared = {**{k: v for k, v in snap.items() if k not in ('deployments', 'pods')},
            'version': 1, 'revision': REVISION, 'at': observed, 'deployments': deployments,
            'old_pods': snap['pods'], 'initial_images': initial_images, 'store_binding_sha256': STORE_BINDING,
            'prior_artifacts': artifacts, 'desired_active_source_sha256': digest(original),
            'previous_cycle_source_sha256': C5_PREVIOUS_CONTROLLER_SHA,
            'edge_readmission_sha256': C5_EDGE_SHA,
            'config_hashes': {k: digest(encoded(v)) for k, v in variants.items()}}
        self.root.mkdir(mode=0o700); syncdir(self.root.parent)
        save(self.root / 'plan.json', self.plan_raw)
        for variant, value in variants.items():save(self.root / ('configs-' + variant + '.json'), value)
        save(self.root / 'prepared.json', prepared)
        save(self.root / 'state.json', {'version': 1, 'revision': REVISION, 'phase': 'prepared', 'runtime': 'target',
            'source_sha256': digest(Path(__file__).read_bytes()), 'plan_sha256': digest(self.plan_raw),
            'prepared_sha256': digest(encoded(prepared)), 'configs': 'old', 'pods': snap['pods'],
            'images': initial_images, 'replicas': {'postgres': 1, 'writer': 0, 'backend': 0}})
        self.guard()
