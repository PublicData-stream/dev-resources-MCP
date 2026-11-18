"""Runtime additions rendered into the new controller only."""


def cycle6_previous_controller(context):
    require(context == 'default', 'explicit_target_required')
    bridge, receipt_sha = cycle4_edge_bridge()
    require(receipt_sha == C5_EDGE_SHA, 'fixed_reused_edge_admission_required')
    bridge.native_guard(receipt_sha)
    path = PREVIOUS_CONTROLLER
    body = cycle5_source_bytes(path)
    require(digest(body) == PREVIOUS_CONTROLLER_SHA, 'fixed_cycle5_controller_required')
    spec = importlib.util.spec_from_file_location('cycle6_frozen_cycle5', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(body, str(path), 'exec'), module.__dict__)
    require(module.REVISION == PREVIOUS_REVISION and module.IMAGE == PREVIOUS_IMAGE
            and module.WORK == str(PREVIOUS_WORK) and module.BUNDLE == str(PREVIOUS_BUNDLE),
            'fixed_cycle5_runtime_required')
    require(digest(cycle5_source_bytes(PREVIOUS_BUNDLE / 'state.json')) == PREVIOUS_STATE_SHA,
            'fixed_cycle5_restored_state_required')
    require(digest(cycle5_source_bytes(PREVIOUS_BUNDLE / 'restore/restored.json')) == PREVIOUS_RESTORE_SHA,
            'fixed_cycle5_restoration_required')

    original = module.Controller
    attributes = {
        '__module__': original.__module__,
        '__init__': cycle5_clone(original.__init__, {'predecessor': predecessor}),
    }
    # Historical guard methods depend on the external source-manifest pin.
    # Use this cycle's admitted edge bridge without changing historical globals.
    for name in ('edge', 'boundary_guard'):
        method = getattr(original, name)
        require('cycle4_edge_bridge' in method.__code__.co_names, 'fixed_cycle5_edge_call_sites_required')
        attributes[name] = cycle5_clone(method, {'cycle4_edge_bridge': cycle4_edge_bridge})
    adapted = type('Cycle6BoundFrozenCycle5', (original,), attributes)
    facade = bridge._read_only_facade(adapted)
    for name in ('start_observer', 'stop_observer', 'renew_active_migration', 'npm_assess', 'cleanup_maintenance'):
        setattr(facade, name, bridge._refuse_mutation)
    with bridge.historical_projection():
        previous = facade(str(PREVIOUS_BUNDLE), str(PREVIOUS_BUNDLE / 'plan.json'), context)
    require(cycle5_source_bytes(path) == body, 'fixed_cycle5_controller_changed')
    return previous


def cycle6_restore_template_images(controller, prepared):
    """Restore the actual captured template image without starting either role."""
    for role in ROLES:
        obj = controller.get('deployment', role)
        projection, image = deployment_projection(obj)
        wanted = prepared['initial_images'][role]
        require(wanted == PREVIOUS_IMAGE and image in (PREVIOUS_IMAGE, IMAGE)
                and projection == prepared['deployments'][role]['projection']
                and obj['spec']['replicas'] == 0, 'restore_template_boundary_changed')
        if image != wanted:
            patch = [
                {'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                {'op': 'test', 'path': '/spec/replicas', 'value': 0},
                {'op': 'test', 'path': '/spec/template/spec/containers/0/image', 'value': image},
                {'op': 'replace', 'path': '/spec/template/spec/containers/0/image', 'value': wanted},
            ]
            controller.mutate('restore-template-image-' + role, lambda r=role, p=patch:
                controller.old.k('patch', 'deployment', r, '--type=json', '--patch-file=/dev/stdin', data=encoded(p)))
            actual = controller.get('deployment', role)
            require(deployment_projection(actual) == (projection, wanted)
                    and actual['spec']['replicas'] == 0, 'restore_template_image_readback_changed')


def cycle6_check_assessment(controller):
    helper = controller.helper('npm-recovery.py', 'cycle6_completed_assessment')
    report = read(Path(WORK) / 'npm-assessment/report.json')
    expected = helper.validate_report(json.loads(report))
    value = load(controller.root / 'npm-assessment-completed.json')
    expected_keys = set(expected) | {'report_sha256', 'transport', 'pod_uid', 'container_id',
                                     'cli_report_in_logs', 'phases', 'phase_known', 'at'}
    require(set(value) == expected_keys and all(value[name] == v for name, v in expected.items())
            and value['eligible'] is False and value['deferred'] is True
            and value['reason'] == 'legacy_unknown' and digest(report) == value['report_sha256']
            and value['transport'] == 'uid-bookended-private-exec' and value['cli_report_in_logs'] is False,
            'verified_assessment_report_required')
    identity = load(controller.root / 'npm-assessment-pod-identity.json')
    require(identity == {'name': helper.POD, 'uid': value['pod_uid']}
            and isinstance(value['pod_uid'], str) and bool(value['pod_uid'])
            and isinstance(value['container_id'], str) and value['container_id'].startswith('containerd://')
            and value['phase_known'] is (value['phases'] is not None), 'assessment_execution_identity_changed')
    require(not os.path.lexists(controller.root / 'npm-assessment-failed.json')
            and load(controller.root / 'npm-assessment-network-admission.json')
            and load(controller.root / 'npm-assessment-network-state.json') == {'phase': 'removed'}
            and not helper.network_guard(controller), 'assessment_cleanup_required')
    pods = json.loads(controller.old.k('get', 'pods', '-o', 'json'))['items']
    require(all(pod['metadata']['name'] != helper.POD
                and pod['metadata'].get('labels', {}).get('app') != helper.ASSESSMENT_APP for pod in pods),
            'assessment_pod_remaining')
