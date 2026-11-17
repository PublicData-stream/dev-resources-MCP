"""Fail-closed acceptance adaptations for the fresh, target-only deployment cycle.

The renderer supplies already rebased, immutable predecessor text.  This module
changes only the listed first-party producers; it never imports a live controller
or modifies a consumed source closure.
"""
from __future__ import annotations

import ast
import textwrap


class TransformError(RuntimeError):
    pass


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise TransformError('one_reviewed_acceptance_site_required')
    return source.replace(old, new)


def replace_function(source, name, replacement):
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    if len(nodes) != 1:
        raise TransformError('one_reviewed_acceptance_function_required')
    node = nodes[0]
    lines = source.splitlines(keepends=True)
    return ''.join(lines[:node.lineno - 1]) + textwrap.dedent(replacement).strip() + '\n' + ''.join(lines[node.end_lineno:])


LIFECYCLE = '''
def run_lifecycle(stage, sources, runtime):
    """One target: bootstrap, read-only observation, then active ownership."""
    common.need(runtime == 'target', 'target_only_deployment')
    phase = lambda operation: source_command('phase-driver.py', operation,
        '--controller-sha', sources['upgrade-controller.py'])
    proofs = ['--controller', str(common.CONTROLLER), '--controller-sha', sources['upgrade-controller.py'],
              '--checkpoint', str(common.CHECKPOINT), '--checkpoint-sha', sources['physical-checkpoint.py']]
    stage('apply', phase('apply'), 300)
    stage('start-writer', phase('start-writer'), 360)
    stage('migration-before-npm', source_command('operational-proof.py', 'migration',
          '--label', 'migration-before-npm', *proofs), 360)
    # The maintained assessment stops bootstrap and never restarts a full writer.
    stage('npm-recovery', phase('npm-recovery'), 900)
    stage('start-observer', phase('start-observer'), 720)
    stage('paused-acceptance', source_command('runner.py', '--runtime', 'target', '--mode', 'paused',
          '--source-manifest-sha256', os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256']), 2400)
    # Consume the exact paused receipt while observer/reader identities are live.
    # The controller then stops both, reverses Service/policies and starts the
    # full writer, renews migration proof, and finally starts the reader.
    stage('activate-existing', phase('activate-existing'), 1200)
    stage('active-acceptance', source_command('runner.py', '--runtime', 'target', '--mode', 'active',
          '--source-manifest-sha256', os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256']), 3300)
'''

RECOVER_TARGET = '''
def recover_target(controller):
    """At most one physical restoration; no restored application is started."""
    runtime, phase = controller_phase(controller)
    if phase == 'withdrawn' and runtime == 'restored':
        common.need(set(controller.state().get('pods', {})) == {'postgres'}, 'restored_application_remaining')
        controller.guard()
        controller.storage_guard(18, owner=False)
        return True
    common.need(runtime == 'target', 'unknown_recovery_runtime')
    common.need(enforce_withdrawal(controller), 'withdrawal_incomplete')
    controller.rollback()
    state = controller.state()
    common.need(state.get('runtime') == 'restored' and state.get('phase') == 'withdrawn'
        and set(state.get('pods', {})) == {'postgres'}, 'restore_withdrawal_incomplete')
    return True
'''

COMPLETE = '''
def complete(runtime, sources, controller, supervisor, manifest_sha):
    """Target failure is never converted into accepted fallback service."""
    common.need(runtime == 'target', 'target_only_deployment')
    stage = lambda label, command, timeout: supervisor.run_stage('deploy-' + label, command, timeout)
    try:
        run_lifecycle(stage, sources, runtime)
        common.need(controller_phase(controller) == ('target', 'complete'), 'completed_runtime_required')
        return {'known_complete': True, 'target_deployed': True, 'fallback_deployed': False,
                'runtime': 'target', 'revision': common.REVISION, 'outcome': 'target_accepted'}
    except BaseException:
        try:
            recover_target(controller)
            return {'known_complete': False, 'target_deployed': False, 'fallback_deployed': False,
                    'runtime': 'restored', 'outcome': 'target_failed_restored_withdrawn',
                    'withdrawal_completed': True, 'schema18_restored': True}
        except BaseException:
            fenced = False
            try:
                fenced = enforce_withdrawal(controller)
            except BaseException:
                pass
            return {'known_complete': False, 'target_deployed': False, 'fallback_deployed': False,
                    'runtime': 'target', 'outcome': 'restore_incomplete', 'withdrawal_completed': fenced}
'''

RECOVER_FAILURE = '''
def recover_failure():
    # Only the outer deployment controller/supervisor owns physical recovery.
    # Acceptance children always return after withdrawal, even when invoked alone.
    result = {'known_complete': False, 'runtime': common.RUNTIME,
              'withdrawal_completed': False, 'fallback_prepared': False}
    try:
        result['withdrawal_completed'] = withdraw()
    except BaseException:
        pass
    return result
'''


def transform(name, source):
    """Adapt only known source sites and reject drift rather than guessing."""
    if name == 'deploy.py':
        source = replace_function(source, 'run_lifecycle', LIFECYCLE)
        source = replace_function(source, 'recover_target', RECOVER_TARGET)
        source = replace_function(source, 'complete', COMPLETE)
        source = replace_function(source, 'supervise_fallback', '''
            def supervise_fallback(*args, **kwargs):
                raise RuntimeError('fallback_service_forbidden')
        ''')
        source = replace_once(source, "    common.need(runtime == common.RUNTIME, 'runtime_environment_mismatch')",
            "    common.need(runtime == common.RUNTIME == 'target', 'target_only_deployment')")
        source = replace_once(source,
            "        if runtime == 'target':\n            verify_restore_rehearsal(controller, sources)",
            "        if runtime == 'target':\n            controller.require_operational_baseline()\n            verify_restore_rehearsal(controller, sources)")
        source = replace_once(source,
            "    return 0 if value.get('target_deployed') or args.runtime == 'fallback' and value.get('fallback_deployed') else 1",
            "    return 0 if value.get('target_deployed') is True else 1")
    elif name == 'phase-driver.py':
        source = replace_once(source,
            "'withdraw', 'npm-recovery')", "'withdraw', 'npm-recovery', 'start-observer')")
        source = replace_once(source,
            "    if operation == 'npm-recovery':",
            "    if operation == 'start-observer':\n"
            "        result = controller.start_observer()\n"
            "        common.need(controller.state()['phase'] == 'reader_ready', 'observer_reader_ready_required')\n"
            "        return {'operation': operation, 'runtime': 'target', 'known_complete': True, 'phase': 'reader_ready'}\n"
            "    if operation == 'npm-recovery':")
        source = replace_once(source, "result = controller.npm_recovery()", "result = controller.npm_assess()")
    elif name == 'runner.py':
        source = replace_once(source,
            "role in {'backend', 'writer', 'postgres'}", "role in {'backend', 'writer', 'postgres', 'status-observer', 'devres-npm-assessment'}")
        source = replace_once(source,
            "            ('activate-existing', phase('activate-existing'), 720),\n", '')
        source = replace_function(source, 'recover_failure', RECOVER_FAILURE)
        source = replace_once(source,
            "    os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256'] = expected",
            "    common.need(common.RUNTIME == 'target', 'target_only_acceptance')\n"
            "    os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256'] = expected")
    elif name == 'deploy/diagnostics/evidence.py':
        source = replace_once(source,
            "value['role'] not in {'backend', 'writer', 'postgres'}",
            "value['role'] not in {'backend', 'writer', 'postgres', 'status-observer', 'devres-npm-assessment'}")
    elif name == 'operational-proof.py':
        source = _operational(source)
    elif name == 'acceptance-receipt.py':
        source = _receipts(source)
    elif name == 'target-private-acceptance.py':
        source = _private(source)
    ast.parse(source, filename=name)
    return source


def _operational(source):
    source = replace_once(source,
        "        need(state['phase'] in ('prepared','stopped') and state['configs']=='old','baseline_before_target_only')",
        "        need(state['runtime']=='target' and state['phase']=='stopped' and state['configs']=='old'\n"
        "             and state['replicas']=={'postgres':1,'writer':0,'backend':0}\n"
        "             and set(state['pods'])=={'postgres'}\n"
        "             and state['pods']==load(BUNDLE/'prepared.json')['old_pods'],'baseline_before_target_only')\n"
        "        sources=common.manifest_sources()\n"
        "        need(sha(raw(Path(controller.__file__)))==sources['upgrade-controller.py']\n"
        "             and sha(raw(Path(checkpoint.__file__)))==sources['physical-checkpoint.py']\n"
        "             and sha(raw(Path(__file__)))==sources['operational-proof.py'],'baseline_source_binding_required')")
    source = replace_once(source,
        "        result={'version':1,'kind':'pre-upgrade-operational-baseline','revision':REVISION,'observed_at':now(),",
        "        result={'version':1,'kind':'pre-upgrade-operational-baseline','revision':REVISION,'observed_at':now(),\n"
        "                'source_manifest_sha256':sha(raw(common.MANIFEST)),\n"
        "                'sources':{name:sources[name] for name in ('upgrade-controller.py','physical-checkpoint.py','operational-proof.py')},\n"
        "                'pre_upgrade':{'phase':state['phase'],'configs':state['configs'],'replicas':state['replicas'],'pods':state['pods']},")
    source = replace_once(source, 'import argparse\n', 'import argparse\nimport contextlib\n')
    source = replace_once(source,
        '    module = importlib.util.module_from_spec(spec)\n    spec.loader.exec_module(module)',
        '    module = importlib.util.module_from_spec(spec)\n    sys.modules[name] = module\n    spec.loader.exec_module(module)')
    source = replace_once(source,
        "    if state['configs']=='paused':",
        "    if state['configs'] in ('paused','observer'):")
    source = replace_once(source,
        'def observation(controller,checkpoint,mode,label):\n'
        "    c=controller.Controller(str(BUNDLE),str(BUNDLE/'plan.json'),'default')",
        'def observation(controller,checkpoint,mode,label,*,locked_controller=None):\n'
        "    c=locked_controller if locked_controller is not None else controller.Controller(str(BUNDLE),str(BUNDLE/'plan.json'),'default')\n"
        "    if locked_controller is not None:\n"
        "        need(mode=='migration-active' and c.__class__ is controller.Controller\n"
        "             and str(c.root)==str(BUNDLE) and c.context=='default', 'sameprocess_locked_migration_required')")
    source = replace_once(source,
        "    out=proofs/label;out.mkdir(mode=0o700)\n    with c.locked():",
        "    out=proofs/label;out.mkdir(mode=0o700)\n    with (contextlib.nullcontext() if locked_controller is not None else c.locked()):")
    source = replace_once(source,
        "    need(len(owners)==1 and owners[0]['role']=='devres_writer'\n"
        "         and owners[0]['client_addr']==state['pods']['writer']['pod_ip'],'sole_writer_owner_required')",
        "    if 'status-observer' in state['pods']:\n"
        "        need(state['configs']=='observer' and set(state['pods'])=={'postgres','backend','status-observer'}\n"
        "             and owners==[], 'paused_observer_without_owner_required')\n"
        "    else:\n"
        "        need(len(owners)==1 and owners[0]['role']=='devres_writer'\n"
        "             and owners[0]['client_addr']==state['pods']['writer']['pod_ip'],'sole_writer_owner_required')")
    source = replace_once(source,
        "        if mode=='migration':need(state['phase']=='writer_ready' and state['configs']=='paused' and set(state['pods'])=={'postgres','writer'},'paused_sole_target_writer_required')",
        "        if mode=='migration':need(state['phase']=='writer_ready' and state['configs']=='paused' and set(state['pods'])=={'postgres','writer'},'paused_sole_target_writer_required')\n"
        "        elif mode=='migration-active':need(state['phase']=='activate-existing_incomplete' and state['configs']=='active' and set(state['pods'])=={'postgres','writer'},'active_sole_target_writer_required')")
    source = replace_once(source,
        "        record['free_bytes']=shutil.disk_usage('/database/devres').free",
        "        if 'status-observer' in state['pods']:\n"
        "            observer=c.observer_proof()\n"
        "            need(observer.get('verified') is True and observer.get('process')==state['pods']['status-observer']\n"
        "                 and all(observer.get(k) is True for k in ('no_publication_owner','retained_sql_unchanged','no_provider_requests','no_repairs_or_queue_writes')), 'observer_readonly_proof_required')\n"
        "            record['observer']=observer\n"
        "        record['free_bytes']=shutil.disk_usage('/database/devres').free")
    old = "        c.guard();need(c.state()==state,'guard_state_changed')\n        detail=out/'observation.json';save(detail,record)"
    source = replace_once(source, old,
        "        if mode=='migration-active':\n"
        "            prior=WORK/'operational-proofs/migration-before-npm'\n"
        "            paused=load(prior/'observation.json')\n"
        "            sealed=load(prior/'migration-receipt.json')\n"
        "            need(sealed.get('version')==1 and sealed.get('kind')=='migration'+str(common.SCHEMA)\n"
        "                 and sealed.get('revision')==REVISION and sealed.get('verified') is True\n"
        "                 and sealed.get('prepared_sha256')==state['prepared_sha256']\n"
        "                 and sealed.get('runtime')=='target' and sealed.get('runtime_revision')==common.IDENTITY['revision']\n"
        "                 and sealed.get('processes')==paused['pods'] and sealed.get('configs')=='paused'\n"
        "                 and all(sealed.get('checks',{}).get(k) is True for k in ('schema'+str(common.SCHEMA),'policy2','sole_writer','new_table_reader_grants','history_preserved','archive_binding_preserved','historical_notices_preserved')), 'prior_paused_migration_receipt_required')\n"
        "            expected_paths={str(prior/name) for name in ('observation.json','archive-bindings.jsonl','capture-bindings.jsonl')}\n"
        "            need(isinstance(sealed.get('artifacts'),list) and {v.get('path') for v in sealed['artifacts']}==expected_paths\n"
        "                 and all(file_sha(Path(v['path']))==v.get('sha256') for v in sealed['artifacts']), 'prior_paused_migration_artifacts_changed')\n"
        "            need(paused['revision']==REVISION and paused['prepared_sha256']==state['prepared_sha256']\n"
        "                 and paused['configs_variant']=='paused' and paused['database']['schema']==common.SCHEMA\n"
        "                 and paused['database']['system_id']==database['system_id']\n"
        "                 and paused['database']['archive']==database['archive']\n"
        "                 and database['capture_count']>=paused['database']['capture_count']\n"
        "                 and database['archive_files']>=paused['database']['archive_files'], 'active_migration_history_binding_required')\n"
        "            for name in ('observation.json','migration-receipt.json','archive-bindings.jsonl','capture-bindings.jsonl'):\n"
        "                artifacts.append({'path':str(prior/name),'sha256':file_sha(prior/name)})\n"
        "            record['history_scope']='prior_exact_paused_manifest_and_current_monotonic_counts'\n"
        "        c.guard();need(c.state()==state,'guard_state_changed')\n        detail=out/'observation.json';save(detail,record)")
    source = replace_once(source,
        "        if mode=='migration':\n            receipt=", "        if mode in ('migration','migration-active'):\n            receipt=")
    source = replace_once(source,
        "choices=('baseline','migration','sample')", "choices=('baseline','migration','migration-active','sample')")
    return source


def _receipts(source):
    source = replace_once(source,
        "    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)",
        "    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m)")
    source = replace_once(source,
        "        checks={'schema'+str(common.SCHEMA):True,'policy2':True,'sole_writer':True,'read_only_serving':True,'private_boundary':True,",
        "        paused='status-observer' in state['pods']\n"
        "        need(paused == (args.mode != 'finish'), 'receipt_authority_phase_mismatch')\n"
        "        checks={'schema'+str(common.SCHEMA):True,'policy2':True,'read_only_serving':True,'private_boundary':True,")
    source = replace_once(source,
        "        if args.mode in ('activate-existing','finish'):",
        "        if paused:\n"
        "            proof=c.observer_proof()\n"
        "            need(proof.get('verified') is True and proof.get('process')==state['pods']['status-observer']\n"
        "                 and all(proof.get(k) is True for k in ('no_publication_owner','retained_sql_unchanged','no_provider_requests','no_repairs_or_queue_writes')), 'observer_readonly_proof_required')\n"
        "            checks.update(paused_read_only_observer=True,no_publication_owner=True)\n"
        "        else:\n"
        "            checks['sole_writer']=True\n"
        "        if args.mode in ('activate-existing','finish'):")
    source = replace_once(source,
        "        receipt['operation_label']=label(args.label)",
        "        receipt['authority_mode']='status_only_observer' if paused else 'full_writer'\n"
        "        if paused:receipt['observer']=proof\n"
        "        receipt['operation_label']=label(args.label)")
    source = replace_once(source,
        "    need(v['authority_sha256']==current['authority_sha256'],'sample_database_credentials_changed')",
        "    paused='status-observer' in state['pods']\n"
        "    need(paused == ('status-observer' in v['pods']), 'sample_authority_mode_changed')\n"
        "    if paused:\n"
        "        proof=v.get('observer',{})\n"
        "        need(proof.get('verified') is True and proof.get('process')==state['pods']['status-observer']\n"
        "             and all(proof.get(k) is True for k in ('no_publication_owner','retained_sql_unchanged','no_provider_requests','no_repairs_or_queue_writes')), 'sample_observer_proof_required')\n"
        "    need(v['authority_sha256']==current['authority_sha256'],'sample_database_credentials_changed')")
    source = replace_once(source,
        "    private_proof(value,allow_historical=not fresh_private)",
        "    private_proof(value,allow_historical=not fresh_private)\n"
        "    if 'status-observer' in state['pods']:\n"
        "        need(value.get('authority_mode')=='status_only_observer'\n"
        "             and value.get('observer_acquisition_denied') is True\n"
        "             and value.get('observer_process')==state['pods']['status-observer'], 'private_observer_authority_required')\n"
        "    else:need(value.get('authority_mode')=='full_writer','private_full_writer_authority_required')")
    return source


def _private(source):
    source = replace_once(source,
        " items=json.loads(podread.stdout)['items'];need(len(items)==3 and {p['metadata']['labels']['app'] for p in items}=={'backend','writer','postgres'},'exact_three_unique_roles')\n"
        " pods={v['metadata']['labels']['app']:v for v in items}\n"
        " need(set(pods)=={'backend','writer','postgres'},'three_roles')",
        " observer_mode='status-observer' in initial['pods']\n"
        " expected={'backend','status-observer','postgres'} if observer_mode else {'backend','writer','postgres'}\n"
        " items=json.loads(podread.stdout)['items'];need(len(items)==3 and {p['metadata']['labels']['app'] for p in items}==expected,'exact_three_unique_roles')\n"
        " pods={v['metadata']['labels']['app']:v for v in items}\n"
        " need(set(pods)==expected,'three_roles')\n"
        " if observer_mode:pods['writer']=pods.pop('status-observer')")
    source = replace_once(source,
        " role=command(['kubectl'",
        " observer_denied=False\n"
        " if observer_mode:\n"
        "  observer_denied=prove_observer_authority(controlled,initial,ctx)\n"
        " role=command(['kubectl'")
    source = replace_once(source,
        " fd=os.open(N/('target-private-acceptance-'+output_label+'.json')",
        " out['authority_mode']='status_only_observer' if observer_mode else 'full_writer'\n"
        " if observer_mode:out.update(observer_acquisition_denied=observer_denied,observer_process=initial['pods']['status-observer'])\n"
        " fd=os.open(N/('target-private-acceptance-'+output_label+'.json')")
    source = replace_once(source, 'def main():', textwrap.dedent('''
        def prove_observer_authority(controlled,initial,ctx):
         observer=controlled.observer_proof()
         need(observer.get('verified') is True and observer.get('process')==initial['pods']['status-observer']
              and all(observer.get(k) is True for k in ('no_publication_owner','retained_sql_unchanged','no_provider_requests','no_repairs_or_queue_writes')), 'observer_readonly_proof_required')
         token_result=command(['kubectl','--context','default','-n','devres','exec','deployment/backend','--','cat','/run/devres-writer-identity/token'])
         need(token_result.returncode==0 and 0<len(token_result.stdout)<=16384,'observer_client_identity_unavailable')
         token=token_result.stdout.decode().strip()
         connection=http.client.HTTPSConnection('writer.devres.svc',9443,context=ctx,timeout=15)
         try:
          connection.request('POST','/v1/acquire',b'{"kind":"acquire","source":{"operation":"rfc_representation","number":9000,"format":"txt"}}',{'Content-Type':'application/json','Authorization':'Bearer '+token})
          answer=connection.getresponse();answer.read(65537)
          need(answer.status==403,'observer_authenticated_acquisition_not_denied')
         finally:
          connection.close();del token;del token_result
         after=controlled.observer_proof()
         need(after==observer,'observer_authority_changed')
         return True

        def main():
    ''').lstrip())
    return source
