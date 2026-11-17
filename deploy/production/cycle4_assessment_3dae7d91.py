"""Source-bound assessment adaptation for the fresh 3dae7d91 deployment.

Only the successor closure is transformed. Frozen production helpers are inputs,
not mutable implementation dependencies. No cluster operation occurs at import.
"""
from __future__ import annotations

import ast


class TransformError(RuntimeError):
    """A reviewed input function no longer matches the adaptation contract."""


def _replace_function(source, name, replacement):
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(nodes) != 1:
        raise TransformError('one_assessment_function_required:' + name)
    node = nodes[0]
    lines = source.splitlines(keepends=True)
    start = sum(map(len, lines[:node.lineno - 1])) + node.col_offset
    end = sum(map(len, lines[:node.end_lineno - 1])) + node.end_col_offset
    return source[:start] + replacement + source[end:]


HELPERS = r'''
ASSESSMENT_APP='devres-npm-assessment'
ASSESSMENT_SCOPE='3dae7d91-assessment'
ASSESSMENT_POLICIES=('cycle4-npm-assessment-egress','cycle4-npm-assessment-postgres')

def maintained():
    import hashlib
    import importlib.util
    import sys
    name='deploy/diagnostics/npm_assessment.py'
    path=WORK/name
    need(not any(p.is_symlink() for p in (path,*path.parents)),'assessment_helper_symlink')
    body=path.read_bytes()
    manifest=json.loads((WORK/'source-manifest.json').read_bytes())
    need(len(body)<=4*1024**2 and hashlib.sha256(body).hexdigest()==manifest[name],
         'assessment_helper_source_changed')
    spec=importlib.util.spec_from_file_location('cycle4_exact_maintained_assessment',path)
    helper=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=helper
    spec.loader.exec_module(helper)
    return helper


def assessment_network_policies():
    labels={'devres-assessment':ASSESSMENT_SCOPE}
    dns={'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'kube-system'}},
         'podSelector':{'matchLabels':{'k8s-app':'kube-dns'}}}
    def policy(name,spec):
        return {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
            'metadata':{'name':name,'namespace':'devres','labels':labels},'spec':spec}
    return [policy(ASSESSMENT_POLICIES[0],{
        'podSelector':{'matchLabels':{'app':ASSESSMENT_APP}},'policyTypes':['Ingress','Egress'],
        'egress':[
            {'to':[dns],'ports':[{'port':53,'protocol':'UDP'},{'port':53,'protocol':'TCP'}]},
            {'to':[{'podSelector':{'matchLabels':{'app':'postgres'}}}],
             'ports':[{'port':5432,'protocol':'TCP'}]}]}),
        policy(ASSESSMENT_POLICIES[1],{
            'podSelector':{'matchLabels':{'app':'postgres'}},'policyTypes':['Ingress'],
            'ingress':[{'from':[{'podSelector':{'matchLabels':{'app':ASSESSMENT_APP}}}],
                        'ports':[{'port':5432,'protocol':'TCP'}]}]})]


def _selector_matches(selector,labels):
    need(type(selector) is dict and not set(selector)-{'matchLabels','matchExpressions'},
         'assessment_network_selector_invalid')
    matched=all(labels.get(key)==value for key,value in selector.get('matchLabels',{}).items())
    for expression in selector.get('matchExpressions',[]):
        need(type(expression) is dict and set(expression)<={'key','operator','values'}
             and type(expression.get('key')) is str,'assessment_network_selector_invalid')
        key=expression['key'];operator=expression.get('operator');values=expression.get('values',[])
        need(operator in ('In','NotIn','Exists','DoesNotExist') and type(values) is list,
             'assessment_network_selector_invalid')
        if operator=='In':matched=matched and key in labels and labels[key] in values
        elif operator=='NotIn':matched=matched and (key not in labels or labels[key] not in values)
        elif operator=='Exists':matched=matched and key in labels
        else:matched=matched and key not in labels
    return matched


def _policy_projection(value):
    metadata=value['metadata']
    return {'name':metadata['name'],'uid':metadata['uid'],
        'namespace':metadata.get('namespace','devres'),'labels':metadata.get('labels',{}),
        'spec':value['spec']}


def _network_inventory(c):
    values=json.loads(c.old.k('get','networkpolicies','-o','json'))['items']
    need(type(values) is list and len(values)<=100,'assessment_network_inventory_bound')
    result={value['metadata']['name']:_policy_projection(value) for value in values}
    need(len(result)==len(values),'assessment_network_policy_duplicate')
    return result


def _module(c):
    import importlib
    return importlib.import_module(c.__class__.__module__)


def network_guard(c):
    """Validate exact temporary additions before a controller filters foundation."""
    module=_module(c)
    path=c.root/'npm-assessment-network-admission.json'
    if not path.exists():return set()
    admission=module.load(path)
    expected={value['metadata']['name']:value for value in assessment_network_policies()}
    need(admission.get('policies')==expected,'assessment_network_admission_changed')
    state_path=c.root/'npm-assessment-network-state.json'
    state=module.load(state_path) if state_path.exists() else {'phase':'installing'}
    need(state.get('phase') in ('installing','installed','removing','removed'),
         'assessment_network_transition_invalid')
    current=_network_inventory(c)
    own=set(current)&set(expected)
    if state['phase']=='removed':
        need(not own,'assessment_network_cleanup_incomplete')
        # The outer source-bound foundation guard admits later observer changes.
        return set()
    need({name:value for name,value in current.items() if name not in expected}==admission['baseline'],
         'assessment_network_preimage_changed')
    if state['phase']=='installed':need(own==set(expected),'assessment_network_policy_missing')
    for name in own:
        projection=current[name];wanted=expected[name]
        need(projection['namespace']=='devres' and projection['labels']==wanted['metadata']['labels']
             and projection['spec']==wanted['spec'],'assessment_network_policy_changed')
        identity=c.root/('npm-assessment-network-'+name+'-identity.json')
        if identity.exists():need(module.load(identity)=={'name':name,'uid':projection['uid']},
                                 'assessment_network_uid_changed')
        else:
            need(state['phase']=='installing' and
                 (c.root/(c.state()['runtime']+'-npm-assessment-network-create-'+name+'-intent.json')).exists(),
                 'assessment_network_create_intent_required')
    return own


def install_network(c):
    module=_module(c)
    baseline=_network_inventory(c)
    expected={value['metadata']['name']:value for value in assessment_network_policies()}
    need(not set(expected)&set(baseline),'fresh_assessment_network_required')
    labels={'app':ASSESSMENT_APP,'devres-assessment':ASSESSMENT_SCOPE}
    for value in baseline.values():
        spec=value['spec']
        egress='Egress' in spec.get('policyTypes',(['Ingress','Egress'] if 'egress' in spec else ['Ingress']))
        need(not (egress and spec.get('egress') and _selector_matches(spec['podSelector'],labels)),
             'assessment_inherited_egress_refused')
    module.save(c.root/'npm-assessment-network-admission.json',{'baseline':baseline,'policies':expected})
    module.save(c.root/'npm-assessment-network-state.json',{'phase':'installing'})
    for name,value in expected.items():
        c.mutate('npm-assessment-network-create-'+name,
            lambda value=value:c.old.k('create','-f','/dev/stdin',data=module.encoded(value)))
        observed=c.get('networkpolicy',name)
        projection=_policy_projection(observed)
        need(projection['labels']==value['metadata']['labels'] and projection['spec']==value['spec'],
             'assessment_network_created_projection')
        module.save(c.root/('npm-assessment-network-'+name+'-identity.json'),
                    {'name':name,'uid':projection['uid']})
    module.save(c.root/'npm-assessment-network-state.json',{'phase':'installed'},replace=True)
    network_guard(c)


def cleanup_network(c):
    module=_module(c)
    path=c.root/'npm-assessment-network-admission.json'
    if not path.exists():return
    own=network_guard(c)
    values=json.loads(c.old.k('get','pods','-o','json'))['items']
    need(not any(v['metadata'].get('labels',{}).get('app')==ASSESSMENT_APP for v in values),
         'assessment_network_cleanup_requires_pod_absence')
    state_path=c.root/'npm-assessment-network-state.json'
    state=module.load(state_path) if state_path.exists() else {'phase':'installing'}
    if state['phase']=='removed':return
    current=_network_inventory(c)
    for name in sorted(own):
        identity=c.root/('npm-assessment-network-'+name+'-identity.json')
        if not identity.exists():
            # Lost create responses are reconciled from the exact admitted spec
            # and consumed create intent before any deletion transition.
            module.save(identity,{'name':name,'uid':current[name]['uid']})
    module.save(c.root/'npm-assessment-network-state.json',{'phase':'removing'},replace=state_path.exists())
    for name in sorted(own):
        uid=current[name]['uid']
        options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid},'propagationPolicy':'Foreground'}
        c.old.k('delete','--raw','/apis/networking.k8s.io/v1/namespaces/devres/networkpolicies/'+name,
                '-f','/dev/stdin',data=module.encoded(options))
        c.old.k('wait','--for=delete','networkpolicy/'+name,'--timeout=120s',timeout=150)
    need(_network_inventory(c)==module.load(path)['baseline'],
         'assessment_network_preimage_not_restored')
    module.save(c.root/'npm-assessment-network-state.json',{'phase':'removed'},replace=True)
    network_guard(c)
'''

POD = r'''def assessment_pod(template,image):
    helper=maintained()
    pod=helper.build_assessment_pod(template,image,helper.Selection(JOB),POD,'devres',ASSESSMENT_SCOPE)
    volumes={value['name']:value for value in pod['spec']['volumes']}
    need(volumes['config']['secret']['secretName']=='devres-serving-config'
         and volumes['s3']['secret']['secretName']=='devres-serving-s3',
         'reader_only_maintenance_inputs_required')
    pod['metadata']['labels']['app']=ASSESSMENT_APP
    return pod'''

ASSESS = r'''def assess(c):
    module=_module(c)
    with c.locked():
        c.guard();state=c.state()
        need(state['runtime']=='target' and state['phase']=='writer_ready' and state['configs']=='paused',
             'paused_target_required')
        c.storage_guard(19,owner=True);selected=selection(c)
        module.save(c.root/'npm-assessment-intent.json',
            {'job_id':JOB,'revision':selected['revision'],'writes_admitted':False,'at':module.stamp()})
        c.scale('writer',0,'npm-assessment-stop-writer');c.storage_guard(19,owner=False)
        output=WORK/'npm-assessment';output.mkdir(mode=0o700)
        helper=maintained();selection_value=helper.Selection(JOB)
        pod=assessment_pod(c.get('deployment','backend')['spec']['template'],state['images']['backend'])
        last={}
        def observe():
            value=c.get('pod',POD)
            metadata=value.get('metadata',{})
            need(metadata.get('name')==POD and metadata.get('namespace')=='devres'
                 and metadata.get('labels')==pod['metadata']['labels'],
                 'assessment_observed_metadata_changed')
            # Validate the actual API-admitted process authority before any exec.
            # Supervision additionally binds the UID/container on both sides.
            observed=value['spec'];node=c.old.settings()['node_name']
            if value.get('status',{}).get('phase')=='Pending' and observed.get('nodeName') is None:
                need(observed.get('nodeSelector')==pod['spec'].get('nodeSelector'),
                     'assessment_pending_node_selector_changed')
                # Scheduling has not assigned nodeName yet; preserve the actual
                # object and validate all other authority without relaxing Running.
                observed=copy.deepcopy(observed);observed['nodeName']=node
            module.admitted_pod_spec(observed,pod['spec'],node)
            last.clear();last.update(value)
            return value
        started=False
        try:
            install_network(c)
            module.save(c.root/'npm-assessment-pod-admission.json',{'name':POD,'pod':pod})
            c.mutate('npm-assessment-pod-create',lambda:c.old.k('create','-f','/dev/stdin',data=module.encoded(pod)))
            admitted=observe();uid=admitted['metadata']['uid']
            module.save(c.root/'npm-assessment-pod-identity.json',{'name':POD,'uid':uid})
            started=True
            report_bytes,report,phases=helper.supervise(
                get_pod=observe,read_report=lambda timeout:helper.report_exchange(assessment_command(),timeout),
                cleanup=lambda:cleanup(c),persist=lambda body:module.save(output/'report.json',body),
                persist_failure=lambda value:module.save(c.root/'npm-assessment-failed.json',value),
                selection=selection_value,uid=uid,image=state['images']['backend'])
        finally:
            if not started:cleanup(c)
        helper.validate_report(report,selection_value)
        need(report['reason']=='legacy_unknown','exact_legacy_unknown_required')
        result=validate_report(report)
        need(selection(c)==selected,'incident_changed_during_assessment')
        c.guard();c.storage_guard(19,owner=False)
        identity=last['status']['containerStatuses'][0]['containerID']
        module.save(c.root/'npm-assessment-completed.json',{**result,'report_sha256':module.digest(report_bytes),
            'transport':'uid-bookended-private-exec','pod_uid':uid,'container_id':identity,
            'cli_report_in_logs':False,'phases':phases,'phase_known':phases is not None,'at':module.stamp()})
        return result'''

CLEANUP = r'''def cleanup(c):
    # A failed Pod cleanup deliberately leaves restrictive policies installed.
    _cleanup_pod(c)
    cleanup_network(c)'''


def transform(source: str) -> str:
    """Adapt only a complete reviewed legacy recovery source."""
    for name, body in (
        ('assessment_pod', POD),
        ('report_exchange', "def report_exchange(command,timeout=5):\n    return maintained().report_exchange(command,timeout)"),
        ('decode_report_frame', "def decode_report_frame(body):\n    return maintained().decode_report_frame(body,maintained().Selection(JOB))"),
        ('assessment_command', "def assessment_command():\n    return ['k3s','kubectl','--context','default','--namespace','devres','--request-timeout=5s',\n            'exec',POD,'-c','assessment','--','/bin/sh','-c',maintained().read_script()]"),
        ('assess', ASSESS),
    ):
        source = _replace_function(source, name, body)
    cleanup_nodes = [node for node in ast.parse(source).body
                     if isinstance(node, ast.FunctionDef) and node.name == 'cleanup']
    if len(cleanup_nodes) != 1:
        raise TransformError('one_assessment_cleanup_required')
    cleanup = ast.get_source_segment(source, cleanup_nodes[0])
    cleanup = cleanup.replace('def cleanup(c):', 'def _cleanup_pod(c):', 1)
    cleanup = cleanup.replace("    import importlib\n    module=importlib.import_module(c.__class__.__module__)","    module=_module(c)",1)
    # Scope was deliberately rebased by the owning renderer before adaptation.
    old = "current['metadata']['labels'].get('devres-rollout')=="
    start = cleanup.find(old)
    if start < 0 or cleanup.count(old) != 1:
        raise TransformError('one_assessment_cleanup_label_required')
    end = cleanup.index("'maintenance_cleanup_identity_changed'", start)
    cleanup = cleanup[:start] + (
        "current['metadata']['labels'].get('devres-assessment')==ASSESSMENT_SCOPE\n"
        "             and current['metadata']['labels'].get('app')==ASSESSMENT_APP,"
    ) + cleanup[end:]
    source = _replace_function(source, 'cleanup', cleanup + '\n\n\n' + CLEANUP)
    legacy_constants={'REPORT','READY','FRAME','MAX_REPORT','MAX_STREAM','MAX_STDERR','HOLD_SECONDS','CLI_SCRIPT','READ_SCRIPT'}
    for node in reversed(ast.parse(source).body):
        if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id in legacy_constants for target in node.targets):
            lines=source.splitlines(keepends=True)
            start=sum(map(len,lines[:node.lineno-1]))
            end=sum(map(len,lines[:node.end_lineno]))
            source=source[:start]+source[end:]
    source += '\n\n' + HELPERS
    ast.parse(source)
    return source
