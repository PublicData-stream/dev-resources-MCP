#!/usr/bin/env python3
"""Assess the exact schema18 incident after schema19 migration, without rearming it.

This rollout admits only the migration-created revision. It cannot authenticate
legacy failure causes; authoritative newer work requires a different exact-state
admission and its schema19 checkpoint. No source request or recovery write occurs.
"""
import copy
import json
import os
from pathlib import Path
import stat
import time

JOB='blake3:73ead14961ca01609b5f9843b2d4fc14ecbea622d2aec43b0ac733012532cac9'
POD='devres-npm-assessment-1d76fbcc'
WORK=Path('/tmp/devres-upgrade-1d76fbcc-20261115')


def need(value,code):
    if not value:raise RuntimeError(code)


def sql(c,query):
    need(query.startswith('SELECT ') and ';' not in query,'fixed_readonly_query_required')
    raw=c.old.k('exec','deployment/postgres','-c','postgres','--','psql','-X','-q','-U','devres_admin',
        '-d','devres','-At','-v','ON_ERROR_STOP=1','-c',
        "BEGIN READ ONLY; SET LOCAL statement_timeout='20s'; "+query+'; COMMIT;')
    return json.loads(raw)


def selection(c):
    rows=sql(c,"SELECT COALESCE(json_agg(json_build_object('job_id',job_id,'revision',revision,'authoritative',data->'cause_authoritative')),'[]'::json) FROM devres_npm_advisory_job_history")
    need(rows==[{'job_id':JOB,'revision':1,'authoritative':False}],'exact_migrated_legacy_incident_required')
    return rows[0]


def validate_report(value):
    need(value.get('job_id')==JOB and value.get('revision')==1 and value.get('eligible') is False
         and value.get('reason') in ('legacy_unknown','already_published')
         and value.get('recipe')=='npm-materialization-deadline-v1', 'sealed_legacy_ineligibility_required')
    return {'eligible':False,'deferred':True,'reason':value['reason'],'job_id':JOB,'revision':1}


def assess(c):
    import importlib.util
    # Keep helpers' private I/O rules identical to the controller, whose bytes
    # have already been externally pinned before dispatch.
    module=__import__(c.__class__.__module__,fromlist=['save'])
    with c.locked():
        c.guard();state=c.state()
        need(state['runtime']=='target' and state['phase']=='writer_ready' and state['configs']=='paused', 'paused_target_required')
        c.storage_guard(19,owner=True)
        selected=selection(c)
        module.save(c.root/'npm-assessment-intent.json',{'job_id':JOB,'revision':selected['revision'],'writes_admitted':False,'at':module.stamp()})
        c.scale('writer',0,'npm-assessment-stop-writer')
        c.storage_guard(19,owner=False)
        output=WORK/'npm-assessment'
        output.mkdir(mode=0o700)
        os.chown(output,65532,65532)
        template=copy.deepcopy(c.get('deployment','backend')['spec']['template'])
        spec=template['spec'];spec['restartPolicy']='Never'
        for key in ('affinity','initContainers'):spec.pop(key,None)
        need(len(spec['containers'])==1,'one_maintenance_container_required')
        container=spec['containers'][0]
        container['name']='assessment'
        container['command']=['/usr/local/bin/devres-server','recover-collection','dry-run','/etc/devres/config/serving.toml',
            '--provider','npm','--job-id',JOB,'--revision','1','--recipe','npm-materialization-deadline-v1','--output','/tmp/recovery/report.json']
        for key in ('args','ports','readinessProbe','livenessProbe','startupProbe'):container.pop(key,None)
        for volume in spec['volumes']:
            if volume['name']=='cache':
                volume.clear();volume.update(name='cache',emptyDir={'sizeLimit':'64Mi'})
        # This metadata-only CLI needs neither acquisition delegation nor its
        # projected writer-audience token. Do not expose that authority here.
        spec['volumes']=[v for v in spec['volumes'] if v['name']!='writer-identity']
        container['volumeMounts']=[v for v in container.get('volumeMounts',[]) if v['name']!='writer-identity']
        spec['volumes'].append({'name':'report','hostPath':{'path':str(output),'type':'Directory'}})
        container.setdefault('volumeMounts',[]).append({'name':'report','mountPath':'/tmp/recovery'})
        pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':POD,'namespace':'devres','labels':{'app':'backend','devres-rollout':'1d76fbcc-assessment'}},'spec':spec}
        # No listener is started, no PVC is mounted, and only the serving reader
        # DB/S3 credentials are present in this exact backend-derived template.
        need(not any('persistentVolumeClaim' in v for v in spec['volumes']),'maintenance_pvc_refused')
        module.save(c.root/'npm-assessment-pod-admission.json',{'name':POD,'pod':pod})
        c.mutate('npm-assessment-pod-create',lambda:c.old.k('create','-f','/dev/stdin',data=module.encoded(pod)))
        admitted=c.get('pod',POD)
        uid=admitted['metadata']['uid']
        module.save(c.root/'npm-assessment-pod-identity.json',{'name':POD,'uid':uid})
        try:
            deadline=time.monotonic()+330
            while True:
                current=c.get('pod',POD)
                need(current['metadata']['uid']==uid,'maintenance_pod_identity_changed')
                phase=current.get('status',{}).get('phase')
                if phase in ('Succeeded','Failed'):break
                need(time.monotonic()<deadline,'npm_assessment_timeout')
                time.sleep(1)
            need(phase=='Succeeded','npm_assessment_cli_failed')
            path=output/'report.json'
            # Report is created by the nonroot maintenance container. Validate
            # before changing ownership for root-private journal verification.
            info=path.lstat()
            need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid==65532 and info.st_nlink==1
                 and info.st_mode&0o777==0o600 and info.st_size<=1024**2,'private_assessment_report_required')
            os.chown(path,0,0);os.chown(output,0,0)
            report=json.loads(module.read(path,maximum=1024**2))
            result=validate_report(report)
            need(selection(c)==selected,'incident_changed_during_assessment')
            module.save(c.root/'npm-assessment-completed.json',{**result,'report_sha256':module.digest(module.read(path)),'at':module.stamp()})
        finally:
            cleanup(c)
        c.guard();c.storage_guard(19,owner=False)
        c.pacing_delay();c.scale('writer',1,'npm-assessment-start-writer')
        return result


def cleanup(c):
    import importlib
    module=importlib.import_module(c.__class__.__module__)
    admission_path=c.root/'npm-assessment-pod-admission.json'
    if not admission_path.exists():return
    admission=module.load(admission_path)
    need(admission['name']==POD,'maintenance_admission_identity')
    values=json.loads(c.old.k('get','pods','-o','json'))['items']
    matches=[v for v in values if v['metadata']['name']==POD]
    if not matches:return
    need(len(matches)==1,'one_maintenance_pod_required')
    current=matches[0]
    expected=admission['pod']
    identity=c.root/'npm-assessment-pod-identity.json'
    if identity.exists():
        need(current['metadata']['uid']==module.load(identity)['uid'],'maintenance_cleanup_identity_changed')
    else:
        # Reconcile a lost create response using exact first-party command,
        # admitted image, role, mount destinations, and immutable node binding.
        need(current['metadata']['labels'].get('devres-rollout')=='1d76fbcc-assessment'
             and current['metadata']['labels'].get('app')=='backend','maintenance_cleanup_identity_changed')
        observed=current['spec']['containers'];wanted=expected['spec']['containers']
        need(len(observed)==len(wanted)==1 and all(observed[0].get(k)==wanted[0].get(k)
             for k in ('image','command','volumeMounts')),'maintenance_cleanup_preimage_changed')
        node=c.old.settings()['node_name']
        wanted_selector=expected['spec'].get('nodeSelector',{})
        need(wanted_selector.get('kubernetes.io/hostname')==node
             and current['spec'].get('nodeSelector')==wanted_selector
             and current['spec'].get('nodeName') in (None,node),'maintenance_node_changed')
        need(current['spec'].get('securityContext')==expected['spec'].get('securityContext')
             and current['spec'].get('serviceAccountName')==expected['spec'].get('serviceAccountName'),
             'maintenance_security_changed')
        desired={v['name']:v for v in expected['spec']['volumes']}
        actual={v['name']:v for v in current['spec']['volumes']}
        need(set(actual)==set(desired),'maintenance_volume_set_changed')
        def includes(observed,wanted):
            if isinstance(wanted,dict):return isinstance(observed,dict) and all(k in observed and includes(observed[k],v) for k,v in wanted.items())
            if isinstance(wanted,list):return isinstance(observed,list) and len(observed)==len(wanted) and all(includes(a,b) for a,b in zip(observed,wanted))
            return observed==wanted
        need(all(includes(actual[name],value) for name,value in desired.items()),'maintenance_volume_changed')
    options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':current['metadata']['uid']},'propagationPolicy':'Foreground'}
    # UID precondition prevents deletion of a replacement with the same name.
    c.old.k('delete','--raw','/api/v1/namespaces/devres/pods/'+POD,'-f','/dev/stdin',data=module.encoded(options))
    c.old.k('wait','--for=delete','pod/'+POD,'--timeout=120s',timeout=150)
