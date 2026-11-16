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
import selectors
import signal
import subprocess
import re
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
    need(isinstance(value,dict) and set(value)=={'version','job_id','revision','recipe','state_digest','eligible',
         'outcome','reason','operation_id','publication_snapshot'}
         and type(value.get('version')) is int and value['version']==1
         and value.get('job_id')==JOB and type(value.get('revision')) is int and value['revision']==1
         and value.get('eligible') is False and value.get('outcome')=='ineligible'
         and value.get('operation_id') is None and value.get('publication_snapshot') is None
         and isinstance(value.get('state_digest'),str) and re.fullmatch('blake3:[0-9a-f]{64}',value['state_digest'])
         and value.get('reason') in ('legacy_unknown','already_published')
         and value.get('recipe')=='npm-materialization-deadline-v1', 'sealed_legacy_ineligibility_required')
    return {'eligible':False,'deferred':True,'reason':value['reason'],'job_id':JOB,'revision':1}


REPORT='/tmp/npm-assessment/report.json'
READY='/tmp/npm-assessment/ready'
FRAME=b'DEVRES_NPM_REPORT_V1\n'
MAX_REPORT=1024**2+1  # Released serializer caps JSON at 1 MiB, then adds one newline.
MAX_STREAM=MAX_REPORT+256
MAX_STDERR=4096
HOLD_SECONDS=120
CLI_SCRIPT=(
    'set -eu\numask 077\n'
    '/usr/local/bin/devres-server recover-collection dry-run /etc/devres/config/serving.toml '
    '--provider npm --job-id '+JOB+' --revision 1 --recipe npm-materialization-deadline-v1 '
    '--output '+REPORT+'\n'
    "printf 'DEVRES_NPM_REPORT_V1\\n' > "+READY+'\n'
    'exec /bin/sleep '+str(HOLD_SECONDS)+'\n')
READ_SCRIPT=('set -eu\n[ -f '+READY+' ]\n'
             "/usr/bin/stat -c '%u:%a:%h:%s:%F' "+REPORT+'\n'
             '/bin/cat '+READY+' '+REPORT+'\n')


def assessment_pod(template,image):
    """Keep only reader configuration/S3 keys and private ephemeral /tmp."""
    spec=copy.deepcopy(template['spec']);spec['restartPolicy']='Never'
    spec['activeDeadlineSeconds']=450
    spec['terminationGracePeriodSeconds']=15
    spec['automountServiceAccountToken']=False
    for key in ('affinity','initContainers','ephemeralContainers'):spec.pop(key,None)
    need(len(spec['containers'])==1,'one_maintenance_container_required')
    container=spec['containers'][0]
    need(container['image']==image,'maintenance_image_changed')
    container['name']='assessment'
    # Utilities below were executed from this exact qualified image by the
    # independent local gate. CLI output stays in its private file; logs contain
    # only the CLI's finite report_written status, never report JSON.
    container['command']=['/usr/bin/timeout','--signal=TERM','--kill-after=5s','420s','/bin/sh','-c',CLI_SCRIPT]
    for key in ('args','ports','readinessProbe','livenessProbe','startupProbe','env','envFrom','lifecycle'):
        container.pop(key,None)
    volumes={v['name']:v for v in spec['volumes']}
    need(volumes.get('config',{}).get('secret',{}).get('secretName')=='devres-serving-config'
         and volumes.get('s3',{}).get('secret',{}).get('secretName')=='devres-serving-s3'
         and 'emptyDir' in volumes.get('tmp',{}),'reader_only_maintenance_inputs_required')
    spec['volumes']=[volumes['config'],volumes['s3'],{'name':'tmp','emptyDir':{'sizeLimit':'16Mi'}}]
    mounts={v['name']:v for v in container.get('volumeMounts',[])}
    need(mounts.get('config',{}).get('mountPath')=='/etc/devres/config'
         and mounts.get('s3',{}).get('mountPath')=='/run/devres-s3'
         and mounts.get('tmp',{}).get('mountPath')=='/tmp'
         and mounts['config'].get('readOnly') is True and mounts['s3'].get('readOnly') is True,
         'reader_only_maintenance_mounts_required')
    container['volumeMounts']=[mounts[name] for name in ('config','s3','tmp')]
    security=spec.get('securityContext',{})
    local=container.get('securityContext',{})
    need(security.get('runAsNonRoot') is True and security.get('runAsUser')==65532
         and security.get('fsGroup')==65532 and security.get('seccompProfile',{}).get('type')=='RuntimeDefault'
         and local.get('allowPrivilegeEscalation') is False
         and local.get('readOnlyRootFilesystem') is True
         and local.get('capabilities',{}).get('drop')==['ALL']
         and not any(spec.get(k) for k in ('hostNetwork','hostPID','hostIPC'))
         and not local.get('privileged') and not local.get('capabilities',{}).get('add'),
         'restricted_maintenance_security_required')
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':POD,'namespace':'devres',
            'labels':{'app':'backend','devres-rollout':'1d76fbcc-assessment'}},'spec':spec}


def report_exchange(command,timeout=5):
    """Bound stdout/stderr while reading; never log received report data."""
    process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             start_new_session=True,close_fds=True)
    selector=selectors.DefaultSelector();buffers={'stdout':bytearray(),'stderr':bytearray()}
    limits={'stdout':MAX_STREAM,'stderr':MAX_STDERR};deadline=time.monotonic()+timeout
    try:
        for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
        while selector.get_map() or process.poll() is None:
            need(time.monotonic()<deadline,'maintenance_report_stream_deadline')
            for key,_ in selector.select(min(.05,max(0,deadline-time.monotonic()))):
                for _ in range(4):
                    try:chunk=os.read(key.fileobj.fileno(),min(65536,limits[key.data]-len(buffers[key.data])+1))
                    except BlockingIOError:break
                    if not chunk:selector.unregister(key.fileobj);break
                    buffers[key.data].extend(chunk)
                    need(len(buffers[key.data])<=limits[key.data],'maintenance_report_stream_bound')
        # Missing marker during CLI execution is an expected nonzero exec result.
        if process.returncode!=0:return None
        return bytes(buffers['stdout'])
    finally:
        selector.close()
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        try:process.wait(timeout=.5)
        except subprocess.TimeoutExpired:pass
        for stream in (process.stdout,process.stderr):stream.close()


def decode_report_frame(body):
    need(isinstance(body,bytes) and 0<len(body)<=MAX_STREAM,'private_assessment_stream_required')
    metadata,separator,remaining=body.partition(b'\n')
    fields=metadata.decode('ascii').split(':',4)
    need(separator and len(fields)==5 and fields[0]=='65532' and fields[1]=='600' and fields[2]=='1'
         and fields[4]=='regular file' and re.fullmatch('[0-9]+',fields[3]),'private_assessment_file_metadata_required')
    size=int(fields[3]);need(0<size<=MAX_REPORT and remaining.startswith(FRAME),'complete_assessment_marker_required')
    report=remaining[len(FRAME):]
    need(len(report)==size,'assessment_report_transfer_incomplete')
    def unique(pairs):
        value={}
        for key,item in pairs:
            need(key not in value,'duplicate_assessment_report_field');value[key]=item
        return value
    value=json.loads(report,object_pairs_hook=unique)
    validate_report(value)
    return report,value


def assessment_command():
    return ['k3s','kubectl','--context','default','--namespace','devres','--request-timeout=5s',
            'exec',POD,'-c','assessment','--','/bin/sh','-c',READ_SCRIPT]


FAILURE_STEPS=frozenset(('create-pod','get-created-pod','save-pod-identity','get-pod-status',
    'check-pod-status','check-container-status','check-process-identity','exec-private-report',
    'get-report-bookend','check-report-bookend','decode-private-report','validate-report','recheck-selection'))
STATUS_REASONS=frozenset(('Completed','Error','OOMKilled','ContainerCannotRun','StartError','DeadlineExceeded',
    'Evicted','NodeLost','ContainerCreating','PodInitializing','ErrImagePull','ImagePullBackOff',
    'CrashLoopBackOff','CreateContainerConfigError','CreateContainerError','RunContainerError','InvalidImageName'))
EXCEPTION_TYPES=frozenset(('RuntimeError','OSError','PermissionError','FileNotFoundError','ConnectionError',
    'TimeoutError','ValueError','JSONDecodeError','UnicodeDecodeError','KeyError','IndexError','TypeError',
    'AttributeError','AssertionError','SubprocessError','CalledProcessError','TimeoutExpired',
    'KeyboardInterrupt','SystemExit'))


def pod_failure_metadata(pod):
    """Copy only closed status fields from an already observed Pod, without I/O."""
    if type(pod) is not dict:return None
    metadata=pod.get('metadata',{});status=pod.get('status',{})
    if type(metadata) is not dict:metadata={}
    if type(status) is not dict:status={}
    uid=metadata.get('uid');phase=status.get('phase');reason=status.get('reason')
    uid=uid.lower() if type(uid) is str and len(uid)==36 and re.fullmatch(
        '[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',uid) else None
    values=status.get('containerStatuses',[])
    if type(values) is not list:values=[]
    containers=[]
    for value in values[:2]:
        if type(value) is not dict:value={}
        state=value.get('state',{})
        if type(state) is not dict:state={}
        kinds=[key for key in ('running','waiting','terminated') if type(state.get(key)) is dict]
        kind=kinds[0] if len(kinds)==1 else 'unknown';detail=state[kind] if kind!='unknown' else {}
        why=detail.get('reason');restart=value.get('restartCount');exit_code=detail.get('exitCode')
        containers.append({'state':kind,'reason':why if type(why) is str and why in STATUS_REASONS else None,
            'restart_count':restart if type(restart) is int and 0<=restart<=2147483647 else None,
            'exit_code':exit_code if kind=='terminated' and type(exit_code) is int and -2147483648<=exit_code<=2147483647 else None,
            'oom_killed':kind=='terminated' and why=='OOMKilled',
            'container_id_present':type(value.get('containerID')) is str and bool(value['containerID'])})
    return {'uid':uid,'phase':phase if type(phase) is str and phase in ('Pending','Running','Succeeded','Failed','Unknown') else None,
        'reason':reason if type(reason) is str and reason in STATUS_REASONS else None,
        'container_status_count':min(len(values),2),'container_statuses_truncated':len(values)>2,'containers':containers}


def assessment_failure_metadata(step,error,last_pod):
    """Exclude exception messages, arguments, source text, locals and remote data."""
    frames=[];trace=error.__traceback__;remaining=64
    functions={'assess','need','sql','selection','validate_report','decode_report_frame','report_exchange','unique','<lambda>'}
    while trace is not None and remaining:
        code=trace.tb_frame.f_code
        if code.co_filename==__file__:
            frames.append({'function':code.co_name if code.co_name in functions else 'other','line':trace.tb_lineno})
        trace=trace.tb_next;remaining-=1
    name=type(error).__name__
    value={'version':1,'kind':'npm-assessment-failure','step':step if type(step) is str and step in FAILURE_STEPS else 'other',
        'exception_type':name if name in EXCEPTION_TYPES else 'other','source':'npm-recovery.py',
        'traceback':frames[-4:],'traceback_truncated':trace is not None or len(frames)>4,'last_pod':last_pod}
    need(len(json.dumps(value).encode())<=4096,'closed_failure_metadata_bound')
    return value


def assess(c):
    import importlib
    module=importlib.import_module(c.__class__.__module__)
    with c.locked():
        c.guard();state=c.state()
        need(state['runtime']=='target' and state['phase']=='writer_ready' and state['configs']=='paused','paused_target_required')
        c.storage_guard(19,owner=True);selected=selection(c)
        module.save(c.root/'npm-assessment-intent.json',{'job_id':JOB,'revision':selected['revision'],'writes_admitted':False,'at':module.stamp()})
        c.scale('writer',0,'npm-assessment-stop-writer');c.storage_guard(19,owner=False)
        output=WORK/'npm-assessment';output.mkdir(mode=0o700)
        pod=assessment_pod(c.get('deployment','backend')['spec']['template'],state['images']['backend'])
        module.save(c.root/'npm-assessment-pod-admission.json',{'name':POD,'pod':pod})
        failure=None;last_pod=None;step='create-pod'
        try:
            # Cleanup covers rejected/lost create responses and UID persistence
            # failures, as well as the successful process/report path.
            c.mutate('npm-assessment-pod-create',lambda:c.old.k('create','-f','/dev/stdin',data=module.encoded(pod)))
            step='get-created-pod';admitted=c.get('pod',POD);last_pod=pod_failure_metadata(admitted)
            uid=admitted['metadata']['uid'];step='save-pod-identity'
            module.save(c.root/'npm-assessment-pod-identity.json',{'name':POD,'uid':uid})
            deadline=time.monotonic()+330
            while True:
                step='get-pod-status';current=c.get('pod',POD);last_pod=pod_failure_metadata(current)
                step='check-pod-status'
                need(current['metadata']['uid']==uid,'maintenance_pod_identity_changed')
                phase=current.get('status',{}).get('phase')
                need(phase not in ('Succeeded','Failed'),'npm_assessment_cli_or_hold_ended')
                need(time.monotonic()<deadline,'npm_assessment_timeout')
                if phase=='Running':
                    step='check-container-status'
                    statuses=current.get('status',{}).get('containerStatuses',[])
                    need(len(statuses)==1 and statuses[0].get('restartCount',0)==0,'one_unrestarted_assessment_required')
                    step='check-process-identity'
                    identity=statuses[0].get('containerID')
                    need(isinstance(identity,str) and identity,'assessment_process_identity_required')
                    step='exec-private-report'
                    body=report_exchange(assessment_command(),timeout=min(5,max(.01,deadline-time.monotonic())))
                    step='get-report-bookend';after=c.get('pod',POD);last_pod=pod_failure_metadata(after)
                    step='check-report-bookend'
                    after_status=after.get('status',{}).get('containerStatuses',[])
                    need(after['metadata']['uid']==uid and len(after_status)==1
                         and after_status[0].get('containerID')==identity and after_status[0].get('restartCount',0)==0,
                         'maintenance_report_process_identity_changed')
                    if body is not None:
                        step='decode-private-report'
                        report_bytes,report=decode_report_frame(body);break
                time.sleep(1)
            step='validate-report';result=validate_report(report)
            step='recheck-selection';need(selection(c)==selected,'incident_changed_during_assessment')
        except BaseException as error:
            try:failure=assessment_failure_metadata(step,error,last_pod)
            except BaseException:pass
            raise
        finally:
            cleanup(c)
            if failure is not None:
                try:module.save(c.root/'npm-assessment-failed.json',failure)
                except BaseException:pass
        c.guard();c.storage_guard(19,owner=False)
        # Remove the Pod before local report fsync: evidence persistence cannot
        # leave the credential-bearing assessment process alive on a failed path.
        module.save(output/'report.json',report_bytes)
        module.save(c.root/'npm-assessment-completed.json',{**result,'report_sha256':module.digest(report_bytes),
            'transport':'uid-bookended-private-exec','pod_uid':uid,'container_id':identity,
            'cli_report_in_logs':False,'at':module.stamp()})
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
