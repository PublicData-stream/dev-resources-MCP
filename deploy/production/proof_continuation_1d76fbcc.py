#!/usr/bin/env python3
"""One separately admitted successor of the failed isolated checkpoint proof.

Frozen checkpoint/controller/restore sources, original failed journals and the
original source manifest remain unchanged. Only the copied writer's cache ceiling
returns to its original configuration value; no product limit is changed.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import tomllib

sys.dont_write_bytecode=True
WORK=Path('/tmp/devres-upgrade-1d76fbcc-20261115')
BUNDLE=Path('/var/lib/devres-production-upgrades/1d76fbcc-20261115')
INSTALL=Path('/usr/local/libexec/devres-upgrade-1d76fbcc')
ORIGINAL=WORK/'checkpoint-state'
SCOPE=ORIGINAL/'proof-successor-v1'
REVISION='1d76fbcc5693efc9ca927fd05f942078f667f056'
IMMUTABLE=('baseline.json','checkpoint-completed.json','original-pg-resumed.json','quiescent-identity.json',
           'clean-pg-control.json','pg-file-manifest.jsonl','archive-bindings.jsonl','capture-bindings.jsonl',
           'archive-manifest-receipt.json','capture-manifest-receipt.json','cache-baselines.json')
FAILED=('proof-intent.json','clone-writer-create-intent.json','clone-cleanup-completed.json',
        'clone-network-fence.json','clone-network-fence-removed.json')
MAX=1024**3
CAPTURE_SECONDS=20
class Stop(RuntimeError):pass

def need(v,code):
    if not v:raise Stop(code)
def enc(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def read(path,maximum=MAX):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)),'private_path_required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
             and not info.st_mode&0o077 and info.st_size<=maximum,'private_file_required')
        body=f.read(maximum+1)
        need(len(body)==info.st_size,'private_file_changed')
    return body

def save(path,value):
    need(not path.exists() and not path.is_symlink(),'create_new_proof_artifact_required')
    info=path.parent.stat();need(info.st_uid==os.geteuid() and not info.st_mode&0o077,'private_parent_required')
    body=value if isinstance(value,bytes) else enc(value)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(body);f.flush();os.fsync(f.fileno())
    sync(path.parent)
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def load(path):return json.loads(read(path))

def import_cp(expected):
    path=INSTALL/'physical-checkpoint.py'
    need(sha(read(path))==expected,'frozen_checkpoint_source_changed')
    spec=importlib.util.spec_from_file_location('frozen_proof_successor_checkpoint',path)
    value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;spec.loader.exec_module(value)
    need(value.REV==REVISION and value.S==ORIGINAL,'exact_frozen_checkpoint_required')
    return value

def verify_original_pins(cp,a):
    need(sha(read(Path(__file__),1024**2))==a['source_sha256']
         and sha(read(INSTALL/'physical-checkpoint.py'))==a['checkpoint_source_sha256'],
         'continuation_or_frozen_checkpoint_source_changed')
    checks=((WORK/'source-manifest.json','global_manifest_sha256'),(cp.PUBLIC,'public_identity_sha256'),
            (cp.APPROVAL,'checkpoint_approval_sha256'),(ORIGINAL/'owner.json','original_owner_sha256'),
            (BUNDLE/'prepared.json','prepared_sha256'))
    for path,key in checks:need(sha(read(path))==a[key],'original_admission_changed')
    need(set(a['immutable_sha256'])==set(IMMUTABLE) and set(a['failed_proof_sha256'])==set(FAILED),
         'complete_original_provenance_required')
    for name,expected in {**a['immutable_sha256'],**a['failed_proof_sha256']}.items():
        need(sha(read(ORIGINAL/name))==expected,'original_proof_or_checkpoint_changed')
    need(sha(cp.enc(cp.cache_manifest(ORIGINAL/'private')))==a['private_input_manifest_sha256'],
         'original_private_proof_inputs_changed')
    need(cp.authorize()==load(ORIGINAL/'owner.json')['pins'],'original_checkpoint_authority_changed')

def old_scope_absent(cp):
    token=load(ORIGINAL/'owner.json')['token']
    need(re.fullmatch('[0-9a-f]{24}',token),'original_owner_token_required')
    need(not cp.run(['docker','ps','-aq','--filter','label='+cp.LABEL+'='+token]).strip(),
         'original_owned_container_remains')
    need(not cp.run(['docker','network','ls','-q','--filter','label='+cp.LABEL+'='+token]).strip(),
         'original_owned_network_remains')
    tables=json.loads(cp.run(['nft','--json','list','tables']))['nftables']
    need(not any(item.get('table',{}).get('name')=='devres_cp_'+token for item in tables),
         'original_owned_network_fence_remains')

def verify_admission(path,expected_sha,source_sha):
    body=read(path,1024**2)
    need(sha(body)==expected_sha and sha(read(Path(__file__),1024**2))==source_sha,'external_continuation_admission_changed')
    a=json.loads(body)
    need(a['version']==1 and a['kind']=='isolated-proof-successor-v1' and a['revision']==REVISION
         and a['source_sha256']==source_sha and a['maximum_attempts']==1
         and a['only_change']=='restore_original_writer_cache_ceiling'
         and a['original_scope']==str(ORIGINAL) and a['successor_scope']==str(SCOPE),'exact_continuation_scope_required')
    cp=import_cp(a['checkpoint_source_sha256'])
    verify_original_pins(cp,a)
    need(not (ORIGINAL/'completed.json').exists() and not (ORIGINAL/'backup-receipt.json').exists()
         and not (ORIGINAL/'clone-proof-result.json').exists() and not (ORIGINAL/'clone-writer-proof.json').exists(),
         'only_missing_proof_outputs_may_be_published')
    need(load(ORIGINAL/'clone-cleanup-completed.json')['all_owned_containers_removed'] is True
         and load(ORIGINAL/'clone-network-fence-removed.json')['removed'] is True,'original_failed_scope_not_cleaned')
    old_scope_absent(cp)
    cp.source_guard();cp.roles_stopped()
    current=cp.schema_identity();cp.checked_identity(current,True)
    baseline=load(ORIGINAL/'baseline.json')
    need(current['archive']==baseline['identity']['archive']
         and cp.pod_projection(cp.role_pods('postgres')[0])==load(ORIGINAL/'original-pg-resumed.json')['new_pg_pod'],
         'unchanged_original_database_required')
    writer=tomllib.loads(read(ORIGINAL/'private/writer.toml').decode())
    limit=writer['storage']['s3']['cache_max_bytes']
    need(type(limit) is int and limit==a['writer_cache_max_bytes'] and limit>64*1024**2,
         'original_writer_cache_ceiling_required')
    return cp,a

def corrected_writer_config(cp,frozen,original,limit):
    before=tomllib.loads(original)
    need(before['storage']['s3']['cache_max_bytes']==limit,'original_cache_ceiling_changed')
    base=frozen(original);expected=tomllib.loads(base)
    expected['storage']['s3']['cache_max_bytes']=limit
    value=cp.replace_scalar(base,'storage.s3','cache_max_bytes',limit)
    need(tomllib.loads(value)==expected,'continuation_config_change_exceeded')
    return value

def bounded_child(args,maximum=65536,timeout=5,merge_stderr=False):
    """Bound readers before buffering, including a blocked Docker daemon."""
    p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL)
    selector=selectors.DefaultSelector();body=bytearray();truncated=False
    try:
        os.set_blocking(p.stdout.fileno(),False);selector.register(p.stdout,selectors.EVENT_READ)
        deadline=time.monotonic()+timeout
        while selector.get_map() and time.monotonic()<deadline:
            for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),min(65536,maximum-len(body)+1))
                if not chunk:selector.unregister(key.fileobj);break
                body.extend(chunk)
                if len(body)>maximum:truncated=True;return bytes(body[:maximum]),truncated
        return bytes(body),truncated or bool(selector.get_map())
    finally:
        selector.close()
        if p.poll() is None:p.kill()
        try:p.wait(timeout=1)
        except subprocess.TimeoutExpired:pass
        p.stdout.close()

def redactions():
    from urllib.parse import urlsplit,unquote
    values=[]
    for name in ('access-key','secret-key'):
        values.append(read(ORIGINAL/'private'/name,16384).decode().strip())
    for name in ('serving.toml','writer.toml'):
        cfg=tomllib.loads(read(ORIGINAL/'private'/name).decode())
        password=urlsplit(cfg['storage']['database_url']).password
        if password:values.extend((password,unquote(password)))
    return [value for value in values if value]

def sanitize_logs(body,secrets):
    text=body.decode('utf-8','replace')
    for value in sorted(secrets,key=len,reverse=True):text=text.replace(value,'[redacted]')
    text=re.sub(r'(?:https?|postgres(?:ql)?)://\S+','[endpoint]',text)
    lines=[];pem=False
    for line in text.splitlines():
        if 'BEGIN ' in line and 'PRIVATE KEY' in line:pem=True
        ending='END ' in line and 'PRIVATE KEY' in line
        if not pem and not ending:
            # Docker's --tail may begin inside a key block. Suppress bare encoded
            # lines and long encoded fragments even when BEGIN was not captured.
            if not re.fullmatch(r'[A-Za-z0-9+/=_-]{8,}',line.strip()):
                lines.append(re.sub(r'[A-Za-z0-9+/=_-]{32,}','[encoded]',line[:2048]))
        if ending:pem=False
    return '\n'.join(lines[-64:])[:65536]

def capture_before_cleanup(cp,containers,token,phase):
    records=[];secrets=redactions()
    ids_body,_=bounded_child(['docker','ps','-aq','--filter','label='+cp.LABEL+'='+token],4096)
    identifiers=sorted(set(containers)|{v for v in ids_body.decode().split() if re.fullmatch('[0-9a-f]{12,64}',v)})
    for index,identifier in enumerate(identifiers[:4]):
        state,truncated=bounded_child(['docker','inspect',identifier],2*1024**2)
        rows=json.loads(state)
        need(len(rows)==1 and rows[0]['Config'].get('Labels',{}).get(cp.LABEL)==token,'foreign_diagnostic_container_refused')
        row=rows[0];status=row['State']
        record={'id':row['Id'],'image':row['Image'],'running':status['Running'],'exit_code':status['ExitCode'],
                'oom_killed':status.get('OOMKilled',False),'engine_error_present':bool(status.get('Error')),
                'started_at':status.get('StartedAt'),'finished_at':status.get('FinishedAt'),'inspect_truncated':truncated}
        logs,cut=bounded_child(['docker','logs','--tail','64',identifier],65536,merge_stderr=True)
        logpath=SCOPE/('pre-cleanup-'+str(index)+'.log')
        save(logpath,(sanitize_logs(logs,secrets) or '[no retained log lines]').encode())
        record.update(log_path=str(logpath),log_sha256=sha(read(logpath)),log_truncated=cut);records.append(record)
    save(SCOPE/'pre-cleanup-diagnostics.json',{'phase':phase,'containers':records,'before_cleanup':True})

def capture_independently(cp,containers,token,phase,timeout=CAPTURE_SECONDS):
    """Blocked evidence I/O must never delay the original resource cleanup."""
    import select
    read_fd,write_fd=os.pipe()
    pid=os.fork()
    if pid==0:
        os.close(read_fd)
        try:
            os.setsid()
            capture_before_cleanup(cp,containers,token,phase)
            diagnostics=load(SCOPE/'pre-cleanup-diagnostics.json')
            logs={row['log_path']:row['log_sha256'] for row in diagnostics['containers']}
            need(all(sha(read(Path(path)))==digest for path,digest in logs.items()),'diagnostic_log_changed')
            save(SCOPE/'diagnostics-ack.json',{'token':token,'phase':phase,
                 'diagnostics_sha256':sha(read(SCOPE/'pre-cleanup-diagnostics.json')),'logs':logs})
            os.write(write_fd,b'1')
        except BaseException:
            try:os.write(write_fd,b'0')
            except OSError:pass
        finally:
            os.close(write_fd);os._exit(0)
    os.close(write_fd)
    acknowledged=False
    try:
        ready,_,_=select.select([read_fd],[],[],timeout)
        if ready:acknowledged=os.read(read_fd,1)==b'1'
    finally:
        os.close(read_fd)
        try:os.killpg(pid,signal.SIGKILL)
        except ProcessLookupError:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
        # A kernel-blocked child may remain unreapable; never wait on its fsync
        # before stopping owned containers. The acknowledgement alone admits proof.
        deadline=time.monotonic()+.2
        while time.monotonic()<deadline:
            if os.waitpid(pid,os.WNOHANG)[0]:break
            time.sleep(.01)
    return acknowledged

def seed_scope(cp,a,admission,admission_sha):
    need(not SCOPE.exists() and not SCOPE.is_symlink(),'one_successor_proof_attempt_only')
    baseline=load(ORIGINAL/'baseline.json');cp.disk_identity()
    cache=load(ORIGINAL/'cache-baselines.json')
    pg=load(ORIGINAL/'checkpoint-completed.json')
    need(cp.shutil.disk_usage(ORIGINAL).free>=3*pg['pg_bytes']+2*cache['bytes']+cp.RESERVE,
         'successor_copy_and_clone_headroom_required')
    SCOPE.mkdir(mode=0o700);sync(SCOPE.parent)
    save(SCOPE/'admission.json',read(admission));save(SCOPE/'owner.json',{'token':os.urandom(12).hex(),
          'pins':load(ORIGINAL/'owner.json')['pins'],'admission_sha256':admission_sha,'source_sha256':a['source_sha256']})
    for name in IMMUTABLE:save(SCOPE/name,read(ORIGINAL/name))
    old=cp.S;cp.S=SCOPE
    try:
        (SCOPE/'pg-checkpoint').mkdir(mode=0o700)
        cp.copy_tree(ORIGINAL/'pg-checkpoint',SCOPE/'pg-checkpoint')
        rows,_=cp.scan_tree(SCOPE/'pg-checkpoint',True)
        need(sha(b''.join(cp.enc(row)+b'\n' for row in rows))==pg['pg_files_sha256'],'copied_golden_database_changed')
        (SCOPE/'private').mkdir(mode=0o700)
        private=cp.cache_manifest(ORIGINAL/'private')
        need(sha(cp.enc(private))==a['private_input_manifest_sha256'],'original_private_proof_inputs_changed')
        cp.copy_cache(ORIGINAL/'private',SCOPE/'private',private)
        (SCOPE/'fallback-cache').mkdir(mode=0o700)
        for role in ('serving','writer'):
            target=SCOPE/'fallback-cache'/role;target.mkdir(mode=0o700)
            cp.copy_cache(ORIGINAL/'fallback-cache'/role,target,cache['manifests'][role])
    finally:cp.S=old
    return baseline

def publish_missing(cp,a,admission_sha):
    # Frozen consumers still read the original completed/golden paths. New
    # successful evidence is create-new and explicitly records the failed origin.
    need(not (ORIGINAL/'completed.json').exists() and not (ORIGINAL/'backup-receipt.json').exists(),
         'original_proof_publication_already_present')
    provenance={'version':1,'kind':'isolated-proof-successor-v1','source_sha256':a['source_sha256'],
                'admission_sha256':admission_sha,'successor_scope':str(SCOPE),
                'failed_original_artifacts':a['failed_proof_sha256'],
                'global_manifest_sha256':a['global_manifest_sha256'],
                'private_input_manifest_sha256':a['private_input_manifest_sha256'],
                'only_change':'restore_original_writer_cache_ceiling','writer_cache_max_bytes':a['writer_cache_max_bytes']}
    completed=load(SCOPE/'completed.json');completed['proof_continuation']=provenance
    backup=load(SCOPE/'backup-receipt.json')
    backup['proof_continuation']=provenance
    extra=[SCOPE/'admission.json',SCOPE/'completed.json',SCOPE/'pre-cleanup-diagnostics.json',SCOPE/'diagnostics-ack.json',
           INSTALL/'proof-continuation.py']
    extra += [ORIGINAL/name for name in FAILED]
    acknowledgement=load(SCOPE/'diagnostics-ack.json')
    diagnostics=load(SCOPE/'pre-cleanup-diagnostics.json')
    need(acknowledgement['token']==load(SCOPE/'owner.json')['token']
         and acknowledgement['phase']==diagnostics['phase']
         and acknowledgement['logs']=={row['log_path']:row['log_sha256'] for row in diagnostics['containers']}
         and acknowledgement['diagnostics_sha256']==sha(read(SCOPE/'pre-cleanup-diagnostics.json')),
         'diagnostic_acknowledgement_changed')
    for path,digest in acknowledgement['logs'].items():
        path=Path(path)
        need(path.parent==SCOPE and re.fullmatch('pre-cleanup-[0-3]\\.log',path.name)
             and sha(read(path))==digest,'diagnostic_log_changed')
        extra.append(path)
    for path in extra:backup['artifacts'].append({'path':str(path),'sha256':sha(read(path))})
    backup['artifacts'].append({'path':str(ORIGINAL/'completed.json'),'sha256':sha(enc(completed))})
    outputs={name:read(SCOPE/name) for name in ('clone-proof-result.json','clone-writer-proof.json')}
    outputs['completed.json']=enc(completed)
    outputs['backup-receipt.json']=enc(backup)
    # This intent is inert reconciliation evidence. It does not permit a proof
    # replay; an interrupted publication requires separately admitted reconciliation.
    save(SCOPE/'publication-intent.json',{'admission_sha256':admission_sha,'backup_last':True,
         'planned_output_sha256':{name:sha(body) for name,body in outputs.items()}})
    for name in outputs:
        need(not (ORIGINAL/name).exists() and not (ORIGINAL/name).is_symlink(),'original_output_already_present')
    for name,body in outputs.items():save(ORIGINAL/name,body)
    save(SCOPE/'published.json',{'original_completed_sha256':sha(read(ORIGINAL/'completed.json')),
                                'original_backup_sha256':sha(read(ORIGINAL/'backup-receipt.json'))})

def execute(cp,a,admission,admission_sha):
    baseline=seed_scope(cp,a,admission,admission_sha)
    old_s=cp.S;frozen_writer=cp.writer_config;frozen_disk=cp.disk_identity;frozen_cleanup=cp.cleanup_clone
    token=load(SCOPE/'owner.json')['token'];phase={'name':'proof_entry'};capture={'ok':False}
    def disk():
        previous=cp.S;cp.S=ORIGINAL
        try:value=frozen_disk()
        finally:cp.S=previous
        need(SCOPE.stat().st_dev==ORIGINAL.stat().st_dev and SCOPE.stat().st_uid==os.geteuid()
             and not SCOPE.stat().st_mode&0o077,'successor_scope_mount_changed')
        need(value==baseline['disk_identity'],'original_checkpoint_mount_changed')
        return value
    def cleanup(containers,network,owner):
        try:
            capture['ok']=capture_independently(cp,containers,owner,phase['name'])
        except Exception:capture['ok']=False
        finally:frozen_cleanup(containers,network,owner)
    originals={}
    for name in ('fallback_writer_proof','cold_body_readback','notice_readback'):
        originals[name]=getattr(cp,name)
        def wrapped(*args,_name=name,**kwargs):
            phase['name']=_name;return originals[_name](*args,**kwargs)
        setattr(cp,name,wrapped)
    cp.S=SCOPE;cp.disk_identity=disk;cp.cleanup_clone=cleanup
    cp.writer_config=lambda text:corrected_writer_config(cp,frozen_writer,text,a['writer_cache_max_bytes'])
    success=False
    try:
        cp.proof(load(SCOPE/'owner.json')['pins']);success=True
    except BaseException as error:
        code=str(error) if isinstance(error,cp.Stop) and re.fullmatch('[a-z0-9_]+',str(error)) else 'proof_operation_failed'
        try:save(SCOPE/'failure.json',{'phase':phase['name'],'error_type':type(error).__name__,
                'code':code,'diagnostics_persisted':capture['ok'],'original_failed_proof_preserved':True})
        except Exception:pass
        raise
    finally:
        cp.S=old_s;cp.writer_config=frozen_writer;cp.disk_identity=frozen_disk;cp.cleanup_clone=frozen_cleanup
        for name,value in originals.items():setattr(cp,name,value)
    need(success and capture['ok'],'proof_or_required_diagnostics_incomplete')
    need(sha(read(admission,1024**2))==admission_sha and sha(read(SCOPE/'admission.json',1024**2))==admission_sha,
         'standalone_admission_changed_during_proof')
    verify_original_pins(cp,a)
    for name,expected in a['immutable_sha256'].items():
        need(sha(read(SCOPE/name))==expected,'copied_immutable_proof_input_changed')
    need(sha(cp.enc(cp.cache_manifest(SCOPE/'private')))==a['private_input_manifest_sha256'],
         'copied_private_proof_inputs_changed')
    rows,_=cp.scan_tree(SCOPE/'pg-checkpoint',True)
    need(sha(b''.join(cp.enc(row)+b'\n' for row in rows))==load(ORIGINAL/'checkpoint-completed.json')['pg_files_sha256'],
         'copied_golden_database_changed_after_proof')
    for role,expected in load(ORIGINAL/'cache-baselines.json')['manifests'].items():
        need(cp.cache_manifest(SCOPE/'fallback-cache'/role)==expected,'copied_golden_cache_changed_after_proof')
    finished=load(SCOPE/'completed.json')
    need(finished['revision']==REVISION and finished['schema']==18
         and finished['pins']==load(ORIGINAL/'owner.json')['pins']
         and finished['old_clone_verified'] is True and finished['fallback_writer_verified'] is True
         and finished['checkpoint_receipt_sha256']==sha(read(SCOPE/'checkpoint-completed.json'))
         and finished['clone_proof_sha256']==sha(read(SCOPE/'clone-proof-result.json')),
         'finished_successor_proof_changed')
    for artifact in load(SCOPE/'backup-receipt.json')['artifacts']:
        need(sha(read(Path(artifact['path'])))==artifact['sha256'],'finished_successor_artifact_changed')
    cp.source_guard();cp.roles_stopped();cp.checked_identity(cp.schema_identity(),True)
    need(cp.pod_projection(cp.role_pods('postgres')[0])==load(ORIGINAL/'original-pg-resumed.json')['new_pg_pod'],
         'original_pg_process_changed_after_successor')
    publish_missing(cp,a,admission_sha)
    return {'verified':True,'proof_successor_completed':True,'production_mutation_attempted':False,
            'original_failure_preserved':True,'backup_receipt_sha256':sha(read(ORIGINAL/'backup-receipt.json'))}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--admission',type=Path,required=True)
    p.add_argument('--admission-sha256',required=True);p.add_argument('--source-sha256',required=True);args=p.parse_args()
    need(os.geteuid()==0,'root_required')
    cp,a=verify_admission(args.admission,args.admission_sha256,args.source_sha256)
    fd=os.open(ORIGINAL/'.proof-successor-v1.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        import fcntl
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(execute(cp,a,args.admission,args.admission_sha256),sort_keys=True))
    finally:os.close(fd)

if __name__=='__main__':
    try:main()
    except Exception:
        print(json.dumps({'verified':False,'proof_successor_incomplete':True,'original_failed_proof_preserved':True}))
        raise SystemExit(1)
