#!/usr/bin/env python3
"""Execute the pinned restore state machine against isolated real PostgreSQL.

Production access is restricted to reading the verified golden checkpoint, full
cache baselines and admission files. No Kubernetes command, application process,
source-provider request or production credential mount is available to the adapter.
"""
import argparse
import copy
import datetime
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
import time
import types

sys.dont_write_bytecode = True
WORK = Path('/tmp/devres-upgrade-1d76fbcc-20261115')
BUNDLE = Path('/var/lib/devres-production-upgrades/1d76fbcc-20261115')
INSTALL = Path('/usr/local/libexec/devres-upgrade-1d76fbcc')
STATE = WORK / 'restore-rehearsal-state'
VOLUME = BUNDLE / 'restore-rehearsal-volume'
OUTPUT = WORK / 'restore-rehearsal-receipt.json'
REVISION = '1d76fbcc5693efc9ca927fd05f942078f667f056'
LABEL = 'devres.restore-rehearsal'
MAX_OUTPUT = 8 * 1024**2
RESERVE = 128 * 1024**3

class Stop(RuntimeError): pass

def need(value, code):
    if not value: raise Stop(code)

def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(value): return hashlib.sha256(value).hexdigest()

def read(path, maximum=MAX_OUTPUT):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)), 'private_path_required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
             and not info.st_mode&0o077 and info.st_size<=maximum,'private_source_required')
        body=stream.read(maximum+1)
        need(len(body)==info.st_size,'private_source_changed')
    return body

def save(path,value):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)), 'private_path_required')
    info=path.parent.stat()
    need(info.st_uid==os.geteuid() and not info.st_mode&0o077,'private_parent_required')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(encoded(value));stream.flush();os.fsync(stream.fileno())
    sync(path.parent)

def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def run(args,timeout=60,data=None):
    result=subprocess.run(args,input=data,capture_output=True,timeout=timeout)
    need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=MAX_OUTPUT,'isolated_command_failed')
    return result.stdout

def bound_module(path,expected,name):
    need(re.fullmatch('[0-9a-f]{64}',expected or '') and sha(read(path))==expected,'source_pin_changed')
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module

def durable_scope():
    need(STATE.is_dir() and not STATE.is_symlink() and not any(STATE.iterdir()),'fresh_rehearsal_scope_required')
    need(VOLUME.is_dir() and not any(p.is_symlink() for p in (VOLUME,*VOLUME.parents)),'owned_rehearsal_volume_required')
    a,b=STATE.stat(),VOLUME.stat()
    need(a.st_uid==b.st_uid==os.geteuid() and not a.st_mode&0o077 and not b.st_mode&0o077
         and (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'rehearsal_bind_identity_required')
    mounts=json.loads(run(['findmnt','--json','--target',str(STATE),'--output','TARGET,FSTYPE,OPTIONS']))['filesystems']
    need(len(mounts)==1 and mounts[0]['target']==str(STATE)
         and mounts[0]['fstype'] not in ('tmpfs','ramfs','rootfs','overlay')
         and 'rw' in mounts[0]['options'].split(','),'disk_backed_rehearsal_required')
    return {'device':a.st_dev,'inode':a.st_ino}

def production_files(cp):
    paths=[BUNDLE/name for name in ('state.json','prepared.json','plan.json')]
    paths += [cp.S/name for name in ('completed.json','checkpoint-completed.json')]
    return {str(path):sha(read(path,cp.MAX_MANIFEST)) for path in paths}

def production_fingerprint(files): return sha(encoded(files))

def file_hash(path):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)), 'private_artifact_path_required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
             and not info.st_mode&0o077,'private_artifact_required')
        result=hashlib.file_digest(stream,'sha256').hexdigest()
        after=os.fstat(stream.fileno())
        need((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'private_artifact_changed')
    return result

def revalidated_backup(cp,sources):
    """Fresh verification of the existing checkpoint, without another checkpoint."""
    original=cp.S/'backup-receipt.json'
    original_bytes=read(original)
    value=json.loads(original_bytes)
    need(value['kind']=='coordinated-schema18-backup' and value['revision']==REVISION
         and value['schema']==18 and value['verified'] is True
         and value['prepared_sha256']==sha(read(BUNDLE/'prepared.json')),
         'original_backup_receipt_changed')
    restore_checks=('coordinated_pg_s3','old_clone_verified','roles_stopped','pg_restarted_without_restore',
                    'credentials_preserved','fallback_writer_verified')
    need(all(value['checks'].get(name) is True for name in restore_checks),'original_backup_checks_missing')
    for artifact in value['artifacts']:
        need(file_hash(Path(artifact['path']))==artifact['sha256'],'original_backup_artifact_changed')
    need(file_hash(INSTALL/'restore-rehearsal.py')==sources['restore-rehearsal.py'],'rehearsal_source_changed')
    value['observed_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    value['current_revalidation']=True
    value['original_checkpoint_receipt_sha256']=sha(original_bytes)
    value['artifacts'] += [{'path':str(original),'sha256':sha(original_bytes)},
                           {'path':str(INSTALL/'restore-rehearsal.py'),'sha256':sources['restore-rehearsal.py']},
                           {'path':str(OUTPUT),'sha256':file_hash(OUTPUT)}]
    save(cp.S/'backup-receipt-after-rehearsal.json',value)
    return value

def copy_initial(cp,restore,source,target,expected):
    need(target.is_relative_to(STATE) and target.is_dir() and not any(target.iterdir()),'fresh_isolated_copy_required')
    run(['/usr/bin/rsync','-aHAX','--checksum','--numeric-ids','--one-file-system','--no-devices','--no-specials','--',str(source)+'/',str(target)+'/'],1800)
    need(restore.manifest(cp,target)['sha256']==expected,'isolated_initial_copy_changed')
    restore.flush_tree(cp,target)

class Adapter:
    """Only private Docker state implements the restore helper's runtime calls."""
    def __init__(self,cp,restore,root,token,pgimage,golden):
        self.original=cp;self.restore=restore;self.root=root;self.token=token;self.pgimage=pgimage
        self.PV=root/'isolated-pv';self.PV.mkdir(mode=0o700)
        self.source=self.PV/'18/docker';self.source.mkdir(parents=True,mode=0o700)
        self.S=cp.S;self.SYSID=cp.SYSID;self.PG=cp.PG;self.POLICY=cp.POLICY;self.MAX_MANIFEST=cp.MAX_MANIFEST
        self.CACHE_ROOTS={role:root/('cache-'+role) for role in ('serving','writer')}
        self.cache_data=copy.deepcopy(cp.load('cache-baselines.json'))
        self.layout={'source':str(self.source),'pv_uid':token+'-pv','pv_name':'isolated-pv',
            'pvc_uid':token+'-pvc','pvc_name':'isolated-pvc','pv_path':str(self.PV),
            'relative':'18/docker','container_data_directory':'/var/lib/postgresql/18/docker'}
        copy_initial(cp,restore,cp.S/'pg-checkpoint',self.source,golden['pg_files_sha256'])
        self.baseline={'layout':self.layout,'identity':copy.deepcopy(cp.load('baseline.json')['identity'])}
        for role,path in self.CACHE_ROOTS.items():
            path.mkdir(mode=0o700)
            cp.copy_cache(cp.S/'fallback-cache'/role,path,self.cache_data['manifests'][role])
            self.cache_data['layouts'][role]={'path':str(path),'identity':restore.tree_identity(path),
                'pv_uid':token+'-'+role+'-pv','pv_name':role+'-pv','pvc_uid':token+'-'+role+'-pvc','pvc_name':role+'-pvc'}
        self.cid=None
        self.name='devres-restore-rehearsal-'+token
        self.scan_tree=cp.scan_tree;self.cache_manifest=cp.cache_manifest;self.copy_cache=cp.copy_cache
        self.raw=cp.raw;self.disk_identity=cp.disk_identity;self.checked_identity=cp.checked_identity
        self.image_id=cp.image_id;self.control=cp.control
        self.pod_projection=lambda row:row

    def load(self,name):
        if name=='baseline.json':return copy.deepcopy(self.baseline)
        if name=='cache-baselines.json':return copy.deepcopy(self.cache_data)
        return self.original.load(name)

    def inspect(self):
        rows=json.loads(run(['docker','inspect',self.cid]))
        need(len(rows)==1,'one_owned_postgres_required')
        value=rows[0]
        need(value['Id']==self.cid and value['Config'].get('Labels',{}).get(LABEL)==self.token
             and value['Image']==self.pgimage and value['HostConfig']['NetworkMode']=='none'
             and not value['HostConfig'].get('PortBindings'),'isolated_postgres_identity_changed')
        need(all(Path(m['Source']).is_relative_to(self.root) for m in value['Mounts'] if m['Type']=='bind'),
             'production_mount_refused')
        return value

    def create(self):
        args=['docker','run','--detach','--pull','never','--name',self.name,'--network','none',
            '--read-only','--user','70:70','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--security-opt','apparmor=devres-runtime','--label',LABEL+'='+self.token,'--memory','4g','--cpus','2',
            '--tmpfs','/tmp:rw,nosuid,nodev,mode=1777','--tmpfs','/var/run/postgresql:rw,nosuid,nodev,uid=70,gid=70,mode=0777',
            '--mount','type=bind,src='+str(self.source)+',dst='+self.layout['container_data_directory'],self.pgimage,
            'postgres','-D',self.layout['container_data_directory'],'-c','listen_addresses=127.0.0.1',
            '-c','archive_mode=off','-c','archive_command=','-c','restore_command=','-c','primary_conninfo=',
            '-c','shared_buffers=256MB','-c','max_connections=30','-c','ssl=off',
            '-c','fsync=on','-c','full_page_writes=on','-c','synchronous_commit=on']
        save(self.root/'postgres-create-intent.json',{'name':self.name,'token':self.token,'image':self.pgimage})
        self.cid=run(args).decode().strip()
        need(re.fullmatch('[0-9a-f]{64}',self.cid),'isolated_container_id_required')
        save(self.root/'postgres-created.json',{'id':self.cid,'token':self.token})
        self.ready()

    def ready(self):
        deadline=time.monotonic()+180
        while True:
            need(self.inspect()['State']['Running'],'isolated_postgres_exited')
            value=subprocess.run(['docker','exec',self.cid,'pg_isready','-h','127.0.0.1','-U','devres_admin','-d','devres'],capture_output=True,timeout=10)
            if value.returncode==0:return
            need(time.monotonic()<deadline,'isolated_postgres_readiness_deadline');time.sleep(1)

    def sql(self,query):
        self.inspect()
        return json.loads(run(['docker','exec',self.cid,'psql','-X','-q','-U','devres_admin','-d','devres','-At','-v','ON_ERROR_STOP=1','-c',query]))

    def schema_identity(self):
        query="SELECT json_build_object('system_id',(SELECT system_identifier::text FROM pg_control_system()),'schema',(SELECT version FROM devres_schema WHERE singleton),'data_directory',current_setting('data_directory'),'recovery',pg_is_in_recovery(),'external_tablespaces',(SELECT count(*) FROM pg_tablespace WHERE pg_tablespace_location(oid)<>''),'wikipedia_tables',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_wikipedia_evidence')),(to_regclass('public.devres_wikipedia_state'))) t(oid) WHERE oid IS NOT NULL),'schema18_objects',(SELECT count(*) FROM (VALUES(to_regclass('public.devres_crate_enrichment_v2')),(to_regclass('public.devres_crate_enrichment_heads_v2')),(to_regclass('public.devres_crate_dump_failures')),(to_regclass('public.devres_crate_enrichment_all'))) t(oid) WHERE oid IS NOT NULL),'archive',(SELECT json_build_object('backend',backend,'binding',binding,'epoch',epoch,'pending_binding',pending_binding,'initializing_s3',initializing_s3,'store_id',store_id) FROM devres_archive_control WHERE singleton),'publication_owners',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1835365490 AND objid=1 AND objsubid=2 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())),'attribution',"+self.original.attribution_query()+')'
        return self.sql(query)

    def roles_stopped(self):
        # No application container, listener or credentials exist in this scope.
        self.inspect()

    def role_pods(self,role):
        need(role=='postgres','application_runtime_prohibited')
        value=self.inspect()
        if not value['State']['Running']:return []
        return [{'uid':self.cid,'container_id':'docker://'+self.cid,'image_id':value['Image'],
                 'started_at':value['State']['StartedAt'],'restarts':value['RestartCount'],
                 'name':self.name,'pod_ip':'127.0.0.1','owner':[{'uid':self.token}]}]

    def get(self,kind,name):
        if kind=='deployment' and name=='postgres':return {'spec':{'replicas':int(self.inspect()['State']['Running'])}}
        layouts=[self.layout,*self.cache_data['layouts'].values()]
        for layout in layouts:
            if kind=='pvc' and name==layout['pvc_name']:
                return {'metadata':{'uid':layout['pvc_uid']},'spec':{'volumeName':layout['pv_name']}}
            if kind=='pv' and name==layout['pv_name']:
                return {'metadata':{'uid':layout['pv_uid']},'spec':{'local':{'path':layout.get('path',str(self.PV))}}}
        raise Stop('production_resource_operation_prohibited')

    def k(self,*args,**kwargs):
        # No string accepted here can invoke kubectl or a production object.
        if args==('scale','deployment/postgres','--replicas=0'):
            self.inspect();return run(['docker','stop','--time','60',self.cid],90)
        if args==('scale','deployment/postgres','--replicas=1'):
            self.inspect();return run(['docker','start',self.cid],60)
        if args[:3]==('wait','--for=delete','pod'):
            need(not self.inspect()['State']['Running'],'isolated_postgres_not_stopped');return b''
        if args[:3]==('rollout','status','deployment/postgres'):
            self.ready();return b''
        raise Stop('production_resource_operation_prohibited')

    def cleanup(self):
        if self.cid is None:
            # A timed-out create is never assumed absent. Resolve its exact name,
            # then inspect immutable token/image/mount identity before removal.
            result=subprocess.run(['docker','inspect',self.name],capture_output=True,timeout=30)
            if result.returncode:
                need(not result.stdout,'uncertain_postgres_creation');return
            rows=json.loads(result.stdout)
            need(len(rows)==1,'one_owned_postgres_required');self.cid=rows[0]['Id']
        value=self.inspect()
        if value['State']['Running']:run(['docker','stop','--time','60',self.cid],90)
        need(not self.inspect()['State']['Running'],'isolated_postgres_not_stopped')
        run(['docker','rm',self.cid],60)

class IsolatedController:
    def __init__(self,adapter,root,controller_sha):
        self.a=adapter;self.root=root;root.mkdir(mode=0o700);self.recorded=None
        save(root/'rollback-intent.json',{'source_sha256':controller_sha,'maximum_attempts':1})
    def state(self):return {'runtime':'target','phase':'withdrawn'}
    def restore_guard(self,stage='',**kwargs):
        self.a.inspect();self.a.roles_stopped()
    def restore_record(self,receipt):
        need(receipt['database_restored'] is True and receipt['baseline_caches_restored'] is True,'isolated_restore_incomplete')
        self.recorded=copy.deepcopy(receipt)

def execute(cp,restore,source_pins):
    scope=durable_scope();completed=restore.checked_golden(cp)
    before=production_files(cp)
    need(shutil.disk_usage(STATE).free>=3*cp.load('checkpoint-completed.json')['pg_bytes']
         +3*cp.load('cache-baselines.json')['bytes']+RESERVE,'isolated_full_restore_headroom_required')
    token=os.urandom(12).hex();save(STATE/'owner.json',{'token':token,'scope':scope,'sources':source_pins})
    root=STATE/'runtime';root.mkdir(mode=0o700)
    adapter=None;success=False;proof=None
    try:
        adapter=Adapter(cp,restore,root,token,cp.image_id(cp.PG),completed)
        adapter.create()
        initial=adapter.schema_identity();cp.checked_identity(initial,True)
        # Fixed first-party marker proves replacement of changed cloned SQL, not
        # merely a restart of the same golden directory. It never touches corpus tables.
        run(['docker','exec',adapter.cid,'psql','-X','-q','-U','devres_admin','-d','devres','-v','ON_ERROR_STOP=1','-c',
             'CREATE TABLE devres_restore_rehearsal_marker(value integer NOT NULL); INSERT INTO devres_restore_rehearsal_marker VALUES(1);'])
        need(adapter.sql("SELECT to_json(to_regclass('public.devres_restore_rehearsal_marker') IS NOT NULL)") is True,'isolated_marker_not_created')
        controller_sha=json.loads(cp.raw(cp.PUBLIC))['controller_source_sha256']
        controller=IsolatedController(adapter,root/'controller',controller_sha)
        driver=restore.Restore(adapter,controller,root/'restore')
        receipt=driver.run({'controller':controller_sha,'checkpoint':source_pins['physical-checkpoint.py'],
                           'prepared':sha(read(BUNDLE/'prepared.json'))})
        after=adapter.schema_identity();cp.checked_identity(after,True)
        need(after['archive']==initial['archive'] and after['system_id']==initial['system_id'],'isolated_archive_or_system_changed')
        need(adapter.sql("SELECT to_json(to_regclass('public.devres_restore_rehearsal_marker') IS NULL)") is True,'isolated_marker_survived_restore')
        for role,path in adapter.CACHE_ROOTS.items():
            need(cp.cache_manifest(path)==adapter.cache_data['manifests'][role],'isolated_cache_restore_failed')
        need(controller.recorded==receipt and receipt['database_restored'] and receipt['baseline_caches_restored'],
             'exact_restore_state_machine_not_completed')
        proof={'before_schema':initial['schema'],'after_schema':after['schema'],'system_id':after['system_id'],
               'archive':after['archive'],'marker_removed':True,'restore_receipt':receipt,
               'postgres_image':adapter.pgimage,'postgres_process_after':adapter.role_pods('postgres')[0],
               'no_kubernetes_commands':True,'no_production_credentials':True,'no_network':True}
        save(STATE/'real-pg-proof.json',proof)
        success=True
    finally:
        if adapter is not None:adapter.cleanup()
    need(success,'real_restore_rehearsal_incomplete')
    restore.checked_golden(cp)
    after_files=production_files(cp)
    need(after_files==before,'production_admission_or_checkpoint_files_changed')
    save(STATE/'cleanup-completed.json',{'token':token,'owned_container_removed':True,'golden_retained':True})
    result={'version':1,'kind':'isolated-real-pg-restore-rehearsal','revision':REVISION,
            'prepared_sha256':sha(read(BUNDLE/'prepared.json')),'store_binding_sha256':cp.BIND,
            'verified':True,'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'sources':source_pins,'golden':{k:completed[k] for k in
                ('pg_files_sha256','capture_manifest_sha256','manifest_sha256','cache_baselines_sha256')},
            'production_state_scope':'admission_and_checkpoint_files','production_files':before,
            'production_before_sha256':production_fingerprint(before),'production_after_sha256':production_fingerprint(after_files),
            'checks':{'isolated_real_pg_restore':True,'restore_state_machine':True,'full_baseline_caches':True,
                      'production_untouched':True,'marker_removed':True,'owned_cleanup_complete':True},
            'artifacts':[{'path':str(STATE/'real-pg-proof.json'),'sha256':sha(read(STATE/'real-pg-proof.json'))},
                         {'path':str(STATE/'cleanup-completed.json'),'sha256':sha(read(STATE/'cleanup-completed.json'))}]}
    save(OUTPUT,result)
    revalidated_backup(cp,source_pins)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkpoint-sha256',required=True);parser.add_argument('--restore-sha256',required=True)
    parser.add_argument('--output',type=Path,default=OUTPUT)
    args=parser.parse_args()
    need(os.geteuid()==0 and args.output==OUTPUT and not OUTPUT.exists(),'root_and_fresh_fixed_receipt_required')
    cp=bound_module(INSTALL/'physical-checkpoint.py',args.checkpoint_sha256,'rehearsal_checkpoint')
    restore=bound_module(INSTALL/'restore-controller.py',args.restore_sha256,'rehearsal_restore')
    source_pins={'restore-rehearsal.py':sha(read(Path(__file__))),
                 'restore-controller.py':args.restore_sha256,'physical-checkpoint.py':args.checkpoint_sha256}
    result=execute(cp,restore,source_pins)
    print(json.dumps({'verified':True,'isolated_real_pg_restore':True,'receipt_sha256':sha(read(OUTPUT))}))

if __name__=='__main__':
    try:main()
    except Exception:
        print(json.dumps({'verified':False,'isolated_rehearsal_incomplete':True,'production_mutation_offered':False}))
        raise SystemExit(1)
