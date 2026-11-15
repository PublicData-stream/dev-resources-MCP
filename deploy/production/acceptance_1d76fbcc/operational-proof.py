#!/usr/bin/env python3
"""Source-bound read-only migration and sampled operational evidence.
No schema, credential, queue, collector or production storage changes are offered.
"""
import argparse
import base64
import copy
import datetime as dt
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
import tomllib

sys.dont_write_bytecode = True
import acceptance_common as common

REVISION = '1d76fbcc5693efc9ca927fd05f942078f667f056'
BUNDLE = Path('/var/lib/devres-production-upgrades/1d76fbcc-20261115')
WORK = common.WORK
SOURCES = common.ROOT
BASELINE = SOURCES / 'operational-baseline.json'
GENERATION = 'blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81'
POLICY2 = 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'
PROVIDERS = ('rfc','crates','rustsec','mdn','whatwg','w3c','chromium','npm','wikipedia')
TIMERS = ('devres-capacity.timer','devres-cert-renew.timer')
K = ['k3s','kubectl','--context','default','--namespace','devres','--request-timeout=30s']
RESERVE = 128 * 1024**3
MAX_JSON = 8 * 1024**2

class Stop(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Stop(code)

def sha(value):
    return hashlib.sha256(value).hexdigest()

def enc(value):
    return json.dumps(value, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode()

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def raw(path, maximum=MAX_JSON):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)), 'private_path_required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        m = os.fstat(stream.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == os.geteuid() and not m.st_mode & 0o077
             and m.st_nlink == 1 and m.st_size <= maximum, 'bounded_private_file_required')
        value = stream.read(maximum+1)
        need(len(value) == m.st_size, 'file_changed')
        return value

def load(path):
    return json.loads(raw(path))

def file_sha(path):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)), 'private_path_required')
    with open(path,'rb') as stream:
        m = os.fstat(stream.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == os.geteuid() and not m.st_mode & 0o077 and m.st_nlink == 1,
             'private_artifact_required')
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
        n = os.fstat(stream.fileno())
        need((m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns)==(n.st_dev,n.st_ino,n.st_size,n.st_mtime_ns), 'artifact_changed')
    return h.hexdigest()

def bound_module(path, expected, name):
    need(re.fullmatch('[0-9a-f]{64}', expected or '') is not None and sha(raw(path)) == expected, 'source_hash_mismatch')
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def private_dir(path):
    path = Path(path)
    need(path.is_absolute() and Path('/tmp') in path.parents and not any(p.is_symlink() for p in (path,*path.parents)), 'owned_tmp_directory_required')
    m = path.stat()
    need(stat.S_ISDIR(m.st_mode) and m.st_uid == os.geteuid() and not m.st_mode & 0o077, 'private_directory_required')

def save(path,value):
    private_dir(path.parent)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(enc(value)); stream.flush(); os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def run(args, timeout=35):
    result=subprocess.run(args,capture_output=True,timeout=timeout)
    need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=MAX_JSON, 'readonly_command_failed')
    return result.stdout

# Password verifiers are hashed inside PostgreSQL; raw password/verifier material
# never leaves PostgreSQL. Returned fingerprints stay in root-private evidence.
AUTH_SQL = """SELECT json_build_object(
'roles',(SELECT json_agg(x ORDER BY x.rolname) FROM
 (SELECT a.oid::text,a.rolname,a.rolsuper,a.rolinherit,a.rolcreaterole,a.rolcreatedb,a.rolcanlogin,
 a.rolreplication,a.rolconnlimit,a.rolvaliduntil::text,a.rolbypassrls,r.rolconfig,
 encode(sha256(convert_to(coalesce(a.rolpassword,''),'UTF8')),'hex') AS verifier_sha256
 FROM pg_authid a JOIN pg_roles r ON r.oid=a.oid
 WHERE a.rolname IN('devres_admin','devres_reader','devres_writer')) x),
'memberships',(SELECT coalesce(json_agg(x ORDER BY x.member,x.roleid),'[]'::json) FROM
 (SELECT member::text,roleid::text,admin_option,inherit_option,set_option FROM pg_auth_members
 WHERE member IN(SELECT oid FROM pg_roles WHERE rolname IN('devres_admin','devres_reader','devres_writer'))) x))"""

IDENTITY_SQL = """SELECT json_build_object(
'system_id',(SELECT system_identifier::text FROM pg_control_system()),
'schema',(SELECT version FROM devres_schema WHERE singleton),
'archive',(SELECT json_build_object('backend',backend,'binding',binding,'epoch',epoch,
 'pending_binding',pending_binding,'initializing_s3',initializing_s3,'store_id',store_id)
 FROM devres_archive_control WHERE singleton),
'control',(SELECT data FROM devres_attribution_control WHERE singleton),
'recovery',pg_is_in_recovery(),
'npm_recovery_tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND c.relname IN('devres_npm_advisory_job_history','devres_npm_advisory_recoveries','devres_npm_recovery_work')),
'new_tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind='r' AND c.relname IN('devres_attribution_recoveries','devres_attribution_origins')),
'new_columns',(SELECT count(*) FROM information_schema.columns WHERE table_schema='public'
 AND table_name='devres_rfc_jobs' AND column_name IN('failure','last_attempt_at')),
'recovery_trigger',(SELECT count(*) FROM pg_trigger t JOIN pg_class c ON t.tgrelid=c.oid
 WHERE c.relname='devres_attribution_recoveries' AND t.tgname='devres_attribution_recovery_immutable' AND NOT t.tgisinternal),
'reader_select_gaps',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN('r','p','v','m') AND NOT has_table_privilege('devres_reader',c.oid,'SELECT')),
'reader_mutation_tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN('r','p','v','m')
 AND has_table_privilege('devres_reader',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')),
'reader_default_readonly',(SELECT coalesce(rolconfig @> ARRAY['default_transaction_read_only=on'],false)
 AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls
 FROM pg_roles WHERE rolname='devres_reader'),
'owners',(SELECT coalesce(json_agg(json_build_object('pid',a.pid,'backend_start',a.backend_start::text,
 'role',a.usename,'client_addr',host(a.client_addr)) ORDER BY a.pid),'[]'::json)
 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory'
 AND l.classid=1835365490 AND l.objid=1 AND l.objsubid=2 AND l.granted AND l.mode='ExclusiveLock'
 AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())),
'capture_count',(SELECT count(*) FROM devres_captures),
'archive_files',(SELECT count(*) FROM devres_archive_file WHERE complete),
'pinned_generation',(SELECT json_build_object('id',id,'data',data,'data_integrity',data_integrity)
 FROM devres_attribution_generations WHERE id='"""+GENERATION+"""'))"""

BASE_IDENTITY_SQL = """SELECT json_build_object(
'system_id',(SELECT system_identifier::text FROM pg_control_system()),
'schema',(SELECT version FROM devres_schema WHERE singleton),
'archive',(SELECT json_build_object('backend',backend,'binding',binding,'epoch',epoch,
 'pending_binding',pending_binding,'initializing_s3',initializing_s3,'store_id',store_id)
 FROM devres_archive_control WHERE singleton),
'control',(SELECT data FROM devres_attribution_control WHERE singleton),
'pinned_generation',(SELECT json_build_object('id',id,'data',data,'data_integrity',data_integrity)
 FROM devres_attribution_generations WHERE id='"""+GENERATION+"""'))"""

def sql(query):
    need(query.startswith('SELECT ') and ';' not in query, 'fixed_readonly_query_required')
    return json.loads(run([*K,'exec','deployment/postgres','-c','postgres','--','psql','-X','-q','-U','devres_admin',
        '-d','devres','-At','-v','ON_ERROR_STOP=1','-c',
        "BEGIN READ ONLY; SET LOCAL statement_timeout='20s'; SET LOCAL lock_timeout='250ms'; "+query+'; COMMIT;']))

def generation_hash(value):
    need(isinstance(value,dict) and value.get('id')==GENERATION and value.get('data',{}).get('policy_epoch')==1
         and re.fullmatch('blake3:[0-9a-f]{64}',value.get('data_integrity','')) is not None,
         'historical_generation_missing_or_invalid')
    need(isinstance(value['data'].get('notices'),list) and value['data']['notices'], 'historical_notices_missing')
    return sha(enc(value))

def source_flags(controller,state):
    c=controller.Controller(str(BUNDLE),str(BUNDLE/'plan.json'),'default')
    texts=c.configurations(state)
    values={role:tomllib.loads(text) for role,text in texts.items()}
    flags={role:{provider:value[provider]['enabled'] for provider in PROVIDERS} for role,value in values.items()}
    need(set(flags)=={'backend','writer'} and all(type(v) is bool for f in flags.values() for v in f.values()),'explicit_nine_flags_required')
    if state['configs']=='paused':
        need(all(not v for f in flags.values() for v in f.values()) and all(not v['npm']['advisories_enabled'] for v in values.values()),'paused_collectors_required')
    return flags,{role:value['source']['url'] for role,value in values.items()}

def validate_identity(identity,baseline,state):
    need(identity['schema']==common.SCHEMA and identity['recovery'] is False,'runtime_schema_primary_required')
    need(identity['system_id']==baseline['database']['system_id'] and identity['archive']==baseline['database']['archive'],
         'original_database_or_archive_binding_changed')
    need(identity['control']=={'format_version':1,'required_policy_epoch':2,'required_policy_fingerprint':POLICY2},'policy2_required')
    need(identity['npm_recovery_tables']==(3 if common.SCHEMA==19 else 0),'runtime_npm_recovery_tables_required')
    need(identity['new_tables']==2 and identity['new_columns']==2 and identity['recovery_trigger']==1,'schema18_objects_required')
    need(identity['reader_select_gaps']==0 and identity['reader_mutation_tables']==0 and identity['reader_default_readonly'] is True,'actual_reader_authority_changed')
    owners=identity['owners']
    need(len(owners)==1 and owners[0]['role']=='devres_writer'
         and owners[0]['client_addr']==state['pods']['writer']['pod_ip'],'sole_writer_owner_required')
    need(generation_hash(identity['pinned_generation'])==baseline['generation_sha256'],'historical_notice_generation_changed')

def baseline(controller,checkpoint,label):
    c=controller.Controller(str(BUNDLE),str(BUNDLE/'plan.json'),'default')
    with c.locked():
        c.guard(); state=copy.deepcopy(c.state())
        need(state['phase'] in ('prepared','stopped') and state['configs']=='old','baseline_before_target_only')
        database=sql(BASE_IDENTITY_SQL)
        need(database['schema']==18 and database['control']=={'format_version':1,'required_policy_epoch':2,'required_policy_fingerprint':POLICY2},'old_schema18_policy2_required')
        need(database['system_id']==checkpoint.SYSID and {k:database['archive'][k] for k in checkpoint.ARCHIVE}==checkpoint.ARCHIVE,'old_database_archive_identity_required')
        authority=sql(AUTH_SQL)
        need(len(authority['roles'])==3,'actual_three_database_roles_required')
        result={'version':1,'kind':'pre-upgrade-operational-baseline','revision':REVISION,'observed_at':now(),
                'prepared_sha256':state['prepared_sha256'],'database':database,'authority':authority,
                'collectors':source_flags(controller,state)[0],'authority_sha256':sha(enc(authority)),'generation_sha256':generation_hash(database['pinned_generation'])}
        c.guard();need(c.state()==state,'guard_state_changed')
        save(BASELINE,result)
    return {'baseline_created':True,'schema':18,'historical_generation_preserved_for_comparison':True}

def observation(controller,checkpoint,mode,label):
    c=controller.Controller(str(BUNDLE),str(BUNDLE/'plan.json'),'default')
    base=load(BASELINE)
    need(base['revision']==REVISION,'baseline_revision_changed')
    private_dir(WORK)
    proofs=WORK/'operational-proofs'
    if not proofs.exists():proofs.mkdir(mode=0o700)
    private_dir(proofs)
    out=proofs/label;out.mkdir(mode=0o700)
    with c.locked():
        c.guard();state=copy.deepcopy(c.state())
        need(base['prepared_sha256']==state['prepared_sha256'],'baseline_prepared_changed')
        if mode=='migration':need(state['phase']=='writer_ready' and state['configs']=='paused' and set(state['pods'])=={'postgres','writer'},'paused_sole_target_writer_required')
        else:need(state['phase'] in ('reader_ready','runtime_ready','collectors_active','complete'),'sample_active_phase_required')
        database=sql(IDENTITY_SQL);validate_identity(database,base,state)
        authority=sql(AUTH_SQL)
        need(sha(enc(authority))==base['authority_sha256'],'database_role_or_credentials_changed')
        flags,urls=source_flags(controller,state)
        expected_url=common.SOURCE_URL
        need(all(url==expected_url for url in urls.values()),'target_source_offer_configuration_required')
        record={'version':1,'revision':REVISION,'observed_at':now(),'monotonic':time.monotonic(),
                'runtime':common.RUNTIME,'runtime_revision':common.IDENTITY['revision'],'prepared_sha256':state['prepared_sha256'],'phase':state['phase'],'configs_variant':state['configs'],
                'pods':state['pods'],'edge':c.edge(),'profiles':{p:sha(v) for p,v in c.profiles().items()},'boot':c.boot(),
                'database':database,'authority_sha256':sha(enc(authority)),'collectors':flags,'source_urls':urls,
                'guard_passed':True,'no_provider_acquisition':True}
        record['free_bytes']=shutil.disk_usage('/database/devres').free
        record['free_inodes']=os.statvfs('/database/devres').f_favail
        need(record['free_bytes']>=RESERVE and record['free_inodes']>0,'capacity_reserve_required')
        record['timers']={name:run(['systemctl','is-active',name]).decode().strip() for name in TIMERS}
        need(all(v=='active' for v in record['timers'].values()),'capacity_certificate_timers_required')
        artifacts=[]
        if mode=='migration':
            original=checkpoint.S
            previous=load(original/'checkpoint-completed.json')
            need(previous['schema']==18 and previous['pins']['controller_prepared_sha256']==state['prepared_sha256'],'checkpoint_identity_changed')
            need(previous['system_identifier']==database['system_id'] and previous['store_id']==database['archive']['store_id'],'checkpoint_database_changed')
            try:
                checkpoint.S=out
                for kind,field,name in [('archive','archive_manifest','archive-bindings.jsonl'),('captures','capture_manifest','capture-bindings.jsonl')]:
                    expected=previous[field]
                    need(file_sha(original/name)==expected['sha256'],'original_manifest_changed')
                    current=checkpoint.stream_manifest(kind)
                    need(current['sha256']==expected['sha256'] and current['files']==expected['files'],'paused_history_manifest_changed')
                    record[field]=current
                    artifacts.append({'path':str(out/name),'sha256':current['sha256']})
            finally:checkpoint.S=original
        c.guard();need(c.state()==state,'guard_state_changed')
        detail=out/'observation.json';save(detail,record)
        artifacts.append({'path':str(detail),'sha256':file_sha(detail)})
        if mode=='migration':
            receipt={'version':1,'kind':'migration'+str(common.SCHEMA),'revision':REVISION,'prepared_sha256':state['prepared_sha256'],
                     'store_binding_sha256':controller.STORE_BINDING,'verified':True,'observed_at':now(),'schema':common.SCHEMA,'runtime':common.RUNTIME,'runtime_revision':common.IDENTITY['revision'],
                     'processes':state['pods'],'configs':state['configs'],
                     'checks':{key:True for key in ('schema'+str(common.SCHEMA),'policy2','sole_writer','new_table_reader_grants','history_preserved','archive_binding_preserved','historical_notices_preserved')},
                     'artifacts':artifacts}
            save(out/'migration-receipt.json',receipt)
    return {'verified':True,'mode':mode,'phase':state['phase'],'evidence_path':str(detail),
            'evidence_sha256':file_sha(detail),'no_provider_acquisition':True}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('baseline','migration','sample'))
    p.add_argument('--label',required=True)
    p.add_argument('--controller',type=Path,required=True)
    p.add_argument('--controller-sha',required=True)
    p.add_argument('--checkpoint',type=Path,required=True)
    p.add_argument('--checkpoint-sha',required=True)
    a=p.parse_args()
    common.manifest_sources()
    need(os.geteuid()==0 and re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',a.label) is not None,'root_and_bounded_label_required')
    controller=bound_module(a.controller,a.controller_sha,'exact_upgrade_controller')
    checkpoint=bound_module(a.checkpoint,a.checkpoint_sha,'exact_checkpoint_helper')
    need(controller.REVISION==REVISION and controller.BUNDLE==str(BUNDLE) and checkpoint.REV==REVISION,'exact_source_identity_required')
    print(json.dumps(baseline(controller,checkpoint,a.label) if a.mode=='baseline' else observation(controller,checkpoint,a.mode,a.label),sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception as error:
        code=str(error) if isinstance(error,Stop) else 'operational_proof_failed'
        print(json.dumps({'verified':False,'code':code,'no_production_mutation_attempted':True}));sys.exit(1)
