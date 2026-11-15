#!/usr/bin/env python3
"""Thirty-two source-bound, read-only samples at 30-second intervals.
Failure retains its intent and evidence; this helper never alters a workload.
"""
import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode=True
import acceptance_common as common

WORK=common.WORK
REVISION='1d76fbcc5693efc9ca927fd05f942078f667f056'
SAMPLER_SHA=None
PERIOD=30
COUNT=32
RESERVE=128*1024**3
PROVIDERS={'rfc','crates','rustsec','mdn','whatwg','w3c','chromium','npm','wikipedia'}

class Stop(RuntimeError):pass

def need(v,c):
    if not v:raise Stop(c)

def sha(v):return hashlib.sha256(v).hexdigest()

def now():return dt.datetime.now(dt.timezone.utc).isoformat()

def load_source(path,expected):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)),'sampler_path')
    need(sha(path.read_bytes())==expected,'sampler_source_hash')
    spec=importlib.util.spec_from_file_location('loop_readonly_operational',path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m

def stable(v):
    out={key:v[key] for key in ('prepared_sha256','pods','edge','profiles','boot','configs_variant','collectors','source_urls','authority_sha256','timers')}
    out['database']={key:v['database'][key] for key in ('system_id','schema','archive','owners','control','reader_select_gaps','reader_mutation_tables','reader_default_readonly','pinned_generation')}
    return out

def validate(v,first=None,previous=None):
    need(v.get('version')==1 and v.get('revision')==REVISION and v.get('phase')=='collectors_active'
         and v.get('runtime')==common.RUNTIME and v.get('runtime_revision')==common.IDENTITY['revision']
         and v.get('configs_variant')=='active' and v.get('guard_passed') is True,'active_guarded_sample_required')
    need(set(v['pods'])=={'postgres','writer','backend'} and all(p.get('container_id') and p.get('started_at') for p in v['pods'].values()),'all_active_processes_required')
    d=v['database']
    need(d['schema']==common.SCHEMA and d['control']=={'format_version':1,'required_policy_epoch':2,'required_policy_fingerprint':'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'}
         and d['reader_select_gaps']==0 and d['reader_mutation_tables']==0 and d['reader_default_readonly'] is True,'runtime_readonly_policy2_required')
    need(len(d['owners'])==1 and d['owners'][0]['role']=='devres_writer'
         and d['owners'][0]['client_addr']==v['pods']['writer']['pod_ip'],'one_unchanged_writer_required')
    need(set(v['collectors'])=={'backend','writer'} and all(set(f)==PROVIDERS and all(type(x) is bool for x in f.values()) for f in v['collectors'].values()),'nine_source_settings_required')
    need(v['collectors']==json.loads((common.ROOT/'operational-baseline.json').read_bytes())['collectors'],'original_source_settings_required')
    need(set(v['source_urls'])=={'backend','writer'} and all(url==common.SOURCE_URL for url in v['source_urls'].values()),'target_source_url_required')
    need(v['free_bytes']>=RESERVE and v['free_inodes']>0
         and set(v['timers'])=={'devres-capacity.timer','devres-cert-renew.timer'} and all(t=='active' for t in v['timers'].values()),'capacity_and_timers_required')
    if first is not None:need(stable(v)==stable(first),'sampled_process_or_boundary_drift')
    if previous is not None:
        need(0<v['monotonic']-previous['monotonic']<=45,'maximum_sample_gap')
        need(d['capture_count']>=previous['database']['capture_count'] and d['archive_files']>=previous['database']['archive_files'],'permanent_history_count_regressed')

def run(args):
    need(re.fullmatch('[a-z0-9][a-z0-9-]{0,55}',args.label) is not None,'bounded_loop_label')
    common.manifest_sources()
    op=load_source(args.operational,args.operational_sha)
    # The operational sampler validates root-private module files and fixed context.
    op.bound_module(args.controller,args.controller_sha,'loop_exact_controller')
    op.bound_module(args.checkpoint,args.checkpoint_sha,'loop_exact_checkpoint')
    need(re.fullmatch('[0-9a-f]{64}',args.compression_sha or '') is not None
         and op.file_sha(common.ROOT/'compressed-probe.py')==args.compression_sha,'compression_source_hash')
    op.private_dir(WORK)
    root=WORK/args.label;root.mkdir(mode=0o700)
    intent={'version':1,'revision':REVISION,'started_at':now(),'read_only':True,'sample_count':COUNT,
            'period_seconds':PERIOD,'maximum_gap_seconds':45,'minimum_duration_seconds':900,
            'sources':{'loop':sha(Path(__file__).read_bytes()),'operational':args.operational_sha,
                       'controller':args.controller_sha,'checkpoint':args.checkpoint_sha,'compression':args.compression_sha}}
    op.save(root/'intent.json',intent)
    values=[];artifacts=[];started=time.monotonic()
    try:
        for index in range(COUNT):
            # No mutation or a rebaseline is allowed between samples.
            need(sha(args.operational.read_bytes())==args.operational_sha,'sampler_source_changed')
            need(op.file_sha(common.ROOT/'compressed-probe.py')==args.compression_sha,'compression_source_changed')
            name=args.label+'-%02d'%index
            result=subprocess.run([sys.executable,'-B',str(args.operational),'sample','--label',name,
                '--controller',str(args.controller),'--controller-sha',args.controller_sha,
                '--checkpoint',str(args.checkpoint),'--checkpoint-sha',args.checkpoint_sha],capture_output=True,timeout=50)
            need(result.returncode==0 and len(result.stdout)+len(result.stderr)<32768,'guarded_sample_failed')
            answer=json.loads(result.stdout)
            path=WORK/'operational-proofs'/name/'observation.json'
            need(answer.get('verified') is True and answer.get('evidence_path')==str(path),'sample_result_identity')
            digest=op.file_sha(path);need(answer.get('evidence_sha256')==digest,'sample_artifact_changed')
            value=op.load(path);validate(value,values[0] if values else None,values[-1] if values else None)
            values.append(value);artifacts.append({'path':str(path),'sha256':digest})
            if index<COUNT-1:time.sleep(max(0,started+(index+1)*PERIOD-time.monotonic()))
        duration=values[-1]['monotonic']-values[0]['monotonic']
        maximum=max(b['monotonic']-a['monotonic'] for a,b in zip(values,values[1:]))
        need(duration>=900 and maximum<=45,'actual_observation_interval_required')
        summary={'version':1,'revision':REVISION,'verified':True,'observed_at':now(),'sample_count':len(values),
                 'duration_seconds':duration,'maximum_gap_seconds':maximum,'started_at':values[0]['observed_at'],
                 'ended_at':values[-1]['observed_at'],'minimum_free_bytes':min(v['free_bytes'] for v in values),
                 'capture_count_start':values[0]['database']['capture_count'],'capture_count_end':values[-1]['database']['capture_count'],
                 'sampled_continuity_only':True,'continuous_availability_claimed':False,'sources':intent['sources'],'samples':artifacts}
        op.save(root/'completed.json',summary)
        return {'verified':True,'summary':str(root/'completed.json'),'sample_count':len(values),'duration_seconds':duration,'maximum_gap_seconds':maximum}
    except Exception as error:
        op.save(root/'failed.json',{'version':1,'revision':REVISION,'verified':False,'failed_at':now(),'completed_samples':len(values),
                                 'reason':str(error) if isinstance(error,Stop) else 'observation_incomplete','retained_samples':artifacts})
        raise

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True)
    p.add_argument('--operational',type=Path,default=common.ROOT/'operational-proof.py');p.add_argument('--operational-sha',default=common.manifest_sources()['operational-proof.py'])
    p.add_argument('--compression-sha',required=True);p.add_argument('--controller',type=Path,required=True);p.add_argument('--controller-sha',required=True)
    p.add_argument('--checkpoint',type=Path,required=True);p.add_argument('--checkpoint-sha',required=True)
    a=p.parse_args();need(os.geteuid()==0,'root_required');print(json.dumps(run(a),sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'verified':False,'code':str(error) if isinstance(error,Stop) else 'observation_loop_failed'}));sys.exit(1)
