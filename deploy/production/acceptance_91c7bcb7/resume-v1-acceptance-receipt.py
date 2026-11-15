#!/usr/bin/env python3
"""Aggregate actual guarded private/public observations into exact controller receipts.
Receipt freshness requires fresh private evidence and a fresh unchanged-runtime bookend.
"""
import argparse
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.dont_write_bytecode=True
WORK=Path('/tmp/devres-upgrade-91c7bcb7-20261115')
BUNDLE=Path('/var/lib/devres-production-upgrades/91c7bcb7-20261115')
REVISION='91c7bcb7aed8eede1627bf87254c0567ef48ab7b'
VERSION='0.1.0-build.91c7bcb7'
PROBE=Path('/tmp/devres-public-probe-91c7bcb7/devres-probe')
PROBE_SHA='2fd8e53e3eee3091b6a86a56136233f6adaf3e96cad33a6117361a08069cdd4e'
SOURCE_SHA='d92b3850074b3155866a376824b0a625151be17a260e4ea7bae058fb46f224a9'
OPERATIONAL_SHA='f75f6dd5b042a2dd4989f7afb1e43dd0f7a05f417c0a4fad7d5d936d62d2fc28'
PRODUCERS={'target-private-acceptance.py':'9e512e9adad66f8df7ca27cac852e751406352f5248a683d1639d72fb8d0b3bb',
           'resume-v1-public-matrix.py':'29ef35509c37ed91481e77d10290c082498e6dc8cdae45bac7be167656463985',
           'mcp_smoke.py':'0a7db0771b066e5cb74e08c3a7d01d5098da0eea0962c67ccaa8271d63e7e601'}
REVISIONS=('2025-11-25','2026-07-28')
FAMILIES=('ipv4','ipv6')
CID='blake3:f561023b34507798258530bff923c41bab5d092d71b2cae7da484e6d5ce6d0e0'
BODY='blake3:58f50168dc03a034edf54305bbf7dd71e1e1f91cb942d5e8e401ab8939890c1a'
NOTICE='e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156'
PROVIDERS=('rfc','crates','rustsec','mdn','whatwg','w3c','chromium','npm','wikipedia')
RESERVE=128*1024**3

class Stop(RuntimeError):pass

def need(value,code):
    if not value:raise Stop(code)

def now():return dt.datetime.now(dt.timezone.utc)

def instant(value):
    v=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    need(v.tzinfo is not None and v.utcoffset()==dt.timedelta(0),'utc_timestamp_required')
    return v

def code_sha(path,expected,private=True):
    path=Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)),'artifact_path')
    with path.open('rb') as stream:
        meta=os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid==os.geteuid() and meta.st_nlink==1
             and not meta.st_mode&(0o077 if private else 0o022),'artifact_permissions')
        import hashlib
        h=hashlib.sha256()
        for block in iter(lambda:stream.read(1024**2),b''):h.update(block)
        final=os.fstat(stream.fileno())
        need((meta.st_dev,meta.st_ino,meta.st_size,meta.st_mtime_ns)==(final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns),'artifact_changed')
    actual=h.hexdigest()
    if expected is not None:need(actual==expected,'artifact_hash')
    return {'path':str(path),'sha256':actual}

def label(value):
    need(re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',value or '') is not None,'bounded_label_required')
    return value

def source_module(path,expected,name):
    code_sha(path,expected)
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m

def fixed_sources(compression_sha):
    # Public executable permissions cannot enter the controller's private artifact
    # list. Verify its actual bytes, then retain its private OCI qualification.
    code_sha(PROBE,PROBE_SHA,False)
    native=WORK/'probe-native-qualification.json'
    qualifier=json.loads(native.read_bytes())
    need(qualifier.get('commit')==REVISION and qualifier.get('binary_sha256')==PROBE_SHA
         and qualifier.get('architecture')=='amd64' and qualifier.get('anonymous_full_pull') is True,'native_probe_qualification')
    artifacts=[code_sha(WORK/'source.tar.gz',SOURCE_SHA),code_sha(native,None)]
    need(re.fullmatch('[0-9a-f]{64}',compression_sha or '') is not None,'compression_source_hash_required')
    artifacts.append(code_sha(WORK/'compressed-probe.py',compression_sha))
    artifacts.extend(code_sha(WORK/name,h) for name,h in PRODUCERS.items())
    return artifacts

def read_artifact(op,path,artifacts):
    body=op.raw(path)
    import hashlib
    artifacts.append({'path':str(path),'sha256':hashlib.sha256(body).hexdigest()})
    return json.loads(body)

def sample_path(name):return WORK/'operational-proofs'/label(name)/'observation.json'

def frozen_projection(v):
    keys=('prepared_sha256','pods','edge','profiles','boot','configs_variant','collectors','source_urls','authority_sha256')
    return {key:v[key] for key in keys}

def validate_sample(v,state,current,phase=None):
    need(v.get('version')==1 and v.get('revision')==REVISION and v.get('guard_passed') is True
         and v.get('prepared_sha256')==state['prepared_sha256'] and v.get('pods')==state['pods'],'sample_runtime_identity')
    need(v.get('phase')==(phase or state['phase']) and v['configs_variant']==state['configs'],'sample_phase')
    need(v['edge']==current['edge'] and v['profiles']==current['profiles'] and v['boot']==current['boot'],'sample_edge_or_boot_changed')
    need(v['database']['owners']==current['database']['owners'] and v['database']['archive']==current['database']['archive']
         and v['database']['system_id']==current['database']['system_id'],'sample_writer_or_archive_changed')
    need(v['database']['schema']==18 and v['database']['control']==current['database']['control']
         and v['database']['reader_select_gaps']==0 and v['database']['reader_mutation_tables']==0
         and v['database']['reader_default_readonly'] is True,'sample_schema_or_authority')
    need(v['authority_sha256']==current['authority_sha256'],'sample_database_credentials_changed')
    need(v['free_bytes']>=RESERVE and v['free_inodes']>0 and set(v['timers'])=={'devres-capacity.timer','devres-cert-renew.timer'}
         and all(x=='active' for x in v['timers'].values()),'sample_capacity_or_timers')
    need(v['collectors']==current['collectors'] and v['source_urls']==current['source_urls'],'sample_source_settings_changed')

def private_proof(value,allow_historical=False):
    need(value.get('version')==1 and value.get('release')==VERSION and value.get('private_mcp_both_revisions') is True
         and value.get('tool_inventory')==98 and value.get('source_offer_verified') is True
         and value.get('no_provider_acquisition') is True,'private_contract')
    need(value.get('client_certificate')=={'missing':'rejected','wrong':'rejected'}
         and value.get('writer_authorization')=={'missing':401,'invalid':401}
         and value.get('reader_sqlstates')=={'explicit_read_only':'25006','privilege':'42501'}
         and value.get('reader_noop_transactions_rolled_back') is True,'private_authentication_or_readonly')
    need(value.get('edge_private_denials')=={'postgres':'blocked','writer':'blocked','private_health':'blocked'}
         and value.get('edge_nodeport_positive') is True,'private_network_boundary')
    pinned=value.get('pinned',{})
    need(set(pinned)==set(REVISIONS),'private_protocol_cells')
    for v in pinned.values():
        need(v.get('capture')==CID and v.get('historical_notice_sha256')==NOTICE,'private_immutable_notice')
        need(v.get('current_policy_read') == 'ready','private_policy_failure')
        if v['current_policy_read']=='ready':
            need(v.get('body_hash')==BODY and isinstance(v.get('generation'),str)
                 and v['generation'].startswith('devres://attribution/blake3:'),'private_ready_capture_identity')
    age=(now()-instant(value['observed_at'])).total_seconds()
    need(age>=-5 and (allow_historical or age<=300),'private_proof_stale')

def public_proofs(op,folder,artifacts,full=False,compression_sha=None):
    dates=[]
    for family in FAMILIES:
        value=read_artifact(op,folder/('http-'+family+'.json'),artifacts)
        need(value.get('family')==family and value.get('http_contract_passed') is True and value.get('tool_inventory')==98
             and value.get('release')==VERSION and set(value.get('protocols',[]))==set(REVISIONS)
             and value.get('no_source_acquisition') is True,'public_http_cells')
        trace=folder/('trace-'+family+'.jsonl')
        artifacts.append(code_sha(trace,value.get('exchange_trace_sha256')))
        need(isinstance(value.get('exchange_trace_sha256'),str),'exchange_trace_required')
        if full:need(value.get('exhaustive_obsolete_name_negatives') is True,'paused_http_full_negatives_required')
        dates.append(instant(value['observed_at']))
        address='62.210.240.40' if family=='ipv4' else '2001:bc8:701:65:56fb:66ff:fe00:da0d'
        expected=('127.0.0.1 localhost\n::1 localhost\n'+address+' dev-resources.mcp.publicdata.stream\n').encode()
        import hashlib
        hostsha=hashlib.sha256(expected).hexdigest()
        # hosts files are intentionally world-readable for the dropped-uid probe.
        code_sha(folder/('hosts-'+family),hostsha,False)
        need((folder/('hosts-'+family)).read_bytes()==expected,'public_family_hosts')
        for revision in REVISIONS:
            value=read_artifact(op,folder/('wt-'+family+'-'+revision+'.json'),artifacts)
            need(value.get('family')==family and value.get('revision')==revision and value.get('exit')==0
                 and value.get('released_probe_sha256')==PROBE_SHA and value.get('client_transport_override') is False
                 and value.get('family_mapping_verified') is True and value.get('hosts_sha256')==hostsha,'public_wt_cells')
            need(value.get('stdout','').strip()=='WebTransport '+revision+': discovery, tool listing, and server identity verified.','native_probe_success_required')
            dates.append(instant(value['observed_at']))
    value=read_artifact(op,folder/'compression.json',artifacts)
    need(value.get('version')==1 and value.get('verified') is True and value.get('release')==VERSION
         and value.get('producer_sha256')==compression_sha and re.fullmatch('[0-9a-f]{64}',compression_sha or '') is not None
         and value.get('no_provider_acquisition') is True,'compression_proof_identity')
    begin=instant(value['started_at']);end=instant(value['observed_at'])
    need(begin<=end,'compression_proof_interval')
    cells=value.get('cells',[])
    expected={(f,r,e) for f in FAMILIES for r in REVISIONS for e in ('gzip','br','zstd')}
    need(isinstance(cells,list) and len(cells)==12,'compression_twelve_cells_required')
    seen=set();canonical={}
    for cell in cells:
        key=(cell.get('family'),cell.get('revision'),cell.get('encoding'))
        need(key in expected and key not in seen,'compression_unique_cells_required')
        seen.add(key)
        need(cell.get('http_status')==200 and cell.get('content_encoding')==key[2]
             and cell.get('framing') == 'sse' and cell.get('cache_control_no_store') is True
             and cell.get('vary_accept_encoding') is True and cell.get('tool_inventory')==98
             and type(cell.get('decoded_bytes')) is int and 0<cell['decoded_bytes']<=8*1024**2,'compression_decoded_contract')
        digest=cell.get('canonical_result_sha256')
        need(isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest) is not None,'compression_canonical_digest')
        if key[1] in canonical:need(canonical[key[1]]==digest,'compression_canonical_result_mismatch')
        canonical[key[1]]=digest
        observed=instant(cell['observed_at']);need(begin<=observed<=end,'compression_cell_interval')
        dates.append(observed)
    need(seen==expected,'compression_all_codecs_required')
    dates.extend((begin,end))
    return dates

def proofset(op,private,public,before,after,state,current,artifacts,full=False,fresh_private=True,compression_sha=None):
    a=read_artifact(op,sample_path(before),artifacts);b=read_artifact(op,sample_path(after),artifacts)
    validate_sample(a,state,current);validate_sample(b,state,current)
    need(frozen_projection(a)==frozen_projection(b),'proofset_process_drift')
    start=instant(a['observed_at']);end=instant(b['observed_at'])
    need(0<=(end-start).total_seconds()<=1800 and a['monotonic']<=b['monotonic'],'bounded_proof_interval_required')
    value=read_artifact(op,WORK/('target-private-acceptance-'+label(private)+'.json'),artifacts)
    private_proof(value,allow_historical=not fresh_private)
    dates=[instant(value['observed_at'])]
    if public is not None:dates+=public_proofs(op,WORK/label(public),artifacts,full,compression_sha)
    need(all(start<=v<=end for v in dates),'proofs_outside_frozen_bookends')
    if fresh_private:need(-5<=(now()-end).total_seconds()<=120,'proofset_after_sample_stale')
    return {'before':before,'after':after,'private':private,'public':public,'first_receipt_at':min(dates).isoformat(),
            'last_receipt_at':max(dates).isoformat(),'bookend_start':a['observed_at'],'bookend_end':b['observed_at'],
            'runtime_projection':frozen_projection(b)}

def observation_set(op,name,state,current,artifacts,compression_sha):
    folder=WORK/label(name)
    result=read_artifact(op,folder/'completed.json',artifacts)
    need(result.get('verified') is True and result.get('revision')==REVISION,'observation_result_identity')
    need(result.get('sources',{}).get('compression')==compression_sha,'observation_compression_source_changed')
    samples=[]
    for item in result.get('samples',[]):
        p=Path(item['path'])
        need(p.parent.parent==WORK/'operational-proofs' and p.name=='observation.json','owned_observation_sample_path')
        code_sha(p,item['sha256'])
        value=read_artifact(op,p,artifacts);validate_sample(value,state,current,'collectors_active')
        samples.append(value)
    need(len(samples)>=31 and len(samples)==result.get('sample_count'),'observation_sample_count')
    need(len({v['monotonic'] for v in samples})==len(samples),'duplicate_observation_sample')
    for a,b in zip(samples,samples[1:]):
        need(0<b['monotonic']-a['monotonic']<=45,'observation_sample_gap')
        need(frozen_projection(a)==frozen_projection(b),'observation_process_drift')
        need(b['database']['capture_count']>=a['database']['capture_count']
             and b['database']['archive_files']>=a['database']['archive_files'],'permanent_history_count_regressed')
    duration=samples[-1]['monotonic']-samples[0]['monotonic']
    maximum=max(b['monotonic']-a['monotonic'] for a,b in zip(samples,samples[1:]))
    need(duration>=900 and result.get('duration_seconds')==duration
         and result.get('maximum_gap_seconds')==maximum,'observation_actual_duration')
    need(-5<=(now()-instant(samples[-1]['observed_at'])).total_seconds()<=300,'observation_last_sample_stale')
    return {'duration_seconds':duration,'sample_count':len(samples),'maximum_gap_seconds':maximum,
            'started_at':samples[0]['observed_at'],'ended_at':samples[-1]['observed_at']}

def aggregate(args):
    op=source_module(args.operational,args.operational_sha,'reviewed_operational_proof')
    controller=source_module(args.controller,args.controller_sha,'reviewed_current_controller')
    checkpoint=source_module(args.checkpoint,args.checkpoint_sha,'reviewed_current_checkpoint')
    need(controller.REVISION==REVISION and checkpoint.REV==REVISION,'source_revision')
    c=controller.Controller(str(BUNDLE),str(BUNDLE/'plan.json'),'default')
    artifacts=fixed_sources(args.compression_sha)+[code_sha(args.operational,args.operational_sha),code_sha(args.controller,args.controller_sha),code_sha(args.checkpoint,args.checkpoint_sha)]
    with c.locked():
        c.guard();state=copy.deepcopy(c.state())
        expected={'runtime-ready':'reader_ready','activate-existing':'runtime_ready','finish':'collectors_active'}[args.mode]
        need(state['phase']==expected,'receipt_phase')
        base=op.load(op.BASELINE);database=op.sql(op.IDENTITY_SQL);op.validate_identity(database,base,state)
        authority=op.sql(op.AUTH_SQL);need(op.sha(op.enc(authority))==base['authority_sha256'],'current_database_authority_changed')
        flags,urls=op.source_flags(controller,state)
        current={'database':database,'authority_sha256':base['authority_sha256'],'collectors':flags,'source_urls':urls,
                 'edge':c.edge(),'profiles':{p:op.sha(v) for p,v in c.profiles().items()},'boot':c.boot()}
        sets=[];observation={}
        if args.mode=='finish':
            need(args.early and args.late and args.observation,'finish_inputs_required')
            sets.append(proofset(op,*args.early,state,current,artifacts,full=True,fresh_private=False,compression_sha=args.compression_sha))
            sets.append(proofset(op,*args.late,state,current,artifacts,compression_sha=args.compression_sha))
            observation=observation_set(op,args.observation,state,current,artifacts,args.compression_sha)
            need(instant(sets[0]['bookend_end'])<=instant(observation['started_at'])
                 and instant(observation['ended_at'])<=instant(sets[1]['bookend_end']),'active_bookends_must_cover_observation')
            need(all(set(f)==set(PROVIDERS) and all(f.values()) for f in flags.values()),'all_nine_sources_restored')
        else:
            need(args.private and args.before and args.after,'proofset_inputs_required')
            if args.mode=='activate-existing':need(args.public is not None,'activation_public_proofs_required')
            sets.append(proofset(op,args.private,args.public,args.before,args.after,state,current,artifacts,full=args.mode=='activate-existing',compression_sha=args.compression_sha))
        c.guard();need(c.state()==state,'receipt_runtime_changed')
        checks={'schema18':True,'policy2':True,'sole_writer':True,'read_only_serving':True,'private_boundary':True,
                'capture_notice_preserved':True,'tool_contract':True}
        if args.mode in ('activate-existing','finish'):
            checks.update(public_http_both_families_revisions=True,public_wt_both_families_revisions=True,public_compression_gzip_br_zstd=True)
        if args.mode=='finish':checks.update(nine_source_settings_preserved=True,timers_preserved=True,stable_processes=True)
        receipt={'version':1,'kind':{'runtime-ready':'target-private-acceptance','activate-existing':'target-activation-acceptance','finish':'target-observation-acceptance'}[args.mode],
                 'revision':REVISION,'prepared_sha256':state['prepared_sha256'],'store_binding_sha256':controller.STORE_BINDING,
                 'schema':18,'verified':True,'observed_at':now().isoformat(),'checks':checks,'artifacts':artifacts,
                 'processes':state['pods'],'configs':state['configs'],'proof_sets':sets,**observation}
        if args.mode == 'finish':
            result = op.load(WORK / args.observation / 'completed.json')
            samples = [op.load(item['path']) for item in result['samples']]
            simplified = {'samples':[{'pods':r['pods'],'configs':r['configs_variant'],
                'schema':r['database']['schema'],'policy':r['database']['control']['required_policy_epoch'],
                'writer_owner':r['database']['owners'],'monotonic':r['monotonic']} for r in samples]}
            observation_path=WORK/'resume-v1-active-observation-bound.json'
            op.save(observation_path,simplified)
            artifacts.append(code_sha(observation_path,None))
            receipt['observation_artifact']=str(observation_path)
        receipt['operation_label']=label(args.label)
        path=WORK/{'runtime-ready':'private-receipt.json','activate-existing':'activation-receipt.json','finish':'resume-v1-observation-receipt.json'}[args.mode]
        op.save(path,receipt)
    return {'verified':True,'kind':receipt['kind'],'receipt':str(path),'sha256':code_sha(path,None)['sha256']}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('runtime-ready','activate-existing','finish'))
    p.add_argument('--compression-sha',required=True);p.add_argument('--label',required=True);p.add_argument('--controller',type=Path,required=True);p.add_argument('--controller-sha',required=True)
    p.add_argument('--checkpoint',type=Path,required=True);p.add_argument('--checkpoint-sha',required=True)
    p.add_argument('--operational',type=Path,default=WORK/'operational-proof.py');p.add_argument('--operational-sha',default=OPERATIONAL_SHA)
    for name in ('private','public','before','after','observation'):p.add_argument('--'+name)
    p.add_argument('--early',nargs=4,metavar=('PRIVATE','PUBLIC','BEFORE','AFTER'));p.add_argument('--late',nargs=4,metavar=('PRIVATE','PUBLIC','BEFORE','AFTER'))
    a=p.parse_args();need(os.geteuid()==0,'root_required');print(json.dumps(aggregate(a),sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'verified':False,'code':str(error) if isinstance(error,Stop) else 'acceptance_aggregation_failed'}));sys.exit(1)
