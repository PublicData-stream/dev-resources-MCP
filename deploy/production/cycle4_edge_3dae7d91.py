#!/usr/bin/env python3
"""Source-bound re-admission of one observed native edge process transition.

Historical files and admissions remain untouched. Historical projections exist
only inside explicit read-only guard/snapshot contexts. Native callers receive
the exact newly admitted snapshot. This module never restarts or changes the edge.
"""
from __future__ import annotations

import argparse
import contextlib
import contextvars
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

sys.dont_write_bytecode=True
REVISION='3dae7d914baa9379abc402c5a3bcf311e0db01bf'
SCOPE=Path('/var/lib/devres-production-edge-admissions/3dae7d91-20261117')
CANDIDATE=SCOPE/'candidate.json'
ADMISSION=SCOPE/'admission.json'
QUALIFIER=Path('/usr/local/libexec/devres-upgrade-3dae7d91/edge-qualification.py')
WORK=Path('/tmp/devres-upgrade-9373f71e-20261116')
PUBLIC=WORK/'public-upgrade-identity.json'
PUBLIC_SHA='977034a2a9806606f8971a536a2d3ea8d0553002a15e27781045e0cbaaf3a6b5'
MANIFEST_SHA='5dbf9d3be45cd6222eda9d36cc2d59b0dcd580b65143743933cc5d4b33a23a4b'
EXPECTED_BEFORE_SHA='feecd86fd6560ac969599f6763abda7d259d6c9caf3bcfc18bb906284949a854'
EXPECTED_AFTER_SHA='a2eccd752a0a6553df9b767e1bce561cfa187407304ab5515bc8096f9b2dc302'
WRAPPER=Path('/usr/local/libexec/devres-upgrade-33f3c730/upgrade-controller.py')
WRAPPER_SHA='4491b9b05d42f0519be4928cc49bc2490dbc5519c0dc75a6d28310faa172986c'
OLD_ADMISSION=Path('/var/lib/devres-production-upgrades/33f3c730-20261114/compression-sse-transition/admission.json')
CHAIN={
    str(WRAPPER):('33f3c730',WRAPPER_SHA,Path('/var/lib/devres-production-upgrades/33f3c730-20261114')),
    '/usr/local/libexec/devres-upgrade-91c7bcb7/upgrade-controller.py':('91c7bcb7','fa1ad0b5a7713787d12a44477b2a8f68ec7a79655c7a847ec4b74a819b8c4100',Path('/var/lib/devres-production-upgrades/91c7bcb7-20261115')),
    '/usr/local/libexec/devres-upgrade-9373f71e/upgrade-controller.py':('9373f71e','b98d2a02804feba7ba12a45fc539879ef435c74951dbfd20a68d999b3a745957',Path('/var/lib/devres-production-upgrades/9373f71e-20261116')),
}
SPECIAL={'upgrade-controller.py','physical-checkpoint.py','restore-controller.py','restore-rehearsal.py','npm-recovery.py','safety-supervisor.py'}
CHECKS=frozenset(('native_image_config_check','edge_process_listener_binding','public_tls_ipv4','public_tls_ipv6',
    'public_withdrawn_http_ipv4','public_withdrawn_http_ipv6','private_nodeport_ipv4','private_nodeport_ipv6',
    'retained_firewall_and_private_routes'))
_DEPTH=contextvars.ContextVar('cycle4_historical_edge_projection_depth',default=0)


class Refused(RuntimeError):pass


def need(value,code):
    if not value:raise Refused(code)


def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(body):return hashlib.sha256(body).hexdigest()


def raw(path,maximum=16*1024**2,private=True):
    path=Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)),'owned_path_required')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_nlink==1
             and not before.st_mode&(0o077 if private else 0o022) and before.st_size<=maximum,'owned_file_required')
        body=stream.read(maximum+1);after=os.fstat(stream.fileno())
        need(len(body)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'source_changed_during_read')
    return body


def load(path):
    value=json.loads(raw(path));need(type(value) is dict,'object_required');return value


def new(path,value):
    need(path.parent==SCOPE and not any(p.is_symlink() for p in (path,*path.parents)),'fixed_admission_scope_required')
    info=SCOPE.stat();need(info.st_uid==os.geteuid() and not info.st_mode&0o077,'private_scope_required')
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(encode(value));stream.flush();os.fsync(stream.fileno())
    descriptor=os.open(SCOPE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def source_guard():
    public_raw=raw(PUBLIC);need(sha(public_raw)==PUBLIC_SHA,'fixed_public_identity_required')
    public=json.loads(public_raw);sources=public.get('dependency_sources')
    need(type(sources) is dict and 2<=len(sources)<=32 and sources.get(str(WRAPPER))==WRAPPER_SHA,
         'fixed_dependency_manifest_required')
    manifest_raw=raw(WORK/'source-manifest.json');need(sha(manifest_raw)==MANIFEST_SHA,'fixed_consumed_source_manifest_required')
    manifest=json.loads(manifest_raw);need(type(manifest) is dict and len(manifest)==26,'fixed_source_count_required')
    result={str(PUBLIC):PUBLIC_SHA,str(WORK/'source-manifest.json'):MANIFEST_SHA}
    for name,wanted in sources.items():
        path=Path(name)
        need(path.is_relative_to('/usr/local/libexec') and path.suffix=='.py'
             and re.fullmatch('[0-9a-f]{64}',wanted or ''),'fixed_dependency_path_required')
        need(sha(raw(path,private=False))==wanted,'frozen_dependency_changed');result[str(path)]=wanted
    install=Path('/usr/local/libexec/devres-upgrade-9373f71e')
    for name,wanted in manifest.items():
        logical=Path(name)
        need(not logical.is_absolute() and '..' not in logical.parts and str(logical)==name
             and re.fullmatch('[0-9a-f]{64}',wanted or ''),'fixed_logical_source_required')
        path=(install if name in SPECIAL else WORK)/name
        need(sha(raw(path))==wanted,'frozen_source_changed');result[str(path)]=wanted
    for path,(_,wanted,_) in CHAIN.items():need(result.get(path)==wanted,'frozen_chain_hash_required')
    return result


def checked_module(path,wanted,name):
    need(sha(raw(path,private=False))==wanted,'source_hash_required')
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def changed_paths(before,after,prefix=()):
    if type(before) is not type(after):return {prefix}
    if type(before) is dict:
        result=set()
        for key in set(before)|set(after):
            result |= changed_paths(before[key],after[key],(*prefix,key)) if key in before and key in after else {(*prefix,key)}
        return result
    if type(before) is list:
        if len(before)!=len(after):return {prefix}
        return set().union(*(changed_paths(a,b,(*prefix,str(i))) for i,(a,b) in enumerate(zip(before,after))))
    return set() if before==after else {prefix}


def validate_delta(before,after):
    """Exactly the twelve observed fields; no generic restart or DNS allowance."""
    expected={('edge',key) for key in ('pid','pid_start_ticks','started')}
    expected|={('docker','host_config',key) for key in ('Dns','DnsOptions','DnsSearch')}
    for network in ('devres-net','pdf2md-net'):
        expected.add(('docker','networks',network,'MacAddress'))
        expected|={('networks',network,'edge_member',key) for key in ('MacAddress','EndpointID')}
    need(changed_paths(before,after)==expected,'exact_observed_delta_required')
    for key in ('Dns','DnsOptions','DnsSearch'):
        need(before['docker']['host_config'][key] is None and after['docker']['host_config'][key]==[],
             'only_null_to_empty_dns_metadata_admitted')
    a,b=before['edge'],after['edge']
    need(type(a['pid']) is type(b['pid']) is int and a['pid']>0 and b['pid']>0 and a['pid']!=b['pid']
         and re.fullmatch('[0-9]+',a['pid_start_ticks']) and re.fullmatch('[0-9]+',b['pid_start_ticks'])
         and int(b['pid_start_ticks'])>int(a['pid_start_ticks']),'one_later_edge_process_required')
    before_at=datetime.datetime.fromisoformat(a['started'].replace('Z','+00:00'))
    after_at=datetime.datetime.fromisoformat(b['started'].replace('Z','+00:00'))
    need(before_at.tzinfo is not None and after_at.tzinfo is not None and after_at>before_at,'later_edge_start_required')
    for network in ('devres-net','pdf2md-net'):
        mac=after['docker']['networks'][network]['MacAddress'];member=after['networks'][network]['edge_member']
        need(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac or '') and not int(mac[:2],16)&1
             and member['MacAddress']==mac and re.fullmatch('[0-9a-f]{64}',member.get('EndpointID','')),
             'same_network_endpoint_identity_required')
    return True



def validate_observed_snapshots(before,after):
    validate_delta(before,after)
    need(sha(encode(before))==EXPECTED_BEFORE_SHA and sha(encode(after))==EXPECTED_AFTER_SHA,
         'exact_observed_native_snapshot_required')
    return True


def _wrapper():
    return checked_module(WRAPPER,WRAPPER_SHA,'cycle4_checked_compression_wrapper')



ORIGINAL_OPERATOR=Path('/usr/local/libexec/devres-production-candidate-a938112b-apparmor-v1/scripts/production-operator.py')
ORIGINAL_BUNDLE=Path('/var/lib/devres-production-preparation/a938112b-7c7a24f')
CURRENT_BUNDLE=CHAIN['/usr/local/libexec/devres-upgrade-9373f71e/upgrade-controller.py'][2]


def _retained_bindings():
    state=load(CURRENT_BUNDLE/'state.json');prepared_raw=raw(CURRENT_BUNDLE/'prepared.json')
    need(state.get('source_sha256')==CHAIN['/usr/local/libexec/devres-upgrade-9373f71e/upgrade-controller.py'][1]
         and state.get('prepared_sha256')==sha(prepared_raw)
         and state.get('plan_sha256')==sha(raw(CURRENT_BUNDLE/'plan.json')),
         'retained_predecessor_binding_changed')
    need(state.get('runtime')=='fallback' and state.get('phase')=='withdrawn' and state.get('configs')=='paused'
         and state.get('replicas')=={'postgres':1,'writer':0,'backend':0}
         and set(state.get('pods',{}))=={'postgres'},'retained_withdrawn_state_required')
    # The original operator predates upgrade journals: prepare() wrote
    # settings/state plus rendered release/Kubernetes artifacts, not prepared.json.
    original=load(ORIGINAL_BUNDLE/'state.json')
    need(original.get('settings_sha256')==sha(raw(ORIGINAL_BUNDLE/'settings.json'))
         and original.get('runtime_receipt_sha256')==sha(raw(ORIGINAL_BUNDLE/'acceptance-receipt.json')),
         'original_operator_artifact_binding_changed')
    paths=[CURRENT_BUNDLE/name for name in ('state.json','prepared.json','plan.json')]
    paths += [ORIGINAL_BUNDLE/name for name in ('state.json','settings.json','release.json','kubernetes.json',
        'acceptance-receipt.json','boot-guard-acceptance.json')]
    return {str(path):sha(raw(path)) for path in paths}


def qualification_context(candidate=None):
    """Expose source-checked read-only baselines/modules, never guard acceptance."""
    sources=source_guard();bindings=_retained_bindings()
    if candidate is not None:need(candidate.get('retained_context')==bindings,'qualification_retained_context_changed')
    need(str(ORIGINAL_OPERATOR) in sources,'original_operator_dependency_required')
    wrapper=_wrapper()
    return {'prepared':load(CURRENT_BUNDLE/'prepared.json'),'bindings':bindings,'sources':sources,
        'controller_module':wrapper._immutable_predecessor,'compression_module':wrapper._implementation_module,
        'operator_module':checked_module(ORIGINAL_OPERATOR,sources[str(ORIGINAL_OPERATOR)],'cycle4_checked_original_operator'),
        'operator_bundle':ORIGINAL_BUNDLE}


def capture_current():
    """Read candidate reality only after retaining the original guard's denial."""
    sources=source_guard();wrapper=_wrapper();implementation=wrapper._implementation_module
    base=wrapper._immutable_predecessor;captured={}
    class Capture(wrapper.Controller):
        def _actual(self):
            try:return super()._actual()
            except Exception as error:
                if str(error)!='admitted_sse_edge_changed':raise
                actual,compose=implementation.native_snapshot(self,base,self._admission['after']['conf_contents'])
                validate_observed_snapshots(self._admission['after'],actual)
                need(sha(compose)==self._admission['compose_sha256'],'compose_must_remain_exact')
                captured.update(before=copy.deepcopy(self._admission['after']),after=actual,
                    compose_sha256=sha(compose),old_admission_sha256=sha(self._admission_raw))
                raise
    try:
        Capture(str(CHAIN[str(WRAPPER)][2]),str(CHAIN[str(WRAPPER)][2]/'plan.json'),'default')
    except Exception as error:
        need(str(error)=='admitted_sse_edge_changed' and bool(captured),'original_guard_denial_required')
    else:raise Refused('original_guard_denial_required')
    need(source_guard()==sources and sha(raw(OLD_ADMISSION))==captured['old_admission_sha256'],'historical_source_or_admission_changed')
    return {'version':1,'kind':'cycle4-edge-readmission-candidate','revision':REVISION,
        'bridge_source_sha256':sha(Path(__file__).read_bytes()),'historical_sources':sources,
        'public_identity_sha256':PUBLIC_SHA,'original_guard_denied':True,
        'original_error':'admitted_sse_edge_changed','retained_context':_retained_bindings(),**captured}


def candidate_matches_current(candidate):
    return {key:value for key,value in candidate.items() if key!='qualification_producer_sha256'}==capture_current()


def prepare_candidate(qualification_producer_sha):
    need(re.fullmatch('[0-9a-f]{64}',qualification_producer_sha or ''),'qualification_producer_pin_required')
    need(sha(raw(QUALIFIER))==qualification_producer_sha,'qualification_producer_source_changed')
    need(not any(p.is_symlink() for p in (SCOPE,*SCOPE.parents)),'fixed_scope_symlink_refused')
    SCOPE.mkdir(mode=0o700,parents=True,exist_ok=True)
    new(SCOPE/'candidate-intent.json',{'maximum_attempts':1,'bridge_source_sha256':sha(Path(__file__).read_bytes()),
        'qualification_producer_sha256':qualification_producer_sha})
    candidate=capture_current();candidate['qualification_producer_sha256']=qualification_producer_sha
    new(CANDIDATE,candidate)
    return {'candidate_sha256':sha(raw(CANDIDATE)),'original_guard_denied':True,'guard_accepted':False}


def validate_qualification(candidate,candidate_sha,qualification,producer_sha):
    need(qualification.get('version')==1 and qualification.get('kind')=='cycle4-native-edge-qualification'
         and qualification.get('candidate_sha256')==candidate_sha and qualification.get('producer_sha256')==producer_sha
         and candidate.get('qualification_producer_sha256')==producer_sha
         and qualification.get('fixture') is False and qualification.get('verified') is True,
         'real_source_bound_edge_qualification_required')
    checks=qualification.get('checks')
    need(type(checks) is dict and set(checks)==CHECKS and all(value is True for value in checks.values()),
         'complete_edge_qualification_checks_required')
    need(qualification.get('full_public_mcp_acceptance') is False and qualification.get('native_webtransport_acceptance') is False,
         'deferred_full_acceptance_must_be_explicit')
    artifacts=qualification.get('artifacts')
    need(type(artifacts) is list and 1<=len(artifacts)<=64,'qualified_edge_artifacts_required')
    need(len({item.get('path') for item in artifacts})==len(artifacts),'unique_edge_qualification_artifacts_required')
    for item in artifacts:
        path=Path(item['path'])
        need(path.is_relative_to(SCOPE) and path not in (ADMISSION,CANDIDATE)
             and sha(raw(path))==item.get('sha256'),'edge_qualification_artifact_changed')


def admit(candidate_sha,qualification_path,qualification_sha,qualification_producer_sha):
    need(Path(qualification_path)==SCOPE/'qualification.json','fixed_qualification_path_required')
    candidate=load(CANDIDATE);candidate_identity(candidate);qualification=load(qualification_path)
    need(sha(raw(CANDIDATE))==candidate_sha and sha(raw(qualification_path))==qualification_sha,
         'external_qualification_hash_required')
    need(sha(raw(QUALIFIER))==qualification_producer_sha,'qualification_producer_source_changed')
    validate_qualification(candidate,candidate_sha,qualification,qualification_producer_sha)
    need(candidate_matches_current(candidate),'candidate_native_reality_changed')
    new(ADMISSION,{'version':1,'kind':'cycle4-native-edge-readmission','revision':REVISION,'verified':True,
        'bridge_source_sha256':sha(Path(__file__).read_bytes()),'candidate_sha256':candidate_sha,
        'qualification_sha256':qualification_sha,'qualification_producer_sha256':qualification_producer_sha,
        'candidate':candidate,'qualification':qualification})
    return {'admission_sha256':sha(raw(ADMISSION)),'historical_files_unchanged':True,
            'full_public_mcp_acceptance':False,'native_webtransport_acceptance':False}



def candidate_identity(candidate):
    need(candidate.get('version')==1 and candidate.get('kind')=='cycle4-edge-readmission-candidate'
         and candidate.get('revision')==REVISION and candidate.get('bridge_source_sha256')==sha(Path(__file__).read_bytes())
         and candidate.get('public_identity_sha256')==PUBLIC_SHA and candidate.get('original_guard_denied') is True
         and candidate.get('original_error')=='admitted_sse_edge_changed','candidate_source_identity_required')


def _receipt(receipt_sha):
    body=raw(ADMISSION);need(re.fullmatch('[0-9a-f]{64}',receipt_sha or '') and sha(body)==receipt_sha,'external_edge_receipt_pin_required')
    value=json.loads(body)
    need(value.get('version')==1 and value.get('kind')=='cycle4-native-edge-readmission'
         and value.get('revision')==REVISION and value.get('verified') is True
         and value.get('bridge_source_sha256')==sha(Path(__file__).read_bytes()),'edge_receipt_source_identity')
    candidate_identity(value['candidate'])
    need(sha(raw(CANDIDATE))==value['candidate_sha256'] and load(CANDIDATE)==value['candidate']
         and sha(raw(SCOPE/'qualification.json'))==value['qualification_sha256']
         and load(SCOPE/'qualification.json')==value['qualification']
         and sha(raw(QUALIFIER))==value['qualification_producer_sha256'],'edge_receipt_inputs_changed')
    validate_qualification(value['candidate'],value['candidate_sha256'],value['qualification'],value['qualification_producer_sha256'])
    need(value['candidate']['historical_sources']==source_guard()
         and value['candidate']['old_admission_sha256']==sha(raw(OLD_ADMISSION))
         and value['candidate']['retained_context']==_retained_bindings(),'historical_binding_changed')
    validate_observed_snapshots(value['candidate']['before'],value['candidate']['after'])
    return value


@contextlib.contextmanager
def historical_projection():
    token=_DEPTH.set(_DEPTH.get()+1)
    try:yield
    finally:_DEPTH.reset(token)


def _refuse_mutation(*args,**kwargs):raise Refused('historical_facade_is_read_only')


def _read_only_facade(base,constructor=None,extra=None):
    attributes={'__module__':base.__module__}
    if constructor is not None:attributes['__init__']=constructor
    attributes.update(extra or {})
    for name in ('guard','boundary_guard','protected_snapshot','snapshot','safety','verify_edge_admission'):
        function=getattr(base,name,None)
        if function is None:continue
        def contextual(self,*args,_function=function,**kwargs):
            with historical_projection():return _function(self,*args,**kwargs)
        attributes[name]=contextual
    for name in ('record','prepare','run','mutate','scale','change_config','chain_record','rollback','withdraw',
                 'npm_recovery','prepare_fallback','restore_record'):
        if hasattr(base,name):attributes[name]=_refuse_mutation
    return type('ReadOnlyHistoricalController',(base,),attributes)


def _compression_controller(wrapper,receipt,bundle,context):
    original=wrapper.Controller;implementation=wrapper._implementation_module;base=wrapper._immutable_predecessor
    candidate=receipt['candidate']
    def actual(self):
        try:original._actual(self)
        except Exception as error:
            need(str(error)=='admitted_sse_edge_changed','original_edge_denial_changed')
        else:raise Refused('original_edge_denial_changed')
        need(sha(self._admission_raw)==candidate['old_admission_sha256'],'frozen_edge_admission_changed')
        snapshot,compose=implementation.native_snapshot(self,base,self._admission['after']['conf_contents'])
        validate_observed_snapshots(self._admission['after'],snapshot)
        need(snapshot==candidate['after'] and sha(compose)==candidate['compose_sha256'],'new_native_edge_changed')
        return snapshot,compose
    def edge(self):
        need(_DEPTH.get()>0,'historical_projection_context_required');actual(self)
        return copy.deepcopy(self._admission['before' if self._compat_depth else 'after']['edge'])
    def snapshot(self):
        need(_DEPTH.get()>0,'historical_projection_context_required');actual(self)
        return copy.deepcopy(self._admission['before' if self._compat_depth else 'after']),implementation.raw(base.EDGE_COMPOSE)
    facade=_read_only_facade(original,extra={'_actual':actual,'edge':edge,'native_edge_snapshot':snapshot})
    with historical_projection():return facade(str(bundle),str(bundle/'plan.json'),context)


def _injected_constructor(original,predecessor):
    need(original.__closure__ is None and 'predecessor' in original.__code__.co_names,'fixed_constructor_dependency_required')
    namespace=dict(original.__globals__);namespace['predecessor']=predecessor
    result=types.FunctionType(original.__code__,namespace,original.__name__,original.__defaults__)
    result.__kwdefaults__=original.__kwdefaults__
    return result


def load_controller(path,expected_sha,bundle,context='default',*,receipt_sha):
    path=Path(path);bundle=Path(bundle)
    need(str(path) in CHAIN and context=='default' and (expected_sha,bundle)==CHAIN[str(path)][1:],
         'fixed_historical_controller_required')
    receipt=_receipt(receipt_sha)
    def construct(selected):
        revision,wanted,root=CHAIN[str(selected)]
        if selected==WRAPPER:return _compression_controller(_wrapper(),receipt,root,context)
        module=checked_module(selected,wanted,'cycle4_checked_historical_'+revision)
        previous=WRAPPER if revision=='91c7bcb7' else next(Path(name) for name,entry in CHAIN.items() if entry[0]=='91c7bcb7')
        constructor=_injected_constructor(module.Controller.__init__,lambda value:construct(previous) if value==context else _refuse_mutation())
        facade=_read_only_facade(module.Controller,constructor)
        with historical_projection():return facade(str(root),str(root/'plan.json'),context)
    return construct(path)


def native_guard(receipt_sha):
    receipt=_receipt(receipt_sha);controller=_compression_controller(_wrapper(),receipt,CHAIN[str(WRAPPER)][2],'default')
    actual,_compose=controller._actual()
    return actual


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    prepare=sub.add_parser('candidate');prepare.add_argument('--qualification-producer-sha256',required=True)
    approve=sub.add_parser('admit');approve.add_argument('--candidate-sha256',required=True)
    approve.add_argument('--qualification',type=Path,required=True);approve.add_argument('--qualification-sha256',required=True)
    approve.add_argument('--qualification-producer-sha256',required=True)
    args=parser.parse_args();need(os.geteuid()==0,'root_required')
    if args.operation=='candidate':result=prepare_candidate(args.qualification_producer_sha256)
    else:result=admit(args.candidate_sha256,args.qualification,args.qualification_sha256,args.qualification_producer_sha256)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except Exception:
        print(json.dumps({'verified':False,'code':'edge_readmission_refused'}));sys.exit(1)
