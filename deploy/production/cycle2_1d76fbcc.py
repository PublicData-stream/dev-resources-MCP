#!/usr/bin/env python3
"""Render one fresh cycle from immutable, reviewed first-party operational sources.

Rendering is local only. It neither installs sources nor creates credentials,
changes a cluster, publishes a release, or replays the preceding failed cycle.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

BASE_COMMIT='93426e7395fc499455a27929dd8be1fe6f84ee89'
WORK='/tmp/devres-upgrade-1d76fbcc-cycle2-20261116'
BUNDLE='/var/lib/devres-production-upgrades/1d76fbcc-cycle2-20261116'
INSTALL='/usr/local/libexec/devres-upgrade-1d76fbcc-cycle2-20261116'
TRANSFER='/tmp/devres-1d76fbcc-cycle2-transfer-20261116'
OLD_WORK='/tmp/devres-upgrade-1d76fbcc-20261115'
OLD_BUNDLE='/var/lib/devres-production-upgrades/1d76fbcc-20261115'
OLD_INSTALL='/usr/local/libexec/devres-upgrade-1d76fbcc'
PREVIOUS_CONTROLLER_SHA='0bde00a440dcfb0eec32c22410500ea59998266a45727f0721050e63bad07fa5'
PREVIOUS_MANIFEST_SHA='f166396d51045a64b9fafda6b4d171c175460a8d5ab0bedc80bffa35f70910a9'
PROBE_DIRECTORIES={
    'target':'/tmp/devres-public-probe-1d76fbcc-cycle2-20261116',
    'fallback':'/tmp/devres-public-probe-91c7bcb7-cycle2-20261116'}
SPECIAL_NAMES={
    'upgrade-controller.py':'deploy/production/upgrade_1d76fbcc.py',
    'physical-checkpoint.py':'deploy/production/checkpoint_1d76fbcc.py',
    'restore-controller.py':'deploy/production/restore_1d76fbcc.py',
    'restore-rehearsal.py':'deploy/production/rehearse_restore_1d76fbcc.py',
    'npm-recovery.py':'deploy/production/npm_recovery_1d76fbcc.py',
    'safety-supervisor.py':'deploy/production/supervisor_1d76fbcc.py'}
ACCEPTANCE_NAMES=('acceptance_common.py','acceptance-receipt.py','compressed-probe.py','deploy.py',
    'observation-loop.py','operational-proof.py','phase-driver.py','process-launch.py','process-watch.py',
    'public-matrix.py','runner.py','sitecustomize.py','store-claim.py','target-private-acceptance.py')
SOURCE_MAP={**SPECIAL_NAMES,
    **{name:'deploy/production/acceptance_1d76fbcc/'+name for name in ACCEPTANCE_NAMES},
    **{name:name for name in ('deploy/diagnostics/__init__.py','deploy/diagnostics/evidence.py','deploy/diagnostics/runner.py')},
    'mcp_smoke.py':'scripts/mcp_smoke.py'}
REPOSITORY=Path(__file__).resolve().parents[2]

class RenderError(RuntimeError):pass

def need(value,code):
    if not value:raise RenderError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(value):return hashlib.sha256(value).hexdigest()

def base_source(path):
    need(path in SOURCE_MAP.values(),'unreviewed_source_path')
    result=subprocess.run(['git','show',BASE_COMMIT+':'+path],cwd=REPOSITORY,capture_output=True,timeout=30)
    need(result.returncode==0 and len(result.stdout)<=4*1024**2,'immutable_base_source_unavailable')
    return result.stdout

def replace_node(source,node,replacement):
    lines=source.splitlines(keepends=True)
    start=sum(len(line) for line in lines[:node.lineno-1])+node.col_offset
    end=sum(len(line) for line in lines[:node.end_lineno-1])+node.end_col_offset
    return source[:start]+replacement+source[end:]

def method(source,name):
    cls=next(node for node in ast.parse(source).body if isinstance(node,ast.ClassDef) and node.name=='Controller')
    values=[node for node in cls.body if isinstance(node,ast.FunctionDef) and node.name==name]
    need(len(values)==1,'one_reviewed_controller_method_required')
    return values[0]

CONTROLLER_HELPERS=r'''
# These immutable aliases identify the consumed first cycle. They are never rebased.
PREVIOUS_WORK=Path('/tmp/devres-upgrade-1d76fbcc-20261115')
PREVIOUS_BUNDLE=Path('/var/lib/devres-production-upgrades/1d76fbcc-20261115')
PREVIOUS_CONTROLLER=Path('/usr/local/libexec/devres-upgrade-1d76fbcc/upgrade-controller.py')
PREVIOUS_CONTROLLER_SHA='0bde00a440dcfb0eec32c22410500ea59998266a45727f0721050e63bad07fa5'
PREVIOUS_MANIFEST_SHA='f166396d51045a64b9fafda6b4d171c175460a8d5ab0bedc80bffa35f70910a9'
PREVIOUS_SPECIAL_NAMES=__PREVIOUS_SPECIAL_NAMES__
PREVIOUS_SOURCE_NAMES=__PREVIOUS_SOURCE_NAMES__

def previous_cycle(context):
    require(digest(read(PREVIOUS_CONTROLLER))==PREVIOUS_CONTROLLER_SHA,'previous_cycle_controller_changed')
    require(digest(read(PREVIOUS_WORK/'source-manifest.json'))==PREVIOUS_MANIFEST_SHA,'previous_cycle_manifest_changed')
    spec=importlib.util.spec_from_file_location('immutable_consumed_first_cycle',PREVIOUS_CONTROLLER)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module.Controller(str(PREVIOUS_BUNDLE),str(PREVIOUS_BUNDLE/'plan.json'),context)

def cycle2_metadata_rules():
    # Only operator journal prefixes are enumerated. Runtime, private keys,
    # archive bodies and mutable Git/package cache trees are never traversed.
    rules=[(PREVIOUS_BUNDLE,'*.json'),(PREVIOUS_BUNDLE/'restore','*.json'),
           (PREVIOUS_WORK,'*.json'),(PREVIOUS_WORK,'*.log'),(PREVIOUS_WORK/'checkpoint-state','*.json'),
           (PREVIOUS_WORK/'checkpoint-state/proof-successor-v1','*.json'),
           (PREVIOUS_WORK/'restore-rehearsal-state','*.json')]
    for runtime in ('target','fallback'):
        root=PREVIOUS_WORK/runtime
        rules.extend(((root,'*.json'),(root,'*.log'),(root/'command-evidence','*/*.json'),
                      (root/'command-evidence','*/*.log'),(root/'command-evidence','*/runtime.jsonl'),
                      (root/'operational-proofs','*/*.json'),(root/'operational-proofs','*/*.log')))
    return rules

def cycle2_metadata_inventory():
    result={};count=0
    for root,_ in cycle2_metadata_rules():
        if str(root) in result:continue
        require(not any(path.is_symlink() for path in (root,*root.parents)),'previous_journal_symlink')
        names=[]
        if root.exists():
            require(root.is_dir(),'previous_journal_directory_required')
            with os.scandir(root) as entries:
                for entry in entries:
                    count+=1;require(count<=10000,'previous_journal_inventory_bound')
                    mode=entry.stat(follow_symlinks=False).st_mode
                    require(not stat.S_ISLNK(mode),'previous_journal_symlink')
                    names.append([entry.name,'directory' if stat.S_ISDIR(mode) else 'file'])
        result[str(root)]={'exists':root.exists(),'entries':sorted(names)}
    return result

def cycle2_metadata_paths():
    manifest_path=PREVIOUS_WORK/'source-manifest.json'
    raw=read(manifest_path)
    require(digest(raw)==PREVIOUS_MANIFEST_SHA,'previous_cycle_manifest_changed')
    manifest=json.loads(raw)
    require(set(manifest)==set(PREVIOUS_SPECIAL_NAMES)|set(PREVIOUS_SOURCE_NAMES),'previous_source_set_changed')
    result={PREVIOUS_CONTROLLER,manifest_path}
    result.update(PREVIOUS_CONTROLLER.parent/name for name in PREVIOUS_SPECIAL_NAMES)
    result.update(PREVIOUS_WORK/name for name in PREVIOUS_SOURCE_NAMES)
    for root,pattern in cycle2_metadata_rules():
        require(not any(path.is_symlink() for path in (root,*root.parents)),'previous_journal_symlink')
        if root.exists():
            for path in root.glob(pattern):
                result.add(path);require(len(result)<=10000,'previous_journal_inventory_bound')
    require(len(result)<=10000,'previous_journal_inventory_bound')
    required={PREVIOUS_BUNDLE/name for name in ('state.json','prepared.json','plan.json','configs-paused.json',
              'configs-active.json','configs-fallback-paused.json','configs-fallback-active.json')}
    required.add(PREVIOUS_BUNDLE/'restore/restored.json')
    require(required<=result,'previous_cycle_history_incomplete')
    return sorted(result,key=str)

def cycle2_metadata_hashes():
    import time
    started=time.monotonic();inventory=cycle2_metadata_inventory();paths=cycle2_metadata_paths();result={};total=0
    for path in paths:
        require(not any(p.is_symlink() for p in (path,*path.parents)),'previous_journal_symlink')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_nlink==1
                    and not before.st_mode&0o077 and before.st_size<=1024**3,'previous_private_journal_required')
            total+=before.st_size
            require(total<=4*1024**3,'previous_journal_bytes_bound')
            value=hashlib.sha256()
            for block in iter(lambda:stream.read(1024**2),b''):
                value.update(block)
                require(time.monotonic()-started<180,'previous_journal_hash_deadline')
            after=os.fstat(stream.fileno())
            require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
                    (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'previous_journal_changed')
        result[str(path)]=value.hexdigest()
    require(paths==cycle2_metadata_paths() and inventory==cycle2_metadata_inventory(),'previous_journal_inventory_changed')
    manifest=load(PREVIOUS_WORK/'source-manifest.json')
    for name,wanted in manifest.items():
        path=PREVIOUS_CONTROLLER.parent/name if name in PREVIOUS_SPECIAL_NAMES else PREVIOUS_WORK/name
        require(result[str(path)]==wanted,'previous_source_changed')
    result['cycle2:previous-journal-inventory']=digest(encoded(inventory))
    return result
'''

PRIOR_HASHES=r'''def prior_hashes(self):
        paths=[Path(PRIOR_CONTROLLER)]+[Path(PRIOR_BUNDLE)/name for name in
              ('state.json','prepared.json','plan.json','configs-active.json','configs-paused.json')]
        continuation=Path(PRIOR_BUNDLE)/'resume-v1'
        require(continuation.is_dir() and not continuation.is_symlink(),'failed_continuation_required')
        paths+=sorted(continuation.glob('*.json'))
        result={str(path):digest(read(path)) for path in paths}
        result.update(cycle2_metadata_hashes())
        return result'''

PREPARE=r'''def prepare(self):
        require(not self.root.exists(),'bundle_already_exists')
        previous=previous_cycle(self.context)
        previous.guard();before=previous.state()
        require(before['revision']==REVISION and before['runtime']=='fallback'
                and before['phase']=='withdrawn' and before['configs']=='paused'
                and before['replicas']=={'postgres':1,'writer':0,'backend':0}
                and set(before['pods'])=={'postgres'},'withdrawn_previous_cycle_required')
        snap=self.snapshot()
        require(snap==previous.snapshot() and snap['pods']==before['pods'],'previous_cycle_runtime_changed')
        self.storage_guard(18,owner=False)
        observed=stamp()
        original=read(PREVIOUS_BUNDLE/'configs-fallback-active.json')
        old_prepared=load(PREVIOUS_BUNDLE/'prepared.json')
        require(digest(original)==old_prepared['config_hashes']['fallback-active'],'previous_desired_active_config_changed')
        desired=json.loads(original)
        require(set(desired)==set(ROLES),'desired_runtime_role_set')
        variants={key:{} for key in ('paused','active','fallback-paused','fallback-active')}
        deployments={}
        for role in ('postgres','writer','backend'):
            obj=self.get('deployment',role);projection,image=deployment_projection(obj)
            require(image==(PG_IMAGE if role=='postgres' else OLD_IMAGE),'initial_image')
            deployments[role]={'projection':projection,'manifest':obj}
        for role in ROLES:
            for variant in variants:
                text=configuration(desired[role],variant.endswith('active'))
                if variant.startswith('fallback-'):text=text.replace(SOURCE_URL,fallback_source_url())
                variants[variant][role]=text
        artifacts=self.prior_hashes()
        previous.guard()
        require(self.snapshot()==snap and self.prior_hashes()==artifacts,'prepare_runtime_changed')
        require((utc_now()-instant(observed)).total_seconds()<=300,'inventory_stale')
        self.plan={'version':1,'revision':REVISION,'context':self.context,'target_image':IMAGE,
                   'store_binding_sha256':STORE_BINDING,'captured_at':observed,'cycle':2}
        self.plan_raw=encoded(self.plan)
        prepared={**{k:v for k,v in snap.items() if k not in ('deployments','pods')},
            'version':1,'revision':REVISION,'at':observed,'deployments':deployments,'old_pods':snap['pods'],
            'store_binding_sha256':STORE_BINDING,'prior_artifacts':artifacts,
            'desired_active_source_sha256':digest(original),'previous_cycle_source_sha256':PREVIOUS_CONTROLLER_SHA,
            'config_hashes':{k:digest(encoded(v)) for k,v in variants.items()}}
        self.root.mkdir(mode=0o700);syncdir(self.root.parent)
        save(self.root/'plan.json',self.plan_raw)
        for variant,value in variants.items():save(self.root/('configs-'+variant+'.json'),value)
        save(self.root/'prepared.json',prepared)
        save(self.root/'state.json',{'version':1,'revision':REVISION,'phase':'prepared','runtime':'target',
            'source_sha256':digest(Path(__file__).read_bytes()),'plan_sha256':digest(self.plan_raw),
            'prepared_sha256':digest(encoded(prepared)),'configs':'old','pods':snap['pods'],
            'images':{r:(PG_IMAGE if r=='postgres' else OLD_IMAGE) for r in ('postgres','writer','backend')},
            'replicas':{'postgres':1,'writer':0,'backend':0}})
        self.guard()'''

def transform(name,body):
    source=body.decode('utf-8')
    mappings={OLD_WORK:WORK,OLD_BUNDLE:BUNDLE,OLD_INSTALL:INSTALL,
              '/tmp/devres-public-probe-1d76fbcc':PROBE_DIRECTORIES['target'],
              '/tmp/devres-public-probe-91c7bcb7':PROBE_DIRECTORIES['fallback']}
    for original,replacement in sorted(mappings.items(),key=lambda pair:-len(pair[0])):
        source=source.replace(original,replacement)
    if name=='upgrade-controller.py':
        source=replace_node(source,method(source,'prior_hashes'),PRIOR_HASHES)
        source=replace_node(source,method(source,'prepare'),PREPARE)
        index=source.index('\nclass Controller:')
        helpers=CONTROLLER_HELPERS.replace('__PREVIOUS_SPECIAL_NAMES__',repr(tuple(sorted(SPECIAL_NAMES))))
        helpers=helpers.replace('__PREVIOUS_SOURCE_NAMES__',repr(tuple(sorted(
            set(SOURCE_MAP)-set(SPECIAL_NAMES)|{'target-native-qualification.json','fallback-native-qualification.json'}))))
        source=source[:index]+'\n'+helpers+source[index:]
    elif name=='physical-checkpoint.py':
        tree=ast.parse(source)
        functions=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='writer_config']
        need(len(functions)==1,'one_checkpoint_writer_config_required')
        fields=[node for node in ast.walk(functions[0]) if isinstance(node,ast.Tuple) and len(node.elts)==3
                and isinstance(node.elts[0],ast.Constant) and node.elts[0].value=='storage.s3'
                and isinstance(node.elts[1],ast.Constant) and node.elts[1].value=='cache_max_bytes']
        need(len(fields)==1,'one_writer_cache_ceiling_override_required')
        source=replace_node(source,fields[0],"('storage.s3', 'cache_max_bytes', before['storage']['s3']['cache_max_bytes'])")
    elif name=='operational-proof.py':
        original="'collectors':source_flags(controller,state)[0]"
        need(source.count(original)==1,'one_operational_baseline_collectors_required')
        source=source.replace(original,"'collectors':source_flags(controller,{**state,'configs':'active'})[0],"
                              "'observed_preimage_collectors':source_flags(controller,state)[0]")
    elif name=='npm-recovery.py':
        need(source.count("POD='devres-npm-assessment-1d76fbcc'")==1
             and source.count("'1d76fbcc-assessment'")==2,'fixed_assessment_scope_required')
        source=source.replace("POD='devres-npm-assessment-1d76fbcc'","POD='devres-npm-assessment-1d76fbcc-cycle2'")
        source=source.replace("'1d76fbcc-assessment'","'1d76fbcc-cycle2-assessment'")
    ast.parse(source,filename=name)
    return source.encode()

def render(output_dir):
    output=Path(output_dir)
    need(output.is_absolute() and Path('/tmp') in output.parents and '..' not in output.parts
         and not any(path.is_symlink() for path in (output,*output.parents)),'owned_temporary_output_required')
    need(not output.exists(),'fresh_render_directory_required')
    output.mkdir(mode=0o700,parents=True)
    result={};metadata={}
    for name,path in sorted(SOURCE_MAP.items()):
        original=base_source(path);body=transform(name,original)
        destination=output/name;destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        remote=str(Path(INSTALL if name in SPECIAL_NAMES else WORK)/name)
        value={'source':path,'source_sha256':digest(original),'sha256':digest(body),'remote':remote}
        metadata[name]=value;result[name]={**value,'local':str(destination)}
    document={'version':1,'base_commit':BASE_COMMIT,'renderer_sha256':digest(Path(__file__).read_bytes()),
              'scope':{'work':WORK,'bundle':BUNDLE,'install':INSTALL,'transfer':TRANSFER,
                       'probe_directories':PROBE_DIRECTORIES},'files':metadata}
    path=output/'render-manifest.json'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(encoded(document));stream.flush();os.fsync(stream.fileno())
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=render(args.output)
    print(json.dumps({'rendered':True,'files':len(result),'base_commit':BASE_COMMIT,
                      'render_manifest_sha256':digest((args.output/'render-manifest.json').read_bytes())}))

if __name__=='__main__':main()
