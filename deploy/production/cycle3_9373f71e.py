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

BASE_COMMIT='9373f71e06936970b4a8dc4ca30584b9d464a5b9'
WORK='/tmp/devres-upgrade-9373f71e-20261116'
BUNDLE='/var/lib/devres-production-upgrades/9373f71e-20261116'
INSTALL='/usr/local/libexec/devres-upgrade-9373f71e'
TRANSFER='/tmp/devres-9373f71e-transfer-20261116'
OLD_WORK='/tmp/devres-upgrade-1d76fbcc-20261115'
OLD_BUNDLE='/var/lib/devres-production-upgrades/1d76fbcc-20261115'
OLD_INSTALL='/usr/local/libexec/devres-upgrade-1d76fbcc'
TARGET_REVISION='9373f71e06936970b4a8dc4ca30584b9d464a5b9'
PREVIOUS_REVISION='1d76fbcc5693efc9ca927fd05f942078f667f056'
TARGET_VERSION='0.1.0-build.9373f71e'
TARGET_IMAGE='ghcr.io/publicdata-stream/dev-resources-server@sha256:b549e2a7552f230ba10b06df4457b4201e61a7a19da245c32a3d3f11641e3718'
TARGET_PROBE='ghcr.io/publicdata-stream/dev-resources-probe@sha256:5a6a4696d24fd8d05616a03333a7fb1bbfe5f3168f1d195c6ed3d3e3553fad5a'
TARGET_SOURCE_SHA='f65738d8621fba3c7ad37029d5fb4f4a8844c2bdc91bd2f1671f99e975fd8620'
CHECKPOINT_SCOPE='physical-pg-checkpoint-9373f71e'
HISTORIES=(
    {'name':'cycle1','work':OLD_WORK,'bundle':OLD_BUNDLE,'install':OLD_INSTALL,
     'controller_sha256':'0bde00a440dcfb0eec32c22410500ea59998266a45727f0721050e63bad07fa5',
     'manifest_sha256':'f166396d51045a64b9fafda6b4d171c175460a8d5ab0bedc80bffa35f70910a9'},
    {'name':'cycle2','work':'/tmp/devres-upgrade-1d76fbcc-cycle2-20261116',
     'bundle':'/var/lib/devres-production-upgrades/1d76fbcc-cycle2-20261116',
     'install':'/usr/local/libexec/devres-upgrade-1d76fbcc-cycle2-20261116',
     'controller_sha256':'1e8efdf0f26ce12b3156fc0baa09cc154c1b52bcc51790762f1b34fc15530024',
     'manifest_sha256':'c89d1543fbefa7de5b8c8174f23fffa97da958650dd9ecacb2b4826f381c1259'})
PROBE_DIRECTORIES={
    'target':'/tmp/devres-public-probe-9373f71e-20261116',
    'fallback':'/tmp/devres-public-probe-91c7bcb7-9373f71e-20261116'}
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
# Historical aliases are injected after rebasing; neither failed cycle is rewritten.
HISTORIES=__HISTORIES__
PREVIOUS_REVISION='1d76fbcc5693efc9ca927fd05f942078f667f056'
PREVIOUS_WORK=Path(HISTORIES[-1]['work'])
PREVIOUS_BUNDLE=Path(HISTORIES[-1]['bundle'])
PREVIOUS_CONTROLLER=Path(HISTORIES[-1]['install'])/'upgrade-controller.py'
PREVIOUS_CONTROLLER_SHA=HISTORIES[-1]['controller_sha256']
PREVIOUS_MANIFEST_SHA=HISTORIES[-1]['manifest_sha256']
PREVIOUS_SPECIAL_NAMES=__PREVIOUS_SPECIAL_NAMES__
PREVIOUS_SOURCE_NAMES=__PREVIOUS_SOURCE_NAMES__

def previous_cycle(context):
    require(digest(read(PREVIOUS_CONTROLLER))==PREVIOUS_CONTROLLER_SHA,'previous_cycle_controller_changed')
    require(digest(read(PREVIOUS_WORK/'source-manifest.json'))==PREVIOUS_MANIFEST_SHA,'previous_cycle_manifest_changed')
    spec=importlib.util.spec_from_file_location('immutable_consumed_cycle2',PREVIOUS_CONTROLLER)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module.Controller(str(PREVIOUS_BUNDLE),str(PREVIOUS_BUNDLE/'plan.json'),context)

def history_metadata_rules():
    rules=[]
    for history in HISTORIES:
        work,bundle=Path(history['work']),Path(history['bundle'])
        rules.extend(((bundle,'*.json'),(bundle/'restore','*.json'),(work,'*.json'),(work,'*.log'),
            (work/'checkpoint-state','*.json'),(work/'checkpoint-state/proof-successor-v1','*.json'),
            (work/'restore-rehearsal-state','*.json')))
        for runtime in ('target','fallback'):
            root=work/runtime
            rules.extend(((root,'*.json'),(root,'*.log'),(root/'command-evidence','*/*.json'),
                (root/'command-evidence','*/*.log'),(root/'command-evidence','*/runtime.jsonl'),
                (root/'operational-proofs','*/*.json'),(root/'operational-proofs','*/*.log')))
        if history['name']=='cycle2':
            diagnostics=work/'diagnostic-state'
            rules.extend(((work/'diagnostic-drivers','*.py'),(diagnostics,'*.json'),(diagnostics,'*.log')))
            require(not any(p.is_symlink() for p in (diagnostics,*diagnostics.parents)),'previous_journal_symlink')
            if diagnostics.exists():
                for count,child in enumerate(diagnostics.iterdir(),1):
                    require(count<=10000,'previous_journal_inventory_bound')
                    if child.name.startswith(('npm-real-graph','fallback-private-graph')):
                        require(child.is_dir() and not child.is_symlink(),'previous_diagnostic_directory_required')
                        rules.extend(((child,'*.json'),(child,'*.log'),(child,'report-frame.bin')))
    return rules

def history_metadata_inventory():
    result={};count=0
    for root,_ in history_metadata_rules():
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

def history_metadata_paths():
    result=set()
    for history in HISTORIES:
        work,bundle,install=Path(history['work']),Path(history['bundle']),Path(history['install'])
        raw=read(work/'source-manifest.json')
        require(digest(raw)==history['manifest_sha256'],'previous_cycle_manifest_changed')
        manifest=json.loads(raw)
        require(set(manifest)==set(PREVIOUS_SPECIAL_NAMES)|set(PREVIOUS_SOURCE_NAMES),'previous_source_set_changed')
        result.update((install/'upgrade-controller.py',work/'source-manifest.json'))
        result.update(install/name for name in PREVIOUS_SPECIAL_NAMES)
        result.update(work/name for name in PREVIOUS_SOURCE_NAMES)
        required={bundle/name for name in ('state.json','prepared.json','plan.json','configs-paused.json',
            'configs-active.json','configs-fallback-paused.json','configs-fallback-active.json','restore/restored.json')}
        require(all(path.is_file() for path in required),'previous_cycle_history_incomplete')
        result.update(required)
    for root,pattern in history_metadata_rules():
        require(not any(path.is_symlink() for path in (root,*root.parents)),'previous_journal_symlink')
        if root.exists():
            for path in root.glob(pattern):
                result.add(path);require(len(result)<=10000,'previous_journal_inventory_bound')
    require(len(result)<=10000,'previous_journal_inventory_bound')
    return sorted(result,key=str)

def history_metadata_hashes():
    import time
    started=time.monotonic();inventory=history_metadata_inventory();paths=history_metadata_paths();result={};total=0
    for path in paths:
        require(not any(p.is_symlink() for p in (path,*path.parents)),'previous_journal_symlink')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_nlink==1
                and not before.st_mode&0o077 and before.st_size<=1024**3,'previous_private_journal_required')
            total+=before.st_size;require(total<=4*1024**3,'previous_journal_bytes_bound')
            value=hashlib.sha256()
            for block in iter(lambda:stream.read(1024**2),b''):
                value.update(block);require(time.monotonic()-started<180,'previous_journal_hash_deadline')
            after=os.fstat(stream.fileno())
            require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'previous_journal_changed')
        result[str(path)]=value.hexdigest()
    require(paths==history_metadata_paths() and inventory==history_metadata_inventory(),'previous_journal_inventory_changed')
    for history in HISTORIES:
        work,install=Path(history['work']),Path(history['install'])
        require(result[str(install/'upgrade-controller.py')]==history['controller_sha256'],'previous_cycle_controller_changed')
        for name,wanted in load(work/'source-manifest.json').items():
            path=install/name if name in PREVIOUS_SPECIAL_NAMES else work/name
            require(result[str(path)]==wanted,'previous_source_changed')
    result['cycle3:previous-journal-inventory']=digest(encoded(inventory))
    return result
'''

PRIOR_HASHES=r'''def prior_hashes(self):
        paths=[Path(PRIOR_CONTROLLER)]+[Path(PRIOR_BUNDLE)/name for name in
              ('state.json','prepared.json','plan.json','configs-active.json','configs-paused.json')]
        continuation=Path(PRIOR_BUNDLE)/'resume-v1'
        require(continuation.is_dir() and not continuation.is_symlink(),'failed_continuation_required')
        paths+=sorted(continuation.glob('*.json'))
        result={str(path):digest(read(path)) for path in paths}
        result.update(history_metadata_hashes())
        return result'''

PREPARE=r'''def prepare(self):
        require(not self.root.exists(),'bundle_already_exists')
        previous=previous_cycle(self.context)
        previous.guard();before=previous.state()
        require(before['revision']==PREVIOUS_REVISION and before['runtime']=='fallback'
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
                   'store_binding_sha256':STORE_BINDING,'captured_at':observed,'cycle':3}
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

SUBSTITUTIONS={
    OLD_WORK:WORK,OLD_BUNDLE:BUNDLE,OLD_INSTALL:INSTALL,
    PREVIOUS_REVISION:TARGET_REVISION,'0.1.0-build.1d76fbcc':TARGET_VERSION,
    'ghcr.io/publicdata-stream/dev-resources-server@sha256:7f6e3bbe220370c3db65a23c5a44062ebf44dd35ebf7ddf906cee994027cecd7':TARGET_IMAGE,
    'ghcr.io/publicdata-stream/dev-resources-probe@sha256:d8bc8f1bd14a4d8ec21b8855c6c715fd13d168eaaff4c6aacae8efd93f387244':TARGET_PROBE,
    'bf33e61badcb7c7726acee9bcab561acd0be8dfce402eb9629b056737adbd2bf':TARGET_SOURCE_SHA,
    '/tmp/devres-public-probe-1d76fbcc':PROBE_DIRECTORIES['target'],
    '/tmp/devres-public-probe-91c7bcb7':PROBE_DIRECTORIES['fallback'],
    'physical-pg-checkpoint-1d76fbcc':CHECKPOINT_SCOPE}

def rebase(body):
    source=body.decode('utf-8')
    for original,replacement in sorted(SUBSTITUTIONS.items(),key=lambda pair:-len(pair[0])):
        source=source.replace(original,replacement)
    return source

def replace_once(source,original,replacement,code):
    need(source.count(original)==1,code)
    return source.replace(original,replacement)

def transform(name,body):
    need(name in SOURCE_MAP,'unreviewed_logical_source')
    source=rebase(body)
    if name=='upgrade-controller.py':
        source=replace_node(source,method(source,'prior_hashes'),PRIOR_HASHES)
        source=replace_node(source,method(source,'prepare'),PREPARE)
        source=replace_once(source,'len(rows) >= 31','len(rows) >= 32','one_controller_rows_floor')
        source=replace_once(source,"accepted['sample_count'] >= 31","accepted['sample_count'] >= 32",'one_controller_receipt_floor')
        helpers=CONTROLLER_HELPERS.replace('__HISTORIES__',repr(HISTORIES))
        helpers=helpers.replace('__PREVIOUS_SPECIAL_NAMES__',repr(tuple(sorted(SPECIAL_NAMES))))
        helpers=helpers.replace('__PREVIOUS_SOURCE_NAMES__',repr(tuple(sorted(
            set(SOURCE_MAP)-set(SPECIAL_NAMES)|{'target-native-qualification.json','fallback-native-qualification.json'}))))
        index=source.index('\nclass Controller:');source=source[:index]+'\n'+helpers+source[index:]
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
        source=replace_once(source,"'collectors':source_flags(controller,state)[0]",
            "'collectors':source_flags(controller,{**state,'configs':'active'})[0],'observed_preimage_collectors':source_flags(controller,state)[0]",
            'one_operational_baseline_collectors_required')
    elif name=='acceptance-receipt.py':
        source=replace_once(source,'len(samples)>=31','len(samples)>=32','one_acceptance_sample_floor')
    elif name=='npm-recovery.py':
        source=replace_once(source,"POD='devres-npm-assessment-1d76fbcc'","POD='devres-npm-assessment-9373f71e'",'fixed_assessment_scope_required')
        need(source.count("'1d76fbcc-assessment'")==2,'fixed_assessment_cleanup_scope_required')
        source=source.replace("'1d76fbcc-assessment'","'9373f71e-assessment'")
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
