#!/usr/bin/env python3
"""Retire exact completed C4/C5 disposable proof copies.

Inspect is metadata-only for copy bodies; runtime qualification additionally reads
Docker/firewall metadata. Apply needs an externally pinned exact preview+approval,
consumes a fresh phase journal once, and preserves every selected root inode.
No checkpoint, rehearsal, production restore, SQL, HTTP or object-store operation.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
import datetime,errno,fcntl,hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
MAX_ENTRIES=1_500_000
MAX_BYTES=1024**3
MAX_METADATA_BYTES=4*1024**3
SPECIAL={'upgrade-controller.py','physical-checkpoint.py','restore-controller.py',
         'restore-rehearsal.py','npm-recovery.py','safety-supervisor.py'}
class Refused(RuntimeError):pass


def need(value,code):
    if not value:raise Refused(code)

def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def sha(body):return hashlib.sha256(body).hexdigest()

def stable_stat(value):
    return tuple(getattr(value,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid',
        'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def safe_path(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),
         'symlink_or_noncanonical_path')
    return path

def identity(path):
    value=os.stat(path,follow_symlinks=False)
    need(stat.S_ISDIR(value.st_mode),'directory_required')
    return {'dev':value.st_dev,'ino':value.st_ino,'uid':value.st_uid,'gid':value.st_gid,
            'mode':stat.S_IMODE(value.st_mode)}

def file_record(path,private=True,maximum=MAX_BYTES):
    safe_path(path)
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maximum,
             'bounded_regular_metadata_required')
        if private:need(before.st_uid==os.geteuid() and not before.st_mode&0o077,'private_metadata_required')
        digest=hashlib.file_digest(stream,'sha256').hexdigest();after=os.fstat(stream.fileno())
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
             (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'metadata_changed')
    return {'sha256':digest,'dev':before.st_dev,'ino':before.st_ino,'size':before.st_size,
            'uid':before.st_uid,'gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode),
            'mtime_ns':before.st_mtime_ns,'ctime_ns':before.st_ctime_ns}

def load(path):
    path=safe_path(path);descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=MAX_BYTES
             and before.st_uid==os.geteuid() and not before.st_mode&0o077,'private_bounded_metadata_required')
        body=stream.read(before.st_size+1);after=os.fstat(stream.fileno())
        need(len(body)==before.st_size and stable_stat(before)==stable_stat(after)
             and stable_stat(path.lstat())==stable_stat(after),'metadata_changed')
    value=json.loads(body)
    need(type(value) is dict,'metadata_object_required')
    return value

def new(path,value):
    safe_path(path);parent=path.parent.stat()
    need(parent.st_uid==os.geteuid() and not parent.st_mode&0o077,'private_output_parent_required')
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(encode(value));stream.flush();os.fsync(stream.fileno())
    sync(path.parent)

def sync(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)

def row(path,relative,device):
    value=os.stat(path,follow_symlinks=False)
    need(value.st_dev==device,'device_crossing_refused')
    kind='directory' if stat.S_ISDIR(value.st_mode) else 'file' if stat.S_ISREG(value.st_mode) else 'link' if stat.S_ISLNK(value.st_mode) else None
    need(kind is not None,'special_file_refused')
    result={'path':relative,'kind':kind,'dev':value.st_dev,'ino':value.st_ino,'uid':value.st_uid,
        'gid':value.st_gid,'mode':stat.S_IMODE(value.st_mode),'size':value.st_size,
        'links':value.st_nlink,'blocks':value.st_blocks,'mtime_ns':value.st_mtime_ns,'ctime_ns':value.st_ctime_ns}
    if kind=='link':
        need(value.st_nlink==1,'hardlinked_symlink_refused')
        result['target']=os.readlink(path)
    return result

def tree(path):
    safe_path(path);device=path.stat().st_dev;rows=[row(path,'',device)];started=time.monotonic()
    # fwalk uses nofollow directory descriptors and does not descend symlinks.
    for directory,children,files,fd in os.fwalk(path,follow_symlinks=False):
        children.sort()
        if Path(directory)==path:
            value=os.fstat(fd);need((value.st_dev,value.st_ino)==(rows[0]['dev'],rows[0]['ino']),'tree_root_changed')
        for name in sorted(children+files):
            value=os.stat(name,dir_fd=fd,follow_symlinks=False)
            need(value.st_dev==device,'device_crossing_refused')
            kind='directory' if stat.S_ISDIR(value.st_mode) else 'file' if stat.S_ISREG(value.st_mode) else 'link' if stat.S_ISLNK(value.st_mode) else None
            need(kind is not None,'special_file_refused')
            item={'path':str((Path(directory)/name).relative_to(path)),'kind':kind,'dev':value.st_dev,'ino':value.st_ino,
                'uid':value.st_uid,'gid':value.st_gid,'mode':stat.S_IMODE(value.st_mode),'size':value.st_size,
                'links':value.st_nlink,'blocks':value.st_blocks,'mtime_ns':value.st_mtime_ns,'ctime_ns':value.st_ctime_ns}
            if kind=='link':
                need(value.st_nlink==1,'hardlinked_symlink_refused');item['target']=os.readlink(name,dir_fd=fd)
            rows.append(item)
            need(len(rows)<=MAX_ENTRIES and time.monotonic()-started<1800,'tree_scan_bound')
    need(row(path,'',device)==rows[0],'tree_root_changed')
    return rows

def under(path,parent):
    return path==parent or path.is_relative_to(parent)

def unescape_mount(value):
    return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),value)

def mount_rows(body):
    rows=[]
    for line in body.splitlines():
        fields=line.split();need(len(fields)>=10 and '-' in fields,'mountinfo_invalid')
        separator=fields.index('-')
        need(separator>=6 and len(fields)==separator+4,'mountinfo_invalid')
        rows.append({'device':fields[2],'root':unescape_mount(fields[3]),'target':unescape_mount(fields[4]),
            'id':int(fields[0]),'parent':int(fields[1]),'options':fields[5].split(','),
            'propagation':fields[6:separator],'filesystem':fields[separator+1],
            'source':unescape_mount(fields[separator+2]),'super_options':fields[separator+3].split(',')})
    return rows

def path_used(text,roots):
    # Paths from kernel/API metadata are data; this never resolves their links.
    if text.endswith(' (deleted)'):text=text[:-10]
    if not text.startswith('/'):return False
    path=Path(text)
    return any(under(path,root) for root in roots)

def command(arguments,maximum=32*1024**2):
    result=subprocess.run(arguments,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,timeout=120,check=False)
    need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=maximum,'system_inspection_incomplete')
    return result.stdout


def canonical_iptables_save(body):
    """Normalize only admitted v1.8.11 nf_tables wallclock banners."""
    generated=(b'# Generated by iptables-save v1.8.11 (nf_tables) on ',
               b'# Generated by ip6tables-save v1.8.11 (nf_tables) on ')
    completed=b'# Completed on '
    months=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')
    weekdays=('Mon','Tue','Wed','Thu','Fri','Sat','Sun')
    result=[]
    for line in body.split(b'\n'):
        if line.lstrip().startswith((b'# Generated',b'# Completed')):
            prefix=next((p for p in generated if line.startswith(p)),None)
            if prefix is None and line.startswith(completed):prefix=completed
            need(prefix is not None,'unknown_iptables_banner')
            match=re.fullmatch(rb'(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( [1-9]|[12][0-9]|3[01]) ([0-2][0-9]):([0-5][0-9]):([0-5][0-9]) ([0-9]{4})',line[len(prefix):])
            need(match is not None,'malformed_iptables_banner')
            weekday,month,day,hour,minute,second,year=(part.decode('ascii') for part in match.groups())
            try:value=datetime.datetime(int(year),months.index(month)+1,int(day),int(hour),int(minute),int(second))
            except ValueError:raise Refused('malformed_iptables_banner') from None
            need(weekdays[value.weekday()]==weekday,'malformed_iptables_banner')
            line=prefix+b'<wallclock>'
        result.append(line)
    return b'\n'.join(result)


REVISION='3dae7d914baa9379abc402c5a3bcf311e0db01bf'
C4_SOURCES={'physical-checkpoint.py':'4c99e4a14ab1ff696528236844bc34f94ea0e3a20b10f64980b6d111a4329723',
 'restore-controller.py':'eff09c70056934d759c90d819a223bb9341bd13847bd5d4c0b06549cbb908578',
 'restore-rehearsal.py':'247f4584df370ad776cf39b9012866ead0276ed1516517b35064fc9648acf2a4'}
C4_RESTORED='bd466f56be125f7f15aed1fc3b55a6a52a54cfdc8cfe37b5fb6a57364961b555'


@dataclass(frozen=True)
class Scope:
    phase:str
    bundle:Path
    work:Path
    install:Path
    journal:Path


def production_scope(phase):
    need(phase in ('cycle4-completed','cycle5-checkpoint-proof'),'fixed_phase_required')
    suffix='3dae7d91-20261117' if phase=='cycle4-completed' else '3dae7d91-cycle5-20261118'
    install='devres-upgrade-3dae7d91' if phase=='cycle4-completed' else 'devres-upgrade-3dae7d91-cycle5'
    return Scope(phase,Path('/var/lib/devres-production-upgrades')/suffix,
        Path('/tmp')/('devres-upgrade-'+suffix),Path('/usr/local/libexec')/install,
        Path('/var/lib/devres-production-reclaim/3dae7d91-cycle5-20261118')/phase)


def directory_record(path):
    safe_path(path);value=identity(path)
    need(value['uid'] in (os.geteuid(),70,65532),'unexpected_directory_owner')
    return value


def process_identity(path):
    head=(path/'stat').read_text();fields=head.rsplit(')',1)[1].split()
    need(head.startswith(path.name+' (') and len(fields)>=20,'process_stat_invalid')
    status=(path/'status').read_text().splitlines()
    uid=next(line for line in status if line.startswith('Uid:')).split()[1:]
    return {'pid':int(path.name),'start_ticks':fields[19],'uid':uid,
        'exe':os.readlink(path/'exe'),'cwd':os.readlink(path/'cwd'),
        'root':os.readlink(path/'root'),'cgroup':(path/'cgroup').read_text().strip()}


def environment(roots,aliases,tokens,inodes,*,proc=Path('/proc'),runtime=False):
    """Known whole-host/owned-work views only; unknown mount aliases refuse."""
    proc=Path(proc);namespaces={};processes=[];handles=set();started=time.monotonic()
    for path in sorted(proc.iterdir(),key=lambda p:p.name):
        if not path.name.isdecimal():continue
        need(len(processes)<100000 and time.monotonic()-started<180,'process_inventory_bound')
        try:
            ns=os.readlink(path/'ns/mnt');processes.append((path,ns))
            if ns not in namespaces:
                body=(path/'mountinfo').read_bytes()
                namespaces[ns]={'sha256':sha(body),'mounts':mount_rows(body.decode()),'members':[]}
            namespaces[ns]['members'].append(path)
        except FileNotFoundError:continue
        except PermissionError:raise Refused('process_inventory_incomplete') from None
    current=os.readlink(proc/'self/ns/mnt');need(current in namespaces,'self_namespace_missing')
    physical=[]
    for root in roots:
        s=root.stat();device=str(os.major(s.st_dev))+':'+str(os.minor(s.st_dev))
        matches=[m for m in namespaces[current]['mounts'] if m['device']==device and under(root,Path(m['target']))]
        need(matches,'root_mapping_missing');base=max(matches,key=lambda m:len(Path(m['target']).parts))
        physical.append((device,Path(base['root'])/root.relative_to(base['target'])))
    exposures={};geometry=[];snapshots={}
    for ns,data in namespaces.items():
        visible=set(roots+aliases);hostfs=False
        for mount in data['mounts']:
            target=Path(mount['target']);mounted=Path(mount['root'])
            need(not any(under(target,r) for r in visible),'leaf_or_descendant_mount')
            for device,physical_root in physical:
                if mount['device']!=device:continue
                need(not under(mounted,physical_root),'leaf_filesystem_submount')
                if not under(physical_root,mounted):continue
                view=target/physical_root.relative_to(mounted)
                if view not in visible:
                    prefix=Path('/var/lib/snapd/hostfs')
                    need(under(view,prefix) and Path('/')/view.relative_to(prefix) in set(roots+aliases),
                         'unknown_ancestor_alias')
                    hostfs=True;visible.add(view)
                geometry.append({'namespace':ns,'mount':mount,'view':str(view)})
        if hostfs:
            need(len(data['members'])==1,'hostfs_namespace_membership_changed')
            member=data['members'][0];before=process_identity(member)
            need(before['uid']==['0']*4 and before['root']=='/'
                 and re.fullmatch('/snap/canonical-livepatch/[0-9]+/canonical-livepatchd',before['exe'])
                 and re.fullmatch('/var/snap/canonical-livepatch/[0-9]+',before['cwd'])
                 and before['cgroup']=='0::/system.slice/snap.canonical-livepatch.canonical-livepatchd.service',
                 'hostfs_process_identity_unknown')
            executable=file_record(Path(before['exe']),private=False,maximum=128*1024**2)
            need(executable['uid']==0 and not executable['mode']&0o022,'hostfs_executable_authority')
            snapshots[ns]={'process':before,'executable':executable}
        exposures[ns]=visible
    for path,ns in processes:
        try:
            need(os.readlink(path/'ns/mnt')==ns,'process_namespace_drift')
            args=(path/'cmdline').read_bytes().split(b'\0')
            need(not any(Path(arg.decode(errors='replace')).name in SPECIAL for arg in args if arg),
                 'producer_process_active')
            references=[path/'cwd',path/'root',path/'exe',*list((path/'fd').iterdir())]
            for reference in references:
                try:
                    target=os.readlink(reference)
                    if re.fullmatch(r'mnt:\[[0-9]+\]',target):handles.add(target)
                    need(not path_used(target,exposures[ns]),'active_copy_reference')
                    value=reference.stat()
                    need((value.st_dev,value.st_ino) not in inodes,'active_copy_inode')
                except (FileNotFoundError,ProcessLookupError):continue
                except OSError as error:
                    if error.errno not in (errno.ENOENT,errno.ESRCH,errno.EINVAL):raise Refused('fd_inventory_incomplete') from None
            for line in (path/'maps').read_text().splitlines():
                fields=line.split(None,5)
                need(len(fields)!=6 or not path_used(fields[5],exposures[ns]),'active_copy_mapping')
                if len(fields)>=5:
                    major,minor=(int(x,16) for x in fields[3].split(':'))
                    need((os.makedev(major,minor),int(fields[4])) not in inodes,'active_copy_mapped_inode')
            need(os.readlink(path/'ns/mnt')==ns,'process_namespace_drift')
        except (FileNotFoundError,ProcessLookupError):continue
        except PermissionError:raise Refused('process_inventory_incomplete') from None
    need(not handles-set(namespaces),'unknown_held_mount_namespace')
    docker=[];firewall=[]
    if runtime:
        need(not os.environ.get('DOCKER_CONTEXT') and not os.environ.get('DOCKER_HOST'),
             'ambient_docker_endpoint_refused')
        sockets={Path('/var/run/docker.sock'),*Path('/run/user').glob('*/docker.sock')}
        for socket in sorted(sockets,key=str):
            if not socket.exists():continue
            prefix=['docker','--host','unix://'+str(socket)]
            ids=command(prefix+['ps','-aq']).decode().split();need(len(ids)<=10000,'docker_inventory_bound')
            containers=json.loads(command(prefix+['inspect',*ids])) if ids else []
            ids=command(prefix+['network','ls','-q']).decode().split();need(len(ids)<=10000,'docker_inventory_bound')
            networks=json.loads(command(prefix+['network','inspect',*ids])) if ids else []
            for item in containers:
                labels=item.get('Config',{}).get('Labels') or {}
                need(not any(t in labels.values() for t in tokens),'owned_container_remaining')
                for mount in item.get('Mounts',[]):
                    if mount.get('Type')=='bind':
                        source=Path(mount['Source'])
                        need(not any(under(source,r) or under(r,source) for r in set().union(*exposures.values())),
                             'docker_copy_bind_remaining')
            for item in networks:
                labels=item.get('Labels') or {}
                need(not any(t in labels.values() or t in item.get('Name','') for t in tokens),'owned_network_remaining')
            docker.append({'socket':str(socket),'sha256':sha(encode({'containers':containers,'networks':networks}))})
        for arguments in (['nft','--stateless','--json','list','ruleset'],['iptables-save'],['ip6tables-save']):
            body=command(arguments)
            need(not any(t.encode() in body for t in tokens),'owned_firewall_remaining')
            need(not any(str(r).encode() in body for r in set().union(*exposures.values())),'copy_firewall_reference')
            firewall.append(sha(canonical_iptables_save(body) if arguments[0] in ('iptables-save','ip6tables-save') else body))
    # Bookend existing namespaces and reject any newly observed namespace.
    checked=set()
    for path in proc.iterdir():
        if not path.name.isdecimal():continue
        try:
            ns=os.readlink(path/'ns/mnt');need(ns in namespaces,'new_mount_namespace')
            if ns not in checked:
                need(sha((path/'mountinfo').read_bytes())==namespaces[ns]['sha256'],'mount_table_drift');checked.add(ns)
        except FileNotFoundError:continue
    for ns,value in snapshots.items():
        need(process_identity(proc/str(value['process']['pid']))==value['process']
             and file_record(Path(value['process']['exe']),private=False,maximum=128*1024**2)==value['executable'],
             'hostfs_process_drift')
    return {'runtime_qualified':runtime,'mounts':geometry,'hostfs':snapshots,
        'namespaces':{ns:data['sha256'] for ns,data in namespaces.items()},
        'docker':docker,'firewall':firewall,'boot_id':(proc/'sys/kernel/random/boot_id').read_text().strip()}


class Engine:
    def __init__(self,scope,guard=environment):self.scope=scope;self.guard=guard

    def receipts(self):
        scope=self.scope;cp=scope.bundle/'checkpoint-volume';rr=scope.bundle/'restore-rehearsal-volume'
        for p in (scope.bundle,scope.work,scope.install):
            value=directory_record(p);need(value['uid']==os.geteuid() and not value['mode']&0o077,'private_scope_required')
        cp_alias=scope.work/'checkpoint-state'
        need(directory_record(cp_alias)==directory_record(cp),'checkpoint_receipt_alias_identity')
        owner=load(cp/'owner.json');completed=load(cp/'completed.json');checkpoint=load(cp/'checkpoint-completed.json')
        cleanup=load(cp/'clone-cleanup-completed.json');proof=load(cp/'clone-proof-result.json');intent=load(cp/'proof-intent.json')
        token=owner.get('token');need(re.fullmatch('[0-9a-f]{24}',token or ''),'checkpoint_owner_token')
        source=file_record(scope.install/'physical-checkpoint.py')['sha256']
        need(owner['pins']['source_sha256']==source and completed['pins']==owner['pins'] and checkpoint['pins']==owner['pins'],
             'checkpoint_owner_source_chain')
        need(completed.get('revision')==REVISION and completed.get('schema')==18
             and all(completed.get(k) is True for k in ('old_clone_verified','fallback_writer_verified','original_s3_retained'))
             and completed.get('independent_s3_backup') is False,'completed_checkpoint_required')
        need(intent['token']==token and all(cleanup.get(k) is True for k in
             ('all_owned_containers_removed','owned_network_removed','physical_checkpoint_retained'))
             and proof.get('isolated_clone_only') is True and proof.get('no_production_mount') is True
             and proof.get('provider_source_requests')==0,'completed_owned_clone_cleanup_required')
        need(completed['checkpoint_receipt_sha256']==file_record(cp/'checkpoint-completed.json')['sha256']
             and completed['clone_proof_sha256']==file_record(cp/'clone-proof-result.json')['sha256']
             and completed['cache_baselines_sha256']==file_record(cp/'cache-baselines.json')['sha256'],
             'checkpoint_proof_hash_chain')
        roots=[cp/'pg-clone',cp/'rehearsal/cache',cp/'rehearsal/writer-cache'];tokens=[token]
        protected=[cp/'pg-checkpoint',cp/'fallback-cache/serving',cp/'fallback-cache/writer']
        if scope.phase=='cycle4-completed':
            need({name:file_record(scope.install/name)['sha256'] for name in C4_SOURCES}==C4_SOURCES,'exact_c4_sources_required')
            need(file_record(scope.bundle/'restore/restored.json')['sha256']==C4_RESTORED,'exact_c4_completed_restore_required')
            restored=load(scope.bundle/'restore/restored.json');real=load(scope.bundle/'restore/state.json')
            need(real['phase']=='restored' and real['preservation']=='manifest_verified' and real['preserved_directory'] is True
                 and all(restored.get(k) is True for k in ('verified','database_restored','baseline_caches_restored'))
                 and restored.get('s3_rewound') is False,'real_restore_completion_required')
            rr_owner=load(rr/'owner.json');rr_cleanup=load(rr/'cleanup-completed.json');rr_proof=load(rr/'real-pg-proof.json')
            receipt=load(scope.work/'restore-rehearsal-receipt.json');synthetic=load(rr/'runtime/restore/state.json')
            rr_alias=scope.work/'restore-rehearsal-state'
            need(directory_record(rr_alias)==directory_record(rr),'rehearsal_receipt_alias_identity')
            need(rr_owner['sources']==receipt['sources']==C4_SOURCES and rr_owner['scope']=={
                'device':rr.stat().st_dev,'inode':rr.stat().st_ino},'exact_rehearsal_owner_sources_required')
            need(rr_cleanup['token']==rr_owner['token'] and rr_cleanup['owned_container_removed'] is True
                 and rr_cleanup['golden_retained'] is True and receipt['verified'] is True
                 and receipt['kind']=='isolated-real-pg-restore-rehearsal' and receipt['revision']==REVISION
                 and receipt['checks']==dict.fromkeys(('full_baseline_caches','isolated_real_pg_restore',
                     'marker_removed','owned_cleanup_complete','production_untouched','restore_state_machine'),True)
                 and all(rr_proof.get(k) is True for k in ('marker_removed','no_kubernetes_commands','no_production_credentials','no_network')),
                 'completed_restore_rehearsal_required')
            expected_rr_artifacts={
                str(rr_alias/'real-pg-proof.json'):file_record(rr/'real-pg-proof.json')['sha256'],
                str(rr_alias/'cleanup-completed.json'):file_record(rr/'cleanup-completed.json')['sha256']}
            need(len(receipt['artifacts'])==2 and {item['path']:item['sha256'] for item in receipt['artifacts']}==expected_rr_artifacts,
                'rehearsal_artifact_chain_changed')
            need(all(file_record(Path(path))['sha256']==wanted for path,wanted in expected_rr_artifacts.items()),
                 'rehearsal_artifact_chain_changed')
            need(synthetic['phase']=='restored' and re.fullmatch('[0-9a-f]{24}',synthetic['token']),'synthetic_restore_token')
            tokens+=[rr_owner['token'],synthetic['token']]
            roots += [rr/'runtime'/name for name in ('isolated-pv','cache-serving','cache-writer',
                '.failed-serving-'+synthetic['token'],'.failed-writer-'+synthetic['token'])]
            need(re.fullmatch('[0-9a-f]{24}',real['token']),'real_restore_token')
            protected.append(safe_path(real['source']).with_name('.failed-'+real['token']))
            layouts=load(cp/'cache-baselines.json')['layouts']
            for role in ('serving','writer'):
                protected.append(safe_path(layouts[role]['path']).with_name('.failed-'+role+'-'+real['token']))
        else:
            need(scope.phase=='cycle5-checkpoint-proof','fixed_phase_required')
            need(not (rr/'owner.json').exists() and not (scope.work/'restore-rehearsal-receipt.json').exists(),
                 'proof_retirement_must_precede_rehearsal')
        for p in protected:directory_record(p)
        copy_aliases=[scope.work/('checkpoint-state' if under(p,cp) else 'restore-rehearsal-state')/
            p.relative_to(cp if under(p,cp) else rr) for p in roots]
        for name in ('backup-receipt.json','backup-receipt-after-rehearsal.json'):
            path=cp/name
            if not path.exists():
                need(name!='backup-receipt.json','backup_receipt_required');continue
            backup=load(path);need(backup.get('verified') is True and backup.get('revision')==REVISION
                and backup.get('schema')==18 and backup.get('kind')=='coordinated-schema18-backup'
                and backup.get('checks')==dict.fromkeys(('coordinated_pg_s3','credentials_preserved',
                    'fallback_writer_verified','old_clone_verified','pg_restarted_without_restore','roles_stopped'),True),
                'verified_backup_required')
            required={str(cp_alias/n):cp/n for n in ('completed.json','checkpoint-completed.json','clone-proof-result.json',
                'clone-cleanup-completed.json','cache-baselines.json','pg-file-manifest.jsonl','archive-bindings.jsonl','capture-bindings.jsonl')}
            need(set(required)<={a['path'] for a in backup['artifacts']},'backup_metadata_artifacts_missing')
            for artifact in backup['artifacts']:
                artifact_path=safe_path(artifact['path'])
                need(not any(under(artifact_path,p) for p in roots+copy_aliases),'backup_requires_disposable_copy')
                if artifact['path'] in required:
                    need(file_record(required[artifact['path']])['sha256']==artifact['sha256'],
                         'retained_backup_artifact_changed')
                need(file_record(artifact_path)['sha256']==artifact['sha256'],'retained_backup_artifact_changed')
        return roots,protected,tokens

    def protected(self,roots,protected):
        scope=self.scope;result={};total=0;count=0
        excluded=roots+protected+[scope.work/'checkpoint-state',scope.work/'restore-rehearsal-state']
        def regular(fd,name):
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            with os.fdopen(descriptor,'rb') as stream:
                before=os.fstat(stream.fileno())
                need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=MAX_BYTES,
                     'protected_bounded_regular_required')
                digest=hashlib.file_digest(stream,'sha256').hexdigest();after=os.fstat(stream.fileno())
                need(stable_stat(before)==stable_stat(after)
                     and stable_stat(os.stat(name,dir_fd=fd,follow_symlinks=False))==stable_stat(after),
                     'protected_metadata_changed')
            return {'sha256':digest,'dev':before.st_dev,'ino':before.st_ino,'size':before.st_size,
                'uid':before.st_uid,'gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode),
                'mtime_ns':before.st_mtime_ns,'ctime_ns':before.st_ctime_ns}
        def visit(path,fd):
            nonlocal total,count
            s=os.fstat(fd)
            need(s.st_dev in (scope.bundle.stat().st_dev,scope.work.stat().st_dev),'protected_device_crossing')
            need(s.st_uid in (os.geteuid(),70,65532),'unexpected_directory_owner')
            result[str(path)]={'directory':{'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}}
            for name in sorted(os.listdir(fd)):
                child=path/name
                if any(under(child,p) for p in excluded):continue
                need(not name.startswith('.failed-'),'unknown_preserved_generation_requires_review')
                count+=1;need(count<=100000,'protected_entry_bound')
                value=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISDIR(value.st_mode):
                    descriptor=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    try:
                        opened=os.fstat(descriptor)
                        need((opened.st_dev,opened.st_ino)==(value.st_dev,value.st_ino),'protected_directory_changed')
                        visit(child,descriptor)
                    finally:os.close(descriptor)
                else:
                    need(stat.S_ISREG(value.st_mode),'protected_symlink_or_special_requires_review')
                    record=regular(fd,name);total+=record['size'];need(total<=MAX_METADATA_BYTES,'protected_bytes_bound')
                    result[str(child)]=record
            need(stable_stat(os.fstat(fd))==stable_stat(s),'protected_directory_drift')
        for path in (scope.bundle,scope.work,scope.install):
            safe_path(path);descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:visit(path,descriptor)
            finally:os.close(descriptor)
        for path in protected:result[str(path)]={'body_retained_not_read':directory_record(path)}
        return result

    def preview(self,*,runtime=False):
        roots,protected,tokens=self.receipts();aliases=[];inventories={};ancestors={};records=[]
        for root in roots:
            safe_path(root);directory_record(root)
            cp=self.scope.bundle/'checkpoint-volume';rr=self.scope.bundle/'restore-rehearsal-volume'
            base=cp if under(root,cp) else rr
            alias=self.scope.work/('checkpoint-state' if base==cp else 'restore-rehearsal-state')/root.relative_to(base)
            need(directory_record(alias)==directory_record(root),'work_bind_alias_identity')
            aliases.append(alias);inventories[str(root)]=tree(root)
            for item in inventories[str(root)]:
                need(item['uid'] in (os.geteuid(),70,65532) and item['gid'] in (os.getegid(),70,65532),'unexpected_copy_entry_owner')
                records.append(item)
            for ancestor in (root,root.parent,self.scope.bundle):ancestors[str(ancestor)]=directory_record(ancestor)
        protected_snapshot=self.protected(roots,protected)
        files=[item for item in records if item['kind']=='file'];counts=Counter((r['dev'],r['ino']) for r in files)
        need(all(counts[r['dev'],r['ino']]==r['links'] for r in files),'external_hardlink_refused')
        need(len(records)<=MAX_ENTRIES,'aggregate_inventory_bound')
        seen=set();allocated=logical=0
        for item in records:
            key=(item['dev'],item['ino'])
            if key not in seen:
                if item['path']:allocated+=item['blocks']*512
                if item['kind']=='file':logical+=item['size']
                seen.add(key)
        evidence=self.guard(roots,aliases,tokens,seen,runtime=runtime)
        need(self.protected(roots,protected)==protected_snapshot,'protected_bookend_changed')
        need(self.receipts()==(roots,protected,tokens),'producer_receipts_changed')
        return {'version':1,'kind':'cycle5-completed-copy-retirement','phase':self.scope.phase,
            'script_sha256':sha(Path(__file__).read_bytes()),'roots':[str(p) for p in roots],
            'aliases':[str(p) for p in aliases],'protected_roots':[str(p) for p in protected],
            'tokens':tokens,'ancestors':ancestors,'trees':inventories,'protected':protected_snapshot,
            'allocated_bytes':allocated,'logical_regular_bytes':logical,'entries':len(records),
            'environment':evidence,'payload_contents_hashed':False}

    def apply(self,preview,preview_sha,script_sha,approval):
        need(sha(encode(preview))==preview_sha and preview['script_sha256']==script_sha
             and sha(Path(__file__).read_bytes())==script_sha,'external_preview_source_pin_required')
        need(approval=={'version':1,'approved':True,'kind':'cycle5-completed-copy-retirement',
            'phase':self.scope.phase,'preview_sha256':preview_sha,'source_sha256':script_sha,
            'maximum_applies':1,'operations':['apply']},'exact_external_approval_required')
        need(preview['phase']==self.scope.phase and preview['environment']['runtime_qualified'] is True,
             'full_runtime_qualification_required')
        need(not self.scope.journal.exists(),'retirement_intent_already_consumed')
        before=self.preview(runtime=True)
        need(before==preview,'retirement_preview_stale')
        parent=safe_path(self.scope.journal.parent);s=parent.stat()
        need(s.st_uid==os.geteuid() and not s.st_mode&0o077,'existing_private_journal_parent_required')
        self.scope.journal.mkdir(mode=0o700);sync(parent)
        free_before=os.statvfs(parent).f_bavail*os.statvfs(parent).f_frsize
        new(self.scope.journal/'intent.json',{'source_sha256':script_sha,'preview_sha256':preview_sha,
            'maximum_applies':1,'roots':preview['roots'],'free_before':free_before})
        self.removed_links=Counter();self.link_ctimes={}
        try:
            for text in preview['roots']:
                self.clear(Path(text),preview['trees'][text])
            for path,expected in preview['ancestors'].items():
                need(directory_record(Path(path))==expected,'retained_root_identity_changed')
            roots=[Path(p) for p in preview['roots']];protected=[Path(p) for p in preview['protected_roots']]
            need(self.protected(roots,protected)==preview['protected'],'protected_artifacts_changed')
            need(self.receipts()[0]==roots,'producer_completion_changed')
            after=self.guard(roots,[Path(p) for p in preview['aliases']],preview['tokens'],set(),runtime=True)
            need(after==preview['environment'],'runtime_boundary_changed')
            need(all(not any(p.iterdir()) for p in roots),'copy_children_remain')
            free_after=os.statvfs(parent).f_bavail*os.statvfs(parent).f_frsize
            result={'version':1,'verified':True,'source_sha256':script_sha,'preview_sha256':preview_sha,
                'roots_preserved':True,'protected_unchanged':True,'producer_completion_retained':True,
                'free_before':free_before,'free_after':free_after,'observed_free_delta':free_after-free_before,
                'directory_timestamps_changed':True,'atime_equivalence_claimed':False}
            new(self.scope.journal/'completed.json',result);return result
        except BaseException:
            try:new(self.scope.journal/'failed.json',{'verified':False,'no_retry':True,'manual_reconciliation_required':True})
            except BaseException:pass
            raise

    def clear(self,root,rows):
        """Linear nofollow dirfd deletion with current nlink/ctime tracking."""
        expected={r['path']:r for r in rows};device=rows[0]['dev']
        children={}
        for relative in expected:
            if relative:
                parent=str(Path(relative).parent);children.setdefault('' if parent=='.' else parent,set()).add(Path(relative).name)
        def observed(fd,name,relative):
            value=os.stat(name,dir_fd=fd,follow_symlinks=False)
            need(value.st_dev==device,'delete_device_crossing')
            kind='directory' if stat.S_ISDIR(value.st_mode) else 'file' if stat.S_ISREG(value.st_mode) else 'link' if stat.S_ISLNK(value.st_mode) else None
            need(kind is not None,'delete_special_entry')
            item={'path':relative,'kind':kind,'dev':value.st_dev,'ino':value.st_ino,'uid':value.st_uid,
                'gid':value.st_gid,'mode':stat.S_IMODE(value.st_mode),'size':value.st_size,
                'links':value.st_nlink,'blocks':value.st_blocks,'mtime_ns':value.st_mtime_ns,'ctime_ns':value.st_ctime_ns}
            if kind=='link':item['target']=os.readlink(name,dir_fd=fd)
            return item
        def visit(fd,relative):
            names=sorted(os.listdir(fd))
            wanted=children.get(relative,set())
            need(set(names)==wanted,'delete_child_set_changed')
            for name in names:
                child=str(Path(relative)/name) if relative else name;item=dict(expected[child]);key=(item['dev'],item['ino'])
                if item['kind']=='file' and key in self.removed_links:
                    item['links']-=self.removed_links[key];item['ctime_ns']=self.link_ctimes[key]
                need(observed(fd,name,child)==item,'delete_entry_changed')
                descriptor=os.open(name,(os.O_RDONLY|os.O_DIRECTORY if item['kind']=='directory' else os.O_PATH)|os.O_NOFOLLOW,dir_fd=fd)
                try:
                    value=os.fstat(descriptor);need((value.st_dev,value.st_ino)==key,'opened_entry_changed')
                    if item['kind']=='directory':
                        visit(descriptor,child)
                        current=observed(fd,name,child)
                        need(all(current[k]==item[k] for k in ('kind','dev','ino','uid','gid','mode')),'parent_entry_replaced')
                        os.rmdir(name,dir_fd=fd)
                    else:
                        need(observed(fd,name,child)==item,'unlink_entry_replaced')
                        os.unlink(name,dir_fd=fd);after=os.fstat(descriptor)
                        need(after.st_nlink==item['links']-1 and after.st_size==item['size']
                             and after.st_mtime_ns==item['mtime_ns'],'unlink_inode_changed')
                        if item['kind']=='file':self.removed_links[key]+=1;self.link_ctimes[key]=after.st_ctime_ns
                finally:os.close(descriptor)
            os.fsync(fd)
        descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            value=os.fstat(descriptor);need((value.st_dev,value.st_ino)==(rows[0]['dev'],rows[0]['ino']),'delete_root_changed')
            need(row(root,'',device)==rows[0],'delete_root_metadata_changed')
            visit(descriptor,'')
        finally:os.close(descriptor)


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    inspect=sub.add_parser('inspect');inspect.add_argument('--phase',choices=('cycle4-completed','cycle5-checkpoint-proof'),required=True)
    inspect.add_argument('--output',type=Path,required=True);inspect.add_argument('--runtime',action='store_true')
    apply=sub.add_parser('apply');apply.add_argument('--phase',choices=('cycle4-completed','cycle5-checkpoint-proof'),required=True)
    apply.add_argument('--preview',type=Path,required=True);apply.add_argument('--preview-sha256',required=True)
    apply.add_argument('--script-sha256',required=True);apply.add_argument('--approval',type=Path,required=True)
    apply.add_argument('--approval-sha256',required=True)
    args=parser.parse_args();need(os.geteuid()==0,'root_required');engine=Engine(production_scope(args.phase))
    if args.operation=='inspect':
        need(args.output.is_absolute() and Path('/tmp') in args.output.parents,'private_tmp_preview_required')
        value=engine.preview(runtime=args.runtime);new(args.output,value)
        result={'preview':True,'sha256':sha(encode(value)),'runtime_qualified':args.runtime,
            'entries':value['entries'],'allocated_bytes':value['allocated_bytes']}
    else:
        need(file_record(args.approval)['sha256']==args.approval_sha256,'approval_file_pin_changed')
        result=engine.apply(load(args.preview),args.preview_sha256,args.script_sha256,load(args.approval))
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except Exception:
        print(json.dumps({'verified':False,'reason':'copy_retirement_refused','no_automatic_retry':True}));sys.exit(1)
