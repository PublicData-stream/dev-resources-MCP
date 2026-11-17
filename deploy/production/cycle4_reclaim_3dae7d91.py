#!/usr/bin/env python3
"""Inspect, then consume one exact admission to reclaim completed fixture copies.

Production CLI paths are immutable. Preview never removes files. Apply preserves
leaf/data-root identities and every retained artifact, and cannot be replayed.
No credentials, source bodies, process command lines or firewall data are emitted.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

MAX_ENTRIES=3_000_000
MAX_BYTES=1024**3
MAX_METADATA_BYTES=4*1024**3
SPECIAL={'upgrade-controller.py','physical-checkpoint.py','restore-controller.py',
         'restore-rehearsal.py','npm-recovery.py','safety-supervisor.py'}
JOURNAL=Path('/var/lib/devres-production-reclaim/3dae7d91-20261117')
sys.dont_write_bytecode=True


class Refused(RuntimeError):pass


def need(value,code):
    if not value:raise Refused(code)


def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(body):return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Cycle:
    name:str
    bundle:Path
    work:Path
    install:Path


CYCLES=tuple(Cycle(name,Path('/var/lib/devres-production-upgrades')/scope,
    Path('/tmp')/('devres-upgrade-'+scope),Path('/usr/local/libexec')/install)
    for name,scope,install in (
        ('cycle1','1d76fbcc-20261115','devres-upgrade-1d76fbcc'),
        ('cycle2','1d76fbcc-cycle2-20261116','devres-upgrade-1d76fbcc-cycle2-20261116'),
        ('cycle3','9373f71e-20261116','devres-upgrade-9373f71e')))
LEAVES=('checkpoint-volume/pg-clone','checkpoint-volume/rehearsal','restore-rehearsal-volume/runtime')


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
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
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
    file_record(path)
    body=Path(path).read_bytes();need(len(body)<=MAX_BYTES,'metadata_bound')
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
    safe_path(path);device=path.stat().st_dev;rows=[];started=time.monotonic()
    def visit(current,relative):
        value=row(current,relative,device);rows.append(value)
        need(len(rows)<=MAX_ENTRIES and time.monotonic()-started<1800,'tree_scan_bound')
        if value['kind']=='directory':
            with os.scandir(current) as entries:names=sorted(entry.name for entry in entries)
            for name in names:visit(current/name,str(Path(relative)/name) if relative else name)
    visit(path,'')
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


def system_guard(roots,aliases,tokens,*,proc=Path('/proc'),socket_paths=None,alias_qualification_sha=None,retained_data_qualification_sha=None,metadata_qualification_sha=None):
    """Classify every namespace mapping before checking any process reference."""
    exposure=set(roots)|set(aliases);namespaces={};processes=0;started=time.monotonic()
    proc=Path(proc);all_mounts=[];inventory=[]
    qualified=validate_livepatch_aliases(alias_qualification_sha,roots,aliases,proc=proc,retained_data_qualification_sha=retained_data_qualification_sha,metadata_qualification_sha=metadata_qualification_sha) if alias_qualification_sha else None
    self_mounts=mount_rows((proc/'self/mountinfo').read_text())
    for path in sorted(proc.iterdir(),key=lambda p:p.name):
        if not path.name.isdecimal():continue
        processes+=1;need(processes<=100000 and time.monotonic()-started<180,'process_inventory_bound')
        try:
            namespace=os.readlink(path/'ns/mnt')
            if namespace not in namespaces:
                body=(path/'mountinfo').read_text();namespaces[namespace]=sha(body.encode())
                all_mounts += [(namespace,mount) for mount in mount_rows(body)]
            inventory.append((path,namespace))
        except FileNotFoundError:continue
        except PermissionError:raise Refused('process_inventory_incomplete') from None
    physical=[]
    for root in roots:
        device=str(os.major(root.stat().st_dev))+':'+str(os.minor(root.stat().st_dev))
        bases=[m for m in self_mounts if m['device']==device and under(root,Path(m['target']))]
        need(bool(bases),'leaf_filesystem_mapping_missing')
        base=max(bases,key=lambda m:len(Path(m['target']).parts))
        physical.append((device,Path(base['root'])/root.relative_to(Path(base['target']))))
    permitted={} if qualified is None else {item['alias']:(item['namespace'],item['mount']) for item in qualified['snapshot']['mappings']}
    observed=set()
    for namespace,mount in all_mounts:
        need(not path_used(mount['target'],exposure),'leaf_or_nested_mount')
        for device,relative in physical:
            if mount['device']!=device:continue
            mounted=Path(mount['root'])
            need(not under(mounted,relative),'leaf_exposed_by_mount')
            if under(relative,mounted):
                derived=Path(mount['target'])/relative.relative_to(mounted)
                if derived not in exposure:
                    key=str(derived)
                    need(key in permitted and permitted[key]==(namespace,mount),'unknown_ancestor_mount_alias')
                    observed.add(key)
        target=Path(mount['target'])
        try:
            need(not (target.exists() and any((target.stat().st_dev,target.stat().st_ino)==
                (root.stat().st_dev,root.stat().st_ino) for root in roots)),'leaf_bind_mount')
        except PermissionError:raise Refused('mount_inventory_incomplete') from None
    need(observed==set(permitted),'qualified_alias_mapping_missing')
    exposure.update(Path(name) for name in observed)
    # No reference scan can precede this expansion. New namespace drift during
    # the second pass fails closed, including drift of the pinned OS process.
    for path,namespace in inventory:
        try:
            need(os.readlink(path/'ns/mnt')==namespace,'process_namespace_changed')
            references=[path/'cwd',path/'root',path/'exe']
            with os.scandir(path/'fd') as entries:references += [Path(entry.path) for entry in entries]
            for reference in references:
                try:target=os.readlink(reference)
                except FileNotFoundError:continue
                need(not path_used(target,exposure),'active_process_reference')
            for line in (path/'maps').read_text().splitlines():
                fields=line.split(None,5)
                if len(fields)==6:need(not path_used(fields[5],exposure),'active_process_mapping')
            need(os.readlink(path/'ns/mnt')==namespace,'process_namespace_changed')
        except FileNotFoundError:continue
        except PermissionError:raise Refused('process_inventory_incomplete') from None
    def mount_bookend():
        checked=set()
        for path in proc.iterdir():
            if not path.name.isdecimal():continue
            try:
                namespace=os.readlink(path/'ns/mnt')
                need(namespace in namespaces,'process_namespace_changed')
                if namespace not in checked:
                    need(sha((path/'mountinfo').read_bytes())==namespaces[namespace],'process_mounts_changed')
                    checked.add(namespace)
            except FileNotFoundError:continue
            except PermissionError:raise Refused('process_inventory_incomplete') from None
    mount_bookend()
    if qualified is not None:
        need(validate_livepatch_aliases(alias_qualification_sha,roots,aliases,proc=proc,retained_data_qualification_sha=retained_data_qualification_sha,metadata_qualification_sha=metadata_qualification_sha)==qualified,
             'livepatch_alias_qualification_changed')
    sockets=set(socket_paths) if socket_paths is not None else {Path('/var/run/docker.sock'),*Path('/run/user').glob('*/docker.sock')}
    configured=os.environ.get('DOCKER_HOST')
    if configured:
        need(configured.startswith('unix:///'),'uninspectable_docker_endpoint')
        sockets.add(Path(configured.removeprefix('unix://')))
    docker=[]
    for socket in sorted(sockets,key=str):
        if not socket.exists():continue
        prefix=['docker','--host','unix://'+str(socket)]
        ids=command(prefix+['ps','-aq']).decode().split();need(len(ids)<=10000,'docker_inventory_bound')
        containers=json.loads(command(prefix+['inspect',*ids])) if ids else []
        network_ids=command(prefix+['network','ls','-q']).decode().split()
        need(len(network_ids)<=10000,'docker_network_bound')
        networks=json.loads(command(prefix+['network','inspect',*network_ids])) if network_ids else []
        for value in containers:
            labels=value.get('Config',{}).get('Labels') or {}
            need(not any(token in labels.values() for token in tokens),'owned_container_remains')
            for mount in value.get('Mounts',[]):
                if mount.get('Type')!='bind':continue
                source=Path(mount['Source'])
                need(not any(under(source,root) or under(root,source) for root in exposure),'docker_bind_reference')
        for value in networks:
            labels=value.get('Labels') or {}
            need(not any(token in labels.values() or token in value.get('Name','') for token in tokens),
                 'owned_network_remains')
        docker.append(sha(encode({'containers':containers,'networks':networks})))
    firewall=[]
    for arguments in (['nft','-j','list','ruleset'],['iptables-save'],['ip6tables-save']):
        body=command(arguments)
        need(not any(token.encode() in body for token in tokens),'owned_firewall_reference')
        need(not any(str(root).encode() in body for root in exposure),'leaf_firewall_reference')
        firewall.append(sha(body))
    mount_bookend()
    if qualified is not None:
        need(validate_livepatch_aliases(alias_qualification_sha,roots,aliases,proc=proc,retained_data_qualification_sha=retained_data_qualification_sha,metadata_qualification_sha=metadata_qualification_sha)==qualified,
             'livepatch_alias_qualification_changed')
    return {'verified':True,'process_count':processes,'mount_namespaces':len(namespaces),
        'alias_qualification_sha256':alias_qualification_sha,'retained_data_qualification_sha256':retained_data_qualification_sha,'metadata_qualification_sha256':metadata_qualification_sha,'qualified_alias_count':len(observed),
        'mounts_sha256':sha(encode(sorted(all_mounts,key=encode))),
        'docker_sha256':sha(encode(docker)),'firewall_sha256':sha(encode(firewall))}


class Engine:
    """Parameterized for local fake trees; the CLI never accepts alternate roots."""
    def __init__(self,cycles=CYCLES,journal=JOURNAL,guard=system_guard,*,qualification_sha=None,retained_data_qualification_sha=None,metadata_qualification_sha=None):
        self.cycles=cycles;self.journal=Path(journal);self.qualification_sha=qualification_sha
        self.retained_data_qualification_sha=retained_data_qualification_sha
        self.metadata_qualification_sha=metadata_qualification_sha
        if metadata_qualification_sha is not None:
            need(re.fullmatch('[0-9a-f]{64}',metadata_qualification_sha or ''),'external_discovery_qualification_required')
            preflight_discovery_metadata(metadata_qualification_sha)
            need(qualification_sha==FROZEN_ALIAS_SHA and retained_data_qualification_sha==FROZEN_DATA_SHA
                 and self.journal==METADATA_JOURNAL,'fixed_metadata_apply_scope_required')
        need(metadata_qualification_sha is not None or retained_data_qualification_sha is None or self.journal==DATA_JOURNAL,'fixed_retained_data_apply_journal_required')
        self.guard=(lambda roots,aliases,tokens:system_guard(roots,aliases,tokens,alias_qualification_sha=qualification_sha,retained_data_qualification_sha=retained_data_qualification_sha,metadata_qualification_sha=metadata_qualification_sha)) if qualification_sha and guard is system_guard else guard
        self.whitelist={cycle.bundle/relative:(cycle,relative) for cycle in cycles for relative in LEAVES}

    def canonical(self,path):
        path=Path(path)
        for cycle in self.cycles:
            for source,destination in ((cycle.work/'checkpoint-state',cycle.bundle/'checkpoint-volume'),
                (cycle.work/'restore-rehearsal-state',cycle.bundle/'restore-rehearsal-volume')):
                if under(path,source):return destination/path.relative_to(source)
        return path

    def aliases(self,leaves):
        aliases=[]
        for leaf in leaves:
            cycle,relative=self.whitelist[leaf]
            parent=cycle.bundle/Path(relative).parts[0]
            alias=cycle.work/('checkpoint-state' if relative.startswith('checkpoint-volume/') else 'restore-rehearsal-state')
            if alias.exists():
                safe_path(alias)
                need(identity(alias)==identity(parent),'historical_bind_alias_changed')
                aliases.append(alias/leaf.relative_to(parent))
        return aliases

    def delete_roots(self,leaf,relative):
        if relative.endswith('/pg-clone'):return [leaf]
        if relative.endswith('/rehearsal'):names=['cache','writer-cache']
        else:
            names=['isolated-pv','cache-serving','cache-writer']
            names += [p.name for p in leaf.iterdir() if re.fullmatch(r'\.failed-(?:serving|writer)-[0-9a-f]{24}',p.name)]
        return [leaf/name for name in sorted(set(names)) if (leaf/name).exists()]

    def validate_receipts(self,cycle,relative):
        cp=cycle.bundle/'checkpoint-volume';volume=cycle.bundle/'restore-rehearsal-volume'
        if relative.startswith('checkpoint-volume/'):
            owner=load(cp/'owner.json');cleanup=load(cp/'clone-cleanup-completed.json')
            need(all(cleanup.get(key) is True for key in ('all_owned_containers_removed','owned_network_removed','physical_checkpoint_retained')),
                 'completed_clone_cleanup_required')
            proof=load(cp/'clone-proof-result.json');intent=load(cp/'proof-intent.json')
            need(proof.get('isolated_clone_only') is True and proof.get('provider_source_requests')==0
                 and intent.get('token')==owner.get('token') and intent.get('no_production_mount') is True,
                 'completed_isolated_clone_required')
        else:
            owner=load(volume/'owner.json');cleanup=load(volume/'cleanup-completed.json')
            need(cleanup.get('token')==owner.get('token') and cleanup.get('owned_container_removed') is True
                 and cleanup.get('golden_retained') is True,'completed_restore_cleanup_required')
            proof=load(volume/'real-pg-proof.json')
            need(proof.get('marker_removed') is True and proof.get('no_kubernetes_commands') is True
                 and proof.get('no_production_credentials') is True and proof.get('no_network') is True,
                 'completed_isolated_restore_required')
            scope=owner.get('scope',{})
            need(scope=={'device':volume.stat().st_dev,'inode':volume.stat().st_ino},'restore_scope_identity_changed')
        token=owner.get('token');need(type(token) is str and re.fullmatch('[0-9a-f]{24}',token),'owned_fixture_token_required')
        need(load(cp/'completed.json').get('old_clone_verified') is True,'completed_checkpoint_required')
        need((cp/'baseline.json').is_file(),'checkpoint_baseline_required')
        return token

    def protected(self,selected,delete):
        retained=None;metadata=None
        if self.metadata_qualification_sha is not None:
            metadata=validate_discovery_metadata(self.metadata_qualification_sha,selected,self.aliases(selected),delete=delete)
            retained=metadata['retained_data_qualification']
        elif self.retained_data_qualification_sha:
            retained=validate_retained_data_scope(self.retained_data_qualification_sha,selected,self.aliases(selected),delete=delete)
        body_roots=[] if retained is None else [Path(item['path']) for item in retained['producer_data']['roots']]
        paths=set();cycles={self.whitelist[path][0] for path in selected}
        for cycle in cycles:
            manifest=load(cycle.work/'source-manifest.json');paths.add(cycle.work/'source-manifest.json')
            need(1<=len(manifest)<=100,'source_manifest_bound')
            for name,wanted in manifest.items():
                logical=Path(name)
                need(not logical.is_absolute() and '..' not in logical.parts and str(logical)==name
                     and re.fullmatch('[0-9a-f]{64}',wanted or ''),'source_manifest_invalid')
                path=(cycle.install if name in SPECIAL else cycle.work)/name
                need(file_record(path)['sha256']==wanted,'historical_source_changed');paths.add(path)
            skipped={cycle.bundle/'checkpoint-volume'/'pg-checkpoint',cycle.bundle/'checkpoint-volume'/'fallback-cache',*body_roots}
            for base in (cycle.bundle,cycle.work):
                for folder,dirs,files in os.walk(base,followlinks=False):
                    current=Path(folder)
                    dirs[:]=[name for name in dirs if not any(under(self.canonical(current/name),root) for root in [*skipped,*delete])]
                    for name in files:
                        path=current/name
                        if any(under(self.canonical(path),root) for root in delete):continue
                        if path.suffix in ('.json','.jsonl','.log','.py','.toml'):
                            paths.add(self.canonical(path))
                            need(len(paths)<=50000,'protected_inventory_bound')
        records={};total=0
        for path in sorted(paths,key=str):
            admitted=metadata is not None and str(path) in metadata['discovery']['files']
            record=file_record(path,private=False,maximum=65536) if admitted else file_record(path,private=False)
            if admitted:need(record==metadata['discovery']['files'][str(path)],'protected_discovery_record_changed')
            else:need(record['uid'] in (os.geteuid(),70,65532) and not record['mode']&0o077,'protected_file_authority_changed')
            total+=record['size'];need(total<=MAX_METADATA_BYTES,'protected_metadata_bytes_bound')
            records[str(path)]=record
            if 'backup-receipt' in path.name and path.suffix=='.json':
                receipt=load(path)
                need(receipt.get('verified') is True and type(receipt.get('artifacts')) is list,'verified_backup_required')
                for artifact in receipt['artifacts']:
                    artifact_path=self.canonical(artifact['path'])
                    need(not any(under(artifact_path,leaf) for leaf in selected),'backup_artifact_inside_reclaim_leaf')
                    need(file_record(artifact_path)['sha256']==artifact['sha256'],'backup_artifact_changed')
        if retained is not None:
            records['producer-retained-data']={'kind':'structural-nonmodification','payloads_rehashed':False,
                'qualification_sha256':self.retained_data_qualification_sha,'producer_data':retained['producer_data']}
        if metadata is not None:
            records['discovery-metadata']={'qualification_sha256':self.metadata_qualification_sha,
                'projection':metadata['discovery'],'environment':metadata['environment']}
        return records

    def preview(self,selected):
        leaves=[Path(value) for value in selected]
        need(1<=len(leaves)<=9 and len(set(leaves))==len(leaves) and all(path in self.whitelist for path in leaves),
             'exact_fixture_leaf_whitelist_required')
        leaves=sorted(leaves,key=str);delete=[];tokens=[];ancestors={};inventories={}
        for leaf in leaves:
            cycle,relative=self.whitelist[leaf];safe_path(leaf)
            need(identity(cycle.bundle)['uid']==os.geteuid() and not identity(cycle.bundle)['mode']&0o077,
                 'private_historical_bundle_required')
            tokens.append(self.validate_receipts(cycle,relative))
            for ancestor in (leaf,leaf.parent,cycle.bundle):ancestors[str(ancestor)]=identity(ancestor)
            candidates=self.delete_roots(leaf,relative)
            for candidate in candidates:
                safe_path(candidate);identity(candidate)
            delete+=candidates
            inventories[str(leaf)]=tree(leaf)
        aliases=self.aliases(leaves)
        protected=self.protected(leaves,delete)
        files=[(Path(leaf)/item['path'],item) for leaf,rows in inventories.items() for item in rows
               if item['kind']=='file' and any(under(Path(leaf)/item['path'],root) and Path(leaf)/item['path']!=root for root in delete)]
        counts=Counter((item['dev'],item['ino']) for _,item in files)
        need(all(counts[item['dev'],item['ino']]==item['links'] for _,item in files),'external_hardlink_refused')
        seen=set();allocated=0
        for _,item in files:
            key=(item['dev'],item['ino'])
            if key not in seen:allocated+=item['blocks']*512;seen.add(key)
        proof=self.guard(leaves,aliases,sorted(set(tokens)))
        return {'version':1,'kind':'cycle4-completed-fixture-reclaim','script_sha256':sha(Path(__file__).read_bytes()),
            'alias_qualification_sha256':self.qualification_sha,'retained_data_qualification_sha256':self.retained_data_qualification_sha,
            'metadata_qualification_sha256':self.metadata_qualification_sha,
            'leaves':[str(path) for path in leaves],'delete_roots':[str(path) for path in delete],
            'aliases':[str(path) for path in aliases],'tokens':sorted(set(tokens)),
            'ancestors':ancestors,'trees':inventories,'protected':protected,
            'allocated_file_bytes':allocated,'runtime_evidence':proof}

    def apply(self,preview,preview_sha,script_sha):
        need(sha(encode(preview))==preview_sha and preview.get('script_sha256')==script_sha
             and sha(Path(__file__).read_bytes())==script_sha,'external_admission_hash_required')
        need(not self.journal.exists(),'reclaim_intent_already_consumed')
        before=self.preview(preview['leaves'])
        need({k:v for k,v in before.items() if k!='runtime_evidence'}==
             {k:v for k,v in preview.items() if k not in ('runtime_evidence','live_boundary')},'reclaim_preview_stale')
        safe_path(self.journal);self.journal.mkdir(mode=0o700,parents=True);sync(self.journal.parent)
        new(self.journal/'intent.json',{'version':1,'preview_sha256':preview_sha,'script_sha256':script_sha,
            'maximum_attempts':1,'allocated_file_bytes':preview['allocated_file_bytes']})
        self._removed_links=Counter();self._link_ctimes={}
        try:
            for text in preview['delete_roots']:
                root=Path(text);leaf=next(Path(path) for path in preview['leaves'] if under(root,Path(path)))
                rows={str(Path(path)):item for item in preview['trees'][str(leaf)] for path in [item['path']]}
                self._clear(root,leaf,rows)
            for text,expected in preview['ancestors'].items():
                need(identity(Path(text))==expected,'retained_directory_identity_changed')
            need(self.protected([Path(p) for p in preview['leaves']],[Path(p) for p in preview['delete_roots']])==preview['protected'],
                 'protected_artifacts_changed')
            after=self.guard([Path(p) for p in preview['leaves']],[Path(p) for p in preview['aliases']],preview['tokens'])
            for text in preview['delete_roots']:need(not any(Path(text).iterdir()),'reclaim_contents_remain')
            new(self.journal/'completed.json',{'version':1,'verified':True,'preview_sha256':preview_sha,
                'root_identities_preserved':True,'protected_artifacts_unchanged':True,'runtime_evidence':after,
                'directory_timestamps_changed':True,'atime_equivalence_claimed':False,
                'free_bytes':os.statvfs(self.journal).f_bavail*os.statvfs(self.journal).f_frsize})
        except BaseException:
            try:new(self.journal/'failed.json',{'version':1,'known_complete':False,'manual_reconciliation_required':True})
            except BaseException:pass
            raise
        return load(self.journal/'completed.json')

    def _clear(self,root,leaf,rows):
        root_expected=rows[str(root.relative_to(leaf))]
        descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            value=os.fstat(descriptor)
            need((value.st_dev,value.st_ino,value.st_uid,value.st_gid,stat.S_IMODE(value.st_mode))==
                 tuple(root_expected[key] for key in ('dev','ino','uid','gid','mode')),'delete_root_identity_changed')
            def clear(fd,current):
                for name in sorted(os.listdir(fd)):
                    path=current/name;relative=str(path.relative_to(leaf));expected=dict(rows[relative])
                    key=(expected['dev'],expected['ino'])
                    if expected['kind']=='file' and key in self._removed_links:
                        expected['links']-=self._removed_links[key]
                        expected['ctime_ns']=self._link_ctimes[key]
                    observed=row(path,relative,root_expected['dev'])
                    need(observed==expected,'delete_entry_changed')
                    if expected['kind']=='directory':
                        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                        try:
                            pinned=os.fstat(child)
                            need((pinned.st_dev,pinned.st_ino,pinned.st_uid,pinned.st_gid,stat.S_IMODE(pinned.st_mode))==
                                 tuple(expected[key] for key in ('dev','ino','uid','gid','mode')),'opened_child_identity_changed')
                            clear(child,path)
                        finally:os.close(child)
                        os.rmdir(name,dir_fd=fd)
                    elif expected['kind']=='file' and expected['links']>1:
                        pinned=os.open(name,os.O_PATH|os.O_NOFOLLOW,dir_fd=fd)
                        try:
                            info=os.fstat(pinned)
                            need((info.st_dev,info.st_ino)==key,'hardlink_inode_changed')
                            os.unlink(name,dir_fd=fd)
                            after=os.fstat(pinned)
                            need(after.st_nlink==expected['links']-1 and after.st_size==expected['size']
                                 and after.st_mtime_ns==expected['mtime_ns'],'hardlink_unlink_changed')
                            self._removed_links[key]+=1;self._link_ctimes[key]=after.st_ctime_ns
                        finally:os.close(pinned)
                    else:os.unlink(name,dir_fd=fd)
                os.fsync(fd)
            clear(descriptor,root)
        finally:os.close(descriptor)



PREVIOUS=CYCLES[-1]
PREVIOUS_CONTROLLER_SHA='b98d2a02804feba7ba12a45fc539879ef435c74951dbfd20a68d999b3a745957'
PREVIOUS_MANIFEST_SHA='5dbf9d3be45cd6222eda9d36cc2d59b0dcd580b65143743933cc5d4b33a23a4b'
PREVIOUS_SOURCE_NAMES=SPECIAL|{
    'acceptance_common.py','acceptance-receipt.py','compressed-probe.py','deploy.py','observation-loop.py',
    'operational-proof.py','phase-driver.py','process-launch.py','process-watch.py','public-matrix.py',
    'runner.py','sitecustomize.py','store-claim.py','target-private-acceptance.py',
    'deploy/diagnostics/__init__.py','deploy/diagnostics/evidence.py','deploy/diagnostics/runner.py',
    'mcp_smoke.py','target-native-qualification.json','fallback-native-qualification.json'}

EDGE_BRIDGE=Path('/usr/local/libexec/devres-upgrade-3dae7d91/edge-readmission.py')
CURRENT_MANIFEST=Path('/tmp/devres-upgrade-3dae7d91-20261117/source-manifest.json')


def bound_edge_bridge():
    expected=os.environ.get('DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256','')
    need(re.fullmatch('[0-9a-f]{64}',expected) and file_record(CURRENT_MANIFEST)['sha256']==expected,
         'current_external_source_manifest_required')
    manifest=load(CURRENT_MANIFEST)
    need(file_record(EDGE_BRIDGE)['sha256']==manifest.get('edge-readmission.py'),'edge_bridge_source_changed')
    receipt_sha=os.environ.get('DEVRES_EDGE_READMISSION_SHA256','')
    need(re.fullmatch('[0-9a-f]{64}',receipt_sha),'edge_receipt_pin_required')
    spec=importlib.util.spec_from_file_location('reclaim_exact_edge_bridge',EDGE_BRIDGE)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module,receipt_sha,expected


class LiveBoundary:
    """Fixed predecessor proof, held under its original lifecycle/certificate locks."""
    def source_guard(self):
        path=PREVIOUS.work/'source-manifest.json'
        need(file_record(path)['sha256']==PREVIOUS_MANIFEST_SHA,'exact_previous_manifest_required')
        manifest=load(path)
        need(set(manifest)==PREVIOUS_SOURCE_NAMES,'exact_previous_source_set_required')
        for name,wanted in manifest.items():
            source=(PREVIOUS.install if name in SPECIAL else PREVIOUS.work)/name
            need(re.fullmatch('[0-9a-f]{64}',wanted or '') and file_record(source)['sha256']==wanted,
                 'previous_source_changed')
        need(manifest['upgrade-controller.py']==PREVIOUS_CONTROLLER_SHA,'exact_previous_controller_required')

    def check(self):
        self.source_guard()
        module,receipt_sha,manifest_sha=bound_edge_bridge()
        native=module.native_guard(receipt_sha)
        self.controller.guard();self.controller.storage_guard(18,owner=False)
        state=self.controller.state()
        need(state.get('runtime')=='fallback' and state.get('phase')=='withdrawn' and state.get('configs')=='paused'
             and state.get('replicas')=={'postgres':1,'writer':0,'backend':0}
             and set(state.get('pods',{}))=={'postgres'},'withdrawn_schema18_predecessor_required')
        fingerprint={'controller_sha256':PREVIOUS_CONTROLLER_SHA,'manifest_sha256':PREVIOUS_MANIFEST_SHA,
            'state_sha256':sha(encode(state)),'prepared_sha256':file_record(PREVIOUS.bundle/'prepared.json')['sha256'],
            'edge_readmission_sha256':receipt_sha,'current_source_manifest_sha256':manifest_sha,
            'native_edge_sha256':sha(encode(native))}
        if hasattr(self,'fingerprint'):need(fingerprint==self.fingerprint,'previous_boundary_changed')
        else:self.fingerprint=fingerprint
        return fingerprint

    def __enter__(self):
        self.source_guard()
        module,receipt_sha,_=bound_edge_bridge()
        self.controller=module.load_controller(PREVIOUS.install/'upgrade-controller.py',PREVIOUS_CONTROLLER_SHA,
            str(PREVIOUS.bundle),'default',receipt_sha=receipt_sha)
        self.lock=self.controller.locked();self.lock.__enter__()
        try:self.check()
        except BaseException:
            self.lock.__exit__(*sys.exc_info());raise
        return self

    def __exit__(self,kind,error,trace):
        try:self.check()
        finally:self.lock.__exit__(kind,error,trace)


ALIAS_SCOPE=Path('/var/lib/devres-production-reclaim-qualifications/3dae7d91-20261117')
ALIAS_RECEIPT=ALIAS_SCOPE/'livepatch-hostfs.json'
ALIAS_INTENT=ALIAS_SCOPE/'intent.json'
ORIGINAL_RECLAIM=Path('/usr/local/libexec/devres-upgrade-3dae7d91/reclaim-completed-fixtures.original-ba1cbc57.py')
ORIGINAL_RECLAIM_SHA='ba1cbc57bea7905e05fb193f016495af53808bf97715b70ad0a49b0e839bfff7'
ALIAS_MANIFEST_SHA='a23b1015e38926627bfe2d8883d3ebe46d9c23dadcbe68ba1695529f0808be5e'
ALIAS_EDGE_SHA='e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a'
LIVEPATCH_PID=1166
LIVEPATCH_BOOT='f9c0269b-c802-4a04-bda2-64ef0d4128bf'
LIVEPATCH_START=21054
LIVEPATCH_NAMESPACE='mnt:[4026532742]'
LIVEPATCH_EXE='/snap/canonical-livepatch/418/canonical-livepatchd'
LIVEPATCH_EXE_SHA='4f4e55fa28eb0d66281c11f21d2c275c9e0f43188507ec886af70720ddb25885'
LIVEPATCH_EXE_IDENTITY={'dev':1792,'ino':2,'uid':0,'gid':0,'mode':0o755,'size':12337562}
LIVEPATCH_NS_IDENTITY={'dev':5,'ino':4026532742,'uid':0,'gid':0,'mode':0o444}
LIVEPATCH_CGROUP='0::/system.slice/snap.canonical-livepatch.canonical-livepatchd.service'
LIVEPATCH_MOUNTS_SHA='748b8d049f6fded24981b56b52c5a57b3281b94688a31e6ced8cf308c927efd6'
LIVEPATCH_PREFIX=Path('/var/lib/snapd/hostfs')
ALIAS_LEAVES=tuple(cycle.bundle/relative for cycle in CYCLES if cycle.name in ('cycle1','cycle3') for relative in LEAVES)


def _read_stable(path,maximum=32*1024**2):
    with open(path,'rb') as stream:
        before=os.fstat(stream.fileno());body=stream.read(maximum+1);after=os.fstat(stream.fileno())
    need(len(body)<=maximum and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'qualification_read_changed')
    return body


def _livepatch_process(path):
    raw=(path/'stat').read_text();head,tail=raw.rsplit(') ',1);fields=tail.split()
    need(head.startswith(path.name+' (') and len(fields)>=20 and fields[19].isdecimal(),'livepatch_process_invalid')
    uids=next((line.split()[1:] for line in (path/'status').read_text().splitlines() if line.startswith('Uid:')),None)
    executable=os.readlink(path/'exe');body=_read_stable(path/'exe')
    info=os.stat(path/'exe');namespace=os.readlink(path/'ns/mnt');ns=os.stat(path/'ns/mnt')
    return {'pid':int(path.name),'uids':uids,'start_ticks':int(fields[19]),'exe':executable,'exe_sha256':sha(body),
        'exe_identity':{'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,'gid':info.st_gid,
            'mode':stat.S_IMODE(info.st_mode),'size':info.st_size},
        'namespace':namespace,'namespace_identity':{'dev':ns.st_dev,'ino':ns.st_ino,'uid':ns.st_uid,
            'gid':ns.st_gid,'mode':stat.S_IMODE(ns.st_mode)},'cgroup':(path/'cgroup').read_text().strip(),
        'root':os.readlink(path/'root'),'cwd':os.readlink(path/'cwd')}


def capture_livepatch_aliases(roots,aliases,*,proc=Path('/proc')):
    """Only the observed process/namespace/12 mappings; not a general snap rule."""
    proc=Path(proc);roots=sorted(map(Path,roots),key=str);aliases=sorted(map(Path,aliases),key=str)
    need(roots==sorted(ALIAS_LEAVES,key=str) and len(aliases)==6,'exact_livepatch_leaf_scope_required')
    pid=proc/str(LIVEPATCH_PID);before=_livepatch_process(pid)
    need((proc/'sys/kernel/random/boot_id').read_text().strip()==LIVEPATCH_BOOT
         and before['pid']==LIVEPATCH_PID and before['uids']==['0']*4 and before['start_ticks']==LIVEPATCH_START
         and before['exe']==LIVEPATCH_EXE and before['exe_sha256']==LIVEPATCH_EXE_SHA
         and before['exe_identity']==LIVEPATCH_EXE_IDENTITY and before['namespace']==LIVEPATCH_NAMESPACE
         and before['namespace_identity']==LIVEPATCH_NS_IDENTITY
         and before['cgroup']==LIVEPATCH_CGROUP and before['root']=='/'
         and before['cwd']=='/var/snap/canonical-livepatch/418','exact_livepatch_process_required')
    body=_read_stable(pid/'mountinfo',8*1024**2);need(sha(body)==LIVEPATCH_MOUNTS_SHA,'exact_livepatch_mounts_required')
    members=[];count=0;started=time.monotonic()
    for path in proc.iterdir():
        if not path.name.isdecimal():continue
        count+=1;need(count<=100000 and time.monotonic()-started<60,'livepatch_membership_bound')
        try:
            if os.readlink(path/'ns/mnt')==LIVEPATCH_NAMESPACE:members.append(int(path.name))
        except FileNotFoundError:continue
        except PermissionError:raise Refused('livepatch_membership_incomplete') from None
    need(sorted(members)==[LIVEPATCH_PID],'exact_livepatch_membership_required')
    rows=mount_rows(body.decode());mappings=[]
    expected={LIVEPATCH_PREFIX/str(path).lstrip('/') for path in (*roots,*aliases)}
    for root in roots:
        info=identity(root);device=str(os.major(info['dev']))+':'+str(os.minor(info['dev']))
        for mount in rows:
            relative=Path(mount['root'])
            if mount['device']!=device or not under(root,relative):continue
            alias=Path(mount['target'])/root.relative_to(relative)
            if alias in roots or alias in aliases:continue
            need(alias in expected,'unobserved_livepatch_alias')
            exposed=pid/'root'/str(alias).lstrip('/')
            need(identity(exposed)==info,'livepatch_alias_inode_changed')
            mappings.append({'namespace':LIVEPATCH_NAMESPACE,'mount':mount,'alias':str(alias),
                'leaf':str(root),'leaf_identity':info})
    need(len(mappings)==12 and {Path(item['alias']) for item in mappings}==expected,'exact_twelve_livepatch_aliases_required')
    need(_livepatch_process(pid)==before and _read_stable(pid/'mountinfo',8*1024**2)==body
         and (proc/'sys/kernel/random/boot_id').read_text().strip()==LIVEPATCH_BOOT,'livepatch_snapshot_changed')
    return {'boot_id':LIVEPATCH_BOOT,'process':before,'members':members,'mountinfo_sha256':sha(body),
        'roots':[str(path) for path in roots],'aliases':[str(path) for path in aliases],
        'mappings':sorted(mappings,key=lambda item:item['alias'])}


def _alias_record(receipt_sha,roots,aliases):
    info=file_record(ALIAS_RECEIPT);body=ALIAS_RECEIPT.read_bytes()
    need(re.fullmatch('[0-9a-f]{64}',receipt_sha or '') and sha(body)==receipt_sha
         and file_record(ALIAS_RECEIPT)==info,'external_alias_qualification_required')
    value=json.loads(body)
    need(value.get('version')==1 and value.get('kind')=='cycle4-livepatch-hostfs-reclaim-qualification'
         and value.get('script_sha256')==sha(Path(__file__).read_bytes())
         and value.get('original_source_sha256')==ORIGINAL_RECLAIM_SHA
         and file_record(ORIGINAL_RECLAIM)['sha256']==ORIGINAL_RECLAIM_SHA
         and value.get('original_source_identity')==file_record(ORIGINAL_RECLAIM)
         and value.get('original_guard_denied') is True and value.get('original_error')=='unknown_ancestor_mount_alias'
         and value.get('read_only') is True and value.get('maximum_attempts')==1,'source_bound_alias_qualification_required')
    need(load(ALIAS_INTENT)=={'version':1,'maximum_attempts':1,'script_sha256':value['script_sha256'],
        'original_source_sha256':ORIGINAL_RECLAIM_SHA},'alias_qualification_intent_changed')
    _,edge_sha,manifest_sha=bound_edge_bridge()
    need(manifest_sha==ALIAS_MANIFEST_SHA and edge_sha==ALIAS_EDGE_SHA
         and value['live_boundary']['current_source_manifest_sha256']==manifest_sha
         and value['live_boundary']['edge_readmission_sha256']==edge_sha,'alias_qualification_boundary_changed')
    need(value['snapshot']['roots']==[str(p) for p in sorted(map(Path,roots),key=str)]
         and value['snapshot']['aliases']==[str(p) for p in sorted(map(Path,aliases),key=str)],'alias_qualification_scope_changed')
    return value


def validate_livepatch_aliases(receipt_sha,roots,aliases,*,proc=Path('/proc'),live_boundary=None,retained_data_qualification_sha=None,metadata_qualification_sha=None):
    if metadata_qualification_sha is not None:
        need(receipt_sha==FROZEN_ALIAS_SHA and retained_data_qualification_sha==FROZEN_DATA_SHA,'exact_metadata_predecessor_pins_required')
        return validate_discovery_metadata(metadata_qualification_sha,roots,aliases,proc=proc,live_boundary=live_boundary)['retained_data_qualification']['alias_qualification']
    if retained_data_qualification_sha is not None:
        need(receipt_sha==FROZEN_ALIAS_SHA,'exact_historical_alias_pin_required')
        return validate_retained_data_scope(retained_data_qualification_sha,roots,aliases,proc=proc,live_boundary=live_boundary)['alias_qualification']
    value=_alias_record(receipt_sha,roots,aliases)
    need(value['snapshot']==capture_livepatch_aliases(roots,aliases,proc=proc),'livepatch_qualification_stale')
    if live_boundary is not None:need(value['live_boundary']==live_boundary,'alias_qualification_boundary_changed')
    return value


def qualify_livepatch_aliases(boundary):
    roots=sorted(ALIAS_LEAVES,key=str);engine=Engine();aliases=engine.aliases(roots)
    tokens=sorted({engine.validate_receipts(*engine.whitelist[root]) for root in roots})
    original_identity=file_record(ORIGINAL_RECLAIM)
    need(original_identity['sha256']==ORIGINAL_RECLAIM_SHA,'original_reclaim_source_required')
    source_sha=sha(Path(__file__).read_bytes())
    before=boundary.check()
    need(before['current_source_manifest_sha256']==ALIAS_MANIFEST_SHA and before['edge_readmission_sha256']==ALIAS_EDGE_SHA,
         'fixed_livepatch_boundary_required')
    safe_path(ALIAS_SCOPE);need(not ALIAS_SCOPE.exists(),'alias_qualification_already_consumed')
    ALIAS_SCOPE.mkdir(mode=0o700,parents=True);sync(ALIAS_SCOPE.parent)
    new(ALIAS_INTENT,{'version':1,'maximum_attempts':1,'script_sha256':source_sha,
        'original_source_sha256':ORIGINAL_RECLAIM_SHA})
    spec=importlib.util.spec_from_file_location('reclaim_original_unknown_alias_guard',ORIGINAL_RECLAIM)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    try:module.system_guard(roots,aliases,tokens)
    except module.Refused as error:
        need(str(error)=='unknown_ancestor_mount_alias','exact_original_alias_denial_required')
    else:raise Refused('original_guard_must_deny_alias')
    snapshot=capture_livepatch_aliases(roots,aliases)
    need(capture_livepatch_aliases(roots,aliases)==snapshot and boundary.check()==before
         and file_record(ORIGINAL_RECLAIM)==original_identity
         and sha(Path(__file__).read_bytes())==source_sha,'alias_qualification_boundary_changed')
    new(ALIAS_RECEIPT,{'version':1,'kind':'cycle4-livepatch-hostfs-reclaim-qualification','maximum_attempts':1,
        'script_sha256':source_sha,'original_source_sha256':ORIGINAL_RECLAIM_SHA,
        'original_source_identity':original_identity,'original_guard_denied':True,'original_error':'unknown_ancestor_mount_alias','read_only':True,
        'live_boundary':before,'snapshot':snapshot})
    return {'alias_qualification_sha256':sha(ALIAS_RECEIPT.read_bytes()),'alias_count':12,'guard_accepted':False}


# A new explicit envelope preserves the consumed bfe helper/33 alias admission.
FROZEN_RECLAIM=Path('/usr/local/libexec/devres-upgrade-3dae7d91/reclaim-completed-fixtures.livepatch-bfe19552.py')
FROZEN_RECLAIM_SHA='bfe195526a19847a06fc352f6d407c65f34356ad309ecb2e7352814f9f43561a'
FROZEN_ALIAS_SHA='33acd1ef6093aae4129a0cf2c632f77895333d7c9a321ee605cdb6afdb6b5de9'
DATA_SCOPE=Path('/var/lib/devres-production-reclaim-qualifications/3dae7d91-20261117-producer-data-v1')
DATA_INTENT=DATA_SCOPE/'intent.json'
DATA_RECEIPT=DATA_SCOPE/'qualification.json'
DATA_JOURNAL=Path('/var/lib/devres-production-reclaim/3dae7d91-20261117-producer-data-v1')
PRODUCER_CYCLE=CYCLES[0]
PRODUCER_ROOT=PRODUCER_CYCLE.bundle/'checkpoint-volume/proof-successor-v1'
PRODUCER_BODY_NAMES=('pg-checkpoint','pg-clone','fallback-cache','rehearsal/cache','rehearsal/writer-cache')
PRODUCER_BODY_AUTHORITY={'pg-checkpoint':(70,70,0o700),'pg-clone':(70,70,0o700),
    'fallback-cache':(0,0,0o700),'rehearsal/cache':(65532,65532,0o700),
    'rehearsal/writer-cache':(65532,65532,0o2770)}
PRODUCER_PINS={
    PRODUCER_CYCLE.install/'proof-continuation.py':'1f547b63a08f3ff5b5dd91944cbd092acc243df9f1d03656831edb80a33ac43d',
    PRODUCER_CYCLE.install/'physical-checkpoint.py':'c8efc0d0e398e057dfb0395db18e74e4bdbb95998c93e1f64ea797b5eadd2eef',
    PRODUCER_CYCLE.bundle/'checkpoint-volume/completed.json':'0ddc0a989e44e2d4c9ae680ebce8918218a2557c0a43502b57461c2b03d82a60',
    PRODUCER_CYCLE.bundle/'checkpoint-volume/backup-receipt.json':'8a0c3f3a5db9a6528fcdafc40e480b123bc47d18a5bb5b95d0dbcea71f25e3c1',
    PRODUCER_ROOT/'admission.json':'e056d3eef3263134948491d55056ba1a33c4833f6c9738023a0c244dde277e00',
    PRODUCER_ROOT/'completed.json':'fccedcb2bb880607426b2eb18b6a757bda43bdcf17121cc9cc1283ae1afa39ae',
    PRODUCER_ROOT/'backup-receipt.json':'a66f78e586eac3cc7efa496177aff78dfe341afd6a8a0742481c00d19e788ea4',
    PRODUCER_ROOT/'cache-baselines.json':'abfe1c988855985aec8350af3f31009eed5635b5307adf93fb45017f55dbc163',
    PRODUCER_ROOT/'pg-file-manifest.jsonl':'454b91828731d83441a8056338161ef448e376b682eccbb2f75bc8a8f27941eb',
    PRODUCER_ROOT/'checkpoint-completed.json':'2342c68c03fd2b1c43ef9176e4374f414d1e597c0232f50b3440ea0085f608dd'}


def frozen_reclaim():
    need(file_record(FROZEN_RECLAIM)['sha256']==FROZEN_RECLAIM_SHA,'exact_frozen_reclaim_required')
    spec=importlib.util.spec_from_file_location('reclaim_preserved_bfe_namespace_authority',FROZEN_RECLAIM)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    need(file_record(FROZEN_RECLAIM)['sha256']==FROZEN_RECLAIM_SHA,'exact_frozen_reclaim_required')
    return module


def producer_canonical(path):
    path=Path(path)
    source=PRODUCER_CYCLE.work/'checkpoint-state'
    return PRODUCER_CYCLE.bundle/'checkpoint-volume'/path.relative_to(source) if under(path,source) else path


def producer_data_projection(selected,delete):
    """Existing complete provenance plus structural noninterference; no body read."""
    canonical=Engine(cycles=CYCLES).canonical
    selected=[canonical(Path(path)) for path in selected];delete=[canonical(Path(path)) for path in delete]
    need(sorted(selected,key=str)==sorted(ALIAS_LEAVES,key=str),'exact_retained_data_leaf_scope_required')
    safe_path(PRODUCER_ROOT);parent=identity(PRODUCER_ROOT)
    need(parent['uid']==os.geteuid() and parent['mode']==0o700,'private_producer_root_required')
    pins={}
    for path,wanted in PRODUCER_PINS.items():
        record=file_record(path);need(record['sha256']==wanted,'retained_data_producer_changed');pins[str(path)]=record
    cp=PRODUCER_CYCLE.bundle/'checkpoint-volume';admission=load(PRODUCER_ROOT/'admission.json')
    completed=load(PRODUCER_ROOT/'completed.json');outer=load(cp/'completed.json')
    checkpoint=load(PRODUCER_ROOT/'checkpoint-completed.json')
    cache_sha=pins[str(PRODUCER_ROOT/'cache-baselines.json')]['sha256']
    pg_sha=pins[str(PRODUCER_ROOT/'pg-file-manifest.jsonl')]['sha256']
    need(admission.get('version')==1 and admission.get('kind')=='isolated-proof-successor-v1'
         and admission.get('maximum_attempts')==1 and admission.get('only_change')=='restore_original_writer_cache_ceiling'
         and producer_canonical(admission.get('successor_scope',''))==PRODUCER_ROOT
         and producer_canonical(admission.get('original_scope',''))==cp
         and admission.get('source_sha256')==pins[str(PRODUCER_CYCLE.install/'proof-continuation.py')]['sha256']
         and admission.get('checkpoint_source_sha256')==pins[str(PRODUCER_CYCLE.install/'physical-checkpoint.py')]['sha256']
         and admission.get('global_manifest_sha256')==file_record(PRODUCER_CYCLE.work/'source-manifest.json')['sha256'],
         'retained_data_admission_changed')
    need(admission.get('immutable_sha256',{}).get('cache-baselines.json')==cache_sha
         and completed.get('cache_baselines_sha256')==cache_sha and file_record(cp/'cache-baselines.json')['sha256']==cache_sha
         and completed.get('pg_files_sha256')==checkpoint.get('pg_files_sha256')==pg_sha
         and completed.get('checkpoint_receipt_sha256')==pins[str(PRODUCER_ROOT/'checkpoint-completed.json')]['sha256']
         and outer.get('proof_continuation',{}).get('admission_sha256')==pins[str(PRODUCER_ROOT/'admission.json')]['sha256']
         and outer.get('proof_continuation',{}).get('source_sha256')==admission['source_sha256']
         and completed.get('old_clone_verified') is True and completed.get('fallback_writer_verified') is True,
         'complete_retained_data_provenance_required')
    roots=[]
    body_paths=[PRODUCER_ROOT/name for name in PRODUCER_BODY_NAMES]
    need(all(not under(path,other) and not under(other,path) for path in body_paths for other in [*selected,*delete]),
         'retained_data_deletion_overlap')
    expected=PRODUCER_BODY_AUTHORITY
    for name in PRODUCER_BODY_NAMES:
        path=PRODUCER_ROOT/name;safe_path(path);info=identity(path)
        need(info['dev']==parent['dev'] and tuple(info[key] for key in ('uid','gid','mode'))==expected[name],
             'retained_data_root_authority_changed')
        need(not any(under(path,other) or under(other,path) for other in [*selected,*delete]),
             'retained_data_deletion_overlap')
        need(all((info['dev'],info['ino'])!=(identity(other)['dev'],identity(other)['ino']) for other in [*selected,*delete]),
             'retained_data_inode_overlap')
        alias=PRODUCER_CYCLE.work/'checkpoint-state'/path.relative_to(cp)
        safe_path(alias);need(identity(alias)==info,'retained_data_work_alias_changed')
        roots.append({'path':str(path),'identity':info,'work_alias':str(alias)})
    need(len({(item['identity']['dev'],item['identity']['ino']) for item in roots})==5
         and all(not under(Path(first['path']),Path(second['path'])) for first in roots for second in roots if first is not second),
         'distinct_retained_body_roots_required')
    # Explicit backup artifacts are always metadata, never hidden by a body prune.
    for path in (cp/'backup-receipt.json',PRODUCER_ROOT/'backup-receipt.json'):
        backup=load(path)
        need(backup.get('verified') is True and type(backup.get('artifacts')) is list,'verified_retained_backup_required')
        need(any(Path(item['path']).name=='cache-baselines.json' and item['sha256']==cache_sha for item in backup['artifacts']),
             'retained_cache_manifest_not_bound')
        for item in backup['artifacts']:
            artifact=producer_canonical(item['path'])
            need(not any(under(artifact,Path(root['path'])) for root in roots),'retained_data_metadata_overlap')
            need(file_record(artifact)['sha256']==item['sha256'],'retained_data_backup_artifact_changed')
    return {'roots':roots,'producer_root_identity':parent,'provenance':pins,
        'payloads_rehashed':False,'preservation_scope':'structurally_disjoint_unlink_only'}


def _retained_data_record(receipt_sha,selected,aliases,delete=None,*,proc=Path('/proc'),live_boundary=None):
    safe_path(JOURNAL);safe_path(DATA_JOURNAL)
    info=file_record(DATA_RECEIPT);body=DATA_RECEIPT.read_bytes()
    need(re.fullmatch('[0-9a-f]{64}',receipt_sha or '') and sha(body)==receipt_sha
         and file_record(DATA_RECEIPT)==info,'external_retained_data_qualification_required')
    value=json.loads(body)
    need(value.get('version')==1 and value.get('kind')=='cycle4-producer-data-reclaim-qualification'
         and value.get('script_sha256')==sha(Path(__file__).read_bytes()) and value.get('maximum_attempts')==1
         and value.get('previous_source_sha256')==FROZEN_RECLAIM_SHA
         and value.get('previous_qualification_sha256')==FROZEN_ALIAS_SHA
         and value.get('previous_source_identity')==file_record(FROZEN_RECLAIM)
         and value.get('payloads_rehashed') is False
         and value.get('previous_reclaim_journal')=={'path':str(JOURNAL),'absent':True}
         and value.get('new_reclaim_journal')==str(DATA_JOURNAL) and not JOURNAL.exists(),
         'source_bound_retained_data_qualification_required')
    need(load(DATA_INTENT)=={'version':1,'maximum_attempts':1,'script_sha256':value['script_sha256'],
        'previous_source_sha256':FROZEN_RECLAIM_SHA,'previous_qualification_sha256':FROZEN_ALIAS_SHA,
        'previous_journal':str(JOURNAL),'new_journal':str(DATA_JOURNAL)},'retained_data_intent_changed')
    old=frozen_reclaim()
    historical=old.validate_livepatch_aliases(FROZEN_ALIAS_SHA,selected,aliases,proc=proc,
        live_boundary=live_boundary if live_boundary is not None else value['live_boundary'])
    need(historical==value['alias_qualification'],'historical_alias_qualification_changed')
    if delete is None:
        engine=Engine(cycles=CYCLES);delete=[root for leaf in selected for root in engine.delete_roots(Path(leaf),engine.whitelist[Path(leaf)][1])]
    need(value['producer_data']==producer_data_projection(selected,delete),'retained_data_projection_changed')
    return value


def validate_retained_data_scope(receipt_sha,selected,aliases,delete=None,*,proc=Path('/proc'),live_boundary=None):
    return _retained_data_record(receipt_sha,selected,aliases,delete,proc=proc,live_boundary=live_boundary)


def qualify_retained_data_scope(boundary):
    old=frozen_reclaim();selected=list(ALIAS_LEAVES);engine=Engine(cycles=CYCLES);aliases=engine.aliases(selected)
    delete=[root for leaf in selected for root in engine.delete_roots(leaf,engine.whitelist[leaf][1])]
    before=boundary.check();source_sha=sha(Path(__file__).read_bytes());source_identity=file_record(FROZEN_RECLAIM)
    need(not DATA_SCOPE.exists(),'retained_data_qualification_already_consumed')
    safe_path(JOURNAL);safe_path(DATA_JOURNAL)
    need(not JOURNAL.exists() and not DATA_JOURNAL.exists(),'only_inspect_only_fresh_reclaim_continues')
    safe_path(DATA_SCOPE)
    DATA_SCOPE.mkdir(mode=0o700,parents=True);sync(DATA_SCOPE.parent)
    new(DATA_INTENT,{'version':1,'maximum_attempts':1,'script_sha256':source_sha,
        'previous_source_sha256':FROZEN_RECLAIM_SHA,'previous_qualification_sha256':FROZEN_ALIAS_SHA,
        'previous_journal':str(JOURNAL),'new_journal':str(DATA_JOURNAL)})
    historical=old.validate_livepatch_aliases(FROZEN_ALIAS_SHA,selected,aliases,live_boundary=before)
    projection=producer_data_projection(selected,delete)
    safe_path(JOURNAL);safe_path(DATA_JOURNAL)
    need(producer_data_projection(selected,delete)==projection and boundary.check()==before
         and old.validate_livepatch_aliases(FROZEN_ALIAS_SHA,selected,aliases,live_boundary=before)==historical
         and sha(Path(__file__).read_bytes())==source_sha and file_record(FROZEN_RECLAIM)==source_identity
         and not JOURNAL.exists() and not DATA_JOURNAL.exists(),'retained_data_qualification_bookend_changed')
    new(DATA_RECEIPT,{'version':1,'kind':'cycle4-producer-data-reclaim-qualification','maximum_attempts':1,
        'script_sha256':source_sha,'previous_source_sha256':FROZEN_RECLAIM_SHA,
        'previous_source_identity':source_identity,'previous_qualification_sha256':FROZEN_ALIAS_SHA,
        'alias_qualification':historical,'live_boundary':before,'producer_data':projection,'payloads_rehashed':False,
        'previous_reclaim_journal':{'path':str(JOURNAL),'absent':True},'new_reclaim_journal':str(DATA_JOURNAL)})
    return {'retained_data_qualification_sha256':sha(DATA_RECEIPT.read_bytes()),'retained_body_root_count':5,
        'payloads_rehashed':False,'guard_accepted':False}


# The previous data admission remains valid only through its exact original module.
FROZEN_DATA_RECLAIM=Path('/usr/local/libexec/devres-upgrade-3dae7d91/reclaim-completed-fixtures.producer-data-0e78bad.py')
FROZEN_DATA_RECLAIM_SHA='0e78bad73c08399d82f6212ce27a7fbf75dab47fa9e66daf84592d1811e32111'
FROZEN_DATA_SHA='a0a8a00ac6fd8fea3306d356aacceafc20cd3cad8b6e999547a5590dd399d964'
METADATA_SCOPE=Path('/var/lib/devres-production-reclaim-qualifications/3dae7d91-20261117-discovery-metadata-v1')
METADATA_INTENT=METADATA_SCOPE/'intent.json'
METADATA_RECEIPT=METADATA_SCOPE/'qualification.json'
METADATA_JOURNAL=Path('/var/lib/devres-production-reclaim/3dae7d91-20261117-discovery-metadata-v1')
DISCOVERY_OPERATIONAL_CACHE=Path('/tmp/devres-reclaim-discovery-3dae7d91-20261117')
DISCOVERY_WORK=CYCLES[0].work
DISCOVERY_ROOT=DISCOVERY_WORK/'.kube/cache/discovery/127.0.0.1_6443'
DISCOVERY_RELATIVE=('servergroups.json',*(name+'/serverresources.json' for name in (
    'admissionregistration.k8s.io/v1','apiextensions.k8s.io/v1','apiregistration.k8s.io/v1','apps/v1',
    'authentication.k8s.io/v1','authorization.k8s.io/v1','autoscaling/v1','autoscaling/v2','batch/v1',
    'certificates.k8s.io/v1','coordination.k8s.io/v1','discovery.k8s.io/v1','events.k8s.io/v1',
    'flowcontrol.apiserver.k8s.io/v1','gateway.networking.k8s.io/v1','gateway.networking.k8s.io/v1beta1',
    'helm.cattle.io/v1','k3s.cattle.io/v1','metrics.k8s.io/v1beta1','networking.k8s.io/v1','node.k8s.io/v1',
    'policy/v1','rbac.authorization.k8s.io/v1','resource.k8s.io/v1','scheduling.k8s.io/v1','storage.k8s.io/v1',
    'storagemigration.k8s.io/v1','v1')))


def discovery_environment():
    """Checked before frozen constructors or any kubectl-capable guard."""
    need(os.environ.get('KUBECACHEDIR')==str(DISCOVERY_OPERATIONAL_CACHE),'fixed_discovery_cache_environment_required')
    safe_path(DISCOVERY_OPERATIONAL_CACHE);value=identity(DISCOVERY_OPERATIONAL_CACHE)
    need(value['uid']==0 and value['gid']==0 and value['mode']==0o700,'private_discovery_operational_cache_required')
    mounts=mount_rows(Path('/proc/self/mountinfo').read_text())
    parent=Path('/tmp')
    need(not any(under(Path(row['target']),DISCOVERY_OPERATIONAL_CACHE) for row in mounts),
         'discovery_cache_mount_alias_refused')
    parent_rows=[row for row in mounts if under(parent,Path(row['target']))]
    cache_rows=[row for row in mounts if under(DISCOVERY_OPERATIONAL_CACHE,Path(row['target']))]
    need(parent_rows and cache_rows,'discovery_cache_mount_mapping_required')
    covering=lambda rows:max(rows,key=lambda row:len(Path(row['target']).parts))
    need(covering(parent_rows)==covering(cache_rows),'discovery_cache_mount_alias_refused')
    return {'KUBECACHEDIR':str(DISCOVERY_OPERATIONAL_CACHE),'identity':value,'covering_mount':covering(cache_rows)}


def discovery_projection():
    expected={DISCOVERY_ROOT/name for name in DISCOVERY_RELATIVE}
    expected_dirs={p for path in expected for p in path.parents if p==DISCOVERY_ROOT or DISCOVERY_ROOT in p.parents}
    actual_files=set();actual_dirs={DISCOVERY_ROOT};count=0
    safe_path(DISCOVERY_ROOT)
    for folder,dirs,files in os.walk(DISCOVERY_ROOT,followlinks=False):
        current=Path(folder)
        for name in [*dirs,*files]:
            count+=1;need(count<=100,'discovery_membership_bound')
            path=current/name;safe_path(path)
            if name in dirs:actual_dirs.add(path)
            else:actual_files.add(path)
    need(actual_files==expected and actual_dirs==expected_dirs,'exact_discovery_metadata_membership_required')
    parents={}
    for path in sorted({p for file in expected for p in file.parents if p==DISCOVERY_WORK or DISCOVERY_WORK in p.parents},key=str):
        safe_path(path);value=identity(path)
        need(value['uid']==0 and value['gid']==0 and value['mode']==0o700,'private_discovery_ancestor_required')
        parents[str(path)]=value
    need(len(expected)==29 and len(parents)==58,'exact_discovery_layout_required')
    records={}
    for path in sorted(expected,key=str):
        record=file_record(path,private=False,maximum=65536)
        need(record['uid']==0 and record['gid']==0 and record['mode']==0o660 and record['size']<=65536,
             'exact_discovery_file_authority_required')
        body=path.read_bytes();need(sha(body)==record['sha256'],'discovery_metadata_changed')
        value=json.loads(body)
        if path.name=='servergroups.json':
            need(type(value) is dict and set(value)=={'apiVersion','kind','groups'}
                 and value['kind']=='APIGroupList' and value['apiVersion']=='v1' and type(value['groups']) is list,
                 'discovery_schema_required')
        else:
            group=str(path.parent.relative_to(DISCOVERY_ROOT))
            need(type(value) is dict and set(value)=={'apiVersion','kind','groupVersion','resources'}
                 and value['kind']=='APIResourceList' and value['apiVersion']=='v1'
                 and value['groupVersion']==group and type(value['resources']) is list,'discovery_schema_required')
        need(file_record(path,private=False,maximum=65536)==record,'discovery_metadata_changed');records[str(path)]=record
    return {'files':records,'parents':parents,'file_count':29,'ancestor_count':58,
        'payloads_are_discovery_metadata':True,'k3s_library_linkage_verified':False}


def frozen_data_reclaim():
    info=file_record(FROZEN_DATA_RECLAIM)
    need(info['sha256']==FROZEN_DATA_RECLAIM_SHA,'exact_frozen_data_reclaim_required')
    spec=importlib.util.spec_from_file_location('reclaim_preserved_0e78_data_authority',FROZEN_DATA_RECLAIM)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    need(file_record(FROZEN_DATA_RECLAIM)==info,'exact_frozen_data_reclaim_required')
    return module


def discovery_journal_history(*,fresh=False):
    for path in (JOURNAL,DATA_JOURNAL,METADATA_JOURNAL):safe_path(path)
    need(not JOURNAL.exists() and not DATA_JOURNAL.exists()
         and (not fresh or not METADATA_JOURNAL.exists()),'only_inspect_only_metadata_continues')
    return {'absent_previous_journals':[str(JOURNAL),str(DATA_JOURNAL)],'new_journal':str(METADATA_JOURNAL)}


def discovery_intent(source_sha):
    return {'version':1,'maximum_attempts':1,'script_sha256':source_sha,
        'previous_source_sha256':FROZEN_DATA_RECLAIM_SHA,'previous_qualification_sha256':FROZEN_DATA_SHA,
        'history':discovery_journal_history()}


def preflight_discovery_metadata(receipt_sha):
    # No constructor, historical module, kubectl or network call before this pin.
    need(re.fullmatch('[0-9a-f]{64}',receipt_sha or ''),'external_discovery_qualification_required')
    environment=discovery_environment()
    info=file_record(METADATA_RECEIPT);body=METADATA_RECEIPT.read_bytes()
    need(sha(body)==receipt_sha and file_record(METADATA_RECEIPT)==info,'external_discovery_qualification_required')
    value=json.loads(body)
    need(value.get('version')==1 and value.get('kind')=='cycle4-discovery-metadata-reclaim-qualification'
         and value.get('maximum_attempts')==1 and value.get('script_sha256')==sha(Path(__file__).read_bytes())
         and value.get('environment')==environment,'source_bound_discovery_qualification_required')
    return value


def validate_discovery_metadata(receipt_sha,selected,aliases,delete=None,*,proc=Path('/proc'),live_boundary=None):
    value=preflight_discovery_metadata(receipt_sha)
    environment=value['environment'];history=discovery_journal_history();source_sha=sha(Path(__file__).read_bytes())
    need(value.get('previous_source_sha256')==FROZEN_DATA_RECLAIM_SHA
         and value.get('previous_qualification_sha256')==FROZEN_DATA_SHA
         and value.get('previous_source_identity')==file_record(FROZEN_DATA_RECLAIM)
         and value.get('environment')==environment and value.get('history')==history,
         'source_bound_discovery_qualification_required')
    need(load(METADATA_INTENT)==discovery_intent(source_sha),'discovery_qualification_intent_changed')
    old=frozen_data_reclaim()
    historical=old.validate_retained_data_scope(FROZEN_DATA_SHA,selected,aliases,delete=delete,proc=proc,
        live_boundary=live_boundary if live_boundary is not None else value['live_boundary'])
    need(historical==value['retained_data_qualification'],'historical_data_qualification_changed')
    need(value.get('previous_guard_denial')=={'denied':True,'reason':'protected_file_authority_changed',
         'source_sha256':FROZEN_DATA_RECLAIM_SHA},'previous_metadata_guard_denial_changed')
    need(discovery_projection()==value['discovery'],'discovery_projection_changed')
    need(discovery_environment()==environment and discovery_journal_history()==history,'discovery_validation_bookend_changed')
    return value


def previous_discovery_denial(old,selected,delete):
    engine=old.Engine(cycles=old.CYCLES,journal=old.DATA_JOURNAL,qualification_sha=old.FROZEN_ALIAS_SHA,
        retained_data_qualification_sha=FROZEN_DATA_SHA)
    try:engine.protected(selected,delete)
    except old.Refused as error:
        need(str(error)=='protected_file_authority_changed','exact_previous_metadata_authority_denial_required')
    else:raise Refused('previous_metadata_authority_denial_required')
    return {'denied':True,'reason':'protected_file_authority_changed','source_sha256':FROZEN_DATA_RECLAIM_SHA}


def qualify_discovery_metadata(boundary):
    environment=discovery_environment();history=discovery_journal_history(fresh=True)
    safe_path(METADATA_SCOPE);need(not METADATA_SCOPE.exists(),'discovery_qualification_already_consumed')
    old=frozen_data_reclaim();selected=list(ALIAS_LEAVES);engine=Engine(cycles=CYCLES);aliases=engine.aliases(selected)
    delete=[root for leaf in selected for root in engine.delete_roots(leaf,engine.whitelist[leaf][1])]
    source_sha=sha(Path(__file__).read_bytes());source_identity=file_record(FROZEN_DATA_RECLAIM)
    before=boundary.check();need(discovery_environment()==environment,'discovery_environment_changed')
    METADATA_SCOPE.mkdir(mode=0o700,parents=True);sync(METADATA_SCOPE.parent)
    new(METADATA_INTENT,discovery_intent(source_sha))
    projection=discovery_projection()
    historical=old.validate_retained_data_scope(FROZEN_DATA_SHA,selected,aliases,delete=delete,live_boundary=before)
    denial=previous_discovery_denial(old,selected,delete)
    need(boundary.check()==before and discovery_projection()==projection and discovery_environment()==environment
         and discovery_journal_history(fresh=True)==history and file_record(FROZEN_DATA_RECLAIM)==source_identity
         and sha(Path(__file__).read_bytes())==source_sha
         and old.validate_retained_data_scope(FROZEN_DATA_SHA,selected,aliases,delete=delete,live_boundary=before)==historical,
         'discovery_qualification_bookend_changed')
    new(METADATA_RECEIPT,{'version':1,'kind':'cycle4-discovery-metadata-reclaim-qualification','maximum_attempts':1,
        'script_sha256':source_sha,'previous_source_sha256':FROZEN_DATA_RECLAIM_SHA,
        'previous_source_identity':source_identity,'previous_qualification_sha256':FROZEN_DATA_SHA,
        'retained_data_qualification':historical,'live_boundary':before,'discovery':projection,'previous_guard_denial':denial,
        'environment':environment,'history':history})
    return {'metadata_qualification_sha256':sha(METADATA_RECEIPT.read_bytes()),'protected_discovery_file_count':29,
        'private_ancestor_count':58,'guard_accepted':False}


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    inspect=sub.add_parser('inspect');inspect.add_argument('--leaf',type=Path,action='append',required=True)
    inspect.add_argument('--output',type=Path,required=True)
    sub.add_parser('qualify-aliases');sub.add_parser('qualify-data-scope');sub.add_parser('qualify-discovery-metadata')
    inspect.add_argument('--alias-qualification-sha256');inspect.add_argument('--retained-data-qualification-sha256');inspect.add_argument('--metadata-qualification-sha256')
    apply=sub.add_parser('apply');apply.add_argument('--preview',type=Path,required=True)
    apply.add_argument('--preview-sha256',required=True);apply.add_argument('--script-sha256',required=True)
    apply.add_argument('--alias-qualification-sha256');apply.add_argument('--retained-data-qualification-sha256');apply.add_argument('--metadata-qualification-sha256')
    args=parser.parse_args();need(os.geteuid()==0,'root_required')
    qualification_sha=getattr(args,'alias_qualification_sha256',None)
    data_sha=getattr(args,'retained_data_qualification_sha256',None)
    metadata_sha=getattr(args,'metadata_qualification_sha256',None)
    if metadata_sha is not None:
        need(re.fullmatch('[0-9a-f]{64}',metadata_sha or ''),'external_discovery_qualification_required')
    if metadata_sha is not None:preflight_discovery_metadata(metadata_sha)
    elif args.operation=='qualify-discovery-metadata':discovery_environment()
    need(data_sha is None or qualification_sha==FROZEN_ALIAS_SHA,'historical_alias_pin_required_with_data_scope')
    engine=Engine(journal=METADATA_JOURNAL if metadata_sha is not None else DATA_JOURNAL if data_sha else JOURNAL,qualification_sha=qualification_sha,retained_data_qualification_sha=data_sha,metadata_qualification_sha=metadata_sha)
    with LiveBoundary() as boundary:
        if args.operation=='qualify-aliases':
            result=qualify_livepatch_aliases(boundary)
        elif args.operation=='qualify-data-scope':
            result=qualify_retained_data_scope(boundary)
        elif args.operation=='qualify-discovery-metadata':
            result=qualify_discovery_metadata(boundary)
        elif args.operation=='inspect':
            need(args.output.is_absolute() and Path('/tmp') in args.output.parents,'private_tmp_preview_required')
            if qualification_sha:validate_livepatch_aliases(qualification_sha,args.leaf,engine.aliases(args.leaf),live_boundary=boundary.check(),retained_data_qualification_sha=data_sha,metadata_qualification_sha=metadata_sha)
            value=engine.preview(args.leaf);value['live_boundary']=boundary.check();new(args.output,value)
            result={'preview':True,'preview_sha256':sha(encode(value)),
                'allocated_file_bytes':value['allocated_file_bytes'],'leaf_count':len(value['leaves'])}
        else:
            file_record(Path(__file__))
            value=load(args.preview)
            need(value.get('metadata_qualification_sha256')==metadata_sha,'external_metadata_qualification_changed')
            need(value.get('retained_data_qualification_sha256')==data_sha,'external_retained_data_qualification_changed')
            need(value.get('alias_qualification_sha256')==qualification_sha,'external_alias_qualification_changed')
            if qualification_sha:validate_livepatch_aliases(qualification_sha,value['leaves'],[Path(p) for p in value['aliases']],live_boundary=boundary.check(),retained_data_qualification_sha=data_sha,metadata_qualification_sha=metadata_sha)
            need(value.get('live_boundary')==boundary.check(),'external_live_boundary_changed')
            completed=engine.apply(value,args.preview_sha256,args.script_sha256)
            new(engine.journal/'live-boundary-completed.json',{'verified':True,
                'preview_sha256':args.preview_sha256,'fingerprint':boundary.check()})
            result={'reclaimed':True,'verified':completed['verified'],'free_bytes':completed['free_bytes']}
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except Exception:
        print(json.dumps({'ok':False,'reason':'reclaim_admission_or_operation_refused'}));sys.exit(1)
