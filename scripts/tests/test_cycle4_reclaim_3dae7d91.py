"""Reclaim is confined to completed disposable copies, with durable no-replay."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('cycle4_reclaim',ROOT/'deploy/production/cycle4_reclaim_3dae7d91.py')
n=importlib.util.module_from_spec(spec);sys.modules[spec.name]=n;spec.loader.exec_module(n)


def write(path,value):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    path.write_bytes(value if type(value) is bytes else n.encode(value));path.chmod(0o600)


def fixture(root):
    cycle=n.Cycle('fixture',root/'bundle',root/'work',root/'install')
    for path in (cycle.bundle,cycle.work,cycle.install):path.mkdir(mode=0o700)
    cp=cycle.bundle/'checkpoint-volume';volume=cycle.bundle/'restore-rehearsal-volume'
    cp.mkdir(mode=0o700);volume.mkdir(mode=0o700)
    for relative in n.LEAVES:(cycle.bundle/relative).mkdir(mode=0o700)
    token='a'*24
    for name,value in {
        'owner.json':{'token':token},
        'clone-cleanup-completed.json':{'all_owned_containers_removed':True,'owned_network_removed':True,'physical_checkpoint_retained':True},
        'clone-proof-result.json':{'isolated_clone_only':True,'provider_source_requests':0},
        'proof-intent.json':{'token':token,'no_production_mount':True},
        'completed.json':{'old_clone_verified':True},'baseline.json':{'production':'preserve'},
    }.items():write(cp/name,value)
    write(volume/'owner.json',{'token':token,'scope':{'device':volume.stat().st_dev,'inode':volume.stat().st_ino}})
    write(volume/'cleanup-completed.json',{'token':token,'owned_container_removed':True,'golden_retained':True})
    write(volume/'real-pg-proof.json',{'marker_removed':True,'no_kubernetes_commands':True,'no_production_credentials':True,'no_network':True})
    write(cycle.install/'upgrade-controller.py',b'# exact frozen first-party source\n')
    write(cycle.work/'source-manifest.json',{'upgrade-controller.py':hashlib.sha256((cycle.install/'upgrade-controller.py').read_bytes()).hexdigest()})
    write(cp/'backup-receipt.json',{'verified':True,'artifacts':[{
        'path':str(cp/'baseline.json'),'sha256':hashlib.sha256((cp/'baseline.json').read_bytes()).hexdigest()}]})
    write(cp/'pg-checkpoint'/'PG_VERSION',b'18\n')
    write(cp/'fallback-cache'/'writer'/'keep',b'baseline')
    return cycle


class ReclaimTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.cycle=fixture(self.root)
        self.guard=Mock(return_value={'verified':True})
        self.engine=n.Engine((self.cycle,),self.root/'new-journal',self.guard)
        self.clone=self.cycle.bundle/'checkpoint-volume/pg-clone'
        self.rehearsal=self.cycle.bundle/'checkpoint-volume/rehearsal'
        self.runtime=self.cycle.bundle/'restore-rehearsal-volume/runtime'
    def apply(self,preview):return self.engine.apply(preview,n.sha(n.encode(preview)),preview['script_sha256'])
    def test_preview_is_nonmutating_and_apply_preserves_leaf_and_all_protected_state(self):
        write(self.clone/'data'/'block',b'x'*8192)
        before=n.identity(self.clone);metadata=n.file_record(self.cycle.bundle/'checkpoint-volume/baseline.json')
        preview=self.engine.preview([self.clone])
        self.assertTrue((self.clone/'data/block').exists());self.assertFalse(self.engine.journal.exists())
        self.assertGreaterEqual(preview['allocated_file_bytes'],8192)
        self.assertTrue(self.apply(preview)['verified']);self.assertEqual(n.identity(self.clone),before)
        self.assertFalse(any(self.clone.iterdir()));self.assertEqual(n.file_record(self.cycle.bundle/'checkpoint-volume/baseline.json'),metadata)
        self.assertEqual((self.cycle.bundle/'checkpoint-volume/pg-checkpoint/PG_VERSION').read_bytes(),b'18\n')
        self.assertTrue((self.engine.journal/'intent.json').exists())
        self.assertFalse(n.load(self.engine.journal/'completed.json')['atime_equivalence_claimed'])
    def test_rehearsal_and_runtime_preserve_config_journal_and_log_children(self):
        for path in (self.rehearsal/'cache/data',self.rehearsal/'writer-cache/data',self.runtime/'isolated-pv/18/docker/data',
            self.runtime/'cache-serving/data',self.runtime/('.failed-writer-'+'b'*24)/'data'):
            write(path,b'disposable')
        retained=(self.rehearsal/'files/serving.toml',self.runtime/'controller/rollback-intent.json',
                  self.runtime/'restore/restored.json',self.runtime/'stdout.log')
        for path in retained:write(path,b'keep')
        before={str(path):n.file_record(path) for path in retained}
        preview=self.engine.preview([self.rehearsal,self.runtime]);self.apply(preview)
        self.assertEqual({str(path):n.file_record(path) for path in retained},before)
        for root in preview['delete_roots']:self.assertFalse(any(Path(root).iterdir()))
    def test_only_exact_leaf_paths_are_accepted(self):
        for path in (self.cycle.bundle,self.clone/'nested',self.cycle.bundle/'checkpoint-volume/pg-checkpoint',
                     self.cycle.bundle/'checkpoint-volume/fallback-cache',Path('/database/devres/corpus')):
            with self.subTest(path=path),self.assertRaisesRegex(n.Refused,'whitelist'):self.engine.preview([path])
    def test_missing_or_uncompleted_cleanup_receipt_prevents_preview(self):
        write(self.cycle.bundle/'checkpoint-volume/clone-cleanup-completed.json',{'all_owned_containers_removed':False})
        with self.assertRaisesRegex(n.Refused,'completed_clone_cleanup'):self.engine.preview([self.clone])
        self.assertFalse(self.engine.journal.exists())
    def test_foreign_source_or_owner_token_cannot_qualify(self):
        write(self.cycle.install/'upgrade-controller.py',b'changed')
        with self.assertRaisesRegex(n.Refused,'source_changed'):self.engine.preview([self.clone])
    def test_backup_artifact_inside_leaf_or_bind_alias_is_rejected(self):
        for path in (self.clone/'data',self.cycle.work/'checkpoint-state/pg-clone/data'):
            write(self.cycle.bundle/'checkpoint-volume/backup-receipt.json',{
                'verified':True,'artifacts':[{'path':str(path),'sha256':'0'*64}]})
            with self.subTest(path=path),self.assertRaisesRegex(n.Refused,'artifact_inside'):self.engine.preview([self.clone])
    def test_revalidated_backup_artifacts_are_checked_and_data_root_symlinks_refused(self):
        write(self.cycle.bundle/'checkpoint-volume/backup-receipt-after-rehearsal.json',
            {'verified':True,'artifacts':[{'path':str(self.clone/'data'),'sha256':'0'*64}]})
        with self.assertRaisesRegex(n.Refused,'artifact_inside'):self.engine.preview([self.clone])
        (self.cycle.bundle/'checkpoint-volume/backup-receipt-after-rehearsal.json').unlink()
        write(self.root/'permanent/data',b'keep')
        (self.rehearsal/'cache').symlink_to(self.root/'permanent')
        with self.assertRaisesRegex(n.Refused,'symlink'):self.engine.preview([self.rehearsal])
    def test_external_hardlink_is_refused_and_internal_hardlinks_can_be_unlinked(self):
        write(self.clone/'data',b'owned');os.link(self.clone/'data',self.root/'outside')
        with self.assertRaisesRegex(n.Refused,'external_hardlink'):self.engine.preview([self.clone])
        (self.root/'outside').unlink();os.link(self.clone/'data',self.clone/'second')
        preview=self.engine.preview([self.clone]);self.apply(preview)
        self.assertFalse(any(self.clone.iterdir()))
    def test_symlink_is_unlinked_without_reading_or_removing_its_external_target(self):
        write(self.root/'outside',b'permanent');(self.clone/'link').symlink_to(self.root/'outside')
        preview=self.engine.preview([self.clone]);self.apply(preview)
        self.assertEqual((self.root/'outside').read_bytes(),b'permanent')
    def test_symlink_leaf_or_ancestor_is_refused(self):
        self.clone.rmdir();self.clone.symlink_to(self.root/'outside')
        with self.assertRaisesRegex(n.Refused,'symlink'):self.engine.preview([self.clone])
    def test_special_file_and_changed_bind_alias_are_refused(self):
        os.mkfifo(self.clone/'fifo')
        with self.assertRaisesRegex(n.Refused,'special_file'):self.engine.preview([self.clone])
        (self.clone/'fifo').unlink();(self.cycle.work/'checkpoint-state').mkdir(mode=0o700)
        with self.assertRaisesRegex(n.Refused,'alias_changed'):self.engine.preview([self.clone])
    def test_changed_preview_or_external_script_hash_refuses_before_intent(self):
        preview=self.engine.preview([self.clone])
        for preview_sha,script_sha in (('0'*64,preview['script_sha256']),(n.sha(n.encode(preview)),'0'*64)):
            with self.subTest(preview_sha=preview_sha),self.assertRaisesRegex(n.Refused,'external_admission'):
                self.engine.apply(preview,preview_sha,script_sha)
        self.assertFalse(self.engine.journal.exists())
    def test_changed_tree_or_protected_metadata_refuses_before_intent(self):
        preview=self.engine.preview([self.clone]);write(self.clone/'new',b'late')
        with self.assertRaisesRegex(n.Refused,'preview_stale'):self.apply(preview)
        self.assertFalse(self.engine.journal.exists())
    def test_no_replay_after_success_or_partial_failure(self):
        write(self.clone/'data',b'owned');preview=self.engine.preview([self.clone]);self.apply(preview)
        with self.assertRaisesRegex(n.Refused,'already_consumed'):self.apply(preview)
        self.engine.journal=self.root/'second-scope';write(self.clone/'later',b'owned')
        preview=self.engine.preview([self.clone])
        with patch.object(self.engine,'_clear',side_effect=OSError('not retained')),self.assertRaises(OSError):self.apply(preview)
        self.assertTrue((self.engine.journal/'failed.json').exists())
        with self.assertRaisesRegex(n.Refused,'already_consumed'):self.apply(preview)
    def test_preview_and_apply_bind_the_same_external_alias_qualification(self):
        write(self.clone/'data',b'disposable')
        first=n.Engine((self.cycle,),self.root/'new-journal',self.guard,qualification_sha='1'*64)
        preview=first.preview([self.clone])
        self.assertEqual(preview['alias_qualification_sha256'],'1'*64)
        changed=n.Engine((self.cycle,),self.root/'new-journal',self.guard,qualification_sha='2'*64)
        with self.assertRaisesRegex(n.Refused,'preview_stale'):
            changed.apply(preview,n.sha(n.encode(preview)),preview['script_sha256'])
        self.assertTrue((self.clone/'data').exists());self.assertFalse(changed.journal.exists())
    def test_quiescence_failure_prevents_mutation(self):
        self.guard.side_effect=n.Refused('active_process_reference')
        with self.assertRaisesRegex(n.Refused,'active_process_reference'):self.engine.preview([self.clone])
        self.assertFalse(self.engine.journal.exists())
    def test_protected_change_during_reclaim_is_reported_as_incomplete(self):
        write(self.clone/'data',b'owned');preview=self.engine.preview([self.clone]);clear=self.engine._clear
        def change(*args):
            clear(*args);write(self.cycle.bundle/'checkpoint-volume/baseline.json',{'changed':True})
        with patch.object(self.engine,'_clear',side_effect=change),self.assertRaises(n.Refused):self.apply(preview)
        self.assertTrue((self.engine.journal/'failed.json').exists())
        self.assertFalse((self.engine.journal/'completed.json').exists())


class KernelPathTests(unittest.TestCase):
    def test_mount_parser_decodes_kernel_escapes_without_shell_interpretation(self):
        value=n.mount_rows('23 1 8:1 /parent /tmp/with\\040space rw - ext4 /dev/x rw\n')[0]
        self.assertEqual(value,{'device':'8:1','root':'/parent','target':'/tmp/with space','id':23,'parent':1,
            'options':['rw'],'propagation':[],'filesystem':'ext4','source':'/dev/x','super_options':['rw']})
    def test_deleted_descriptors_and_paths_under_any_alias_are_detected(self):
        roots=[Path('/real/leaf'),Path('/tmp/alias/leaf')]
        self.assertTrue(n.path_used('/real/leaf/data (deleted)',roots))
        self.assertTrue(n.path_used('/tmp/alias/leaf/data',roots))
        self.assertFalse(n.path_used('/real/leafish/data',roots))
        self.assertFalse(n.path_used('/real',roots))



class SystemGuardTests(unittest.TestCase):
    """Exercise the real guard against a synthetic proc namespace, not a mockguard."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.leaf=self.root/'volume'/'leaf';self.leaf.mkdir(parents=True)
        self.proc=self.root/'proc';self.pid=self.proc/'123';(self.pid/'ns').mkdir(parents=True)
        (self.pid/'fd').mkdir();(self.pid/'ns/mnt').symlink_to('mnt:[1]')
        (self.proc/'self').symlink_to(self.pid)
        for name,value in (('cwd',str(self.root)),('root','/'),('exe','/usr/bin/python3')):(self.pid/name).symlink_to(value)
        (self.pid/'maps').write_text('')
        value=self.leaf.stat();self.device=f'{os.major(value.st_dev)}:{os.minor(value.st_dev)}'
        self.mounts=[f'1 0 {self.device} / / rw - ext4 /dev/test rw']
        self.set_mounts()
        self.calls=patch.object(n,'command',return_value=b'{}');self.command=self.calls.start();self.addCleanup(self.calls.stop)
        self.environment=patch.dict(os.environ,{'DOCKER_HOST':''});self.environment.start();self.addCleanup(self.environment.stop)
    def set_mounts(self): (self.pid/'mountinfo').write_text('\n'.join(self.mounts)+'\n')
    def run_guard(self,aliases=(),sockets=()):
        return n.system_guard([self.leaf],list(aliases),['a'*24],proc=self.proc,socket_paths=sockets)
    def test_ordinary_root_mount_and_registered_parent_bind_alias_pass(self):
        alias=self.root/'alias';alias.mkdir()
        self.mounts.append(f'2 1 {self.device} {self.leaf.parent} {alias} rw - ext4 /dev/test rw');self.set_mounts()
        self.assertTrue(self.run_guard([alias/'leaf'])['verified'])
    def test_unregistered_ancestor_bind_alias_is_refused_even_without_live_fds(self):
        alias=self.root/'hidden';alias.mkdir()
        self.mounts.append(f'2 1 {self.device} {self.leaf.parent} {alias} rw - ext4 /dev/test rw');self.set_mounts()
        with self.assertRaisesRegex(n.Refused,'unknown_ancestor_mount_alias'):self.run_guard()
    def test_registered_alias_cannot_hide_open_process_descriptor(self):
        alias=self.root/'alias';alias.mkdir()
        self.mounts.append(f'2 1 {self.device} {self.leaf.parent} {alias} rw - ext4 /dev/test rw');self.set_mounts()
        (self.pid/'fd/3').symlink_to(alias/'leaf'/'open-file')
        with self.assertRaisesRegex(n.Refused,'active_process_reference'):self.run_guard([alias/'leaf'])
    def test_direct_leaf_or_nested_mount_is_refused(self):
        for mount in (f'2 1 {self.device} {self.leaf} {self.root}/elsewhere rw - ext4 /dev/test rw',
                      f'2 1 {self.device} /irrelevant {self.leaf}/nested rw - ext4 /dev/test rw'):
            self.mounts=self.mounts[:1]+[mount];self.set_mounts()
            with self.subTest(mount=mount),self.assertRaises(n.Refused):self.run_guard()
    def test_open_mapping_is_refused_before_docker_or_firewall_checks(self):
        (self.pid/'maps').write_text('1-2 r--p 0 08:01 1 '+str(self.leaf/'data')+'\n')
        with self.assertRaisesRegex(n.Refused,'active_process_mapping'):self.run_guard()
        self.command.assert_not_called()
    def test_docker_parent_bind_and_token_network_are_refused(self):
        socket=self.root/'docker.sock';socket.touch()
        def answers(arguments,maximum=32*1024**2):
            if arguments[-2:]==['ps','-aq']:return b'container'
            if 'inspect' in arguments and 'network' not in arguments:
                return n.encode([{'Config':{'Labels':{}},'Mounts':[{'Type':'bind','Source':str(self.leaf.parent)}]}])
            if arguments[-3:]==['network','ls','-q']:return b''
            return b'{}'
        self.command.side_effect=answers
        with self.assertRaisesRegex(n.Refused,'docker_bind_reference'):self.run_guard(sockets=[socket])
        def networks(arguments,maximum=32*1024**2):
            if arguments[-2:]==['ps','-aq']:return b''
            if arguments[-3:]==['network','ls','-q']:return b'network'
            if 'network' in arguments and 'inspect' in arguments:return n.encode([{'Name':'devres-checkpoint-'+'a'*24,'Labels':{}}])
            return b'{}'
        self.command.side_effect=networks
        with self.assertRaisesRegex(n.Refused,'owned_network_remains'):self.run_guard(sockets=[socket])
    def test_owned_firewall_token_is_refused(self):
        self.command.return_value=('devres_cp_'+'a'*24).encode()
        with self.assertRaisesRegex(n.Refused,'owned_firewall_reference'):self.run_guard()


class LivepatchAliasTests(unittest.TestCase):
    """Real guard, fixed receipt lifecycle and synthetic namespace path views."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.proc=self.root/'proc';self.proc.mkdir()
        self.leaves=[];self.aliases=[];self.mirrors=[]
        for cycle in ('cycle1','cycle3'):
            bundle=self.root/cycle/'bundle';work=self.root/cycle/'work'
            for relative in n.LEAVES:
                leaf=bundle/relative;leaf.mkdir(parents=True);self.leaves.append(leaf)
                prefix='checkpoint-state' if relative.startswith('checkpoint-volume/') else 'restore-rehearsal-state'
                alias=work/prefix/Path(relative).name;self.aliases.append(alias)
            for volume,prefix in (('checkpoint-volume','checkpoint-state'),('restore-rehearsal-volume','restore-rehearsal-state')):
                (work/prefix).mkdir(parents=True)
                self.mirrors.append((bundle/volume,work/prefix))
        self.pid=self.proc/str(n.LIVEPATCH_PID);self.other=self.proc/'123'
        self.namespace_root=self.root/'namespace-root';self.namespace_root.mkdir()
        for path in (self.pid,self.other):
            (path/'fd').mkdir(parents=True);(path/'ns').mkdir()
            (path/'maps').write_text('');(path/'cwd').symlink_to('/var/snap/canonical-livepatch/418' if path==self.pid else '/')
            (path/'root').symlink_to(self.namespace_root if path==self.pid else Path('/'))
        self.executable=Path(sys.executable).resolve();(self.pid/'exe').symlink_to(self.executable)
        (self.other/'exe').symlink_to('/usr/bin/true')
        (self.pid/'ns/mnt').symlink_to('/proc/self/ns/mnt');(self.other/'ns/mnt').symlink_to('mnt:[1]')
        (self.proc/'self').symlink_to(self.other)
        (self.proc/'sys/kernel/random').mkdir(parents=True);(self.proc/'sys/kernel/random/boot_id').write_text(n.LIVEPATCH_BOOT)
        fields=['S','1']+['0']*17+[str(n.LIVEPATCH_START)]
        (self.pid/'stat').write_text(str(n.LIVEPATCH_PID)+' (livepatch) '+' '.join(fields))
        (self.pid/'status').write_text('Uid: 0 0 0 0\n');(self.pid/'cgroup').write_text(n.LIVEPATCH_CGROUP+'\n')
        info=self.leaves[0].stat();self.device=f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}'
        base=f'1 0 {self.device} / / rw - ext4 /dev/test rw'
        self.self_mounts=[base]+[f'{index+2} 1 {self.device} {source} {target} rw - ext4 /dev/test rw'
            for index,(source,target) in enumerate(self.mirrors)]
        (self.other/'mountinfo').write_text('\n'.join(self.self_mounts)+'\n')
        self.prefix=Path('/snap-hostfs')
        self.live_mounts=[f'124 277 {self.device} / {self.prefix} rw master:1 - ext4 /dev/test rw']
        self.live_mounts += [f'{index+500} 211 {self.device} {source} {self.prefix/str(target).lstrip("/")} rw master:1 - ext4 /dev/test rw'
            for index,(source,target) in enumerate(self.mirrors)]
        (self.pid/'mountinfo').write_text('\n'.join(self.live_mounts)+'\n')
        for leaf,alias in zip(self.leaves,self.aliases):
            for source in (leaf,alias):
                location=self.namespace_root/self.prefix.relative_to('/')/str(source).lstrip('/')
                location.parent.mkdir(parents=True,exist_ok=True);location.symlink_to(leaf,target_is_directory=True)
        exe=self.executable.stat();ns=os.stat('/proc/self/ns/mnt')
        self.scope=self.root/'qualification';self.receipt=self.scope/'livepatch-hostfs.json';self.intent=self.scope/'intent.json'
        self.original=self.root/'original-reclaim.py'
        write(self.original,b"class Refused(RuntimeError):pass\ndef system_guard(roots,aliases,tokens):raise Refused('unknown_ancestor_mount_alias')\n")
        constants={'ALIAS_LEAVES':tuple(self.leaves),'LIVEPATCH_PREFIX':self.prefix,
            'LIVEPATCH_EXE':str(self.executable),'LIVEPATCH_EXE_SHA':n.sha(self.executable.read_bytes()),
            'LIVEPATCH_EXE_IDENTITY':{'dev':exe.st_dev,'ino':exe.st_ino,'uid':exe.st_uid,'gid':exe.st_gid,'mode':stat.S_IMODE(exe.st_mode),'size':exe.st_size},
            'LIVEPATCH_NS_IDENTITY':{'dev':ns.st_dev,'ino':ns.st_ino,'uid':ns.st_uid,'gid':ns.st_gid,'mode':stat.S_IMODE(ns.st_mode)},
            'LIVEPATCH_MOUNTS_SHA':n.sha((self.pid/'mountinfo').read_bytes()),'ALIAS_SCOPE':self.scope,'ALIAS_RECEIPT':self.receipt,
            'ALIAS_INTENT':self.intent,'ORIGINAL_RECLAIM':self.original,'ORIGINAL_RECLAIM_SHA':n.sha(self.original.read_bytes())}
        pins=patch.multiple(n,**constants);pins.start();self.addCleanup(pins.stop)
        real_readlink=os.readlink;observed_namespace=n.LIVEPATCH_NAMESPACE
        def readlink(path,*args,**kwargs):
            if Path(path)==self.pid/'root':return '/'
            if Path(path)==self.pid/'ns/mnt':return observed_namespace
            return real_readlink(path,*args,**kwargs)
        links=patch.object(os,'readlink',side_effect=readlink);links.start();self.addCleanup(links.stop)
        # A synthetic symlink supplies the same inode as a real bind mount.
        # Only the namespace alias leaves receive this kernel-view emulation;
        # production still uses lstat semantics and refuses symlink leaves.
        real_stat=os.stat
        namespace_prefix=self.pid/'root'/str(self.prefix).lstrip('/')
        def namespace_stat(path,*args,**kwargs):
            if isinstance(path,(str,bytes,os.PathLike)) and not isinstance(path,bytes) and n.under(Path(path),namespace_prefix):
                kwargs['follow_symlinks']=True
            return real_stat(path,*args,**kwargs)
        stats=patch.object(os,'stat',side_effect=namespace_stat);stats.start();self.addCleanup(stats.stop)
        self.boundary=SimpleNamespace(check=Mock(return_value={'current_source_manifest_sha256':n.ALIAS_MANIFEST_SHA,
            'edge_readmission_sha256':n.ALIAS_EDGE_SHA,'state_sha256':'frozen'}))
        bridge=patch.object(n,'bound_edge_bridge',return_value=(None,n.ALIAS_EDGE_SHA,n.ALIAS_MANIFEST_SHA));bridge.start();self.addCleanup(bridge.stop)
        self.commands=patch.object(n,'command',return_value=b'{}');self.command=self.commands.start();self.addCleanup(self.commands.stop)
        environment=patch.dict(os.environ,{'DOCKER_HOST':''});environment.start();self.addCleanup(environment.stop)
    def capture(self):return n.capture_livepatch_aliases(self.leaves,self.aliases,proc=self.proc)
    def qualify(self):
        engine=SimpleNamespace(aliases=lambda roots:self.aliases,validate_receipts=lambda cycle,relative:'a'*24,
            whitelist={root:(None,None) for root in self.leaves})
        original=n.capture_livepatch_aliases
        def capture(roots,aliases,**kwargs):return original(roots,aliases,proc=self.proc)
        with patch.object(n,'Engine',return_value=engine),patch.object(n,'capture_livepatch_aliases',side_effect=capture):
            return n.qualify_livepatch_aliases(self.boundary)
    def guard(self,sha=None):return n.system_guard(self.leaves,self.aliases,['a'*24],proc=self.proc,socket_paths=[],alias_qualification_sha=sha)
    def test_fixed_qualification_preserves_bytes_and_only_adds_twelve_aliases(self):
        original=n.file_record(self.original);roots={str(path):n.identity(path) for path in self.leaves}
        with self.assertRaisesRegex(n.Refused,'unknown_ancestor_mount_alias'):self.guard()
        result=self.qualify();pin=result['alias_qualification_sha256']
        self.assertEqual(result['alias_count'],12);self.assertFalse(result['guard_accepted'])
        value=n.validate_livepatch_aliases(pin,self.leaves,self.aliases,proc=self.proc,live_boundary=self.boundary.check())
        self.assertEqual(len(value['snapshot']['mappings']),12);self.assertEqual(n.file_record(self.original),original)
        self.assertEqual({str(path):n.identity(path) for path in self.leaves},roots)
        proof=self.guard(pin);self.assertTrue(proof['verified']);self.assertEqual(proof['qualified_alias_count'],12)
        with self.assertRaisesRegex(n.Refused,'already_consumed'):self.qualify()
    def test_every_expanded_alias_is_checked_before_docker_and_firewall(self):
        pin=self.qualify()['alias_qualification_sha256'];value=n.load(self.receipt)
        for item in value['snapshot']['mappings']:
            target=item['alias']+'/held (deleted)';descriptor=self.other/'fd/9';descriptor.symlink_to(target)
            with self.subTest(alias=item['alias']),self.assertRaisesRegex(n.Refused,'active_process_reference'):self.guard(pin)
            descriptor.unlink();self.command.assert_not_called()
    def test_expanded_maps_cwd_and_root_are_still_refused(self):
        pin=self.qualify()['alias_qualification_sha256'];alias=n.load(self.receipt)['snapshot']['mappings'][0]['alias']
        (self.other/'maps').write_text('1-2 r--p 0 00:00 1 '+alias+'/mapped\n')
        with self.assertRaisesRegex(n.Refused,'active_process_mapping'):self.guard(pin)
        (self.other/'maps').write_text('')
        for name in ('cwd','root'):
            path=self.other/name;path.unlink();path.symlink_to(alias)
            with self.subTest(name=name),self.assertRaisesRegex(n.Refused,'active_process_reference'):self.guard(pin)
            path.unlink();path.symlink_to('/')
    def test_foreign_namespace_and_thirteenth_alias_cannot_reuse_qualification(self):
        pin=self.qualify()['alias_qualification_sha256'];foreign=self.proc/'456';(foreign/'ns').mkdir(parents=True)
        (foreign/'ns/mnt').symlink_to('mnt:[foreign]');(foreign/'mountinfo').write_bytes((self.pid/'mountinfo').read_bytes())
        with self.assertRaisesRegex(n.Refused,'unknown_ancestor_mount_alias'):self.guard(pin)
        (foreign/'ns/mnt').unlink();(foreign/'ns').rmdir();(foreign/'mountinfo').unlink();foreign.rmdir()
        (self.other/'mountinfo').write_text('\n'.join(self.self_mounts+[f'990 1 {self.device} / /unapproved rw - ext4 /dev/test rw'])+'\n')
        with self.assertRaisesRegex(n.Refused,'unknown_ancestor_mount_alias'):self.guard(pin)
    def test_process_boot_membership_and_mount_identity_are_exact(self):
        pin=self.qualify()['alias_qualification_sha256']
        for path,body in ((self.pid/'stat',(self.pid/'stat').read_bytes().replace(str(n.LIVEPATCH_START).encode(),b'99999')),
            (self.pid/'cgroup',b'0::/foreign'),(self.pid/'status',b'Uid: 1 1 1 1\n'),
            (self.proc/'sys/kernel/random/boot_id',b'different'),
            (self.pid/'mountinfo',(self.pid/'mountinfo').read_bytes().replace(b'master:1',b'master:2'))):
            original=path.read_bytes();path.write_bytes(body)
            with self.subTest(path=path),self.assertRaises(n.Refused):self.guard(pin)
            path.write_bytes(original)
        joined=self.proc/'999';(joined/'ns').mkdir(parents=True);(joined/'ns/mnt').symlink_to(n.LIVEPATCH_NAMESPACE)
        with self.assertRaisesRegex(n.Refused,'membership'):self.guard(pin)
    def test_wrong_inode_source_external_sha_and_live_boundary_refuse(self):
        pin=self.qualify()['alias_qualification_sha256']
        with self.assertRaisesRegex(n.Refused,'external_alias'):self.guard('0'*64)
        with self.assertRaisesRegex(n.Refused,'boundary_changed'):
            n.validate_livepatch_aliases(pin,self.leaves,self.aliases,proc=self.proc,live_boundary={'state_sha256':'changed'})
        mapping=n.load(self.receipt)['snapshot']['mappings'][0]
        path=self.namespace_root/mapping['alias'].lstrip('/');path.unlink();path.symlink_to(self.leaves[-1])
        with self.assertRaisesRegex(n.Refused,'inode_changed'):self.guard(pin)
        path.unlink();path.symlink_to(Path(mapping['leaf']))
        write(self.original,b'changed')
        with self.assertRaisesRegex(n.Refused,'source_bound'):self.guard(pin)
    def test_mount_drift_during_reference_pass_is_refused(self):
        pin=self.qualify()['alias_qualification_sha256'];read=Path.read_text;changed=[False]
        def reading(path,*args,**kwargs):
            if path==self.other/'maps' and not changed[0]:
                changed[0]=True;(self.pid/'mountinfo').write_text('\n'.join(self.live_mounts)+'\n990 1 '+self.device+' / /foreign rw - ext4 /dev/test rw\n')
            return read(path,*args,**kwargs)
        with patch.object(Path,'read_text',reading),self.assertRaisesRegex(n.Refused,'mounts_changed'):self.guard(pin)
        self.command.assert_not_called()
    def test_scope_executable_and_namespace_are_fixed_not_generic_livepatch(self):
        with self.assertRaisesRegex(n.Refused,'leaf_scope'):n.capture_livepatch_aliases(self.leaves[:1],self.aliases,proc=self.proc)
        for key,value in (('LIVEPATCH_EXE_SHA','0'*64),('LIVEPATCH_PID',999),('LIVEPATCH_NAMESPACE','mnt:[foreign]')):
            with self.subTest(key=key),patch.object(n,key,value),self.assertRaises((n.Refused,FileNotFoundError)):
                self.capture()
    def test_qualified_leaf_symlink_is_refused_instead_of_followed(self):
        # Remove the fixture-only bind emulation for this one alias. Production
        # always sees lstat semantics; a real symlink is not an admitted mapping.
        real_stat=os.stat
        alias=self.pid/'root'/str(self.prefix).lstrip('/')/str(self.leaves[0]).lstrip('/')
        underlying=self.namespace_root/str(self.prefix).lstrip('/')/str(self.leaves[0]).lstrip('/')
        with patch.object(os,'stat',side_effect=lambda path,*args,**kwargs:os.lstat(underlying) if Path(path)==alias else real_stat(path,*args,**kwargs)), self.assertRaisesRegex(n.Refused,'directory_required'):
            self.capture()
    def test_wrong_original_denial_consumes_qualification_without_receipt_or_retry(self):
        write(self.original,b"class Refused(RuntimeError):pass\ndef system_guard(roots,aliases,tokens):raise Refused('different_denial')\n")
        with patch.object(n,'ORIGINAL_RECLAIM_SHA',n.sha(self.original.read_bytes())):
            with self.assertRaisesRegex(n.Refused,'exact_original_alias_denial'):self.qualify()
            self.assertTrue(self.intent.exists());self.assertFalse(self.receipt.exists())
            with self.assertRaisesRegex(n.Refused,'already_consumed'):self.qualify()
    def test_qualification_bookend_failure_has_consumed_intent_but_no_receipt(self):
        original=self.boundary.check.return_value
        self.boundary.check.side_effect=[original,{**original,'state_sha256':'changed'}]
        with self.assertRaisesRegex(n.Refused,'boundary_changed'):self.qualify()
        self.assertTrue(self.intent.exists());self.assertFalse(self.receipt.exists())
    def test_original_source_is_hashed_before_import_or_new_intent(self):
        write(self.original,b'raise AssertionError("must never import")')
        with patch.object(n.importlib.util,'spec_from_file_location') as loader,self.assertRaisesRegex(n.Refused,'original_reclaim_source'):
            self.qualify()
        loader.assert_not_called();self.assertFalse(self.intent.exists())
    def test_direct_leaf_mount_is_never_qualified(self):
        pin=self.qualify()['alias_qualification_sha256']
        (self.other/'mountinfo').write_text('\n'.join(self.self_mounts+[f'991 1 {self.device} {self.leaves[0]} /direct rw - ext4 /dev/test rw'])+'\n')
        with self.assertRaisesRegex(n.Refused,'leaf_exposed_by_mount'):self.guard(pin)


class ProducerDataScopeTests(unittest.TestCase):
    """Synthetic producer metadata + prior self-hash API model, not live acceptance."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        cycles=[]
        for index,name in enumerate(('cycle1','cycle3')):
            parent=self.root/name;parent.mkdir();value=fixture(parent)
            cycles.append(n.Cycle(name,value.bundle,value.work,value.install))
        self.cycles=tuple(cycles);self.cycle=cycles[0];cp=self.cycle.bundle/'checkpoint-volume'
        self.producer=cp/'proof-successor-v1';self.producer.mkdir(mode=0o700)
        self.leaves=[cycle.bundle/relative for cycle in cycles for relative in n.LEAVES]
        self.roots=[self.producer/name for name in n.PRODUCER_BODY_NAMES]
        for path in self.roots:path.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.body=self.producer/'rehearsal/writer-cache/capture.json';write(self.body,b'public retained cache body')
        write(self.producer/'fallback-cache/object.json',b'another retained body')
        self.evidence=self.producer/'rehearsal/files/retained.toml';write(self.evidence,b'operational configuration')
        for cycle in cycles:
            for volume,prefix in (('checkpoint-volume','checkpoint-state'),('restore-rehearsal-volume','restore-rehearsal-state')):
                (cycle.work/prefix).mkdir()
            for relative in ('checkpoint-volume/rehearsal/cache','checkpoint-volume/rehearsal/writer-cache',
                'restore-rehearsal-volume/runtime/cache-serving','restore-rehearsal-volume/runtime/isolated-pv'):
                (cycle.bundle/relative).mkdir(parents=True,exist_ok=True)
        self.alias_root=self.cycle.work/'checkpoint-state/proof-successor-v1'
        for name in n.PRODUCER_BODY_NAMES:(self.alias_root/name).mkdir(mode=0o700,parents=True,exist_ok=True)
        write(self.alias_root/'rehearsal/writer-cache/capture.json',b'same retained alias payload')
        identity=n.identity
        def projected_identity(path):
            path=Path(path)
            for cycle in self.cycles:
                for prefix,volume in (('checkpoint-state','checkpoint-volume'),('restore-rehearsal-state','restore-rehearsal-volume')):
                    alias=cycle.work/prefix
                    if n.under(path,alias):return identity(cycle.bundle/volume/path.relative_to(alias))
            return identity(path)
        aliases=patch.object(n,'identity',side_effect=projected_identity);aliases.start();self.addCleanup(aliases.stop)
        write(self.cycle.install/'physical-checkpoint.py',b'# immutable producer checkpoint source')
        write(self.cycle.install/'proof-continuation.py',b'# immutable admitted continuation source')
        manifest=n.load(self.cycle.work/'source-manifest.json')
        manifest['physical-checkpoint.py']=n.sha((self.cycle.install/'physical-checkpoint.py').read_bytes())
        write(self.cycle.work/'source-manifest.json',manifest)
        cache={'manifests':{'writer':{'sha256':'b'*64,'rows':[{'path':'capture.json','kind':'file'}]}}}
        write(cp/'cache-baselines.json',cache);write(self.producer/'cache-baselines.json',cache)
        pg=b'{"kind":"file","path":"PG_VERSION","sha256":"retained"}\n';write(self.producer/'pg-file-manifest.jsonl',pg)
        checkpoint={'pg_files_sha256':n.sha(pg)};write(self.producer/'checkpoint-completed.json',checkpoint)
        admission={'version':1,'kind':'isolated-proof-successor-v1','maximum_attempts':1,
            'only_change':'restore_original_writer_cache_ceiling',
            'successor_scope':str(self.alias_root),'original_scope':str(self.cycle.work/'checkpoint-state'),
            'source_sha256':n.sha((self.cycle.install/'proof-continuation.py').read_bytes()),
            'checkpoint_source_sha256':manifest['physical-checkpoint.py'],
            'global_manifest_sha256':n.sha((self.cycle.work/'source-manifest.json').read_bytes()),
            'immutable_sha256':{'cache-baselines.json':n.sha((cp/'cache-baselines.json').read_bytes())}}
        write(self.producer/'admission.json',admission)
        completed={'cache_baselines_sha256':n.sha((cp/'cache-baselines.json').read_bytes()),
            'pg_files_sha256':n.sha(pg),'checkpoint_receipt_sha256':n.sha((self.producer/'checkpoint-completed.json').read_bytes()),
            'old_clone_verified':True,'fallback_writer_verified':True}
        write(self.producer/'completed.json',completed)
        write(cp/'completed.json',{'old_clone_verified':True,'proof_continuation':{
            'admission_sha256':n.sha((self.producer/'admission.json').read_bytes()),'source_sha256':admission['source_sha256']}})
        artifacts=[{'path':str(path),'sha256':n.sha(path.read_bytes())} for path in
            (self.producer/'cache-baselines.json',self.producer/'pg-file-manifest.jsonl',self.producer/'completed.json')]
        write(self.producer/'backup-receipt.json',{'verified':True,'artifacts':artifacts})
        write(cp/'backup-receipt.json',{'verified':True,'artifacts':artifacts})
        pins={path:n.sha(path.read_bytes()) for path in (self.cycle.install/'proof-continuation.py',
            self.cycle.install/'physical-checkpoint.py',cp/'completed.json',cp/'backup-receipt.json',
            *(self.producer/name for name in ('admission.json','completed.json','backup-receipt.json','cache-baselines.json','pg-file-manifest.jsonl','checkpoint-completed.json')))}
        self.old_source=self.root/'preserved-prior.py';self.old_receipt=self.root/'prior-qualification.json'
        code=("import hashlib,json,pathlib\nRECEIPT=pathlib.Path("+repr(str(self.old_receipt))+")\ndef need(value):\n if not value:raise RuntimeError('prior_binding_refused')\ndef validate_livepatch_aliases(pin,roots,aliases,proc=None,live_boundary=None):\n body=RECEIPT.read_bytes();need(hashlib.sha256(body).hexdigest()==pin)\n value=json.loads(body);need(value['script_sha256']==hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest())\n need(value['snapshot']['roots']==sorted(map(str,roots)))\n need(value['snapshot']['aliases']==sorted(map(str,aliases)))\n if live_boundary is not None:need(value['live_boundary']==live_boundary)\n return value\n").encode()
        write(self.old_source,code)
        self.scope=self.root/'new-data-scope';self.receipt=self.scope/'qualification.json';self.intent=self.scope/'intent.json'
        values={'CYCLES':self.cycles,'ALIAS_LEAVES':tuple(self.leaves),'PRODUCER_CYCLE':self.cycle,
            'PRODUCER_ROOT':self.producer,'PRODUCER_PINS':pins,
            'PRODUCER_BODY_AUTHORITY':{name:(os.geteuid(),os.getegid(),0o700) for name in n.PRODUCER_BODY_NAMES},
            'FROZEN_RECLAIM':self.old_source,'FROZEN_RECLAIM_SHA':n.sha(code),'DATA_SCOPE':self.scope,
            'DATA_RECEIPT':self.receipt,'DATA_INTENT':self.intent,
            'JOURNAL':self.root/'previous-journal','DATA_JOURNAL':self.root/'new-apply-journal'}
        constants=patch.multiple(n,**values);constants.start();self.addCleanup(constants.stop)
        engine=n.Engine(cycles=self.cycles);self.aliases=engine.aliases(self.leaves)
        self.fp={'current_source_manifest_sha256':n.ALIAS_MANIFEST_SHA,'edge_readmission_sha256':n.ALIAS_EDGE_SHA,'state_sha256':'exact'}
        self.boundary=SimpleNamespace(check=Mock(return_value=self.fp))
        prior={'script_sha256':n.sha(code),'snapshot':{'roots':sorted(map(str,self.leaves)),
            'aliases':sorted(map(str,self.aliases)),'mappings':[]},'live_boundary':self.fp}
        write(self.old_receipt,prior);pin=patch.object(n,'FROZEN_ALIAS_SHA',n.sha(self.old_receipt.read_bytes()));pin.start();self.addCleanup(pin.stop)
        self.guard=Mock(return_value={'verified':True})
    def qualify(self):return n.qualify_retained_data_scope(self.boundary)
    def engine(self,pin):return n.Engine(self.cycles,self.root/'new-apply-journal',self.guard,
        qualification_sha=n.FROZEN_ALIAS_SHA,retained_data_qualification_sha=pin)
    def test_exact_producer_scope_chain_prunes_only_five_data_roots_without_body_reads(self):
        before={path:n.file_record(path) for path in (self.body,self.evidence,self.old_source,self.old_receipt)}
        result=self.qualify();pin=result['retained_data_qualification_sha256'];self.assertFalse(result['payloads_rehashed'])
        original=n.file_record
        def records(path,*args,**kwargs):
            canonical=n.producer_canonical(path)
            if any(n.under(canonical,root) and canonical!=root for root in self.roots):raise AssertionError('retained body read')
            return original(path,*args,**kwargs)
        with patch.object(n,'file_record',side_effect=records):
            preview=self.engine(pin).preview(self.leaves)
        self.assertIn(str(self.evidence),preview['protected']);self.assertNotIn(str(self.body),preview['protected'])
        self.assertEqual(preview['protected']['producer-retained-data']['kind'],'structural-nonmodification')
        self.assertEqual(preview['retained_data_qualification_sha256'],pin)
        self.assertEqual({path:n.file_record(path) for path in before},before)
        with self.assertRaisesRegex(n.Refused,'already_consumed'):self.qualify()
    def test_every_body_root_is_structurally_disjoint_including_known_work_aliases(self):
        engine=n.Engine(cycles=self.cycles);delete=[root for leaf in self.leaves for root in engine.delete_roots(leaf,engine.whitelist[leaf][1])]
        for root in self.roots:
            for overlap in (root,root/'child',root.parent,self.alias_root/root.relative_to(self.producer),self.alias_root/root.relative_to(self.producer)/'child'):
                with self.subTest(root=root,overlap=overlap),self.assertRaisesRegex(n.Refused,'deletion_overlap'):
                    n.producer_data_projection(self.leaves,delete+[overlap])
    def test_producer_hash_and_outside_metadata_changes_never_authorize_prune(self):
        write(self.cycle.install/'proof-continuation.py',b'changed')
        with self.assertRaisesRegex(n.Refused,'producer_changed'):self.qualify()
        self.assertTrue(self.intent.exists());self.assertFalse(self.receipt.exists())
    def test_root_symlink_device_mode_and_work_alias_drift_are_refused(self):
        original=n.identity
        for mutation in ('device','inode-alias','mode'):
            def identity(path):
                result=original(path)
                if Path(path)==self.roots[0]:result={**result,('dev' if mutation=='device' else 'mode'):(result['dev']+1 if mutation=='device' else 0o777)}
                if mutation=='inode-alias' and Path(path)==self.alias_root/'pg-checkpoint':result={**result,'ino':result['ino']+1}
                return result
            with self.subTest(mutation=mutation),patch.object(n,'identity',side_effect=identity),self.assertRaises(n.Refused):
                n.producer_data_projection(self.leaves,[])
        target=self.roots[1];target.rmdir();target.symlink_to(self.roots[0])
        with self.assertRaisesRegex(n.Refused,'symlink'):n.producer_data_projection(self.leaves,[])
    def test_frozen_source_and_old_self_hash_are_checked_without_global_rebinding(self):
        result=self.qualify();pin=result['retained_data_qualification_sha256']
        frozen=n.frozen_reclaim();self.assertEqual(Path(frozen.__file__),self.old_source)
        self.assertEqual(frozen.validate_livepatch_aliases.__code__.co_filename,str(self.old_source))
        self.assertEqual(frozen.RECEIPT,self.old_receipt)
        old=n.load(self.old_receipt);old['script_sha256']='0'*64;write(self.old_receipt,old)
        with self.assertRaises(RuntimeError):n.validate_retained_data_scope(pin,self.leaves,self.aliases)
    def test_wrong_external_pin_source_or_boundary_refuses(self):
        pin=self.qualify()['retained_data_qualification_sha256']
        with self.assertRaisesRegex(n.Refused,'external_retained'):n.validate_retained_data_scope('0'*64,self.leaves,self.aliases)
        with self.assertRaises(RuntimeError):n.validate_retained_data_scope(pin,self.leaves,self.aliases,live_boundary={'state_sha256':'changed'})
        write(self.old_source,b'raise AssertionError("must not import")')
        with patch.object(n.importlib.util,'spec_from_file_location') as loader,self.assertRaises(n.Refused):
            n.validate_retained_data_scope(pin,self.leaves,self.aliases)
        loader.assert_not_called()
    def test_new_outside_metadata_is_protected_and_fails_stale_preview_before_intent(self):
        pin=self.qualify()['retained_data_qualification_sha256'];engine=self.engine(pin)
        leaf=self.leaves[0];write(leaf/'delete.bin',b'disposable');preview=engine.preview(self.leaves)
        outside=self.producer/'rehearsal/files/new-operational.json';write(outside,{'keep':True})
        with self.assertRaisesRegex(n.Refused,'preview_stale'):
            engine.apply(preview,n.sha(n.encode(preview)),preview['script_sha256'])
        self.assertTrue((leaf/'delete.bin').exists());self.assertFalse(engine.journal.exists())
        self.assertIn(str(outside),engine.preview(self.leaves)['protected'])
    def test_external_hardlink_to_retained_body_still_refuses_before_any_apply(self):
        pin=self.qualify()['retained_data_qualification_sha256'];os.link(self.body,self.leaves[0]/'alias.json')
        with self.assertRaisesRegex(n.Refused,'external_hardlink'):self.engine(pin).preview(self.leaves)
        self.assertFalse(self.engine(pin).journal.exists())
    def test_qualification_bookend_drift_consumes_intent_without_new_receipt(self):
        self.boundary.check.side_effect=[self.fp,{**self.fp,'state_sha256':'changed'}]
        with self.assertRaisesRegex(n.Refused,'bookend_changed'):self.qualify()
        self.assertTrue(self.intent.exists());self.assertFalse(self.receipt.exists())
    def test_consumed_previous_journal_cannot_be_rearmed_by_a_new_scope(self):
        write(n.JOURNAL/'intent.json',{'consumed':True})
        with self.assertRaisesRegex(n.Refused,'inspect_only'):self.qualify()
        self.assertFalse(self.intent.exists());self.assertFalse(self.receipt.exists())
    def test_later_previous_intent_blocks_apply_but_current_apply_journal_validation_is_allowed(self):
        pin=self.qualify()['retained_data_qualification_sha256'];engine=self.engine(pin)
        preview=engine.preview(self.leaves)
        write(n.DATA_JOURNAL/'intent.json',{'current-own-intent':True})
        self.assertEqual(n.validate_retained_data_scope(pin,self.leaves,self.aliases)['new_reclaim_journal'],str(n.DATA_JOURNAL))
        (n.DATA_JOURNAL/'intent.json').unlink();n.DATA_JOURNAL.rmdir()
        write(n.JOURNAL/'intent.json',{'consumed':True})
        with self.assertRaisesRegex(n.Refused,'source_bound_retained'):
            engine.apply(preview,n.sha(n.encode(preview)),preview['script_sha256'])
        self.assertFalse(n.DATA_JOURNAL.exists())
    def test_new_journal_is_fresh_at_qualification_and_fixed_for_apply(self):
        write(n.DATA_JOURNAL/'intent.json',{'consumed':True})
        with self.assertRaisesRegex(n.Refused,'inspect_only'):self.qualify()
        self.assertFalse(self.intent.exists())
        with self.assertRaisesRegex(n.Refused,'fixed_retained_data_apply_journal'):
            n.Engine(self.cycles,self.root/'different-journal',self.guard,qualification_sha=n.FROZEN_ALIAS_SHA,retained_data_qualification_sha='1'*64)
    def test_dangling_or_aliased_journals_never_prove_inspect_only_history(self):
        for journal in (n.JOURNAL,n.DATA_JOURNAL):
            journal.symlink_to(self.root/'absent-journal-target')
            with self.subTest(journal=journal),self.assertRaisesRegex(n.Refused,'symlink'):self.qualify()
            self.assertFalse(self.intent.exists());journal.unlink()
        pin=self.qualify()['retained_data_qualification_sha256']
        n.JOURNAL.symlink_to(self.root/'absent-previous-journal')
        with self.assertRaisesRegex(n.Refused,'symlink'):n.validate_retained_data_scope(pin,self.leaves,self.aliases)
    def test_old_alias_authority_cannot_be_used_by_new_source_without_explicit_envelope(self):
        alias=patch.object(n,'ALIAS_RECEIPT',self.old_receipt);alias.start();self.addCleanup(alias.stop)
        with self.assertRaises(n.Refused):n.validate_livepatch_aliases(n.FROZEN_ALIAS_SHA,self.leaves,self.aliases)


class DiscoveryMetadataScopeTests(unittest.TestCase):
    """Real new engine, synthetic root authority and a self-checking prior API model."""
    def setUp(self):
        ProducerDataScopeTests.setUp(self)
        self.cache=self.cycle.work/'.kube/cache/discovery/127.0.0.1_6443'
        self.operational=self.root/'operational-cache';self.operational.mkdir(mode=0o700)
        for name in n.DISCOVERY_RELATIVE:
            path=self.cache/name
            value=({'apiVersion':'v1','kind':'APIGroupList','groups':[]} if name=='servergroups.json' else
                {'apiVersion':'v1','kind':'APIResourceList','groupVersion':str(Path(name).parent),'resources':[]})
            write(path,value);path.chmod(0o660)
        self.cache_files={self.cache/name for name in n.DISCOVERY_RELATIVE}
        self.cache_parents={p for f in self.cache_files for p in f.parents if p==self.cycle.work or self.cycle.work in p.parents}
        for parent in self.cache_parents:parent.chmod(0o700)
        self.metadata_scope=self.root/'metadata-scope';self.metadata_receipt=self.metadata_scope/'qualification.json'
        self.data_source=self.root/'preserved-data.py';self.data_receipt=self.root/'preserved-data-qualification.json'
        code=("import hashlib,json,pathlib\nRECEIPT=pathlib.Path("+repr(str(self.data_receipt))+")\ndef validate_retained_data_scope(pin,roots,aliases,delete=None,proc=None,live_boundary=None):\n body=RECEIPT.read_bytes();value=json.loads(body)\n if hashlib.sha256(body).hexdigest()!=pin or value['script_sha256']!=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest():raise RuntimeError('old_data_source_or_receipt_changed')\n if value['roots']!=sorted(map(str,roots)) or value['aliases']!=sorted(map(str,aliases)):raise RuntimeError('old_data_scope_changed')\n if live_boundary is not None and live_boundary!=value['live_boundary']:raise RuntimeError('old_data_boundary_changed')\n return value\n").encode()
        code+=b'\nCYCLES=()\nDATA_JOURNAL=RECEIPT.parent/"old-data-journal"\nFROZEN_ALIAS_SHA="prior"\nclass Refused(RuntimeError):pass\nclass Engine:\n def __init__(self,**kwargs):pass\n def protected(self,selected,delete):\n  raise Refused("protected_file_authority_changed")\n'
        write(self.data_source,code)
        delete=[r for leaf in self.leaves for r in n.Engine(cycles=self.cycles).delete_roots(leaf,n.Engine(cycles=self.cycles).whitelist[leaf][1])]
        previous={'script_sha256':n.sha(code),'roots':sorted(map(str,self.leaves)),
            'aliases':sorted(map(str,self.aliases)),'live_boundary':self.fp,
            'alias_qualification':n.load(self.old_receipt),'producer_data':n.producer_data_projection(self.leaves,delete)}
        write(self.data_receipt,previous)
        values={'FROZEN_DATA_RECLAIM':self.data_source,'FROZEN_DATA_RECLAIM_SHA':n.sha(code),
            'FROZEN_DATA_SHA':n.sha(self.data_receipt.read_bytes()),'METADATA_SCOPE':self.metadata_scope,
            'METADATA_INTENT':self.metadata_scope/'intent.json','METADATA_RECEIPT':self.metadata_receipt,
            'METADATA_JOURNAL':self.root/'metadata-journal','DISCOVERY_OPERATIONAL_CACHE':self.operational,
            'DISCOVERY_WORK':self.cycle.work,'DISCOVERY_ROOT':self.cache}
        constants=patch.multiple(n,**values);constants.start();self.addCleanup(constants.stop)
        env=patch.dict(os.environ,{'KUBECACHEDIR':str(self.operational)});env.start();self.addCleanup(env.stop)
        identity=n.identity
        def root_identity(path):
            result=identity(path)
            if Path(path) in self.cache_parents|{self.operational}:result={**result,'uid':0,'gid':0}
            return result
        authority=patch.object(n,'identity',side_effect=root_identity);authority.start();self.addCleanup(authority.stop)
        record=n.file_record
        def root_record(path,*args,**kwargs):
            result=record(path,*args,**kwargs)
            if Path(path) in self.cache_files:result={**result,'uid':0,'gid':0}
            return result
        authority=patch.object(n,'file_record',side_effect=root_record);authority.start();self.addCleanup(authority.stop)
    def qualify(self):return n.qualify_discovery_metadata(self.boundary)['metadata_qualification_sha256']
    def engine(self,pin):return n.Engine(self.cycles,n.METADATA_JOURNAL,self.guard,
        qualification_sha=n.FROZEN_ALIAS_SHA,retained_data_qualification_sha=n.FROZEN_DATA_SHA,metadata_qualification_sha=pin)
    def test_exact_29_records_are_preserved_by_full_preview_and_apply(self):
        pin=self.qualify();engine=self.engine(pin);leaf=self.leaves[0];write(leaf/'disposable.bin',b'owned disposable')
        before={p:n.file_record(p,private=False) for p in self.cache_files}
        preview=engine.preview(self.leaves)
        self.assertEqual(preview['metadata_qualification_sha256'],pin)
        self.assertEqual(len(preview['protected']['discovery-metadata']['projection']['parents']),58)
        self.assertTrue(all(preview['protected'][str(p)]==value for p,value in before.items()))
        completed=engine.apply(preview,n.sha(n.encode(preview)),preview['script_sha256'])
        self.assertTrue(completed['verified']);self.assertFalse((leaf/'disposable.bin').exists())
        self.assertEqual({p:n.file_record(p,private=False) for p in self.cache_files},before)
        self.assertFalse(n.JOURNAL.exists());self.assertFalse(n.DATA_JOURNAL.exists())
        self.assertEqual(n.validate_discovery_metadata(pin,self.leaves,self.aliases)['history']['new_journal'],str(n.METADATA_JOURNAL))
    def test_default_old_authority_still_refuses_and_no_global_file_record_relaxation(self):
        with self.assertRaisesRegex(n.Refused,'protected_file_authority_changed'):
            n.Engine(cycles=self.cycles).protected(self.leaves,[])
        with self.assertRaisesRegex(n.Refused,'private_metadata_required'):n.file_record(next(iter(self.cache_files)))
    def test_30th_file_missing_file_and_extra_directory_are_refused(self):
        extra=self.cache/'extra.json';write(extra,{'unapproved':True})
        with self.assertRaisesRegex(n.Refused,'membership'):n.discovery_projection()
        extra.unlink();extra=self.cache/'foreign';extra.mkdir()
        with self.assertRaisesRegex(n.Refused,'membership'):n.discovery_projection()
        extra.rmdir();next(iter(self.cache_files)).unlink()
        with self.assertRaisesRegex(n.Refused,'membership'):n.discovery_projection()
    def test_parent_mode_symlink_uid_and_file_mode_gid_link_refuse(self):
        parent=next(p for p in self.cache_parents if p!=self.cycle.work);parent.chmod(0o750)
        with self.assertRaisesRegex(n.Refused,'ancestor'):n.discovery_projection()
        parent.chmod(0o700);file=next(iter(self.cache_files));file.chmod(0o664)
        with self.assertRaisesRegex(n.Refused,'file_authority'):n.discovery_projection()
        file.chmod(0o660);os.link(file,self.root/'external-link')
        with self.assertRaisesRegex(n.Refused,'bounded_regular'):n.discovery_projection()
        (self.root/'external-link').unlink();saved=file.read_bytes();file.unlink();file.symlink_to(self.data_receipt)
        with self.assertRaisesRegex(n.Refused,'symlink'):n.discovery_projection()
        file.unlink();write(file,saved);file.chmod(0o660)
        original=n.identity
        with patch.object(n,'identity',side_effect=lambda p:{**original(p),'uid':1} if Path(p)==parent else original(p)):
            with self.assertRaisesRegex(n.Refused,'ancestor'):n.discovery_projection()
        original=n.file_record
        with patch.object(n,'file_record',side_effect=lambda p,*a,**kw:{**original(p,*a,**kw),'gid':1} if Path(p)==file else original(p,*a,**kw)):
            with self.assertRaisesRegex(n.Refused,'file_authority'):n.discovery_projection()
    def test_environment_is_checked_before_boundary_or_frozen_import(self):
        for value in ('',str(self.root/'other-cache')):
            with patch.dict(os.environ,{'KUBECACHEDIR':value}),patch.object(n,'frozen_data_reclaim') as loader:
                with self.assertRaisesRegex(n.Refused,'environment'):self.qualify()
                self.boundary.check.assert_not_called();loader.assert_not_called()
        self.operational.chmod(0o750)
        with self.assertRaisesRegex(n.Refused,'operational_cache'):self.qualify()
        self.boundary.check.assert_not_called()
    def test_record_refresh_even_same_bytes_or_parent_inode_change_is_refused(self):
        pin=self.qualify();file=next(iter(self.cache_files));temp=file.with_name('temporary')
        write(temp,file.read_bytes());temp.chmod(0o660);temp.replace(file)
        with self.assertRaisesRegex(n.Refused,'projection_changed'):n.validate_discovery_metadata(pin,self.leaves,self.aliases)
        self.assertFalse(n.METADATA_JOURNAL.exists())
    def test_wrong_external_pin_source_old_receipt_and_scope_refuse(self):
        pin=self.qualify()
        with self.assertRaisesRegex(n.Refused,'external_discovery'):n.validate_discovery_metadata('0'*64,self.leaves,self.aliases)
        with self.assertRaisesRegex(RuntimeError,'old_data_scope'):n.validate_discovery_metadata(pin,self.leaves[:-1],self.aliases)
        with self.assertRaisesRegex(RuntimeError,'old_data_boundary'):n.validate_discovery_metadata(pin,self.leaves,self.aliases,live_boundary={'changed':True})
        write(self.data_receipt,{**n.load(self.data_receipt),'changed':True})
        with self.assertRaisesRegex(RuntimeError,'old_data_source_or_receipt'):n.validate_discovery_metadata(pin,self.leaves,self.aliases)
        write(self.data_source,b'raise AssertionError("must not import")')
        with patch.object(n.importlib.util,'spec_from_file_location') as loader,self.assertRaises(n.Refused):
            n.validate_discovery_metadata(pin,self.leaves,self.aliases)
        loader.assert_not_called()
    def test_consumed_prior_or_new_journal_prevents_qualification_and_later_prior_blocks_apply(self):
        for journal in (n.JOURNAL,n.DATA_JOURNAL,n.METADATA_JOURNAL):
            write(journal/'intent.json',{'consumed':True})
            with self.subTest(journal=journal),self.assertRaisesRegex(n.Refused,'inspect_only_metadata'):self.qualify()
            self.assertFalse(n.METADATA_INTENT.exists());(journal/'intent.json').unlink();journal.rmdir()
        pin=self.qualify();engine=self.engine(pin);preview=engine.preview(self.leaves)
        write(n.DATA_JOURNAL/'intent.json',{'consumed':True})
        with self.assertRaisesRegex(n.Refused,'inspect_only_metadata'):
            engine.apply(preview,n.sha(n.encode(preview)),preview['script_sha256'])
        self.assertFalse(n.METADATA_JOURNAL.exists())
    def test_qualification_one_intent_and_bookend_drift_never_emits_receipt(self):
        self.boundary.check.side_effect=[self.fp,{**self.fp,'state_sha256':'changed'}]
        with self.assertRaisesRegex(n.Refused,'bookend'):self.qualify()
        self.assertTrue(n.METADATA_INTENT.exists());self.assertFalse(n.METADATA_RECEIPT.exists())
        with self.assertRaisesRegex(n.Refused,'already_consumed'):self.qualify()
    def test_unrelated_0660_metadata_still_refuses_and_cache_env_replacement_refuses(self):
        pin=self.qualify();other=self.cycle.bundle/'unapproved.json';write(other,{});other.chmod(0o660)
        with self.assertRaisesRegex(n.Refused,'protected_file_authority'):self.engine(pin).preview(self.leaves)
        other.unlink();self.operational.rename(self.root/'retained-old-operational');self.operational.mkdir(mode=0o700)
        with self.assertRaisesRegex(n.Refused,'source_bound_discovery'):n.validate_discovery_metadata(pin,self.leaves,self.aliases)
    def test_dangling_journal_and_discovery_parent_are_refused(self):
        n.DATA_JOURNAL.symlink_to(self.root/'missing')
        with self.assertRaisesRegex(n.Refused,'symlink'):self.qualify()
        self.assertFalse(n.METADATA_INTENT.exists())
    def test_original_guard_must_reject_with_exact_authority_reason(self):
        class OldRefused(RuntimeError):pass
        for error in (None,OldRefused('protected_inventory_bound'),RuntimeError('unexpected')):
            engine=SimpleNamespace(protected=Mock(side_effect=error))
            old=SimpleNamespace(Engine=Mock(return_value=engine),CYCLES=(),DATA_JOURNAL=n.DATA_JOURNAL,
                FROZEN_ALIAS_SHA=n.FROZEN_ALIAS_SHA,Refused=OldRefused)
            with self.subTest(error=error),self.assertRaises((n.Refused,RuntimeError)):
                n.previous_discovery_denial(old,self.leaves,[])
        old.Engine.return_value.protected.side_effect=OldRefused('protected_file_authority_changed')
        self.assertTrue(n.previous_discovery_denial(old,self.leaves,[])['denied'])
    def test_cli_invalid_pin_or_environment_fails_before_boundary_entry(self):
        argv=['reclaim','inspect','--leaf','/tmp/unused','--output','/tmp/unusable','--metadata-qualification-sha256']
        for pin in ('','short','A'*64):
            with patch.object(sys,'argv',argv+[pin]),patch.object(n.os,'geteuid',return_value=0),patch.object(n.os,'umask') as umask,patch.object(n,'LiveBoundary') as boundary:
                with self.assertRaisesRegex(n.Refused,'external_discovery'):n.main()
                boundary.assert_not_called();umask.assert_called_once_with(0o077)
        with patch.object(sys,'argv',argv+['a'*64]),patch.object(n.os,'geteuid',return_value=0),patch.dict(os.environ,{'KUBECACHEDIR':''}),patch.object(n.os,'umask') as umask,patch.object(n,'LiveBoundary') as boundary:
            with self.assertRaisesRegex(n.Refused,'environment'):n.main()
            boundary.assert_not_called();umask.assert_called_once_with(0o077)
    def test_recreated_cache_or_sealed_header_drift_refuses_before_engine_and_boundary(self):
        pin=self.qualify();saved=n.METADATA_RECEIPT.read_bytes()
        self.operational.rename(self.root/'retained-original-operational');self.operational.mkdir(mode=0o700)
        argv=['reclaim','inspect','--leaf','/tmp/unused','--output','/tmp/unusable','--metadata-qualification-sha256']
        with patch.object(sys,'argv',argv+[pin]),patch.object(n.os,'geteuid',side_effect=[0]+[os.getuid()]*1000),patch.object(n.os,'umask') as umask,patch.object(n,'Engine') as engine,patch.object(n,'LiveBoundary') as boundary:
            with self.assertRaisesRegex(n.Refused,'source_bound_discovery'):n.main()
            engine.assert_not_called();boundary.assert_not_called();umask.assert_called_once_with(0o077)
        self.operational.rmdir();(self.root/'retained-original-operational').rename(self.operational)
        for field,value in (('script_sha256','0'*64),('kind','foreign'),('version',2)):
            record={**json.loads(saved),field:value};write(n.METADATA_RECEIPT,record)
            changed_pin=n.sha(n.METADATA_RECEIPT.read_bytes())
            with patch.object(sys,'argv',argv+[changed_pin]),patch.object(n.os,'geteuid',side_effect=[0]+[os.getuid()]*1000),patch.object(n.os,'umask'),patch.object(n,'LiveBoundary') as boundary:
                with self.assertRaisesRegex(n.Refused,'source_bound_discovery'):n.main()
                boundary.assert_not_called()
    def test_cache_bind_ancestor_or_submount_refuses_before_any_boundary(self):
        rows=n.mount_rows(Path('/proc/self/mountinfo').read_text());cover=n.discovery_environment()['covering_mount']
        for target in (self.operational,self.operational/'nested',self.operational.parent):
            bind={**cover,'id':999999,'parent':cover['id'],'target':str(target),'root':str(self.cache)}
            with self.subTest(target=target),patch.object(n,'mount_rows',return_value=[*rows,bind]):
                with self.assertRaisesRegex(n.Refused,'mount_alias'):self.qualify()
                self.boundary.check.assert_not_called();self.assertFalse(n.METADATA_INTENT.exists())
    def test_covering_mount_projection_drift_is_pinned_by_preflight(self):
        pin=self.qualify();rows=n.mount_rows(Path('/proc/self/mountinfo').read_text())
        cover=n.discovery_environment()['covering_mount']
        changed=[{**row,'options':[*row['options'],'changed']} if row==cover else row for row in rows]
        with patch.object(n,'mount_rows',return_value=changed),self.assertRaisesRegex(n.Refused,'source_bound_discovery'):
            n.preflight_discovery_metadata(pin)
    def test_oversized_historical_cache_refuses_before_legacy_guard_hashing(self):
        next(iter(self.cache_files)).write_bytes(b'x'*65537)
        with patch.object(n,'previous_discovery_denial') as legacy_guard,self.assertRaisesRegex(n.Refused,'bounded_regular'):
            self.qualify()
        legacy_guard.assert_not_called();self.assertFalse(n.METADATA_RECEIPT.exists())

    def test_discovery_size_bound_is_enforced_before_hashing(self):
        file=next(iter(self.cache_files));file.write_bytes(b'x'*65537)
        with patch.object(n.hashlib,'file_digest') as digest,self.assertRaisesRegex(n.Refused,'bounded_regular'):
            n.file_record(file,private=False,maximum=65536)
        digest.assert_not_called()

    def test_schema_bound_and_parent_inode_refresh_are_refused(self):
        file=self.cache/'v1/serverresources.json';saved=file.read_bytes()
        write(file,{**json.loads(saved),'groupVersion':'foreign/v1'});file.chmod(0o660)
        with self.assertRaisesRegex(n.Refused,'schema'):n.discovery_projection()
        write(file,saved);file.chmod(0o660);pin=self.qualify()
        parent=file.parent;parent.rename(self.root/'retained-discovery-parent');parent.mkdir(mode=0o700)
        write(file,saved);file.chmod(0o660)
        with self.assertRaisesRegex(n.Refused,'projection_changed'):n.validate_discovery_metadata(pin,self.leaves,self.aliases)

    def test_old_code_uses_own_file_and_unchanged_default_remains_strict(self):
        pin=self.qualify();old=n.frozen_data_reclaim()
        self.assertEqual(old.validate_retained_data_scope.__code__.co_filename,str(self.data_source))
        self.assertEqual(Path(old.__file__),self.data_source)
        self.assertEqual(old.validate_retained_data_scope(n.FROZEN_DATA_SHA,self.leaves,self.aliases),n.load(self.data_receipt))
        with patch.object(n,'DATA_RECEIPT',self.data_receipt),self.assertRaises(n.Refused):
            n.validate_retained_data_scope(n.FROZEN_DATA_SHA,self.leaves,self.aliases)
        with self.assertRaisesRegex(n.Refused,'fixed_metadata_apply_scope'):
            n.Engine(self.cycles,n.DATA_JOURNAL,self.guard,qualification_sha=n.FROZEN_ALIAS_SHA,
                retained_data_qualification_sha=n.FROZEN_DATA_SHA,metadata_qualification_sha=pin)


class LiveBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.cycle=fixture(Path(self.temp.name))
        code=b'''import contextlib,importlib\nregistered=importlib.import_module(__name__)\nevents=[]\nclass Controller:\n def __init__(self,bundle,plan,context):\n  assert context=='default';self.root=bundle\n @contextlib.contextmanager\n def locked(self):\n  events.append('lock-enter')\n  try:yield\n  finally:events.append('lock-exit')\n def guard(self):events.append('guard')\n def storage_guard(self,schema,owner):\n  assert schema==18 and owner is False;events.append('storage')\n def state(self):return {'runtime':'fallback','phase':'withdrawn','configs':'paused','replicas':{'postgres':1,'writer':0,'backend':0},'pods':{'postgres':{'uid':'original'}}}\n'''
        write(self.cycle.install/'upgrade-controller.py',code)
        source_sha=n.sha(code);write(self.cycle.work/'source-manifest.json',{'upgrade-controller.py':source_sha})
        write(self.cycle.bundle/'prepared.json',{'prepared':'exact'})
        values={'PREVIOUS':self.cycle,'PREVIOUS_CONTROLLER_SHA':source_sha,
            'PREVIOUS_MANIFEST_SHA':n.sha((self.cycle.work/'source-manifest.json').read_bytes()),
            'PREVIOUS_SOURCE_NAMES':{'upgrade-controller.py'}}
        self.patch=patch.multiple(n,**values);self.patch.start();self.addCleanup(self.patch.stop)
        def load_controller(path,expected,bundle,context,*,receipt_sha):
            self.assertEqual(n.sha(Path(path).read_bytes()),expected)
            self.assertEqual(receipt_sha,'b'*64)
            spec=importlib.util.spec_from_file_location('cycle4_reclaim_exact_predecessor',path)
            value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;spec.loader.exec_module(value)
            return value.Controller(bundle,str(Path(bundle)/'plan.json'),context)
        bridge=type('Bridge',(),{})()
        bridge.load_controller=load_controller
        bridge.native_guard=lambda _:{'edge':{'pid':123}}
        edge_patch=patch.object(n,'bound_edge_bridge',return_value=(bridge,'b'*64,'c'*64))
        edge_patch.start();self.addCleanup(edge_patch.stop)
    def test_exact_sources_are_imported_registered_and_checked_inside_lock(self):
        with n.LiveBoundary() as boundary:
            fingerprint=boundary.check();module=sys.modules['cycle4_reclaim_exact_predecessor']
            self.assertIs(module.registered,module)
            self.assertEqual(module.events[0],'lock-enter')
            self.assertNotIn('lock-exit',module.events)
        self.assertEqual(module.events[-1],'lock-exit')
        self.assertEqual(fingerprint['controller_sha256'],n.PREVIOUS_CONTROLLER_SHA)
    def test_changed_source_is_refused_before_execution(self):
        write(self.cycle.install/'upgrade-controller.py',b'raise AssertionError("must not execute")\n')
        with self.assertRaisesRegex(n.Refused,'previous_source_changed'):
            with n.LiveBoundary():pass
    def test_changed_state_is_refused_and_lock_released(self):
        with self.assertRaisesRegex(n.Refused,'withdrawn_schema18'):
            with n.LiveBoundary() as boundary:
                boundary.controller.state=lambda:{'runtime':'target'}
        self.assertEqual(sys.modules['cycle4_reclaim_exact_predecessor'].events[-1],'lock-exit')


if __name__=='__main__':unittest.main()
