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
