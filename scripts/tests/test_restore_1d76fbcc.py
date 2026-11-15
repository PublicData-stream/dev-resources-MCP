"""Synthetic cold PGDATA restoration and interruption cuts; no server/provider I/O."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
m = module('restore_1d76_fixture', ROOT / 'deploy/production/restore_1d76fbcc.py')
cp_source = module('restore_checkpoint_fixture', ROOT / 'deploy/production/checkpoint_1d76fbcc.py')

class RestoreCuts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='devres-restore-test-', dir='/tmp')
        self.root = Path(self.temp.name)
        self.pv = self.root / 'pv'; self.live = self.pv / '18/docker'; self.live.mkdir(parents=True)
        self.state_root = self.root / 'checkpoint'; self.state_root.mkdir(mode=0o700)
        self.golden = self.state_root / 'pg-checkpoint'; self.golden.mkdir(mode=0o700)
        for path, schema in ((self.live, 19), (self.golden, 18)):
            (path / 'PG_VERSION').write_bytes(b'18\n'); (path / 'schema').write_text(str(schema))
            (path / 'base').mkdir(); (path / 'base/retained').write_text('post-task' if schema == 19 else 'current-pre-task')
        self.pg = 1; self.apps = 0; self.calls = []; self.records = []; self.guard_calls = []
        self.archive = {**cp_source.ARCHIVE, 'store_id': 'a'*32}
        self.layout = {'source': str(self.live), 'pv_uid':'pvuid','pv_name':'corpus-pv','pvc_uid':'pvcuid','pvc_name':'corpus',
                       'pv_path':str(self.pv),'relative':'18/docker','container_data_directory':'/var/lib/postgresql/18/docker'}
        self.baseline = {'layout':self.layout, 'identity':{'archive':self.archive}}
        self.cache_roots = {role: self.root / ('cache-' + role) for role in ('serving','writer')}
        self.cache_data = {'layouts':{}, 'manifests':{}}
        for role, path in self.cache_roots.items():
            path.mkdir(mode=0o700); (path/'workspace').write_text('pre-task-' + role)
            target=self.state_root/'fallback-cache'/role; target.parent.mkdir(mode=0o700,exist_ok=True)
            shutil.copytree(path,target)
            self.cache_data['layouts'][role]={'path':str(path),'identity':m.tree_identity(path),
                'pvc_name':role,'pv_name':'pv-'+role,'pvc_uid':'uid-'+role,'pv_uid':'pvuid-'+role}
            self.cache_data['manifests'][role]=cp_source.cache_manifest(path)
            (path/'workspace').write_text('newer-task-' + role)
        self.cp = types.SimpleNamespace(S=self.state_root, PV=self.pv, SYSID=cp_source.SYSID, POLICY=cp_source.POLICY,
            PG=cp_source.PG, MAX_MANIFEST=cp_source.MAX_MANIFEST, scan_tree=cp_source.scan_tree,
            load=self.load_checkpoint, raw=lambda p,*a:Path(p).read_bytes(), get=self.get, k=self.k,
            roles_stopped=self.roles_stopped, role_pods=self.role_pods, schema_identity=self.identity,
            image_id=lambda ref:'pinned-pg-image', control=self.control, checked_identity=self.check_identity,
            pod_projection=lambda row:row, CACHE_ROOTS=self.cache_roots, cache_manifest=cp_source.cache_manifest,
            copy_cache=cp_source.copy_cache)
        self.controller_root=self.root/'controller';self.controller_root.mkdir(mode=0o700)
        m.save(self.controller_root/'rollback-intent.json',{'source_sha256':'a'*64,'maximum_attempts':1})
        self.c = types.SimpleNamespace(restore_guard=self.guard, restore_record=self.records.append,
            root=self.controller_root,state=lambda:{'runtime':'target','phase':'withdrawn'})
        self.restore = m.Restore(self.cp, self.c, self.root / 'restore')
        self.gold_hash = m.manifest(self.cp, self.golden)['sha256']
        self.patches = [patch.object(m, 'checked_golden', return_value={'pg_files_sha256':self.gold_hash}),
                        patch.object(m, 'RESERVE', 0), patch.object(m,'no_nested_mounts',return_value=True)]
        for item in self.patches: item.start()
        self.pins = {'controller':'a'*64, 'checkpoint':'b'*64, 'prepared':'c'*64}
    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()
    def load_checkpoint(self, name):
        if name == 'baseline.json': return self.baseline
        if name == 'checkpoint-completed.json': return {'pg_bytes':1024}
        if name == 'cache-baselines.json': return self.cache_data
        raise AssertionError(name)
    def get(self, kind, name):
        for role, path in self.cache_roots.items():
            if name == role and kind == 'pvc': return {'metadata':{'uid':'uid-'+role},'spec':{'volumeName':'pv-'+role}}
            if name == 'pv-'+role and kind == 'pv': return {'metadata':{'uid':'pvuid-'+role},'spec':{'local':{'path':str(path)}}}
        if kind == 'pvc': return {'metadata':{'uid':'pvcuid'}, 'spec':{'volumeName':'corpus-pv'}}
        if kind == 'pv': return {'metadata':{'uid':'pvuid'}, 'spec':{'local':{'path':str(self.pv)}}}
        if kind == 'deployment': return {'spec':{'replicas':self.pg}}
        raise AssertionError((kind,name))
    def k(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ('scale','deployment/postgres'): self.pg = int(args[2].split('=')[1])
        return b''
    def roles_stopped(self):
        m.need(self.apps == 0, 'fixture_application_owner_present')
    def role_pods(self, role):
        return [{'uid':'restored-pg' if (self.live/'schema').read_text() == '18' else 'original-pg'}] if self.pg and role == 'postgres' else []
    def guard(self, stage='', **kwargs):
        self.guard_calls.append(stage); self.roles_stopped()
    def identity(self):
        return {'system_id':self.cp.SYSID,'schema':int((self.live/'schema').read_text()),'recovery':False,
                'external_tablespaces':0,'publication_owners':0,'archive':copy.deepcopy(self.archive),
                'attribution':{'control':{'data':self.cp.POLICY}}}
    def control(self, path, image):
        m.need((path/'PG_VERSION').read_bytes() == b'18\n' and not (path/'postmaster.pid').exists(), 'fixture_unclean_control')
        if path == self.live: m.need(self.pg == 0, 'fixture_running_pg_control')
        return {'system_id':self.cp.SYSID,'cluster_state':'shut down'}
    def check_identity(self, value, stopped=False):
        m.need(value['schema'] == 18 and value['publication_owners'] == 0, 'fixture_restored_schema_identity')
    def staged(self):
        if not Path('/usr/bin/rsync').exists(): self.skipTest('rsync unavailable')
        state = self.restore.admit(self.pins); self.restore.stage(state); return state
    def stopped(self):
        state = self.staged(); self.restore.stop(state); return state
    def test_actual_copy_rename_fsync_and_preserved_current_pair(self):
        if not Path('/usr/bin/rsync').exists(): self.skipTest('rsync unavailable')
        events=[]
        realrename=m.os.rename
        def rename(src,dst): events.append(('rename',str(src),str(dst))); return realrename(src,dst)
        with patch.object(m.os,'rename',side_effect=rename),patch.object(m,'sync',wraps=m.sync) as sync:
            receipt = self.restore.run(self.pins)
        self.assertTrue(receipt['database_restored']); self.assertEqual(receipt['schema'],18)
        self.assertFalse(receipt['fallback_accepted']); self.assertEqual(self.pg,1)
        self.assertEqual((self.live/'base/retained').read_text(),'current-pre-task')
        state=self.restore.state(); _,preserved=self.restore.paths(state)
        self.assertEqual((preserved/'base/retained').read_text(),'post-task')
        self.assertEqual(len(events),6); self.assertTrue(sync.called); self.assertEqual(len(self.records),1)
        self.assertEqual(self.records[0]['new_pg_pod'],{'uid':'restored-pg'})
        for role,path in self.cache_roots.items():
            self.assertEqual((path/'workspace').read_text(),'pre-task-'+role)
            preserved_cache=path.with_name('.failed-'+role+'-'+state['token'])
            self.assertEqual((preserved_cache/'workspace').read_text(),'newer-task-'+role)
    def test_bad_golden_or_owner_never_stops_postgres(self):
        self.apps=1
        with self.assertRaisesRegex(m.Stop,'fixture_application'): self.restore.run(self.pins)
        self.assertFalse(self.calls)
        self.apps=0
        with patch.object(m,'checked_golden',side_effect=m.Stop('corrupt_golden')):
            with self.assertRaisesRegex(m.Stop,'corrupt_golden'): self.restore.run(self.pins)
        self.assertFalse(self.calls)
    def test_archive_mismatch_and_system_identifier_block_restore(self):
        self.archive['epoch']+=1
        # baseline must remain immutable; fixture archive copied independently here.
        self.baseline['identity']['archive']={**self.archive,'epoch':2}
        with self.assertRaisesRegex(m.Stop,'archive_binding'): self.restore.run(self.pins)
        self.assertFalse(self.calls)
    def test_preservation_hash_failure_still_restores_golden(self):
        state=self.stopped(); real=m.manifest
        def manifest(cp,path):
            if path == self.live: raise OSError('fixture preservation disk failure')
            return real(cp,path)
        with patch.object(m,'manifest',side_effect=manifest): self.restore.preserve_and_install(state)
        self.restore.restore_caches(state)
        receipt=self.restore.restart(state)
        self.assertEqual(receipt['preservation'],'manifest_incomplete')
        self.assertTrue(receipt['preserved_directory']); self.assertTrue(receipt['database_restored'])
    def test_preservation_rename_failure_allows_scoped_current_sql_loss(self):
        state=self.stopped(); real=m.os.rename
        def rename(src,dst):
            if src == self.live: raise PermissionError('fixture preserve failure')
            return real(src,dst)
        with patch.object(m.os,'rename',side_effect=rename),patch.object(m,'no_nested_mounts',return_value=True):
            self.restore.preserve_and_install(state)
        self.restore.restore_caches(state)
        receipt=self.restore.restart(state)
        self.assertEqual(receipt['preservation'],'post_task_sql_lost'); self.assertFalse(receipt['preserved_directory'])
        self.assertTrue((self.restore.root/'discard-original-intent.json').exists())
    def test_no_deletion_on_mount_or_foreign_inode_drift(self):
        state=self.stopped(); real=m.os.rename
        def rename(src,dst):
            if src == self.live: raise PermissionError('fixture preserve failure')
            return real(src,dst)
        with patch.object(m.os,'rename',side_effect=rename),patch.object(m,'no_nested_mounts',return_value=False):
            with self.assertRaisesRegex(m.Stop,'nested_mount'): self.restore.preserve_and_install(state)
        self.assertEqual((self.live/'schema').read_text(),'19')
        self.assertFalse((self.restore.root/'discard-original-intent.json').exists())
    def test_cut_after_first_rename_reconciles_before_install(self):
        state=self.stopped(); real=m.os.rename
        def rename(src,dst):
            real(src,dst)
            if src == self.live: raise RuntimeError('power cut after first rename')
        with patch.object(m.os,'rename',side_effect=rename):
            with self.assertRaisesRegex(RuntimeError,'power cut'): self.restore.preserve_and_install(state)
        self.assertFalse(self.live.exists()); self.assertEqual(self.pg,0)
        receipt=self.restore.run(self.pins,resume=True)
        self.assertTrue(receipt['database_restored']); self.assertEqual((self.live/'schema').read_text(),'18')
    def test_cut_after_second_rename_reconciles_without_repeating_it(self):
        state=self.stopped(); real=m.os.rename
        def rename(src,dst):
            real(src,dst)
            if dst == self.live: raise RuntimeError('power cut after install')
        with patch.object(m.os,'rename',side_effect=rename):
            with self.assertRaisesRegex(RuntimeError,'power cut'): self.restore.preserve_and_install(state)
        def no_database_replay(src,dst):
            if src == self.live or dst == self.live: raise AssertionError('must not replay database rename')
            return os_rename(src,dst)
        os_rename=m.os.rename
        with patch.object(m.os,'rename',side_effect=no_database_replay):
            receipt=self.restore.run(self.pins,resume=True)
        self.assertTrue(receipt['database_restored'])
    def test_changed_stage_or_clean_shutdown_failure_never_removes_live(self):
        state=self.stopped(); stage,_=self.restore.paths(state); (stage/'schema').write_text('bad')
        with self.assertRaisesRegex(m.Stop,'staging_changed'): self.restore.preserve_and_install(state)
        self.assertEqual((self.live/'schema').read_text(),'19')
        (self.live/'postmaster.pid').touch()
        with self.assertRaisesRegex(m.Stop,'pid_remains'): self.restore.preserve_and_install(state)
    def test_changed_pins_and_unknown_rename_outcome_fail_closed(self):
        state=self.stopped(); stage,preserved=self.restore.paths(state)
        with self.assertRaisesRegex(m.Stop,'pins_changed'): self.restore.run({**self.pins,'controller':'f'*64},resume=True)
        os.rename(self.live,preserved); self.live.mkdir(); (self.live/'schema').write_text('19')
        with self.assertRaisesRegex(m.Stop,'outcome_uncertain'): self.restore.run(self.pins,resume=True)
        self.assertEqual(self.pg,0)
    def test_completed_restore_is_idempotent_but_never_replays_service_start(self):
        if not Path('/usr/bin/rsync').exists(): self.skipTest('rsync unavailable')
        first=self.restore.run(self.pins); count=len(self.calls)
        again=self.restore.run(self.pins,resume=True)
        self.assertEqual(first,again); self.assertEqual(len(self.calls),count)
        with self.assertRaisesRegex(m.Stop,'single_restore_attempt'): self.restore.run(self.pins)
    def test_failed_postgres_start_keeps_apps_stopped_and_resumes_exact_database(self):
        state=self.stopped(); self.restore.preserve_and_install(state)
        self.restore.restore_caches(state)
        real=self.cp.k
        def start(*args,**kwargs):
            if args[:2] == ('rollout','status'): raise OSError('fixture start outcome lost')
            return real(*args,**kwargs)
        with patch.object(self.cp,'k',side_effect=start):
            with self.assertRaises(OSError): self.restore.restart(state)
        self.assertEqual(self.apps,0)
        receipt=self.restore.run(self.pins,resume=True)
        self.assertTrue(receipt['database_restored']); self.assertEqual(len(self.records),1)
    def test_restore_module_refuses_changed_source_before_import(self):
        path=self.root/'module.py'; path.write_text('raise RuntimeError("must not execute")'); path.chmod(0o600)
        with self.assertRaisesRegex(m.Stop,'pinned_module_changed'): m.checked_module(path,'f'*64,'never_import')

if __name__ == '__main__': unittest.main()
