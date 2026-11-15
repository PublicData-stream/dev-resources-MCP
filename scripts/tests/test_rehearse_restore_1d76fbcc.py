"""Local adapter boundaries; real PostgreSQL rehearsal remains an operational gate."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value);return value
m=module('real_restore_rehearsal',ROOT/'deploy/production/rehearse_restore_1d76fbcc.py')
r=module('real_restore_source',ROOT/'deploy/production/restore_1d76fbcc.py')
cp=module('real_checkpoint_source',ROOT/'deploy/production/checkpoint_1d76fbcc.py')

class AdapterBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='restore-rehearsal-tests-',dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.a=m.Adapter.__new__(m.Adapter);self.a.root=self.root;self.a.token='ab'*12
        self.a.pgimage='sha256:'+'c'*64;self.a.cid='a'*64;self.a.name='owned-isolated-pg'
        self.row={'Id':self.a.cid,'Image':self.a.pgimage,'Config':{'Labels':{m.LABEL:self.a.token}},
                  'HostConfig':{'NetworkMode':'none','PortBindings':None},'State':{'Running':False,'StartedAt':'now'},
                  'Mounts':[{'Type':'bind','Source':str(self.root/'pg')}],'RestartCount':0}
    def test_adapter_rejects_foreign_image_token_network_ports_and_mounts(self):
        for change in ('image','token','network','port','mount'):
            row=copy.deepcopy(self.row)
            if change=='image':row['Image']='foreign'
            elif change=='token':row['Config']['Labels'][m.LABEL]='foreign'
            elif change=='network':row['HostConfig']['NetworkMode']='bridge'
            elif change=='port':row['HostConfig']['PortBindings']={'5432/tcp':[{'HostPort':'5432'}]}
            else:row['Mounts'][0]['Source']='/database/devres/corpus'
            with self.subTest(change=change),patch.object(m,'run',return_value=m.encoded([row])):
                with self.assertRaises(m.Stop):self.a.inspect()
    def test_no_production_kubernetes_or_resource_command_is_available(self):
        self.a.layout={};self.a.cache_data={'layouts':{}}
        with patch.object(m,'run') as run:
            for args in (('get','pods'),('exec','deployment/postgres'),('scale','deployment/backend','--replicas=0'),('delete','pod','postgres')):
                with self.assertRaisesRegex(m.Stop,'production_resource_operation_prohibited'):self.a.k(*args)
            run.assert_not_called()
    def test_stop_start_wait_and_health_use_only_owned_docker_identity(self):
        calls=[]
        def run(args,*a,**kw):
            calls.append(args)
            return m.encoded([self.row]) if args[1]=='inspect' else b''
        with patch.object(m,'run',side_effect=run):
            self.a.k('scale','deployment/postgres','--replicas=0')
            self.a.k('wait','--for=delete','pod','-l','app=postgres','--timeout=180s')
            self.a.k('scale','deployment/postgres','--replicas=1')
        self.assertIn(['docker','stop','--time','60',self.a.cid],calls)
        self.assertIn(['docker','start',self.a.cid],calls)
        self.assertTrue(all(args[0]=='docker' for args in calls))
    def test_scalar_sql_is_json_encoded_and_only_owned_container_executes(self):
        calls=[]
        def run(args,*a,**kw):
            calls.append(args)
            return m.encoded([self.row]) if args[1]=='inspect' else b'true\n'
        with patch.object(m,'run',side_effect=run):
            self.assertIs(self.a.sql('SELECT to_json(true)'),True)
        self.assertEqual(calls[1][:3],['docker','exec',self.a.cid])
    def test_real_initial_rsync_copy_is_distinct_and_hash_verified(self):
        if not Path('/usr/bin/rsync').exists():self.skipTest('rsync unavailable')
        source=self.root/'golden';source.mkdir();(source/'PG_VERSION').write_bytes(b'18\n')
        (source/'retained').write_bytes(b'current-public-capture')
        target=self.root/'owned/copy';target.mkdir(parents=True)
        expected=r.manifest(cp,source)['sha256']
        with patch.object(m,'STATE',self.root/'owned'):
            m.copy_initial(cp,r,source,target,expected)
            self.assertEqual(r.manifest(cp,target)['sha256'],expected)
            self.assertNotEqual((source/'retained').stat().st_ino,(target/'retained').stat().st_ino)
            with self.assertRaisesRegex(m.Stop,'fresh_isolated_copy_required'):m.copy_initial(cp,r,source,target,expected)
    def test_source_pin_checked_before_import(self):
        path=self.root/'module.py';path.write_text('raise RuntimeError("must not execute")');path.chmod(0o600)
        with self.assertRaisesRegex(m.Stop,'source_pin_changed'):m.bound_module(path,'f'*64,'unsafe')
    def test_private_hash_rejects_hardlink_or_symlink(self):
        path=self.root/'private';path.write_bytes(b'private-state');path.chmod(0o600)
        self.assertEqual(m.file_hash(path),m.sha(b'private-state'))
        link=self.root/'linked';os.link(path,link)
        with self.assertRaisesRegex(m.Stop,'private_artifact_required'):m.file_hash(path)
        link.unlink();link.symlink_to(path)
        with self.assertRaisesRegex(m.Stop,'private_artifact_path_required'):m.file_hash(link)
    def test_production_fingerprint_has_only_declared_admission_and_golden_files(self):
        bundle=self.root/'bundle';bundle.mkdir();state=self.root/'checkpoint';state.mkdir()
        for path in [*(bundle/name for name in ('state.json','prepared.json','plan.json')),
                     *(state/name for name in ('completed.json','checkpoint-completed.json'))]:
            path.write_bytes(b'owned');path.chmod(0o600)
        with patch.object(m,'BUNDLE',bundle):
            files=m.production_files(types.SimpleNamespace(S=state,MAX_MANIFEST=1024))
        self.assertEqual(len(files),5)
        before=m.production_fingerprint(files);files[str(bundle/'state.json')]='changed'
        self.assertNotEqual(before,m.production_fingerprint(files))

if __name__=='__main__':unittest.main()
