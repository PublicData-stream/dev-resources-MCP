"""Offline first-party checkpoint guards. No provider/network or host mutations."""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('checkpoint_fixture', HERE.parents[1] / 'deploy/production/checkpoint_1d76fbcc.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Fixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='checkpoint-fixtures-', dir='/tmp')
        self.root = Path(self.tmp.name)
        self.s = self.root / 'state'; self.s.mkdir(mode=0o700)
        # Synthetic fixtures assert fsync ordering separately; avoid committing hundreds
        # of tiny fixture receipts to the shared host journal.
        self.patches = [patch.object(m, 'N', self.root), patch.object(m, 'S', self.s), patch.object(m.os, 'fsync')]
        for p in self.patches: p.start()
        self.public=self.root/'public.json'
        p=patch.object(m,'PUBLIC',self.public);self.patches.append(p);p.start()
        m.new(self.public,{'attribution_target_ids':['a'*64]})
        m.save('owner.json', {'token': 'ab'*12})
    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()
    def rejects(self, code, fn, *args):
        with self.assertRaisesRegex(m.Stop, code): fn(*args)
    def tree(self, name='pg-checkpoint'):
        p=self.s/name; p.mkdir(mode=0o700); (p/'PG_VERSION').write_bytes(b'18\n'); return p
    def deploy(self):
        return {'metadata':{'uid':'deployment'}, 'spec':{'replicas':1,'template':{'spec':{'containers':[{'name':'postgres','image':m.PG,'volumeMounts':[{'name':'pg','mountPath':'/var/lib/postgresql'}]}], 'volumes':[{'name':'pg','persistentVolumeClaim':{'claimName':'corpus'}}]}}}}
    def identity(self):
        return {'system_id':m.SYSID,'schema':18,'recovery':False,'external_tablespaces':0,'wikipedia_tables':2,'schema18_objects':4,'attribution':{'origin_table':True,'control':{'data':m.POLICY,'data_integrity':'a'*64},'targets':[{'id':'a'*64,'policy_epoch':2,'data':{'generation':'c'*64}}],'generations':[{'id':m.GENERATION,'data':{},'data_integrity':'b'*64},{'id':'c'*64,'data':{'policy_epoch':2},'data_integrity':'d'*64}]},'publication_owners':0,'data_directory':'/var/lib/postgresql/18/docker','archive':{**m.ARCHIVE,'store_id':'a'*32}}
    def pod(self):
        return {'metadata':{'name':'postgres-fixture','uid':'pod','ownerReferences':[{'uid':'rs'}]},'status':{'phase':'Running','podIP':'10.42.0.3','containerStatuses':[{'ready':True,'state':{'running':{'startedAt':'now'}},'containerID':'containerd://a','imageID':'repo@sha256:b','restartCount':0}]}}
    def config(self):
        parts=['[source]\nurl="https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.91c7bcb7/source.tar.gz"']
        for p in m.PROVIDERS: parts += ['['+p+']\nenabled=true'+ ('\npackages=["fixture"]\nadvisories_enabled=true' if p=='npm' else '')]
        parts += ['[storage]\nbackend="s3"\nblob_dir="/data/cache"\ndatabase_url="postgres://devres_reader:fixture@postgres/devres"\nscratch_dir="/tmp/devres-serving"','[storage.s3]\nprefix="production"\ncache_max_bytes=34359738368','[storage.s3.credentials]\nmode="files"\naccess_key_file="/run/devres-s3/access-key"\nsecret_key_file="/run/devres-s3/secret-key"','[writer_client]\nendpoint="https://writer.devres.svc:9443/v1/acquire"\ntoken_file="/run/devres-writer-identity/token"']
        return '\n'.join(parts)+'\n'
    def test_exclusive_private_receipts(self):
        m.save('receipt.json', {'ok':True})
        self.assertEqual((self.s/'receipt.json').stat().st_mode & 0o777,0o600)
        with self.assertRaises(FileExistsError): m.save('receipt.json',{})
        self.rejects('record_basename_required',m.save,'../outside.json',{})
    def test_duplicate_input_rejected(self):
        self.rejects('duplicate_json_key',m.decode,b'{"x":1,"x":2}')
    def test_symlink_and_hardlink_input_refused(self):
        p=self.s/'a';p.write_bytes(b'bytes');os.chmod(p,0o600)
        (self.s/'alias').symlink_to(p)
        with self.assertRaises(OSError):m.raw(self.s/'alias')
        os.link(p,self.s/'hard');self.rejects('bounded_regular_file_required',m.raw,p)
    def test_scan_hashes_and_metadata_stable(self):
        p=self.tree();(p/'base').mkdir();(p/'base'/'a').write_bytes(b'actual data')
        rows,total=m.scan_tree(p,True)
        self.assertEqual(rows,m.scan_tree(p,True)[0]);self.assertEqual(total,14)
        self.assertEqual(next(r['sha256'] for r in rows if r['path']=='base/a'),hashlib.sha256(b'actual data').hexdigest())
    def test_scan_rejects_symlink_hardlink_signal(self):
        p=self.tree();(p/'bad').symlink_to('/etc/passwd')
        self.rejects('pg_symlink_special',m.scan_tree,p);(p/'bad').unlink()
        os.link(p/'PG_VERSION',p/'bad');self.rejects('pg_hardlink_refused',m.scan_tree,p);(p/'bad').unlink()
        (p/'standby.signal').touch();self.rejects('primary_only',m.scan_tree,p)
    def test_scan_bounds_and_nonregular(self):
        p=self.tree()
        with patch.object(m,'MAX_PG_BYTES',2):self.rejects('pg_checkpoint_bound',m.scan_tree,p)
        os.mkfifo(p/'fifo');self.rejects('pg_symlink_special',m.scan_tree,p)
    def test_delete_copy_only_owned_destination(self):
        src=self.root/'source';src.mkdir();dst=self.tree()
        with patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')) as call:
            m.copy_tree(src,dst);argv=call.call_args.args[0]
            self.assertIn('--delete',argv);self.assertIn('--checksum',argv);self.assertEqual(argv[-1],str(dst)+'/')
            self.rejects('only_exact_owned',m.copy_tree,src,self.root/'outside')
            self.assertEqual(call.call_count,1)
    def test_final_copy_flushes_files_and_directory_entries_before_return(self):
        src=self.root/'source';src.mkdir();dst=self.tree();(dst/'base').mkdir();(dst/'base/block').write_bytes(b'data')
        events=[]
        def copy(*a,**kw):events.append('copy');return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
        original_sync=m.os.fsync
        def fsync(fd):events.append('fsync');return original_sync(fd)
        with patch.object(m.subprocess,'run',side_effect=copy),patch.object(m.os,'fsync',side_effect=fsync):
            result=m.copy_tree(src,dst)
        self.assertEqual(events[0],'copy');self.assertGreaterEqual(events.count('fsync'),5)
        self.assertTrue(result['durable_files_and_directories'])
        with patch.object(m.subprocess,'run',side_effect=copy),patch.object(m,'flush_owned_copy') as flush:
            result=m.copy_tree(src,dst,True);flush.assert_not_called();self.assertFalse(result['durable_files_and_directories'])

    def test_overlap_and_destination_symlink_refused(self):
        dst=self.tree();self.rejects('overlapping_copy',m.copy_tree,dst,dst)
        shutil.rmtree(dst);dst.symlink_to(self.root)
        self.rejects('owned_copy_destination',m.dest_checked,dst)
    def test_live_vanished_file_allowed_final_never(self):
        dst=self.tree();src=self.root/'source';src.mkdir()
        with patch.object(m.subprocess,'run',return_value=types.SimpleNamespace(returncode=24,stdout=b'',stderr=b'vanished')):
            self.assertTrue(m.copy_tree(src,dst,True)['untrusted_live_precopy'])
            self.rejects('physical_copy_failed',m.copy_tree,src,dst)
    def test_final_checksum_required_for_equal_size_equal_second_precopy(self):
        src=self.root/'source';src.mkdir();(src/'same').write_bytes(b'new!');dst=self.tree();(dst/'same').write_bytes(b'old!')
        # Both snapshots intentionally have exactly equal size and whole-second mtime.
        timestamp=1700000000
        os.utime(src/'same',(timestamp,timestamp));os.utime(dst/'same',(timestamp,timestamp))
        if not Path('/usr/bin/rsync').exists():self.skipTest('system rsync unavailable')
        # Exercise the real system utility only against these synthetic /tmp paths.
        m.copy_tree(src,dst,True);self.assertEqual((dst/'same').read_bytes(),b'old!')
        m.copy_tree(src,dst);self.assertEqual((dst/'same').read_bytes(),b'new!')

    def test_separate_copy_no_golden_mutation(self):
        src=self.tree();(src/'block').write_bytes(b'immutable');dst=self.tree('pg-clone')
        before=m.scan_tree(src,True)
        def rsync(args,**kw):
            shutil.copytree(src,dst,dirs_exist_ok=True);return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
        with patch.object(m.subprocess,'run',side_effect=rsync):m.copy_tree(src,dst)
        (dst/'block').write_bytes(b'clone changed')
        self.assertEqual(before,m.scan_tree(src,True));self.assertNotEqual((src/'block').stat().st_ino,(dst/'block').stat().st_ino)
    def test_exact_source_mount_and_volume_chain(self):
        pv=self.root/'pv';p=pv/'18/docker';p.mkdir(parents=True);(p/'PG_VERSION').write_bytes(b'18\n')
        def get(kind,name):return {'metadata':{'uid':kind+'uid','name':name},'spec':{'volumeName':'local'} if kind=='pvc' else {'local':{'path':str(pv)}}}
        with patch.object(m,'PV',pv),patch.object(m,'get',side_effect=get):
            layout=m.source_layout(self.deploy(),self.identity());self.assertEqual(layout['source'],str(p));self.assertEqual(layout['pv_uid'],'pvuid')
            d=self.deploy();d['spec']['template']['spec']['containers'][0]['volumeMounts'][0]['subPath']='evil';self.rejects('pg_subpath',m.source_layout,d,self.identity())
            i=self.identity();i['data_directory']='/other';self.rejects('unambiguous_pgdata',m.source_layout,self.deploy(),i)
    def test_identity_requires_no_writer_and_original_schema(self):
        v=self.identity();m.checked_identity(v,True)
        v['publication_owners']=1;self.rejects('publication_owner_remains',m.checked_identity,v,True)
        v['schema']=15;self.rejects('schema18_primary',m.checked_identity,v)
    def test_config_digest_distinct_from_manifest_accepted(self):
        row={'Architecture':'amd64','Os':'linux','Id':'sha256:'+'c'*64,'RepoDigests':[m.OLD],'Config':{'Entrypoint':['/usr/local/bin/devres-server'],'Labels':{'org.opencontainers.image.revision':m.OLD_REV}}}
        with patch.object(m,'run',side_effect=lambda *a:m.enc([row])):
            self.assertEqual(m.image_id(m.OLD,m.OLD_REV),row['Id']);self.assertNotEqual(row['Id'],m.OLD.split('@')[1])
            row['RepoDigests']=[];self.rejects('pinned_release_repository_digest',m.image_id,m.OLD,m.OLD_REV)
    def test_foreign_revision_or_architecture_refused(self):
        row={'Architecture':'arm64','Os':'linux','Id':'sha256:'+'c'*64,'RepoDigests':[m.OLD]}
        with patch.object(m,'run',return_value=m.enc([row])):self.rejects('native_qualified',m.image_id,m.OLD)
        row['Architecture']='amd64'
        row['Config']={'Entrypoint':['/usr/local/bin/devres-server']}
        with patch.object(m,'run',return_value=m.enc([row])):self.rejects('old_server_revision',m.image_id,m.OLD,m.OLD_REV)
    def test_published_entrypoint_effective_serve_command_not_duplicated(self):
        entry=['/usr/local/bin/devres-server']
        command=m.reader_command('sha256:'+'a'*64)
        self.assertEqual(entry+command[1:],['/usr/local/bin/devres-server','serve','/etc/devres/config/serving.toml'])
        row={'Architecture':'amd64','Os':'linux','Id':'sha256:'+'c'*64,'RepoDigests':[m.OLD],'Config':{'Entrypoint':['/different-entrypoint'],'Labels':{'org.opencontainers.image.revision':m.OLD_REV}}}
        with patch.object(m,'run',return_value=m.enc([row])):self.rejects('old_server_entrypoint_required',m.image_id,m.OLD,m.OLD_REV)

    def test_reader_config_preserves_db_and_s3_only_disables_collection(self):
        old=m.tomllib.loads(self.config());new=m.tomllib.loads(m.reader_config(self.config()))
        self.assertEqual(old['storage']['database_url'],new['storage']['database_url'])
        self.assertEqual(old['storage']['s3']['credentials'],new['storage']['s3']['credentials'])
        self.assertTrue(all(new[p]['enabled'] is False for p in m.PROVIDERS))
        self.assertFalse(new['npm']['advisories_enabled']);self.assertEqual(new['writer_client']['endpoint'],'https://127.0.0.1:9/v1/acquire')
        self.assertEqual(new['storage']['s3']['cache_max_bytes'],64*1024**2)
    def test_reader_refuses_writer_role_and_unknown_runtime(self):
        self.rejects('clone_requires_actual_reader_role',m.reader_config,self.config().replace('devres_reader:','devres_writer:'))
        self.rejects('old_reader_only',m.reader_config,self.config().replace('[wikipedia]\nenabled=true','[wikipedia]\n# missing flag'))
    def test_controller_projection_only_image_and_replica_removed(self):
        d=self.deploy();p=m.deployment_projection(d);expected=copy.deepcopy(p);expected['spec']['template']['spec']['containers'][0].pop('image')
        self.assertEqual(m.controller_deployment_hash(p),m.sha(m.enc(expected)))
        self.assertEqual(d['spec']['replicas'],1);self.assertEqual(p['spec']['template']['spec']['containers'][0]['image'],m.PG)
    def test_subnet_avoids_both_host_and_docker_routes(self):
        self.assertEqual(m.choose_subnet([],[{'IPAM':{'Config':None}}]),'172.30.253.0/24')
        self.assertEqual(m.choose_subnet([{'dst':'172.30.253.0/24'}],[{'IPAM':{'Config':[{'Subnet':'172.30.252.0/24'}]}}]),'10.229.252.0/24')
        self.rejects('no_nonoverlapping',m.choose_subnet,[{'dst':'172.30.0.0/16'},{'dst':'10.229.0.0/16'}],[])
    def test_cleanup_foreign_container_never_removed(self):
        with patch.object(m,'run',return_value=m.enc([{'Id':'a'*64,'Config':{'Labels':{m.LABEL:'foreign'}}}])) as call:
            self.rejects('foreign_clone_container',m.cleanup_clone,['a'*64],None,'owner')
            self.assertEqual(call.call_count,1)
    def test_cleanup_nonempty_or_foreign_network_never_removed(self):
        row={'Name':'own','Id':'id','Labels':{m.LABEL:'owner'},'Containers':{'active':{}}}
        with patch.object(m,'run',side_effect=lambda args,*a:m.enc([row])) as call:
            self.rejects('foreign_or_nonempty',m.cleanup_clone,[],'own','owner');self.assertEqual(call.call_count,1)
    def test_cleanup_owned_exact_ids_no_force(self):
        row={'Id':'a'*64,'Config':{'Labels':{m.LABEL:'owner'}},'State':{'Running':False}}
        def run(args,*a):
            if args[1:3]==['network','inspect']:return m.enc([{'Name':'own','Id':'network-id','Labels':{m.LABEL:'owner'},'Containers':{}}])
            if args[1]=='inspect':return m.enc([row])
            return b''
        with patch.object(m,'run',side_effect=run) as call:
            m.cleanup_clone(['a'*64],'own','owner');calls=[c.args[0] for c in call.call_args_list]
            self.assertIn(['docker','rm','a'*64],calls);self.assertIn(['docker','network','rm','network-id'],calls);self.assertFalse(any('--force' in c for c in calls))
    def test_secret_data_and_uid_drift_refused(self):
        b={'original_files_sha256':{},'secret_bindings':[{'name':'fixture','uid':'u','data_sha256':m.sha(m.enc({'k':'eA=='}))}]}
        with patch.object(m,'prepared_input',return_value={'secrets':{}}),patch.object(m,'get',return_value={'metadata':{'uid':'changed'},'data':{'k':'eA=='}}):self.rejects('original_secret_identity',m.private_sources_unchanged,b)
    def test_pg_copy_failure_always_restarts_original_no_complete(self):
        b={'pins':{'store_id':'a'*32},'old_pg_pod':m.pod_projection(self.pod()),'layout':{'source':str(self.root/'source')},'qualified_local_images':{'pg':'pg-id'}}
        (self.root/'source').mkdir();m.new(self.s/'baseline.json',b);m.save('prepared.json',{'baseline_sha256':m.sha(m.raw(self.s/'baseline.json'))})
        locks=[]
        @contextlib.contextmanager
        def lock(bundle,name='.operator.lock'):
            locks.append(name);yield
        module=types.SimpleNamespace(bundle_lock=lock)
        with contextlib.ExitStack() as stack:
            replacements={'source_guard':lambda:(module,None),'stable_foundation':lambda b:self.deploy(),'roles_stopped':lambda:None,'role_pods':lambda role:[self.pod()] if not (self.s/'stop-postgres-intent.json').exists() else [],'schema_identity':self.identity,'source_layout':lambda d,v:b['layout'],'stream_manifest':lambda *a:{'sha256':'f'*64},'image_id':lambda r:'pg-id','k':lambda *a,**kw:b'','control':lambda *a:{'ok':True},'copy_tree':lambda *a,**kw:(_ for _ in ()).throw(m.Stop('fixture_copy_failed'))}
            for key,value in replacements.items():stack.enter_context(patch.object(m,key,value))
            restart=stack.enter_context(patch.object(m,'restore_original_pg',return_value={}))
            self.rejects('fixture_copy_failed',m.checkpoint,b['pins']);restart.assert_called_once_with(b)
            self.assertEqual(locks,['.operator.lock','.certificate.lock']);self.assertFalse((self.s/'checkpoint-completed.json').exists())
            self.rejects('one_checkpoint_attempt',m.checkpoint,b['pins'])
    def test_unknown_docker_create_never_claims_cleanup_complete(self):
        pins={'store_id':'a'*32}
        b={'identity':self.identity(),'layout':{'container_data_directory':'/var/lib/postgresql/18/docker'},'qualified_local_images':{'pg':'pg','old_server':'old'}}
        c={'pins':pins,'pg_files_sha256':m.sha(b'')}
        known={'checkpoint-completed.json':c,'baseline.json':b,'owner.json':{'token':'ab'*12},'original-pg-resumed.json':{'new_pg_pod':m.pod_projection(self.pod())}}
        @contextlib.contextmanager
        def lock(*a): yield
        original_new=m.new
        def localnew(path,value,uid=None,mode=0o600):original_new(path,value,mode=mode)
        def read(path,*a,**kw):return m.enc({'attribution_target_ids':['a'*64]}) if path == m.PUBLIC else (self.config().encode() if path.name=='serving.toml' else b'fixture')
        commands=[]
        def run(args,*a,**kw):
            commands.append(args)
            if args[1:4]==['network','ls','-q']:return b''
            if args[:2]==['ip','-j']:return b'[]'
            if args[1:3]==['network','create']:raise subprocess.TimeoutExpired(args,60)
            raise AssertionError('Unexpected command '+repr(args))
        with contextlib.ExitStack() as stack:
            values={'load':lambda n:known[n],'source_guard':lambda:(types.SimpleNamespace(bundle_lock=lock),None),'stable_foundation':lambda b:None,'roles_stopped':lambda:None,'schema_identity':self.identity,'role_pods':lambda r:[self.pod()],'scan_tree':lambda *a:([],0),'copy_tree':lambda *a:None,'image_id':lambda r,*a:'pg' if r==m.PG else 'old','raw':read,'reader_config':lambda s:s,'new':localnew,'run':run}
            for k,v in values.items():stack.enter_context(patch.object(m,k,v))
            stack.enter_context(patch.object(m.shutil,'disk_usage',return_value=types.SimpleNamespace(free=m.RESERVE+1)))
            stack.enter_context(patch.object(m.os,'chown'))
            cleanup=stack.enter_context(patch.object(m,'cleanup_clone'))
            self.rejects('clone_creation_outcome_unknown',m.proof,pins)
            cleanup.assert_called_once_with([], 'devres-checkpoint-'+'ab'*12, 'ab'*12)
        self.assertTrue((self.s/'clone-network-create-intent.json').exists())
        self.assertTrue((self.s/'clone-cleanup-required.json').exists())
        self.assertFalse((self.s/'clone-cleanup-completed.json').exists())
        self.assertFalse((self.s/'completed.json').exists())

    def new_prepared_fixture(self):
        self.upgrade=self.root/'new-upgrade';self.upgrade.mkdir(mode=0o700)
        self.prepared_path=self.upgrade/'prepared.json';self.approval_path=self.root/'checkpoint-approval.json'
        self.deployed={}
        deployments={}
        for role in ('postgres','backend','writer'):
            value=self.deploy();value['metadata']['uid']='deployment-'+role
            value['spec']['template']['spec']['containers'][0]['name']=role
            value['spec']['template']['spec']['containers'][0]['image']=m.PG if role=='postgres' else m.OLD
            self.deployed[role]=value
            projection=m.deployment_projection(value);projection['spec']['template']['spec']['containers'][0].pop('image')
            deployments[role]={'projection':projection,'manifest':copy.deepcopy(value)}
        self.secrets={'config':{'metadata':{'uid':'secret-uid'},'type':'Opaque','data':{'config':'synthetic-current-rotated-configuration'}}}
        self.foundation=[{'kind':'Service','metadata':{'name':'service','uid':'service-uid'},'spec':{'clusterIP':'10.43.0.1'}}]
        prepared={'revision':m.REV,'store_binding_sha256':m.BIND,'deployments':deployments,'secrets':{k:m.secret_projection(v) for k,v in self.secrets.items()},'foundation':m.foundation_projection(self.foundation)}
        m.new(self.prepared_path,prepared)
        m.new(self.approval_path,{'controller_prepared_sha256':m.sha(m.raw(self.prepared_path))})
        m.new(self.upgrade/'state.json',{'revision':m.REV,'prepared_sha256':m.sha(m.raw(self.prepared_path)),'phase':'prepared'})
        self.patches.extend([patch.object(m,'UPGRADE',self.upgrade),patch.object(m,'PREPARED',self.prepared_path),patch.object(m,'APPROVAL',self.approval_path)])
        for p in self.patches[-3:]:p.start()
        return prepared

    def new_prepared_live_reads(self):
        def get(kind,name):return copy.deepcopy(self.deployed[name] if kind=='deployment' else self.secrets[name])
        return patch.object(m,'get',side_effect=get),patch.object(m,'k',side_effect=lambda *a:m.enc({'items':self.foundation}))

    def test_prepared_boundary_accepts_current_secret_and_template_only(self):
        expected=self.new_prepared_fixture()
        reads=self.new_prepared_live_reads()
        with reads[0],reads[1]:self.assertEqual(m.prepared_boundary(),expected)
        self.deployed['backend']['spec']['template']['spec']['containers'][0]['env']=[{'name':'UNREVIEWED','value':'1'}]
        reads=self.new_prepared_live_reads()
        with reads[0],reads[1]:self.rejects('prepared_workload_boundary_changed',m.prepared_boundary)

    def test_prepared_current_password_change_or_foundation_change_refused(self):
        self.new_prepared_fixture()
        self.secrets['config']['data']['config']='different-current-configuration'
        reads=self.new_prepared_live_reads()
        with reads[0],reads[1]:self.rejects('prepared_secret_boundary_changed',m.prepared_boundary)
        self.secrets['config']['data']['config']='synthetic-current-rotated-configuration'
        self.foundation[0]['spec']['clusterIP']='10.43.0.2'
        reads=self.new_prepared_live_reads()
        with reads[0],reads[1]:self.rejects('prepared_cluster_foundation_changed',m.prepared_boundary)

    def test_prepared_tamper_and_post_migration_phase_refused(self):
        self.new_prepared_fixture();original=m.raw(self.prepared_path)
        self.prepared_path.write_bytes(original+b' ')
        self.rejects('accepted_controller_prepared_changed',m.prepared_input)
        self.prepared_path.write_bytes(original)
        (self.upgrade/'state.json').write_bytes(m.enc({'revision':m.REV,'prepared_sha256':m.sha(original),'phase':'applied'}))
        self.rejects('checkpoint_only_before_target_mutation',m.prepared_boundary)

    def test_source_guard_refuses_unapproved_controller_bytes_before_import(self):
        with patch.object(m, 'raw', side_effect=lambda path,*a,**kw: m.enc({'controller_source_sha256':'a'*64}) if path == m.PUBLIC else b'changed-source'):
            self.rejects('frozen_successor_controller_required',m.source_guard)

    def test_schema18_object_set_rejects_new_or_missing_tables(self):
        for key,value in [('wikipedia_tables',0),('schema18_objects',1)]:
            altered={**self.identity(),key:value}
            self.rejects('schema18_object_set_required',m.checked_identity,altered)

    def test_projection_rejects_pg_process_ip_and_identity_refresh(self):
        original=m.pod_projection(self.pod())
        altered=self.pod();altered['status']['podIP']='10.42.0.99'
        self.assertNotEqual(m.pod_projection(altered),original)
        altered=self.pod();altered['status']['containerStatuses'][0]['containerID']='containerd://new'
        self.assertNotEqual(m.pod_projection(altered),original)
        altered=self.pod();altered['status']['containerStatuses'][0]['ready']=False
        self.rejects('one_ready_container_required',m.pod_projection,altered)

    def test_authorization_binds_prepared_source_claim_and_single_attempt(self):
        import base64
        source=b'fixed-owned-checkpoint-helper';prepared=b'fixed-new-private-prepared'
        producer=b'fixed-withdrawn-store-claim-producer';manifest=m.enc({'store-claim.py':m.sha(producer)})
        public={'revision':m.REV,'old_image':m.OLD,'pg_image':m.PG,'pg_pv_path':str(m.PV),'old_operator_sha256':m.OP_SHA,'schema_before':18,'source_manifest_sha256':m.sha(manifest)}
        body=m.enc({'version':1,'store_id':'a'*32})
        claim={'version':1,'status':200,'key':'production/store.json','storage_binding_sha256':m.BIND,'actual_operating_files_match_admitted_binding':False,'boundary_mode':'withdrawn','stopped_role_secret_templates_match_admitted_binding':True,'source_sha256':m.sha(producer),'body_base64':base64.b64encode(body).decode(),'body_sha256':m.sha(body),'request_id':'synthetic-native-id'}
        approved={'version':1,'approved':True,'scope':'physical-pg-checkpoint-1d76fbcc','source_sha256':m.sha(source),'public_identity_sha256':m.sha(m.enc(public)),'store_claim_sha256':m.sha(m.enc(claim)),'controller_prepared_sha256':m.sha(prepared),'operations':['prepare','run','proof'],'maximum_checkpoints':1,'maximum_rehearsals':1,'independent_s3_backup':False}
        values={m.PUBLIC:m.enc(public),m.CLAIM:m.enc(claim),m.PREPARED:prepared,Path(m.__file__):source,m.APPROVAL:m.enc(approved),m.N/'source-manifest.json':manifest,m.N/'store-claim.py':producer}
        with patch.object(m.os,'geteuid',return_value=0),patch.object(m,'private_dir'),patch.object(m,'raw',side_effect=lambda p,*a,**kw:values[p]),patch.object(m,'source_guard'),patch.object(m,'roles_stopped'):
            pins=m.authorize();self.assertEqual(pins['controller_prepared_sha256'],m.sha(prepared))
            values[m.PREPARED]=prepared+b'changed'
            self.rejects('explicit_exact_checkpoint_approval_required',m.authorize)
            values[m.PREPARED]=prepared
            values[m.APPROVAL]=m.enc({**approved,'maximum_rehearsals':2})
            self.rejects('explicit_exact_checkpoint_approval_required',m.authorize)
            values[m.APPROVAL]=m.enc(approved)
            values[m.CLAIM]=m.enc({**claim,'status':403})
            self.rejects('explicit_exact_checkpoint_approval_required',m.authorize)

    def test_nine_source_clone_preserves_wikipedia_identity_without_token_authority(self):
        text = self.config() + '[wikipedia.request_policy]\nrequests_per_second=2\n'
        text = text.replace('[wikipedia]\nenabled=true', '[wikipedia]\nenabled=true\nuser_agent="current-bot"\noauth2_token_file="/run/devres-wikipedia/token"')
        value = m.tomllib.loads(m.reader_config(text))
        self.assertEqual(len(m.PROVIDERS), 9)
        self.assertTrue(all(value[p]['enabled'] is False for p in m.PROVIDERS))
        self.assertEqual(value['wikipedia']['user_agent'], 'current-bot')
        self.assertEqual(value['wikipedia']['oauth2_token_file'], '/run/devres-wikipedia/token')
        self.assertEqual(value['wikipedia']['request_policy']['requests_per_second'], 2)

    def test_store_claim_requires_current_producer_and_explicit_withdrawn_proof(self):
        producer=b'exact-reviewed-withdrawn-producer'
        manifest=m.enc({'store-claim.py':m.sha(producer)})
        public={'source_manifest_sha256':m.sha(manifest)}
        claim={'version':1,'status':200,'key':'production/store.json','storage_binding_sha256':m.BIND,
               'source_sha256':m.sha(producer),'boundary_mode':'withdrawn',
               'stopped_role_secret_templates_match_admitted_binding':True,
               'actual_operating_files_match_admitted_binding':False}
        values={m.N/'source-manifest.json':manifest,m.N/'store-claim.py':producer}
        with patch.object(m,'raw',side_effect=lambda path,*a,**kw:values[path]):
            m.checked_store_claim(claim,public)
            for changed in ({'boundary_mode':'running'},{'actual_operating_files_match_admitted_binding':True},
                            {'stopped_role_secret_templates_match_admitted_binding':False}):
                with self.subTest(changed=changed):
                    self.rejects('withdrawn_store_claim_required',m.checked_store_claim,{**claim,**changed},public)
            self.rejects('store_claim_producer_source_changed',m.checked_store_claim,{**claim,'source_sha256':'f'*64},public)
            values[m.N/'store-claim.py']=b'changed-producer'
            self.rejects('store_claim_producer_source_changed',m.checked_store_claim,claim,public)
            self.rejects('current_source_manifest_required',m.checked_store_claim,claim,{'source_manifest_sha256':'f'*64})

    def manifest_process(self, lines, calls):
        original = subprocess.Popen
        def process(args, **kwargs):
            calls.append(args)
            return original([__import__('sys').executable, '-c', 'import sys;sys.stdout.buffer.write(' + repr(lines) + ')'], **kwargs)
        return patch.object(m.subprocess, 'Popen', side_effect=process)

    def test_capture_manifest_is_full_ordered_readonly_rows(self):
        rows = [{'id':'a'*64,'source_key':'rfc:9000','source_url':'https://example.test/rfc','body_hash':'b'*64,'media_type':'text/plain','retrieved_at':1},
                {'id':'blake3:'+'c'*64,'source_key':'rfc:9110','source_url':'https://example.test/other','body_hash':'blake3:'+'d'*64,'media_type':'text/plain','retrieved_at':2}]
        data = b''.join(m.enc(r)+b'\n' for r in rows)
        calls = []
        with self.manifest_process(data, calls):
            result = m.stream_manifest('captures')
        self.assertEqual(Path(result['path']).read_bytes(), data)
        self.assertEqual(result['sha256'], m.sha(data))
        self.assertEqual(result['files'], 2)
        query = calls[0][-1]
        self.assertIn('BEGIN READ ONLY;', query)
        self.assertIn('row_to_json(c) FROM devres_captures', query)
        self.assertIn('ORDER BY id COLLATE "C"', query)

    def test_capture_manifest_refuses_reordered_duplicate_bad_digest_and_unknown_kind(self):
        row = {'id':'a'*64,'body_hash':'b'*64}
        for index, rows in enumerate(([row,row], [{'id':'bad','body_hash':'b'*64}])):
            directory = self.root / ('stream-'+str(index)); directory.mkdir(mode=0o700)
            with patch.object(m, 'S', directory), self.manifest_process(b''.join(m.enc(r)+b'\n' for r in rows), []):
                self.rejects('ordered_unique_manifest_required' if index == 0 else 'capture_manifest_identity', m.stream_manifest, 'captures')
        self.rejects('fixed_manifest_kind_required', m.stream_manifest, 'caller_sql')

    def test_backup_envelope_binds_real_manifest_bytes_and_completed_proof(self):
        pins = {'controller_prepared_sha256':'a'*64}
        archive = b'archive-data\n'; captures = b'capture-data\n'
        m.new(self.s/'archive-bindings.jsonl', archive)
        m.new(self.s/'capture-bindings.jsonl', captures)
        checkpoint = {'archive_manifest':{'sha256':m.sha(archive)}, 'capture_manifest':{'sha256':m.sha(captures)}}
        m.new(self.s/'checkpoint-completed.json', checkpoint)
        for name in ('clone-proof-result.json','clone-cleanup-completed.json','original-pg-resumed.json','clean-pg-control.json','baseline.json','quiescent-identity.json','archive-manifest-receipt.json','capture-manifest-receipt.json','cache-baselines.json','clone-writer-proof.json','clone-network-fence.json','clone-network-fence-removed.json'):
            m.new(self.s/name, {'fixture':True})
        m.new(self.s/'pg-file-manifest.jsonl', b'physical-files\n')
        completed = {'revision':m.REV,'schema':18,'pins':pins,'old_clone_verified':True,'fallback_writer_verified':True,'roles_stopped':True,'credentials_preserved':True,'original_s3_retained':True,'independent_s3_backup':False,
                     'checkpoint_receipt_sha256':m.sha(m.raw(self.s/'checkpoint-completed.json')),'clone_proof_sha256':m.sha(m.raw(self.s/'clone-proof-result.json')),'pg_files_sha256':m.sha(m.raw(self.s/'pg-file-manifest.jsonl')),
                     'manifest_sha256':m.sha(archive),'capture_manifest_sha256':m.sha(captures),'old_pg_pod':{'uid':'old'},'new_pg_pod':{'uid':'new'},'postgres_deployment_sha256':'c'*64}
        m.new(self.s/'completed.json', completed)
        completed['cache_baselines_sha256'] = m.sha(m.raw(self.s/'cache-baselines.json'))
        (self.s/'completed.json').write_bytes(m.enc(completed))
        receipt = m.write_backup_receipt()
        self.assertEqual(receipt['kind'], 'coordinated-schema18-backup')
        self.assertEqual(receipt['prepared_sha256'], pins['controller_prepared_sha256'])
        self.assertEqual(receipt['schema'], 18)
        self.assertFalse(receipt['independent_s3_backup'])
        self.assertTrue(all(receipt['checks'].values()))
        self.assertEqual(len(receipt['artifacts']), 17)
        (self.s/'capture-bindings.jsonl').write_bytes(b'changed bytes')
        self.rejects('completed_manifest_bytes_changed', m.write_backup_receipt)

    def test_policy2_control_and_historical_generation_required(self):
        for changed in (
            {**self.identity()['attribution'], 'origin_table':False},
            {**self.identity()['attribution'], 'control':{'data':{**m.POLICY,'required_policy_epoch':1},'data_integrity':'a'*64}},
        ):
            self.rejects('current_schema18_policy2_required',m.checked_attribution,changed)
        value=self.identity()['attribution'];value['generations']=[]
        self.rejects('historical_generation_missing',m.checked_attribution,value)
        value=self.identity()['attribution'];value['control']['data_integrity']='invalid'
        self.rejects('sealed_attribution_control_required',m.checked_attribution,value)

    def test_selected_target_query_rejects_injection_duplicates_and_unbounded_inventory(self):
        for values in ([], ["a'); DELETE FROM devres_captures; --"], ['a'*64]*2, ['a'*64]*17):
            with patch.object(m,'raw',return_value=m.enc({'attribution_target_ids':values})):
                self.rejects('bounded_exact_attribution_targets_required',m.attribution_query)
        target='blake3:'+'a'*64
        with patch.object(m,'raw',return_value=m.enc({'attribution_target_ids':[target]})):
            query=m.attribution_query()
        self.assertIn("WHERE id IN ('"+target+"')",query)
        self.assertIn('devres_attribution_control',query)
        self.assertIn('devres_attribution_generations',query)
        self.assertIn('devres_attribution_origins',query)

    def test_selected_targets_must_exist_in_quiescent_snapshot(self):
        value=self.identity()['attribution']
        with patch.object(m,'raw',return_value=m.enc({'attribution_target_ids':['d'*64]})):
            self.rejects('selected_attribution_targets_missing',m.checked_attribution,value)

    def test_current_policy_generation_must_be_preserved_separately_from_v1_notice(self):
        value=self.identity()['attribution'];value['generations']=value['generations'][:1]
        self.rejects('selected_current_policy_generation_missing',m.checked_attribution,value)

    def cold_fixture(self):
        body=b'first original RFC page'.ljust(1024,b' ')
        control={'kind':'rfc-format-page','capture':m.CID,'body_hash':m.BODY,'format':'txt',
                 'offset':0,'limit':1024,'expected_bytes':1024,'sha256':m.sha(body)}
        generation='blake3:'+'c'*64
        answer={'isError':False,'structuredContent':{'capture':{'id':m.CID,'body_hash':m.BODY},
            'format':'txt','page':{'offset':0,'text':body.decode()},'attribution':{'status':'ready',
            'policy_epoch':2,'policy_fingerprint':m.POLICY['required_policy_fingerprint'],
            'generations':[{'id':generation}],'readable_notice':'current complete notice'}}}
        return control,answer

    def test_cold_original_body_and_current_notice_are_verified_against_exact_baseline(self):
        control,answer=self.cold_fixture()
        with patch.object(m,'rpc',return_value=answer) as rpc,patch.object(m,'notice_readback',return_value={'pages':1}) as notices:
            result=m.cold_body_readback('127.0.0.2',control,self.root,self.identity()['attribution'])
        self.assertEqual(result['bytes'],1024);self.assertEqual(result['sha256'],control['sha256'])
        self.assertTrue(result['empty_disposable_cache']);self.assertFalse(result['whole_archive_verified'])
        rpc.assert_called_once_with('127.0.0.2','tools/call',{'name':'rfc.format_get',
            'arguments':{'number':9000,'format':'txt','capture':m.CID,'offset':0,'limit':1024}},100,self.root)
        self.assertEqual(notices.call_args.args[1],'blake3:'+'c'*64)
        self.assertEqual(notices.call_args.args[2],m.sha(b'current complete notice'))

    def test_cold_control_rejects_arbitrary_destination_selector_and_input(self):
        control,_=self.cold_fixture()
        for key,value in [('format','html'),('capture','blake3:'+'f'*64),('offset',1024),
                          ('limit',2048),('kind','arbitrary-http'),('expected_bytes',1)]:
            with patch.object(m,'rpc') as rpc:
                self.rejects('fixed_cold_read_control_required',m.cold_body_readback,
                             '127.0.0.2',{**control,key:value},self.root,self.identity()['attribution'])
                rpc.assert_not_called()

    def test_cold_reader_failure_identity_bytes_policy_and_generation_drift_rejected(self):
        control,answer=self.cold_fixture()
        changes=[('isError',True,'cold_capture_read_failed'),
                 ('structuredContent.capture.body_hash','blake3:'+'f'*64,'cold_capture_identity_changed'),
                 ('structuredContent.page.text','wrong','cold_capture_original_bytes_changed'),
                 ('structuredContent.attribution.policy_epoch',1,'cold_capture_current_policy_not_ready'),
                 ('structuredContent.attribution.generations',[{'id':'blake3:'+'f'*64}],'cold_capture_generation_changed')]
        for path,value,reason in changes:
            changed=copy.deepcopy(answer);parent=changed;parts=path.split('.')
            for key in parts[:-1]:parent=parent[key]
            parent[parts[-1]]=value
            with patch.object(m,'rpc',return_value=changed),patch.object(m,'notice_readback') as notices:
                self.rejects(reason,m.cold_body_readback,'127.0.0.2',control,self.root,self.identity()['attribution'])
                notices.assert_not_called()

    def notice_fixture(self, text):
        body=text.encode();offset=0;pages=[]
        while offset < len(body):
            end=min(offset+1024,len(body))
            while True:
                try:part=body[offset:end].decode();break
                except UnicodeDecodeError:end-=1
            pages.append({'contents':[{'text':part,'_meta':{'offset':offset,'total_bytes':len(body),
                'next_offset':end if end<len(body) else None,'attribution':{'id':m.GENERATION,'policy_epoch':1}}}]})
            offset=end
        return body,pages

    def test_historical_notice_pages_preserve_bytes_without_claiming_policy2_readiness(self):
        body,pages=self.notice_fixture('한글 notice\n'*300)
        with patch.object(m,'rpc',side_effect=pages) as request:
            result=m.notice_readback('127.0.0.2',m.GENERATION,m.sha(body),self.root)
        self.assertEqual(result['bytes'],len(body));self.assertEqual(result['pages'],len(pages))
        self.assertEqual(result['generation'],m.GENERATION)
        self.assertNotIn('current_policy_ready',result)
        self.assertEqual(request.call_args_list[1].args[2]['uri'],
            'devres://attribution/'+m.GENERATION+'?offset='+str(len(pages[0]['contents'][0]['text'].encode()))+'&limit=1024')

    def test_historical_notice_rejects_identity_offset_total_and_hash_drift(self):
        body,pages=self.notice_fixture('notice '*200)
        for field,value,reason in [('offset',1,'historical_notice_page_identity'),
                                   ('total_bytes',999999,'historical_notice_page_identity'),
                                   ('next_offset',1,'historical_notice_pagination_changed')]:
            changed=copy.deepcopy(pages);changed[0]['contents'][0]['_meta'][field]=value
            with patch.object(m,'rpc',side_effect=changed):
                self.rejects(reason,m.notice_readback,'127.0.0.2',m.GENERATION,m.sha(body),self.root)
        changed=copy.deepcopy(pages);changed[1]['contents'][0]['_meta']['total_bytes']+=1
        with patch.object(m,'rpc',side_effect=changed):
            self.rejects('historical_notice_page_identity',m.notice_readback,'127.0.0.2',m.GENERATION,m.sha(body),self.root)
        with patch.object(m,'rpc',side_effect=pages):
            self.rejects('historical_notice_bytes_changed',m.notice_readback,'127.0.0.2',m.GENERATION,'f'*64,self.root)

    def mount_volume(self):
        volume=MagicMock()
        volume.is_absolute.return_value=True;volume.is_relative_to.return_value=False
        volume.is_symlink.return_value=False;volume.parents=()
        volume.stat.return_value=self.s.stat()
        return volume

    def test_disk_identity_requires_exact_durable_bind_mount_and_non_tmpfs(self):
        volume=self.mount_volume()
        entry={'target':str(self.s),'source':'/dev/fixture[/durable/checkpoint-volume]',
               'fstype':'ext4','options':'rw,relatime','id':123}
        with patch.object(m,'CHECKPOINT_VOLUME',volume),patch.object(m,'run',return_value=m.enc({'filesystems':[entry]})):
            actual=m.disk_identity();self.assertEqual(actual['inode'],self.s.stat().st_ino)
        for key,value in [('target',str(self.root)),('fstype','tmpfs'),('options','ro,relatime')]:
            with patch.object(m,'CHECKPOINT_VOLUME',volume),patch.object(m,'run',return_value=m.enc({'filesystems':[{**entry,key:value}]})):
                self.rejects('disk_backed_checkpoint_mount_required',m.disk_identity)
        volume.stat.return_value=types.SimpleNamespace(st_mode=0o40700,st_uid=os.geteuid(),st_dev=99,st_ino=1)
        with patch.object(m,'CHECKPOINT_VOLUME',volume):
            self.rejects('checkpoint_bind_mount_identity_required',m.disk_identity)

    def test_durable_mount_change_rejected_before_foundation_or_pg_mutation(self):
        with patch.object(m,'disk_identity',return_value={'inode':2}),patch.object(m,'prepared_boundary') as prepared:
            self.rejects('checkpoint_mount_changed',m.stable_foundation,{'disk_identity':{'inode':1}})
            prepared.assert_not_called()

    def test_cache_copy_preserves_git_workspace_links_and_distinct_inodes(self):
        if not Path('/usr/bin/rsync').exists(): self.skipTest('rsync unavailable')
        source=self.root/'cache-source';source.mkdir(mode=0o700)
        (source/'history.git').mkdir();(source/'history.git/config').write_bytes(b'retained-git-state')
        os.link(source/'history.git/config',source/'linked-config')
        (source/'internal-link').symlink_to('history.git/config')
        target=self.root/'cache-copy';target.mkdir(mode=0o700)
        expected=m.cache_manifest(source);m.copy_cache(source,target,expected)
        self.assertEqual(m.cache_manifest(target),expected)
        self.assertEqual((target/'linked-config').stat().st_ino,(target/'history.git/config').stat().st_ino)
        self.assertNotEqual((source/'linked-config').stat().st_ino,(target/'linked-config').stat().st_ino)
        self.assertEqual(os.readlink(target/'internal-link'),'history.git/config')
        (target/'linked-config').write_bytes(b'changed')
        self.assertEqual((source/'linked-config').read_bytes(),b'retained-git-state')
    def test_cache_rejects_external_symlink_hardlink_and_special_file(self):
        source=self.root/'cache-source';source.mkdir(mode=0o700)
        outside=self.root/'external';outside.write_bytes(b'not-owned-cache')
        link=source/'link';link.symlink_to('../external')
        self.rejects('external_cache_symlink',m.cache_manifest,source);link.unlink()
        os.link(outside,link);self.rejects('external_cache_hardlink',m.cache_manifest,source);link.unlink()
        os.mkfifo(link);self.rejects('cache_special_file',m.cache_manifest,source)
    def test_writer_clone_has_no_provider_or_kubernetes_authority(self):
        text=self.config().split('[writer_client]')[0].replace('devres_reader:','devres_writer:')
        text += '[writer_listener]\nbind="0.0.0.0:9443"\ncertificate="/run/devres-writer-tls/tls.crt"\nprivate_key="/run/devres-writer-tls/tls.key"\nallowed_clients=[{namespace="devres",service_account="devres-serving"}]\n[writer_listener.auth]\nkube_api_url="https://kubernetes.default.svc"\nkube_token_file="/run/devres-kube/token"\nkube_ca_file="/run/devres-kube/ca.crt"\naudience="devres-writer"\n'
        value=m.tomllib.loads(m.writer_config(text))
        self.assertTrue(all(value[p]['enabled'] is False for p in m.PROVIDERS))
        self.assertFalse(value['npm']['advisories_enabled'])
        self.assertEqual(value['writer_listener']['bind'],'127.0.0.1:9443')
        self.assertEqual(value['writer_listener']['auth']['kube_api_url'],'https://127.0.0.1:9')
        self.assertEqual(value['storage']['s3']['credentials'],m.tomllib.loads(text)['storage']['s3']['credentials'])
    def test_rehearsal_network_allows_only_pinned_s3_and_its_private_subnet(self):
        cfg={'storage':{'s3':{'endpoint':'https://s3.example.test','bucket':'archive','path_style':True}}}
        calls=[]
        def run(args,timeout=60,data=None):
            calls.append((args,data))
            return m.enc({'nftables':[{'table':{'name':'fixture'}}]}) if '--json' in args else b''
        with patch.object(m.socket,'getaddrinfo',return_value=[(None,None,None,None,('93.184.216.34',443))]),patch.object(m,'run',side_effect=run):
            hosts=m.network_fence('ab'*12,'172.30.253.0/24',cfg)
            m.remove_network_fence('ab'*12)
        rules=calls[0][1].decode()
        self.assertIn('ip daddr { 93.184.216.34 } tcp dport 443 accept',rules)
        self.assertTrue(rules.endswith('ip saddr 172.30.253.0/24 drop\n'))
        self.assertEqual(hosts,['--add-host=s3.example.test:93.184.216.34'])
        self.assertTrue((self.s/'clone-network-fence-removed.json').exists())
    def test_rehearsal_s3_private_resolution_or_uncertain_firewall_is_fail_closed(self):
        cfg={'storage':{'s3':{'endpoint':'https://s3.example.test','bucket':'archive','path_style':True}}}
        with patch.object(m.socket,'getaddrinfo',return_value=[(None,None,None,None,('127.0.0.1',443))]):
            self.rejects('bounded_public_s3',m.archive_hosts,cfg)
        m.save('clone-network-fence-intent.json',{'table':'fixture'})
        self.rejects('fence_creation_uncertain',m.remove_network_fence,'ab'*12)

if __name__=='__main__':unittest.main()
