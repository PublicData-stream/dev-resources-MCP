import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('evidence_copy', ROOT / 'scripts/copy-evidence-to-s3.py')
copy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(copy)


class S3Error(Exception):
    def __init__(self, code): self.response = {'Error': {'Code': code}}


class Guard:
    def __init__(self): self.calls, self.failure = 0, None
    def check(self, force=False):
        self.calls += 1
        if self.failure: raise copy.CopyError(self.failure)


class Limiter:
    def __init__(self, guard): self.guard, self.bytes = guard, 0
    def consume(self, size): self.guard.check(); self.bytes += size


class S3:
    def __init__(self):
        self.objects, self.uploads, self.calls, self.gets = {}, {}, [], []
        self.fail_part, self.corrupt_get, self.on_put = False, None, None
    def get_bucket_versioning(self, **kwargs): self.calls.append(('versioning',)); return {}
    def get_bucket_acl(self, **kwargs):
        return {'Owner': {'ID': 'owner'}, 'Grants': [{'Grantee': {'Type': 'CanonicalUser', 'ID': 'owner'}, 'Permission': 'FULL_CONTROL'}]}
    def list_objects_v2(self, MaxKeys=1000, **kwargs):
        return {'Contents': [{'Key': k} for k in sorted(self.objects)[:MaxKeys]], 'IsTruncated': False}
    def get_object(self, Key, **kwargs):
        self.gets.append(Key)
        if Key not in self.objects: raise S3Error('NoSuchKey')
        data, metadata = self.objects[Key]
        if self.corrupt_get == Key: data += b'corrupt'
        return {'Body': io.BytesIO(data), 'Metadata': metadata}
    @staticmethod
    def consume(body):
        if isinstance(body, bytes): return body
        parts = []
        while True:
            value = body.read(1024 * 1024)
            if not value: return b''.join(parts)
            parts.append(value)
    def put_object(self, Key, Body, Metadata, IfNoneMatch, **kwargs):
        self.calls.append(('put', Key, IfNoneMatch))
        if IfNoneMatch != '*': raise AssertionError('overwrite condition missing')
        if Key in self.objects: raise S3Error('PreconditionFailed')
        data = self.consume(Body)
        if self.on_put: self.on_put(Key)
        self.objects[Key] = data, Metadata
        return {}
    def create_multipart_upload(self, Key, Metadata, **kwargs):
        identifier = 'upload-' + str(len(self.calls))
        self.calls.append(('create', Key, identifier))
        self.uploads[identifier] = {'key': Key, 'metadata': Metadata, 'parts': {}}
        return {'UploadId': identifier}
    def upload_part(self, Key, UploadId, PartNumber, Body, **kwargs):
        self.calls.append(('part', Key, UploadId, PartNumber))
        if self.fail_part: raise S3Error('ServerFailure')
        self.uploads[UploadId]['parts'][PartNumber] = self.consume(Body)
        return {'ETag': 'etag-' + str(PartNumber)}
    def complete_multipart_upload(self, Key, UploadId, MultipartUpload, IfNoneMatch, **kwargs):
        self.calls.append(('complete_mpu', Key, UploadId, IfNoneMatch))
        if IfNoneMatch != '*': raise AssertionError('overwrite condition missing')
        if Key in self.objects: raise S3Error('PreconditionFailed')
        value = self.uploads.pop(UploadId)
        data = b''.join(value['parts'][p['PartNumber']] for p in MultipartUpload['Parts'])
        self.objects[Key] = data, value['metadata']
        return {}
    def abort_multipart_upload(self, Key, UploadId, **kwargs):
        self.calls.append(('abort', Key, UploadId))
        if UploadId not in self.uploads: raise S3Error('NoSuchUpload')
        if self.uploads[UploadId]['key'] != Key: raise AssertionError('wrong owner')
        self.uploads.pop(UploadId)
        return {}


class CopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='devres-evidence-copy-', dir='/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source, self.state = self.root / 'snapshot', self.root / 'state'
        self.source.mkdir(mode=0o700); self.state.mkdir(mode=0o700)
        (self.source / 'blobs').mkdir(); (self.source / 'blobs' / 'empty').mkdir()
        (self.source / 'blobs' / '.hidden').write_bytes(b'hidden evidence')
        (self.source / 'blobs' / 'first').write_bytes(b'canonical public evidence')
        os.link(self.source / 'blobs' / 'first', self.source / 'blobs' / 'hardlink')
        self.plan = {'version': 1, 'source_dataset': copy.DATASET, 'source_dataset_guid': '123',
            'source_snapshot': copy.DATASET + '@copy-fixed', 'source_snapshot_guid': '456',
            'source_root': str(self.source), 'hold': 'devres-copy', 'bucket': copy.BUCKET,
            'endpoint': copy.ENDPOINT, 'region': copy.REGION, 'prefix': '', 'profile': 'newprofile',
            'credential_user': 'codex', 'deadline_at': copy.DEADLINE, 'migration_proof_id': 'a' * 64,
            'state_dir': str(self.state)}
        self.plan_file = self.root / 'plan.json'
        self.plan_file.write_bytes(copy.canonical(self.plan)); self.plan_file.chmod(0o600)
        self.plan_hash = copy.digest(self.plan_file.read_bytes())
        self.guard, self.s3 = Guard(), S3()
    def copier(self):
        return copy.Copier(self.plan, self.plan_hash, self.guard, self.s3, Limiter(self.guard))
    def manifest(self):
        return [json.loads(v) for v in self.s3.objects[copy.CONTROL + 'manifest.jsonl'][0].splitlines()]
    def test_rate_limiter_guard_can_advance_past_scheduled_sleep(self):
        clock = SimpleNamespace(now=0.0)
        guard = MagicMock()
        def check():
            if guard.check.call_count >= 2:
                clock.now = 2.0
        guard.check.side_effect = check
        with patch.object(copy.time, 'monotonic', side_effect=lambda: clock.now), \
                patch.object(copy.time, 'sleep') as sleep:
            limiter = copy.Limiter(guard, rate=1024)
            limiter.consume(1024)
        sleep.assert_not_called()
        self.assertEqual(limiter.bytes, 1024)
    def test_scaleway_empty_unversioned_status_keeps_bucket_guards(self):
        for response in ({}, {'Status': ''}, {'Status': 'Suspended'}):
            with self.subTest(response=response), patch.object(self.s3, 'get_bucket_versioning', return_value=response):
                self.copier().bucket_check()
        for status in ('Enabled', 'unknown', False):
            with self.subTest(status=status), patch.object(self.s3, 'get_bucket_versioning', return_value={'Status': status}):
                with self.assertRaisesRegex(copy.CopyError, 'unexpected_bucket_versioning'):
                    self.copier().bucket_check()
        self.assertEqual(self.s3.objects, {})
    def test_whole_tree_native_root_hidden_empty_directory_and_hardlinks_verified(self):
        value = self.copier().run()
        self.assertTrue(value['complete']); self.assertEqual(value['files'], 3)
        self.assertEqual(set(self.s3.objects), {'blobs/.hidden', 'blobs/first', 'blobs/hardlink',
            copy.CONTROL+'owner.json', copy.CONTROL+'manifest.jsonl', copy.CONTROL+'COMPLETE.json'})
        entries = {base64.b64decode(row['path_bytes_base64']): row for row in self.manifest()}
        self.assertEqual(entries[b'blobs/empty']['kind'], 'directory')
        self.assertEqual(entries[b'blobs/first']['sha256'], entries[b'blobs/hardlink']['sha256'])
        for key in ('blobs/.hidden', 'blobs/first', 'blobs/hardlink'):
            self.assertIn(key, self.s3.gets)
        mutations = [c for c in self.s3.calls if c[0] == 'put']
        self.assertEqual(mutations[-1][1], copy.CONTROL + 'COMPLETE.json')
        self.assertEqual(stat.S_IMODE((self.state/'copy.sqlite3').stat().st_mode), 0o600)
    def test_resume_regets_all_objects_and_never_puts_finished_data_again(self):
        self.copier().run(); before = list(self.s3.calls); self.s3.gets.clear()
        self.copier().run()
        self.assertEqual(before, self.s3.calls[:len(before)])
        self.assertFalse(any(c[0] in ('put', 'create', 'complete_mpu') for c in self.s3.calls[len(before):]))
        for key in ('blobs/first','blobs/hardlink','blobs/.hidden'): self.assertIn(key, self.s3.gets)
    def test_initial_nonempty_root_without_owner_refuses_without_write(self):
        self.s3.objects['unrelated'] = b'keep', {}
        with self.assertRaisesRegex(copy.CopyError, 'bucket_root_not_empty'): self.copier().run()
        self.assertEqual(self.s3.objects, {'unrelated': (b'keep', {})})
        self.assertFalse(any(c[0] == 'put' for c in self.s3.calls))
    def test_resume_owner_or_metadata_collision_never_overwrites(self):
        self.copier().run()
        original = self.s3.objects['blobs/first']
        self.s3.objects['blobs/first'] = original[0], {'wrong': 'owner'}
        with self.assertRaisesRegex(copy.CopyError, 'metadata_collision'): self.copier().run()
        self.assertEqual(self.s3.objects['blobs/first'][1], {'wrong':'owner'})
        self.s3.objects[copy.CONTROL+'owner.json'] = b'other owner', {}
        with self.assertRaisesRegex(copy.CopyError, 'owner_collision'): self.copier().run()
    def test_get_corruption_blocks_end_marker_after_uploaded_objects_retained(self):
        self.s3.corrupt_get = 'blobs/first'
        with self.assertRaisesRegex(copy.CopyError, 'object_size_collision'): self.copier().run()
        self.assertNotIn(copy.CONTROL + 'COMPLETE.json', self.s3.objects)
        self.assertIn('blobs/first', self.s3.objects)
        self.s3.corrupt_get = None
        self.assertTrue(self.copier().run()['complete'])
    def test_source_symlink_fifo_and_reserved_path_fail_before_any_remote_write(self):
        for name, creator in (('symlink', lambda p:p.symlink_to('/etc/passwd')),
                              ('fifo', os.mkfifo), ('_devres-copy', lambda p:p.mkdir())):
            path = self.source / name; creator(path)
            with self.assertRaisesRegex(copy.CopyError, 'source_special_or_symlink|reserved_source_path'):
                self.copier().run()
            self.assertFalse(any(c[0]=='put' for c in self.s3.calls))
            if path.is_dir(): path.rmdir()
            else: path.unlink()
    def test_check_is_readonly_and_rejects_nonempty_unowned_root(self):
        value = self.copier().check()
        self.assertTrue(value['check_passed']); self.assertFalse(value['remote_writes'])
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual(self.s3.objects, {})
        self.s3.objects['blobs/foreign'] = b'x', {}
        with self.assertRaisesRegex(copy.CopyError, 'bucket_root_not_empty'): self.copier().check()
    def test_unknown_existing_key_on_resume_blocks_more_writes(self):
        self.copier().run(); self.s3.objects['foreign'] = b'x', {}
        before = len(self.s3.calls)
        with self.assertRaisesRegex(copy.CopyError, 'unexpected_existing_bucket_object'): self.copier().run()
        self.assertFalse(any(c[0]=='put' for c in self.s3.calls[before:]))
    def test_raw_non_utf8_and_long_paths_map_deterministically_in_manifest(self):
        raw = os.fsencode(self.source / 'blobs') + b'/raw-\xff'
        fd = os.open(raw, os.O_WRONLY|os.O_CREAT,0o600); os.write(fd,b'raw name'); os.close(fd)
        parent = self.source / 'blobs'
        for _ in range(6): parent /= 'x'*200; parent.mkdir()
        (parent / 'leaf').write_bytes(b'long name')
        self.copier().run()
        mapped = [r for r in self.manifest() if r['object_key'] and r['object_key'].startswith(copy.CONTROL+'mapped/')]
        self.assertEqual(len(mapped), 2)
        for row in mapped:
            path = base64.b64decode(row['path_bytes_base64'])
            self.assertEqual(row['object_key'], copy.CONTROL+'mapped/'+copy.digest(path))
    def test_multipart_adaptive_math_beyond_15_gib_and_up_to_object_limit(self):
        for size in (16*1024**3+1, 130*1024**3, copy.MAX_OBJECT):
            width = copy.part_size(size)
            self.assertGreaterEqual(width, 16*1024**2)
            self.assertLessEqual(width, 5_000_000_000)
            self.assertLessEqual((size+width-1)//width,1000)
        with self.assertRaisesRegex(copy.CopyError,'unsupported_object_size'): copy.part_size(copy.MAX_OBJECT+1)
    def test_multipart_failure_aborts_only_own_upload_and_resume_retains_other_objects(self):
        with patch.object(copy,'MIN_PART',4), patch.object(copy,'part_size',return_value=8):
            self.s3.uploads['someone-else']={'key':'foreign','metadata':{},'parts':{}}
            self.s3.fail_part=True
            with self.assertRaisesRegex(copy.CopyError,'s3_request_failed'): self.copier().run()
            self.assertEqual(set(self.s3.uploads), {'someone-else'})
            self.assertNotIn(copy.CONTROL+'COMPLETE.json',self.s3.objects)
            self.s3.fail_part=False
            self.assertTrue(self.copier().run()['complete'])
            self.assertEqual(set(self.s3.uploads), {'someone-else'})
            self.assertTrue(any(c[0]=='complete_mpu' and c[3]=='*' for c in self.s3.calls))
    def test_deadline_or_rollback_guard_blocks_completion_and_preserves_objects(self):
        self.s3.on_put=lambda key: setattr(self.guard,'failure','copy_deadline_exceeded') if key=='blobs/first' else None
        with self.assertRaisesRegex(copy.CopyError,'copy_deadline_exceeded'): self.copier().run()
        self.assertNotIn(copy.CONTROL+'COMPLETE.json',self.s3.objects)
        self.assertIn('blobs/first',self.s3.objects)
        self.s3.on_put=None; self.guard.failure='migration_owner_or_phase_changed'
        with self.assertRaisesRegex(copy.CopyError,'migration_owner_or_phase_changed'): self.copier().run()
        self.assertNotIn(copy.CONTROL+'COMPLETE.json',self.s3.objects)
        self.assertIn('blobs/first',self.s3.objects)
    def test_part_body_seeks_retries_and_caps_reads(self):
        body=copy.PartBody(io.BytesIO(b'prefixPAYLOADsuffix'),6,7,Limiter(self.guard))
        self.assertEqual(body.read(),b'PAYLOAD'); self.assertEqual(body.read(),b'')
        body.seek(0); self.assertEqual(body.read(3),b'PAY'); body.seek(-2,2); self.assertEqual(body.read(),b'AD')
        with self.assertRaisesRegex(copy.CopyError,'invalid_part_seek'): body.seek(8)
    def test_strict_plan_modes_fields_root_destination_and_fixed_authority(self):
        self.assertEqual(copy.read_plan(self.plan_file)[0],self.plan)
        for key,value in (('prefix','timestamp/'),('endpoint','https://other.invalid'),('deadline_at',copy.DEADLINE+1),('profile','default')):
            changed={**self.plan,key:value}; self.plan_file.write_bytes(copy.canonical(changed))
            with self.assertRaisesRegex(copy.CopyError,'invalid_plan'): copy.read_plan(self.plan_file)
        self.plan_file.write_bytes(copy.canonical(self.plan)); self.plan_file.chmod(0o644)
        with self.assertRaisesRegex(copy.CopyError,'unsafe_private_file'): copy.read_plan(self.plan_file)
    def test_no_source_follow_after_inventory_path_swap(self):
        value=self.copier(); value.database(); value.inventory()
        (self.source/'blobs'/'first').unlink(); (self.source/'blobs'/'first').symlink_to('/etc/passwd')
        with self.assertRaises(OSError):
            with copy.open_source(self.source,b'blobs/first',json.loads(value.db.execute("SELECT identity FROM entries WHERE path=?",(b'blobs/first',)).fetchone()[0])): pass
        value.db.close()

    def test_empty_object_and_conditional_race_require_full_matching_get(self):
        (self.source/'blobs'/'zero').write_bytes(b'')
        original=self.s3.put_object
        def race(**kwargs):
            if kwargs['Key']=='blobs/first' and kwargs['Key'] not in self.s3.objects:
                self.s3.objects[kwargs['Key']]=(b'concurrent foreign bytes',kwargs['Metadata'])
                raise S3Error('PreconditionFailed')
            return original(**kwargs)
        self.s3.put_object=race
        with self.assertRaisesRegex(copy.CopyError,'object_size_collision|object_content_collision'): self.copier().run()
        self.assertEqual(self.s3.objects['blobs/first'][0],b'concurrent foreign bytes')
        self.assertNotIn(copy.CONTROL+'COMPLETE.json',self.s3.objects)
        self.s3.objects.pop('blobs/first'); self.s3.put_object=original
        self.assertTrue(self.copier().run()['complete'])
        self.assertEqual(self.s3.objects['blobs/zero'][0],b'')

    def test_unknown_mpu_create_response_blocks_fresh_create_and_never_aborts_other_ids(self):
        original=self.s3.create_multipart_upload
        def lost(**kwargs):
            original(**kwargs)
            raise S3Error('Timeout')
        self.s3.create_multipart_upload=lost
        with patch.object(copy,'MIN_PART',4), patch.object(copy,'part_size',return_value=8):
            with self.assertRaisesRegex(copy.CopyError,'multipart_creation_uncertain'): self.copier().run()
            count=len([c for c in self.s3.calls if c[0]=='create'])
            with self.assertRaisesRegex(copy.CopyError,'multipart_creation_uncertain'): self.copier().run()
            self.assertEqual(count,len([c for c in self.s3.calls if c[0]=='create']))
            self.assertFalse(any(c[0]=='abort' for c in self.s3.calls))
            self.assertNotIn(copy.CONTROL+'COMPLETE.json',self.s3.objects)

    def test_readonly_guard_checks_domain_proof_guids_hold_dataset_tree_and_rollback(self):
        mountpoint=self.root/'mount'; snapshot=mountpoint/'.zfs'/'snapshot'/'copy-fixed'
        snapshot.mkdir(parents=True)
        plan={**self.plan,'source_root':str(snapshot)}
        token='e'*24
        plan['migration_proof_id']=copy.digest(b'devres-nodeport-proof-v1\0'+token.encode())
        self.plan_file.write_bytes(copy.canonical(plan)); plan_hash=copy.digest(self.plan_file.read_bytes())
        journal=self.root/'journal.json'
        record={'token':token,'phase':'running_migrate_storage','mode':'direct','deadline_at':copy.DEADLINE}
        journal.write_bytes(copy.canonical(record)); journal.chmod(0o600)
        values={'dataset_guid':'123','snapshot_guid':'456','hold':plan['hold'],'descendants':copy.DATASET}
        def run(args):
            if args[:2]==['zfs','holds']: return plan['source_snapshot']+'\t'+values['hold']+'\tdate'
            if args[:2]==['zfs','list']: return values['descendants']
            if args[-2]=='mountpoint': return str(mountpoint)
            return values['snapshot_guid' if '@' in args[-1] else 'dataset_guid']
        with patch.object(copy,'JOURNAL',journal), patch.object(copy.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)), \
                patch.object(copy,'mount_paths',return_value=[str(snapshot)]):
            def guard(): return copy.Guard(plan,self.plan_file,plan_hash,run=run,clock=lambda:copy.DEADLINE-1000)
            guard().check(force=True)
            original_read=copy.private_read
            races=[]
            def raced(path,*args):
                if Path(path)==journal:
                    races.append(path)
                    if len(races)<3: raise copy.CopyError('private_file_changed')
                return original_read(path,*args)
            with patch.object(copy,'private_read',side_effect=raced): guard().check(force=True)
            self.assertEqual(len(races),3)
            with patch.object(copy,'private_read',side_effect=lambda path,*args:
                              (_ for _ in ()).throw(copy.CopyError('private_file_changed')) if Path(path)==journal
                              else original_read(path,*args)):
                with self.assertRaisesRegex(copy.CopyError,'private_file_changed'): guard().check(force=True)
            for key,value,code in (('dataset_guid','999','source_identity_changed'),('snapshot_guid','999','source_identity_changed'),
                                   ('hold','missing','source_hold_missing'),('descendants',copy.DATASET+'\n'+copy.DATASET+'/child','source_child_dataset')):
                old=values[key]; values[key]=value
                with self.assertRaisesRegex(copy.CopyError,code): guard().check(force=True)
                values[key]=old
            for phase in ('rolling_back','rolled_back','recovering_original','unknown'):
                journal.write_bytes(copy.canonical({**record,'phase':phase}))
                with self.assertRaisesRegex(copy.CopyError,'migration_owner_or_phase_changed'): guard().check(force=True)
            journal.write_bytes(copy.canonical({**record,'token':'f'*24}))
            with self.assertRaisesRegex(copy.CopyError,'migration_owner_or_phase_changed'): guard().check(force=True)
            journal.write_bytes(copy.canonical(record))
            with patch.object(copy,'mount_paths',return_value=[str(snapshot/'blobs')]):
                with self.assertRaisesRegex(copy.CopyError,'source_child_mount'): guard().check(force=True)
            with patch.object(copy.os,'statvfs',return_value=SimpleNamespace(f_flag=0)):
                with self.assertRaisesRegex(copy.CopyError,'source_snapshot_not_readonly'): guard().check(force=True)
            expired=copy.Guard(plan,self.plan_file,plan_hash,run=run,clock=lambda:copy.DEADLINE)
            with self.assertRaisesRegex(copy.CopyError,'copy_deadline_exceeded'): expired.check(force=True)
            with patch.object(copy,'STOPPED',True):
                with self.assertRaisesRegex(copy.CopyError,'copy_interrupted'): guard().check(force=True)

    def test_listing_pagination_checks_all_keys_and_refuses_stuck_cursor(self):
        value=self.copier(); value.database(); value.inventory(); value.claim_root()
        def pages(ContinuationToken=None, **kwargs):
            if ContinuationToken is None:
                return {'Contents':[{'Key':copy.CONTROL+'owner.json'}], 'IsTruncated':True, 'NextContinuationToken':'page2'}
            self.assertEqual(ContinuationToken,'page2')
            return {'Contents':[{'Key':'blobs/first'}], 'IsTruncated':False}
        self.s3.list_objects_v2=pages
        value.verify_bucket_keys()
        self.s3.list_objects_v2=lambda **kwargs:{'IsTruncated':True,'NextContinuationToken':'stuck'}
        with self.assertRaisesRegex(copy.CopyError,'invalid_bucket_listing'): value.verify_bucket_keys()
        value.db.close()

    def test_private_fifo_rejected_without_waiting_for_writer(self):
        path=self.root/'fifo'; os.mkfifo(path,0o600)
        with self.assertRaisesRegex(copy.CopyError,'unsafe_private_file'): copy.private_read(path)

    def test_selected_credentials_only_fixed_sdk_destination_and_bounded_attempts(self):
        sdk=MagicMock(); session=sdk.Session.return_value; client=session.client.return_value
        client.meta.service_model.operation_model.return_value.input_shape.members={'IfNoneMatch':object()}
        config=MagicMock()
        modules={'boto3':sdk,'botocore':SimpleNamespace(),'botocore.config':SimpleNamespace(Config=config)}
        result=SimpleNamespace(returncode=0,stdout=json.dumps(['ACCESS','SECRET',copy.REGION]).encode())
        account=SimpleNamespace(pw_name='codex',pw_uid=1001,pw_gid=1001,pw_dir='/home/codex')
        with patch.dict('sys.modules',modules),patch.object(copy.pwd,'getpwnam',return_value=account) as lookup, \
                patch.object(copy.subprocess,'run',return_value=result) as run:
            self.assertIs(copy.make_client(self.plan),client)
            self.assertEqual(run.call_args.args[0],['/usr/local/bin/scw','-p','newprofile','-o','json',
                             'config','get','access-key','secret-key','default-region'])
            lookup.assert_called_once_with('codex')
            self.assertEqual({k:run.call_args.kwargs[k] for k in ('user','group','extra_groups')},
                             {'user':1001,'group':1001,'extra_groups':[]})
            self.assertEqual(run.call_args.kwargs['env'],{'HOME':'/home/codex','USER':'codex','LOGNAME':'codex',
                             'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C'})
            self.assertIs(run.call_args.kwargs['stdin'],copy.subprocess.DEVNULL)
            sdk.Session.assert_called_once_with(aws_access_key_id='ACCESS',aws_secret_access_key='SECRET',region_name=copy.REGION)
            self.assertEqual(config.call_args.kwargs['retries']['total_max_attempts'],1)
            self.assertIs(session.client.call_args.kwargs['verify'],True)
            callback=client.meta.events.register.call_args.args[1]
            callback(SimpleNamespace(url=copy.ENDPOINT+'/dev-resources-mcp/blobs/file'))
            with self.assertRaisesRegex(copy.CopyError,'unexpected_s3_destination'):
                callback(SimpleNamespace(url='https://other.invalid/bucket'))
        bad=SimpleNamespace(returncode=0,stdout=b'"wrong profile shape"')
        with patch.object(copy.pwd,'getpwnam',return_value=account),patch.object(copy.subprocess,'run',return_value=bad):
            with self.assertRaisesRegex(copy.CopyError,'credential_profile_invalid'): copy.make_client(self.plan)


    def test_credential_child_rejects_root_missing_account_or_failed_privilege_drop(self):
        account={'pw_name':'codex','pw_uid':1001,'pw_gid':1001,'pw_dir':'/home/codex'}
        for changed in ({'pw_uid':0},{'pw_gid':0},{'pw_name':'root'},{'pw_dir':'relative'}):
            with patch.object(copy.pwd,'getpwnam',return_value=SimpleNamespace(**{**account,**changed})), \
                    patch.object(copy.subprocess,'run') as run:
                with self.assertRaisesRegex(copy.CopyError,'credential_account_invalid'): copy.make_client(self.plan)
                run.assert_not_called()
        with patch.object(copy.pwd,'getpwnam',side_effect=KeyError('codex')),patch.object(copy.subprocess,'run') as run:
            with self.assertRaisesRegex(copy.CopyError,'credential_account_invalid'): copy.make_client(self.plan)
            run.assert_not_called()
        with patch.object(copy.pwd,'getpwnam',return_value=SimpleNamespace(**account)), \
                patch.object(copy.subprocess,'run',side_effect=PermissionError('private error must stay hidden')):
            with self.assertRaisesRegex(copy.CopyError,'^credential_selection_failed$'): copy.make_client(self.plan)


    def test_inventory_partial_batch_fault_keeps_only_durable_prefix_then_rebuilds_before_s3(self):
        for number in range(330):
            (self.source/'blobs'/('batch-%04d'%number)).write_bytes(('evidence-%d'%number).encode())
        original=copy.hash_stream; calls=[]
        def fault(stream,limiter):
            value=original(stream,limiter); calls.append(value)
            if len(calls)==300: raise copy.CopyError('inventory_test_interrupted')
            return value
        with patch.object(copy,'hash_stream',side_effect=fault):
            with self.assertRaisesRegex(copy.CopyError,'inventory_test_interrupted'): self.copier().run()
        with copy.contextlib.closing(sqlite3.connect(self.state/'copy.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM entries').fetchone()[0],256)
            self.assertIsNone(db.execute("SELECT value FROM metadata WHERE key='inventory_complete'").fetchone())
        self.assertFalse((self.state/'manifest.jsonl').exists())
        self.assertEqual(self.s3.objects,{})
        self.assertFalse(any(call[0] in ('put','create','complete_mpu') for call in self.s3.calls))
        with patch.object(copy,'hash_stream',wraps=original) as hashes:
            result=self.copier().run()
        self.assertEqual(hashes.call_count,333)
        self.assertEqual(result['files'],333)
        self.assertTrue(result['complete'])
        self.assertEqual(len([r for r in self.manifest() if r['kind']=='file']),333)

    def trace_s3_file_order(self):
        events=[]; get=self.s3.get_object; put=self.s3.put_object; create=self.s3.create_multipart_upload
        def get_traced(**kwargs): events.append(('get',kwargs['Key'])); return get(**kwargs)
        def put_traced(**kwargs): events.append(('put',kwargs['Key'])); return put(**kwargs)
        def create_traced(**kwargs): events.append(('create',kwargs['Key'])); return create(**kwargs)
        self.s3.get_object=get_traced; self.s3.put_object=put_traced; self.s3.create_multipart_upload=create_traced
        return events

    def test_fresh_small_file_put_then_full_get_but_resume_gets_without_put(self):
        events=self.trace_s3_file_order()
        value=self.copier(); self.assertTrue(value.run()['complete']); self.assertTrue(value.fresh_root)
        self.assertEqual([kind for kind,key in events if key=='blobs/first'],['put','get'])
        events.clear()
        resumed=self.copier(); self.assertTrue(resumed.run()['complete']); self.assertFalse(resumed.fresh_root)
        self.assertEqual([kind for kind,key in events if key=='blobs/first'],['get'])

    def test_fresh_small_412_accepts_only_matching_object_after_full_get(self):
        put=self.s3.put_object
        def race(**kwargs):
            if kwargs['Key']=='blobs/first' and kwargs['Key'] not in self.s3.objects:
                self.s3.objects[kwargs['Key']]=(S3.consume(kwargs['Body']),kwargs['Metadata'])
                raise S3Error('PreconditionFailed')
            return put(**kwargs)
        self.s3.put_object=race
        events=self.trace_s3_file_order()
        value=self.copier(); self.assertTrue(value.run()['complete']); self.assertTrue(value.fresh_root)
        self.assertEqual([kind for kind,key in events if key=='blobs/first'],['put','get'])
        self.assertEqual(self.s3.objects['blobs/first'][0],(self.source/'blobs'/'first').read_bytes())

    def test_owner_412_race_is_conservative_resume_and_large_mpu_keeps_pre_get(self):
        put=self.s3.put_object
        def race(**kwargs):
            if kwargs['Key']==copy.CONTROL+'owner.json' and kwargs['Key'] not in self.s3.objects:
                self.s3.objects[kwargs['Key']]=(S3.consume(kwargs['Body']),kwargs['Metadata'])
                raise S3Error('PreconditionFailed')
            return put(**kwargs)
        self.s3.put_object=race
        events=self.trace_s3_file_order()
        value=self.copier(); self.assertTrue(value.run()['complete']); self.assertFalse(value.fresh_root)
        self.assertEqual([kind for kind,key in events if key=='blobs/first'],['get','put','get'])
        # An independently fresh bucket still checks before a large multipart upload.
        self.s3=S3(); self.state=self.root/'large-state'; self.state.mkdir(mode=0o700)
        self.plan={**self.plan,'state_dir':str(self.state)}
        events=self.trace_s3_file_order()
        with patch.object(copy,'MIN_PART',8),patch.object(copy,'part_size',return_value=16):
            value=self.copier(); self.assertTrue(value.run()['complete']); self.assertTrue(value.fresh_root)
        self.assertEqual([kind for kind,key in events if key=='blobs/first'],['get','create','get'])


    def max_copier(self):
        return copy.Copier(self.plan,self.plan_hash,self.guard,self.s3,max_speed=True)

    def test_max_speed_hash_and_small_transfers_overlap_sqlite_stays_coordinator_only(self):
        for number in range(90):
            (self.source/'blobs'/('parallel-%03d'%number)).write_bytes(bytes([number])*4096)
        lock=threading.Lock(); counts={'hash':0,'hash_high':0,'put':0,'put_high':0}
        original_hash=copy.hash_stream; original_put=self.s3.put_object; connect=sqlite3.connect
        sql_threads=[]; coordinator=threading.get_ident()
        def hash_work(*args):
            with lock:
                counts['hash']+=1; counts['hash_high']=max(counts['hash_high'],counts['hash'])
            try:
                time.sleep(.004)
                return original_hash(*args)
            finally:
                with lock: counts['hash']-=1
        def put(**kwargs):
            with lock:
                self.assertEqual(counts['hash'],0)
                counts['put']+=1; counts['put_high']=max(counts['put_high'],counts['put'])
            try:
                if kwargs['Key']==copy.CONTROL+'owner.json':
                    with copy.contextlib.closing(connect(self.state/'copy.sqlite3')) as observer:
                        self.assertEqual(observer.execute("SELECT value FROM metadata WHERE key='inventory_complete'").fetchone(),('true',))
                        self.assertEqual(observer.execute("SELECT COUNT(*) FROM entries WHERE kind='file'").fetchone()[0],93)
                time.sleep(.004)
                return original_put(**kwargs)
            finally:
                with lock: counts['put']-=1
        def tracked_connect(*args,**kwargs):
            db=connect(*args,**kwargs); db.set_trace_callback(lambda _sql:sql_threads.append(threading.get_ident())); return db
        self.s3.put_object=put
        with patch.object(copy,'hash_stream',side_effect=hash_work),patch.object(copy.sqlite3,'connect',side_effect=tracked_connect):
            result=self.max_copier().run()
        self.assertTrue(result['complete']); self.assertEqual(result['files'],93)
        self.assertGreater(counts['hash_high'],1); self.assertLessEqual(counts['hash_high'],copy.HASH_WORKERS)
        self.assertGreater(counts['put_high'],1); self.assertLessEqual(counts['put_high'],copy.COPY_WORKERS)
        self.assertEqual(set(sql_threads),{coordinator})
        self.assertEqual(counts['hash'],0); self.assertEqual(counts['put'],0)
        puts=[c for c in self.s3.calls if c[0]=='put']
        self.assertEqual(puts[-1][1],copy.CONTROL+'COMPLETE.json')
        events=len(puts); self.assertTrue(self.max_copier().run()['complete'])
        self.assertEqual(events,len([c for c in self.s3.calls if c[0]=='put']))

    def test_parallel_window_does_not_consume_unbounded_input(self):
        release=threading.Event(); entered=threading.Event(); lock=threading.Lock()
        counts={'produced':0,'active':0,'high':0}; results=[]; errors=[]
        def items():
            for number in range(20):
                with lock: counts['produced']+=1
                yield number
        def work(number):
            with lock:
                counts['active']+=1; counts['high']=max(counts['high'],counts['active'])
                if counts['active']==2: entered.set()
            try:
                if not release.wait(5): raise AssertionError('test release missing')
                return number
            finally:
                with lock: counts['active']-=1
        def coordinator():
            try:
                with copy.parallel_results(work,items(),2,4,threading.Event(),lambda:None) as output:
                    results.extend(output)
            except BaseException as error: errors.append(error)
        thread=threading.Thread(target=coordinator); thread.start()
        try:
            self.assertTrue(entered.wait(5))
            limit=time.monotonic()+5
            while counts['produced']<4 and time.monotonic()<limit: time.sleep(.001)
            self.assertEqual(counts['produced'],4)
            self.assertEqual(counts['high'],2)
        finally:
            release.set(); thread.join(10)
        self.assertFalse(thread.is_alive()); self.assertEqual(errors,[])
        self.assertEqual(sorted(results),list(range(20))); self.assertEqual(counts['active'],0)

    def test_parallel_small_failure_drains_before_return_and_preserves_resume(self):
        for number in range(20): (self.source/'blobs'/('queued-%02d'%number)).write_bytes(b'queue')
        release=threading.Event(); entered=threading.Event(); failed=threading.Event(); lock=threading.Lock()
        counts={'started':0,'active':0}; errors=[]; original=self.s3.put_object
        def put(**kwargs):
            if not kwargs['Key'].startswith('blobs/'): return original(**kwargs)
            with lock: counts['started']+=1; rank=counts['started']; counts['active']+=1
            try:
                if rank==1:
                    entered.set()
                    if not release.wait(5): raise AssertionError('test release missing')
                if rank==2:
                    if not entered.wait(5): raise AssertionError('first request missing')
                    failed.set(); raise S3Error('ServerFailure')
                return original(**kwargs)
            finally:
                with lock: counts['active']-=1
        self.s3.put_object=put
        def run():
            try: self.max_copier().run()
            except BaseException as error: errors.append(error)
        with patch.object(copy,'COPY_WORKERS',2),patch.object(copy,'COPY_PENDING',4):
            thread=threading.Thread(target=run); thread.start()
            try:
                self.assertTrue(failed.wait(5)); self.assertTrue(thread.is_alive())
                self.assertNotIn(copy.CONTROL+'COMPLETE.json',self.s3.objects)
            finally: release.set(); thread.join(10)
        self.assertFalse(thread.is_alive()); self.assertEqual(counts['active'],0)
        self.assertEqual(str(errors[0]),'s3_request_failed')
        self.assertLessEqual(counts['started'],2)
        self.s3.put_object=original
        self.assertTrue(self.max_copier().run()['complete'])

    def test_parallel_multipart_uses_independent_offsets_sorted_etags_and_no_active_parts_at_complete(self):
        body=bytes(range(251))*1700
        (self.source/'blobs'/'large').write_bytes(body)
        original=self.s3.upload_part; complete=self.s3.complete_multipart_upload
        lock=threading.Lock(); counts={'active':0,'high':0}
        def part(**kwargs):
            with lock: counts['active']+=1; counts['high']=max(counts['high'],counts['active'])
            try:
                self.assertTrue(kwargs['Body'].independent)
                kwargs['Body'].stream.seek(11)
                kwargs['Body'].read(3); kwargs['Body'].seek(0)
                time.sleep(.002*(4-kwargs['PartNumber']%4))
                return original(**kwargs)
            finally:
                with lock: counts['active']-=1
        def finished(**kwargs):
            self.assertEqual(counts['active'],0)
            numbers=[p['PartNumber'] for p in kwargs['MultipartUpload']['Parts']]
            self.assertEqual(numbers,sorted(numbers))
            return complete(**kwargs)
        self.s3.upload_part=part; self.s3.complete_multipart_upload=finished
        with patch.object(copy,'MIN_PART',8),patch.object(copy,'part_size',return_value=32768):
            self.assertTrue(self.max_copier().run()['complete'])
        self.assertEqual(self.s3.objects['blobs/large'][0],body)
        self.assertGreater(counts['high'],1); self.assertLessEqual(counts['high'],copy.PART_WORKERS)
        self.assertEqual(self.s3.uploads,{})

    def test_parallel_part_failure_drains_before_aborting_exact_owned_id(self):
        (self.source/'blobs'/'large').write_bytes(b'part-evidence'*20000)
        release=threading.Event(); entered=threading.Event(); failed=threading.Event(); lock=threading.Lock()
        counts={'active':0}; errors=[]; original=self.s3.upload_part; abort=self.s3.abort_multipart_upload
        self.s3.uploads['foreign']={'key':'foreign','metadata':{},'parts':{}}
        def part(**kwargs):
            if kwargs['Key']!='blobs/large': return original(**kwargs)
            with lock: counts['active']+=1
            try:
                if kwargs['PartNumber']==1:
                    entered.set()
                    if not release.wait(5): raise AssertionError('test release missing')
                if kwargs['PartNumber']==2:
                    if not entered.wait(5): raise AssertionError('first request missing')
                    failed.set(); raise S3Error('ServerFailure')
                return original(**kwargs)
            finally:
                with lock: counts['active']-=1
        def abort_owned(**kwargs):
            if kwargs['Key']=='blobs/large': self.assertEqual(counts['active'],0)
            self.assertNotEqual(kwargs['UploadId'],'foreign')
            return abort(**kwargs)
        self.s3.upload_part=part; self.s3.abort_multipart_upload=abort_owned
        def run():
            try: self.max_copier().run()
            except BaseException as error: errors.append(error)
        with patch.object(copy,'MIN_PART',8),patch.object(copy,'part_size',return_value=32768):
            thread=threading.Thread(target=run); thread.start()
            try:
                self.assertTrue(failed.wait(5)); self.assertTrue(thread.is_alive())
                self.assertFalse(any(c[0]=='abort' and c[1]=='blobs/large' for c in self.s3.calls))
            finally: release.set(); thread.join(10)
        self.assertFalse(thread.is_alive()); self.assertEqual(counts['active'],0)
        self.assertEqual(str(errors[0]),'s3_request_failed')
        self.assertEqual(set(self.s3.uploads),{'foreign'})
        self.assertNotIn(copy.CONTROL+'COMPLETE.json',self.s3.objects)

    def test_max_speed_limiter_counts_atomically_without_sleep(self):
        limiter=copy.Limiter(self.guard,rate=None)
        with patch.object(copy.time,'sleep',side_effect=AssertionError('unthrottled mode slept')):
            with copy.concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(lambda _: [limiter.consume(1) for _ in range(1000)],range(16)))
        self.assertEqual(limiter.bytes,16000)
        value=self.max_copier(); self.assertIsNone(value.limiter.rate)
        self.assertEqual(copy.Copier(self.plan,self.plan_hash,self.guard,self.s3).limiter.rate,copy.RATE)


    def test_parallel_hash_failure_drains_and_cannot_publish_inventory_or_remote_owner(self):
        release=threading.Event(); entered=threading.Event(); failed=threading.Event(); lock=threading.Lock()
        counts={'rank':0,'active':0}; errors=[]; original=copy.hash_stream
        def hashed(*args):
            with lock: counts['rank']+=1; rank=counts['rank']; counts['active']+=1
            try:
                if rank==1:
                    entered.set()
                    if not release.wait(5): raise AssertionError('test release missing')
                if rank==2:
                    if not entered.wait(5): raise AssertionError('first hash missing')
                    failed.set(); raise copy.CopyError('source_file_changed')
                return original(*args)
            finally:
                with lock: counts['active']-=1
        def run():
            try: self.max_copier().run()
            except BaseException as error: errors.append(error)
        with patch.object(copy,'HASH_WORKERS',2),patch.object(copy,'HASH_PENDING',4),patch.object(copy,'hash_stream',side_effect=hashed):
            thread=threading.Thread(target=run); thread.start()
            try:
                self.assertTrue(failed.wait(5)); self.assertTrue(thread.is_alive())
                self.assertEqual(self.s3.objects,{})
            finally: release.set(); thread.join(10)
        self.assertFalse(thread.is_alive()); self.assertEqual(counts['active'],0)
        self.assertEqual(str(errors[0]),'source_file_changed')
        with copy.contextlib.closing(sqlite3.connect(self.state/'copy.sqlite3')) as db:
            self.assertIsNone(db.execute("SELECT value FROM metadata WHERE key='inventory_complete'").fetchone())
        self.assertEqual(self.s3.objects,{})
        self.assertTrue(self.max_copier().run()['complete'])

    def test_guard_serializes_source_probes_and_rechecks_cache_after_lock(self):
        mountpoint=self.root/'thread-mount'; snapshot=mountpoint/'.zfs'/'snapshot'/'copy-fixed'
        snapshot.mkdir(parents=True)
        token='e'*24; plan={**self.plan,'source_root':str(snapshot),
            'migration_proof_id':copy.digest(b'devres-nodeport-proof-v1\0'+token.encode())}
        self.plan_file.write_bytes(copy.canonical(plan)); plan_hash=copy.digest(self.plan_file.read_bytes())
        journal=self.root/'thread-journal.json'
        journal.write_bytes(copy.canonical({'token':token,'phase':'running_migrate_storage','mode':'direct','deadline_at':copy.DEADLINE}))
        journal.chmod(0o600); probes=[]
        def run(args):
            probes.append(args); time.sleep(.002)
            if args[:2]==['zfs','holds']: return plan['source_snapshot']+'\t'+plan['hold']+'\tdate'
            if args[:2]==['zfs','list']: return copy.DATASET
            if args[-2]=='mountpoint': return str(mountpoint)
            return '456' if '@' in args[-1] else '123'
        guard=copy.Guard(plan,self.plan_file,plan_hash,run=run,clock=lambda:copy.DEADLINE-1000)
        barrier=threading.Barrier(8)
        def check(_): barrier.wait(timeout=5); guard.check()
        with patch.object(copy,'JOURNAL',journal),patch.object(copy.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)), \
                patch.object(copy,'mount_paths',return_value=[]):
            with copy.concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(check,range(8)))
            self.assertEqual(len(probes),5)
            guard.run=lambda _args:'wrong-guid'
            with self.assertRaisesRegex(copy.CopyError,'source_identity_changed'): guard.check(force=True)
            guard.run=run
            def stopped(_):
                with self.assertRaisesRegex(copy.CopyError,'source_identity_changed'): guard.check()
            with copy.concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(stopped,range(8)))
            self.assertEqual(len(probes),5)
            def stop_during_probe(args):
                copy.STOPPED=True
                return run(args)
            with patch.object(copy,'STOPPED',False):
                interrupted=copy.Guard(plan,self.plan_file,plan_hash,run=stop_during_probe,clock=lambda:copy.DEADLINE-1000)
                with self.assertRaisesRegex(copy.CopyError,'copy_interrupted'): interrupted.check(force=True)

    def test_cli_max_speed_passes_fixed_mode_and_sdk_pool_is_sufficient(self):
        result=SimpleNamespace(returncode=0,stdout=json.dumps(['ACCESS','SECRET',copy.REGION]).encode())
        account=SimpleNamespace(pw_name='codex',pw_uid=1001,pw_gid=1001,pw_dir='/home/codex')
        sdk=MagicMock(); config=MagicMock(); client=sdk.Session.return_value.client.return_value
        client.meta.service_model.operation_model.return_value.input_shape.members={'IfNoneMatch':object()}
        modules={'boto3':sdk,'botocore':SimpleNamespace(),'botocore.config':SimpleNamespace(Config=config)}
        with patch.dict('sys.modules',modules),patch.object(copy.pwd,'getpwnam',return_value=account), \
                patch.object(copy.subprocess,'run',return_value=result): copy.make_client(self.plan,max_speed=True)
        self.assertEqual(config.call_args.kwargs['max_pool_connections'],copy.MAX_CONNECTIONS)
        self.assertGreaterEqual(copy.MAX_CONNECTIONS,max(copy.COPY_WORKERS,copy.PART_WORKERS))
        with patch.object(copy.os,'geteuid',return_value=0),patch.object(copy,'read_plan',return_value=(self.plan,self.plan_hash)), \
                patch.object(copy,'Guard'),patch.object(copy,'make_client') as make,patch.object(copy,'Copier') as copier, \
                patch.object(copy.os,'umask'),patch.object(copy.signal,'signal'),patch('sys.stdout',new=io.StringIO()):
            copier.return_value.check.return_value={'check_passed':True}
            copy.main(['--plan',str(self.plan_file),'--check','--max-speed'])
        self.assertTrue(make.call_args.kwargs['max_speed'])
        self.assertTrue(copier.call_args.kwargs['max_speed'])
        copier.return_value.check.assert_called_once()


    def test_parallel_sqlite_consumer_failure_drains_and_releases_cursor_for_resume(self):
        for number in range(12): (self.source/'blobs'/('sql-%02d'%number)).write_bytes(b'checkpoint evidence')
        value=self.max_copier(); database=value.database; original=self.s3.put_object
        release=threading.Event(); checkpoint_failed=threading.Event(); entered=threading.Event()
        lock=threading.Lock(); counts={'active':0,'rank':0}; errors=[]
        def opened():
            database()
            value.db.execute("CREATE TEMP TRIGGER reject_checkpoint BEFORE UPDATE OF verified ON entries BEGIN SELECT RAISE(FAIL,'fixture_checkpoint_failure'); END")
            value.db.set_trace_callback(lambda sql:checkpoint_failed.set() if sql.startswith('UPDATE entries SET verified') else None)
        def put(**kwargs):
            if not kwargs['Key'].startswith('blobs/'): return original(**kwargs)
            with lock: counts['active']+=1; counts['rank']+=1; rank=counts['rank']
            try:
                if rank==1:
                    entered.set()
                    if not release.wait(5): raise AssertionError('test release missing')
                return original(**kwargs)
            finally:
                with lock: counts['active']-=1
        def run():
            try: value.run()
            except BaseException as error: errors.append(error)
        value.database=opened; self.s3.put_object=put
        with patch.object(copy,'COPY_WORKERS',2),patch.object(copy,'COPY_PENDING',4):
            thread=threading.Thread(target=run); thread.start()
            try:
                self.assertTrue(entered.wait(5)); self.assertTrue(checkpoint_failed.wait(5))
                self.assertTrue(thread.is_alive()); self.assertIsNotNone(value.db)
                self.assertNotIn(copy.CONTROL+'COMPLETE.json',self.s3.objects)
            finally: release.set(); thread.join(10)
        self.assertFalse(thread.is_alive()); self.assertEqual(counts['active'],0); self.assertIsNone(value.db)
        self.assertIsInstance(errors[0],sqlite3.IntegrityError)
        self.s3.put_object=original
        self.assertTrue(self.max_copier().run()['complete'])

    def test_default_and_parallel_hash_order_produce_identical_manifest(self):
        for number in range(30): (self.source/'blobs'/('same-%02d'%number)).write_bytes(bytes([number])*1024)
        self.copier().run()
        expected=self.s3.objects[copy.CONTROL+'manifest.jsonl'][0]
        self.s3=S3(); self.state=self.root/'parallel-state'; self.state.mkdir(mode=0o700)
        self.plan={**self.plan,'state_dir':str(self.state)}
        self.plan_hash=copy.digest(copy.canonical(self.plan))
        self.assertTrue(self.max_copier().run()['complete'])
        self.assertEqual(self.s3.objects[copy.CONTROL+'manifest.jsonl'][0],expected)
        self.assertTrue(self.copier().run()['complete'])

    def test_worker_cancellation_during_guard_cannot_start_another_request(self):
        value=self.max_copier()
        with patch.object(self.guard,'check',side_effect=lambda **_kwargs:value.cancelled.set()), \
                patch.object(self.s3,'get_object') as get:
            with self.assertRaisesRegex(copy.CopyError,'copy_worker_cancelled'):
                value.call('get_object',Key='blobs/first')
        get.assert_not_called()


if __name__=='__main__': unittest.main()
