"""Synthetic/private filesystem behavior only; never imports installed producers."""
import copy,hashlib,importlib.util,json,os,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[2]/'deploy/production/cycle5_reclaim_3dae7d91.py'
spec=importlib.util.spec_from_file_location('cycle5_reclaim_candidate',SOURCE)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)


def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    path.write_bytes(m.encode(value) if not isinstance(value,bytes) else value);path.chmod(0o600)


class Fixture:
    def __init__(self,root):
        self.root=root;self.bundle=root/'bundle';self.work=root/'work';self.install=root/'install';self.journal=root/'journal/phase'
        for p in (self.bundle,self.work,self.install,self.journal.parent):p.mkdir(mode=0o700)
        self.cp=self.bundle/'checkpoint-volume';self.cp.mkdir(mode=0o700)
        self.scope=m.Scope('cycle5-checkpoint-proof',self.bundle,self.work,self.install,self.journal)
        for p in ('pg-clone','rehearsal/cache','rehearsal/writer-cache','pg-checkpoint','fallback-cache/serving','fallback-cache/writer'):
            path=self.cp/p;path.mkdir(parents=True,mode=0o700);put(path/'payload',b'copy-payload')
        put(self.install/'physical-checkpoint.py',b'# synthetic producer source only\n')
        pins={'source_sha256':m.file_record(self.install/'physical-checkpoint.py')['sha256']}
        put(self.cp/'owner.json',{'token':'a'*24,'pins':pins})
        put(self.cp/'checkpoint-completed.json',{'pins':pins,'pg_bytes':12})
        put(self.cp/'proof-intent.json',{'token':'a'*24})
        put(self.cp/'clone-cleanup-completed.json',dict.fromkeys(('all_owned_containers_removed','owned_network_removed','physical_checkpoint_retained'),True))
        put(self.cp/'clone-proof-result.json',{'isolated_clone_only':True,'no_production_mount':True,'provider_source_requests':0})
        put(self.cp/'cache-baselines.json',{'bytes':24})
        completed={'revision':m.REVISION,'schema':18,'pins':pins,'old_clone_verified':True,'fallback_writer_verified':True,
            'original_s3_retained':True,'independent_s3_backup':False}
        for field,name in (('checkpoint_receipt_sha256','checkpoint-completed.json'),('clone_proof_sha256','clone-proof-result.json'),('cache_baselines_sha256','cache-baselines.json')):
            completed[field]=m.file_record(self.cp/name)['sha256']
        put(self.cp/'completed.json',completed)
        for name in ('pg-file-manifest.jsonl','archive-bindings.jsonl','capture-bindings.jsonl'):put(self.cp/name,b'bounded manifest metadata\n')
        names=('completed.json','checkpoint-completed.json','clone-proof-result.json','clone-cleanup-completed.json',
            'cache-baselines.json','pg-file-manifest.jsonl','archive-bindings.jsonl','capture-bindings.jsonl')
        backup={'verified':True,'revision':m.REVISION,'schema':18,'kind':'coordinated-schema18-backup',
            'checks':dict.fromkeys(('coordinated_pg_s3','credentials_preserved','fallback_writer_verified','old_clone_verified',
                'pg_restarted_without_restore','roles_stopped'),True),
            'artifacts':[{'path':str(self.cp/n),'sha256':m.file_record(self.cp/n)['sha256']} for n in names]}
        put(self.cp/'backup-receipt.json',backup)
        self.engine=m.Engine(self.scope,guard=lambda *a,**k:{'runtime_qualified':k['runtime'],'stable':True})
    def edit(self,name,mutate):
        p=self.cp/name;v=json.loads(p.read_bytes());mutate(v);put(p,v)
    def preview(self):
        # Directory bind aliases are admitted by actual dev/ino equality in
        # production; fixture maps only that path comparison, never receipts.
        original=m.directory_record
        def record(path):
            path=Path(path)
            if m.under(path,self.work/'checkpoint-state'):path=self.cp/path.relative_to(self.work/'checkpoint-state')
            return original(path)
        with patch.object(m,'directory_record',record):return self.engine.preview(runtime=True)
    def approved(self,preview):
        digest=m.sha(m.encode(preview));source=m.sha(SOURCE.read_bytes())
        approval={'version':1,'approved':True,'kind':'cycle5-completed-copy-retirement','phase':self.scope.phase,
            'preview_sha256':digest,'source_sha256':source,'maximum_applies':1,'operations':['apply']}
        return digest,source,approval
    def make_c4(self):
        self.scope=m.Scope('cycle4-completed',self.bundle,self.work,self.install,self.journal)
        self.engine=m.Engine(self.scope,guard=lambda *a,**k:{'runtime_qualified':k['runtime'],'stable':True})
        rr=self.bundle/'restore-rehearsal-volume';rr.mkdir(mode=0o700)
        for name in ('restore-controller.py','restore-rehearsal.py'):put(self.install/name,b'# synthetic review source\n')
        sources={n:m.file_record(self.install/n)['sha256'] for n in m.C4_SOURCES}
        put(rr/'owner.json',{'token':'b'*24,'sources':sources,'scope':{'device':rr.stat().st_dev,'inode':rr.stat().st_ino}})
        put(rr/'cleanup-completed.json',{'token':'b'*24,'owned_container_removed':True,'golden_retained':True})
        put(rr/'real-pg-proof.json',dict.fromkeys(('marker_removed','no_kubernetes_commands','no_production_credentials','no_network'),True))
        put(self.work/'restore-rehearsal-receipt.json',{'verified':True,'revision':m.REVISION,'kind':'isolated-real-pg-restore-rehearsal',
            'sources':sources,'checks':dict.fromkeys(('full_baseline_caches','isolated_real_pg_restore','marker_removed',
                'owned_cleanup_complete','production_untouched','restore_state_machine'),True),
            'artifacts':[{'path':str(rr/n),'sha256':m.file_record(rr/n)['sha256']} for n in ('real-pg-proof.json','cleanup-completed.json')]})
        put(rr/'runtime/restore/state.json',{'phase':'restored','token':'d'*24})
        for name in ('isolated-pv','cache-serving','cache-writer','.failed-serving-'+'d'*24,'.failed-writer-'+'d'*24):
            p=rr/'runtime'/name;p.mkdir(mode=0o700);put(p/'payload',b'synthetic restore copy')
        put(self.bundle/'restore/state.json',{'phase':'restored','preservation':'manifest_verified','preserved_directory':True,
            'source':str(self.root/'real-pg'),'token':'c'*24})
        put(self.bundle/'restore/restored.json',{'verified':True,'database_restored':True,'baseline_caches_restored':True,'s3_rewound':False})
        for name in ('.failed-'+'c'*24,'.failed-serving-'+'c'*24,'.failed-writer-'+'c'*24):
            p=self.root/name;p.mkdir(mode=0o700);put(p/'payload',b'protected real postattempt data')
        put(self.cp/'cache-baselines.json',{'bytes':24,'layouts':{r:{'path':str(self.root/('real-'+r))} for r in ('serving','writer')}})
        self.edit('completed.json',lambda v:v.update(cache_baselines_sha256=m.file_record(self.cp/'cache-baselines.json')['sha256']))
        def update(v):
            for a in v['artifacts']:a['sha256']=m.file_record(Path(a['path']))['sha256']
        self.edit('backup-receipt.json',update)
        return sources,m.file_record(self.bundle/'restore/restored.json')['sha256']


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='c5-reclaim-tests-',dir='/tmp');self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.f=Fixture(self.root)
    def tearDown(self):self.temp.cleanup()
    def test_fixed_cli_scopes_and_distinct_journals(self):
        a=m.production_scope('cycle4-completed');b=m.production_scope('cycle5-checkpoint-proof')
        self.assertNotEqual(a.journal,b.journal);self.assertNotEqual(a.bundle,b.bundle)
        self.assertEqual(b.install,Path('/usr/local/libexec/devres-upgrade-3dae7d91-cycle5'))
        self.assertEqual(b.bundle,Path('/var/lib/devres-production-upgrades/3dae7d91-cycle5-20261118'))
        self.assertEqual(b.work,Path('/tmp/devres-upgrade-3dae7d91-cycle5-20261118'))
        for value in ('cycle3','/tmp/anything','cycle4-proof'):
            with self.assertRaises(m.Refused):m.production_scope(value)
    def test_c4_selects_eight_synthetic_leaves_and_protects_real_generations(self):
        sources,restored=self.f.make_c4()
        with patch.object(m,'C4_SOURCES',sources),patch.object(m,'C4_RESTORED',restored):
            roots,protected,tokens=self.f.engine.receipts()
        self.assertEqual(len(roots),8);self.assertEqual(len(protected),6);self.assertEqual(len(tokens),3)
        self.assertTrue(all(p.is_relative_to(self.f.bundle) for p in roots))
        self.assertTrue(all(not any(m.under(p,r) for r in roots) for p in protected))
        self.assertEqual(sum(p.name.startswith('.failed-') for p in roots),2)
        self.assertEqual(sum(p.name.startswith('.failed-') for p in protected),3)
    def test_c4_wrong_source_or_restored_receipt_refuses(self):
        sources,restored=self.f.make_c4()
        with patch.object(m,'C4_SOURCES',sources),patch.object(m,'C4_RESTORED','0'*64):
            with self.assertRaisesRegex(m.Refused,'exact_c4_completed_restore'):self.f.engine.receipts()
        with patch.object(m,'C4_SOURCES',dict(sources,**{'restore-controller.py':'0'*64})),patch.object(m,'C4_RESTORED',restored):
            with self.assertRaisesRegex(m.Refused,'exact_c4_sources'):self.f.engine.receipts()
    def test_c4_wrong_rehearsal_owner_or_artifacts_refuses(self):
        sources,restored=self.f.make_c4();p=self.f.bundle/'restore-rehearsal-volume/cleanup-completed.json'
        v=json.loads(p.read_bytes());v['token']='0'*24;put(p,v)
        with patch.object(m,'C4_SOURCES',sources),patch.object(m,'C4_RESTORED',restored):
            with self.assertRaisesRegex(m.Refused,'completed_restore_rehearsal'):self.f.engine.receipts()
    def test_receipt_chain_selects_only_three_disposable_roots(self):
        roots,protected,tokens=self.f.engine.receipts()
        self.assertEqual([p.relative_to(self.f.cp).as_posix() for p in roots],['pg-clone','rehearsal/cache','rehearsal/writer-cache'])
        self.assertEqual(len(protected),3);self.assertEqual(tokens,['a'*24])
    def test_scope_and_metadata_require_invoking_owner_and_private_flags(self):
        self.assertEqual(self.f.bundle.stat().st_uid,os.geteuid())
        self.assertEqual((self.f.cp/'owner.json').stat().st_nlink,1)
        original=m.identity(self.f.bundle)
        with patch.object(m,'identity',return_value=dict(original,uid=123456)):
            with self.assertRaisesRegex(m.Refused,'unexpected_directory_owner'):self.f.engine.receipts()
        owner=self.f.cp/'owner.json';owner.chmod(0o644)
        with self.assertRaisesRegex(m.Refused,'private_bounded_metadata'):self.f.engine.receipts()
        owner.chmod(0o600);os.link(owner,self.root/'metadata-hardlink')
        with self.assertRaisesRegex(m.Refused,'private_bounded_metadata'):self.f.engine.receipts()
    def test_root_invocation_refuses_nonroot_scope_or_copy_owner(self):
        original=m.identity(self.f.bundle)
        with patch.object(os,'geteuid',return_value=0),patch.object(m,'identity',return_value=dict(original,uid=1000)):
            with self.assertRaisesRegex(m.Refused,'unexpected_directory_owner'):self.f.engine.receipts()
        original_tree=m.tree
        def tree(path):
            rows=original_tree(path);rows[0]=dict(rows[0],uid=1000,gid=1000);return rows
        def directory(path):
            m.safe_path(path);return dict(m.identity(path),uid=0,gid=0)
        with patch.object(os,'geteuid',return_value=0),patch.object(os,'getegid',return_value=0),\
            patch.object(self.f.engine,'receipts',return_value=([self.f.cp/'pg-clone'],[],['a'*24])),\
            patch.object(m,'directory_record',side_effect=directory),patch.object(m,'tree',side_effect=tree):
            # Override only directory ownership after its normal canonical checks
            # so this specifically exercises copy metadata's root-only owner set.
            with self.assertRaisesRegex(m.Refused,'unexpected_copy_entry_owner'):self.f.preview()
    def test_cli_refuses_nonroot_before_snapshot_or_output(self):
        output=self.root/'must-not-exist.json'
        with patch.object(os,'geteuid',return_value=1000),patch.object(os,'umask'),patch.object(sys,'argv',[
            str(SOURCE),'inspect','--phase','cycle4-completed','--output',str(output)]),\
            patch.object(m.Engine,'preview',side_effect=AssertionError('must not inspect')):
            with self.assertRaisesRegex(m.Refused,'root_required'):m.main()
        self.assertFalse(output.exists())
    def test_special_metadata_fifo_refuses_without_waiting_for_a_writer(self):
        path=self.root/'metadata-fifo';os.mkfifo(path,0o600)
        with self.assertRaisesRegex(m.Refused,'bounded_regular_metadata'):m.file_record(path)
        with self.assertRaisesRegex(m.Refused,'private_bounded_metadata'):m.load(path)
    def test_metadata_single_descriptor_refuses_symlink_and_unbounded_or_replaced_file(self):
        source=self.root/'metadata.json';put(source,{'value':True});link=self.root/'metadata-link.json';link.symlink_to(source)
        self.assertEqual(m.load(source),{'value':True})
        with self.assertRaisesRegex(m.Refused,'symlink'):m.load(link)
        with patch.object(m,'MAX_BYTES',1):
            with self.assertRaisesRegex(m.Refused,'bounded_metadata'):m.load(source)
        original=os.fstat;calls=0
        def changing(fd):
            nonlocal calls
            result=original(fd);calls+=1
            if calls==1:
                replacement=self.root/'replacement.json';put(replacement,{'value':False});replacement.replace(source)
            return result
        with patch.object(os,'fstat',side_effect=changing):
            with self.assertRaisesRegex(m.Refused,'metadata_changed'):m.load(source)
    def test_unknown_owner_source_or_completion_refuses(self):
        for name,fn in [('proof-intent.json',lambda v:v.update(token='b'*24)),
            ('clone-cleanup-completed.json',lambda v:v.update(owned_network_removed=False)),
            ('completed.json',lambda v:v.update(schema=19)),('completed.json',lambda v:v.update(fallback_writer_verified=False)),
            ('owner.json',lambda v:v['pins'].update(source_sha256='0'*64)),
            ('clone-proof-result.json',lambda v:v.update(provider_source_requests=1))]:
            with self.subTest(name=name):
                path=self.f.cp/name;original=path.read_bytes();self.f.edit(name,fn)
                with self.assertRaises(m.Refused):self.f.engine.receipts()
                put(path,original)
    def test_changed_clone_receipt_refuses_even_if_booleans_true(self):
        self.f.edit('clone-proof-result.json',lambda v:v.update(another=True))
        with self.assertRaisesRegex(m.Refused,'checkpoint_proof_hash_chain'):self.f.engine.receipts()
    def test_backup_cannot_depend_on_retired_body(self):
        p=self.f.cp/'pg-clone/payload'
        self.f.edit('backup-receipt.json',lambda v:v['artifacts'].append({'path':str(p),'sha256':m.file_record(p)['sha256']}))
        with self.assertRaisesRegex(m.Refused,'backup_requires_disposable_copy'):self.f.engine.receipts()
    def test_backup_missing_manifest_or_hash_refuses(self):
        original=(self.f.cp/'backup-receipt.json').read_bytes()
        self.f.edit('backup-receipt.json',lambda v:v['artifacts'].pop())
        with self.assertRaises(m.Refused):self.f.engine.receipts()
        put(self.f.cp/'backup-receipt.json',original)
        put(self.f.cp/'archive-bindings.jsonl',b'changed metadata')
        with self.assertRaisesRegex(m.Refused,'retained_backup_artifact_changed'):self.f.engine.receipts()
    def test_proof_retirement_refuses_started_rehearsal(self):
        put(self.f.bundle/'restore-rehearsal-volume/owner.json',{'started':True})
        with self.assertRaisesRegex(m.Refused,'must_precede'):self.f.engine.receipts()
    def test_unknown_phase_never_selects_data(self):
        scope=m.Scope('unknown',self.f.bundle,self.f.work,self.f.install,self.f.journal)
        with self.assertRaisesRegex(m.Refused,'fixed_phase'):m.Engine(scope).receipts()
    def test_preview_does_not_open_copy_payloads_or_golden_bodies(self):
        original=m.file_record
        def record(p,*a,**k):
            self.assertNotEqual(Path(p).name,'payload');return original(p,*a,**k)
        with patch.object(m,'file_record',record):value=self.f.preview()
        self.assertFalse(value['payload_contents_hashed']);self.assertEqual(len(value['roots']),3)
        self.assertEqual(len(value['trees']),3);self.assertFalse(self.f.journal.exists())
    def test_external_hardlink_refuses(self):
        os.link(self.f.cp/'pg-clone/payload',self.root/'outside')
        with self.assertRaisesRegex(m.Refused,'external_hardlink'):self.f.preview()
    def test_all_selected_hardlinks_are_accepted(self):
        os.link(self.f.cp/'pg-clone/payload',self.f.cp/'rehearsal/cache/second')
        value=self.f.preview();self.assertEqual(len(value['roots']),3)
    def test_unknown_preserved_generation_is_not_hashed(self):
        path=self.f.bundle/'.failed-foreign';path.mkdir();put(path/'payload',b'private generation')
        with self.assertRaisesRegex(m.Refused,'unknown_preserved_generation'):self.f.preview()
    def test_symlink_ancestor_refuses(self):
        target=self.f.cp/'pg-clone';renamed=self.root/'external';target.rename(renamed);target.symlink_to(renamed,target_is_directory=True)
        with self.assertRaisesRegex(m.Refused,'symlink'):self.f.preview()
    def test_apply_preserves_roots_golden_metadata_and_logs_and_refuses_replay(self):
        put(self.f.work/'history.log',b'retained history')
        os.link(self.f.cp/'pg-clone/payload',self.f.cp/'rehearsal/cache/linked')
        preview=self.f.preview();digest,source,approval=self.f.approved(preview)
        protected=copy.deepcopy(preview['protected']);self.f.engine.preview=lambda **k:preview
        result=self.f.engine.apply(preview,digest,source,approval)
        self.assertTrue(result['verified']);self.assertTrue((self.f.journal/'completed.json').is_file())
        for p in preview['roots']:self.assertEqual(list(Path(p).iterdir()),[])
        self.assertEqual(self.f.engine.protected([Path(p) for p in preview['roots']],[Path(p) for p in preview['protected_roots']]),protected)
        self.assertEqual((self.f.cp/'pg-checkpoint/payload').read_bytes(),b'copy-payload')
        with self.assertRaisesRegex(m.Refused,'already_consumed'):self.f.engine.apply(preview,digest,source,approval)
    def test_stale_preview_or_wrong_approval_refuses_before_intent(self):
        preview=self.f.preview();digest,source,approval=self.f.approved(preview)
        self.f.engine.preview=lambda **k:dict(preview,entries=-1)
        with self.assertRaisesRegex(m.Refused,'preview_stale'):self.f.engine.apply(preview,digest,source,approval)
        self.assertFalse(self.f.journal.exists());approval['maximum_applies']=2
        with self.assertRaisesRegex(m.Refused,'exact_external_approval'):self.f.engine.apply(preview,digest,source,approval)
        self.assertFalse(self.f.journal.exists())
    def test_files_only_preview_can_never_apply(self):
        preview=self.f.preview();preview['environment']['runtime_qualified']=False;digest,source,approval=self.f.approved(preview)
        with self.assertRaisesRegex(m.Refused,'full_runtime'):self.f.engine.apply(preview,digest,source,approval)
        self.assertFalse(self.f.journal.exists())
    def test_delete_late_inode_or_children_drift_keeps_failure_receipt(self):
        preview=self.f.preview();digest,source,approval=self.f.approved(preview);self.f.engine.preview=lambda **k:preview
        put(self.f.cp/'pg-clone/new-private-file',b'late')
        with self.assertRaisesRegex(m.Refused,'root_metadata_changed'):self.f.engine.apply(preview,digest,source,approval)
        self.assertTrue((self.f.journal/'failed.json').is_file());self.assertFalse((self.f.journal/'completed.json').exists())
        self.assertTrue((self.f.cp/'pg-clone/payload').is_file())
    def test_renamed_payload_is_not_unlinked(self):
        root=self.f.cp/'pg-clone';rows=m.tree(root);(root/'payload').unlink();put(root/'payload',b'replacement')
        self.f.engine.removed_links=m.Counter();self.f.engine.link_ctimes={}
        with self.assertRaisesRegex(m.Refused,'root_metadata_changed'):self.f.engine.clear(root,rows)
        self.assertEqual((root/'payload').read_bytes(),b'replacement')
    def test_clear_nested_entries_is_linear_and_tracks_crossroot_links(self):
        a=self.f.cp/'pg-clone';b=self.f.cp/'rehearsal/cache';(a/'nested').mkdir();put(a/'nested/payload',b'nested')
        os.link(a/'nested/payload',b/'linked');rows_a=m.tree(a);rows_b=m.tree(b)
        self.f.engine.removed_links=m.Counter();self.f.engine.link_ctimes={}
        self.f.engine.clear(a,rows_a);self.f.engine.clear(b,rows_b)
        self.assertEqual(list(a.iterdir()),[]);self.assertEqual(list(b.iterdir()),[])


class FirewallCanonicalizationTests(unittest.TestCase):
    def dump(self,stamp,rule=b'-A INPUT -j ACCEPT',comment=b'# retained operator comment',program=b'iptables-save'):
        return b'# Generated by '+program+b' v1.8.11 (nf_tables) on '+stamp+b'\n*filter\n:INPUT ACCEPT [0:0]\n'+comment+b'\n'+rule+b'\nCOMMIT\n# Completed on '+stamp+b'\n'
    def test_timestamp_only_changes_are_equivalent_for_both_families(self):
        a=b'Wed Nov 18 02:01:46 2026';b=b'Wed Nov 18 02:02:47 2026'
        for family,program,rule in [('ipv4',b'iptables-save',b'-A INPUT -s 192.0.2.1 -j ACCEPT'),
                                    ('ipv6',b'ip6tables-save',b'-A INPUT -s 2001:db8::1 -j ACCEPT')]:
            with self.subTest(family=family):
                original=self.dump(a,rule,program=program);canonical=m.canonical_iptables_save(original)
                self.assertEqual(canonical,m.canonical_iptables_save(self.dump(b,rule,program=program)))
                self.assertEqual(canonical,original.replace(a,b'<wallclock>'))
                self.assertIn(b'# Generated by '+program+b' v1.8.11 (nf_tables) on ',canonical)
    def test_rule_other_comment_and_line_ending_bytes_remain_significant(self):
        stamp=b'Wed Nov 18 02:01:46 2026';original=self.dump(stamp)
        for changed in (self.dump(stamp,b'-A INPUT -j DROP'),self.dump(stamp,comment=b'# changed operator comment'),
            original.replace(b'COMMIT\n',b'COMMIT \n'),original[:-1]):
            self.assertNotEqual(m.canonical_iptables_save(original),m.canonical_iptables_save(changed))
    def test_unknown_version_backend_or_banner_refuses(self):
        original=self.dump(b'Wed Nov 18 02:01:46 2026')
        for changed in (original.replace(b'v1.8.11',b'v1.8.12'),original.replace(b'(nf_tables)',b'(legacy)'),
            original.replace(b'# Generated by iptables-save',b'# Generated by another-tool'),
            original.replace(b'# Completed on ',b'# Completed at '),b' '+original):
            with self.subTest(changed=changed[:70]):
                with self.assertRaises(m.Refused):m.canonical_iptables_save(changed)
    def test_malformed_or_impossible_calendar_date_refuses(self):
        for stamp in (b'Wed Nov 18 25:01:46 2026',b'Wed Nov 18 02:60:46 2026',b'Thu Nov 18 02:01:46 2026',
            b'Wed Feb 30 02:01:46 2026',b'Wed Nov 18 02:01:46 0000',b'Wed Nov 8 02:01:46 2026',
            b'Wed Nov 18 02:01:46 2026 extra'):
            with self.subTest(stamp=stamp):
                with self.assertRaisesRegex(m.Refused,'malformed_iptables_banner'):m.canonical_iptables_save(self.dump(stamp))
    def test_single_digit_day_and_multiple_tables_preserve_all_rule_bytes(self):
        a=b'Wed Nov  4 02:01:46 2026';b=b'Wed Nov  4 02:01:47 2026'
        body=self.dump(a)+self.dump(a,b'-A OUTPUT -j DROP')
        self.assertEqual(m.canonical_iptables_save(body),body.replace(a,b'<wallclock>'))
        self.assertEqual(m.canonical_iptables_save(body),m.canonical_iptables_save(body.replace(a,b)))


class ProcessGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='c5-proc-tests-',dir='/tmp');self.root=Path(self.tmp.name)
        self.copy=self.root/'copy';self.copy.mkdir();put(self.copy/'payload',b'data');self.proc=self.root/'proc';self.proc.mkdir()
        self.pid=self.proc/'101';(self.pid/'ns').mkdir(parents=True);(self.pid/'fd').mkdir()
        (self.pid/'ns/mnt').symlink_to('mnt:[100]');(self.proc/'self').symlink_to('101')
        for name,value in [('cwd','/'),('root','/'),('exe','/usr/bin/python3')]: (self.pid/name).symlink_to(value)
        put(self.pid/'cmdline',b'synthetic-test\0');put(self.pid/'maps',b'')
        put(self.proc/'sys/kernel/random/boot_id',b'synthetic-boot')
        dev=self.copy.stat().st_dev;self.device=f'{os.major(dev)}:{os.minor(dev)}'
        self.base=f'10 1 {self.device} / / rw - ext4 /dev/test rw\n';put(self.pid/'mountinfo',self.base.encode())
    def tearDown(self):self.tmp.cleanup()
    def guard(self,**kwargs):return m.environment([self.copy],[],['a'*24],set(),proc=self.proc,**kwargs)
    def test_readonly_guard_success_has_no_runtime_commands(self):
        with patch.object(m,'command',side_effect=AssertionError('no runtime command')):value=self.guard()
        self.assertFalse(value['runtime_qualified']);self.assertEqual(len(value['namespaces']),1)
    def test_active_producer_or_fd_refuses(self):
        put(self.pid/'cmdline',b'python3\0/path/physical-checkpoint.py\0')
        with self.assertRaisesRegex(m.Refused,'producer_process'):self.guard()
        put(self.pid/'cmdline',b'test\0');(self.pid/'fd/3').symlink_to(self.copy/'payload')
        with self.assertRaisesRegex(m.Refused,'active_copy_reference'):self.guard()
    def test_mapped_inode_refuses_even_without_copy_path(self):
        s=(self.copy/'payload').stat();put(self.pid/'maps',f'1000-2000 r--p 00000000 {os.major(s.st_dev):02x}:{os.minor(s.st_dev):02x} {s.st_ino} /different-name\n'.encode())
        with self.assertRaisesRegex(m.Refused,'mapped_inode'):m.environment([self.copy],[],[],{(s.st_dev,s.st_ino)},proc=self.proc)
    def test_unknown_ancestor_alias_and_leaf_submount_refuse(self):
        for line,code in [(f'11 10 {self.device} {self.copy.parent} /foreign rw - ext4 /dev/test rw\n','unknown_ancestor'),
            (f'11 10 {self.device} {self.copy} /elsewhere rw - ext4 /dev/test rw\n','filesystem_submount'),
            (f'11 10 0:2 / {self.copy}/nested rw - tmpfs tmpfs rw\n','descendant_mount')]:
            with self.subTest(code=code):
                put(self.pid/'mountinfo',(self.base+line).encode())
                with self.assertRaisesRegex(m.Refused,code):self.guard()
    def test_unknown_held_namespace_refuses(self):
        (self.pid/'fd/4').symlink_to('mnt:[999]')
        with self.assertRaisesRegex(m.Refused,'unknown_held'):self.guard()
    def test_ambient_context_fails_before_docker_commands(self):
        with patch.dict(os.environ,{'DOCKER_CONTEXT':'foreign'}),patch.object(m,'command',side_effect=AssertionError('command')):
            with self.assertRaisesRegex(m.Refused,'ambient_docker'):self.guard(runtime=True)
    def test_unqualified_hostfs_process_refuses(self):
        line=f'11 10 {self.device} / /var/lib/snapd/hostfs rw - ext4 /dev/test rw\n'
        put(self.pid/'mountinfo',(self.base+line).encode())
        put(self.pid/'stat',b'101 (test) S '+b'0 '*21);put(self.pid/'status',b'Uid:\t0\t0\t0\t0\n');put(self.pid/'cgroup',b'0::/foreign\n')
        with self.assertRaisesRegex(m.Refused,'hostfs_process_identity'):self.guard()


if __name__=='__main__':unittest.main()
