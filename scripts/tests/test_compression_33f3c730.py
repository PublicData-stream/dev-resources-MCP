"""Bounded SSE policy/source adoption using first-party synthetic /tmp fixtures."""
import base64
import copy
import contextlib
import datetime as dt
import importlib.util
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
def imported(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

h = imported('compression33_fixture', ROOT / 'deploy/production/compression_33f3c730.py')
f = imported('original33_fixture_helpers', ROOT / 'scripts/tests/test_upgrade_33f3c730.py')
u = f.u


def adopted(before, candidates):
    value = copy.deepcopy(before)
    value['edge'].update(pid=2000000, pid_start_ticks='12899999', started='2026-11-14T12:30:00Z')
    for name, body in candidates.items():
        value['conf_contents'][name] = base64.b64encode(body).decode()
        value['conf_tree'][name].update(size=len(body), sha256=h.sha(body), mtime_ns=1800000000000000000)
    return value


class PureTests(unittest.TestCase):
    def setUp(self):
        self.historical, self.before, _, _ = f.edge_fixture()
        self.hashes = {name: h.sha(base64.b64decode(self.before['conf_contents'][name])) for name in h.FILES}
        p = patch.object(h, 'OLD_HASHES', self.hashes)
        p.start(); self.addCleanup(p.stop)
        self.candidates = h.policy_delta(*(base64.b64decode(self.before['conf_contents'][n]) for n in h.FILES))
        self.after = adopted(self.before, self.candidates)

    def test_named_policy_changes_only_mcp_selection_and_explicit_sse_exception(self):
        before = u.tomllib.loads(base64.b64decode(self.before['conf_contents'][h.FILES[0]]).decode())
        after = u.tomllib.loads(self.candidates[h.FILES[0]].decode())
        named = after['compression'].pop('policies')
        self.assertEqual(after, before)
        self.assertEqual(len(named), 1)
        self.assertEqual(named[0]['name'], 'devres-mcp-sse')
        self.assertTrue(named[0]['allow_no_store_sse'])
        self.assertFalse(named[0]['allow_authenticated_sse'])
        self.assertEqual(named[0]['mime_types'], ['text/event-stream'])
        self.assertTrue(all(named[0][n] for n in ('gzip', 'br', 'zstd')))
        self.assertFalse(named[0]['deflate'])
        self.assertEqual(named[0]['level'], before['compression']['level'])
        route = u.tomllib.loads(self.candidates[h.FILES[1]].decode())
        self.assertEqual(route['routes'][0]['compression'], h.POLICY)
        old = base64.b64decode(self.before['conf_contents'][h.FILES[0]])
        self.assertTrue(self.candidates[h.FILES[0]].startswith(old))

    def test_full_native_delta_rejects_unlisted_security_network_tls_or_other_file_changes(self):
        self.assertEqual(h.checked_delta(self.before, self.after, self.candidates), self.before)
        changes = [lambda v: v['docker']['host_config'].__setitem__('Privileged', True),
                   lambda v: v['docker']['mounts'][0].__setitem__('RW', True),
                   lambda v: v['docker']['config']['Env'].append('PRIVATE=unexpected'),
                   lambda v: v['docker']['networks']['devres-net'].__setitem__('IPAddress', 'other'),
                   lambda v: v['networks']['pdf2md-net'].__setitem__('Id', '0'*64),
                   lambda v: v['conf_tree']['10-tls.toml'].__setitem__('sha256', '1'*64),
                   lambda v: v['conf_tree'].__setitem__('unlisted.toml', {})]
        for change in changes:
            value = copy.deepcopy(self.after); change(value)
            with self.subTest(change=change), self.assertRaises(h.Error):
                h.checked_delta(self.before, value, self.candidates)

    def test_only_restart_owned_mac_and_endpoint_can_change(self):
        value = copy.deepcopy(self.after)
        for name in ('devres-net', 'pdf2md-net'):
            value['docker']['networks'][name]['MacAddress'] = '02:00:00:00:00:aa'
            value['networks'][name]['edge_member'].update(MacAddress='02:00:00:00:00:aa', EndpointID='a'*64)
        h.checked_delta(self.before, value, self.candidates)
        value['networks']['pdf2md-net']['edge_member']['IPv4Address'] = '0.0.0.0/0'
        with self.assertRaises(h.Error):
            h.checked_delta(self.before, value, self.candidates)

    def test_staged_mount_is_readable_by_numeric_dropped_uid_under_private_umask(self):
        with tempfile.TemporaryDirectory(prefix='sse-stage-umask-',dir='/tmp') as name:
            root=Path(name);journal=root/'journal';journal.mkdir(mode=0o700)
            source=root/'source';source.mkdir(mode=0o755);(source/'public').mkdir(mode=0o755)
            before={'conf_tree':{'.':{'kind':'directory'},'public':{'kind':'directory'}}}
            bodies={**{n:base64.b64decode(self.before['conf_contents'][n]) for n in h.FILES},'public/asset.toml':b'public_asset=true\n'}
            for relative,body in bodies.items():
                path=source/relative;path.write_bytes(body);path.chmod(0o644)
                before['conf_tree'][relative]={'kind':'file','uid':os.geteuid(),'size':len(body),'sha256':h.sha(body)}
            original_umask=os.umask(0o077)
            try:
                with patch.object(h,'JOURNAL',journal):
                    stage=h.stage_tree(SimpleNamespace(EDGE_CONF=source),before,self.candidates)
                h.verify_stage(stage,before,self.candidates)
            finally:os.umask(original_umask)
            # The container sees only this bind-mounted root, not private host ancestors.
            self.assertEqual(stage.stat().st_mode&0o777,0o755)
            self.assertEqual((stage/'public').stat().st_mode&0o777,0o755)
            for relative in bodies:self.assertEqual((stage/relative).stat().st_mode&0o777,0o644)
            (stage/'public').chmod(0o700)
            with self.assertRaisesRegex(h.Error,'staged_directory_required'):
                h.verify_stage(stage,before,self.candidates)

    def test_same_process_extra_restart_or_outside_intent_is_rejected(self):
        for field, item in (('pid', self.before['edge']['pid']), ('restarts', 1)):
            changed = copy.deepcopy(self.after); changed['edge'][field] = item
            with self.assertRaisesRegex(h.Error, 'one_owned_edge_restart'):
                h.checked_delta(self.before, changed, self.candidates)
        with self.assertRaisesRegex(h.Error, 'edge_restart_outside_intent'):
            h.checked_delta(self.before, self.after, self.candidates, '2026-11-14T13:00:00Z', '2026-11-14T13:01:00Z')


class SuccessorFixture(f.Fixture):
    def setUp(self):
        super().setUp()
        # Real original Controller.__init__, attach/verify, guard, phase dispatcher
        # and fake cluster mutation paths run below. Only native host observations
        # and immutable historical dependencies are replaced by fixture data.
        self.historical, self.before, self.old_compose, self.compose = f.edge_fixture()
        self.journal = self.root / 'compression-sse-transition'; self.journal.mkdir(mode=0o700)
        self.frozen_file = self.top / 'frozen.py'; f.private(self.frozen_file, Path(u.__file__).read_bytes())
        self.wrapper_file = self.top / 'canonical.py'; f.private(self.wrapper_file, b'fixture reviewed wrapper bytes')
        self.implementation_file = self.top / 'implementation.py'; f.private(self.implementation_file, Path(h.__file__).read_bytes())
        self.compose_file = self.top / 'compose'; f.private(self.compose_file, self.compose)
        for mapping in (self.historical, self.before):
            mapping['files'][str(self.compose_file)] = mapping['files'].pop(u.EDGE_COMPOSE)
        self.hashes = {n: h.sha(base64.b64decode(self.before['conf_contents'][n])) for n in h.FILES}
        for name, value in (('BUNDLE', self.root), ('WORK', self.top), ('JOURNAL', self.journal),
                            ('ADMISSION', self.journal/'admission.json'), ('FROZEN', self.frozen_file),
                            ('CANONICAL', self.wrapper_file), ('IMPLEMENTATION', self.implementation_file), ('OLD_HASHES', self.hashes)):
            p=patch.object(h, name, value);p.start();self.addCleanup(p.stop)
        rules=copy.deepcopy(u.CONF_FILE_RULES)
        for name, rule in rules.items():
            rule['old_sha']=self.historical['conf_tree'][name]['sha256'];rule['new_sha']=self.before['conf_tree'][name]['sha256']
        for name, value in (('BUNDLE', str(self.root)), ('WORK', str(self.top)), ('PRIOR_BUNDLE', str(self.prior)),
                            ('EDGE_COMPOSE', str(self.compose_file)), ('OLD_COMPOSE_SHA', h.sha(self.old_compose)), ('NEW_COMPOSE_SHA', h.sha(self.compose)), ('CONF_FILE_RULES', rules)):
            p=patch.object(u, name, value);p.start();self.addCleanup(p.stop)
        self.candidates=h.policy_delta(*(base64.b64decode(self.before['conf_contents'][n]) for n in h.FILES))
        self.after=adopted(self.before,self.candidates)
        for role,(name,key) in u.ROLES.items():
            self.cluster.deployments[role]['spec']['template']['spec']['containers'][0]['image']=u.IMAGE
            self.cluster.new_pod(role)
            text=u.load(self.root/'configs-paused.json')[role]
            self.cluster.secrets[name]['data'][key]=base64.b64encode(text.encode()).decode()
        prior_state=u.load(self.prior/'state.json')
        prior_state.update(edge=self.historical['edge'],new_conf={'63-route-wikimedia-cidrs.toml':self.historical['conf_tree']['63-route-wikimedia-cidrs.toml']})
        ap=u.load(self.prior/'prepared.json');ap.update(edge_docker=self.historical['docker'],edge_base_files=self.historical['files'],edge_conf_tree={k:v for k,v in self.historical['conf_tree'].items() if k not in prior_state['new_conf']})
        prior_state['prepared_sha256']=f.private(self.prior/'prepared.json',ap);f.private(self.prior/'state.json',prior_state)
        # Current raw observers expose the new edge. The old adapter must telescope
        # through the admitted before snapshot rather than observing fake history.
        activation=self.c.activation
        activation.base=self.c.base;self.c.base.module=self.c.module;self.c.base.old=self.cluster
        activation.edge_files=lambda:copy.deepcopy(self.after['files'])
        activation.conf_tree=lambda:copy.deepcopy(self.after['conf_tree'])
        value={'version':1,'kind':'explicit-pdf2md-compression-edge-admission','revision':u.REVISION,
               'controller_sha256':h.FROZEN_SHA,'predecessor_controller_sha256':u.PRIOR_CONTROLLER_SHA,
               'predecessor_state_sha256':u.digest(u.read(self.prior/'state.json')),'predecessor_prepared_sha256':u.digest(u.read(self.prior/'prepared.json')),
               'historical_state':copy.deepcopy(prior_state),'historical':self.historical,'actual':self.before,'boot':{'boot':'same'},'verified':True,'observed_at':u.stamp(),
               'native_check':{'verified':True,'container':u.NEW_EDGE_ID,'stdout_sha256':'b'*64}}
        old_admission=self.top/'old-edge-admission.json';ref={'path':str(old_admission),'sha256':f.private(old_admission,value)}
        # Build the actual frozen predecessor plan/prepared/state, never alter them
        # after the source admission below is created.
        plan={'version':1,'context':'default','store_binding_sha256':u.STORE_BINDING,'preserve_application_passwords':True,'target':u.target_identity(),
              'prior':self.c.prior_artifacts(),'inventory':{},'edge_admission':ref}
        f.private(self.root/'plan.json',plan)
        old_prepared=u.load(self.root/'prepared.json')
        old_prepared.update(edge=self.before['edge'],edge_conf_tree=self.before['conf_tree'],edge_admission=ref,prior_artifacts=self.c.prior_artifacts(),prior_state=copy.deepcopy(prior_state))
        old_state=u.load(self.root/'state.json')
        old_state.update(phase='runtime_ready',configs='paused',chain_phase='runtime_upgraded',plan_sha256=h.sha(u.read(self.root/'plan.json')),
                         images={r:u.PG_IMAGE if r=='postgres' else u.IMAGE for r in ('postgres','writer','backend')},pods={r:u.pod_projection(p) for r,p in self.cluster.live_pods.items()})
        old_state['prepared_sha256']=f.private(self.root/'prepared.json',old_prepared)
        f.private(self.root/'state.json',old_state)
        for name,source in (('old-state.json',self.root/'state.json'),('old-prepared.json',self.root/'prepared.json'),('old-plan.json',self.root/'plan.json'),('old-controller.py',self.frozen_file)):
            f.private(self.journal/name,u.read(source))
        actual_prior=copy.deepcopy(prior_state);actual_prior.update(upgrade_successor=str(self.root),upgrade_successor_phase='runtime_upgraded');f.private(self.prior/'state.json',actual_prior)
        for name in ('native-stage-check.json','native-live-check.json'):
            f.private(self.journal/name,{'version':1,'verified':True,'image':h.EDGE_IMAGE,'container':h.EDGE_ID,'no_network':True,'candidates':{n:h.sha(b) for n,b in self.candidates.items()}})
        self.admission={'version':1,'kind':h.KIND,'revision':h.REVISION,'old_source_sha256':h.FROZEN_SHA,'verified':True,
                        'wrapper_sha256':h.sha(u.read(self.wrapper_file)),'implementation_sha256':h.sha(u.read(self.implementation_file)),
                        'old_state_sha256':h.sha(u.read(self.journal/'old-state.json')),'prepared_sha256':old_state['prepared_sha256'],
                        'plan_sha256':old_state['plan_sha256'],'before':self.before,'after':self.after,'restart_at':'2026-11-14T12:29:59Z',
                        'observed_at':'2026-11-14T12:30:01Z','compose_sha256':h.sha(self.compose),
                        'artifacts':[{'path':str(self.journal/n),'sha256':h.sha(u.read(self.journal/n))} for n in ('native-stage-check.json','native-live-check.json')]}
        f.private(h.ADMISSION,self.admission)
        new_state=copy.deepcopy(old_state);new_state['source_sha256']=self.admission['wrapper_sha256'];new_state['compression_source_history']=h.source_history(self.admission,h.sha(u.read(h.ADMISSION)))
        f.private(self.root/'state.json',new_state)
        for name,fn in (('predecessor',lambda context:activation),):
            p=patch.object(u,name,side_effect=fn);p.start();self.addCleanup(p.stop)
        for name,fn in (('boot',lambda c:{'boot':'same'}),('profiles',lambda c:{'tls-profile':b'unchanged'}),('foundation',lambda c:[{'policy':'same'}]),('edge',lambda c:copy.deepcopy(self.after['edge']))):
            p=patch.object(u.Controller,name,fn);p.start();self.addCleanup(p.stop)
        def preimage(path,size,digest):
            body=base64.b64decode(self.historical['conf_preimages'][Path(path).name]);u.require(len(body)==size and u.digest(body)==digest,'fixture_preimage');return body
        p=patch.object(u,'public_config_read',side_effect=preimage);p.start();self.addCleanup(p.stop)
        p=patch.object(h,'native_snapshot',side_effect=lambda c,b,contents:(copy.deepcopy(self.after),self.compose));p.start();self.addCleanup(p.stop)
        self.wrapper_class=h.controller_type(u,self.wrapper_file)
        self.c=self.wrapper_class(str(self.root),str(self.root/'plan.json'),'default')
        self.c.guard()


class SuccessorTests(SuccessorFixture):
    def test_real_constructor_and_guard_preserve_old_proofs_but_observe_actual_new_edge(self):
        self.assertEqual(self.c.edge(),self.after['edge'])
        self.assertEqual(self.c.snapshot()['edge'],self.after['edge'])
        self.assertEqual(self.c.snapshot()['edge_conf_tree'],self.after['conf_tree'])
        self.assertEqual(self.c.base.edge(),self.historical['edge'])
        self.assertEqual(self.c._compat_depth,0)
        self.assertEqual(u.read(self.root/'prepared.json'),u.read(self.journal/'old-prepared.json'))
        self.assertEqual(u.read(self.root/'plan.json'),u.read(self.journal/'old-plan.json'))

    def test_compatibility_context_resets_and_checks_reality_after_exceptions(self):
        with self.assertRaisesRegex(RuntimeError,'fixture_failure'):
            with self.c._old_boundary():
                self.assertEqual(self.c.edge(),self.before['edge'])
                raise RuntimeError('fixture_failure')
        self.assertEqual(self.c._compat_depth,0)
        self.assertEqual(self.c.edge(),self.after['edge'])
        with self.assertRaisesRegex(h.Error,'admitted_sse_edge_changed'):
            with self.c._old_boundary():
                self.after['edge']['pid']+=1
        self.assertEqual(self.c._compat_depth,0)

    def test_second_restart_or_secret_pod_mount_network_and_tls_drift_are_refused(self):
        original=copy.deepcopy(self.after)
        for mutate in (lambda:self.after['edge'].__setitem__('pid',2000001),
                       lambda:self.after['docker']['mounts'][0].__setitem__('RW',True),
                       lambda:self.after['networks']['pdf2md-net'].__setitem__('Id','0'*64),
                       lambda:self.after['conf_tree']['10-tls.toml'].__setitem__('sha256','0'*64)):
            mutate()
            with self.assertRaises(h.Error):self.c.guard()
            self.after.clear();self.after.update(copy.deepcopy(original))
        self.cluster.secrets['wikipedia-private']['data']['token']='unreviewed'
        with self.assertRaisesRegex(u.Error,'secret_boundary_changed'):self.c.guard()

    def test_source_prepared_or_lineage_tampering_is_never_adopted(self):
        body=u.read(self.root/'prepared.json');f.private(self.root/'prepared.json',body+b' ')
        with self.assertRaisesRegex(h.Error,'original_prepared_or_plan'):self.c.state()
        f.private(self.root/'prepared.json',body)
        state=self.c.state();state['compression_source_history']['old_source_sha256']='wrong';f.private(self.root/'state.json',state)
        with self.assertRaisesRegex(h.Error,'successor_journal_identity'):self.c.state()

    def test_original_activation_and_finish_still_require_real_codec_receipt_flag(self):
        keys=('schema18','policy2','sole_writer','private_boundary','public_http_both_families_revisions','public_wt_both_families_revisions','capture_notice_preserved')
        bad=self.envelope('target-activation-acceptance',keys)
        with self.assertRaisesRegex(u.Error,'receipt_checks'):self.run_op('activate-existing',bad)
        good=self.envelope('target-activation-acceptance',(*keys,'public_compression_gzip_br_zstd'))
        self.run_op('activate-existing',good)
        self.assertEqual(self.c.state()['phase'],'collectors_active')
        self.assertEqual(self.c.edge(),self.after['edge'])
        finish=('schema18','policy2','sole_writer','read_only_serving','private_boundary','public_http_both_families_revisions','public_wt_both_families_revisions','nine_source_settings_preserved','capture_notice_preserved','timers_preserved','stable_processes')
        bad=self.envelope('target-observation-acceptance',finish,duration_seconds=630,sample_count=22,maximum_gap_seconds=30)
        with self.assertRaisesRegex(u.Error,'receipt_checks'):self.run_op('finish',bad)
        good=self.envelope('target-observation-acceptance',(*finish,'public_compression_gzip_br_zstd'),duration_seconds=630,sample_count=22,maximum_gap_seconds=30)
        self.run_op('finish',good)
        self.assertEqual(self.c.state()['phase'],'complete')
        self.assertEqual(self.c.state()['compression_source_history']['old_source_sha256'],h.FROZEN_SHA)

    def test_new_unique_failure_fence_preserves_postgres_and_does_not_replay_withdraw(self):
        h.fence_applications(self.c,u)
        self.assertEqual(self.cluster.deployments['postgres']['spec']['replicas'],1)
        self.assertEqual(self.c.state()['phase'],'compression_transition_fenced')
        self.assertEqual(set(self.c.state()['pods']),{'postgres'})
        self.assertTrue((self.journal/'fence-backend-intent.json').exists())
        self.assertFalse((self.root/'withdraw-backend-intent.json').exists())
        with self.assertRaises(FileExistsError):h.fence_applications(self.c,u)

    def test_thin_canonical_wrapper_import_does_not_overwrite_bound_module_with_exported_function(self):
        import importlib.util
        factory=Mock(return_value=type('BoundController',(),{}))
        original=SimpleNamespace(Controller=object,predecessor=lambda context:None,REVISION=h.REVISION)
        implementation=SimpleNamespace(frozen=lambda:original,controller_type=factory)
        code=(ROOT/'deploy/production/compression_controller_33f3c730.py').read_text()
        code=code.replace('/usr/local/libexec/devres-upgrade-33f3c730/compression_33f3c730.py',str(self.implementation_file))
        namespace={'__file__':str(self.wrapper_file),'__name__':'synthetic_canonical_wrapper'}
        with patch.object(importlib.util,'spec_from_file_location',return_value=SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))),patch.object(importlib.util,'module_from_spec',return_value=implementation):
            exec(compile(code,str(self.wrapper_file),'exec'),namespace)
        factory.assert_called_once_with(original,self.wrapper_file)
        self.assertEqual(namespace['REVISION'],h.REVISION)
        self.assertIs(namespace['Controller'],factory.return_value)

    def test_original_private_runtime_gate_and_new_source_binding_remain_required(self):
        state=self.c.state();state['phase']='reader_ready';f.private(self.root/'state.json',state)
        keys=('schema18','policy2','sole_writer','read_only_serving','private_boundary','capture_notice_preserved','tool_contract98')
        self.run_op('runtime-ready',self.envelope('target-private-acceptance',keys))
        self.assertEqual(self.c.state()['phase'],'runtime_ready')
        f.private(self.wrapper_file,b'unreviewed source')
        with self.assertRaisesRegex(h.Error,'successor_source_changed'):
            self.wrapper_class(str(self.root),str(self.root/'plan.json'),'default')

    def test_native_checker_sees_staged_policy_before_any_live_mutation(self):
        stage=self.top/'stage';stage.mkdir(mode=0o755)
        before={'conf_tree':{'.':{'kind':'directory'}}}
        for name,body in self.candidates.items():
            (stage/name).write_bytes(body);(stage/name).chmod(0o644)
            before['conf_tree'][name]={'kind':'file','sha256':h.sha(base64.b64decode(self.before['conf_contents'][name]))}
        before['docker']={'config':{'User':'65532'},'mounts':[{'Type':'bind','Source':'/fixture/conf','Destination':'/etc/oxibelt/conf.d','RW':False}]}
        controller=SimpleNamespace(module=SimpleNamespace(call=Mock(return_value=b'valid native proposed config')))
        base=SimpleNamespace(EDGE_CONF=Path('/fixture/conf'))
        stage_journal=self.top/'native-check-journal';stage_journal.mkdir(mode=0o700)
        with patch.object(h,'JOURNAL',stage_journal):
            h.stage_check(controller,base,before,stage,self.candidates)
            with self.assertRaises(FileExistsError):h.stage_check(controller,base,before,stage,self.candidates)
        args=controller.module.call.call_args.args[0]
        self.assertIn('--read-only',args);self.assertEqual(args[args.index('--network')+1],'none')
        self.assertTrue(any('src='+str(stage)+',dst=' in v for v in args))
        self.assertEqual(args[-1],'--check')
        self.assertFalse((self.journal/'install-40-compression.toml-intent.json').exists())

    def test_unknown_restart_is_fenced_without_source_adoption_or_repeat(self):
        # Execute the actual apply control flow with synthetic native effects.
        f.private(self.wrapper_file,Path(u.__file__).read_bytes())
        f.private(self.root/'state.json',u.read(self.journal/'old-state.json'))
        wrapper=self.top/'new-wrapper';f.private(wrapper,b'new reviewed wrapper')
        approved=self.top/'scope';f.private(approved,b'approved exact synthetic operation')
        f.private(self.journal/'old-control-snapshot.json',{})
        for name,body in self.candidates.items():f.private(self.journal/(name+'.candidate'),body)
        prepared={'wrapper_sha256':h.sha(u.read(wrapper)),'implementation_sha256':h.sha(u.read(self.implementation_file)),
                  'approval_sha256':h.sha(u.read(approved)),'old_state_sha256':h.sha(u.read(self.root/'state.json')),
                  'prepared_at':h.now().isoformat(),'candidates':{n:h.sha(b) for n,b in self.candidates.items()},'before':self.before}
        f.private(self.journal/'prepared.json',prepared)
        controller=SimpleNamespace(locked=lambda:contextlib.nullcontext(),guard=Mock(),snapshot=lambda:{},
            module=SimpleNamespace(call=Mock(side_effect=RuntimeError('restart outcome unknown'))))
        args=SimpleNamespace(wrapper_candidate=wrapper,wrapper_sha=prepared['wrapper_sha256'],approval=approved,approval_sha=prepared['approval_sha256'])
        with patch.object(h,'install_public') as install,patch.object(h,'fence_applications') as fence:
            with self.assertRaisesRegex(RuntimeError,'restart outcome unknown'):
                h.apply(SimpleNamespace(Controller=lambda *a:controller,EDGE_CONF=Path('/fixture/conf')),args)
            self.assertEqual(install.call_count,2);fence.assert_called_once()
        self.assertTrue((self.journal/'restart-intent.json').exists())
        self.assertTrue((self.journal/'failed-fenced.json').exists())
        self.assertFalse((self.journal/'handoff-intent.json').exists())
        self.assertEqual(h.sha(u.read(self.wrapper_file)),h.FROZEN_SHA)
        with self.assertRaisesRegex(h.Error,'one_compression_transition_only'):h.apply(u,args)

    def test_duplicate_apply_or_stale_preparation_never_restarts(self):
        f.private(self.journal/'apply-intent.json',{'attempted':True})
        with self.assertRaisesRegex(h.Error,'one_compression_transition_only'):h.apply(u,SimpleNamespace())
        (self.journal/'apply-intent.json').unlink()
        f.private(self.wrapper_file,Path(u.__file__).read_bytes())
        candidate=self.top/'candidate';f.private(candidate,b'reviewed wrapper')
        approved=self.top/'approval';f.private(approved,b'fixed approval')
        p={'wrapper_sha256':h.sha(u.read(candidate)),'implementation_sha256':h.sha(u.read(self.implementation_file)),
           'approval_sha256':h.sha(u.read(approved)),'prepared_at':(h.now()-dt.timedelta(seconds=301)).isoformat()}
        f.private(self.journal/'prepared.json',p)
        args=SimpleNamespace(wrapper_candidate=candidate,wrapper_sha=p['wrapper_sha256'],approval=approved,approval_sha=p['approval_sha256'])
        with self.assertRaisesRegex(h.Error,'compression_preparation_stale'):h.apply(u,args)


if __name__=='__main__':unittest.main()
