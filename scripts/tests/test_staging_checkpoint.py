import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

import test_staging_upgrade as helpers

upgrade = helpers.upgrade
cp = upgrade.checkpoint


class Drill:
    def __init__(self, snapshot, **kwargs):
        self.snapshot = snapshot
        self.token = kwargs['token']
        self.name = 'devres-staging-restore-' + self.token
        self.dataset = 'cachepool/' + self.name
        self.root = Path('/tmp') / self.name
        self.resource_profile = kwargs.get('resource_profile', 'upgrade')
        self.postgres_started = False
        self.backend_started = False
        self.offline_sequence = 1
        self.runtime_owned = True
        self.events = []
        self.active = 'f'

    def start_postgres(self):
        self.events.append('start_postgres')
        self.postgres_started = True

    def psql(self, query):
        return self.active

    def offline(self, command, **kwargs):
        self.events.append(command)
        if command == 'activate-storage':
            self.active = 't'

    def check(self, **kwargs):
        self.events.append('readback')
        return {'schema': 10}

    def cleanup(self):
        self.events.append('cleanup')


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.helper = helpers.UpgradeTests()
        self.helper.setUp()
        self.addCleanup(self.helper.doCleanups)
        self.u = self.helper.instance
        (self.u.private / 'backend.toml').chmod(0o600)
        self.u.drill = Drill
        self.original_run = self.u.run
        self.calls = []
        self.u.run = self.fake_run
        self.lifecycle = cp.Lifecycle(self.u)
        self.token = secrets.token_hex(12)
        self.live = secrets.token_hex(12)
        self.drill = Drill(helpers.SNAPSHOT, token=self.live)
        self.runtime = self.drill.root
        self.runtime.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(self.runtime, ignore_errors=True))
        for name in ('config', 'tls', 'postgres', 'evidence'):
            (self.runtime / name).mkdir(mode=0o700)
        upgrade.op.write(self.runtime / 'owner', self.live)
        upgrade.op.write(self.u.root / 'original-config.toml', helpers.CONFIG)
        upgrade.op.write(self.runtime / 'config/backend.toml', upgrade.target_config(helpers.CONFIG, paused=True), mode=0o640)
        for name in ('backend.pem', 'backend-key.pem', 'client-ca.pem'):
            upgrade.op.write(self.runtime / 'tls' / name, 'inert-test-certificate', mode=0o640)
            upgrade.op.write(self.u.private / name, 'inert-test-certificate')
        self.record = {'version': 1, 'fence': None, 'operation': None, 'verified': [],
                       'token': self.token, 'live_token': self.live, 'live_kind': 'restore',
                       'phase': 'rehearsal_running', 'offline_command': 'migrate-storage',
                       'snapshot': helpers.SNAPSHOT, 'pause_scope': 'rehearsal',
                       'resource_profile': 'upgrade', 'target_identity': self.u.identity(),
                       'timers': {'devres-staging-backup.timer': 'active'}}
        self.u.record = self.record
        self.u.save()
        self.guids = {self.drill.dataset + suffix: str(index + 10)
                      for index, suffix in enumerate(('', '/postgres', '/evidence'))}
        self.network = {'Internal': True, 'Labels': {upgrade.restore.LABEL_KEY: self.live},
                        'Containers': {}, 'EnableIPv6': False}
        self.containers = {}
        self.bad_hold = False
        self.bad_tree = False
        self.chown = patch.object(cp.os, 'chown')
        self.chown.start()
        self.addCleanup(self.chown.stop)

    def fake_run(self, args, **kwargs):
        args = [str(v) for v in args]
        self.calls.append(args)
        if args[:2] == ['zfs', 'get']:
            value, name = args[-2:]
            if value == 'guid':
                return self.guids.get(name.split('@')[0], '99') + ('0' if '@' in name else '')
            if value == upgrade.restore.OWNER_KEY:
                return self.live
            if value == 'mountpoint':
                return str(self.runtime / name.rsplit('/', 1)[1])
        if args[:2] == ['zfs', 'holds']:
            return '' if self.bad_hold else args[-1] + '\t' + self.u.hold + '\tdate\n' + args[-1] + '\tdevres-rehearsal-paused\tdate'
        if args[:2] == ['zfs', 'list'] and '-r' in args:
            root = self.drill.dataset
            rows = [[root, self.guids[root], '-', 'none', 'off', str(512 * 1024**3), self.live]]
            for child in ('postgres', 'evidence'):
                name = root + '/' + child
                rows.append([name, self.guids[name], upgrade.m.DATASET + '/' + child + '@' + helpers.SNAPSHOT,
                             str(self.runtime / child), 'on', '0', self.live])
            if self.bad_tree:
                rows.append([root + '/unknown', '99', '-', '/tmp/unknown', 'on', '0', self.live])
            return '\n'.join('\t'.join(row) for row in rows)
        if args[:3] == ['docker', 'network', 'inspect']:
            return json.dumps([self.network])
        if args[:2] == ['docker', 'ps']:
            return '\n'.join(self.containers)
        if args[:2] == ['docker', 'inspect']:
            if args[-1] in self.containers:
                return json.dumps([self.containers[args[-1]]])
            return json.dumps([next(value for value in self.containers.values() if value['Id'] == args[-1])])
        if args[:2] == ['docker', 'rm']:
            for name, value in list(self.containers.items()):
                if value['Id'] == args[-1]:
                    del self.containers[name]
            return ''
        if args[:2] == ['systemctl', 'show']:
            return 'inactive' if args[-1].endswith('.service') else 'active'
        return self.original_run(args, **kwargs)

    def pause_pair(self, command='migrate-storage'):
        self.u.save(offline_command=command)
        self.lifecycle.checkpoint(self.drill, command)
        self.record = upgrade.read_record(self.u.root.parent)
        return self.lifecycle.validate_paused(self.record)

    def test_checkpoint_round_trip_preserves_pair_and_immutable_generation(self):
        receipt = self.pause_pair()
        self.assertFalse(receipt['timing_qualified'])
        first = Path(self.record['pause_receipt'])
        self.assertTrue(first.exists())
        self.lifecycle.checkpoint(self.drill, 'migrate-storage')
        second = Path(self.u.record['pause_receipt'])
        self.assertNotEqual(first, second)
        self.assertTrue(first.exists())
        self.assertFalse(any(call[:2] == ['zfs', 'destroy'] for call in self.calls))
        self.assertFalse(any(call[:2] == ['systemctl', 'start'] for call in self.calls))

    def test_resume_reuses_pair_and_never_qualifies_partial_timing(self):
        self.pause_pair()
        with patch.object(self.lifecycle, 'attach', return_value=self.drill):
            result = self.lifecycle.resume(self.token)
        self.assertTrue(result['rehearsed'])
        self.assertFalse(result['timing_qualified'])
        self.assertEqual(self.drill.events[:4], ['start_postgres', *cp.COMMANDS])
        self.assertNotIn('cleanup', self.drill.events)
        current = upgrade.read_record(self.u.root.parent)
        self.assertEqual(current['phase'], 'rehearsed_unqualified')
        self.assertIn(['systemctl', 'start', 'devres-staging-backup.timer'], self.calls)
        with self.assertRaisesRegex(upgrade.UpgradeError, 'successful_rehearsal_required'):
            self.u.apply()

    def test_active_activation_resume_verifies_without_replaying_migration(self):
        self.pause_pair('activate-storage')
        self.drill.active = 't'
        with patch.object(self.lifecycle, 'attach', return_value=self.drill):
            self.lifecycle.resume(self.token)
        self.assertEqual(self.drill.events[:2], ['start_postgres', 'verify-storage'])
        self.assertNotIn('activate-storage', self.drill.events)

    def test_inactive_activation_resume_requires_fresh_verification(self):
        self.pause_pair('activate-storage')
        with patch.object(self.lifecycle, 'attach', return_value=self.drill):
            self.lifecycle.resume(self.token)
        self.assertEqual(self.drill.events[:3], ['start_postgres', 'verify-storage', 'activate-storage'])

    def test_corrupt_capsule_and_profile_refuse_before_mutation(self):
        self.pause_pair()
        path = Path(self.record['pause_receipt'])
        valid = path.read_text()
        for key, value in (('resource_profile', 'direct'), ('command', 'activate-storage'), ('capsule', '/tmp/unrelated')):
            damaged = json.loads(valid)
            damaged[key] = value
            upgrade.op.write(path, json.dumps(damaged))
            before = len(self.calls)
            with self.assertRaises(cp.CheckpointError):
                self.lifecycle.validate_paused(self.record)
            self.assertEqual(before, len(self.calls))
        upgrade.op.write(path, valid)
        upgrade.op.write(path.parent / 'config/backend.toml', 'changed')
        with self.assertRaisesRegex(cp.CheckpointError, 'integrity_changed'):
            self.lifecycle.validate_paused(self.record)

    def test_changed_hold_tree_or_network_refuse(self):
        self.pause_pair()
        for attribute in ('bad_hold', 'bad_tree'):
            setattr(self, attribute, True)
            with self.assertRaises(cp.CheckpointError):
                self.lifecycle.validate_paused(self.record)
            setattr(self, attribute, False)
        self.network['Containers'] = {'unknown': {}}
        with self.assertRaisesRegex(cp.CheckpointError, 'network_endpoints'):
            self.lifecycle.validate_paused(self.record)

    def test_missing_tmp_owner_recreated_from_verified_capsule(self):
        self.pause_pair()
        (self.runtime / 'owner').unlink()
        for folder in ('config', 'tls'):
            shutil.rmtree(self.runtime / folder)
        receipt = self.lifecycle.validate_paused(self.record)
        attached = self.lifecycle.attach(self.record, receipt)
        self.assertEqual(attached.token, self.live)
        self.assertEqual((self.runtime / 'owner').read_text(), self.live)
        self.assertTrue((self.runtime / 'config/backend.toml').is_file())

    def test_pause_requires_explicit_permanent_scope_and_offline_phase(self):
        for phase in ('pre_upgrade_restore', 'awaiting_acceptance', 'rolling_back', 'starting_candidate'):
            with self.assertRaisesRegex(cp.CheckpointError, 'offline_checkpoint_phase'):
                self.lifecycle.eligible({**self.record, 'phase': phase})
        with self.assertRaisesRegex(cp.CheckpointError, 'not_enabled'):
            self.lifecycle.eligible({**self.record, 'live_kind': 'permanent'})
        self.lifecycle.eligible({**self.record, 'live_kind': 'permanent', 'pause_scope': 'all',
                                 'phase': 'running_migrate_storage'})

    def test_pause_request_ack_and_status_do_not_expose_owner(self):
        def acknowledge(_):
            self.lifecycle.checkpoint(self.drill, 'migrate-storage')
        self.assertTrue(self.lifecycle.pause(self.token, sleep=acknowledge)['paused'])
        encoded = json.dumps(self.lifecycle.status(self.token))
        self.assertNotIn(self.token, encoded)
        self.assertNotIn(self.live, encoded)

    def test_checkpoint_failure_preserves_without_forced_cleanup(self):
        def interrupted(*args, **kwargs):
            raise upgrade.restore.OfflinePaused('migrate-storage', False)
        self.drill.offline = interrupted
        with patch.object(self.lifecycle, 'write_capsule', side_effect=OSError('synthetic fsync failure')):
            with self.assertRaises(OSError):
                self.lifecycle.offline(self.drill, 'migrate-storage')
        self.assertEqual(upgrade.read_record(self.u.root.parent)['phase'], 'rehearsal_preserved_failed')
        self.assertNotIn('cleanup', self.drill.events)
        self.assertFalse(any(call[:2] == ['systemctl', 'start'] for call in self.calls))

    def postgres_container(self, owner=None):
        return {'Id': 'c' * 64,
                'Config': {'Image': upgrade.restore.PG,
                           'Labels': {upgrade.restore.LABEL_KEY: owner or self.live}},
                'HostConfig': {'PortBindings': {}, 'RestartPolicy': {'Name': 'no'}},
                'State': {'Running': False},
                'NetworkSettings': {'Networks': {self.drill.name: {}}, 'Ports': {}},
                'Mounts': [{'Type': 'bind', 'Destination': '/var/lib/postgresql',
                            'Source': str(self.runtime / 'postgres'), 'RW': True}]}

    def test_postgres_identity_refusal_never_falls_back_to_name_cleanup(self):
        self.drill.postgres_started = True
        name = self.drill.name + '-postgres'
        self.containers[name] = self.postgres_container(owner='f' * 24)
        def interrupted(command, **kwargs):
            raise upgrade.restore.OfflinePaused(command, False)
        self.drill.offline = interrupted
        with self.assertRaisesRegex(cp.CheckpointError, 'postgres_identity_changed'):
            self.lifecycle.offline(self.drill, 'migrate-storage')
        self.assertFalse(any(call[:2] == ['docker', 'stop'] for call in self.calls))
        self.assertFalse(any(call[:2] == ['zfs', 'snapshot'] for call in self.calls))
        self.assertEqual(upgrade.read_record(self.u.root.parent)['phase'], 'rehearsal_preserved_failed')

    def test_checkpoint_stops_postgres_by_verified_immutable_id(self):
        self.drill.postgres_started = True
        name = self.drill.name + '-postgres'
        info = self.postgres_container()
        self.containers[name] = info
        self.lifecycle.checkpoint(self.drill, 'migrate-storage')
        stops = [call for call in self.calls if call[:2] == ['docker', 'stop']]
        self.assertEqual(stops, [['docker', 'stop', '--time=120', info['Id']]])

    def test_late_success_pause_wrong_pg_owner_latches_before_outer_cleanup(self):
        self.drill.postgres_started = True
        self.containers[self.drill.name + '-postgres'] = self.postgres_container(owner='f' * 24)
        def completed(command, **kwargs):
            upgrade.op.write(self.u.root / 'pause-request.json', json.dumps({
                'version': 1, 'token': self.token, 'live_token': self.live, 'command': command}))
        self.drill.offline = completed
        with self.assertRaisesRegex(cp.CheckpointError, 'postgres_identity_changed'):
            self.lifecycle.offline(self.drill, 'activate-storage')
        self.assertEqual(self.u.record['phase'], 'rehearsal_preserved_failed')
        self.assertFalse(any(call[:2] in (['docker', 'stop'], ['zfs', 'snapshot']) for call in self.calls))

    def test_late_success_request_is_acknowledged_before_next_phase(self):
        def completed(command, **kwargs):
            upgrade.op.write(self.u.root / 'pause-request.json', json.dumps({
                'version': 1, 'token': self.token, 'live_token': self.live, 'command': command}))
        self.drill.offline = completed
        with self.assertRaises(cp.Paused):
            self.lifecycle.offline(self.drill, 'activate-storage')
        record = upgrade.read_record(self.u.root.parent)
        self.assertEqual(record['phase'], 'rehearsal_paused')
        self.assertTrue(cp.read_json(Path(record['pause_receipt']))['command_completed'])

    def test_finished_command_closes_pause_eligibility(self):
        self.lifecycle.offline(self.drill, 'activate-storage')
        with self.assertRaisesRegex(cp.CheckpointError, 'offline_checkpoint_phase_required'):
            self.lifecycle.pause(self.token, wait_seconds=0)

    def test_expired_permanent_resume_rolls_back_without_restarting_worker(self):
        self.u.save('upgrade_paused', live_kind='permanent', checkpoint_kind='permanent',
                    pause_scope='all', deadline_at=time.time() - 1)
        with patch.object(self.u, '_rollback', return_value={'rolled_back': True}) as rollback, \
                patch.object(self.lifecycle, 'attach') as attach:
            self.assertTrue(self.lifecycle.resume(self.token)['rolled_back'])
        rollback.assert_called_once()
        attach.assert_not_called()

    def test_ordinary_paused_expiry_is_recovered_after_reboot(self):
        self.u.save('upgrade_paused', live_kind='permanent', checkpoint_kind='permanent',
                    pause_scope='all', deadline_at=time.time() - 1,
                    dataset_guids={'postgres': '1', 'evidence': '2'})
        with patch.object(self.u, '_rollback', return_value={'rolled_back': True}) as rollback:
            self.assertTrue(self.u.expire(self.token)['expired'])
        rollback.assert_called_once()

    def test_changed_boot_identity_never_signals_reused_pid(self):
        with patch.object(upgrade.checkpoint, 'boot_id', return_value='new-boot'), \
                patch.object(upgrade.os, 'pidfd_open') as pidfd:
            upgrade.terminate_driver({'driver_boot_id': 'old-boot', 'driver_pid': 500, 'driver_start': '123'})
        pidfd.assert_not_called()

    def test_wall_deadline_never_resets_with_new_monotonic_origin(self):
        self.u.save(deadline_at=time.time() + 10, deadline_seconds=1000)
        self.u.started = -1000000
        self.u.clock = lambda: -1000000
        self.assertLessEqual(self.u.remaining(), 10)
        with patch.object(upgrade.time, 'time', return_value=self.u.record['deadline_at'] + 1):
            with self.assertRaisesRegex(upgrade.UpgradeError, 'deadline_exceeded'):
                self.u.remaining()

    def test_read_helpers_reject_symlink_parent_and_group_writes(self):
        directory = self.helper.root / 'unsafe'
        directory.mkdir()
        file = directory / 'data'
        file.write_text('inert')
        file.chmod(0o620)
        with self.assertRaisesRegex(cp.CheckpointError, 'unsafe_checkpoint_file'):
            cp.read_bytes(file, private=False)
        file.chmod(0o600)
        link = self.helper.root / 'link'
        link.symlink_to(directory, target_is_directory=True)
        with self.assertRaisesRegex(cp.CheckpointError, 'unsafe_checkpoint_parent'):
            cp.read_bytes(link / 'data')

    def test_resuming_status_is_visible_before_first_runtime_mutation(self):
        self.pause_pair()
        def attach(record, receipt):
            status = self.lifecycle.status(self.token)
            self.assertEqual(status['phase'], 'checkpoint_resuming')
            self.assertFalse(status['paused'])
            with self.assertRaisesRegex(cp.CheckpointError, 'offline_checkpoint_phase'):
                self.lifecycle.pause(self.token, wait_seconds=0)
            raise OSError('synthetic attach failure')
        with patch.object(self.lifecycle, 'attach', side_effect=attach):
            with self.assertRaises(OSError):
                self.lifecycle.resume(self.token)
        self.assertEqual(upgrade.read_record(self.u.root.parent)['phase'], 'rehearsal_preserved_failed')

    def test_explicit_failed_resume_qualifies_new_checkpoint_before_replay(self):
        self.pause_pair()
        self.u.save('rehearsal_preserved_failed', live_dataset_guids=self.guids)
        old = self.u.record['pause_checkpoint']
        def attach(record, receipt):
            self.assertNotEqual(record['pause_checkpoint'], old)
            self.assertEqual(cp.read_json(Path(record['pause_receipt']))['dataset_guids'], self.guids)
            return self.drill
        with patch.object(self.lifecycle, 'attach', side_effect=attach):
            result = self.lifecycle.resume(self.token)
        self.assertTrue(result['rehearsed'])
        self.assertFalse(any(call[:2] == ['zfs', 'destroy'] for call in self.calls))

    def test_failed_resume_refuses_unknown_guid_or_unclean_pair(self):
        self.pause_pair()
        self.u.save('rehearsal_preserved_failed', live_dataset_guids={**self.guids, self.drill.dataset: '999'})
        with patch.object(self.drill, 'start_postgres') as start:
            with self.assertRaisesRegex(cp.CheckpointError, 'dataset_identity_changed'):
                self.lifecycle.resume(self.token)
        start.assert_not_called()
        self.u.save(live_dataset_guids=self.guids)
        with patch.object(self.lifecycle, 'clean_postgres', side_effect=cp.CheckpointError('checkpoint_postgres_not_clean')):
            with self.assertRaisesRegex(cp.CheckpointError, 'postgres_not_clean'):
                self.lifecycle.resume(self.token)
        self.assertEqual(upgrade.read_record(self.u.root.parent)['phase'], 'rehearsal_preserved_failed')

    def test_refresh_requires_stopped_formal_rehearsal(self):
        self.pause_pair()
        called = []
        self.u.refresh_paused(self.token, lambda: called.append(True))
        self.assertEqual(called, [True])
        self.u.save('upgrade_paused')
        with self.assertRaisesRegex(upgrade.UpgradeError, 'stopped_rehearsal_required'):
            self.u.refresh_paused(self.token, lambda: called.append(True))

    def make_legacy(self):
        context = self.runtime / 'postgres/.devres-rehearsal-resume-context-2'
        context.mkdir(mode=0o700)
        for name in cp.LEGACY_FILES:
            (context / name).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            upgrade.op.write(context / name, 'raise RuntimeError("must never execute capsule helpers")')
        upgrade.op.write(context / 'owner', self.live)
        old_config = upgrade.target_config(helpers.CONFIG, paused=True).replace(upgrade.VERSION, cp.LEGACY_VERSION)
        upgrade.op.write(context / 'config/backend.toml', old_config)
        upgrade.op.write(self.runtime / 'config/backend.toml', old_config, mode=0o640)
        for name in ('backend.pem', 'backend-key.pem', 'client-ca.pem'):
            upgrade.op.write(context / 'tls' / name, 'inert-test-certificate')
        upgrade.op.write(context / 'original-config.toml', helpers.CONFIG)
        upgrade.op.write(context / 'journal-before-pause.json', json.dumps(self.record))
        upgrade.op.write(context / 'previous-pause-receipt.json', json.dumps({'token': self.token, 'live_token': self.live}))
        upgrade.op.write(context / 'current-resume-receipt.json', json.dumps({
            'previous_attempt_receipt_sha256': cp.digest(context / 'previous-resume-receipt.json'),
            'controller_sha256': cp.digest(context / 'resume-controller.py')}))
        manifest = {'version': 1, 'token': self.token, 'live_token': self.live,
                    'files': {name: {'uid': 0, 'gid': 65532 if name.startswith(('config/', 'tls/')) else 0,
                                     'mode': (0o640 if name.startswith(('config/', 'tls/')) else
                                              0o700 if name in ('pause-helper.py', 'resume-controller.py') else 0o600),
                                     'bytes': len((context / name).read_bytes()),
                                     'sha256': cp.digest(context / name)} for name in cp.LEGACY_FILES}}
        upgrade.op.write(context / 'manifest.json', json.dumps(manifest))
        slot = {'parent': self.drill.dataset, '/postgres': self.drill.dataset + '/postgres',
                '/evidence': self.drill.dataset + '/evidence'}
        legacy = {'version': 1, 'phase': 'paused', 'token': self.token, 'live_token': self.live,
                  'server': cp.LEGACY_SERVER, 'postgres_image': upgrade.restore.PG,
                  'schema': 10, 'integrity_active': False, 'interrupted_timing_qualified': False,
                  'resume_automatically': False, 'source_snapshot': helpers.SNAPSHOT,
                  'original_timers': self.record['timers'], 'operator_bundle': 'a' * 64,
                  'checkpoint': 'devres-pause2-' + self.token,
                  'checkpoint_hold': 'devres-rehearsal-paused',
                  'dataset_guids': {key: self.guids[value] for key, value in slot.items()},
                  'checkpoint_guids': {key: self.guids[value] + '0' for key, value in slot.items()},
                  'previous_pause_receipt_sha256': cp.digest(context / 'previous-pause-receipt.json'),
                  'resume_controller_sha256': cp.digest(context / 'resume-controller.py'),
                  'resume_receipt_sha256': cp.digest(context / 'current-resume-receipt.json')}
        receipt = self.u.root / 'rehearsal-pause-2.json'
        upgrade.op.write(receipt, json.dumps(legacy))
        self.u.save('rehearsal_paused', pause_receipt=receipt.name,
                    pause_checkpoint=legacy['checkpoint'])
        return receipt, context

    def test_legacy_preflight_is_data_only_and_actual_adoption_is_idempotent(self):
        receipt, context = self.make_legacy()
        before = len(self.calls)
        self.assertTrue(self.lifecycle.adopt(self.token, receipt, check_only=True)['check_passed'])
        self.assertFalse(any(call[:2] in (['zfs', 'snapshot'], ['systemctl', 'stop']) for call in self.calls[before:]))
        self.assertTrue(self.lifecycle.adopt(self.token, receipt)['adopted'])
        current = upgrade.read_record(self.u.root.parent)
        self.assertEqual(current['phase'], 'rehearsal_paused')
        self.assertEqual(current['legacy_provenance']['server'], cp.LEGACY_SERVER)
        self.assertTrue(self.lifecycle.adopt(self.token, receipt)['already_adopted'])
        self.assertIn(upgrade.VERSION, (self.runtime / 'config/backend.toml').read_text())
        self.assertTrue((context / 'pause-helper.py').read_text().startswith('raise RuntimeError'))

    def test_legacy_hash_corruption_and_unknown_manifest_member_refuse(self):
        receipt, context = self.make_legacy()
        upgrade.op.write(context / 'resume-controller.py', 'changed')
        with self.assertRaisesRegex(cp.CheckpointError, 'integrity_changed'):
            self.lifecycle.adopt(self.token, receipt, check_only=True)
        self.assertFalse(any(call[:2] == ['systemctl', 'stop'] for call in self.calls))

    def test_legacy_candidate_storage_or_transport_drift_refused_before_writes(self):
        receipt, context = self.make_legacy()
        candidate_path = context / 'config/backend.toml'
        original = candidate_path.read_text()
        for before, after in (('blob_dir = "/data/blobs"', 'blob_dir = "/other"'),
                              ('@postgres:5432/devres', '@other:5432/devres'),
                              ('required_client_dns_san = "devres-edge.internal"',
                               'required_client_dns_san = "other.internal"')):
            self.assertIn(before, original)
            upgrade.op.write(candidate_path, original.replace(before, after))
            manifest = cp.read_json(context / 'manifest.json')
            manifest['files']['config/backend.toml'].update(
                bytes=len(candidate_path.read_bytes()), sha256=cp.digest(candidate_path))
            upgrade.op.write(context / 'manifest.json', json.dumps(manifest))
            with self.assertRaisesRegex(cp.CheckpointError, 'candidate_configuration_changed'):
                self.lifecycle.adopt(self.token, receipt, check_only=True)
            self.assertFalse(any(call[:2] == ['systemctl', 'stop'] for call in self.calls))


if __name__ == '__main__':
    unittest.main()
