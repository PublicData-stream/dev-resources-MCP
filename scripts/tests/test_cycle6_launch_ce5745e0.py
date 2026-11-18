"""Exercise the sixth-cycle launcher without contacting systemd."""

import datetime as dt
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deploy.production import cycle6_launch_ce5745e0 as launch


NOW = dt.datetime(2026, 11, 18, 12, tzinfo=dt.timezone.utc)
SOURCE_SHA = 'a' * 64
LAUNCHER_SHA = 'b' * 64
SUPERVISOR_SHA = 'c' * 64


def approved(template, **overrides):
    return launch.encode({
        **template,
        'approved_at': launch.utc_text(NOW - dt.timedelta(minutes=10)),
        'expires_at': launch.utc_text(NOW + dt.timedelta(minutes=10)),
        **overrides,
    })


def rehearsed(**overrides):
    return launch.encode({
        'version': 1, 'kind': 'isolated-real-pg-restore-rehearsal',
        'revision': launch.TARGET['commit'], 'verified': True,
        'observed_at': launch.utc_text(NOW - dt.timedelta(seconds=100)),
        **overrides,
    })


class LaunchContract(unittest.TestCase):
    def setUp(self):
        self.argv, self.template = launch.launch_spec(SOURCE_SHA, LAUNCHER_SHA, SUPERVISOR_SHA)

    def test_argv_binds_run_and_fence_to_single_supervisor_and_fixed_environment(self):
        argv = self.argv
        self.assertEqual(argv[0], '/usr/bin/systemd-run')
        for option in ('--quiet', '--wait', '--job-mode=fail', '--uid=0', '--gid=0',
                       '--property=Type=oneshot', '--property=RemainAfterExit=no',
                       '--property=KillMode=control-group', '--property=Restart=no',
                       '--property=TimeoutStartSec=9h', '--property=TimeoutStopSec=150min'):
            self.assertIn(option, argv)
        self.assertEqual(argv.count('--unit=' + launch.UNIT), 1)
        for name, value in (
            ('KUBECACHEDIR', str(launch.CACHE)),
            ('DEVRES_ACCEPTANCE_RUNTIME', 'target'),
            ('DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256', SOURCE_SHA),
            ('DEVRES_EDGE_READMISSION_SHA256', launch.EDGE_SHA256),
        ):
            self.assertIn(f'--setenv={name}={value}', argv)
        command = argv[argv.index('--') + 1:]
        self.assertEqual(command, ['/usr/bin/python3', '-I', '-B', str(launch.INSTALL / 'safety-supervisor.py'),
                                   'run', '--source-manifest-sha256', SOURCE_SHA])
        self.assertIn('--property=ExecStopPost=' + ' '.join((*command[:4], 'fence', *command[5:])), argv)
        self.assertEqual(self.template['argv_sha256'], launch.sha256(launch.encode(argv)))

    def test_exact_current_approval_requires_all_source_and_attempt_bindings(self):
        body = approved(self.template)
        launch.verify_approval(body, launch.sha256(body), self.template, NOW)
        for overrides in (
            {'unit': 'other.service'}, {'maximum_attempts': True}, {'maximum_attempts': 2},
            {'target': {**launch.TARGET, 'image': 'foreign'}}, {'argv_sha256': '1' * 64},
            {'source_manifest_sha256': '1' * 64}, {'launcher_sha256': '1' * 64},
            {'supervisor_sha256': '1' * 64}, {'edge_receipt_sha256': '1' * 64},
            {'unexpected': 'ignored'}, {'approved': 1},
        ):
            body = approved(self.template, **overrides)
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                launch.Refused, 'exact_launch_approval_required',
            ):
                launch.verify_approval(body, launch.sha256(body), self.template, NOW)
        body = approved(self.template)
        with self.assertRaisesRegex(launch.Refused, 'approval_file_hash_required'):
            launch.verify_approval(body, '0' * 64, self.template, NOW)
        body = body[:-1] + b',"approved":true}'
        with self.assertRaisesRegex(launch.Refused, 'duplicate_object_key'):
            launch.verify_approval(body, launch.sha256(body), self.template, NOW)

    def test_approval_freshness_and_rehearsal_deadline(self):
        for overrides in (
            {'approved_at': launch.utc_text(NOW + dt.timedelta(seconds=1))},
            {'expires_at': launch.utc_text(NOW)},
            {'expires_at': launch.utc_text(NOW + dt.timedelta(days=2))},
        ):
            body = approved(self.template, **overrides)
            with self.subTest(overrides=overrides), self.assertRaisesRegex(launch.Refused, 'launch_approval_stale'):
                launch.verify_approval(body, launch.sha256(body), self.template, NOW)
        launch.verify_rehearsal(rehearsed(observed_at=launch.utc_text(NOW - dt.timedelta(seconds=300))), NOW)
        # The actual rehearsal producer uses datetime.isoformat() with +00:00.
        launch.verify_rehearsal(rehearsed(observed_at=(NOW - dt.timedelta(seconds=100)).isoformat()), NOW)
        with self.assertRaisesRegex(launch.Refused, 'restore_rehearsal_stale'):
            launch.verify_rehearsal(rehearsed(observed_at=launch.utc_text(NOW - dt.timedelta(seconds=301))), NOW)
        with self.assertRaisesRegex(launch.Refused, 'verified_target_rehearsal_required'):
            launch.verify_rehearsal(rehearsed(revision='0' * 40), NOW)

    def test_inputs_bind_both_code_files_and_exact_retained_edge_bytes(self):
        def staged():
            return {
                launch.INSTALL / 'launch.py': b'candidate launcher',
                launch.INSTALL / 'safety-supervisor.py': b'candidate supervisor',
                launch.WORK / 'source-manifest.json': launch.encode({
                    'safety-supervisor.py': launch.sha256(b'candidate supervisor'),
                }),
                launch.EDGE_RECEIPT: b'exact accepted edge',
            }

        files = staged()
        source_sha = launch.sha256(files[launch.WORK / 'source-manifest.json'])
        launcher_sha = launch.sha256(files[launch.INSTALL / 'launch.py'])
        with (
            patch.object(launch, '__file__', str(launch.INSTALL / 'launch.py')),
            patch.object(launch.os, 'geteuid', return_value=0),
            patch.object(launch, 'trusted_directory') as directory,
            patch.object(launch, 'private_bytes', side_effect=lambda path, maximum: files[path]),
            patch.object(launch, 'EDGE_SHA256', launch.sha256(files[launch.EDGE_RECEIPT])),
        ):
            self.assertEqual(launch.verify_inputs(source_sha, launcher_sha)[1]['launcher_sha256'], launcher_sha)
            directory.assert_called_once_with(launch.CACHE, private=True)
            for path, code in (
                (launch.INSTALL / 'launch.py', 'launcher_source_changed'),
                (launch.INSTALL / 'safety-supervisor.py', 'supervisor_source_changed'),
                (launch.WORK / 'source-manifest.json', 'source_manifest_changed'),
                (launch.EDGE_RECEIPT, 'edge_receipt_changed'),
            ):
                files = staged()
                files[path] += b' changed'
                with self.subTest(path=path), self.assertRaisesRegex(launch.Refused, code):
                    launch.verify_inputs(source_sha, launcher_sha)

    def test_systemd_client_timeout_is_unknown_without_resubmission(self):
        with patch.object(launch.subprocess, 'run', side_effect=subprocess.TimeoutExpired(self.argv, 1)) as runner:
            self.assertEqual(launch.submit(self.argv), {'client_outcome': 'unknown', 'client_exit_status': None})
        runner.assert_called_once_with(
            self.argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=launch.CHILD_ENV, timeout=launch.CLIENT_TIMEOUT,
        )


class DurableLaunch(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cycle6-launch-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.bundle = root / 'bundle'
        self.bundle.mkdir(mode=0o700)
        self.work = root / 'work'
        self.argv, self.template = launch.launch_spec(SOURCE_SHA, LAUNCHER_SHA, SUPERVISOR_SHA)
        self.approval = approved(self.template)
        self.rehearsal = rehearsed()
        self.backup = launch.encode({
            'kind': 'coordinated-schema18-backup', 'revision': launch.TARGET['commit'],
            'schema': 18, 'verified': True, 'current_revalidation': True,
            'artifacts': [{'path': str(self.work / 'restore-rehearsal-receipt.json'),
                           'sha256': launch.sha256(self.rehearsal)}],
        })
        self.intent = self.bundle / launch.INTENT_FILE
        self.result = self.bundle / launch.RESULT_FILE
        for mock in (
            patch.object(launch, 'BUNDLE', self.bundle), patch.object(launch, 'WORK', self.work),
            patch.object(launch, 'verify_inputs', return_value=(self.argv, self.template)),
            patch.object(launch, 'trusted_directory'),
            patch.object(launch, 'private_bytes', side_effect=self.private_input),
            patch.object(launch, 'utc_now', return_value=NOW),
        ):
            mock.start()
            self.addCleanup(mock.stop)

    def private_input(self, path, maximum):
        return {
            launch.APPROVAL_FILE: self.approval,
            'restore-rehearsal-receipt.json': self.rehearsal,
            'backup-receipt-after-rehearsal.json': self.backup,
        }[path.name]

    def run_launch(self):
        return launch.launch(SOURCE_SHA, LAUNCHER_SHA, launch.sha256(self.approval))

    def test_durable_exclusive_intent_exists_before_submission_and_records_exit(self):
        def submit(argv):
            self.assertEqual(argv, self.argv)
            intent = json.loads(self.intent.read_bytes())
            self.assertEqual(intent['kind'], 'cycle6-launch-intent')
            self.assertEqual(intent['argv_sha256'], self.template['argv_sha256'])
            self.assertEqual(intent['rehearsal_sha256'], launch.sha256(self.rehearsal))
            self.assertEqual(stat.S_IMODE(self.intent.stat().st_mode), 0o600)
            self.assertFalse(self.result.exists())
            return {'client_outcome': 'exited', 'client_exit_status': 1}

        with patch.object(launch, 'submit', side_effect=submit) as submission:
            result = self.run_launch()
            self.assertEqual(json.loads(self.result.read_bytes()), result)
            self.assertEqual(stat.S_IMODE(self.result.stat().st_mode), 0o600)
            self.assertEqual(result['client_exit_status'], 1)
            self.assertNotIn('service_accepted', result)
            with self.assertRaisesRegex(launch.Refused, 'launch_result_already_exists'):
                self.run_launch()
        submission.assert_called_once_with(self.argv)

    def test_incomplete_attempt_or_symlink_intent_blocks_any_submission(self):
        self.intent.touch()
        with patch.object(launch, 'submit') as submit:
            with self.assertRaisesRegex(launch.Refused, 'launch_intent_already_consumed'):
                self.run_launch()
            self.intent.unlink()
            self.intent.symlink_to(self.bundle / 'other')
            with self.assertRaisesRegex(launch.Refused, 'launch_intent_already_consumed'):
                self.run_launch()
        submit.assert_not_called()
        self.assertFalse(self.result.exists())

    def test_stale_rehearsal_preserves_unconsumed_intent(self):
        self.rehearsal = rehearsed(observed_at=launch.utc_text(NOW - dt.timedelta(minutes=10)))
        with patch.object(launch, 'submit') as submit:
            with self.assertRaisesRegex(launch.Refused, 'restore_rehearsal_stale'):
                self.run_launch()
        submit.assert_not_called()
        self.assertFalse(os.path.lexists(self.intent))

    def test_rehearsal_without_finished_backup_binding_cannot_consume_intent(self):
        backup = json.loads(self.backup)
        backup['artifacts'][0]['sha256'] = '0' * 64
        self.backup = launch.encode(backup)
        with patch.object(launch, 'submit') as submit, self.assertRaisesRegex(
            launch.Refused, 'completed_rehearsal_backup_required',
        ):
            self.run_launch()
        submit.assert_not_called()
        self.assertFalse(os.path.lexists(self.intent))
