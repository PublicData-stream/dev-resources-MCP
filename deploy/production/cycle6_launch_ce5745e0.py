#!/usr/bin/env python3
"""Reserve and submit the one approved root systemd deployment for ce5745e0."""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


WORK = Path('/tmp/devres-upgrade-ce5745e0-cycle6')
BUNDLE = Path('/var/lib/devres-production-upgrades/ce5745e0-cycle6')
INSTALL = Path('/usr/local/libexec/devres-upgrade-ce5745e0-cycle6')
CACHE = Path('/tmp/devres-reclaim-discovery-3dae7d91-20261117')
EDGE_RECEIPT = Path('/var/lib/devres-production-edge-admissions/3dae7d91-20261117/admission.json')
EDGE_SHA256 = 'e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a'
UNIT = 'devres-upgrade-ce5745e0-cycle6.service'
TARGET = {
    'commit': 'ce5745e0a0a5914dad62cd24f8655276b6f780ce',
    'version': '0.1.0-build.ce5745e0',
    'image': 'ghcr.io/publicdata-stream/dev-resources-server@sha256:05f8880386d7e96ddc75d165475ac410800932eb0848dbde99174182a125ac1f',
}
CHILD_ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}
APPROVAL_FILE = 'launch-approval.json'
INTENT_FILE = 'launch-intent.json'
RESULT_FILE = 'launch-result.json'
# Allow the unit's start and stop deadlines, plus time for systemd's D-Bus bookkeeping.
CLIENT_TIMEOUT = 9 * 3600 + 150 * 60 + 300


class Refused(RuntimeError):
    """The launcher's stable diagnostic codes contain no external input."""


def need(value, code):
    if not value:
        raise Refused(code)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def valid_sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def utc_text(value):
    return value.isoformat().replace('+00:00', 'Z')


def utc_time(value):
    need(isinstance(value, str) and re.fullmatch(
        r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)', value
    ), 'utc_timestamp_required')
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))


def load_object(body):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate_object_key')
            result[key] = value
        return result

    value = json.loads(body, object_pairs_hook=unique)
    need(type(value) is dict, 'object_required')
    return value


def trusted_directory(path, *, private=False):
    need(path.is_absolute() and '..' not in path.parts, 'absolute_directory_required')
    for candidate in (path, *path.parents):
        info = candidate.lstat()
        sticky_tmp = candidate == Path('/tmp') and info.st_mode & stat.S_ISVTX
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
             and (sticky_tmp or not info.st_mode & 0o022), 'trusted_directory_required')
    if private:
        info = path.lstat()
        need(info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'private_root_directory_required')


def private_bytes(path, maximum):
    trusted_directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and not before.st_mode & 0o077 and 0 < before.st_size <= maximum,
             'bounded_private_root_file_required')
        body = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        need(len(body) == before.st_size
             and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
             == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'private_file_changed')
    return body


def save_exclusive(directory, name, value):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(encode(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(directory)


def launch_spec(source_sha, launcher_sha, supervisor_sha):
    supervisor = INSTALL / 'safety-supervisor.py'
    python = ('/usr/bin/python3', '-I', '-B', str(supervisor))
    manifest_option = ('--source-manifest-sha256', source_sha)
    fence = ' '.join((*python, 'fence', *manifest_option))
    argv = [
        '/usr/bin/systemd-run', '--quiet', '--wait', '--no-ask-password', '--job-mode=fail',
        '--unit=' + UNIT, '--uid=0', '--gid=0', '--working-directory=' + str(WORK),
        '--property=Type=oneshot', '--property=RemainAfterExit=no',
        '--property=KillMode=control-group', '--property=Restart=no',
        '--property=TimeoutStartSec=9h', '--property=TimeoutStopSec=150min',
        '--property=StandardOutput=journal', '--property=StandardError=journal',
        '--property=ExecStopPost=' + fence,
        '--setenv=PATH=' + CHILD_ENV['PATH'],
        '--setenv=KUBECACHEDIR=' + str(CACHE),
        '--setenv=DEVRES_ACCEPTANCE_RUNTIME=target',
        '--setenv=DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256=' + source_sha,
        '--setenv=DEVRES_EDGE_READMISSION_SHA256=' + EDGE_SHA256,
        '--', *python, 'run', *manifest_option,
    ]
    approval = {
        'version': 1, 'kind': 'cycle6-deployment-launch', 'approved': True,
        'unit': UNIT, 'runtime': 'target', 'target': TARGET, 'maximum_attempts': 1,
        'source_manifest_sha256': source_sha, 'launcher_sha256': launcher_sha,
        'supervisor_sha256': supervisor_sha, 'edge_receipt_sha256': EDGE_SHA256,
        'argv_sha256': sha256(encode(argv)),
    }
    return argv, approval


def verify_inputs(source_sha, launcher_sha):
    need(os.geteuid() == 0, 'root_required')
    need(valid_sha(source_sha) and valid_sha(launcher_sha), 'external_hashes_required')
    launcher = INSTALL / 'launch.py'
    need(Path(__file__).absolute() == launcher
         and sha256(private_bytes(launcher, 1024**2)) == launcher_sha, 'launcher_source_changed')
    manifest = private_bytes(WORK / 'source-manifest.json', 1024**2)
    need(sha256(manifest) == source_sha, 'source_manifest_changed')
    supervisor_sha = load_object(manifest).get('safety-supervisor.py')
    need(valid_sha(supervisor_sha) and sha256(private_bytes(
        INSTALL / 'safety-supervisor.py', 4 * 1024**2
    )) == supervisor_sha, 'supervisor_source_changed')
    need(sha256(private_bytes(EDGE_RECEIPT, 16 * 1024**2)) == EDGE_SHA256, 'edge_receipt_changed')
    trusted_directory(CACHE, private=True)
    return launch_spec(source_sha, launcher_sha, supervisor_sha)


def verify_approval(body, approval_sha, template, now):
    need(valid_sha(approval_sha) and sha256(body) == approval_sha, 'approval_file_hash_required')
    value = load_object(body)
    approved = utc_time(value.pop('approved_at', None))
    expires = utc_time(value.pop('expires_at', None))
    need(encode(value) == encode(template), 'exact_launch_approval_required')
    need(approved <= now < expires and expires - approved <= dt.timedelta(hours=24),
         'launch_approval_stale')


def verify_rehearsal(body, now):
    value = load_object(body)
    need(type(value.get('version')) is int and value['version'] == 1
         and value.get('kind') == 'isolated-real-pg-restore-rehearsal'
         and value.get('revision') == TARGET['commit'] and value.get('verified') is True,
         'verified_target_rehearsal_required')
    age = (now - utc_time(value.get('observed_at'))).total_seconds()
    need(-5 <= age <= 300, 'restore_rehearsal_stale')


def verify_revalidated_backup(body, rehearsal_path, rehearsal_sha):
    # The producer publishes the rehearsal receipt before completing this
    # second receipt. Both must exist before a launch consumes its intent.
    value = load_object(body)
    artifacts = value.get('artifacts')
    need(value.get('kind') == 'coordinated-schema18-backup' and value.get('schema') == 18
         and value.get('revision') == TARGET['commit'] and value.get('verified') is True
         and value.get('current_revalidation') is True and type(artifacts) is list
         and artifacts.count({'path': str(rehearsal_path), 'sha256': rehearsal_sha}) == 1,
         'completed_rehearsal_backup_required')


def submit(argv):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=CHILD_ENV, timeout=CLIENT_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        # A disconnected or timed-out client cannot establish the unit's outcome.
        return {'client_outcome': 'unknown', 'client_exit_status': None}
    return {'client_outcome': 'exited', 'client_exit_status': result.returncode}


def launch(source_sha, launcher_sha, approval_sha):
    argv, template = verify_inputs(source_sha, launcher_sha)
    trusted_directory(BUNDLE, private=True)
    approval = private_bytes(BUNDLE / APPROVAL_FILE, 16 * 1024)
    rehearsal_path = WORK / 'restore-rehearsal-receipt.json'
    rehearsal = private_bytes(rehearsal_path, 1024**2)
    rehearsal_sha = sha256(rehearsal)
    backup = private_bytes(WORK / 'checkpoint-state/backup-receipt-after-rehearsal.json', 1024**2)
    now = utc_now()
    verify_approval(approval, approval_sha, template, now)
    verify_rehearsal(rehearsal, now)
    verify_revalidated_backup(backup, rehearsal_path, rehearsal_sha)
    descriptor = os.open(BUNDLE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        need(not os.path.lexists(BUNDLE / RESULT_FILE), 'launch_result_already_exists')
        try:
            save_exclusive(descriptor, INTENT_FILE, {
                **template, 'kind': 'cycle6-launch-intent',
                'approval_sha256': approval_sha, 'rehearsal_sha256': rehearsal_sha,
                'reserved_at': utc_text(now),
            })
        except FileExistsError:
            raise Refused('launch_intent_already_consumed') from None
        result = {
            'version': 1, 'kind': 'cycle6-launch-result', 'unit': UNIT,
            'approval_sha256': approval_sha, 'argv_sha256': template['argv_sha256'],
            **submit(argv), 'recorded_at': utc_text(utc_now()),
        }
        save_exclusive(descriptor, RESULT_FILE, result)
        return result
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest='operation', required=True)
    for name in ('preview', 'launch'):
        action = operations.add_parser(name)
        action.add_argument('--source-manifest-sha256', required=True)
        action.add_argument('--launcher-sha256', required=True)
        if name == 'launch':
            action.add_argument('--approval-sha256', required=True)
    args = parser.parse_args()
    try:
        if args.operation == 'preview':
            argv, template = verify_inputs(args.source_manifest_sha256, args.launcher_sha256)
            output = {'argv': argv, 'approval_template': template}
            status = 0
        else:
            output = launch(args.source_manifest_sha256, args.launcher_sha256, args.approval_sha256)
            status = int(output['client_exit_status'] != 0)
    except Refused as error:
        output, status = {'code': str(error)}, 1
    except (OSError, ValueError):
        output, status = {'code': 'launch_input_or_journal_unavailable'}, 1
    print(json.dumps(output, sort_keys=True))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
