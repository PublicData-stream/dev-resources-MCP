#!/usr/bin/env python3
"""Time the retained-row query against the isolated B130E rehearsal copy."""

from functools import partial
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time

from observer_retained_rows import (
    RETAINED_PARALLEL_PROFILE,
    RETAINED_PARALLEL_TEMP_BYTES,
    retained_row_manifest,
)


WORK = Path('/tmp/devres-rehearsal-5a865235')
BACKING = Path('/var/lib/devres-production-upgrades/5a865235-rehearsal')
PG = ('docker.io/library/postgres:18.6-alpine3.24@'
      'sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395')
CONTAINER = 'devres-5a865235-retained-proof'
RESERVE = 128 * 1024**3
CPUS = 4
MEMORY_BYTES = 6 * 1024**3
SHM_BYTES = 64 * 1024**2
POLICY_2 = 'devres-attribution-v2:verified-forward-origins:member-scopes:readable-notices'
POLICY_3 = ('devres-attribution-v3:verified-forward-origins:member-scopes:'
            'rfc-erratum-8173:readable-notices')


def run(*argv, timeout=30, data=None):
    result = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
    if result.returncode or len(result.stdout) + len(result.stderr) > 128 * 1024:
        raise RuntimeError('isolated_postgres_command_failed')
    return result.stdout


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('private_rehearsal_mount_required')
    return info.st_dev, info.st_ino


def validate_workspace():
    if (os.geteuid() != 0 or socket.gethostname().lower() != 'publicdatamcp-b130e'
            or not WORK.is_mount()):
        raise RuntimeError('root_and_exact_rehearsal_mount_required')
    if private_directory(WORK) != private_directory(BACKING):
        raise RuntimeError('rehearsal_mount_mismatch')
    if run('findmnt', '-n', '-o', 'SOURCE', '-T', str(WORK)).split(b'[')[0].strip() != b'/dev/md1':
        raise RuntimeError('rehearsal_volume_mismatch')
    if run('docker', 'image', 'inspect', '--format', '{{.Id}}', PG).strip() != PG.split('@')[1].encode():
        raise RuntimeError('postgres_image_mismatch')


def docker_run(entrypoint, mounts):
    args = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
            '--user', '70:70', '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL',
            '--cpus', str(CPUS), '--memory', str(MEMORY_BYTES), '--shm-size', str(SHM_BYTES),
            '--pids-limit', '64']
    for mount in mounts:
        args.extend(('--mount', mount))
    return [*args, '--entrypoint', entrypoint]


def sql(container, *command, timeout=30, data=None):
    return run('docker', 'exec', '-i', container, 'psql', '-X', '-qAt',
               '-h', '/tmp', '-U', 'devres_admin', '-d', 'devres', '-v', 'ON_ERROR_STOP=1',
               *command, timeout=timeout, data=data)


def proof_exec(container, *argv, request_timeout, timeout, data):
    if argv[-2:] != ('-f', '-') or request_timeout != 260:
        raise RuntimeError('unexpected_retained_row_command')
    return sql(container, '-f', '-', timeout=timeout, data=data)


def write_receipt(path, receipt):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        json.dump(receipt, output, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def wait_ready(container):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            run('docker', 'exec', container, 'pg_isready', '-q', '-h', '/tmp', timeout=5)
        except RuntimeError:
            time.sleep(1)
        else:
            return
    raise RuntimeError('isolated_postgres_not_ready')


def check_identity(container):
    value = json.loads(sql(container, '-c', """
        SELECT json_build_object('schema', version,
            'policy', (SELECT data FROM devres_attribution_control WHERE singleton),
            'recovery', pg_is_in_recovery(), 'read_only', current_setting('transaction_read_only'),
            'listen', current_setting('listen_addresses'), 'archive_mode', current_setting('archive_mode'))
        FROM devres_schema WHERE singleton
        """))
    configuration = value['policy']
    policy = configuration['required_policy_epoch']
    if (value['schema'] != 19 or value['recovery'] is not False or value['read_only'] != 'on'
            or value['listen'] or value['archive_mode'] != 'off'
            or configuration['required_policy_fingerprint'] != {2: POLICY_2, 3: POLICY_3}.get(policy)):
        raise RuntimeError('isolated_postgres_identity_mismatch')
    return policy


def check_proof_limits(container):
    limits = run('docker', 'exec', container, 'cat', '/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/cpu.max').split()
    shm = run('docker', 'inspect', '--type', 'container', '--format', '{{.HostConfig.ShmSize}}', container).strip()
    if (len(limits) != 3 or not all(value.isdigit() for value in limits) or int(limits[0]) != MEMORY_BYTES
            or int(limits[2]) <= 0 or int(limits[1]) != CPUS * int(limits[2]) or shm != str(SHM_BYTES).encode()):
        raise RuntimeError('isolated_postgres_proof_limits_mismatch')


def require_disk_headroom(copy_bytes=0):
    if shutil.disk_usage(WORK).free < RESERVE + copy_bytes + RETAINED_PARALLEL_TEMP_BYTES:
        raise RuntimeError('rehearsal_copy_reserve_exceeded')


def main():
    validate_workspace()
    if len(sys.argv) != 2 or sys.argv[1] not in ('preimage', 'candidate'):
        raise RuntimeError('proof_requires_preimage_or_candidate')
    variant = sys.argv[1]
    source = WORK / ('pgdata' if variant == 'preimage' else 'candidate-pgdata')
    scratch = WORK / ('proof-' + variant)
    if (not source.is_dir() or source.is_symlink() or source.stat().st_uid != 70
            or (source / 'PG_VERSION').read_bytes() != b'18\n'):
        raise RuntimeError('rehearsal_postgres_source_mismatch')
    if (source / 'pg_tblspc').is_symlink() or any((source / 'pg_tblspc').iterdir()):
        raise RuntimeError('isolated_external_tablespaces_unsupported')
    if variant == 'preimage':
        verify = docker_run('pg_verifybackup', [f'type=bind,source={source},target=/base,readonly'])
        run(*verify, PG, '/base', timeout=1800)
    else:
        if (source / 'postmaster.pid').exists():
            raise RuntimeError('stopped_candidate_clone_required')
    pg_bytes = int(run('du', '-sx', '-B1', str(source), timeout=60).split()[0])
    require_disk_headroom(pg_bytes)

    scratch.mkdir(mode=0o700)
    data = scratch / 'data'
    run('cp', '-a', '--one-file-system', '--reflink=auto', '--', str(source), str(data), timeout=1800)
    # Start a disposable copy with no TCP sockets, outbound network, production
    # volumes, or archive/replication commands. Restart leaves OS page cache intact.
    mount = f'type=bind,source={data},target=/pgdata'
    command = docker_run('postgres', [mount])
    cid = run(*command[:-2], '-d', '--name', CONTAINER, '--tmpfs', '/tmp:rw,mode=1777,size=64m',
              '--entrypoint', command[-1], PG, '-D', '/pgdata',
              '-c', 'listen_addresses=', '-c', 'unix_socket_directories=/tmp',
              '-c', 'archive_mode=off', '-c', 'archive_command=', '-c', 'restore_command=',
              '-c', 'primary_conninfo=', '-c', 'primary_slot_name=',
              '-c', 'default_transaction_read_only=on', timeout=60).decode('ascii').strip()
    if re.fullmatch('[0-9a-f]{64}', cid) is None:
        raise RuntimeError('isolated_container_identity_mismatch')
    try:
        wait_ready(cid)
        check_proof_limits(cid)
        policy = check_identity(cid)
        if policy != (2 if variant == 'preimage' else 3):
            raise RuntimeError('unexpected_rehearsal_policy')
        values = []
        for cache in ('postgresql-restart', 'repeat', 'repeat'):
            require_disk_headroom()
            begin = time.monotonic()
            result = retained_row_manifest(partial(proof_exec, cid), profile=RETAINED_PARALLEL_PROFILE)
            values.append({'cache': cache, 'seconds': time.monotonic() - begin,
                           'manifest': result})
        passed = (all(value['seconds'] <= 200 for value in values)
                  and all(value['manifest'] == values[0]['manifest'] for value in values))
        receipt = {'schema': 19, 'policy_epoch': policy, 'runs': values, 'passed': passed,
                   'os_page_cache': 'uncontrolled', 'proof_profile': RETAINED_PARALLEL_PROFILE}
    finally:
        run('docker', 'stop', '--time', '15', cid, timeout=30)
    write_receipt(scratch / 'retained-rows.json', receipt)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        code = str(error) if type(error) is RuntimeError else type(error).__name__
        print(json.dumps({'passed': False, 'code': code}), file=sys.stderr)
        sys.exit(1)
