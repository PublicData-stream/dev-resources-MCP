#!/usr/bin/env python3
"""One checkpoint-admitted target rollout and, on failure, one fresh fallback rollout."""
import argparse
import datetime as dt
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import time
from pathlib import Path
import sys

_bootstrap = argparse.ArgumentParser(add_help=False)
_bootstrap.add_argument('--runtime', choices=('target', 'fallback'))
_selected, _unused = _bootstrap.parse_known_args()
if _selected.runtime:
    os.environ['DEVRES_ACCEPTANCE_RUNTIME'] = _selected.runtime

import acceptance_common as common

sys.dont_write_bytecode = True


def controller_phase(controller):
    state = controller.state()
    return state.get('runtime'), state.get('phase')


def enforce_withdrawal(controller):
    """Reconcile an interrupted bounded fence before any restore is attempted."""
    with controller.locked():
        controller.withdraw()
        state = controller.state()
        return state.get('phase') == 'withdrawn' and set(state.get('pods', {})) == {'postgres'}


def source_command(name, *arguments):
    return [sys.executable, '-B', str(common.ROOT / name), *arguments]


def run_lifecycle(stage, sources, runtime):
    """A yielded npm result never substitutes for migration/public acceptance."""
    phase = lambda operation: source_command('phase-driver.py', operation,
        '--controller-sha', sources['upgrade-controller.py'])
    proofs = ['--controller', str(common.CONTROLLER), '--controller-sha', sources['upgrade-controller.py'],
              '--checkpoint', str(common.CHECKPOINT), '--checkpoint-sha', sources['physical-checkpoint.py']]
    if runtime == 'target':
        stage('apply', phase('apply'), 300)
    stage('start-writer', phase('start-writer'), 360)
    if runtime == 'target':
        stage('migration-before-npm', source_command('operational-proof.py', 'migration',
              '--label', 'migration-before-npm', *proofs), 360)
        stage('npm-recovery', phase('npm-recovery'), 2100)
    # npm maintenance replaces the writer. Generate a new process-bound receipt
    # after its restart; an earlier migration receipt cannot authorize a reader.
    stage('migration', source_command('operational-proof.py', 'migration', '--label', 'migration', *proofs), 360)
    stage('start-reader', phase('start-reader'), 360)
    for mode, timeout in [('paused', 2400), ('active', 3300)]:
        stage(mode + '-acceptance', source_command('runner.py', '--runtime', runtime, '--mode', mode,
              '--source-manifest-sha256', os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256']), timeout)


def recover_target(controller):
    """A runner may already have prepared fallback; never restore twice."""
    runtime, phase = controller_phase(controller)
    if runtime == 'fallback':
        common.need(phase == 'applied', 'fallback_preparation_incomplete')
        return True
    common.need(runtime == 'target', 'unknown_recovery_runtime')
    common.need(enforce_withdrawal(controller), 'withdrawal_incomplete')
    controller.rollback()
    common.need(controller_phase(controller) == ('fallback', 'applied'), 'fallback_preparation_incomplete')
    return True


def supervise_fallback(controller, supervisor, command, timeout=7200):
    """Bound the complete fallback child while it supervises each runtime step.

    The per-step DiagnosticRunner has a one-hour ceiling; the composed fallback
    includes two acceptance phases and therefore needs its own two-hour ceiling.
    This parent does not load target-bound controller callbacks while fallback
    runs. Child stdout/stderr are first-party finite metadata only.
    """
    common.need(type(timeout) in (int, float) and 0.02 <= timeout <= 7200, 'fallback_deadline_bound')
    common.manifest_sources()
    root = common.WORK / 'command-evidence' / 'deploy-fallback'
    root.mkdir(mode=0o700)
    supervisor.private_save(root / 'intent.json', {'runtime': 'fallback', 'maximum_attempts': 1,
        'deadline_seconds': timeout, 'per_step_supervision': True})
    process = None
    selector = selectors.DefaultSelector()
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    counts = {'stdout': 0, 'stderr': 0}
    success = False
    withdrawn = False
    interrupted = [False]
    handlers = {number: signal.signal(number, lambda *_: interrupted.__setitem__(0, True))
                for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        process = subprocess.Popen(supervisor.parent_bound_command(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
        for name, stream in [('stdout', process.stdout), ('stderr', process.stderr)]:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout
        exited = None
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            common.need(not interrupted[0], 'fallback_supervisor_interrupted')
            common.need(now < deadline, 'fallback_deployment_deadline')
            if process.poll() is not None:
                exited = exited if exited is not None else now
                common.need(now - exited < 1, 'fallback_descendant_pipes')
            for key, _ in selector.select(timeout=min(0.05, max(0, deadline-now))):
                for _ in range(4):
                    try:
                        block = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        break
                    if not block:
                        selector.unregister(key.fileobj)
                        break
                    name = key.data
                    counts[name] += len(block)
                    remaining = 4*1024**2-len(buffers[name])
                    buffers[name].extend(block[:remaining])
                    common.need(counts[name] <= 4*1024**2, 'fallback_output_bound')
        common.need(process.returncode == 0, 'fallback_child_failed')
        common.need(controller_phase(controller) == ('fallback', 'complete'), 'fallback_completion_required')
        success = True
    except BaseException:
        success = False
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                success = False
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                success = False
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        selector.close()
        if interrupted[0]:
            success = False
        if not success:
            try:
                withdrawn = enforce_withdrawal(controller)
            except Exception:
                pass
        # Withdrawal is attempted before any evidence fsync on the failed path.
        try:
            for name, body in buffers.items():
                path = root / (name+'.log')
                fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
            supervisor.private_save(root / 'result.json', {'success': success, 'withdrawal_completed': withdrawn,
                'stdout_bytes': counts['stdout'], 'stderr_bytes': counts['stderr'],
                'exit_code': process.returncode if process is not None else None})
        except Exception:
            if success:
                success = False
                try:
                    withdrawn = enforce_withdrawal(controller)
                except Exception:
                    pass
        if interrupted[0] and success:
            success = False
            try:
                enforce_withdrawal(controller)
            except Exception:
                pass
        for number, handler in handlers.items():
            signal.signal(number, handler)
    common.need(success, 'fallback_deployment_failed')
    return True


def complete(runtime, sources, controller, supervisor, manifest_sha):
    """Control result remains distinct from the candidate's failed acceptance."""
    stage = lambda label, command, timeout: supervisor.run_stage('deploy-' + label, command, timeout)
    try:
        run_lifecycle(stage, sources, runtime)
        common.need(controller_phase(controller) == (runtime, 'complete'), 'completed_runtime_required')
        return {'known_complete': True, 'target_deployed': runtime == 'target',
                'fallback_deployed': runtime == 'fallback', 'runtime': runtime,
                'revision': common.RUNTIMES[runtime]['revision'], 'outcome': runtime + '_accepted'}
    except Exception:
        if runtime == 'fallback':
            fenced = False
            try:
                fenced = enforce_withdrawal(controller)
            except Exception:
                pass
            return {'known_complete': False, 'target_deployed': False, 'fallback_deployed': False,
                    'runtime': 'fallback', 'outcome': 'fallback_failed', 'withdrawal_completed': fenced}
        try:
            recover_target(controller)
        except Exception:
            return {'known_complete': False, 'target_deployed': False, 'fallback_deployed': False,
                    'runtime': 'target', 'outcome': 'restore_incomplete'}
        try:
            # Separate process/runtime environment prevents target module globals,
            # native probe pins or output paths leaking into fallback acceptance.
            command = source_command('deploy.py', '--runtime', 'fallback',
                '--source-manifest-sha256', manifest_sha)
            supervise_fallback(controller, supervisor, command)
            common.need(controller_phase(controller) == ('fallback', 'complete'), 'fallback_completion_required')
            return {'known_complete': False, 'target_deployed': False, 'fallback_deployed': True,
                    'runtime': 'fallback', 'revision': common.RUNTIMES['fallback']['revision'],
                    'outcome': 'target_failed_fallback_accepted'}
        except Exception:
            fenced = False
            try:
                fenced = enforce_withdrawal(controller)
            except Exception:
                pass
            return {'known_complete': False, 'target_deployed': False, 'fallback_deployed': False,
                    'runtime': 'fallback', 'outcome': 'fallback_failed', 'withdrawal_completed': fenced}


def private_hash(path):
    """Stream checkpoint manifests without loading retained history into memory."""
    path = Path(path)
    common.need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)),
                'rehearsal_artifact_path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        common.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and not before.st_mode & 0o077
                    and before.st_size <= 1024**3, 'rehearsal_private_artifact_required')
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024**2), b''):
            digest.update(block)
        after = os.fstat(stream.fileno())
        identity = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns)
        common.need(identity(before) == identity(after), 'rehearsal_artifact_changed')
    return digest.hexdigest()


def verify_restore_rehearsal(controller, sources):
    """Require a fresh actual Restore-class rehearsal before target mutation.

    The helper's production bookend covers admission/checkpoint files. This gate
    separately checks the current live runtime with the checkpoint's admitted PG
    process replacement; it does not equate unchanged files with live acceptance.
    """
    receipt_path = common.ROOT / 'restore-rehearsal-receipt.json'
    receipt = json.loads(common.private_bytes(receipt_path))
    state = controller.state()
    common.need(receipt.get('version') == 1 and receipt.get('verified') is True
                and receipt.get('kind') == 'isolated-real-pg-restore-rehearsal'
                and receipt.get('revision') == common.REVISION
                and receipt.get('prepared_sha256') == state['prepared_sha256'],
                'restore_rehearsal_identity')
    expected_sources = {name: sources[name] for name in
        ('restore-rehearsal.py', 'restore-controller.py', 'physical-checkpoint.py')}
    common.need(receipt.get('sources') == expected_sources, 'restore_rehearsal_sources_changed')
    now = dt.datetime.now(dt.timezone.utc)
    observed = dt.datetime.fromisoformat(receipt['observed_at'].replace('Z', '+00:00'))
    common.need(observed.tzinfo is not None and observed.utcoffset() == dt.timedelta(0)
                and -5 <= (now-observed).total_seconds() <= 300, 'restore_rehearsal_stale')
    checks = receipt.get('checks', {})
    common.need(all(checks.get(name) is True for name in
        ('isolated_real_pg_restore', 'restore_state_machine', 'full_baseline_caches', 'production_untouched')),
        'restore_rehearsal_checks_required')
    checkpoint = common.ROOT / 'checkpoint-state'
    production_paths = {common.BUNDLE / name for name in ('state.json', 'prepared.json', 'plan.json')}
    production_paths |= {checkpoint / name for name in ('completed.json', 'checkpoint-completed.json')}
    current = {str(path): private_hash(path) for path in production_paths}
    fingerprint = common.sha(json.dumps(current, sort_keys=True, separators=(',', ':')).encode())
    common.need(receipt.get('production_state_scope') == 'admission_and_checkpoint_files'
                and receipt.get('production_files') == current
                and receipt.get('production_before_sha256') == fingerprint
                and receipt.get('production_after_sha256') == fingerprint,
                'restore_rehearsal_production_bookend_changed')
    completed = json.loads(common.private_bytes(checkpoint / 'completed.json'))
    fields = ('pg_files_sha256', 'capture_manifest_sha256', 'manifest_sha256', 'cache_baselines_sha256')
    common.need(receipt.get('golden') == {name: completed[name] for name in fields},
                'restore_rehearsal_golden_changed')
    manifest_files = {'pg_files_sha256': 'pg-file-manifest.jsonl',
                      'capture_manifest_sha256': 'capture-bindings.jsonl',
                      'manifest_sha256': 'archive-bindings.jsonl',
                      'cache_baselines_sha256': 'cache-baselines.json'}
    common.need(all(private_hash(checkpoint / name) == completed[field]
                    for field, name in manifest_files.items()), 'restore_rehearsal_manifest_changed')
    backup = checkpoint / 'backup-receipt-after-rehearsal.json'
    accepted, _ = controller.receipt(str(backup), private_hash(backup), 'coordinated-schema18-backup',
        ('coordinated_pg_s3', 'old_clone_verified', 'roles_stopped', 'pg_restarted_without_restore',
         'credentials_preserved', 'fallback_writer_verified'))
    common.need(any(item.get('path') == str(receipt_path)
                    and item.get('sha256') == private_hash(receipt_path)
                    for item in accepted.get('artifacts', [])), 'restore_rehearsal_receipt_unbound')
    controller.guard(pg_rebind=accepted.get('new_pg_pod'))
    # Complete source/file checks can take time; reject an expired admission even
    # when its first freshness check succeeded.
    common.need((dt.datetime.now(dt.timezone.utc)-observed).total_seconds() <= 300,
                'restore_rehearsal_stale')
    return receipt


def run(runtime, manifest_sha):
    common.need(runtime == common.RUNTIME, 'runtime_environment_mismatch')
    os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256'] = manifest_sha
    # The outer deployment process owns restore. A nested acceptance runner
    # must return after withdrawal before its supervising process can safely
    # stop monitoring/killing that process group.
    os.environ['DEVRES_ACCEPTANCE_DEFER_ROLLBACK'] = '1'
    sources = common.manifest_sources(manifest_sha)
    supervisor = common.bound_module(common.ROOT / 'runner.py', sources['runner.py'], 'exact_deployment_supervision')
    _, controller = common.controller()
    with controller.locked():
        common.need(controller_phase(controller) == (runtime, 'stopped' if runtime == 'target' else 'applied'),
                    'checkpoint_admitted_deployment_entry_required')
        if runtime == 'target':
            verify_restore_rehearsal(controller, sources)
        else:
            controller.guard()
    common.WORK.mkdir(mode=0o700, exist_ok=True)
    (common.WORK / 'command-evidence').mkdir(mode=0o700, exist_ok=True)
    supervisor.private_save(common.WORK / 'deployment-intent.json',
        {'version': 1, 'runtime': runtime, 'source_manifest_sha256': manifest_sha,
         'maximum_deployments': 1, 'maximum_restores': 1 if runtime == 'target' else 0})
    result = complete(runtime, sources, controller, supervisor, manifest_sha)
    # Failure control has already fenced/restored before this best-effort write.
    try:
        supervisor.private_save(common.WORK / 'deployment-result.json', result)
    except Exception:
        result['result_persisted'] = False
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', choices=('target', 'fallback'), required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    common.need(os.geteuid() == 0, 'root_required')
    common.install_subprocess_guard()
    value = run(args.runtime, args.source_manifest_sha256)
    print(json.dumps(value, sort_keys=True))
    # Fallback success is success for its child process, but never target success.
    return 0 if value.get('target_deployed') or args.runtime == 'fallback' and value.get('fallback_deployed') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print(json.dumps({'known_complete': False, 'target_deployed': False,
                          'fallback_deployed': False, 'code': 'deployment_setup_failed'}))
        raise SystemExit(1)
