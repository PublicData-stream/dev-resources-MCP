#!/usr/bin/env python3
"""Bounded production acceptance with immediate independent withdrawal callbacks."""
import argparse
from dataclasses import asdict
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

# CLI runtime is explicit; child producers inherit it through the environment.
_bootstrap = argparse.ArgumentParser(add_help=False)
_bootstrap.add_argument('--runtime', choices=('target', 'fallback'))
_selected, _unused = _bootstrap.parse_known_args()
if _selected.runtime:
    os.environ['DEVRES_ACCEPTANCE_RUNTIME'] = _selected.runtime

import acceptance_common as common

sys.dont_write_bytecode = True


def private_save(path, value):
    body = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def diagnostic_runner():
    common.manifest_sources()
    directory = common.ROOT / 'deploy' / 'diagnostics'
    name = 'devres_acceptance_diagnostics'
    spec = importlib.util.spec_from_file_location(name, directory / '__init__.py',
                                                submodule_search_locations=[str(directory)])
    package = importlib.util.module_from_spec(spec)
    sys.modules[name] = package
    spec.loader.exec_module(package)
    spec = importlib.util.spec_from_file_location(name + '.runner', directory / 'runner.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.DiagnosticRunner


def collect_runtime(recorder, stop):
    """Reduce private Kubernetes observations to closed fields before Pod deletion."""
    while True:
        result = subprocess.run(['k3s', 'kubectl', '--context', 'default', '--namespace', 'devres',
            '--request-timeout=5s', 'get', 'pods', '-o', 'json'],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
        common.need(result.returncode == 0 and len(result.stdout) <= 2 * 1024**2
                    and len(result.stderr) <= 65536, 'runtime_pod_observation_failed')
        items = json.loads(result.stdout)['items']
        seen = set()
        for value in items:
            role = value.get('metadata', {}).get('labels', {}).get('app')
            common.need(role in {'backend', 'writer', 'postgres'} and role not in seen, 'runtime_role_set')
            seen.add(role)
            statuses = value.get('status', {}).get('containerStatuses', [])
            common.need(len(statuses) <= 1, 'runtime_container_status')
            status = statuses[0] if statuses else {}
            restarts = status.get('restartCount', 0)
            common.need(type(restarts) is int, 'runtime_restart_count')
            recorder.record('pod', {'role': role, 'ready': status.get('ready') is True,
                                    'restarts': restarts})
        common.need('postgres' in seen, 'runtime_postgres_required')
        if stop.wait(5):
            return


def withdraw():
    # Called in an independent bounded process. The parent later reconciles an
    # interrupted wait with the controller's idempotent withdrawal journal.
    _, controller = common.controller()
    with controller.locked():
        controller.withdraw()
        state = controller.state()
        return state.get('phase') == 'withdrawn' and set(state.get('pods', {})) == {'postgres'}


def parent_bound_command(command):
    return common.parent_command(command)


def run_stage(label, command, timeout, collect=collect_runtime, fence=withdraw):
    common.need(re.fullmatch('[a-z0-9][a-z0-9-]{0,63}', label) is not None, 'fixed_stage_label')
    common.manifest_sources()
    directory = common.WORK / 'command-evidence' / label
    directory.mkdir(mode=0o700)
    runner = diagnostic_runner()(directory, evidence_timeout=15, fence_timeout=30, pipe_grace=0.2)
    parent_pid = os.getpid()
    def guarded_collect(recorder, stop):
        with common.parent_lifetime(parent_pid):
            return collect(recorder, stop)
    def guarded_fence():
        with common.parent_lifetime(parent_pid):
            return fence()
    result = runner.run(parent_bound_command(command), timeout_seconds=timeout,
                        collect=guarded_collect, fence=guarded_fence)
    outcome = {'version': 1, 'stage': label, 'runtime': common.RUNTIME,
               'final_outcome': True, 'supervision': asdict(result)}
    private_save(directory / 'final-result.json', outcome)
    print(json.dumps({'stage': label, 'code': result.code, 'exit_code': result.exit_code,
                      'withdrawal_completed': result.withdrawal_completed}), flush=True)
    common.need(result.code == 'ok' and result.exit_code == 0 and result.persisted
                and result.runtime_evidence_complete and result.child_cleanup_complete,
                'acceptance_stage_failed')
    return outcome


def commands(mode, sources):
    common_args = ['--controller', str(common.CONTROLLER), '--controller-sha', sources['upgrade-controller.py'],
                   '--checkpoint', str(common.CHECKPOINT), '--checkpoint-sha', sources['physical-checkpoint.py']]
    compression = ['--compression-sha', sources['compressed-probe.py']]
    operational = ['--operational-sha', sources['operational-proof.py']]
    source = lambda name, *args: [sys.executable, '-B', str(common.ROOT / name), *args]
    sample = lambda label: source('operational-proof.py', 'sample', '--label', label, *common_args)
    phase = lambda op: source('phase-driver.py', op, '--controller-sha', sources['upgrade-controller.py'])
    if mode == 'paused':
        return [
            ('private-before', sample('private-before'), 120),
            ('private', source('target-private-acceptance.py', 'private'), 240),
            ('private-after', sample('private-after'), 120),
            ('private-receipt', source('acceptance-receipt.py', 'runtime-ready', '--label', 'private',
                '--private', 'private', '--before', 'private-before', '--after', 'private-after',
                *compression, *operational, *common_args), 120),
            ('runtime-ready', phase('runtime-ready'), 120),
            ('paused-before', sample('paused-before'), 120),
            ('paused-private', source('target-private-acceptance.py', 'paused'), 240),
            ('paused-public', source('public-matrix.py', 'paused-public', 'full'), 360),
            ('paused-codecs', source('compressed-probe.py', '--public', 'paused-public'), 240),
            ('paused-after', sample('paused-after'), 120),
            ('activation-receipt', source('acceptance-receipt.py', 'activate-existing', '--label', 'paused',
                '--private', 'paused', '--public', 'paused-public', '--before', 'paused-before',
                '--after', 'paused-after', *compression, *operational, *common_args), 120),
            ('activate-existing', phase('activate-existing'), 720),
        ]
    common.need(mode == 'active', 'fixed_acceptance_mode')
    return [
        ('early-before', sample('early-before'), 120),
        ('early-private', source('target-private-acceptance.py', 'early'), 240),
        ('early-public', source('public-matrix.py', 'early-public', 'full'), 360),
        ('early-codecs', source('compressed-probe.py', '--public', 'early-public'), 240),
        ('early-after', sample('early-after'), 120),
        ('observation', source('observation-loop.py', '--label', 'observation', *compression, *operational, *common_args), 1100),
        ('late-before', sample('late-before'), 120),
        ('late-private', source('target-private-acceptance.py', 'late'), 240),
        ('late-public', source('public-matrix.py', 'late-public', 'bounded'), 360),
        ('late-codecs', source('compressed-probe.py', '--public', 'late-public'), 240),
        ('late-after', sample('late-after'), 120),
        ('final-receipt', source('acceptance-receipt.py', 'finish', '--label', 'final',
            '--early', 'early', 'early-public', 'early-before', 'early-after',
            '--late', 'late', 'late-public', 'late-before', 'late-after',
            '--observation', 'observation', *compression, *operational, *common_args), 120),
        ('finish', phase('finish'), 120),
    ]


def recover_failure():
    result = {'known_complete': False, 'runtime': common.RUNTIME,
              'withdrawal_completed': False, 'fallback_prepared': False}
    try:
        result['withdrawal_completed'] = withdraw()
    except Exception:
        pass
    if common.RUNTIME == 'target' and result['withdrawal_completed'] and os.environ.get('DEVRES_ACCEPTANCE_DEFER_ROLLBACK') != '1':
        try:
            _, controller = common.controller()
            controller.rollback()
            state = controller.state()
            result['fallback_prepared'] = state.get('runtime') == 'fallback' and state.get('phase') == 'applied'
        except Exception:
            pass
    return result


def run(mode, expected):
    os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256'] = expected
    sources = common.manifest_sources(expected)
    _, controller = common.controller()
    with controller.locked():
        controller.guard()
        state = controller.state()
        common.need(state['phase'] == ('reader_ready' if mode == 'paused' else 'collectors_active'), 'acceptance_entry_phase')
    common.WORK.mkdir(mode=0o700, exist_ok=True)
    evidence = common.WORK / 'command-evidence'
    evidence.mkdir(mode=0o700, exist_ok=True)
    private_save(common.WORK / (mode + '-runner-intent.json'),
                 {'version': 1, 'runtime': common.RUNTIME, 'mode': mode,
                  'source_manifest_sha256': expected, 'maximum_attempts': 1})
    try:
        for label, command, timeout in commands(mode, sources):
            run_stage(label, command, timeout)
        result = {'known_complete': True, 'runtime': common.RUNTIME, 'mode': mode,
                  'phase': controller.state()['phase']}
        private_save(common.WORK / (mode + '-runner-result.json'), result)
        return result
    except Exception:
        result = recover_failure()
        try:
            private_save(common.WORK / (mode + '-runner-result.json'), result)
        except Exception:
            result['final_result_persisted'] = False
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', choices=('target', 'fallback'), required=True)
    parser.add_argument('--mode', choices=('paused', 'active'), required=True)
    parser.add_argument('--source-manifest-sha256', required=True)
    args = parser.parse_args()
    common.need(os.geteuid() == 0 and args.runtime == common.RUNTIME, 'root_and_runtime_required')
    common.install_subprocess_guard()
    value = run(args.mode, args.source_manifest_sha256)
    print(json.dumps(value, sort_keys=True))
    return 0 if value['known_complete'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print(json.dumps({'known_complete': False, 'code': 'acceptance_setup_failed'}))
        raise SystemExit(1)
