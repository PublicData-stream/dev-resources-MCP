"""Fixed deployment identities and externally pinned, private acceptance sources."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import signal
import threading
import sys

# Only source-bound first-party wrappers set this metadata; no request data enters it.
_parent = os.environ.get('DEVRES_ACCEPTANCE_PARENT_PID')
if _parent is not None and (not _parent.isdigit() or int(_parent) != os.getppid()):
    raise RuntimeError('acceptance_supervisor_parent_changed')

ROOT = Path('/tmp/devres-upgrade-1d76fbcc-20261115')
BUNDLE = Path('/var/lib/devres-production-upgrades/1d76fbcc-20261115')
CONTROLLER = Path('/usr/local/libexec/devres-upgrade-1d76fbcc/upgrade-controller.py')
CHECKPOINT = CONTROLLER.parent / 'physical-checkpoint.py'
RESTORE = CONTROLLER.parent / 'restore-controller.py'
REVISION = '1d76fbcc5693efc9ca927fd05f942078f667f056'
SMOKE_SHA = '0a7db0771b066e5cb74e08c3a7d01d5098da0eea0962c67ccaa8271d63e7e601'
RUNTIMES = {
    'target': {'revision': REVISION, 'schema': 19, 'version': '0.1.0-build.1d76fbcc',
        'probe_image': 'ghcr.io/publicdata-stream/dev-resources-probe@sha256:d8bc8f1bd14a4d8ec21b8855c6c715fd13d168eaaff4c6aacae8efd93f387244',
        'source_sha256': 'bf33e61badcb7c7726acee9bcab561acd0be8dfce402eb9629b056737adbd2bf',
        'source_file': 'source.tar.gz', 'probe_directory': '/tmp/devres-public-probe-1d76fbcc'},
    'fallback': {'revision': '91c7bcb7aed8eede1627bf87254c0567ef48ab7b', 'schema': 18,
        'version': '0.1.0-build.91c7bcb7',
        'probe_image': 'ghcr.io/publicdata-stream/dev-resources-probe@sha256:a0ed3b468b3e7e23b395d2227b66878832cdf149aa4aac28738e8e5aca0cb588',
        'source_sha256': 'd92b3850074b3155866a376824b0a625151be17a260e4ea7bae058fb46f224a9',
        'source_file': 'fallback-source.tar.gz', 'probe_directory': '/tmp/devres-public-probe-91c7bcb7'},
}
RUNTIME = os.environ.get('DEVRES_ACCEPTANCE_RUNTIME', 'target')
if RUNTIME not in RUNTIMES:
    raise RuntimeError('fixed_runtime_required')
IDENTITY = RUNTIMES[RUNTIME]
WORK = ROOT / RUNTIME
SCHEMA = IDENTITY['schema']
VERSION = IDENTITY['version']
SOURCE_URL = 'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/' + VERSION + '/source.tar.gz'
MANIFEST = ROOT / 'source-manifest.json'
SOURCE_NAMES = {'acceptance_common.py', 'operational-proof.py', 'target-private-acceptance.py',
    'observation-loop.py', 'compressed-probe.py', 'acceptance-receipt.py', 'public-matrix.py',
    'runner.py', 'deploy.py', 'process-launch.py', 'process-watch.py', 'sitecustomize.py', 'phase-driver.py', 'store-claim.py', 'mcp_smoke.py',
    'deploy/diagnostics/__init__.py', 'deploy/diagnostics/evidence.py', 'deploy/diagnostics/runner.py',
    'target-native-qualification.json', 'fallback-native-qualification.json'}
SPECIAL_NAMES = {'upgrade-controller.py': CONTROLLER, 'physical-checkpoint.py': CHECKPOINT,
                 'restore-controller.py': RESTORE, 'npm-recovery.py': CONTROLLER.parent / 'npm-recovery.py',
                 'safety-supervisor.py': CONTROLLER.parent / 'safety-supervisor.py',
                 'restore-rehearsal.py': CONTROLLER.parent / 'restore-rehearsal.py'}


def need(value, code):
    if not value:
        raise RuntimeError(code)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def private_bytes(path, maximum=8 * 1024**2):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'private_path_required')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        m = os.fstat(stream.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == os.geteuid() and m.st_nlink == 1
             and not m.st_mode & 0o077 and m.st_size <= maximum, 'bounded_private_file_required')
        body = stream.read(maximum + 1)
        n = os.fstat(stream.fileno())
        need(len(body) == m.st_size and (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns)
             == (n.st_dev, n.st_ino, n.st_size, n.st_mtime_ns), 'private_file_changed')
    return body


def manifest_sources(expected=None):
    expected = expected or os.environ.get('DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256', '')
    body = private_bytes(MANIFEST)
    need(re.fullmatch('[0-9a-f]{64}', expected or '') is not None and sha(body) == expected, 'external_source_manifest_hash')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate_source_name')
            result[key] = value
        return result
    values = json.loads(body, object_pairs_hook=unique)
    need(isinstance(values, dict) and set(values) == SOURCE_NAMES | set(SPECIAL_NAMES), 'fixed_source_set_required')
    for name, digest in values.items():
        need(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest) is not None, 'source_digest_required')
        path = SPECIAL_NAMES[name] if name in SPECIAL_NAMES else ROOT / name
        need(sha(private_bytes(path)) == digest, 'acceptance_source_changed')
    need(values['mcp_smoke.py'] == SMOKE_SHA, 'canonical_smoke_identity')
    return values


def runtime_qualification():
    value = json.loads(private_bytes(ROOT / (RUNTIME + '-native-qualification.json')))
    need(value.get('commit') == IDENTITY['revision'] and value.get('architecture') == 'amd64'
         and value.get('anonymous_full_pull') is True and isinstance(value.get('binary_sha256'), str)
         and re.fullmatch('[0-9a-f]{64}', value['binary_sha256']) is not None, 'native_probe_qualification')
    if RUNTIME == 'fallback':
        need(value['binary_sha256'] == '2fd8e53e3eee3091b6a86a56136233f6adaf3e96cad33a6117361a08069cdd4e',
             'fallback_native_probe_identity')
    return value


def bound_module(path, expected, name):
    need(sha(private_bytes(path)) == expected, 'import_source_hash')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def controller():
    sources = manifest_sources()
    module = bound_module(CONTROLLER, sources['upgrade-controller.py'], 'acceptance_exact_controller')
    need(module.REVISION == REVISION and module.BUNDLE == str(BUNDLE), 'controller_identity')
    value = module.Controller(str(BUNDLE), str(BUNDLE / 'plan.json'), 'default')
    state = value.state()
    need(state.get('runtime') == RUNTIME and value.runtime_revision() == IDENTITY['revision']
         and value.runtime_schema() == SCHEMA and value.runtime_version() == VERSION
         and value.probe_image() == IDENTITY['probe_image'], 'runtime_identity')
    return module, value


def parent_command(command):
    need(isinstance(command, (tuple, list)) and command
         and all(isinstance(value, (str, bytes, os.PathLike)) for value in command), 'first_party_argv_required')
    values = [os.fsdecode(value) for value in command]
    need(all('\0' not in value for value in values), 'first_party_argv_required')
    return ['/usr/bin/setpriv', '--pdeathsig', 'KILL', '--', '/usr/bin/env',
        'DEVRES_ACCEPTANCE_PARENT_PID=' + str(os.getpid()),
        'DEVRES_ACCEPTANCE_SUBPROCESS_GUARD=1', 'PYTHONPATH=' + str(ROOT),
        sys.executable, '-B', str(ROOT / 'process-launch.py'), str(os.getpid()), *values]


def install_subprocess_guard():
    """Guard descendants of first-party and imported frozen maintenance modules.

    No preexec callback or thread-unsafe fork hook is used. Every exec refreshes
    its parent metadata; Python descendants install this same guard through the
    source-bound sitecustomize module, including raw subprocess.run call sites.
    """
    if getattr(subprocess.Popen, '_devres_parent_guard', False):
        return
    original = subprocess.Popen
    class ParentBoundPopen(original):
        _devres_parent_guard = True
        def __init__(self, args, *positional, **kwargs):
            need(not kwargs.get('shell') and kwargs.get('executable') is None,
                 'first_party_exec_without_shell_required')
            super().__init__(parent_command(args), *positional, **kwargs)
    subprocess.Popen = ParentBoundPopen
    os.environ['DEVRES_ACCEPTANCE_SUBPROCESS_GUARD'] = '1'
    os.environ['PYTHONPATH'] = str(ROOT)


@contextlib.contextmanager
def parent_lifetime(parent_pid):
    """Admit a watched fork callback before it can acquire a lifecycle lock."""
    need(type(parent_pid) is int and parent_pid > 1 and os.getppid() == parent_pid,
         'callback_supervisor_parent_changed')
    watcher = subprocess.Popen(parent_command([sys.executable, '-B', str(ROOT / 'process-watch.py'),
        str(os.getpid()), str(parent_pid)]), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, close_fds=True)
    closing = threading.Event()
    monitor = None
    try:
        readable, _, _ = select.select([watcher.stdout], [], [], 5)
        need(readable and os.read(watcher.stdout.fileno(), 16) == b'READY\n'
             and watcher.poll() is None, 'callback_watcher_not_ready')
        def check_watcher():
            while not closing.wait(0.02):
                if watcher.poll() is not None:
                    # A killed/OOM watcher cannot execute its own fail-closed
                    # path. Never let the admitted callback continue unguarded.
                    os.kill(os.getpid(), signal.SIGKILL)
        monitor = threading.Thread(target=check_watcher, daemon=True)
        monitor.start()
        yield
    finally:
        closing.set()
        if monitor is not None:
            monitor.join(timeout=0.2)
        if watcher.poll() is None:
            watcher.terminate()
            try:
                watcher.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                watcher.kill()
                watcher.wait(timeout=0.5)
        if watcher.stdout is not None:
            watcher.stdout.close()
