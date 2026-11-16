"""Future-cycle npm assessment primitives; no production activation entrypoint.

Report bytes stay in the existing private exec frame. Only finite phase records
enter Kubernetes' File-only termination message. Historical rollout sources are
not imported or rewritten here.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
import shlex
import os
import selectors
import signal
import subprocess
import time

REPORT = '/tmp/npm-assessment/report.json'
READY = '/tmp/npm-assessment/ready'
PHASE_FILE = '/tmp/npm-assessment-phases/status'
TERMINATION_FILE = '/tmp/devres-assessment-termination'
FRAME = b'DEVRES_NPM_REPORT_V2\n'
PHASE_FRAME = b'DEVRES_NPM_PHASES_V1\n'
MAX_REPORT = 1024**2 + 1
MAX_PHASE_BYTES = 3072
MAX_PHASE_EVENTS = 48
MAX_STREAM = MAX_REPORT + MAX_PHASE_BYTES + 256
PHASES = frozenset(('wrapper_start', 'cli_start', 'cli_exit', 'ready_write', 'hold_start',
    'parse', 'output_create', 'config_load', 'sql_connect', 'sql_setup', 'lifecycle', 'schema',
    'policy', 'transaction', 'history_select', 'state_select', 'eligibility', 'rollback',
    'report_serialize', 'report_write', 'report_sync'))
WRAPPER_PHASES = frozenset(('wrapper_start', 'cli_start', 'cli_exit', 'ready_write', 'hold_start'))
REASONS = frozenset(('none', 'invalid', 'unavailable', 'permission', 'authentication',
    'connection', 'timeout', 'lock_busy', 'schema', 'integrity', 'missing', 'io', 'capacity', 'unknown'))
POD_REASONS = frozenset(('Completed', 'Error', 'OOMKilled', 'ContainerCannotRun', 'StartError',
    'DeadlineExceeded', 'Evicted', 'NodeLost', 'ContainerCreating', 'PodInitializing', 'ErrImagePull',
    'ImagePullBackOff', 'CrashLoopBackOff', 'CreateContainerConfigError', 'CreateContainerError',
    'RunContainerError', 'InvalidImageName'))


class AssessmentError(RuntimeError):
    """Only fixed first-party codes may be passed to this exception."""


def need(value, code):
    if not value:
        raise AssessmentError(code)


@dataclass(frozen=True)
class Selection:
    job_id: str
    revision: int = 1
    recipe: str = 'npm-materialization-deadline-v1'

    def validate(self):
        need(type(self.job_id) is str and re.fullmatch(r'blake3:[0-9a-f]{64}', self.job_id)
             and type(self.revision) is int and 1 <= self.revision <= 2**63-1
             and self.recipe == 'npm-materialization-deadline-v1', 'invalid_assessment_selection')


def _private_path(value):
    path = PurePosixPath(value)
    need(path.is_absolute() and len(path.parts) >= 4 and path.parts[1] == 'tmp'
         and '..' not in path.parts and str(path) == value, 'invalid_assessment_path')
    return path


def wrapper_script(selection, *, cli='/usr/local/bin/devres-server', report=REPORT,
                   phase_file=PHASE_FILE, termination_file=TERMINATION_FILE, hold_seconds=120):
    """Single CLI attempt; telemetry failure cannot replace the child's status.

    Optional paths/hold support isolated first-party fixtures, never caller input
    or inspected package execution. build_assessment_pod uses the fixed defaults.
    """
    selection.validate()
    report_path, phases = _private_path(report), _private_path(phase_file)
    if termination_file != TERMINATION_FILE:
        _private_path(termination_file)
    need(report_path.parent != phases.parent and type(hold_seconds) is int
         and 0 <= hold_seconds <= 120 and PurePosixPath(cli).is_absolute(), 'invalid_assessment_wrapper')
    ready = str(report_path.parent / 'ready')
    q = shlex.quote
    command = ' '.join(q(value) for value in (cli, 'recover-collection', 'dry-run',
        '/etc/devres/config/serving.toml', '--provider', 'npm', '--job-id', selection.job_id,
        '--revision', str(selection.revision), '--recipe', selection.recipe, '--output', report,
        ))
    return (
        'set -u\numask 077\ntelemetry=0\ntermination=0\n'
        # A new private directory plus noclobber file prevents link/replace reuse.
        f'if mkdir -m 700 {q(str(phases.parent))}; then\n'
        f'  if (set -C; : > {q(phase_file)}); then telemetry=1; fi\nfi\n'
        # The kubelet's finite-only termination mount is intentionally separate.
        f'if [ -f {q(termination_file)} ] && [ ! -L {q(termination_file)} ] '
        f'&& [ ! -s {q(termination_file)} ]; then\n'
        f'  if exec 3>> {q(termination_file)}; then termination=1; fi\nfi\n'
        "emit() { if [ \"$telemetry\" -eq 1 ]; then printf '1\\t%s\\t%s\\t%s\\t0\\t%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" >> "
        + q(phase_file) + ' 2>/dev/null || :; fi; '
        + "if [ \"$termination\" -eq 1 ]; then printf '1\\t%s\\t%s\\t%s\\t0\\t%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" >&3 2>/dev/null || :; fi; }\n"
        + "emit wrapper_start ok none -\nemit cli_start start none -\n"
        + f'set -- {command}\n'
        + f'if [ \"$telemetry\" -eq 1 ]; then set -- \"$@\" --phase-file {q(phase_file)}; fi\n'
        + 'if \"$@\"; then child=0; else child=$?; fi\n'
        'if [ "$child" -eq 0 ]; then emit cli_exit ok none "$child"; '
        'else emit cli_exit error unknown "$child"; exit "$child"; fi\n'
        f"if printf 'DEVRES_NPM_READY_V2\\n' > {q(ready)}; then\n"
        '  emit ready_write ok none -\n'
        'else\n  marker_status=$?\n  emit ready_write error io -\n  exit "$marker_status"\nfi\n'
        'emit hold_start start none -\n'
        f'exec /bin/sleep {hold_seconds}\n')


def read_script(*, report=REPORT, phase_file=PHASE_FILE):
    path = _private_path(report)
    _private_path(phase_file)
    q = shlex.quote
    ready = q(str(path.parent / 'ready'))
    return ('set -eu\n' + f'[ "$(/usr/bin/stat -c \'%u:%a:%h:%s:%F\' {ready})" = \'65532:600:1:20:regular file\' ]\n'
        + f'[ "$(/bin/cat {ready})" = \'DEVRES_NPM_READY_V2\' ]\n'
        + f"/usr/bin/stat -c '%u:%a:%h:%s:%F' {q(report)}\n"
        + "printf 'DEVRES_NPM_REPORT_V2\\n'\n" + f'/bin/cat {q(report)}\n'
        + "printf 'DEVRES_NPM_PHASES_V1\\n'\n"
        + f'if [ -f {q(phase_file)} ]; then /bin/cat {q(phase_file)}; fi\n')


def parse_phases(body):
    """Reject the entire untrusted record stream; never retain raw rejection text."""
    need(isinstance(body, bytes) and 0 < len(body) <= MAX_PHASE_BYTES
         and body.endswith(b'\n'), 'phase_record_unavailable')
    try:
        rows = body.decode('ascii').splitlines()
    except UnicodeDecodeError:
        raise AssessmentError('phase_record_invalid') from None
    need(1 <= len(rows) <= MAX_PHASE_EVENTS, 'phase_record_bound')
    result = []
    elapsed = 0
    for ordinal, row in enumerate(rows):
        fields = row.split('\t')
        need(len(fields) == 6, 'phase_record_invalid')
        version, phase, outcome, reason, millis, child = fields
        need(version == '1' and phase in PHASES and outcome in ('start', 'ok', 'error')
             and reason in REASONS and re.fullmatch(r'0|[1-9][0-9]{0,18}', millis)
             and int(millis) <= 2**63-1, 'phase_record_invalid')
        need((outcome == 'error') == (reason != 'none'), 'phase_record_invalid')
        if phase == 'cli_exit':
            need(re.fullmatch(r'0|[1-9][0-9]{0,2}', child) and int(child) <= 255
                 and (int(child) == 0) == (outcome == 'ok'), 'phase_record_invalid')
        else:
            need(child == '-', 'phase_record_invalid')
        if phase in WRAPPER_PHASES:
            need(millis == '0', 'phase_record_invalid')
        else:
            need(int(millis) >= elapsed, 'phase_record_invalid')
            elapsed = int(millis)
        result.append({'ordinal': ordinal, 'phase': phase, 'outcome': outcome, 'reason': reason,
            'elapsed_ms': None if phase in WRAPPER_PHASES else int(millis),
            'child_exit': None if child == '-' else int(child)})
    return result


def termination_phases(pod, *, uid, image):
    """Read already-fetched status before terminal rejection; no extra I/O."""
    need(pod.get('metadata', {}).get('uid') == uid, 'assessment_uid_changed')
    containers = pod.get('spec', {}).get('containers', [])
    statuses = pod.get('status', {}).get('containerStatuses', [])
    need(type(containers) is list and len(containers) == 1 and type(containers[0]) is dict
         and containers[0].get('image') == image
         and containers[0].get('terminationMessagePolicy') == 'File'
         and containers[0].get('terminationMessagePath') == TERMINATION_FILE,
         'assessment_process_changed')
    if statuses == [] and pod.get('status', {}).get('phase') == 'Pending':
        return None
    if pod.get('status', {}).get('phase') == 'Pending' and type(statuses) is list and len(statuses) == 1:
        value = statuses[0]
        if type(value) is dict and value.get('restartCount') == 0 and not value.get('containerID'):
            return None

    need(type(statuses) is list and len(statuses) == 1 and type(statuses[0]) is dict
         and statuses[0].get('restartCount') == 0
         and type(statuses[0].get('containerID')) is str and bool(statuses[0]['containerID']),
         'assessment_process_changed')
    message = statuses[0].get('state', {}).get('terminated', {}).get('message')
    if type(message) is not str:
        return None
    try:
        return parse_phases(message.encode('ascii'))
    except (AssessmentError, UnicodeEncodeError):
        return None


def pod_failure_metadata(pod):
    """Closed container/wrapper state independent of any CLI phase telemetry."""
    if type(pod) is not dict:
        return None
    metadata, status = pod.get('metadata'), pod.get('status')
    metadata = metadata if type(metadata) is dict else {}
    status = status if type(status) is dict else {}
    uid = metadata.get('uid')
    uid = uid if type(uid) is str and re.fullmatch(
        '[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', uid) else None
    values = status.get('containerStatuses', [])
    values = values if type(values) is list else []
    containers = []
    for value in values[:2]:
        value = value if type(value) is dict else {}
        state = value.get('state', {})
        state = state if type(state) is dict else {}
        kinds = [key for key in ('running', 'waiting', 'terminated') if type(state.get(key)) is dict]
        kind = kinds[0] if len(kinds) == 1 else 'unknown'
        detail = state.get(kind, {})
        reason, exit_code, restart = detail.get('reason'), detail.get('exitCode'), value.get('restartCount')
        containers.append({'state': kind, 'reason': reason if type(reason) is str and reason in POD_REASONS else None,
            'exit_code': exit_code if kind == 'terminated' and type(exit_code) is int and -2**31 <= exit_code < 2**31 else None,
            'restart_count': restart if type(restart) is int and 0 <= restart < 2**31 else None,
            'oom_killed': kind == 'terminated' and reason == 'OOMKilled',
            'container_id_present': type(value.get('containerID')) is str and bool(value['containerID'])})
    reason, phase = status.get('reason'), status.get('phase')
    return {'uid': uid, 'phase': phase if phase in ('Pending', 'Running', 'Succeeded', 'Failed', 'Unknown') else None,
        'reason': reason if type(reason) is str and reason in POD_REASONS else None,
        'container_status_count': min(len(values), 2), 'container_statuses_truncated': len(values) > 2,
        'containers': containers}


def build_assessment_pod(template, image, selection, name, namespace, scope='fixture'):
    selection.validate()
    need(all(type(value) is str and re.fullmatch('[a-z0-9][a-z0-9-]{0,62}', value)
             for value in (name, namespace, scope)), 'invalid_assessment_identity')
    spec = copy.deepcopy(template['spec'])
    containers = spec.get('containers', [])
    need(len(containers) == 1 and containers[0].get('image') == image, 'assessment_image_changed')
    container = containers[0]
    security, local = spec.get('securityContext', {}), container.get('securityContext', {})
    need(security.get('runAsNonRoot') is True and security.get('runAsUser') == 65532
         and security.get('fsGroup') == 65532 and security.get('seccompProfile') == {'type': 'RuntimeDefault'}
         and security.get('runAsGroup', 65532) == 65532
         and local.get('runAsUser', 65532) == 65532 and local.get('runAsGroup', 65532) == 65532
         and local.get('runAsNonRoot', True) is True
         and local.get('seccompProfile', {'type': 'RuntimeDefault'}) == {'type': 'RuntimeDefault'}
         and local.get('appArmorProfile', security.get('appArmorProfile')) == {'type': 'Localhost', 'localhostProfile': 'devres-runtime'}
         and local.get('procMount', 'Default') == 'Default'
         and local.get('allowPrivilegeEscalation') is False and local.get('readOnlyRootFilesystem') is True
         and local.get('capabilities', {}).get('drop') == ['ALL']
         and not local.get('capabilities', {}).get('add') and not local.get('privileged')
         and not any(spec.get(key) for key in ('hostNetwork', 'hostPID', 'hostIPC')), 'assessment_security_changed')
    volumes = {value['name']: value for value in spec.get('volumes', [])}
    mounts = {value['name']: value for value in container.get('volumeMounts', [])}
    need(all('secret' in volumes.get(key, {}) and mounts.get(key, {}).get('readOnly') is True
             for key in ('config', 's3')) and 'emptyDir' in volumes.get('tmp', {})
         and mounts.get('config', {}).get('mountPath') == '/etc/devres/config'
         and mounts.get('s3', {}).get('mountPath') == '/run/devres-s3'
         and mounts.get('tmp', {}).get('mountPath') == '/tmp', 'assessment_mount_changed')
    spec.update(restartPolicy='Never', activeDeadlineSeconds=450, terminationGracePeriodSeconds=15,
                automountServiceAccountToken=False)
    for key in ('affinity', 'initContainers', 'ephemeralContainers'):
        spec.pop(key, None)
    spec['volumes'] = [volumes['config'], volumes['s3'], {'name': 'tmp', 'emptyDir': {'sizeLimit': '16Mi'}}]
    container['volumeMounts'] = [mounts[key] for key in ('config', 's3', 'tmp')]
    container['name'] = 'assessment'
    container['terminationMessagePath'] = TERMINATION_FILE
    container['terminationMessagePolicy'] = 'File'
    container['command'] = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=5s', '420s',
                            '/bin/sh', '-c', wrapper_script(selection)]
    for key in ('args', 'ports', 'readinessProbe', 'livenessProbe', 'startupProbe', 'env', 'envFrom', 'lifecycle'):
        container.pop(key, None)
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace,
        'labels': {'app': 'backend', 'devres-assessment': scope}}, 'spec': spec}


def validate_report(value, selection):
    selection.validate()
    need(type(value) is dict and set(value) == {'version', 'job_id', 'revision', 'recipe', 'state_digest',
        'eligible', 'outcome', 'reason', 'operation_id', 'publication_snapshot'}
        and type(value['version']) is int and value['version'] == 1
        and value['job_id'] == selection.job_id and type(value['revision']) is int
        and value['revision'] == selection.revision and value['recipe'] == selection.recipe
        and value['eligible'] is False and value['outcome'] == 'ineligible'
        and value['operation_id'] is None and value['publication_snapshot'] is None
        and type(value['state_digest']) is str and re.fullmatch(r'blake3:[0-9a-f]{64}', value['state_digest'])
        and value['reason'] in ('legacy_unknown', 'already_published'), 'sealed_legacy_ineligibility_required')
    return value


def decode_report_frame(body, selection):
    need(type(body) is bytes and 0 < len(body) <= MAX_STREAM, 'assessment_stream_bound')
    metadata, separator, remaining = body.partition(b'\n')
    try:
        fields = metadata.decode('ascii').split(':', 4)
    except UnicodeDecodeError:
        raise AssessmentError('assessment_metadata_invalid') from None
    need(separator and len(fields) == 5 and fields[:3] == ['65532', '600', '1']
         and fields[4] == 'regular file' and re.fullmatch('[0-9]{1,7}', fields[3]), 'assessment_metadata_invalid')
    size = int(fields[3])
    need(0 < size <= MAX_REPORT and remaining.startswith(FRAME), 'assessment_frame_invalid')
    remaining = remaining[len(FRAME):]
    report, phases = remaining[:size], remaining[size:]
    need(len(report) == size and phases.startswith(PHASE_FRAME), 'assessment_frame_incomplete')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'assessment_duplicate_field')
            result[key] = value
        return result
    try:
        value = json.loads(report, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError):
        raise AssessmentError('assessment_report_invalid') from None
    validate_report(value, selection)
    try:
        events = parse_phases(phases[len(PHASE_FRAME):])
    except AssessmentError:
        events = None
    return report, value, events


def cleanup_before_persist(cleanup, persist, body):
    """An evidence error cannot leave the credential-bearing process running."""
    cleanup()
    persist(body)


def report_exchange(command, timeout=5):
    """Bound both streams while reading; raw stderr is discarded, never retained."""
    need(0 < timeout <= 5, 'assessment_exchange_deadline')
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    selector = selectors.DefaultSelector()
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    limits = {'stdout': MAX_STREAM, 'stderr': 4096}
    deadline = time.monotonic() + timeout
    try:
        for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            need(time.monotonic() < deadline, 'assessment_exchange_deadline')
            for key, _ in selector.select(min(.05, max(0, deadline-time.monotonic()))):
                for _ in range(4):
                    try:
                        chunk = os.read(key.fileobj.fileno(), min(65536, limits[key.data]-len(buffers[key.data])+1))
                    except BlockingIOError:
                        break
                    if not chunk:
                        selector.unregister(key.fileobj)
                        break
                    buffers[key.data].extend(chunk)
                    need(len(buffers[key.data]) <= limits[key.data], 'assessment_exchange_bound')
        return bytes(buffers['stdout']) if process.returncode == 0 else None
    finally:
        selector.close()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=.5)
        except subprocess.TimeoutExpired:
            pass
        process.stdout.close()
        process.stderr.close()


def supervise(*, get_pod, read_report, cleanup, persist, selection, uid, image,
              persist_failure=None, timeout=330, pause=time.sleep):
    """Observe one admitted Pod. All callbacks are first-party and bounded.

    read_report receives a maximum per-exec timeout (<=5s). get_pod and cleanup
    retain the caller's independently admitted Kubernetes request/UID fences.
    Persistence always happens after cleanup; callback errors cannot cause retry.
    """
    need(type(timeout) in (int, float) and 0 < timeout <= 330, 'assessment_supervision_deadline')
    deadline = time.monotonic() + timeout
    phases = None
    failure = None
    result = None
    container_id = None
    last_pod = None
    try:
        while True:
            pod = get_pod()
            last_pod = pod_failure_metadata(pod)
            # Terminal metadata is extracted before the terminal Pod is rejected.
            phases = termination_phases(pod, uid=uid, image=image)
            status = pod.get('status', {})
            phase = status.get('phase')
            if phase in ('Succeeded', 'Failed'):
                raise AssessmentError('assessment_container_ended')
            need(time.monotonic() < deadline, 'assessment_supervision_deadline')
            if phase == 'Running':
                identity = status['containerStatuses'][0]['containerID']
                if container_id is not None:
                    need(identity == container_id, 'assessment_process_changed')
                container_id = identity
                body = read_report(min(5, max(.001, deadline-time.monotonic())))
                after = get_pod()
                last_pod = pod_failure_metadata(after)
                after_phases = termination_phases(after, uid=uid, image=image)
                if after_phases is not None:
                    phases = after_phases
                need(after['status']['containerStatuses'][0]['containerID'] == identity,
                     'assessment_process_changed')
                need(after['status'].get('phase') not in ('Succeeded', 'Failed'), 'assessment_container_ended')
                if body is not None:
                    result = decode_report_frame(body, selection)
                    break
            pause(min(1, max(0, deadline-time.monotonic())))
    except BaseException as error:
        failure = error
    finally:
        cleanup()
    if failure is not None:
        if persist_failure is not None:
            try:
                persist_failure({'version': 1, 'kind': 'npm-assessment-failure',
                    'phases': phases, 'phase_known': phases is not None, 'last_pod': last_pod})
            except BaseException:
                pass
        raise failure
    persist(result[0])
    return result
