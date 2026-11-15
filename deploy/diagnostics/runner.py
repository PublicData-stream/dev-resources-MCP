"""Local-only bounded diagnostic supervision with independently admitted fencing.

There is deliberately no CLI, cluster adapter, destination, production continuation
or automatic admission. Callers inject trusted first-party commands and callbacks.
Callbacks must not execute inspected packages or issue unapproved provider traffic.
All child output must already satisfy the request-only privacy boundary.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import selectors
import signal
import subprocess
import threading
import time

from .evidence import EventRecorder, EvidenceSink


@dataclass(frozen=True)
class RunOutcome:
    code: str
    exit_code: int | None
    timed_out: bool
    interrupted: bool
    stdout_bytes: int
    stderr_bytes: int
    stdout_retained: int
    stderr_retained: int
    stdout_sha256: str
    stderr_sha256: str
    truncated: bool
    descendant_pipes: bool
    withdrawal_completed: bool
    fence_code: str
    runtime_evidence_complete: bool
    child_cleanup_complete: bool
    persisted: bool


# Linux process isolation is intentional: a blocked fsync or callback cannot hold
# the parent control path. fork also admits trusted local closure fixtures.
CONTEXT = multiprocessing.get_context('fork')


def _collector(root, callback, stop, pipe):
    recorder = None
    try:
        recorder = EventRecorder(root, 'runtime')
        original_record = recorder.record
        ready = [False]
        def first_record(kind, value):
            original_record(kind, value)
            if not ready[0]:
                pipe.send('ready')
                ready[0] = True
        recorder.record = first_record
        callback(recorder, stop)
        pipe.send('complete' if ready[0] and stop.is_set() else 'failed')
    except BaseException:
        try:
            pipe.send('failed')
        except (OSError, EOFError):
            pass
    finally:
        if recorder:
            recorder.close()
        pipe.close()


def _fence(callback, pipe):
    try:
        pipe.send(callback() is True)
    except BaseException:
        try:
            pipe.send(False)
        except (OSError, EOFError):
            pass
    finally:
        pipe.close()


def _persist(root, outcome, stdout, stderr, pipe):
    try:
        with EvidenceSink(root) as sink:
            sink.write('stdout.log', stdout)
            sink.write('stderr.log', stderr)
            # This is deliberately provisional: a signal or missing worker ack
            # may still trigger fencing after this disk write. Only the parent's
            # returned RunOutcome states the final control result.
            candidate = {'version':1, 'kind':'diagnostic-capture-candidate',
                         'final_outcome':False, 'capture':asdict(outcome)}
            sink.write('outcome.json', json.dumps(candidate, sort_keys=True).encode())
        pipe.send(True)
    except BaseException:
        try:
            pipe.send(False)
        except (OSError, EOFError):
            pass
    finally:
        pipe.close()


def _kill_worker(worker):
    if worker is None:
        return
    try:
        if worker.is_alive():
            worker.kill()
    except (OSError, ValueError):
        pass
    try:
        worker.join(timeout=0.2)
    except (OSError, ValueError):
        pass


def _message(pipe, timeout):
    try:
        return pipe.recv() if pipe.poll(timeout) else None
    except (EOFError, OSError):
        return None


def _group_signal(child, sig):
    try:
        os.killpg(child.pid, sig)
    except ProcessLookupError:
        pass


class DiagnosticRunner:
    def __init__(self, root: Path, *, output_limit=4 * 1024**2, evidence_timeout=0.5,
                 fence_timeout=5.0, pipe_grace=0.2):
        if type(output_limit) is not int or not 1 <= output_limit <= 4 * 1024**2:
            raise ValueError('output_bound')
        if any(type(value) not in (float, int) or not 0.02 <= value <= 30
               for value in (evidence_timeout, fence_timeout, pipe_grace)):
            raise ValueError('supervision_bound')
        self.root, self.output_limit = Path(root), output_limit
        self.evidence_timeout, self.fence_timeout, self.pipe_grace = evidence_timeout, fence_timeout, pipe_grace

    def run(self, command, *, timeout_seconds, collect, fence) -> RunOutcome:
        """Run one trusted local attempt; always restore caller signal handlers."""
        if threading.current_thread() is not threading.main_thread():
            raise ValueError('main_thread_required')
        interrupted = [False]
        previous = {}
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, lambda *_: interrupted.__setitem__(0, True))
            return self._run(command, timeout_seconds=timeout_seconds, collect=collect,
                             fence=fence, interrupt=interrupted)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)

    def _run(self, command, *, timeout_seconds, collect, fence, interrupt) -> RunOutcome:
        """One attempt; callbacks receive no command arguments or private payloads.

        `collect(recorder, stop_event)` must record an initial observation before
        the command starts, and run until stop_event. Only finite
        runtime records are accepted. `fence()` must return exactly True to prove
        withdrawal. A false result, exception or deadline is explicitly incomplete.
        Evidence failure always fails this attempt and invokes the fence. Output
        is drained concurrently into fixed-size memory prefixes; all disk I/O is
        isolated from fencing. outcome.json is always a provisional capture,
        never a final success receipt; persisted acknowledges those capture files.
        No callback or process is silently retried.
        """
        if not callable(collect) or not callable(fence):
            raise ValueError('trusted_callbacks_required')
        if type(timeout_seconds) not in (int, float) or not 0.02 <= timeout_seconds <= 3600:
            raise ValueError('command_deadline_bound')
        if not isinstance(command, (tuple, list)) or not command or any(not isinstance(v, str) or '\0' in v for v in command):
            raise ValueError('trusted_command_required')
        if threading.current_thread() is not threading.main_thread():
            raise ValueError('main_thread_required')

        child = collector = None
        stop = None
        collector_pipe = None
        collector_complete = False
        pipes_held = False
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        totals = {'stdout': 0, 'stderr': 0}
        code, exit_code, timed_out = 'setup_failed', None, False
        fence_result, fence_code = False, 'not_required'
        selector = None
        fence_done = False
        cleanup_complete = True

        def stop_group():
            nonlocal cleanup_complete
            if child is None:
                return
            try:
                _group_signal(child, signal.SIGKILL)
            except OSError:
                cleanup_complete = False
                # Direct-child cleanup is best effort; a failed group signal
                # cannot prove descendants stopped and must never skip fencing.
                try:
                    child.kill()
                except OSError:
                    pass

        def withdraw():
            nonlocal fence_done, fence_result, fence_code
            if fence_done:
                return
            fence_done = True
            stop_group()
            receiver = sender = worker = None
            try:
                receiver, sender = CONTEXT.Pipe(duplex=False)
                worker = CONTEXT.Process(target=_fence, args=(fence, sender), daemon=True)
                worker.start()
                sender.close()
                result = _message(receiver, self.fence_timeout)
                fence_result = result is True
                fence_code = 'complete' if fence_result else ('deadline_or_failed' if result is None else 'failed')
            except BaseException:
                fence_code = 'launch_failed'
            finally:
                if receiver is not None:
                    receiver.close()
                if sender is not None:
                    sender.close()
                if worker is not None and worker.pid is not None:
                    _kill_worker(worker)

        try:
            stop = CONTEXT.Event()
            selector = selectors.DefaultSelector()
            collector_pipe, sender = CONTEXT.Pipe(duplex=False)
            collector = CONTEXT.Process(target=_collector, args=(self.root, collect, stop, sender), daemon=True)
            collector.start()
            sender.close()
            if _message(collector_pipe, self.evidence_timeout) != 'ready':
                code = 'runtime_setup_failed'
                withdraw()
            elif interrupt[0]:
                code = 'interrupted'
                withdraw()
            else:
                try:
                    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
                except (OSError, ValueError):
                    code = 'launch_failed'
                    withdraw()
                if child is not None:
                    for name, stream in (('stdout', child.stdout), ('stderr', child.stderr)):
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, name)
                    deadline = time.monotonic() + timeout_seconds
                    exited = None
                    code = 'ok'
                    while selector.get_map() or child.poll() is None:
                        now = time.monotonic()
                        if interrupt[0]:
                            code = 'interrupted'
                            break
                        if now >= deadline:
                            code, timed_out = 'timeout', True
                            break
                        if not collector_complete and collector_pipe.poll():
                            state = _message(collector_pipe, 0)
                            if state != 'complete':
                                code = 'runtime_failed'
                                break
                            collector_complete = True
                        if not collector.is_alive() and not collector_complete:
                            code = 'runtime_failed'
                            break
                        if child.poll() is not None:
                            if exited is None:
                                exited = now
                            if now - exited > self.pipe_grace:
                                pipes_held = bool(selector.get_map())
                                if pipes_held:
                                    code = 'descendant_pipe_deadline'
                                break
                        # Bound every drain turn so an infinite stdout producer
                        # cannot starve stderr, signals or the wall deadline.
                        for key, _ in selector.select(timeout=min(0.02, max(0, deadline - now))):
                            for _ in range(4):
                                try:
                                    block = os.read(key.fileobj.fileno(), 65536)
                                except BlockingIOError:
                                    break
                                if not block:
                                    selector.unregister(key.fileobj)
                                    break
                                name = key.data
                                totals[name] = min(2**63 - 1, totals[name] + len(block))
                                remaining = self.output_limit - len(buffers[name])
                                buffers[name].extend(block[:remaining])
                    exit_code = child.poll()
                    if code == 'ok' and exit_code != 0:
                        code = 'child_failed'
                    if code == 'ok' and any(totals[name] > len(buffers[name]) for name in buffers):
                        code = 'output_truncated'
                    if code != 'ok':
                        # The fence starts without waiting for collector shutdown,
                        # artifact writes or fsync. Child cleanup follows below.
                        withdraw()
        except BaseException:
            code = 'supervision_failed'
            withdraw()
        finally:
            if child is not None:
                # This also kills descendants after a successful direct-child exit.
                stop_group()
                try:
                    child.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    cleanup_complete = False
                if exit_code is None:
                    exit_code = child.poll()
                for stream in (child.stdout, child.stderr):
                    if stream:
                        stream.close()
            if selector is not None:
                selector.close()
            if stop is not None:
                stop.set()
            if collector is not None and collector.pid is not None:
                collector.join(timeout=self.evidence_timeout)
                if collector_pipe:
                    while collector_pipe.poll():
                        state = _message(collector_pipe, 0)
                        if state is None:
                            break
                        if state == 'complete':
                            collector_complete = True
                        elif state == 'failed':
                            collector_complete = False
                            break
                if collector.is_alive():
                    collector_complete = False
                _kill_worker(collector)
            if collector_pipe:
                collector_pipe.close()
            if code == 'ok' and not cleanup_complete:
                code = 'child_cleanup_failed'
                withdraw()
            if code == 'ok' and not collector_complete:
                code = 'runtime_incomplete'
                withdraw()
            # Keep handlers active through bounded persistence, restoring them at
            # the very end so SIGTERM never bypasses child cleanup or fencing.

        stdout, stderr = bytes(buffers['stdout']), bytes(buffers['stderr'])
        outcome = RunOutcome(code, exit_code, timed_out, interrupt[0], totals['stdout'], totals['stderr'],
            len(stdout), len(stderr), hashlib.sha256(stdout).hexdigest(), hashlib.sha256(stderr).hexdigest(),
            any(totals[n] > len(buffers[n]) for n in buffers), pipes_held, fence_result, fence_code,
            collector_complete, cleanup_complete, False)
        receiver = sender = writer = None
        persisted = False
        try:
            receiver, sender = CONTEXT.Pipe(duplex=False)
            writer = CONTEXT.Process(target=_persist, args=(self.root, outcome, stdout, stderr, sender), daemon=True)
            writer.start()
            sender.close()
            persisted = _message(receiver, self.evidence_timeout) is True
        except BaseException:
            pass
        finally:
            if receiver is not None:
                receiver.close()
            if sender is not None:
                sender.close()
            if writer is not None and writer.pid is not None:
                _kill_worker(writer)
        if (not persisted or interrupt[0]) and code == 'ok':
            code = 'interrupted' if interrupt[0] else 'persistence_failed'
            withdraw()
        return replace(outcome, code=code, interrupted=interrupt[0], persisted=persisted,
                       child_cleanup_complete=cleanup_complete,
                       withdrawal_completed=fence_result, fence_code=fence_code)
