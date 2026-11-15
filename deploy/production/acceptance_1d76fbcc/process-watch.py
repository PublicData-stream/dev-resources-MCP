#!/usr/bin/env python3
"""Fail closed if an owned fork callback loses its supervising parent."""
import os
import signal
import sys
import time

admitted = False
target = None
try:
    if len(sys.argv) != 3 or not all(v.isdigit() for v in sys.argv[1:]):
        os._exit(125)
    target, parent = map(int, sys.argv[1:])
    if target <= 1 or parent <= 1 or os.getppid() != target:
        os._exit(125)
    admitted = True
    ready = False
    while True:
        with open('/proc/' + str(target) + '/status', encoding='ascii') as stream:
            value = stream.read(65536)
        ppid = next(int(row.split(':', 1)[1]) for row in value.splitlines() if row.startswith('PPid:'))
        if ppid != parent:
            raise RuntimeError('supervisor_parent_changed')
        if not ready:
            os.write(sys.stdout.fileno(), b'READY\n')
            ready = True
        time.sleep(0.05)
except BaseException:
    # Never signal a PID after reparenting; the admitted callback must still be
    # this watcher's actual parent. Missing/invalid proc evidence fails closed.
    if admitted and target is not None and os.getppid() == target:
        try:
            os.kill(target, signal.SIGKILL)
        except ProcessLookupError:
            pass
    os._exit(1)
