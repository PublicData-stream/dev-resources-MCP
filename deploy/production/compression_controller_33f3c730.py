#!/usr/bin/env python3
"""Canonical source successor for the separately admitted no-store MCP SSE policy."""
import hashlib
import importlib.util
from pathlib import Path
import os
import stat
import sys
sys.dont_write_bytecode = True
IMPLEMENTATION = Path('/usr/local/libexec/devres-upgrade-33f3c730/compression_33f3c730.py')
IMPLEMENTATION_SHA = 'ec9266e1a40b8d0b10b2fda8c8686c2c1487e4900a277c935dff724e90587a21'
if any(p.is_symlink() for p in (IMPLEMENTATION, *IMPLEMENTATION.parents)):
    raise RuntimeError('compression_implementation_symlink')
info = IMPLEMENTATION.stat()
if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
    raise RuntimeError('compression_implementation_permissions')
if hashlib.sha256(IMPLEMENTATION.read_bytes()).hexdigest() != IMPLEMENTATION_SHA:
    raise RuntimeError('compression_implementation_changed')
spec = importlib.util.spec_from_file_location('bound_sse_compression_successor', IMPLEMENTATION)
_implementation_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_implementation_module)
_immutable_predecessor = _implementation_module.frozen()
for name in dir(_immutable_predecessor):
    if not name.startswith('__') and name not in ('Controller', 'main', '_implementation_module', '_immutable_predecessor'):
        globals()[name] = getattr(_immutable_predecessor, name)
Controller = _implementation_module.controller_type(_immutable_predecessor, Path(__file__))
