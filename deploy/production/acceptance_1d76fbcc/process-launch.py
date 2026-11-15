#!/usr/bin/env python3
"""Close the parent-death setup race before executing one first-party command."""
import os
import sys

try:
    if len(sys.argv) < 3 or not sys.argv[1].isdigit() or os.getppid() != int(sys.argv[1]):
        os._exit(125)
    os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
except BaseException:
    os._exit(126)
