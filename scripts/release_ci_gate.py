#!/usr/bin/env python3
"""Require exactly one complete CI and stamped-image production path."""
from __future__ import annotations

import os
import re
import sys


def validate(environment: dict[str, str]) -> str:
    reuse = environment.get("REUSE_CI", "")
    fresh = environment.get("FRESH_CI_RESULT", "")
    images = environment.get("RELEASE_IMAGES_RESULT", "")
    if reuse == "true":
        run = environment.get("REUSED_RUN", "")
        attempt = environment.get("REUSED_ATTEMPT", "")
        if (fresh != "skipped" or images != "success"
                or re.fullmatch(r"[1-9][0-9]*", run) is None
                or re.fullmatch(r"[1-9][0-9]*", attempt) is None):
            raise ValueError("verified CI reuse requires successful stamped images and skipped fresh CI")
        return f"Reused complete CI run {run} attempt {attempt}; stamped native images passed"
    if reuse == "false" and fresh == "success" and images == "skipped":
        return "Fresh complete release CI and stamped native images passed"
    raise ValueError("neither complete release CI path succeeded")


def main() -> int:
    try:
        print(validate(dict(os.environ)))
    except ValueError as error:
        print(f"Release CI gate: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
