#!/usr/bin/env python3
"""Audit the pinned vendored SDK against its original registry advisory identity.

This supplements cargo audit: RustSec excludes path packages. The disposable
projection changes only rmcp's source/checksum, retaining the actual locked graph.
It never edits the repository lockfile or builds/executes package code.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent.parent
NAME = "rmcp"
VERSION = "3.9.0"
SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUM = "d24a7e92f4bcaa36b97fa93c4fa7ca8f3e669eced949345b3462dba333c7f909"


def project(lockfile: bytes, manifest: bytes) -> bytes:
    """Return a registry-identity projection, preserving every other input byte."""
    package = tomllib.loads(manifest.decode("utf-8")).get("package", {})
    if not isinstance(package, dict) or package.get("name") != NAME or package.get("version") != VERSION:
        raise ValueError("Vendored SDK manifest does not match the pinned identity.")
    locked = tomllib.loads(lockfile.decode("utf-8"))
    if locked.get("version") not in (3, 4):
        raise ValueError("Unsupported Cargo.lock format.")
    packages = locked.get("package")
    if not isinstance(packages, list) or not all(isinstance(item, dict) for item in packages):
        raise ValueError("Malformed locked package graph.")
    selected = [item for item in packages if item.get("name") == NAME]
    if len(selected) != 1:
        raise ValueError("Exactly one pinned vendored SDK lock entry is required.")
    sdk = selected[0]
    if sdk.get("version") != VERSION or "source" in sdk or "checksum" in sdk:
        raise ValueError("SDK lock entry must have the pinned version and path identity.")

    # Cargo's generated package tables have unindented [[package]] headings.
    # Parsing every slice rejects ambiguous headings inside nonstandard strings.
    headings = list(re.finditer(rb"(?m)^\[\[package\]\][ \t]*\r?$", lockfile))
    if len(headings) != len(packages):
        raise ValueError("Ambiguous Cargo.lock package boundaries.")
    insertion = None
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(lockfile)
        block = lockfile[heading.start():end]
        parsed = tomllib.loads(block.decode("utf-8")).get("package")
        if parsed != [packages[index]]:
            raise ValueError("Cargo.lock package boundaries do not match parsed identities.")
        if parsed[0].get("name") == NAME:
            versions = list(re.finditer(rb'(?m)^version[ \t]*=[ \t]*"3\.9\.0"[ \t]*(?:#[^\r\n]*)?\r?\n', block))
            if len(versions) != 1:
                raise ValueError("Unsupported SDK version field encoding.")
            line = versions[0]
            newline = b"\r\n" if line.group().endswith(b"\r\n") else b"\n"
            insertion = (heading.start() + line.end(), newline)
    if insertion is None:
        raise ValueError("Pinned SDK package boundary was not found.")
    position, newline = insertion
    identity = (f'source = "{SOURCE}"'.encode() + newline
                + f'checksum = "{CHECKSUM}"'.encode() + newline)
    projected = lockfile[:position] + identity + lockfile[position:]
    checked = tomllib.loads(projected.decode("utf-8"))
    projected_sdk = next(item for item in checked["package"] if item.get("name") == NAME)
    if projected_sdk.pop("source", None) != SOURCE or projected_sdk.pop("checksum", None) != CHECKSUM:
        raise ValueError("Projected SDK registry identity is invalid.")
    if checked != locked:
        raise ValueError("Projection changed the resolved dependency graph.")
    return projected


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--db", type=Path, help="Use this RustSec advisory database.")
    parser.add_argument("--no-fetch", action="store_true", help="Reuse the already refreshed database.")
    options = parser.parse_args(arguments)
    try:
        projected = project((ROOT / "Cargo.lock").read_bytes(),
                            (ROOT / "vendor/rmcp/Cargo.toml").read_bytes())
        with tempfile.TemporaryDirectory(prefix="devres-vendored-audit-", dir="/tmp") as temporary:
            lockfile = Path(temporary) / "Cargo.lock"
            lockfile.touch(mode=0o600, exist_ok=False)
            lockfile.write_bytes(projected)
            command = ["cargo", "audit", "--file", str(lockfile)]
            if options.db is not None:
                command.extend(["--db", str(options.db)])
            if options.no_fetch:
                command.append("--no-fetch")
            return subprocess.run(command, cwd=ROOT, check=False).returncode
    except (OSError, ValueError) as error:
        detail = str(error) if isinstance(error, ValueError) and not isinstance(error, UnicodeError) else "Could not read inputs or execute cargo audit."
        print(f"Vendored advisory audit failed: {detail}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
