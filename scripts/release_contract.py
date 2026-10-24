#!/usr/bin/env python3
"""Validate release identities and prepare reproducible, versioned source trees.

Only first-party version surfaces change. Git's tagged source is the baseline;
third-party resolutions and unrelated source edits cannot enter a release.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tomllib


NUMBER = r"(?:0|[1-9][0-9]*)"
TAG = re.compile(rf"v({NUMBER}\.{NUMBER}\.{NUMBER}(?:-beta\.{NUMBER}|-build\.[0-9a-f]{{8}})?)\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
BASE_VERSION = "0.0.0"
EXCLUDED = {".git", ".agents", ".codex", ".aws", "target", ".cache", "__pycache__"}


def validate(tag: str, commit: str) -> str:
    match = TAG.fullmatch(tag)
    if not match or not COMMIT.fullmatch(commit):
        raise ValueError("release requires an allowed version tag and full lowercase commit SHA")
    version = match[1]
    if "-build." in version:
        suffix = version.split("-build.", 1)[1]
        if suffix != commit[:8]:
            raise ValueError("build tag suffix does not match commit SHA")
        if suffix.isdigit() and len(suffix) > 1 and suffix.startswith("0"):
            raise ValueError("numeric SemVer identifier cannot have leading zeros")
    return version


def git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        raise ValueError("cannot read the requested Git source baseline") from error


def source_path(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    if not parts or relative.startswith("/") or any(p in ("..", ".") for p in parts):
        raise ValueError("unsafe source path")
    path = root.joinpath(*parts)
    if any(parent.is_symlink() for parent in (path, *path.parents) if parent != root.parent):
        raise ValueError("source symlinks are not supported")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("source path escapes root")
    return path


def baseline_text(root: Path, commit: str, relative: str) -> str:
    source_path(root, relative)
    return git(root, "show", f"{commit}:{relative}").decode("utf-8")


def version_line(text: str, section: str, old: str, new: str) -> str:
    active = False
    changed = 0
    lines = []
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("["):
            active = line.strip() == section
        if active:
            line, count = re.subn(rf'^(\s*version\s*=\s*)"{re.escape(old)}"',
                                  lambda m: m[1] + json.dumps(new), line)
            changed += count
        lines.append(line)
    if changed != 1:
        raise ValueError(f"expected one baseline version in {section}")
    return "".join(lines)


def dependency_versions(value: object, expected: str, replacement: str, names: set[str]) -> int:
    """Update the parsed graph independently from text edits, then compare both."""
    changed = 0
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"dependencies", "dev-dependencies", "build-dependencies"} and isinstance(child, dict):
                for alias, dependency in child.items():
                    if isinstance(dependency, dict) and "path" in dependency:
                        if dependency.get("package", alias) not in names or dependency.get("version") != expected:
                            raise ValueError("first-party path dependency is outside the exact baseline")
                        dependency["version"] = replacement
                        changed += 1
            else:
                changed += dependency_versions(child, expected, replacement, names)
    return changed


def manifest_versions(text: str, version: str, names: set[str]) -> str:
    expected = tomllib.loads(text)
    count = dependency_versions(expected, BASE_VERSION, version, names)
    lines = []
    actual = 0
    # The repository uses inline path dependencies. Unsupported future forms fail
    # the parsed comparison rather than accidentally rewriting another version.
    for line in text.splitlines(keepends=True):
        if re.search(r'\bpath\s*=\s*"', line):
            line, replacements = re.subn(r'\bversion\s*=\s*"0\.0\.0"',
                                         'version = ' + json.dumps(version), line)
            actual += replacements
        lines.append(line)
    result = "".join(lines)
    if actual != count or tomllib.loads(result) != expected:
        raise ValueError("unsupported or unexpected path-dependency version layout")
    return result


def prepared_sources(root: Path, tag: str, commit: str) -> tuple[str, dict[str, str], dict[str, str]]:
    version = validate(tag, commit)
    workspace_text = baseline_text(root, commit, "Cargo.toml")
    workspace = tomllib.loads(workspace_text)
    if workspace["workspace"]["package"]["version"] != BASE_VERSION:
        raise ValueError("workspace baseline version must be 0.0.0")
    members = workspace["workspace"]["members"]
    if not members or any(not isinstance(m, str) or any(c in m for c in "*?[") for m in members):
        raise ValueError("release requires explicit workspace members")
    original = {"Cargo.toml": workspace_text}
    names = set()
    for member in members:
        relative = str(PurePosixPath(member) / "Cargo.toml")
        text = baseline_text(root, commit, relative)
        package = tomllib.loads(text)["package"]
        if package.get("version") != {"workspace": True} or package["name"] in names:
            raise ValueError("all unique first-party packages must inherit the workspace version")
        names.add(package["name"])
        original[relative] = text
    prepared = {path: manifest_versions(text, version, names) for path, text in original.items()}
    prepared["Cargo.toml"] = version_line(prepared["Cargo.toml"], "[workspace.package]", BASE_VERSION, version)

    lock_text = baseline_text(root, commit, "Cargo.lock")
    lock = tomllib.loads(lock_text)
    expected_lock = copy.deepcopy(lock)
    seen = set()
    for package in expected_lock["package"]:
        if package["name"] in names and "source" not in package:
            if package["version"] != BASE_VERSION or package["name"] in seen:
                raise ValueError("first-party lockfile baseline is inconsistent")
            seen.add(package["name"])
            package["version"] = version
        if "dependencies" in package:
            package["dependencies"] = [
                f"{name} {version}" if name in names and dependency == f"{name} {BASE_VERSION}" else dependency
                for dependency in package["dependencies"]
                for name in [dependency.split(" ", 1)[0]]
            ]
    if seen != names:
        raise ValueError("lockfile does not contain every first-party package")
    blocks = lock_text.split("[[package]]")
    for index in range(1, len(blocks)):
        package = tomllib.loads("[[package]]" + blocks[index])["package"][0]
        if package["name"] in names and "source" not in package:
            blocks[index], count = re.subn(r'(?m)^(version\s*=\s*)"0\.0\.0"',
                                          lambda m: m[1] + json.dumps(version), blocks[index])
            if count != 1:
                raise ValueError("unexpected first-party lockfile version layout")
        for name in names:
            blocks[index] = blocks[index].replace(json.dumps(f"{name} {BASE_VERSION}"), json.dumps(f"{name} {version}"))
    prepared["Cargo.lock"] = "[[package]]".join(blocks)
    if tomllib.loads(prepared["Cargo.lock"]) != expected_lock:
        raise ValueError("lockfile stamping would change third-party resolution")
    original["Cargo.lock"] = lock_text

    deny_text = baseline_text(root, commit, "deny.toml")
    deny = tomllib.loads(deny_text)
    expected_deny = copy.deepcopy(deny)
    seen = set()
    for exception in expected_deny["licenses"]["exceptions"]:
        crate = exception.get("crate", "")
        name = crate.split("@", 1)[0]
        if name in names:
            if crate != f"{name}@{BASE_VERSION}" or exception.get("allow") != ["AGPL-3.0-only"] or name in seen:
                raise ValueError("first-party license exceptions must have exact baseline scope")
            seen.add(name)
            exception["crate"] = f"{name}@{version}"
    if seen != names:
        raise ValueError("missing exact first-party license exception")
    prepared["deny.toml"] = deny_text
    for name in names:
        prepared["deny.toml"] = prepared["deny.toml"].replace(json.dumps(f"{name}@{BASE_VERSION}"), json.dumps(f"{name}@{version}"))
    if tomllib.loads(prepared["deny.toml"]) != expected_deny:
        raise ValueError("license stamping would change unrelated policy")
    original["deny.toml"] = deny_text
    return version, original, prepared


def require_contents(root: Path, expected: dict[str, str]) -> None:
    for relative, text in expected.items():
        if source_path(root, relative).read_bytes() != text.encode():
            raise ValueError(f"unexpected source contents: {relative}")


def stamp(root: Path, tag: str, commit: str) -> str:
    version, original, prepared = prepared_sources(root, tag, commit)
    require_contents(root, original)
    for relative, text in prepared.items():
        source_path(root, relative).write_text(text)
    require_contents(root, prepared)
    return version


def verify_stamped(root: Path, tag: str, commit: str) -> str:
    version, _, prepared = prepared_sources(root, tag, commit)
    require_contents(root, prepared)
    return version


def excluded(relative: str) -> bool:
    path = PurePosixPath(relative)
    return (bool(set(path.parts) & EXCLUDED) or path.name.startswith(".env")
            or path.name.endswith((".key", "-key.pem", ".dump")))


def archive(root: Path, tag: str, commit: str, output: Path) -> dict[str, str]:
    version, _, prepared = prepared_sources(root, tag, commit)
    require_contents(root, prepared)
    metadata = {"commit": commit, "tag": tag, "version": version}
    entries = git(root, "ls-tree", "-rz", "--full-tree", commit).split(b"\0")
    contents = []
    for entry in entries:
        if not entry:
            continue
        header, name = entry.split(b"\t", 1)
        relative = name.decode("utf-8")
        if excluded(relative):
            continue
        mode, kind, _ = header.decode().split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("source archive requires regular tracked files only")
        path = source_path(root, relative)
        baseline = git(root, "show", f"{commit}:{relative}")
        expected = prepared[relative].encode() if relative in prepared else baseline
        if path.read_bytes() != expected:
            raise ValueError(f"unreviewed source change: {relative}")
        contents.append((relative, expected, 0o755 if mode == "100755" else 0o644))
    if not contents:
        raise ValueError("empty source archive")
    prefix = f"dev-resources-MCP-{version}"
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for relative, data, mode in sorted(contents):
            info = tarfile.TarInfo(f"{prefix}/{relative}")
            info.size, info.mode, info.mtime = len(data), mode, 0
            tar.addfile(info, io.BytesIO(data))
    archive_bytes = gzip.compress(tar_bytes.getvalue(), mtime=0)
    digest = hashlib.sha256(archive_bytes).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "source.tar.gz": archive_bytes,
        "source.tar.gz.sha256": f"{digest}  source.tar.gz\n".encode(),
        "release.json": (json.dumps({**metadata, "source_sha256": digest}, indent=2, sort_keys=True) + "\n").encode(),
    }
    if any((output / name).exists() for name in artifacts):
        raise ValueError("refusing to overwrite an existing release artifact")
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
    return {**metadata, "source_sha256": digest}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "stamp", "verify-stamped", "archive"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--tag", required=True)
        sub.add_argument("--commit", required=True)
        sub.add_argument("--root", type=Path, default=Path.cwd())
        if command == "archive":
            sub.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            print(validate(args.tag, args.commit))
        elif args.command == "stamp":
            print(stamp(args.root.resolve(), args.tag, args.commit))
        elif args.command == "verify-stamped":
            print(verify_stamped(args.root.resolve(), args.tag, args.commit))
        else:
            print(json.dumps(archive(args.root.resolve(), args.tag, args.commit, args.output.resolve()), sort_keys=True))
    except (ValueError, KeyError, OSError, tomllib.TOMLDecodeError) as error:
        print(f"release contract: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
