#!/usr/bin/env python3
"""Collect packaged license/notice texts from the exact locked Cargo graph.

Build-time only. No source downloads beyond Cargo's locked metadata operation.
Output is reproducible for a given package source graph and preserves nested notices.
"""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import shutil
import sys


def collect(destination: Path) -> None:
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"], text=True))
    destination.mkdir(parents=True, exist_ok=True)
    index = []
    missing = []
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        if package["source"] is None:
            continue
        root = Path(package["manifest_path"]).resolve().parent
        target = destination / f'{package["name"]}-{package["version"]}'
        target.mkdir(exist_ok=True)
        found = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or not path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE")):
                continue
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                raise ValueError("Packaged notice points outside package")
            if path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("Packaged notice exceeds build-time limit")
            relative = path.relative_to(root)
            output = target / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(path.read_bytes())
            found.append(str(relative))
        supplemental = Path(__file__).resolve().parent.parent / "third-party" / "licenses" / target.name
        if supplemental.is_dir():
            for path in sorted(supplemental.iterdir()):
                if path.is_file() and not path.is_symlink():
                    output = target / ("upstream-" + path.name)
                    output.write_bytes(path.read_bytes())
                    found.append(output.name)
        record = {"name": package["name"], "version": package["version"],
                  "license": package.get("license"), "repository": package.get("repository"),
                  "source": package["source"], "packaged_notices": found}
        (target / "package.json").write_text(json.dumps(record, indent=2) + "\n")
        if not found:
            # Preserve package-supplied declarations and attribution where no separate text exists.
            for name in ("Cargo.toml", "README.md", "README"):
                path = root / name
                if path.is_file() and path.stat().st_size <= 4 * 1024 * 1024:
                    (target / name).write_bytes(path.read_bytes())
            missing.append(f'{package["name"]}@{package["version"]}')
        index.append(record)
    provenance = Path(__file__).resolve().parent.parent / "third-party" / "licenses" / "provenance.json"
    if provenance.is_file():
        (destination / "supplemental-provenance.json").write_bytes(provenance.read_bytes())
    (destination / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    standard = sysroot / "share" / "doc" / "rust"
    standard_target = destination / "rust-standard-library"
    standard_target.mkdir(exist_ok=True)
    shutil.copyfile(standard / "COPYRIGHT-library.html", standard_target / "COPYRIGHT-library.html")
    shutil.copytree(standard / "licenses", standard_target / "licenses", dirs_exist_ok=True)
    (destination / "README.txt").write_text(
        "Packaged license/notice files from the locked Cargo graph, including build/test/target dependencies.\n"
        "Package source licensing is unchanged. SPDX metadata is inventory, not relicensing.\n"
        "Packages without a standalone notice include their packaged metadata/README instead:\n"
        + "\n".join(missing) + "\n")
    print(f"Collected notices for {len(index)} locked packages; {len(missing)} use packaged metadata/README")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: collect-notices.py OUTPUT_DIRECTORY")
    collect(Path(sys.argv[1]))
