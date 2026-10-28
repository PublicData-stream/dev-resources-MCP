#!/usr/bin/env python3
"""Publish exact corresponding source after every image family has succeeded."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from release_contract import validate
from release_event import check, kind_for
from release_images import ARCHES, DIGEST, FAMILIES, REGISTRY

REPOSITORY = "PublicData-stream/dev-resources-MCP"


def command(*arguments: str) -> bytes:
    return subprocess.check_output(["gh", *arguments])


def get_release(tag: str) -> dict | None:
    response = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/releases/tags/{tag}"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if response.returncode == 0:
        return json.loads(response.stdout)
    if b"HTTP 404" in response.stderr:
        return None
    raise ValueError("Cannot establish existing GitHub Release state")


def checksum(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or symlinked release asset")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def assets(source: Path, digests: Path, tag: str, commit: str) -> list[Path]:
    version = validate(tag, commit)
    archive = source / "source.tar.gz"
    digest = checksum(archive)
    expected_checksum = f"{digest}  source.tar.gz\n"
    if (source / "source.tar.gz.sha256").read_text() != expected_checksum:
        raise ValueError("Corresponding source checksum mismatch")
    metadata = json.loads((source / "release.json").read_text())
    if metadata != {"commit": commit, "tag": tag, "version": version, "source_sha256": digest}:
        raise ValueError("Corresponding source identity mismatch")
    result = [archive, source / "source.tar.gz.sha256", source / "release.json"]
    for target in FAMILIES:
        path = digests / f"{target}.json"
        data = json.loads(path.read_text())
        if (data.get("image"), data.get("tag"), data.get("commit")) != (REGISTRY + target, tag, commit):
            raise ValueError("Release image identity mismatch")
        platforms = data.get("platforms", {})
        if set(platforms) != set(ARCHES) or not all(DIGEST.fullmatch(d) for d in [data.get("digest", ""), *platforms.values()]):
            raise ValueError("Release requires every image and both platform digests")
        result.append(path)
    for path in result:
        checksum(path)
    return result


def publish(source: Path, digests: Path, tag: str, commit: str,
            tag_object: str, kind: str, release_id: str = "") -> None:
    files = assets(source, digests, tag, commit)
    if kind != kind_for(tag, commit):
        raise ValueError("Release kind does not match tag")
    published = kind != "build"
    # Read-only preflight precedes even draft creation.
    release = check(tag, commit, tag_object, kind, release_id) if published else None
    if not published:
        check(tag, commit, tag_object, kind, release_id)
        release = get_release(tag)
    if release is None:
        with tempfile.TemporaryDirectory(prefix="devres-release-", dir="/tmp") as temporary:
            notes = Path(temporary) / "notes.txt"
            notes.write_text(
                f"Native amd64 and ARM64 images for `{commit}`.\n\n"
                "Download source.tar.gz for the exact version-stamped corresponding source. "
                "The JSON assets record the accepted image index and platform digests.\n\n"
                "Assisted-by: Codex <codex@openai.com>\n")
            check(tag, commit, tag_object, kind, release_id)
            command("release", "create", tag, "--repo", REPOSITORY, "--verify-tag", "--target", commit,
                    "--draft", "--title", tag, "--notes-file", str(notes), "--prerelease")
        release = get_release(tag)
    if (not isinstance(release, dict) or type(release.get("id")) is not int or release["id"] <= 0
            or release.get("tag_name") != tag or release.get("prerelease") is not (kind != "stable")
            or type(release.get("draft")) is not bool or type(release.get("immutable")) is not bool):
        raise ValueError("Existing GitHub Release identity differs")
    captured_id = release["id"]
    captured_draft = release["draft"]

    def current() -> dict:
        observed = check(tag, commit, tag_object, kind, release_id)
        if not published:
            observed = get_release(tag)
        if (not isinstance(observed, dict) or observed.get("id") != captured_id
                or observed.get("tag_name") != tag or observed.get("draft") is not captured_draft
                or observed.get("prerelease") is not (kind != "stable")
                or observed.get("immutable") is not release["immutable"]):
            raise ValueError("GitHub Release identity changed during publication")
        return observed

    def missing_assets(observed: dict) -> list[Path]:
        existing = observed.get("assets")
        if not isinstance(existing, list) or any(not isinstance(asset, dict) or not isinstance(asset.get("name"), str) for asset in existing):
            raise ValueError("Invalid existing Release asset inventory")
        names = [asset["name"] for asset in existing]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate existing Release assets")
        by_name = {asset["name"]: asset for asset in existing}
        missing = []
        # Validate the entire inventory before any append, including late conflicts.
        for path in files:
            if path.name not in by_name:
                missing.append(path)
                continue
            asset_digest = by_name[path.name].get("digest")
            if asset_digest is None:
                with tempfile.TemporaryDirectory(prefix="devres-release-asset-", dir="/tmp") as temporary:
                    command("release", "download", tag, "--repo", REPOSITORY,
                            "--pattern", path.name, "--dir", temporary)
                    asset_digest = "sha256:" + checksum(Path(temporary) / path.name)
            if asset_digest != "sha256:" + checksum(path):
                raise ValueError("Refusing to replace conflicting GitHub Release asset")
        if missing and observed["immutable"]:
            raise ValueError("Immutable Release is missing required assets")
        return missing

    missing = missing_assets(release)
    for path in missing:
        observed = current()
        # A racing append must match too; never use --clobber.
        if path in missing_assets(observed):
            command("release", "upload", tag, str(path), "--repo", REPOSITORY)
    observed = current()
    if missing_assets(observed):
        raise ValueError("Release is missing required assets after upload")
    if captured_draft:
        command("release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--digests", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag-object", required=True)
    parser.add_argument("--kind", choices=("stable", "beta", "build"), required=True)
    parser.add_argument("--release-id", default="")
    args = parser.parse_args()
    publish(args.source, args.digests, args.tag, args.commit, args.tag_object, args.kind, args.release_id)


if __name__ == "__main__":
    main()
