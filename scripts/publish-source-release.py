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


def publish(source: Path, digests: Path, tag: str, commit: str) -> None:
    files = assets(source, digests, tag, commit)
    release = get_release(tag)
    prerelease = "-" in validate(tag, commit)
    if release is None:
        with tempfile.TemporaryDirectory(prefix="devres-release-") as temporary:
            notes = Path(temporary) / "notes.txt"
            notes.write_text(
                f"Native amd64 and ARM64 images for `{commit}`.\n\n"
                "Download source.tar.gz for the exact version-stamped corresponding source. "
                "The JSON assets record the image index and platform digests. "
                "Public GHCR visibility and anonymous pulls require separate verification.\n\n"
                "Assisted-by: Codex <codex@openai.com>\n")
            command("release", "create", tag, "--repo", REPOSITORY, "--verify-tag", "--target", commit,
                    "--draft", "--title", tag, "--notes-file", str(notes),
                    *(["--prerelease"] if prerelease else []))
        release = get_release(tag)
    if release is None or release.get("tag_name") != tag or release.get("target_commitish") != commit or release.get("prerelease") != prerelease:
        raise ValueError("Existing GitHub Release identity differs")
    existing = {asset["name"]: asset for asset in release.get("assets", [])}
    for path in files:
        if path.name in existing:
            asset_digest = existing[path.name].get("digest")
            if asset_digest is None:
                with tempfile.TemporaryDirectory(prefix="devres-release-asset-") as temporary:
                    command("release", "download", tag, "--repo", REPOSITORY,
                            "--pattern", path.name, "--dir", temporary)
                    asset_digest = "sha256:" + checksum(Path(temporary) / path.name)
            if asset_digest != "sha256:" + checksum(path):
                raise ValueError("Refusing to replace conflicting GitHub Release asset")
        elif not release.get("draft"):
            raise ValueError("Published release is missing a required asset; refusing mutation")
        else:
            command("release", "upload", tag, str(path), "--repo", REPOSITORY)
    if release.get("draft"):
        command("release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--digests", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    publish(args.source, args.digests, args.tag, args.commit)


if __name__ == "__main__":
    main()
