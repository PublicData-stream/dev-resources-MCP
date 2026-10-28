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
from release_event import check, fetch_release, kind_for
from release_images import ARCHES, DIGEST, FAMILIES, REGISTRY

REPOSITORY = "PublicData-stream/dev-resources-MCP"


def command(*arguments: str) -> bytes:
    return subprocess.check_output(["gh", *arguments])


def publication_identity(release: object, tag: str, kind: str, stage: str,
                         captured: tuple[int, bool, bool] | None = None) -> tuple[int, bool, bool]:
    """Validate identity without including untrusted response values in errors."""
    def reject(field: str, reason: str) -> None:
        raise ValueError(f"GitHub Release identity rejected: stage={stage} field={field} reason={reason}")

    if not isinstance(release, dict):
        reject("release", "wrong-type")
    for field, expected_type in (("id", int), ("tag_name", str), ("draft", bool), ("prerelease", bool)):
        if field not in release:
            reject(field, "missing")
        if type(release[field]) is not expected_type:
            reject(field, "wrong-type")
    if release["id"] <= 0:
        reject("id", "invalid")
    if release["tag_name"] != tag:
        reject("tag_name", "mismatch")
    if release["prerelease"] is not (kind != "stable"):
        reject("prerelease", "mismatch")
    if kind != "build" and release["draft"]:
        reject("draft", "mismatch")
    if captured is not None:
        for field, expected in zip(("id", "draft"), captured[:2]):
            if release[field] != expected:
                reject(field, "changed")
    # GitHub's optional immutable field is unnecessary to establish draft
    # mutability: its protections begin at publication. Null is not omission.
    if "immutable" not in release:
        if not release["draft"]:
            reject("immutable", "missing")
        immutable = False
    else:
        immutable = release["immutable"]
        if type(immutable) is not bool:
            reject("immutable", "wrong-type")
    if immutable and (release["draft"] or kind != "build"):
        reject("immutable", "mismatch")
    identity = (release["id"], release["draft"], immutable)
    if captured is not None and immutable is not captured[2]:
        reject("immutable", "changed")
    return identity


def get_release(tag: str) -> dict | None:
    response = subprocess.run(["gh", "api", f"repos/{REPOSITORY}/releases/tags/{tag}"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if response.returncode == 0:
        return json.loads(response.stdout)
    if b"HTTP 404" not in response.stderr:
        raise ValueError("Cannot establish existing GitHub Release state")
    # The by-tag REST endpoint only returns published releases. Discover drafts
    # through the authenticated inventory before deciding that creation is safe.
    pages = json.loads(command("api", f"repos/{REPOSITORY}/releases?per_page=100",
                               "--paginate", "--slurp"))
    if (not isinstance(pages, list) or not pages
            or any(not isinstance(page, list) for page in pages)):
        raise ValueError("Invalid GitHub Release inventory")
    matches = []
    for page in pages:
        for item in page:
            if not isinstance(item, dict) or not isinstance(item.get("tag_name"), str):
                raise ValueError("Invalid GitHub Release inventory")
            if item["tag_name"] == tag:
                matches.append(item)
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("Ambiguous GitHub Release identity")
    release_id = matches[0].get("id")
    if type(release_id) is not int or release_id <= 0:
        raise ValueError("Invalid GitHub Release identity")
    release = fetch_release(str(release_id))
    if (not isinstance(release, dict) or type(release.get("id")) is not int
            or release["id"] != release_id or release.get("tag_name") != tag):
        raise ValueError("GitHub Release identity changed during discovery")
    return release


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
            notes = (
                f"Native amd64 and ARM64 images for `{commit}`.\n\n"
                "Download source.tar.gz for the exact version-stamped corresponding source. "
                "The JSON assets record the accepted image index and platform digests.\n\n"
                "Assisted-by: Codex <codex@openai.com>\n")
            request = Path(temporary) / "request.json"
            request.write_text(json.dumps({"tag_name": tag, "target_commitish": commit,
                                          "name": tag, "body": notes, "draft": True,
                                          "prerelease": True}))
            check(tag, commit, tag_object, kind, release_id)
            response = command("api", f"repos/{REPOSITORY}/releases", "--method", "POST",
                               "--input", str(request))
        # Bind publication to the creation response instead of requiring a new
        # draft to appear immediately in the Release inventory. Never retry POST.
        try:
            release = json.loads(response)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid GitHub Release creation response") from None
        publication_identity(release, tag, kind, "creation")
        if release["draft"] is not True:
            raise ValueError("GitHub Release identity rejected: stage=creation field=draft reason=mismatch")
    captured = publication_identity(release, tag, kind, "initial")
    captured_id, captured_draft, captured_immutable = captured

    def current() -> dict:
        observed = check(tag, commit, tag_object, kind, release_id)
        if not published:
            observed = fetch_release(str(captured_id))
        publication_identity(observed, tag, kind, "publication", captured)
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
        if missing and captured_immutable:
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
