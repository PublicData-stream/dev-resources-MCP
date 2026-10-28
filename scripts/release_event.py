#!/usr/bin/env python3
"""Validate release events and repeat immutable Git and mutable Release fences."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from release_contract import COMMIT, validate

REPOSITORY = "PublicData-stream/dev-resources-MCP"
MAX_EVENT_BYTES = 2_000_000


def kind_for(tag: str, commit: str) -> str:
    version = validate(tag, commit)
    return "build" if "-build." in version else "beta" if "-beta." in version else "stable"


def release_identity(release: object, tag: str, kind: str, release_id: str) -> dict:
    if (not isinstance(release, dict) or type(release.get("id")) is not int
            or str(release["id"]) != release_id or release["id"] <= 0
            or release.get("tag_name") != tag or release.get("draft") is not False
            or release.get("prerelease") is not (kind == "beta")
            or release.get("immutable") is not False):
        raise ValueError("Published Release identity, classification or mutability differs")
    return release


def fetch_release(release_id: str) -> dict:
    raw = subprocess.check_output(["gh", "api", f"repos/{REPOSITORY}/releases/{release_id}"])
    return json.loads(raw)


def tag_fence(tag: str, commit: str, tag_object: str = "") -> str:
    arguments = ["scripts/verify-release-tag.sh", tag, commit]
    if tag_object:
        if not COMMIT.fullmatch(tag_object):
            raise ValueError("Invalid annotated tag object")
        arguments.append(tag_object)
    value = subprocess.check_output(arguments).decode().strip()
    if not COMMIT.fullmatch(value) or (tag_object and value != tag_object):
        raise ValueError("Invalid annotated tag identity")
    return value


def check(tag: str, commit: str, tag_object: str, kind: str, release_id: str) -> dict | None:
    if not COMMIT.fullmatch(tag_object):
        raise ValueError("Repeated publication check requires the captured annotated tag object")
    if kind != kind_for(tag, commit):
        raise ValueError("Release kind does not match tag")
    if kind == "build":
        if release_id:
            raise ValueError("Build candidates require a tag-push identity")
    elif not re.fullmatch(r"[1-9][0-9]*", release_id):
        raise ValueError("Published Release requires its positive API identity")
    tag_fence(tag, commit, tag_object)
    if kind != "build":
        return release_identity(fetch_release(release_id), tag, kind, release_id)
    return None


def validate_event(event: dict, event_name: str, ref: str, commit: str, repository: str) -> dict[str, str]:
    event_repository = event.get("repository")
    if (repository != REPOSITORY or not isinstance(event_repository, dict)
            or event_repository.get("full_name") != REPOSITORY):
        raise ValueError("Release publication is restricted to the canonical repository")
    release_id = ""
    if event_name == "release":
        release = event.get("release")
        if event.get("action") != "published" or not isinstance(release, dict):
            raise ValueError("Release requires a published event")
        tag = release.get("tag_name", "")
        kind = kind_for(tag, commit)
        if kind == "build":
            raise ValueError("Build candidates require tag pushes")
        release_id = str(release.get("id", ""))
        release_identity(release, tag, kind, release_id)
    elif event_name == "push":
        if not ref.startswith("refs/tags/") or event.get("ref") != ref or event.get("deleted") is not False:
            raise ValueError("Build candidate requires an existing tag-push ref")
        tag = ref.removeprefix("refs/tags/")
        kind = kind_for(tag, commit)
        if kind != "build":
            raise ValueError("Stable and beta versions require published Releases")
    else:
        raise ValueError("Unsupported release event")
    if ref != f"refs/tags/{tag}":
        raise ValueError("Event ref differs from release tag")
    tag_object = tag_fence(tag, commit)
    if kind != "build":
        release_identity(fetch_release(release_id), tag, kind, release_id)
    return {"tag": tag, "version": validate(tag, commit), "revision": commit,
            "kind": kind, "tag-object": tag_object, "release-id": release_id}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate")
    repeated = subparsers.add_parser("check")
    for argument in ("tag", "commit", "tag-object", "kind"):
        repeated.add_argument("--" + argument, required=True)
    repeated.add_argument("--release-id", default="")
    args = parser.parse_args()
    if args.command == "check":
        check(args.tag, args.commit, args.tag_object, args.kind, args.release_id)
    else:
        with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as stream:
            raw = stream.read(MAX_EVENT_BYTES + 1)
        if len(raw) > MAX_EVENT_BYTES:
            raise ValueError("Release event is too large")
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("Invalid release event")
        result = validate_event(event, os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"],
                                os.environ["GITHUB_SHA"], os.environ["GITHUB_REPOSITORY"])
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            for key, value in result.items():
                stream.write(f"{key}={value}\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print(f"Release event rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from error
