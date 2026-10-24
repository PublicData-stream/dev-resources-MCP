#!/usr/bin/env python3
"""Verify and promote tested OCI artifacts. No image build or source-provider I/O."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from release_contract import validate as release_version

FAMILIES = ("server", "probe", "audit-worker")
ARCHES = ("amd64", "arm64")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REGISTRY = "ghcr.io/publicdata-stream/dev-resources-"
SOURCE = "https://github.com/PublicData-stream/dev-resources-MCP"


def command(*args: str) -> bytes:
    return subprocess.check_output(args)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inspect(reference: str, flag: str = "--raw") -> bytes:
    # --config alone pretty-prints JSON, changing its content digest.
    flags = ("--raw", "--config") if flag == "--config" else (flag,)
    return command("skopeo", "inspect", *flags, reference)


def existing_digest(reference: str) -> str | None:
    result = subprocess.run(
        ["skopeo", "inspect", "--raw", "docker://" + reference],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode == 0:
        return "sha256:" + hashlib.sha256(result.stdout).hexdigest()
    # Authentication, transport and rate-limit failures are never absence.
    error = result.stderr.decode("utf-8", errors="replace").lower()
    if any(word in error for word in ("unauthorized", "authentication", "denied", "forbidden", "401", "403", "429", "timeout", "connection")):
        raise ValueError("Cannot establish registry tag state; refusing publication")
    if "manifest unknown" in error or "manifest_unknown" in error or "name unknown" in error:
        return None
    raise ValueError("Cannot establish registry tag state; refusing publication")


def verify(directory: Path, target: str, arch: str, tag: str, commit: str) -> dict:
    version = release_version(tag, commit)
    archive = directory / "image.oci.tar"
    metadata_path = directory / "metadata.json"
    if any(p.is_symlink() or not p.is_file() for p in (archive, metadata_path)):
        raise ValueError("Missing or symlinked image artifact")
    metadata = json.loads(metadata_path.read_text())
    if (metadata.get("schema_version"), metadata.get("target"), metadata.get("platform"),
            metadata.get("archive")) != (1, target, "linux/" + arch, "image.oci.tar"):
        raise ValueError("Image artifact identity mismatch")
    if metadata.get("archive_sha256") != sha256(archive):
        raise ValueError("Image archive checksum mismatch")
    reference = "oci-archive:" + str(archive.resolve())
    raw = inspect(reference)
    manifest = json.loads(raw)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if manifest.get("schemaVersion") != 2 or "manifests" in manifest or manifest.get("mediaType") not in (
            "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"):
        raise ValueError("Expected a single-platform image manifest")
    config_digest = manifest["config"]["digest"]
    layers = [layer["digest"] for layer in manifest["layers"]]
    if not all(DIGEST.fullmatch(d) for d in [digest, config_digest, *layers]):
        raise ValueError("Unsupported image digest")
    if (metadata.get("manifest_digest"), metadata.get("config_digest"),
            metadata.get("layer_digests")) != (digest, config_digest, layers):
        raise ValueError("Image manifest/config/layers mismatch")
    config_raw = inspect(reference, "--config")
    if "sha256:" + hashlib.sha256(config_raw).hexdigest() != config_digest:
        raise ValueError("Image config content checksum mismatch")
    config = json.loads(config_raw)
    if (config.get("os"), config.get("architecture")) != ("linux", arch):
        raise ValueError("Image config platform mismatch")
    labels = config.get("config", {}).get("Labels", {})
    required = {"org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.revision": commit,
                "org.opencontainers.image.version": version,
                "org.opencontainers.image.licenses": "AGPL-3.0-only"}
    if any(labels.get(key) != value for key, value in required.items()):
        raise ValueError("Image source/release labels mismatch")
    return {**metadata, "tag": tag, "commit": commit,
            "image": REGISTRY + target, "arch": arch}


def fence(tag: str, commit: str, tag_object: str) -> None:
    subprocess.run(["scripts/verify-release-tag.sh", tag, commit, tag_object], check=True)


def promote(directory: Path, metadata: dict, tag_object: str) -> dict:
    tag, commit = metadata["tag"], metadata["commit"]
    reference = f'{metadata["image"]}:{tag}-{metadata["arch"]}'
    digest = metadata["manifest_digest"]
    fence(tag, commit, tag_object)
    existing = existing_digest(reference)
    if existing not in (None, digest):
        raise ValueError("Refusing to overwrite a conflicting platform tag")
    if existing is None:
        command("skopeo", "copy", "--preserve-digests",
                "oci-archive:" + str((directory / "image.oci.tar").resolve()),
                "docker://" + reference)
    if existing_digest(reference) != digest:
        raise ValueError("Published platform manifest does not match tested artifact")
    return {**metadata, "platform_reference": reference}


def expected_index(records: list[dict]) -> dict:
    if len(records) != 2 or {r["arch"] for r in records} != set(ARCHES):
        raise ValueError("Exactly one amd64 and one ARM64 artifact are required")
    if len({(r["image"], r["tag"], r["commit"] ) for r in records}) != 1:
        raise ValueError("Mixed release/platform records")
    descriptors = []
    for record in sorted(records, key=lambda r: r["arch"]):
        raw = inspect("docker://" + record["image"] + "@" + record["manifest_digest"])
        manifest = json.loads(raw)
        if "sha256:" + hashlib.sha256(raw).hexdigest() != record["manifest_digest"]:
            raise ValueError("Registry platform digest mismatch")
        descriptors.append({"mediaType": manifest["mediaType"], "size": len(raw),
                            "digest": record["manifest_digest"],
                            "platform": {"os": "linux", "architecture": record["arch"]}})
    return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": descriptors}


def merge(records: list[dict], tag_object: str) -> dict:
    index = expected_index(records)
    first = records[0]
    reference = first["image"] + ":" + first["tag"]
    # Buildx publishes only an index over these already-published digests.
    fence(first["tag"], first["commit"], tag_object)
    existing = existing_digest(reference)
    if existing is None:
        command("docker", "buildx", "imagetools", "create", "--tag", reference,
                *[r["image"] + "@" + r["manifest_digest"] for r in sorted(records, key=lambda r: r["arch"])])
    actual_raw = inspect("docker://" + reference)
    actual = json.loads(actual_raw)
    if actual.get("schemaVersion") != 2 or actual.get("mediaType") not in (
            "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"):
        raise ValueError("Expected a versioned multi-platform index")
    # Preserve an existing identical release, never rewrite a conflicting index.
    actual_descriptors = actual.get("manifests", [])
    comparable = lambda item: (item.get("digest"), item.get("size"), item.get("mediaType"), item.get("platform"))
    if sorted(map(comparable, actual_descriptors)) != sorted(map(comparable, index["manifests"])):
        raise ValueError("Published index conflicts with the tested platform set")
    return {"image": first["image"], "tag": first["tag"], "commit": first["commit"],
            "digest": "sha256:" + hashlib.sha256(actual_raw).hexdigest(),
            "platforms": {r["arch"]: r["manifest_digest"] for r in records}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify", "promote", "merge"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--target", choices=FAMILIES, required=True)
    parser.add_argument("--arch", choices=ARCHES)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag-object")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    release_version(args.tag, args.commit)
    if args.operation == "merge":
        if not args.tag_object:
            parser.error("merge requires --tag-object")
        records = []
        for arch in ARCHES:
            record = json.loads((args.directory / f"{args.target}-{arch}.json").read_text())
            if (record["image"], record["tag"], record["commit"], record["arch"]) != (
                    REGISTRY + args.target, args.tag, args.commit, arch):
                raise ValueError("Promotion record identity mismatch")
            records.append(record)
        result = merge(records, args.tag_object)
    else:
        if not args.arch:
            parser.error("verify/promote require --arch")
        result = verify(args.directory, args.target, args.arch, args.tag, args.commit)
        if args.operation == "promote":
            if not args.tag_object:
                parser.error("promote requires --tag-object")
            result = promote(args.directory, result, args.tag_object)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a") as stream:
            stream.write("digest=" + result.get("digest", result.get("manifest_digest", "")) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"Release image check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
