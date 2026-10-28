#!/usr/bin/env python3
"""Accept published release digests only after provenance and full anonymous pulls."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from release_contract import validate
from release_images import ARCHES, DIGEST, FAMILIES, REGISTRY, SOURCE

REPOSITORY = "PublicData-stream/dev-resources-MCP"
WORKFLOW = REPOSITORY + "/.github/workflows/publish-images.yml"
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
MAX_JSON_BYTES = 2_000_000


def temporary_path(path: Path) -> Path:
    resolved = path.resolve()
    if Path("/tmp") not in resolved.parents:
        raise ValueError("Release acceptance state must be below /tmp")
    return resolved


def json_object(raw: bytes) -> dict:
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("Oversized release metadata")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Release metadata must be an object")
    return value


def content_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require_digest(value: object) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError("Unsupported release digest")
    return value


def load_records(directory: Path, tag: str, commit: str) -> list[dict]:
    validate(tag, commit)
    records = []
    for target in FAMILIES:
        path = directory / f"{target}.json"
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked release digest record")
        record = json_object(path.read_bytes())
        if (record.get("image"), record.get("tag"), record.get("commit")) != (REGISTRY + target, tag, commit):
            raise ValueError("Release digest identity mismatch")
        require_digest(record.get("digest"))
        platforms = record.get("platforms")
        if not isinstance(platforms, dict) or set(platforms) != set(ARCHES):
            raise ValueError("Release requires exactly amd64 and arm64")
        for digest in platforms.values():
            require_digest(digest)
        records.append(record)
    return records


def anonymous_environment(root: Path) -> dict[str, str]:
    """Explicit no-creds flags also prevent credential-helper fallback by Skopeo."""
    root = temporary_path(root)
    environment = os.environ.copy()
    for name in ("DOCKER_AUTH_CONFIG", "REGISTRY_AUTH_FILE", "DOCKER_CONFIG", "GH_CONFIG_DIR"):
        environment.pop(name, None)
    for variable, child in (("DOCKER_CONFIG", "docker"), ("GH_CONFIG_DIR", "gh"),
                            ("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"),
                            ("XDG_RUNTIME_DIR", "runtime"), ("TMPDIR", "tmp")):
        path = root / child
        path.mkdir(mode=0o700)
        environment[variable] = str(path)
    auth = root / "auth.json"
    auth.write_text('{"auths":{}}\n')
    auth.chmod(0o600)
    environment["REGISTRY_AUTH_FILE"] = str(auth)
    return environment


def command(arguments: list[str], environment: dict[str, str], *, timeout: int = 120) -> bytes:
    result = subprocess.run(arguments, env=environment, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        # Child output may include credential-helper diagnostics; do not echo it.
        raise ValueError(f"{arguments[0]} release verification failed")
    return result.stdout


def anonymous_manifest(reference: str, environment: dict[str, str]) -> bytes:
    raw = command(["skopeo", "inspect", "--no-creds", "--raw", "docker://" + reference], environment)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("Oversized registry manifest")
    return raw


def verify_index(record: dict, environment: dict[str, str]) -> dict[str, dict]:
    raw = anonymous_manifest(record["image"] + ":" + record["tag"], environment)
    if content_digest(raw) != record["digest"]:
        raise ValueError("Anonymous version index digest mismatch")
    index = json_object(raw)
    descriptors = index.get("manifests")
    if index.get("schemaVersion") != 2 or index.get("mediaType") not in INDEX_TYPES or not isinstance(descriptors, list) or len(descriptors) != len(ARCHES):
        raise ValueError("Expected one complete multi-platform index")
    result = {}
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            raise ValueError("Malformed platform descriptor")
        platform = descriptor.get("platform")
        if not isinstance(platform, dict):
            raise ValueError("Missing index platform")
        arch = platform.get("architecture")
        if (platform != {"os": "linux", "architecture": arch} or arch not in ARCHES or arch in result
                or descriptor.get("digest") != record["platforms"][arch]
                or descriptor.get("mediaType") not in MANIFEST_TYPES
                or type(descriptor.get("size")) is not int or descriptor["size"] <= 0):
            raise ValueError("Index does not match recorded platform descriptors")
        result[arch] = descriptor
    return result


def verify_provenance(image: str, digest: str, tag: str, commit: str,
                      environment: dict[str, str]) -> None:
    arguments = ["gh", "attestation", "verify", "oci://" + image + "@" + digest,
                 "--bundle-from-oci", "--repo", REPOSITORY,
                 "--source-digest", commit, "--source-ref", "refs/tags/" + tag,
                 "--signer-workflow", WORKFLOW]
    for attempt in range(3):
        try:
            command(arguments, environment)
            return
        except (ValueError, subprocess.TimeoutExpired):
            if attempt == 2:
                raise ValueError("Release provenance could not be verified") from None
            time.sleep(5)


def blob(directory: Path, descriptor: dict) -> Path:
    digest = require_digest(descriptor.get("digest"))
    size = descriptor.get("size")
    if type(size) is not int or size < 0:
        raise ValueError("Invalid OCI blob size")
    path = directory / "blobs" / "sha256" / digest.removeprefix("sha256:")
    if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
        raise ValueError("Missing or wrong-sized downloaded OCI blob")
    with path.open("rb") as stream:
        actual = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != digest:
        raise ValueError("Downloaded OCI blob digest mismatch")
    return path


def verify_download(directory: Path, record: dict, arch: str, descriptor: dict) -> None:
    manifest_path = blob(directory, descriptor)
    manifest = json_object(manifest_path.read_bytes())
    if (manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != descriptor["mediaType"]
            or "manifests" in manifest or not isinstance(manifest.get("config"), dict)
            or not isinstance(manifest.get("layers"), list)):
        raise ValueError("Expected a downloaded single-platform image")
    configuration = json_object(blob(directory, manifest["config"]).read_bytes())
    if (configuration.get("os"), configuration.get("architecture")) != ("linux", arch):
        raise ValueError("Downloaded image platform mismatch")
    config = configuration.get("config", {})
    labels = config.get("Labels", {}) if isinstance(config, dict) else {}
    expected = {"org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.revision": record["commit"],
                "org.opencontainers.image.version": validate(record["tag"], record["commit"]),
                "org.opencontainers.image.licenses": "AGPL-3.0-only"}
    if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in expected.items()):
        raise ValueError("Downloaded image source/release labels mismatch")
    for layer in manifest["layers"]:
        if not isinstance(layer, dict):
            raise ValueError("Invalid image layer descriptor")
        blob(directory, layer)


def accept(digests: Path, tag: str, commit: str, output: Path) -> dict:
    version = validate(tag, commit)
    records = load_records(digests, tag, commit)
    output = temporary_path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Refusing to replace an accepted digest record")
    with tempfile.TemporaryDirectory(prefix="devres-release-acceptance-", dir="/tmp") as scratch:
        root = Path(scratch)
        environment = anonymous_environment(root)
        for record in records:
            descriptors = verify_index(record, environment)
            verify_provenance(record["image"], record["digest"], tag, commit, environment)
            for arch in ARCHES:
                digest = record["platforms"][arch]
                verify_provenance(record["image"], digest, tag, commit, environment)
                # Each platform starts empty, proving every layer can be fetched anonymously.
                with tempfile.TemporaryDirectory(prefix="platform-", dir=root) as platform:
                    destination = Path(platform) / "image"
                    command(["skopeo", "copy", "--src-no-creds", "--preserve-digests",
                             "docker://" + record["image"] + "@" + digest,
                             "oci:" + str(destination) + ":accepted"], environment, timeout=600)
                    verify_download(destination, record, arch, descriptors[arch])
    accepted = {"tag": tag, "version": version, "commit": commit, "images": records}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(accepted, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return accepted


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digests", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        accept(arguments.digests, arguments.tag, arguments.commit, arguments.output)
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired):
        print("Release acceptance failed; any published images remain a partial publication", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
