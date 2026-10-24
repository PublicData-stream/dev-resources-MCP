#!/usr/bin/env python3
"""Synthetic, offline image smoke fixtures and exported-image integrity checks."""
import hashlib
import json
from pathlib import Path
import re
import sys
import time


SENTINEL = "SYNTHETIC_PRIVATE_INPUT_SENTINEL"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")


def worker_input(valid=True):
    now = int(time.time())
    capture = {"id": "a" * 64, "key": "rustsec:head", "source_url": "https://api.github.com/repos/RustSec/advisory-db/commits/main",
               "body_hash": "b" * 64, "media_type": "application/json", "retrieved_at": now, "validated_at": now}
    advisory = {"advisory": {"id": "RUSTSEC-2024-0001", "package": "example", "title": "Synthetic image fixture",
                              "description": "Fixture only.", "date": "2024-01-01", "collection": "crates"},
                "versions": {"patched": [">=1.0.1"], "unaffected": []}}
    lockfile = 'version = 4\n[[package]]\nname = "example"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
    return {"lockfile": lockfile if valid else f"{SENTINEL} = invalid toml",
            "snapshot": {"head": capture, "bundle": capture, "revision": "c" * 40, "advisories": [advisory]},
            "page": {"offset": 0, "limit": 20}}


def check_worker(mode, stdout, stderr):
    if stderr or SENTINEL.encode() in stdout:
        raise ValueError("Worker reflected private fixture data or wrote stderr")
    report = json.loads(stdout)
    if mode == "valid":
        if set(report) != {"Ok"} or report["Ok"].get("assessed_count") != 1 or report["Ok"].get("vulnerability_count") != 1:
            raise ValueError("Worker did not assess the synthetic advisory")
    elif set(report) != {"Err"} or report["Err"].get("code") != "invalid_input":
        raise ValueError("Worker did not return a sanitized invalid-input result")


def check_startup(target, stdout, stderr):
    if stdout:
        raise ValueError("Startup failure unexpectedly wrote stdout")
    expected = b"usage: devres-probe" if target == "probe" else b"/missing.toml"
    # std::fs errors may omit the path, but must report the config/I/O failure.
    if expected not in stderr and not (target == "server" and b"No such file or directory" in stderr):
        raise ValueError("Executable did not return the expected startup error")


def inspect_image(records, platform, target):
    if len(records) != 1:
        raise ValueError("Expected exactly one image")
    image = records[0]
    config = image["Config"]
    if f'{image["Os"]}/{image["Architecture"]}' != platform or config["User"] != "65532:65532":
        raise ValueError("Image platform or non-root identity differs")
    binary = {"runtime": "server", "server": "server", "probe": "probe", "audit-worker": "audit-worker"}[target]
    if config.get("Entrypoint") != [f"/usr/local/bin/devres-{binary}"]:
        raise ValueError("Image entrypoint differs from selected target")
    expected_cmd = ["/etc/devres/server.toml"] if binary == "server" else None
    if config.get("Cmd") not in (expected_cmd, [] if expected_cmd is None else expected_cmd):
        raise ValueError("Image default arguments differ from selected target")
    if not DIGEST.fullmatch(image["Id"]):
        raise ValueError("Expected an immutable image ID")
    if "Descriptor" in image:
        descriptor = image["Descriptor"]
        if descriptor.get("mediaType") not in MANIFEST_TYPES or descriptor.get("digest") != image["Id"]:
            raise ValueError("Docker descriptor must identify the tested single-platform manifest")
    return image["Id"]


def manifest_parts(raw):
    document = json.loads(raw)
    if document.get("mediaType") not in MANIFEST_TYPES or document.get("schemaVersion") != 2 or "manifests" in document:
        raise ValueError("Expected a single image manifest")
    config = document["config"]["digest"]
    layers = [layer["digest"] for layer in document["layers"]]
    if not all(DIGEST.fullmatch(digest) for digest in [config, *layers]):
        raise ValueError("Invalid image content digest")
    return config, layers


def export_metadata(directory, archive_raw, images, platform, target):
    archived = manifest_parts(archive_raw)
    inspect_image(images, platform, target)
    image = images[0]
    manifest_digest = "sha256:" + hashlib.sha256(archive_raw).hexdigest()
    # Docker's OCI import must preserve the canonical manifest, or (with the
    # classic store) its exact config, which binds every uncompressed layer.
    expected_id = manifest_digest if "Descriptor" in image else archived[0]
    if image["Id"] != expected_id:
        raise ValueError("Loaded image differs from the canonical OCI artifact")
    archive = directory / "image.oci.tar"
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    metadata = {"schema_version": 1, "target": target, "platform": platform, "archive": archive.name,
                "archive_sha256": digest, "manifest_digest": manifest_digest,
                "config_digest": archived[0], "layer_digests": archived[1]}
    (directory / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


def main(arguments):
    command, *args = arguments
    if command == "input":
        print(json.dumps(worker_input(args[0] == "valid")))
    elif command == "worker":
        check_worker(args[0], Path(args[1]).read_bytes(), Path(args[2]).read_bytes())
    elif command == "startup":
        check_startup(args[0], Path(args[1]).read_bytes(), Path(args[2]).read_bytes())
    elif command == "inspect":
        print(inspect_image(json.loads(Path(args[0]).read_text()), args[1], args[2]))
    elif command == "metadata":
        export_metadata(Path(args[0]), Path(args[1]).read_bytes(),
                        json.loads(Path(args[2]).read_text()), args[3], args[4])
    else:
        raise ValueError("Unknown fixture command")


if __name__ == "__main__":
    main(sys.argv[1:])
