#!/usr/bin/env python3
"""Transfer a disposable harness image; checksums detect corruption, not trust.

export DIRECTORY IMAGE PLATFORM COMMIT VERSION
verify DIRECTORY PLATFORM COMMIT VERSION  (loads image, prints tag only)
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

OXIBELT_REVISION = "4f3154d8db0e0a49bce7a528c0a0f4c36d169040"
TAG = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._/:\-]*\Z")


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=300)


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect(image, platform):
    info, = json.loads(docker("image", "inspect", image))
    actual = f"{info['Os']}/{info['Architecture']}"
    if info.get("Variant"):
        actual += "/" + info["Variant"]
    # An omitted variant accepts the architecture default (for example arm64/v8).
    expected = platform.split("/")
    if actual.split("/")[:len(expected)] != expected or len(expected) not in (2, 3):
        raise ValueError(f"image platform mismatch: {actual}")
    return info["Id"]


def identity(image):
    output = docker("run", "--rm", "--network", "none", "--read-only",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges",
                    "--entrypoint", "oxibelt", image, "--version")
    values = [json.loads(line.split("=", 1)[1]) for line in output.splitlines()
              if line.startswith("OXIBELT_BUILD_IDENTITY_V1=")]
    if len(values) != 1 or values[0].get("revision") != OXIBELT_REVISION or values[0].get("dirty") != "clean":
        raise ValueError("unexpected OxiBelt identity")
    return values[0]


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected regular artifact file: {path.name}")
    return path


def export(directory, image, platform, commit, version):
    if not TAG.fullmatch(image) or ":" not in image.rsplit("/", 1)[-1]:
        raise ValueError("export requires an explicit image tag")
    image_id = inspect(image, platform)
    edge = identity(image_id)
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / "image.tar"
    metadata = directory / "metadata.json"
    if archive.exists() or archive.is_symlink() or metadata.exists() or metadata.is_symlink():
        raise ValueError("refusing to overwrite an artifact")
    # Save the tag, then recheck its identity to detect a concurrent retag.
    docker("image", "save", "--output", str(archive), image)
    if inspect(image, platform) != image_id:
        archive.unlink()
        raise ValueError("image tag changed during export")
    data = dict(schema_version=1, platform=platform, commit=commit, version=version,
                image_tag=image, image_id=image_id, oxibelt_identity=edge,
                image_sha256=checksum(archive))
    with metadata.open("x") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")


def verify(directory, platform, commit, version):
    metadata = regular(directory / "metadata.json")
    if metadata.stat().st_size > 65536:
        raise ValueError("metadata exceeds limit")
    data = json.loads(metadata.read_text())
    if not isinstance(data, dict):
        raise ValueError("metadata must be an object")
    for key, value in (("schema_version", 1), ("platform", platform),
                       ("commit", commit), ("version", version)):
        if data.get(key) != value:
            raise ValueError(f"artifact {key} mismatch")
    tag = data["image_tag"]
    if not isinstance(tag, str) or not TAG.fullmatch(tag) or ":" not in tag.rsplit("/", 1)[-1]:
        raise ValueError("invalid image tag")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", data["image_id"]):
        raise ValueError("invalid image ID")
    edge = data["oxibelt_identity"]
    if not isinstance(edge, dict) or edge.get("revision") != OXIBELT_REVISION or edge.get("dirty") != "clean":
        raise ValueError("artifact OxiBelt identity mismatch")
    archive = regular(directory / "image.tar")
    if checksum(archive) != data["image_sha256"]:
        raise ValueError("image checksum mismatch")
    docker("image", "load", "--input", str(archive))
    if inspect(tag, platform) != data["image_id"]:
        raise ValueError("loaded image ID mismatch")
    if identity(data["image_id"]) != edge:
        raise ValueError("loaded OxiBelt identity mismatch")
    return tag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("export", "verify"):
        sub = commands.add_parser(name)
        sub.add_argument("directory", type=Path)
        if name == "export":
            sub.add_argument("image")
        for arg in ("platform", "commit", "version"):
            sub.add_argument(arg)
    args = vars(parser.parse_args())
    command = args.pop("command")
    try:
        result = globals()[command](**args)
        if result is not None:
            print(result)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"artifact: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
