#!/usr/bin/env python3
"""Transfer a disposable harness image; checksums detect corruption, not trust.

export DIRECTORY IMAGE PLATFORM COMMIT VERSION
verify DIRECTORY PLATFORM COMMIT VERSION  (loads image, prints tag only)
acquire-minikube DIRECTORY PLATFORM COMMIT VERSION
verify-minikube DIRECTORY PLATFORM COMMIT VERSION  (prints verified tool path only)
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

OXIBELT_REVISION = "4f3154d8db0e0a49bce7a528c0a0f4c36d169040"
TAG = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._/:\-]*\Z")
MINIKUBE_VERSION = "v1.39.0"
MINIKUBE_SHA256 = {
    "linux/amd64": "b738496da01be06bbaf80c688f57ce25acd3849fbb518155f3a88e03ef555aa4",
    "linux/arm64": "202f331cb677761c5aec81c58472d16d65707358b9f66226210be3fe3275b1c3",
}


class MinikubeError(ValueError):
    def __init__(self, message, status=1):
        super().__init__(message)
        self.status = status


def minikube_digest(platform):
    if platform not in MINIKUBE_SHA256:
        raise ValueError("unsupported minikube platform")
    return MINIKUBE_SHA256[platform]


def tool_directory(path, create=False):
    """Reject linked artifact directories before resolving fixed companion names."""
    path = path.absolute()
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise ValueError("minikube artifact directory must not be a symlink")
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError("expected minikube artifact directory")
    return path


def minikube_diagnostic(command, platform, stage, status):
    """Only fixed bootstrap fields are eligible for retained diagnostics."""
    try:
        root = os.environ.get("DEVRES_E2E_DIAGNOSTICS_DIR")
        if not root:
            return
        directory = tool_directory(Path(root) / "bootstrap", create=True)
        data = dict(stage=stage, tool="minikube", minikube_version=MINIKUBE_VERSION,
                    platform=platform if platform in MINIKUBE_SHA256 else "unsupported",
                    status=status)
        path = directory / f"{command}.json"
        # Diagnostics never follow an existing path into private fixture state.
        with path.open("x") as stream:
            json.dump(data, stream, sort_keys=True)
            stream.write("\n")
    except (OSError, ValueError):
        pass


def acquire_minikube(directory, platform, commit, version):
    expected = minikube_digest(platform)
    directory = tool_directory(directory, create=True) / "minikube"
    # An exclusive directory is an ownership fence for failed-acquisition cleanup.
    if directory.exists() or directory.is_symlink():
        raise ValueError("refusing to overwrite a minikube artifact")
    directory.mkdir()
    try:
        with tempfile.TemporaryDirectory(prefix="devres-minikube-download.", dir="/tmp") as temporary:
            binary = Path(temporary) / "minikube"
            url = ("https://github.com/kubernetes/minikube/releases/download/"
                   f"{MINIKUBE_VERSION}/minikube-linux-{platform.split('/')[1]}")
            try:
                subprocess.run([
                    "curl", "--fail", "--location", "--silent", "--show-error",
                    "--proto", "=https", "--proto-redir", "=https",
                    "--retry", "4", "--connect-timeout", "15", "--max-time", "60",
                    "--retry-max-time", "180", "--url", url, "--output", str(binary),
                ], check=True, timeout=240, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as error:
                raise MinikubeError("minikube download failed", error.returncode) from None
            except subprocess.TimeoutExpired:
                raise MinikubeError("minikube download timed out", 124) from None
            if checksum(regular(binary)) != expected:
                raise ValueError("minikube checksum mismatch")
            # Keep the published file non-executable; consumers verify before install.
            with (directory / "minikube").open("xb") as output, binary.open("rb") as source:
                shutil.copyfileobj(source, output)
            data = dict(schema_version=1, platform=platform, commit=commit, version=version,
                        minikube_version=MINIKUBE_VERSION, sha256=expected)
            with (directory / "metadata.json").open("x") as stream:
                json.dump(data, stream, indent=2, sort_keys=True)
                stream.write("\n")
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise


def verify_minikube(directory, platform, commit, version):
    expected = minikube_digest(platform)
    directory = tool_directory(tool_directory(directory) / "minikube")
    metadata = regular(directory / "metadata.json")
    if metadata.stat().st_size > 65536:
        raise ValueError("minikube metadata exceeds limit")
    data = json.loads(metadata.read_text())
    if not isinstance(data, dict):
        raise ValueError("minikube metadata must be an object")
    for key, value in (("schema_version", 1), ("platform", platform), ("commit", commit),
                       ("version", version), ("minikube_version", MINIKUBE_VERSION),
                       ("sha256", expected)):
        if data.get(key) != value:
            raise ValueError(f"minikube artifact {key} mismatch")
    binary = regular(directory / "minikube")
    if checksum(binary) != expected:
        raise ValueError("minikube checksum mismatch")
    return str(binary)


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
    for name in ("export", "verify", "acquire-minikube", "verify-minikube"):
        sub = commands.add_parser(name)
        sub.add_argument("directory", type=Path)
        if name == "export":
            sub.add_argument("image")
        for arg in ("platform", "commit", "version"):
            sub.add_argument(arg)
    args = vars(parser.parse_args())
    command = args.pop("command")
    if command in ("acquire-minikube", "verify-minikube"):
        status = 0
        try:
            result = globals()[command.replace("-", "_")](**args)
            if result is not None:
                print(result)
        except (ValueError, KeyError, TypeError, OSError, RecursionError) as error:
            status = error.status if isinstance(error, MinikubeError) else 1
            # Never echo untrusted metadata, paths or download response details.
            print(f"artifact: {command} failed (exit {status})", file=sys.stderr)
        minikube_diagnostic(command, args["platform"], command, status)
        return status
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
