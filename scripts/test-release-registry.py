#!/usr/bin/env python3
"""Exercise anonymous release downloads with a disposable loopback OCI registry.

Local fixtures cannot mint GitHub OIDC provenance, so attestation verification
is mocked. Real Docker verifies isolated inline credential storage; real Skopeo
requests fetch every platform manifest, config and layer.
No container daemon, public registry, image execution or package code is involved.
"""
from __future__ import annotations

from collections import Counter
import base64
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("verify_release_images", Path(__file__).with_name("verify-release-images.py"))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)
auth_spec = importlib.util.spec_from_file_location("release_registry_auth", Path(__file__).with_name("release_registry_auth.py"))
registry_auth = importlib.util.module_from_spec(auth_spec)
auth_spec.loader.exec_module(registry_auth)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def descriptor(raw, media_type):
    return {"digest": acceptance.content_digest(raw), "size": len(raw), "mediaType": media_type}


def check_docker_inline_store(root: Path, port: int) -> None:
    """Real Docker must use inline credentials even when native helpers exist."""
    class Initialized(BaseException):
        pass

    actor, token = "fixture-actor", "fixture-only-registry-secret"
    manager = registry_auth.RegistryAuth(root / "release-auth")
    # Stop at the login boundary: exercise production configuration creation
    # without sending any request to the helper's fixed production registry.
    try:
        with patch.object(manager, "_login", side_effect=Initialized):
            manager.prepare(token, actor)
    except Initialized:
        pass
    else:
        raise ValueError("Authentication fixture did not stop before production login")
    try:
        helper_directory = root / "credential-helpers"
        helper_directory.mkdir(mode=0o700)
        calls = root / "credential-helper-calls"
        for name in ("pass", "docker-credential-pass", "docker-credential-secretservice"):
            helper = helper_directory / name
            helper.write_text(f'''#!{sys.executable}
import os, sys
sys.stdin.read()
with open(os.environ["FIXTURE_HELPER_CALLS"], "a") as output:
    output.write((sys.argv[1] if len(sys.argv) > 1 else "invoked") + "\\n")
''')
            helper.chmod(0o700)
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"REGISTRY_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "DOCKER_AUTH_CONFIG",
                                      "DOCKER_CONTEXT", "DOCKER_HOST"}}
        environment.update({"PATH": str(helper_directory) + os.pathsep + os.environ["PATH"],
                            "HOME": str(manager.home), "DOCKER_CONFIG": str(manager.docker.parent),
                            "FIXTURE_HELPER_CALLS": str(calls), "TMPDIR": str(root)})
        address = f"localhost:{port}"
        # Docker automatically permits plain HTTP on loopback. Production
        # commands continue to use the fixed HTTPS GHCR destination.
        result = subprocess.run(["docker", "login", "--username", actor, "--password-stdin", address],
                                input=token.encode(), env=environment, capture_output=True,
                                timeout=30, check=False)
        if result.returncode:
            raise ValueError("Loopback Docker authentication failed")
        config = json.loads(manager.docker.read_text())
        expected = base64.b64encode(f"{actor}:{token}".encode()).decode()
        entry = config.get("auths", {}).get(address, {})
        if (calls.exists() or config.get("credsStore") or config.get("credHelpers")
                or entry.get("auth") != expected):
            raise ValueError("Docker did not retain isolated inline credentials")
        print("Loopback Docker login accepted: inline credentials; no native credential helper invoked")
    finally:
        manager.cleanup()


def main():
    routes = {}
    requests = Counter()

    class Registry(BaseHTTPRequestHandler):
        def do_GET(self):
            requests[self.path] += 1
            self.respond()

        def do_HEAD(self):
            self.respond(head=True)

        def respond(self, head=False):
            if self.path in ("/v2/", "/v2"):
                raw, media_type = b"{}", "application/json"
            elif self.path in routes:
                raw, media_type = routes[self.path]
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", media_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
            self.send_header("Docker-Content-Digest", "sha256:" + hashlib.sha256(raw).hexdigest())
            self.end_headers()
            if not head:
                self.wfile.write(raw)

        def log_message(self, *_arguments):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Registry)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    prefix = f"127.0.0.1:{server.server_port}/dev-resources-"
    tag, commit = "1.2.3", "abcdef12" + "0" * 32
    layer = gzip.compress(b"\0" * 10240, mtime=0)
    layer_descriptor = descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")
    try:
        with tempfile.TemporaryDirectory(prefix="devres-registry-fixture-", dir="/tmp") as temporary:
            root = Path(temporary)
            check_docker_inline_store(root, server.server_port)
            digests = root / "digests"
            digests.mkdir()
            for target in acceptance.FAMILIES:
                image = prefix + target
                route = "/v2/dev-resources-" + target
                descriptors, platforms = [], {}
                routes[route + "/blobs/" + layer_descriptor["digest"]] = (layer, "application/octet-stream")
                for arch in acceptance.ARCHES:
                    config = encoded({"os": "linux", "architecture": arch,
                                      "rootfs": {"type": "layers", "diff_ids": [acceptance.content_digest(b"\0" * 10240)]},
                                      "config": {"Labels": {
                                          "org.opencontainers.image.source": acceptance.SOURCE,
                                          "org.opencontainers.image.revision": commit,
                                          "org.opencontainers.image.version": tag,
                                          "org.opencontainers.image.licenses": "AGPL-3.0-only"}}})
                    config_descriptor = descriptor(config, "application/vnd.oci.image.config.v1+json")
                    manifest = encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                        "config": config_descriptor, "layers": [layer_descriptor]})
                    item = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
                    item["platform"] = {"os": "linux", "architecture": arch}
                    descriptors.append(item)
                    platforms[arch] = item["digest"]
                    routes[route + "/manifests/" + item["digest"]] = (manifest, item["mediaType"])
                    routes[route + "/blobs/" + config_descriptor["digest"]] = (config, "application/octet-stream")
                index = encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": descriptors})
                routes[route + "/manifests/" + tag] = (index, "application/vnd.oci.image.index.v1+json")
                record = {"image": image, "tag": tag, "commit": commit,
                          "digest": acceptance.content_digest(index), "platforms": platforms}
                (digests / (target + ".json")).write_bytes(encoded(record))
            real_command = acceptance.command
            attestations = []

            def command(arguments, environment, **kwargs):
                if arguments[0] == "gh":
                    attestations.append(arguments)
                    return b""
                arguments = arguments.copy()
                # HTTP is limited to this loopback-only fixture. Production retains TLS.
                arguments.insert(2, "--tls-verify=false" if arguments[1] == "inspect" else "--src-tls-verify=false")
                return real_command(arguments, environment, **kwargs)

            with patch.object(acceptance, "REGISTRY", prefix), patch.object(acceptance, "command", side_effect=command):
                result = acceptance.accept(digests, tag, commit, root / "accepted.json")
            layer_fetches = sum(count for path, count in requests.items() if path.endswith("/blobs/" + layer_descriptor["digest"]))
            if len(result["images"]) != 3 or len(attestations) != 9 or layer_fetches != 6:
                raise ValueError("Local fixture did not fetch all six complete platforms")
            print("Loopback registry accepted: three indexes, six complete anonymous platform pulls; nine provenance checks mocked")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
