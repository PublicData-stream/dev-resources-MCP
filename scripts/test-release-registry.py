#!/usr/bin/env python3
"""Exercise anonymous release downloads with a disposable loopback OCI registry.

Only attestation verification is mocked: local fixtures cannot mint GitHub OIDC
provenance. Real Skopeo requests fetch every platform manifest, config and layer.
No container daemon, public registry, image execution or package code is involved.
"""
from __future__ import annotations

from collections import Counter
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import tempfile
from threading import Thread
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("verify_release_images", Path(__file__).with_name("verify-release-images.py"))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def descriptor(raw, media_type):
    return {"digest": acceptance.content_digest(raw), "size": len(raw), "mediaType": media_type}


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
