"""Offline acceptance of complete anonymous OCI downloads and release provenance."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

scripts = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("verify_release_images", scripts / "verify-release-images.py")
acceptance = importlib.util.module_from_spec(spec)
with patch.object(sys, "path", [str(scripts), *sys.path]):
    spec.loader.exec_module(acceptance)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def descriptor(raw, media_type):
    return {"digest": acceptance.content_digest(raw), "size": len(raw), "mediaType": media_type}


class RegistryAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.digests = self.root / "digests"
        self.digests.mkdir()
        self.output = self.root / "accepted.json"
        self.tag, self.commit = "1.2.3", "abcdef12" + "0" * 32
        self.records, self.indexes, self.downloads, self.calls = [], {}, {}, []
        for target in acceptance.FAMILIES:
            image = acceptance.REGISTRY + target
            manifests, platforms = [], {}
            for arch in acceptance.ARCHES:
                config = encoded({"os": "linux", "architecture": arch, "config": {"Labels": {
                    "org.opencontainers.image.source": acceptance.SOURCE,
                    "org.opencontainers.image.revision": self.commit,
                    "org.opencontainers.image.version": self.tag,
                    "org.opencontainers.image.licenses": "AGPL-3.0-only",
                }}})
                layer = f"Synthetic {target} {arch} layer fixture".encode()
                config_descriptor = descriptor(config, "application/vnd.oci.image.config.v1+json")
                layer_descriptor = descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")
                manifest = encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                    "config": config_descriptor, "layers": [layer_descriptor]})
                manifest_descriptor = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
                manifest_descriptor["platform"] = {"os": "linux", "architecture": arch}
                manifests.append(manifest_descriptor)
                platforms[arch] = manifest_descriptor["digest"]
                self.downloads[image + "@" + manifest_descriptor["digest"]] = {
                    acceptance.content_digest(raw): raw for raw in (manifest, config, layer)}
            index = encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests})
            record = {"image": image, "tag": self.tag, "commit": self.commit,
                      "digest": acceptance.content_digest(index), "platforms": platforms}
            self.records.append(record)
            self.indexes[image + ":" + self.tag] = index
            (self.digests / (target + ".json")).write_bytes(encoded(record))

    def command(self, arguments, environment, **kwargs):
        self.calls.append((arguments, environment.copy()))
        if arguments[:2] == ["skopeo", "inspect"]:
            self.assertIn("--no-creds", arguments)
            return self.indexes[arguments[-1].removeprefix("docker://")]
        if arguments[:2] == ["skopeo", "copy"]:
            self.assertIn("--src-no-creds", arguments)
            self.assertIn("--preserve-digests", arguments)
            destination = Path(arguments[-1].removeprefix("oci:").removesuffix(":accepted"))
            self.assertFalse(destination.exists())
            blobs = destination / "blobs" / "sha256"
            blobs.mkdir(parents=True)
            for digest, raw in self.downloads[arguments[-2].removeprefix("docker://")].items():
                (blobs / digest.removeprefix("sha256:")).write_bytes(raw)
            return b""
        self.assertEqual(arguments[:3], ["gh", "attestation", "verify"])
        self.assertIn("--bundle-from-oci", arguments)
        self.assertEqual(arguments[arguments.index("--repo") + 1], acceptance.REPOSITORY)
        self.assertEqual(arguments[arguments.index("--source-digest") + 1], self.commit)
        self.assertEqual(arguments[arguments.index("--source-ref") + 1], "refs/tags/" + self.tag)
        self.assertEqual(arguments[arguments.index("--signer-workflow") + 1], acceptance.WORKFLOW)
        self.assertIn("@sha256:", arguments[3])
        return b""

    def accept(self):
        return acceptance.accept(self.digests, self.tag, self.commit, self.output)

    def write_record(self, index):
        target = acceptance.FAMILIES[index]
        (self.digests / (target + ".json")).write_bytes(encoded(self.records[index]))

    def test_all_nine_attestations_and_six_full_downloads_precede_accepted_output(self):
        with patch.object(acceptance, "command", side_effect=self.command):
            result = self.accept()
        self.assertEqual(result, json.loads(self.output.read_text()))
        self.assertEqual(result, {"tag": self.tag, "version": self.tag, "commit": self.commit, "images": self.records})
        self.assertEqual(sum(args[:2] == ["skopeo", "inspect"] for args, _ in self.calls), 3)
        self.assertEqual(sum(args[:2] == ["skopeo", "copy"] for args, _ in self.calls), 6)
        self.assertEqual(sum(args[:3] == ["gh", "attestation", "verify"] for args, _ in self.calls), 9)
        destinations = [Path(args[-1].removeprefix("oci:").removesuffix(":accepted"))
                        for args, _ in self.calls if args[:2] == ["skopeo", "copy"]]
        self.assertEqual(len(set(destinations)), 6)
        self.assertTrue(all(not destination.exists() for destination in destinations))

    def test_ambient_auth_is_replaced_by_isolated_empty_client_files(self):
        with patch.dict(os.environ, {"DOCKER_CONFIG": "/private/docker", "REGISTRY_AUTH_FILE": "/private/auth", "DOCKER_AUTH_CONFIG": "private", "GH_CONFIG_DIR": "/private/gh"}):
            root = self.root / "environment"
            root.mkdir()
            environment = acceptance.anonymous_environment(root)
        self.assertNotIn("DOCKER_AUTH_CONFIG", environment)
        for name in ("DOCKER_CONFIG", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "TMPDIR"):
            self.assertTrue(Path(environment[name]).is_relative_to(root))
        self.assertEqual(json.loads(Path(environment["REGISTRY_AUTH_FILE"]).read_text()), {"auths": {}})
        self.assertEqual(Path(environment["REGISTRY_AUTH_FILE"]).stat().st_mode & 0o777, 0o600)

    def test_wrong_identity_platform_set_and_invalid_digest_never_contact_registry(self):
        original = copy.deepcopy(self.records[0])
        mutations = ({"image": "ghcr.io/other/image"}, {"tag": "9.9.9"}, {"commit": "0" * 40},
                     {"digest": "sha512:bad"}, {"platforms": {"amd64": "sha256:" + "a" * 64}},
                     {"platforms": {"amd64": "sha256:" + "a" * 64, "arm64": 12}})
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.records[0] = {**original, **mutation}
                self.write_record(0)
                with patch.object(acceptance, "command") as command, self.assertRaises(ValueError):
                    self.accept()
                command.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_changed_or_incomplete_version_index_is_rejected(self):
        reference = self.records[0]["image"] + ":" + self.tag
        original = json.loads(self.indexes[reference])
        cases = [b"{}", encoded({**original, "manifests": original["manifests"][:1]}),
                 encoded({**original, "schemaVersion": 1})]
        duplicated = copy.deepcopy(original)
        duplicated["manifests"][1] = duplicated["manifests"][0]
        cases.append(encoded(duplicated))
        wrong = copy.deepcopy(original)
        wrong["manifests"][1]["digest"] = "sha256:" + "0" * 64
        cases.append(encoded(wrong))
        for raw in cases:
            with self.subTest(raw=raw):
                self.indexes[reference] = raw
                self.records[0]["digest"] = acceptance.content_digest(raw)
                self.write_record(0)
                with patch.object(acceptance, "command", side_effect=self.command), self.assertRaises(ValueError):
                    self.accept()
                self.assertFalse(self.output.exists())

    def test_wrong_recorded_index_digest_is_rejected(self):
        self.records[0]["digest"] = "sha256:" + "0" * 64
        self.write_record(0)
        with patch.object(acceptance, "command", side_effect=self.command), self.assertRaisesRegex(ValueError, "index digest"):
            self.accept()
        self.assertFalse(self.output.exists())

    def test_private_image_and_failed_anonymous_download_produce_no_acceptance(self):
        for failure_at in ("inspect", "copy"):
            with self.subTest(failure_at=failure_at):
                def command(args, env, **kwargs):
                    if args[:2] == ["skopeo", failure_at]:
                        raise ValueError("Registry access denied")
                    return self.command(args, env, **kwargs)
                with patch.object(acceptance, "command", side_effect=command), self.assertRaises(ValueError):
                    self.accept()
                self.assertFalse(self.output.exists())

    def test_missing_corrupt_and_wrong_sized_downloaded_layers_are_rejected(self):
        reference = self.records[0]["image"] + "@" + self.records[0]["platforms"]["amd64"]
        original = self.downloads[reference].copy()
        layer_digest = list(original)[-1]
        for mutation in (None, b"", b"x" * len(original[layer_digest])):
            with self.subTest(mutation=mutation):
                self.downloads[reference] = original.copy()
                if mutation is None:
                    del self.downloads[reference][layer_digest]
                else:
                    self.downloads[reference][layer_digest] = mutation
                with patch.object(acceptance, "command", side_effect=self.command), self.assertRaisesRegex(ValueError, "blob"):
                    self.accept()
                self.assertFalse(self.output.exists())

    def test_validly_hashed_wrong_image_configuration_is_rejected(self):
        record = self.records[0]
        reference = record["image"] + "@" + record["platforms"]["amd64"]
        original = self.downloads[reference].copy()
        manifest_digest = record["platforms"]["amd64"]
        original_manifest = json.loads(original[manifest_digest])
        configuration = json.loads(original[original_manifest["config"]["digest"]])
        for field in ("architecture", "org.opencontainers.image.revision"):
            with self.subTest(field=field):
                changed = copy.deepcopy(configuration)
                if field == "architecture":
                    changed[field] = "arm64"
                else:
                    changed["config"]["Labels"][field] = "0" * 40
                config_raw = encoded(changed)
                manifest = {**original_manifest, "config": descriptor(config_raw, original_manifest["config"]["mediaType"])}
                manifest_raw = encoded(manifest)
                platform = descriptor(manifest_raw, manifest["mediaType"])
                platform["platform"] = {"os": "linux", "architecture": "amd64"}
                index_reference = record["image"] + ":" + self.tag
                index = json.loads(self.indexes[index_reference])
                index["manifests"][0] = platform
                self.indexes[index_reference] = encoded(index)
                record["digest"] = acceptance.content_digest(encoded(index))
                record["platforms"]["amd64"] = platform["digest"]
                self.write_record(0)
                self.downloads[record["image"] + "@" + platform["digest"]] = {
                    **original, platform["digest"]: manifest_raw, acceptance.content_digest(config_raw): config_raw}
                with patch.object(acceptance, "command", side_effect=self.command), self.assertRaisesRegex(ValueError, "platform|labels"):
                    self.accept()
                self.assertFalse(self.output.exists())

    def test_invalid_provenance_retries_only_three_times_then_fails_closed(self):
        def command(args, environment, **kwargs):
            if args[0] == "gh":
                raise ValueError("untrusted signer")
            return self.command(args, environment, **kwargs)
        with patch.object(acceptance, "command", side_effect=command) as runner, patch.object(acceptance.time, "sleep") as sleep, self.assertRaisesRegex(ValueError, "provenance"):
            self.accept()
        self.assertEqual(sum(call.args[0][0] == "gh" for call in runner.call_args_list), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertFalse(self.output.exists())

    def test_transient_attestation_delay_is_bounded_and_can_recover(self):
        with patch.object(acceptance, "command", side_effect=[ValueError("not yet"), b""]) as command, patch.object(acceptance.time, "sleep") as sleep:
            acceptance.verify_provenance(self.records[0]["image"], self.records[0]["digest"], self.tag, self.commit, {})
        self.assertEqual(command.call_count, 2)
        sleep.assert_called_once_with(5)

    def test_command_failures_hide_child_output_and_use_timeouts(self):
        result = subprocess.CompletedProcess([], 1, b"secret stdout", b"secret stderr")
        with patch.object(acceptance.subprocess, "run", return_value=result) as run, self.assertRaisesRegex(ValueError, "skopeo release verification failed") as caught:
            acceptance.command(["skopeo", "inspect"], {"PATH": "/bin"})
        self.assertNotIn("secret", str(caught.exception))
        self.assertEqual(run.call_args.kwargs["timeout"], 120)
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/bin"})

    def test_existing_acceptance_and_non_tmp_output_are_not_overwritten(self):
        self.output.write_text("prior acceptance")
        with patch.object(acceptance, "command") as command, self.assertRaisesRegex(ValueError, "replace"):
            self.accept()
        command.assert_not_called()
        self.assertEqual(self.output.read_text(), "prior acceptance")
        with self.assertRaisesRegex(ValueError, "/tmp"):
            acceptance.temporary_path(Path("/var/accepted.json"))

    def test_missing_or_symlinked_digest_record_is_rejected(self):
        path = self.digests / "server.json"
        path.unlink()
        with self.assertRaisesRegex(ValueError, "Missing"):
            acceptance.load_records(self.digests, self.tag, self.commit)
        real = self.root / "server.json"
        real.write_bytes(encoded(self.records[0]))
        path.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            acceptance.load_records(self.digests, self.tag, self.commit)


if __name__ == "__main__":
    unittest.main()
