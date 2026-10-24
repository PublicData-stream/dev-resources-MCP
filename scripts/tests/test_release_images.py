"""Offline release artifact and immutable registry promotion contracts."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


scripts = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("release_images", scripts / "release_images.py")
images = importlib.util.module_from_spec(spec)
with patch.object(sys, "path", [str(scripts), *sys.path]):
    spec.loader.exec_module(images)


def encoded(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class ImageReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tag, self.commit = "v1.2.3", "abcdef12" + "0" * 32
        self.config = {
            "os": "linux", "architecture": "arm64",
            "config": {"Labels": {
                "org.opencontainers.image.source": images.SOURCE,
                "org.opencontainers.image.revision": self.commit,
                "org.opencontainers.image.version": "1.2.3",
                "org.opencontainers.image.licenses": "AGPL-3.0-only",
            }},
        }
        self.archive = self.root / "image.oci.tar"
        self.archive.write_bytes(b"Tested OCI archive fixture")
        self.refresh_fixture()

    def refresh_fixture(self):
        self.config_raw = encoded(self.config)
        self.manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": digest(self.config_raw), "size": len(self.config_raw)},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": "sha256:" + "c" * 64, "size": 42}],
        }
        self.manifest_raw = encoded(self.manifest)
        self.metadata = {
            "schema_version": 1, "target": "server", "platform": "linux/arm64",
            "archive": "image.oci.tar",
            "archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "manifest_digest": digest(self.manifest_raw),
            "config_digest": digest(self.config_raw),
            "layer_digests": [self.manifest["layers"][0]["digest"]],
        }
        self.write_metadata()

    def write_metadata(self):
        (self.root / "metadata.json").write_bytes(encoded(self.metadata))

    def inspect_fixture(self, reference, flag="--raw"):
        self.assertTrue(reference.startswith("oci-archive:"))
        return self.config_raw if flag == "--config" else self.manifest_raw

    def verified_record(self):
        with patch.object(images, "inspect", side_effect=self.inspect_fixture):
            return images.verify(self.root, "server", "arm64", self.tag, self.commit)

    def platform_records(self):
        records, manifests = [], {}
        for arch in ("amd64", "arm64"):
            # Distinct manifests represent the tested native platform artifacts.
            manifest = copy.deepcopy(self.manifest)
            manifest["config"]["digest"] = "sha256:" + ("a" if arch == "amd64" else "b") * 64
            raw = encoded(manifest)
            record = {"arch": arch, "image": images.REGISTRY + "server", "tag": self.tag,
                      "commit": self.commit, "manifest_digest": digest(raw)}
            records.append(record)
            manifests["docker://" + record["image"] + "@" + record["manifest_digest"]] = raw
        return records, manifests

    def test_verified_artifact_binds_release_platform_config_and_layers(self):
        record = self.verified_record()
        self.assertEqual(record["manifest_digest"], digest(self.manifest_raw))
        self.assertEqual((record["image"], record["arch"], record["tag"], record["commit"]),
                         (images.REGISTRY + "server", "arm64", self.tag, self.commit))
        self.assertEqual(record["layer_digests"], self.metadata["layer_digests"])

    def test_archive_checksum_metadata_identity_and_layer_tampering_fail(self):
        mutations = {"archive_sha256": "0" * 64, "platform": "linux/amd64", "target": "probe",
                     "archive": "elsewhere.tar", "manifest_digest": "sha256:" + "0" * 64,
                     "config_digest": "sha256:" + "0" * 64, "layer_digests": []}
        original = copy.deepcopy(self.metadata)
        for field, value in mutations.items():
            with self.subTest(field=field):
                self.metadata = {**original, field: value}
                self.write_metadata()
                with self.assertRaises(ValueError):
                    self.verified_record()

    def test_missing_or_symlinked_artifacts_are_rejected_before_inspection(self):
        for name in ("image.oci.tar", "metadata.json"):
            path = self.root / name
            contents = path.read_bytes()
            path.unlink()
            with self.subTest(name=name, kind="missing"), patch.object(images, "inspect") as inspect:
                with self.assertRaisesRegex(ValueError, "artifact"):
                    images.verify(self.root, "server", "arm64", self.tag, self.commit)
                inspect.assert_not_called()
            destination = self.root / (name + ".real")
            destination.write_bytes(contents)
            path.symlink_to(destination)
            with self.subTest(name=name, kind="symlink"), patch.object(images, "inspect") as inspect:
                with self.assertRaisesRegex(ValueError, "artifact"):
                    images.verify(self.root, "server", "arm64", self.tag, self.commit)
                inspect.assert_not_called()
            path.unlink()
            path.write_bytes(contents)

    def test_config_content_must_match_its_manifest_digest(self):
        self.config_raw += b" "
        with self.assertRaisesRegex(ValueError, "config content checksum"):
            self.verified_record()

    def test_config_inspection_requests_original_blob_bytes(self):
        reference = "oci-archive:/fixture/image.oci.tar"
        with patch.object(images, "command", return_value=self.config_raw) as command:
            self.assertEqual(images.inspect(reference, "--config"), self.config_raw)
            args = command.call_args.args
            self.assertEqual(args[:2], ("skopeo", "inspect"))
            self.assertEqual(set(args[2:-1]), {"--raw", "--config"})
            self.assertEqual(args[-1], reference)

    def test_validly_hashed_wrong_platform_or_release_labels_are_rejected(self):
        original = copy.deepcopy(self.config)
        for field in ("os", "architecture", *self.config["config"]["Labels"]):
            with self.subTest(field=field):
                self.config = copy.deepcopy(original)
                if field in ("os", "architecture"):
                    self.config[field] = "wrong"
                else:
                    self.config["config"]["Labels"][field] = "wrong"
                self.refresh_fixture()
                with self.assertRaisesRegex(ValueError, "platform|labels"):
                    self.verified_record()

    def test_index_instead_of_single_manifest_and_invalid_digests_fail(self):
        for manifest in ({"schemaVersion": 2, "manifests": []},
                         {**self.manifest, "config": {"digest": "sha512:bad"}}):
            with self.subTest(manifest=manifest):
                self.manifest_raw = encoded(manifest)
                self.metadata["manifest_digest"] = digest(self.manifest_raw)
                self.write_metadata()
                with self.assertRaises(ValueError):
                    self.verified_record()

    def test_conflicting_platform_tag_is_never_overwritten(self):
        record = self.verified_record()
        with patch.object(images, "fence") as fence, patch.object(images, "existing_digest", return_value="sha256:" + "0" * 64), patch.object(images, "command") as command:
            with self.assertRaisesRegex(ValueError, "overwrite"):
                images.promote(self.root, record, "f" * 40)
            fence.assert_called_once_with(self.tag, self.commit, "f" * 40)
            command.assert_not_called()

    def test_new_platform_promotion_copies_archive_with_digest_preservation(self):
        record = self.verified_record()
        with patch.object(images, "fence"), patch.object(images, "existing_digest", side_effect=[None, record["manifest_digest"]]), patch.object(images, "command") as command:
            result = images.promote(self.root, record, "f" * 40)
            args = command.call_args.args
            self.assertEqual(args[:3], ("skopeo", "copy", "--preserve-digests"))
            self.assertEqual(args[3], "oci-archive:" + str(self.archive.resolve()))
            self.assertEqual(args[4], "docker://" + result["platform_reference"])
            self.assertTrue(result["platform_reference"].endswith(":v1.2.3-arm64"))

    def test_identical_existing_platform_is_idempotent_without_copy(self):
        record = self.verified_record()
        with patch.object(images, "fence"), patch.object(images, "existing_digest", return_value=record["manifest_digest"]), patch.object(images, "command") as command:
            self.assertEqual(images.promote(self.root, record, "f" * 40)["manifest_digest"], record["manifest_digest"])
            command.assert_not_called()

    def test_partial_or_changed_promotion_cannot_return_success(self):
        record = self.verified_record()
        with patch.object(images, "fence"), patch.object(images, "existing_digest", side_effect=[None, "sha256:" + "0" * 64]), patch.object(images, "command"):
            with self.assertRaisesRegex(ValueError, "does not match"):
                images.promote(self.root, record, "f" * 40)
        with patch.object(images, "fence"), patch.object(images, "existing_digest", return_value=None), patch.object(images, "command", side_effect=subprocess.CalledProcessError(1, "skopeo")):
            with self.assertRaises(subprocess.CalledProcessError):
                images.promote(self.root, record, "f" * 40)

    def test_registry_auth_transport_and_rate_failures_are_not_absence(self):
        for error in (b"unauthorized: authentication required", b"dial tcp: timeout", b"429 Too Many Requests", b"403 Forbidden",
                      b"manifest unknown: unauthorized", b"name unknown: HTTP 403", b"manifest_unknown: authentication required"):
            result = subprocess.CompletedProcess([], 1, b"", error)
            with self.subTest(error=error), patch.object(images.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(ValueError, "registry tag state"):
                    images.existing_digest("ghcr.io/example/image:v1.2.3")
        with patch.object(images.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"manifest unknown")):
            self.assertIsNone(images.existing_digest("ghcr.io/example/image:v1.2.3"))

    def test_merge_requires_exactly_two_platforms_with_one_release_identity(self):
        records, _ = self.platform_records()
        mixed = copy.deepcopy(records)
        mixed[1]["commit"] = "0" * 40
        for invalid in ([], records[:1], records + records[:1], [records[0], records[0]], mixed):
            with self.subTest(records=invalid), patch.object(images, "inspect") as inspect:
                with self.assertRaises(ValueError):
                    images.expected_index(invalid)
                inspect.assert_not_called()

    def test_merge_publishes_only_the_two_tested_digest_references(self):
        records, manifests = self.platform_records()
        with patch.object(images, "inspect", side_effect=lambda ref: manifests[ref]):
            expected = images.expected_index(records)
        index_raw = encoded(expected)
        manifests["docker://" + records[0]["image"] + ":" + self.tag] = index_raw
        with patch.object(images, "inspect", side_effect=lambda ref: manifests[ref]), patch.object(images, "fence"), patch.object(images, "existing_digest", return_value=None), patch.object(images, "command") as command:
            result = images.merge(list(reversed(records)), "f" * 40)
            args = command.call_args.args
            self.assertEqual(args[:5], ("docker", "buildx", "imagetools", "create", "--tag"))
            self.assertEqual(set(args[6:]), {r["image"] + "@" + r["manifest_digest"] for r in records})
            self.assertEqual(result["digest"], digest(index_raw))
            self.assertEqual(result["platforms"], {r["arch"]: r["manifest_digest"] for r in records})

    def test_existing_conflicting_index_is_never_overwritten(self):
        records, manifests = self.platform_records()
        manifests["docker://" + records[0]["image"] + ":" + self.tag] = encoded({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []})
        with patch.object(images, "inspect", side_effect=lambda ref: manifests[ref]), patch.object(images, "fence"), patch.object(images, "existing_digest", return_value="sha256:" + "0" * 64), patch.object(images, "command") as command:
            with self.assertRaisesRegex(ValueError, "conflicts"):
                images.merge(records, "f" * 40)
            command.assert_not_called()

    def test_matching_descriptors_do_not_admit_invalid_index_schema(self):
        records, manifests = self.platform_records()
        with patch.object(images, "inspect", side_effect=lambda ref: manifests[ref]):
            expected = images.expected_index(records)
        for field, value in (("schemaVersion", 1), ("mediaType", "application/vnd.oci.image.manifest.v1+json"),
                             ("mediaType", "application/json")):
            with self.subTest(field=field, value=value):
                manifests["docker://" + records[0]["image"] + ":" + self.tag] = encoded({**expected, field: value})
                with patch.object(images, "inspect", side_effect=lambda ref: manifests[ref]), patch.object(images, "fence"), patch.object(images, "existing_digest", return_value="sha256:" + "0" * 64), patch.object(images, "command") as command:
                    with self.assertRaisesRegex(ValueError, "multi-platform index"):
                        images.merge(records, "f" * 40)
                    command.assert_not_called()

    def test_missing_or_changed_registry_platform_prevents_index_publication(self):
        records, _ = self.platform_records()
        for failure in (subprocess.CalledProcessError(1, "skopeo"), encoded({"schemaVersion": 2})):
            with self.subTest(failure=failure), patch.object(images, "inspect", side_effect=failure if isinstance(failure, Exception) else lambda _ref: failure), patch.object(images, "command") as command:
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    images.merge(records, "f" * 40)
                command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
