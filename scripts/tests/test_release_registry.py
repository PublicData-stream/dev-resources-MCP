"""Coverage evidence for the disposable real-client release registry fixture."""
from collections import Counter
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


scripts = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("release_registry_fixture", scripts / "test-release-registry.py")
fixture = importlib.util.module_from_spec(spec)
with patch.object(sys, "path", [str(scripts), *sys.path]):
    spec.loader.exec_module(fixture)


class RegistryFixtureCoverageTests(unittest.TestCase):
    def setUp(self):
        self.seed(fixture.acceptance.FAMILIES)

    def seed(self, families):
        self.records, self.expected_downloads, self.attestations, self.downloads = [], {}, [], []
        for family in families:
            image = "127.0.0.1:1/dev-resources-" + family
            route = "/v2/dev-resources-" + family
            index = fixture.acceptance.content_digest((family + " index").encode())
            platforms = {}
            self.attestations.append(["gh", "attestation", "verify", "oci://" + image + "@" + index])
            # Layers are intentionally shared by both architectures, as in the real fixture.
            layer = fixture.acceptance.content_digest(b"shared layer")
            for arch in fixture.acceptance.ARCHES:
                digest = fixture.acceptance.content_digest((family + arch + " manifest").encode())
                config = fixture.acceptance.content_digest((family + arch + " config").encode())
                platforms[arch] = digest
                reference = "docker://" + image + "@" + digest
                paths = {route + "/manifests/" + digest, route + "/blobs/" + config,
                         route + "/blobs/" + layer}
                self.expected_downloads[reference] = paths
                self.downloads.append((reference, Counter(paths)))
                self.attestations.append(["gh", "attestation", "verify", "oci://" + image + "@" + digest])
            self.records.append({"image": image, "tag": "1.2.3", "commit": "a" * 40,
                                 "digest": index, "platforms": platforms})
        self.result = {"images": copy.deepcopy(self.records)}

    def verify(self):
        fixture.verify_fixture_coverage(self.records, self.expected_downloads, self.result,
                                        self.attestations, self.downloads)

    def test_complete_current_release_and_different_family_cardinality(self):
        for families in (fixture.acceptance.FAMILIES, ("synthetic",),
                         (*fixture.acceptance.FAMILIES, "future-fixture")):
            with self.subTest(families=families):
                self.seed(families)
                self.verify()

    def test_missing_duplicated_or_substituted_images_are_rejected(self):
        original = copy.deepcopy(self.result["images"])
        wrong_digest = copy.deepcopy(original)
        wrong_digest[0]["digest"] = "sha256:" + "0" * 64
        wrong_image = copy.deepcopy(original)
        wrong_image[0]["image"] = "127.0.0.1:1/substituted"
        for images in (original[:-1], [*original[:-1], original[0]], wrong_digest, wrong_image):
            with self.subTest(images=images):
                self.result["images"] = images
                with self.assertRaisesRegex(ValueError, "release images"):
                    self.verify()

    def test_missing_duplicated_or_wrong_provenance_subjects_are_rejected(self):
        original = copy.deepcopy(self.attestations)
        wrong_image = copy.deepcopy(original)
        wrong_image[-1][3] = wrong_image[-1][3].replace("dev-resources-", "other-")
        wrong_digest = copy.deepcopy(original)
        wrong_digest[-1][3] = wrong_digest[-1][3].split("@")[0] + "@sha256:" + "0" * 64
        for attestations in (original[:-1], [*original[:-1], original[0]],
                             [*original, original[0]], wrong_image, wrong_digest,
                             [*original[:-1], ["gh", "attestation", "verify"]]):
            with self.subTest(attestations=attestations):
                self.attestations = attestations
                with self.assertRaisesRegex(ValueError, "provenance subject"):
                    self.verify()

    def test_missing_or_duplicated_platform_copy_cannot_hide_behind_totals(self):
        original = self.downloads.copy()
        wrong_reference = ("docker://127.0.0.1:1/other@sha256:" + "0" * 64, original[-1][1])
        for downloads in (original[:-1], [*original[:-1], original[0]],
                          [*original, original[0]], [*original[:-1], wrong_reference]):
            with self.subTest(downloads=downloads):
                self.downloads = downloads
                with self.assertRaisesRegex(ValueError, "platform exactly once"):
                    self.verify()

    def test_each_copy_requires_its_own_manifest_configuration_and_layer_fetches(self):
        reference, original = self.downloads[1]
        for missing in original:
            with self.subTest(missing=missing):
                requests = original.copy()
                del requests[missing]
                # Other copies still fetched their routes, including the shared layer.
                self.downloads[1] = (reference, requests)
                with self.assertRaisesRegex(ValueError, "manifest, config and layer"):
                    self.verify()

    def test_fetching_another_repository_route_does_not_cover_a_missing_blob(self):
        reference, original = self.downloads[0]
        requests = Counter({path.replace("dev-resources-", "other-"): count
                            for path, count in original.items()})
        self.downloads[0] = (reference, requests)
        with self.assertRaisesRegex(ValueError, "manifest, config and layer"):
            self.verify()

    def test_repeated_http_requests_do_not_invalidate_complete_copies(self):
        for _, requests in self.downloads:
            requests.update({path: 2 for path in requests})
            requests["/v2/"] += 3
        self.verify()


if __name__ == "__main__":
    unittest.main()
