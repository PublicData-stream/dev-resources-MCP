"""Offline corresponding-source and append-only GitHub Release contracts."""
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
spec = importlib.util.spec_from_file_location("source_release", scripts / "publish-source-release.py")
release = importlib.util.module_from_spec(spec)
with patch.object(sys, "path", [str(scripts), *sys.path]):
    spec.loader.exec_module(release)

GET_RELEASE = release.get_release


class SourceReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source, self.digests = self.root / "source", self.root / "digests"
        self.source.mkdir()
        self.digests.mkdir()
        self.commit = "abcdef12" + "0" * 32
        self.tag_object = "1" * 40
        self.tag = "1.2.3"
        self.kind = "stable"
        self.identity = "42"
        self.archive = self.source / "source.tar.gz"
        self.archive.write_bytes(b"Exact version-stamped fixture source")
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        (self.source / "source.tar.gz.sha256").write_text(f"{digest}  source.tar.gz\n")
        self.write_metadata()
        self.remote = self.fixture_release(complete=False)
        self.calls = []
        self.fences = []
        self.addCleanup(patch.stopall)
        patch.object(release, "get_release", side_effect=lambda tag: copy.deepcopy(self.remote)).start()
        patch.object(release, "check", side_effect=self.fence).start()
        patch.object(release, "command", side_effect=self.command).start()

    def write_metadata(self):
        self.metadata = {"commit": self.commit, "tag": self.tag, "version": self.tag,
                         "source_sha256": release.checksum(self.archive)}
        (self.source / "release.json").write_text(json.dumps(self.metadata))
        for target in release.FAMILIES:
            record = {"image": release.REGISTRY + target, "tag": self.tag, "commit": self.commit,
                      "digest": "sha256:" + "a" * 64,
                      "platforms": {arch: "sha256:" + ("b" if arch == "amd64" else "c") * 64
                                    for arch in release.ARCHES}}
            (self.digests / f"{target}.json").write_text(json.dumps(record))

    def fixture_release(self, draft=False, complete=True):
        files = release.assets(self.source, self.digests, self.tag, self.commit)
        return {"id": 42, "tag_name": self.tag, "target_commitish": "main",
                "prerelease": self.kind != "stable", "draft": draft, "immutable": False,
                "body": "Human release notes", "name": "Human title",
                "assets": [{"name": path.name, "digest": "sha256:" + release.checksum(path)}
                           for path in files] if complete else []}

    def fence(self, *arguments):
        self.fences.append(arguments)
        if self.kind == "build":
            return None
        return copy.deepcopy(self.remote)

    def command(self, *arguments):
        self.calls.append(arguments)
        if arguments[:2] == ("release", "create"):
            self.assertIn("--draft", arguments)
            self.assertIn("--verify-tag", arguments)
            self.assertIn("--prerelease", arguments)
            notes = Path(arguments[arguments.index("--notes-file") + 1]).read_text()
            self.assertIn("Assisted-by: Codex <codex@openai.com>", notes)
            self.remote = self.fixture_release(draft=True, complete=False)
        elif arguments[:2] == ("release", "upload"):
            path = Path(arguments[3])
            self.remote["assets"].append({"name": path.name, "digest": "sha256:" + release.checksum(path)})
        elif arguments[:2] == ("release", "edit"):
            self.remote["draft"] = False
        elif arguments[:2] == ("release", "download"):
            path = arguments[arguments.index("--pattern") + 1]
            destination = Path(arguments[arguments.index("--dir") + 1]) / path
            destination.write_bytes((self.source / path).read_bytes())
        return b""

    def publish(self):
        release.publish(self.source, self.digests, self.tag, self.commit,
                        self.tag_object, self.kind, self.identity)

    def build(self):
        self.tag, self.kind, self.identity = "1.2.3-build.abcdef12", "build", ""
        self.write_metadata()

    def test_exact_source_and_all_image_families_required(self):
        paths = release.assets(self.source, self.digests, self.tag, self.commit)
        self.assertEqual({path.name for path in paths}, {"source.tar.gz", "source.tar.gz.sha256",
                         "release.json", "server.json", "probe.json", "audit-worker.json"})
        for target in release.FAMILIES:
            path = self.digests / f"{target}.json"
            original = path.read_bytes()
            path.unlink()
            with self.subTest(target=target), self.assertRaises(FileNotFoundError):
                self.publish()
            path.write_bytes(original)
        self.assertFalse(self.calls)
        self.assertFalse(self.fences)

    def test_invalid_source_or_platforms_never_contact_github(self):
        for case in ("checksum", "version", "commit", "platform", "digest"):
            with self.subTest(case=case):
                checksum = self.source / "source.tar.gz.sha256"
                metadata = self.source / "release.json"
                image = self.digests / "server.json"
                originals = {p: p.read_bytes() for p in (checksum, metadata, image)}
                if case == "checksum":
                    checksum.write_text("0" * 64 + "  source.tar.gz\n")
                elif case in ("version", "commit"):
                    metadata.write_text(json.dumps({**self.metadata, case: "wrong"}))
                else:
                    changed = json.loads(image.read_text())
                    if case == "platform":
                        del changed["platforms"]["arm64"]
                    else:
                        changed["digest"] = "invalid"
                    image.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    self.publish()
                for path, contents in originals.items():
                    path.write_bytes(contents)
        self.assertFalse(self.calls)
        self.assertFalse(self.fences)

    def test_published_release_appends_assets_and_preserves_human_metadata(self):
        self.publish()
        self.assertEqual(len(self.calls), 6)
        self.assertTrue(all(call[:2] == ("release", "upload") for call in self.calls))
        self.assertEqual(self.remote["body"], "Human release notes")
        self.assertEqual(self.remote["name"], "Human title")
        self.assertEqual(self.remote["target_commitish"], "main")
        self.assertEqual(len(self.fences), 8)

    def test_fresh_build_remains_draft_until_all_assets_uploaded(self):
        self.build()
        self.remote = None
        self.publish()
        self.assertEqual(self.calls[0][:2], ("release", "create"))
        self.assertEqual(self.calls[-1][:2], ("release", "edit"))
        self.assertEqual(len(self.remote["assets"]), 6)
        self.assertFalse(self.remote["draft"])

    def test_failed_asset_upload_never_publishes_build_draft(self):
        self.build()
        self.remote = self.fixture_release(draft=True, complete=False)
        with patch.object(release, "command", side_effect=subprocess.CalledProcessError(1, "gh")) as command:
            with self.assertRaises(subprocess.CalledProcessError):
                self.publish()
        self.assertEqual(command.call_args.args[:2], ("release", "upload"))
        self.assertTrue(self.remote["draft"])

    def test_matching_published_release_is_idempotent(self):
        self.remote = self.fixture_release()
        self.publish()
        self.assertFalse(self.calls)

    def test_late_conflicting_asset_prevents_all_appends(self):
        self.remote = self.fixture_release()
        self.remote["assets"].pop(0)
        self.remote["assets"][-1]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "conflicting"):
            self.publish()
        self.assertFalse(self.calls)

    def test_release_identity_change_stops_before_upload(self):
        original = copy.deepcopy(self.remote)
        for field, value in (("id", 43), ("tag_name", "2.0.0"), ("draft", True),
                             ("prerelease", True), ("immutable", True)):
            with self.subTest(field=field):
                changed = {**original, field: value}
                with patch.object(release, "check", side_effect=[original, changed]):
                    with self.assertRaisesRegex(ValueError, "changed"):
                        self.publish()
                self.assertFalse(self.calls)

    def test_immutable_build_missing_assets_is_rejected(self):
        self.build()
        self.remote = self.fixture_release(complete=False)
        self.remote["immutable"] = True
        with self.assertRaisesRegex(ValueError, "Immutable"):
            self.publish()
        self.assertFalse(self.calls)

    def test_duplicate_assets_are_rejected(self):
        self.remote = self.fixture_release()
        self.remote["assets"].append(self.remote["assets"][0])
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.publish()
        self.assertFalse(self.calls)

    def test_legacy_asset_without_digest_is_downloaded_and_checked(self):
        self.remote = self.fixture_release()
        self.remote["assets"][0].pop("digest")
        self.publish()
        self.assertEqual([call[:2] for call in self.calls], [("release", "download")] * 2)

    def test_http_403_is_not_absence(self):
        forbidden = subprocess.CompletedProcess([], 1, b"", b"gh: Forbidden (HTTP 403)")
        with patch.object(release.subprocess, "run", return_value=forbidden):
            with self.assertRaisesRegex(ValueError, "existing GitHub Release state"):
                GET_RELEASE(self.tag)
        absent = subprocess.CompletedProcess([], 1, b"", b"gh: Not Found (HTTP 404)")
        with patch.object(release.subprocess, "run", return_value=absent):
            self.assertIsNone(GET_RELEASE(self.tag))
