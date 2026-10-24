"""Offline corresponding-source and GitHub Release publication contracts."""
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


class SourceReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.digests = self.root / "digests"
        self.source.mkdir()
        self.digests.mkdir()
        self.tag = "v1.2.3"
        self.commit = "abcdef12" + "0" * 32
        self.archive = self.source / "source.tar.gz"
        self.archive.write_bytes(b"Exact version-stamped source 1.2.3 fixture")
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        (self.source / "source.tar.gz.sha256").write_text(f"{digest}  source.tar.gz\n")
        self.metadata = {"commit": self.commit, "tag": self.tag, "version": "1.2.3", "source_sha256": digest}
        (self.source / "release.json").write_text(json.dumps(self.metadata))
        for target in release.FAMILIES:
            record = {"image": release.REGISTRY + target, "tag": self.tag, "commit": self.commit,
                      "digest": "sha256:" + "a" * 64,
                      "platforms": {arch: "sha256:" + ("b" if arch == "amd64" else "c") * 64
                                    for arch in release.ARCHES}}
            (self.digests / f"{target}.json").write_text(json.dumps(record))

    def fixture_release(self, draft=False, complete=True):
        files = release.assets(self.source, self.digests, self.tag, self.commit)
        return {"tag_name": self.tag, "target_commitish": self.commit, "prerelease": False, "draft": draft,
                "assets": [{"name": path.name, "digest": "sha256:" + release.checksum(path)}
                           for path in files] if complete else []}

    def publish(self):
        release.publish(self.source, self.digests, self.tag, self.commit)

    def test_exact_source_identity_checksum_and_all_three_image_families_are_required(self):
        paths = release.assets(self.source, self.digests, self.tag, self.commit)
        self.assertEqual(len(paths), 6)
        self.assertEqual({path.name for path in paths},
                         {"source.tar.gz", "source.tar.gz.sha256", "release.json",
                          "server.json", "probe.json", "audit-worker.json"})
        self.assertEqual(json.loads(paths[2].read_text())["version"], "1.2.3")
        for target in release.FAMILIES:
            path = self.digests / f"{target}.json"
            original = path.read_bytes()
            path.unlink()
            with self.subTest(target=target), self.assertRaises(FileNotFoundError):
                release.assets(self.source, self.digests, self.tag, self.commit)
            path.write_bytes(original)

    def test_invalid_source_or_incomplete_platforms_never_contact_github(self):
        cases = ("checksum", "version", "commit", "platform", "digest")
        for case in cases:
            with self.subTest(case=case):
                checksum = self.source / "source.tar.gz.sha256"
                metadata = self.source / "release.json"
                image = self.digests / "server.json"
                originals = {path: path.read_bytes() for path in (checksum, metadata, image)}
                if case == "checksum":
                    checksum.write_text("0" * 64 + "  source.tar.gz\n")
                elif case in ("version", "commit"):
                    changed = {**self.metadata, case: "wrong"}
                    metadata.write_text(json.dumps(changed))
                else:
                    changed = json.loads(image.read_text())
                    if case == "platform":
                        del changed["platforms"]["arm64"]
                    else:
                        changed["digest"] = "invalid"
                    image.write_text(json.dumps(changed))
                with patch.object(release, "get_release") as lookup, patch.object(release, "command") as command:
                    with self.assertRaises(ValueError):
                        self.publish()
                    lookup.assert_not_called()
                    command.assert_not_called()
                for path, contents in originals.items():
                    path.write_bytes(contents)

    def test_fresh_release_is_draft_until_all_six_assets_have_uploaded(self):
        draft = self.fixture_release(draft=True, complete=False)
        calls = []

        def command(*args):
            calls.append(args)
            if args[:2] == ("release", "create"):
                notes = Path(args[args.index("--notes-file") + 1]).read_text()
                self.assertIn("Assisted-by: Codex <codex@openai.com>", notes)
                self.assertIn(self.commit, notes)
            return b""

        with patch.object(release, "get_release", side_effect=[None, draft]), patch.object(release, "command", side_effect=command):
            self.publish()
        self.assertEqual(calls[0][:3], ("release", "create", self.tag))
        self.assertIn("--draft", calls[0])
        self.assertIn("--verify-tag", calls[0])
        self.assertNotIn("--prerelease", calls[0])
        self.assertEqual(calls[0][calls[0].index("--target") + 1], self.commit)
        self.assertEqual([call[:2] for call in calls[1:-1]], [("release", "upload")] * 6)
        self.assertEqual({Path(call[3]).name for call in calls[1:-1]},
                         {path.name for path in release.assets(self.source, self.digests, self.tag, self.commit)})
        self.assertEqual(calls[-1][:3], ("release", "edit", self.tag))
        self.assertIn("--draft=false", calls[-1])

    def test_failed_asset_upload_never_publishes_draft(self):
        draft = self.fixture_release(draft=True, complete=False)
        with patch.object(release, "get_release", return_value=draft), patch.object(release, "command", side_effect=subprocess.CalledProcessError(1, "gh")) as command:
            with self.assertRaises(subprocess.CalledProcessError):
                self.publish()
        self.assertEqual(command.call_args.args[:2], ("release", "upload"))

    def test_matching_published_release_is_idempotent(self):
        existing = self.fixture_release()
        with patch.object(release, "get_release", return_value=existing), patch.object(release, "command") as command:
            self.publish()
            command.assert_not_called()

    def test_conflicting_assets_and_published_missing_assets_are_never_mutated(self):
        existing = self.fixture_release()
        conflicting = copy.deepcopy(existing)
        conflicting["assets"][0]["digest"] = "sha256:" + "0" * 64
        missing = copy.deepcopy(existing)
        missing["assets"].pop()
        for record in (conflicting, missing):
            with self.subTest(record=record), patch.object(release, "get_release", return_value=record), patch.object(release, "command") as command:
                with self.assertRaisesRegex(ValueError, "conflicting|missing"):
                    self.publish()
                command.assert_not_called()

    def test_legacy_asset_without_digest_is_downloaded_and_checked(self):
        existing = self.fixture_release()
        existing["assets"][0].pop("digest")

        def command(*args):
            self.assertEqual(args[:2], ("release", "download"))
            directory = Path(args[args.index("--dir") + 1])
            (directory / "source.tar.gz").write_bytes(self.archive.read_bytes())
            return b""

        with patch.object(release, "get_release", return_value=existing), patch.object(release, "command", side_effect=command) as invoke:
            self.publish()
            self.assertEqual(invoke.call_count, 1)

    def test_http_403_is_not_treated_as_absent_release(self):
        forbidden = subprocess.CompletedProcess([], 1, b"", b"gh: Forbidden (HTTP 403)")
        with patch.object(release.subprocess, "run", return_value=forbidden), patch.object(release, "command") as command:
            with self.assertRaisesRegex(ValueError, "existing GitHub Release state"):
                self.publish()
            command.assert_not_called()
        absent = subprocess.CompletedProcess([], 1, b"", b"gh: Not Found (HTTP 404)")
        with patch.object(release.subprocess, "run", return_value=absent):
            self.assertIsNone(release.get_release(self.tag))
