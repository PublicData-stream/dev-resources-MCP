"""Release event classification and repeated publication identity fences."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

scripts = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("release_event", scripts / "release_event.py")
event = importlib.util.module_from_spec(spec)
with patch.object(sys, "path", [str(scripts), *sys.path]):
    spec.loader.exec_module(event)

COMMIT = "abcdef12" + "0" * 32
OBJECT = "1" * 40


class ReleaseEventTests(unittest.TestCase):
    def setUp(self):
        self.release = {"id": 42, "tag_name": "1.2.3", "draft": False,
                        "prerelease": False, "immutable": False, "target_commitish": "main"}
        self.event = {"repository": {"full_name": event.REPOSITORY}, "action": "published",
                      "release": copy.deepcopy(self.release)}
        self.addCleanup(patch.stopall)
        self.tag_check = patch.object(event, "tag_fence", return_value=OBJECT).start()
        self.lookup = patch.object(event, "fetch_release", side_effect=lambda identity: copy.deepcopy(self.release)).start()

    def validate(self, name="release", tag="1.2.3", payload=None, repository=event.REPOSITORY):
        return event.validate_event(payload or self.event, name, f"refs/tags/{tag}", COMMIT, repository)

    def test_stable_published_release_captures_identity(self):
        result = self.validate()
        self.assertEqual(result, {"tag": "1.2.3", "version": "1.2.3", "revision": COMMIT,
                                  "kind": "stable", "tag-object": OBJECT, "release-id": "42"})
        self.tag_check.assert_called_once_with("1.2.3", COMMIT)
        self.lookup.assert_called_once_with("42")

    def test_beta_requires_prerelease(self):
        self.release.update(tag_name="1.2.3-beta.0", prerelease=True)
        self.event["release"] = copy.deepcopy(self.release)
        self.assertEqual(self.validate(tag="1.2.3-beta.0")["kind"], "beta")
        self.event["release"]["prerelease"] = False
        with self.assertRaises(ValueError):
            self.validate(tag="1.2.3-beta.0")

    def test_build_requires_matching_tag_push(self):
        tag = "1.2.3-build.abcdef12"
        payload = {"repository": {"full_name": event.REPOSITORY},
                   "ref": "refs/tags/" + tag, "deleted": False}
        result = self.validate(name="push", tag=tag, payload=payload)
        self.assertEqual((result["kind"], result["release-id"]), ("build", ""))
        self.lookup.assert_not_called()

    def test_stable_and_beta_pushes_are_rejected(self):
        for tag in ("1.2.3", "1.2.3-beta.1"):
            payload = {"repository": {"full_name": event.REPOSITORY},
                       "ref": "refs/tags/" + tag, "deleted": False}
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.validate(name="push", tag=tag, payload=payload)
        self.tag_check.assert_not_called()

    def test_build_release_event_is_rejected(self):
        self.event["release"].update(tag_name="1.2.3-build.abcdef12", prerelease=True)
        with self.assertRaisesRegex(ValueError, "tag pushes"):
            self.validate(tag="1.2.3-build.abcdef12")

    def test_nonpublished_draft_immutable_and_wrong_classification_are_rejected(self):
        for field, value in (("draft", True), ("prerelease", True), ("immutable", True), ("id", True)):
            payload = copy.deepcopy(self.event)
            payload["release"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(payload=payload)
        payload = copy.deepcopy(self.event)
        payload["action"] = "created"
        with self.assertRaises(ValueError):
            self.validate(payload=payload)

    def test_ref_and_canonical_repository_must_match(self):
        with self.assertRaises(ValueError):
            self.validate(tag="2.0.0")
        with self.assertRaises(ValueError):
            self.validate(repository="fork/dev-resources-MCP")
        payload = copy.deepcopy(self.event)
        payload["repository"]["full_name"] = "fork/dev-resources-MCP"
        with self.assertRaises(ValueError):
            self.validate(payload=payload)

    def test_current_release_must_still_match_event(self):
        for field, value in (("id", 43), ("tag_name", "2.0.0"), ("immutable", True), ("draft", True)):
            original = copy.deepcopy(self.release)
            self.release[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
            self.release = original

    def test_deleted_and_mismatched_push_refs_are_rejected(self):
        tag = "1.2.3-build.abcdef12"
        for ref, deleted in (("refs/tags/" + tag, True), ("refs/heads/main", False)):
            payload = {"repository": {"full_name": event.REPOSITORY}, "ref": ref, "deleted": deleted}
            with self.subTest(ref=ref, deleted=deleted), self.assertRaises(ValueError):
                self.validate(name="push", tag=tag, payload=payload)

    def test_repeated_check_rechecks_remote_tag_and_current_release(self):
        self.assertEqual(event.check("1.2.3", COMMIT, OBJECT, "stable", "42"), self.release)
        self.tag_check.assert_called_once_with("1.2.3", COMMIT, OBJECT)
        self.lookup.assert_called_once_with("42")

    def test_repeated_check_rejects_kind_and_release_id_confusion(self):
        for tag, kind, identity in (("1.2.3", "build", ""), ("1.2.3", "stable", "main"),
                                    ("1.2.3-build.abcdef12", "build", "42")):
            with self.subTest(kind=kind, identity=identity), self.assertRaises(ValueError):
                event.check(tag, COMMIT, OBJECT, kind, identity)
        self.tag_check.assert_not_called()

    def test_repeated_check_requires_captured_tag_object(self):
        with self.assertRaises(ValueError):
            event.check("1.2.3", COMMIT, "", "stable", "42")
        self.tag_check.assert_not_called()

    def test_repeated_build_check_has_no_release_api_dependency(self):
        self.assertIsNone(event.check("1.2.3-build.abcdef12", COMMIT, OBJECT, "build", ""))
        self.lookup.assert_not_called()


class TagFenceTests(unittest.TestCase):
    def test_expected_tag_object_is_forwarded_and_checked(self):
        with patch.object(event.subprocess, "check_output", return_value=(OBJECT + "\n").encode()) as command:
            self.assertEqual(event.tag_fence("1.2.3", COMMIT, OBJECT), OBJECT)
        command.assert_called_once_with(["scripts/verify-release-tag.sh", "1.2.3", COMMIT, OBJECT])

    def test_invalid_or_changed_tag_objects_are_rejected(self):
        with patch.object(event.subprocess, "check_output", return_value=b"0" * 40):
            with self.assertRaises(ValueError):
                event.tag_fence("1.2.3", COMMIT, OBJECT)
            with self.assertRaises(ValueError):
                event.tag_fence("1.2.3", COMMIT, "short")

    def test_remote_fence_failure_is_not_ignored(self):
        with patch.object(event.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, "git")):
            with self.assertRaises(subprocess.CalledProcessError):
                event.tag_fence("1.2.3", COMMIT, OBJECT)
