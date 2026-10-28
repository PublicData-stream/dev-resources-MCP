"""Offline corresponding-source and append-only GitHub Release contracts."""
import copy
from contextlib import ExitStack
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
COMMAND = release.command
FETCH_RELEASE = release.fetch_release
CREATE = ("api", f"repos/{release.REPOSITORY}/releases")


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
        self.api_reads = []
        self.addCleanup(patch.stopall)
        patch.object(release, "get_release", side_effect=lambda tag: copy.deepcopy(self.remote)).start()
        patch.object(release, "check", side_effect=self.fence).start()
        patch.object(release, "fetch_release", side_effect=lambda identity: copy.deepcopy(self.remote)).start()
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
        if arguments[:2] == CREATE:
            self.assertEqual(arguments[arguments.index("--method") + 1], "POST")
            request = Path(arguments[arguments.index("--input") + 1])
            self.assertTrue(request.is_relative_to("/tmp"))
            payload = json.loads(request.read_text())
            self.assertEqual(set(payload), {"tag_name", "target_commitish", "name", "body",
                                           "draft", "prerelease"})
            self.assertEqual(payload["tag_name"], self.tag)
            self.assertEqual(payload["target_commitish"], self.commit)
            self.assertEqual(payload["name"], self.tag)
            self.assertIs(payload["draft"], True)
            self.assertIs(payload["prerelease"], True)
            self.assertIn("Assisted-by: Codex <codex@openai.com>", payload["body"])
            self.remote = self.fixture_release(draft=True, complete=False)
            return json.dumps(self.remote).encode()
        elif arguments[:2] == ("release", "upload"):
            path = Path(arguments[3])
            self.remote["assets"].append({"name": path.name, "digest": "sha256:" + release.checksum(path)})
        elif arguments[:2] == ("release", "edit"):
            self.assertEqual(len(self.remote["assets"]), 6)
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
        self.assertEqual(self.calls[0][:2], CREATE)
        self.assertEqual(self.calls[-1][:2], ("release", "edit"))
        self.assertEqual(len(self.remote["assets"]), 6)
        self.assertFalse(self.remote["draft"])

    def test_failed_immediate_tag_fence_prevents_creation(self):
        self.build()
        self.remote = None
        with patch.object(release, "check", side_effect=[None, ValueError("Tag identity changed")]), \
             patch.object(release, "command") as command:
            with self.assertRaisesRegex(ValueError, "Tag identity changed"):
                self.publish()
        command.assert_not_called()

    def test_uncertain_creation_is_not_retried_or_published(self):
        self.build()
        self.remote = None

        def create_then_fail(*arguments):
            self.command(*arguments)
            raise subprocess.CalledProcessError(1, "gh")

        with patch.object(release, "command", side_effect=create_then_fail), \
             patch.object(release, "fetch_release") as fetch:
            with self.assertRaises(subprocess.CalledProcessError):
                self.publish()
        self.assertEqual([call[:2] for call in self.calls], [CREATE])
        self.assertTrue(self.remote["draft"])
        fetch.assert_not_called()

    def test_invalid_creation_response_stops_without_retry_or_upload(self):
        self.build()
        draft = self.fixture_release(draft=True, complete=False)
        invalid = [b"not JSON private-response-sentinel", b"\xff", b"null", b"[]"]
        for field, value in (("id", True), ("id", 0), ("tag_name", "different"),
                             ("prerelease", False), ("draft", False),
                             ("immutable", True), ("immutable", None)):
            invalid.append(json.dumps({**draft, field: value}).encode())
        for field in ("id", "tag_name", "prerelease", "draft"):
            invalid.append(json.dumps({key: value for key, value in draft.items()
                                       if key != field}).encode())
        for response in invalid:
            with self.subTest(response=response):
                self.remote = None
                with patch.object(release, "command", return_value=response) as command, \
                     patch.object(release, "fetch_release") as fetch:
                    with self.assertRaises(ValueError) as error:
                        self.publish()
                self.assertNotIn("private-response-sentinel", str(error.exception))
                command.assert_called_once()
                self.assertEqual(command.call_args.args[:2], CREATE)
                fetch.assert_not_called()

    def test_created_draft_disappearing_by_id_stops_before_upload(self):
        self.build()
        self.remote = None
        with patch.object(release, "fetch_release", side_effect=subprocess.CalledProcessError(1, "gh")) as fetch:
            with self.assertRaises(subprocess.CalledProcessError):
                self.publish()
        self.assertEqual([call[:2] for call in self.calls], [CREATE])
        fetch.assert_called_once_with("42")
        self.assertTrue(self.remote["draft"])

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
                    with self.assertRaisesRegex(ValueError, f"stage=publication field={field} reason="):
                        self.publish()
                self.assertFalse(self.calls)

    def test_build_id_rechecks_reject_identity_changes_before_upload(self):
        self.build()
        self.remote = self.fixture_release(draft=True, complete=False)
        for field, value in (("id", 43), ("id", True), ("tag_name", "different"),
                             ("draft", False), ("prerelease", False), ("immutable", True)):
            with self.subTest(field=field, value=value), patch.object(release, "fetch_release", return_value={
                    **self.remote, field: value}) as fetch:
                with self.assertRaisesRegex(ValueError, f"stage=publication field={field} reason="):
                    self.publish()
                fetch.assert_called_once_with("42")
                self.assertFalse(self.calls)

    def test_immutable_build_missing_assets_is_rejected(self):
        self.build()
        self.remote = self.fixture_release(complete=False)
        self.remote["immutable"] = True
        with self.assertRaisesRegex(ValueError, "Immutable"):
            self.publish()
        self.assertFalse(self.calls)

    def test_complete_immutable_published_build_is_idempotent(self):
        self.build()
        self.remote = self.fixture_release()
        self.remote["immutable"] = True
        with self.github_transport():
            self.publish()
        self.assertFalse(self.calls)

    def test_published_build_requires_explicit_boolean_mutability(self):
        self.build()
        for value in ("missing", None, 0, "false"):
            with self.subTest(value=value):
                self.remote = self.fixture_release()
                if value == "missing":
                    self.remote.pop("immutable")
                else:
                    self.remote["immutable"] = value
                with self.github_transport(), self.assertRaisesRegex(
                        ValueError, "stage=initial field=immutable reason="):
                    self.publish()
                self.assertFalse(self.calls)

    def test_stable_and_beta_still_require_explicit_false_mutability(self):
        for kind, tag in (("stable", "1.2.3"), ("beta", "1.2.3-beta.1")):
            self.kind, self.tag = kind, tag
            self.write_metadata()
            for value in ("missing", None, True):
                with self.subTest(kind=kind, value=value):
                    self.remote = self.fixture_release()
                    if value == "missing":
                        self.remote.pop("immutable")
                    else:
                        self.remote["immutable"] = value
                    with self.assertRaisesRegex(ValueError, "stage=initial field=immutable reason="):
                        self.publish()
                    self.assertFalse(self.calls)

    def test_invalid_draft_identity_diagnostics_are_fixed_and_stop_uploads(self):
        self.build()
        private = "private-response-sentinel\nInjected diagnostic"
        for field, value, reason in (("id", True, "wrong-type"), ("id", 0, "invalid"),
                                     ("tag_name", private, "mismatch"),
                                     ("draft", private, "wrong-type"),
                                     ("prerelease", False, "mismatch"),
                                     ("immutable", None, "wrong-type"),
                                     ("immutable", 0, "wrong-type"),
                                     ("immutable", private, "wrong-type"),
                                     ("immutable", True, "mismatch")):
            with self.subTest(field=field, value=value):
                self.remote = self.fixture_release(draft=True, complete=False)
                self.remote.update({field: value, "body": private, "unexpected": private})
                with self.assertRaises(ValueError) as error:
                    self.publish()
                self.assertEqual(str(error.exception),
                                 f"GitHub Release identity rejected: stage=initial field={field} reason={reason}")
                self.assertFalse(self.calls)
        for field in ("id", "tag_name", "draft", "prerelease"):
            with self.subTest(missing=field):
                self.remote = self.fixture_release(draft=True, complete=False)
                self.remote.pop(field)
                with self.assertRaisesRegex(ValueError, f"stage=initial field={field} reason=missing"):
                    self.publish()
                self.assertFalse(self.calls)

    def test_draft_mutability_omission_and_false_can_alternate_during_upload(self):
        self.build()
        for initially_omitted in (True, False):
            with self.subTest(initially_omitted=initially_omitted):
                self.calls.clear()
                self.remote = self.fixture_release(draft=True, complete=False)
                if initially_omitted:
                    self.remote.pop("immutable")
                reads = 0

                def observe(identity):
                    nonlocal reads
                    self.assertEqual(identity, "42")
                    reads += 1
                    result = copy.deepcopy(self.remote)
                    if (reads % 2 == 0) == initially_omitted:
                        result.pop("immutable", None)
                    else:
                        result["immutable"] = False
                    return result

                with patch.object(release, "fetch_release", side_effect=observe):
                    self.publish()
                self.assertEqual(reads, 7)
                self.assertEqual([call[:2] for call in self.calls],
                                 [("release", "upload")] * 6 + [("release", "edit")])

    def test_invalid_recheck_stops_remaining_uploads_and_publication(self):
        self.build()
        for field, value in (("id", 43), ("tag_name", "different"), ("draft", False),
                             ("prerelease", False), ("immutable", True), ("immutable", None)):
            with self.subTest(field=field, value=value):
                self.calls.clear()
                self.remote = self.fixture_release(draft=True, complete=False)
                self.remote.pop("immutable")

                def observe(identity):
                    result = copy.deepcopy(self.remote)
                    if self.calls:
                        result[field] = value
                    return result

                with patch.object(release, "fetch_release", side_effect=observe), \
                     self.assertRaisesRegex(ValueError, f"stage=publication field={field} reason="):
                    self.publish()
                self.assertEqual([call[:2] for call in self.calls], [("release", "upload")])
                self.assertTrue(self.remote["draft"])

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

    def github_transport(self, fail_after_upload=False, omit_draft_immutable=False,
                         hide_created_draft=False):
        def encode(observed):
            observed = copy.deepcopy(observed)
            if omit_draft_immutable and observed is not None and observed["draft"]:
                observed.pop("immutable", None)
            return json.dumps(observed).encode()

        def by_tag(arguments, **kwargs):
            self.assertEqual(arguments, ["gh", "api", f"repos/{release.REPOSITORY}/releases/tags/{self.tag}"])
            if self.remote is None or self.remote["draft"]:
                return subprocess.CompletedProcess(arguments, 1, b"", b"gh: Not Found (HTTP 404)")
            return subprocess.CompletedProcess(arguments, 0, encode(self.remote), b"")

        def execute(arguments):
            if arguments[1] == "api":
                if "--method" in arguments:
                    response = self.command(*arguments[1:])
                    return encode(json.loads(response))
                self.api_reads.append(tuple(arguments[2:]))
                endpoint = arguments[2]
                if endpoint.endswith("/releases?per_page=100"):
                    self.assertIn("--paginate", arguments)
                    self.assertIn("--slurp", arguments)
                    observed = json.loads(encode(self.remote))
                    if hide_created_draft and any(call[:2] == CREATE for call in self.calls):
                        observed = None
                    return json.dumps([[{"id": 1, "tag_name": "older"}],
                                       [observed] if observed else []]).encode()
                self.assertEqual(endpoint, f"repos/{release.REPOSITORY}/releases/42")
                if fail_after_upload and self.calls and self.calls[-1][:2] == ("release", "upload"):
                    raise subprocess.CalledProcessError(1, arguments, stderr=b"HTTP 404")
                return encode(self.remote)
            return self.command(*arguments[1:])

        stack = ExitStack()
        stack.enter_context(patch.object(release, "get_release", GET_RELEASE))
        stack.enter_context(patch.object(release, "command", COMMAND))
        stack.enter_context(patch.object(release, "fetch_release", FETCH_RELEASE))
        stack.enter_context(patch.object(release.subprocess, "run", side_effect=by_tag))
        stack.enter_context(patch.object(release.subprocess, "check_output", side_effect=execute))
        return stack

    def test_draft_lookup_supports_fresh_and_resumed_build_publication(self):
        self.build()
        for fresh in (True, False):
            for omitted in (True, False):
                with self.subTest(fresh=fresh, immutable_omitted=omitted):
                    self.calls.clear()
                    self.api_reads.clear()
                    self.remote = None if fresh else self.fixture_release(draft=True, complete=False)
                    with self.github_transport(omit_draft_immutable=omitted):
                        self.publish()
                    mutations = [call[:2] for call in self.calls]
                    self.assertEqual(mutations, ([CREATE] if fresh else [])
                                     + [("release", "upload")] * 6 + [("release", "edit")])
                    self.assertFalse(self.remote["draft"])
                    self.assertEqual(sum("--paginate" in read for read in self.api_reads), 1)
                    self.assertTrue(any(read[0].endswith("/releases/42") for read in self.api_reads))

    def test_created_draft_need_not_appear_in_inventory(self):
        self.build()
        self.remote = None
        with self.github_transport(hide_created_draft=True):
            self.publish()
        self.assertEqual(sum("--paginate" in read for read in self.api_reads), 1)
        self.assertEqual([call[:2] for call in self.calls],
                         [CREATE] + [("release", "upload")] * 6 + [("release", "edit")])
        self.assertFalse(self.remote["draft"])

    def test_disappearing_draft_stops_without_recreation_or_publication(self):
        self.build()
        self.remote = self.fixture_release(draft=True, complete=False)
        with self.github_transport(fail_after_upload=True):
            with self.assertRaises(subprocess.CalledProcessError):
                self.publish()
        self.assertEqual([call[:2] for call in self.calls], [("release", "upload")])
        self.assertTrue(self.remote["draft"])


class ReleaseLookupTests(unittest.TestCase):
    tag = "1.2.3-build.abcdef12"

    def setUp(self):
        self.remote = {"id": 42, "tag_name": self.tag, "draft": True,
                       "prerelease": True, "immutable": False, "assets": []}
        self.not_found = subprocess.CompletedProcess([], 1, b"", b"gh: Not Found (HTTP 404)")

    def lookup(self, pages, detail=None):
        responses = [json.dumps(pages).encode(), json.dumps(self.remote if detail is None else detail).encode()]
        with patch.object(release.subprocess, "run", return_value=self.not_found), \
             patch.object(release.subprocess, "check_output", side_effect=responses):
            return GET_RELEASE(self.tag)

    def test_published_release_uses_by_tag_without_listing(self):
        response = subprocess.CompletedProcess([], 0, json.dumps(self.remote).encode(), b"")
        with patch.object(release.subprocess, "run", return_value=response), \
             patch.object(release.subprocess, "check_output") as fallback:
            self.assertEqual(GET_RELEASE(self.tag), self.remote)
        fallback.assert_not_called()

    def test_draft_on_later_page_is_fetched_by_numeric_id(self):
        with patch.object(release.subprocess, "run", return_value=self.not_found), \
             patch.object(release.subprocess, "check_output", side_effect=[
                 json.dumps([[{"id": 1, "tag_name": "older"}], [self.remote]]).encode(),
                 json.dumps(self.remote).encode()]) as api:
            self.assertEqual(GET_RELEASE(self.tag), self.remote)
        self.assertEqual(api.call_args_list[0].args[0], ["gh", "api",
                         f"repos/{release.REPOSITORY}/releases?per_page=100", "--paginate", "--slurp"])
        self.assertEqual(api.call_args_list[1].args[0], ["gh", "api",
                         f"repos/{release.REPOSITORY}/releases/42"])

    def test_absence_requires_successful_exhaustive_listing(self):
        for pages in ([[]], [[{"id": 1, "tag_name": "older"}], []]):
            with self.subTest(pages=pages):
                self.assertIsNone(self.lookup(pages))

    def test_lookup_errors_are_not_absence(self):
        for status in (403, 500):
            response = subprocess.CompletedProcess([], 1, b"", f"gh: Failed (HTTP {status})".encode())
            with self.subTest(status=status), patch.object(release.subprocess, "run", return_value=response), \
                 patch.object(release.subprocess, "check_output") as fallback:
                with self.assertRaises(ValueError):
                    GET_RELEASE(self.tag)
                fallback.assert_not_called()
        with patch.object(release.subprocess, "run", return_value=self.not_found), \
             patch.object(release.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, "gh")):
            with self.assertRaises(subprocess.CalledProcessError):
                GET_RELEASE(self.tag)

    def test_malformed_and_duplicate_listing_is_rejected(self):
        for pages in ({}, [], [None], [[None]], [[{}]], [[{"tag_name": 42}]],
                      [[self.remote], [self.remote]]):
            with self.subTest(pages=pages), self.assertRaises(ValueError):
                self.lookup(pages)
        with patch.object(release.subprocess, "run", return_value=self.not_found), \
             patch.object(release.subprocess, "check_output", return_value=b"not JSON"):
            with self.assertRaises(ValueError):
                GET_RELEASE(self.tag)

    def test_invalid_discovered_ids_and_changed_details_are_rejected(self):
        for identity in (None, True, 0, -1, "42"):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                self.lookup([[{**self.remote, "id": identity}]])
        for field, value in (("id", 43), ("id", True), ("tag_name", "different")):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.lookup([[self.remote]], {**self.remote, field: value})
