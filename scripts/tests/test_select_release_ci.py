"""Offline checks for release reuse of a complete canonical CI attempt."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import select_release_ci as reuse  # noqa: E402


REVISION = "a" * 40
NOW = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)
START = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
# Fixture inventory is intentionally independent of the selector's required set.
JOB_NAMES = (
    "dependencies", "edge", "rust (ubuntu-26.04)", "rust (ubuntu-26.04-arm)",
    "e2e-build (amd64)", "e2e-build (arm64)",
    "e2e (docker, amd64)", "e2e (docker, arm64)",
    "e2e (minikube, amd64)", "e2e (minikube, arm64)",
)


def run(*, run_id=42, attempt=1, started=START):
    return {
        "id": run_id,
        "run_attempt": attempt,
        "workflow_id": 9,
        "path": reuse.WORKFLOW_PATH,
        "event": "push",
        "head_branch": "main",
        "head_sha": REVISION,
        "repository": {"full_name": reuse.REPOSITORY},
        "head_repository": {"full_name": reuse.REPOSITORY},
        "status": "completed",
        "conclusion": "success",
        "run_started_at": started,
    }


def jobs(*, run_id=42, attempt=1):
    return [
        {
            "name": name,
            "run_id": run_id,
            "run_attempt": attempt,
            "head_sha": REVISION,
            "status": "completed",
            "conclusion": "success",
        }
        for name in sorted(JOB_NAMES)
    ]


class FakeApi:
    def __init__(self, *, runs=None, attempt_jobs=None):
        self.runs = deepcopy([run()] if runs is None else runs)
        self.jobs = deepcopy(jobs() if attempt_jobs is None else attempt_jobs)
        self.latest = deepcopy(self.runs[0]) if self.runs else None
        self.calls = []

    def __call__(self, path):
        self.calls.append(path)
        if path == "/actions/workflows/ci.yml":
            return {"id": 9, "path": reuse.WORKFLOW_PATH}
        if path.startswith("/actions/workflows/ci.yml/runs?"):
            return {"total_count": len(self.runs), "workflow_runs": deepcopy(self.runs)}
        if path == "/actions/runs/42/attempts/1":
            return deepcopy(self.runs[0])
        if path == "/actions/runs/42/attempts/2":
            return deepcopy(self.runs[0])
        if path.startswith("/actions/runs/42/attempts/") and "/jobs?" in path:
            return {"total_count": len(self.jobs), "jobs": deepcopy(self.jobs)}
        if path == "/actions/runs/42":
            return deepcopy(self.latest)
        raise AssertionError(f"unexpected API path: {path}")


class ReleaseCIReuseTests(unittest.TestCase):
    def test_accepts_complete_first_attempt_and_complete_rerun(self):
        first = FakeApi()
        self.assertEqual(reuse.select_reusable_ci(first, REVISION, NOW), (42, 1))
        rerun = FakeApi(runs=[run(attempt=2)], attempt_jobs=jobs(attempt=2))
        self.assertEqual(reuse.select_reusable_ci(rerun, REVISION, NOW), (42, 2))
        self.assertIn("/actions/runs/42/attempts/2/jobs?per_page=100&page=1", rerun.calls)

    def test_partial_rerun_cannot_borrow_jobs_from_earlier_attempt(self):
        partial = FakeApi(runs=[run(attempt=2)], attempt_jobs=jobs(attempt=2)[:-1])
        self.assertIsNone(reuse.select_reusable_ci(partial, REVISION, NOW))

    def test_newer_failure_cannot_be_hidden_by_older_success(self):
        newest = run(started=(NOW - timedelta(minutes=5)).isoformat())
        newest["conclusion"] = "failure"
        older = run(run_id=41)
        api = FakeApi(runs=[older, newest])
        self.assertIsNone(reuse.select_reusable_ci(api, REVISION, NOW))
        self.assertFalse(any("/jobs?" in path for path in api.calls))

    def test_age_and_identity_are_required(self):
        stale = FakeApi(runs=[run(started=(NOW - timedelta(hours=25)).isoformat())])
        self.assertIsNone(reuse.select_reusable_ci(stale, REVISION, NOW))
        future = FakeApi(runs=[run(started=(NOW + timedelta(seconds=1)).isoformat())])
        self.assertIsNone(reuse.select_reusable_ci(future, REVISION, NOW))
        for field, value in (
            ("path", ".github/workflows/other.yml"),
            ("head_repository", {"full_name": "someone/fork"}),
            ("status", "in_progress"),
        ):
            with self.subTest(field=field):
                bad = run()
                bad[field] = value
                self.assertIsNone(reuse.select_reusable_ci(FakeApi(runs=[bad]), REVISION, NOW))
        for field, value in (("head_sha", "b" * 40), ("event", "pull_request"),
                             ("head_branch", "other")):
            with self.subTest(field=field):
                bad = run()
                bad[field] = value
                with self.assertRaises(reuse.EvidenceUnavailable):
                    reuse.select_reusable_ci(FakeApi(runs=[bad]), REVISION, NOW)

    def test_missing_duplicate_failed_or_wrong_attempt_job_rejects_reuse(self):
        variants = []
        variants.append(jobs()[:-1])
        duplicate = jobs()
        duplicate[-1]["name"] = duplicate[0]["name"]
        variants.append(duplicate)
        failed = jobs()
        failed[-1]["conclusion"] = "skipped"
        variants.append(failed)
        wrong_attempt = jobs()
        wrong_attempt[-1]["run_attempt"] = 2
        variants.append(wrong_attempt)
        for attempt_jobs in variants:
            with self.subTest(last=attempt_jobs[-1]):
                self.assertIsNone(reuse.select_reusable_ci(
                    FakeApi(attempt_jobs=attempt_jobs), REVISION, NOW
                ))

    def test_rerun_started_during_job_read_rejects_reuse(self):
        api = FakeApi()
        api.latest["run_attempt"] = 2
        self.assertIsNone(reuse.select_reusable_ci(api, REVISION, NOW))

    def test_malformed_or_incomplete_pagination_is_unavailable(self):
        def missing_page(path):
            if path == "/actions/workflows/ci.yml":
                return {"id": 9, "path": reuse.WORKFLOW_PATH}
            return {"total_count": 101, "workflow_runs": []}

        with self.assertRaises(reuse.EvidenceUnavailable):
            reuse.select_reusable_ci(missing_page, REVISION, NOW)

        extra = FakeApi(attempt_jobs=jobs() + jobs()[:1])
        with self.assertRaises(reuse.EvidenceUnavailable):
            reuse.select_reusable_ci(extra, REVISION, NOW)

        pages = {
            1: {"total_count": 101, "items": [{"id": index} for index in range(100)]},
            2: {"total_count": 101, "items": [{"id": 100}]},
        }

        def fetch_page(path):
            return pages[int(path.rsplit("page=", 1)[1])]

        self.assertEqual(len(reuse.paged_items(fetch_page, "/items", "items", 200)), 101)

    def test_exact_freshness_boundary_and_no_runs(self):
        boundary = run(started=(NOW - timedelta(hours=24)).isoformat())
        self.assertEqual(reuse.select_reusable_ci(FakeApi(runs=[boundary]), REVISION, NOW), (42, 1))
        boundary["run_started_at"] = (NOW - timedelta(hours=24, microseconds=1)).isoformat()
        self.assertIsNone(reuse.select_reusable_ci(FakeApi(runs=[boundary]), REVISION, NOW))
        self.assertIsNone(reuse.select_reusable_ci(FakeApi(runs=[]), REVISION, NOW))

    def test_ambiguous_newest_run_and_bad_clock_cannot_establish_evidence(self):
        with self.assertRaises(reuse.EvidenceUnavailable):
            reuse.select_reusable_ci(FakeApi(runs=[run(), run(run_id=43)]), REVISION, NOW)
        with self.assertRaises(reuse.EvidenceUnavailable):
            reuse.select_reusable_ci(FakeApi(), REVISION, NOW.replace(tzinfo=None))
        with self.assertRaises(reuse.EvidenceUnavailable):
            reuse.select_reusable_ci(FakeApi(), "invalid", NOW)

    def test_changed_pagination_and_oversized_response_are_rejected(self):
        pages = {
            1: {"total_count": 101, "items": [{"id": index} for index in range(100)]},
            2: {"total_count": 102, "items": [{"id": 100}, {"id": 101}]},
        }
        with self.assertRaises(reuse.EvidenceUnavailable):
            reuse.paged_items(lambda path: pages[int(path.rsplit("page=", 1)[1])],
                              "/items", "items", 200)
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b" " * (reuse.MAX_RESPONSE_BYTES + 1)
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(reuse, "build_opener", return_value=opener):
            with self.assertRaisesRegex(reuse.EvidenceUnavailable, "too large"):
                reuse.request_json("/actions/workflows/ci.yml", "test-only-token")
        response.read.assert_called_once_with(reuse.MAX_RESPONSE_BYTES + 1)

    def test_redirects_are_rejected_without_forwarding_credentials(self):
        with self.assertRaisesRegex(reuse.EvidenceUnavailable, "redirect"):
            reuse.RejectRedirect().redirect_request(None, None, 302, None, None,
                                                    "https://example.invalid/redirect")

    def test_complete_selection_outputs_identity_and_other_repository_never_queries(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-ci-selector-test.") as temporary:
            output = Path(temporary) / "output"
            environment = {"GITHUB_REPOSITORY": reuse.REPOSITORY, "GITHUB_TOKEN": "test-only-token",
                           "GITHUB_OUTPUT": str(output), "RELEASE_REVISION": REVISION}
            with patch.dict(os.environ, environment), patch.object(
                    reuse, "select_reusable_ci", return_value=(42, 2)):
                self.assertEqual(reuse.main(), 0)
            self.assertEqual(output.read_text(), "reuse=true\nrun_id=42\nattempt=2\n")
            output.unlink()
            environment["GITHUB_REPOSITORY"] = "someone/fork"
            with patch.dict(os.environ, environment), patch.object(reuse, "request_json") as request:
                self.assertEqual(reuse.main(), 0)
                request.assert_not_called()
            self.assertEqual(output.read_text(), "reuse=false\n")

    def test_api_failure_falls_back_to_fresh_ci(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-ci-selector-test.") as temporary:
            output = Path(temporary) / "output"
            environment = {
                "GITHUB_REPOSITORY": reuse.REPOSITORY,
                "GITHUB_TOKEN": "test-only-token",
                "GITHUB_OUTPUT": str(output),
                "RELEASE_REVISION": REVISION,
            }
            with patch.dict(os.environ, environment), patch.object(
                reuse, "request_json", side_effect=URLError("unavailable")
            ):
                self.assertEqual(reuse.main(), 0)
            self.assertEqual(output.read_text(), "reuse=false\n")


if __name__ == "__main__":
    unittest.main()
