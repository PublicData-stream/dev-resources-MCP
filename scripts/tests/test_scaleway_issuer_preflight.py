import importlib.util
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


SPEC = importlib.util.spec_from_file_location(
    "issuer_preflight", Path(__file__).resolve().parents[1] / "scaleway-issuer-preflight.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IssuerPreflightTests(unittest.TestCase):
    def config(self):
        return {"organization_id": "00000000-0000-4000-8000-000000000001",
                "project_id": "00000000-0000-4000-8000-000000000002",
                "issuer_application_id": "00000000-0000-4000-8000-000000000003",
                "reader_application_id": "00000000-0000-4000-8000-000000000004",
                "writer_application_id": "00000000-0000-4000-8000-000000000005",
                "access": "test-access", "secret": "SENSITIVE-MARKER"}

    def test_every_list_is_organization_qualified_and_bounded(self):
        client = MODULE.IAM(self.config())
        query = parse_qs(urlsplit(client.list_path(client.config["reader_application_id"], "x y")).query)
        self.assertEqual(query["organization_id"], [client.config["organization_id"]])
        self.assertEqual(query["description"], ["x y"])
        self.assertEqual(query["page"], ["1"])
        self.assertEqual(query["page_size"], ["100"])

    def test_reads_require_positive_identity_and_lists_without_leaking_values(self):
        client = MODULE.IAM(self.config())
        with patch.object(client, "request", side_effect=[
                (200, {"application_id": client.config["issuer_application_id"], "secret_key": "SENSITIVE-MARKER"}),
                (200, {"total_count": 0, "api_keys": []}), (403, {})]):
            value = MODULE.inspect(client)
        self.assertFalse(value["positive_reads_passed"])
        self.assertFalse(value["acceptance_complete"])
        self.assertNotIn("SENSITIVE-MARKER", json.dumps(value))

    def test_boolean_or_over_capacity_count_does_not_pass(self):
        client = MODULE.IAM(self.config())
        for count in (True, 101, -1):
            with patch.object(client, "request", side_effect=[
                    (200, {"application_id": client.config["issuer_application_id"]}),
                    (200, {"total_count": count, "api_keys": []}),
                    (200, {"total_count": 0, "api_keys": []})]):
                self.assertFalse(MODULE.inspect(client)["positive_reads_passed"])

    def test_read_failure_prevents_key_creation(self):
        client = MODULE.IAM(self.config())
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            with patch.object(client, "request", return_value=(403, {})) as request:
                with self.assertRaises(MODULE.PreflightError):
                    MODULE.issue(client, Path(directory) / "state")
            self.assertTrue(all(call.args[0] == "GET" for call in request.call_args_list))

    def test_uncertain_create_is_recorded_before_io_and_never_replayed(self):
        client = MODULE.IAM(self.config())
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory) / "state"

            def request(method, path, body=None):
                self.assertEqual(method, "POST")
                self.assertTrue((root / "reader-intent.json").exists())
                raise MODULE.PreflightError("iam_request_uncertain")

            with patch.object(MODULE, "inspect", return_value={"positive_reads_passed": True}), \
                    patch.object(client, "request", side_effect=request) as remote:
                with self.assertRaises(MODULE.PreflightError):
                    MODULE.issue(client, root)
                with self.assertRaises(MODULE.PreflightError):
                    MODULE.issue(client, root)
            self.assertEqual(remote.call_count, 1)
            self.assertEqual((root / "reader-intent.json").stat().st_mode & 0o777, 0o600)

    def test_symlinks_and_readable_secret_files_are_refused(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            source = root / "secret"
            source.write_text("SENSITIVE-MARKER")
            source.chmod(0o644)
            with self.assertRaises(MODULE.PreflightError):
                MODULE.private_read(source)
            source.chmod(0o600)
            link = root / "link"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                MODULE.private_read(link)

    def test_redirect_never_forwards_the_issuer_token(self):
        with self.assertRaises(MODULE.PreflightError):
            MODULE.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid")

    def test_nonexpiring_overlong_expired_and_naive_keys_are_rejected(self):
        now = datetime.now(timezone.utc)
        maximum = (now + timedelta(seconds=900)).isoformat()
        for value in ({}, {"expires_at": None},
                      {"expires_at": (now + timedelta(seconds=901)).isoformat()},
                      {"expires_at": (now - timedelta(seconds=1)).isoformat()},
                      {"expires_at": (now + timedelta(seconds=500)).replace(tzinfo=None).isoformat()}):
            with self.subTest(value=value):
                with self.assertRaises(MODULE.PreflightError):
                    MODULE.checked_expiry(value, maximum)
        self.assertEqual(MODULE.checked_expiry({"expires_at": maximum}, maximum).isoformat(), maximum)

    def test_writable_parent_is_refused_before_network_or_state_creation(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = Path(directory)
            parent.chmod(0o777)
            client = MODULE.IAM(self.config())
            with patch.object(client, "request") as request:
                with self.assertRaises(MODULE.PreflightError):
                    MODULE.issue(client, parent / "state")
            self.assertFalse(request.called)
            self.assertFalse((parent / "state").exists())

    def test_readback_metadata_mismatch_stops_before_another_key_is_created(self):
        for field in ("description", "default_project_id", "expires_at"):
            with self.subTest(field=field), tempfile.TemporaryDirectory(dir="/tmp") as directory:
                client = MODULE.IAM(self.config())
                created = {}
                calls = []

                def request(method, path, body=None):
                    calls.append(method)
                    if method == "POST":
                        created.update(body, access_key="test-created", secret_key="SENSITIVE-MARKER")
                        return 200, created.copy()
                    readback = created.copy()
                    readback[field] = None
                    return 200, readback

                with patch.object(MODULE, "inspect", return_value={"positive_reads_passed": True}), \
                        patch.object(client, "request", side_effect=request):
                    with self.assertRaises(MODULE.PreflightError):
                        MODULE.issue(client, Path(directory) / "state")
                self.assertEqual(calls, ["POST", "GET"])


if __name__ == "__main__":
    unittest.main()
