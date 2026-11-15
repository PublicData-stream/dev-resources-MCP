"""Offline checks of private npm metadata acceptance; never starts a service."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "npm_diagnosis_fixture", Path(__file__).parents[1] / "npm-diagnosis-fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def report():
    return {"version": 1, "provider": "npm", "schema": 18, "complete": True,
            "outcome": "inspected", "bytes_read": 512, "diagnostics": [{
                "operation": "npm_advisory_metadata", "job": None,
                "provider_requests": 0, "export_bytes": "not_checked",
                "full_membership": "not_checked", "attribution_qualified": "not_checked",
                "default": {"id": "blake3:" + "a" * 64, "ready": "verified",
                            "snapshot_metadata": "verified", "synthetic": True,
                            "export_artifact": None}}]}


class NpmDiagnosisAcceptanceTests(unittest.TestCase):
    def test_metadata_success_retains_explicit_unchecked_coverage(self):
        fixture.validate_report(report())

    def test_incomplete_and_unverified_default_cannot_pass(self):
        for field, value in (("complete", False), ("outcome", "selected_evidence_unavailable"),
                             ("bytes_read", fixture.MAX_INPUT + 1), ("provider", "mdn")):
            invalid = report()
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                fixture.validate_report(invalid)
        invalid = report()
        invalid["diagnostics"][0]["default"]["ready"] = "missing"
        with self.assertRaisesRegex(AssertionError, "linkage"):
            fixture.validate_report(invalid)

    def test_provider_traffic_and_fabricated_export_acceptance_are_rejected(self):
        for field, value in (("provider_requests", 1), ("export_bytes", "verified"),
                             ("full_membership", "verified"), ("attribution_qualified", "verified")):
            invalid = report()
            invalid["diagnostics"][0][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                fixture.validate_report(invalid)

    def test_reports_cannot_expose_paths_source_urls_error_text_or_audit_inputs(self):
        for key, value in (("relative_path", "npm/raw-artifacts/value"),
                           ("message", "private server exception"),
                           ("source_url", "https://example.invalid"),
                           ("lockfile", "private supplied data"),
                           ("extra", "postgres://private@database"),
                           ("extra", "devres-smoke-private-comment-4d1a8e7c")):
            invalid = report()
            invalid["diagnostics"][0]["unexpected"] = {key: value}
            with self.subTest(key=key), self.assertRaises(AssertionError):
                fixture.validate_report(invalid)

    def test_reader_command_uses_private_tmp_output_and_cleans_it(self):
        observed = []

        def command(args, **kwargs):
            observed.append((args, kwargs))
            output = Path(args[-1])
            self.assertEqual(output.parent.parent, Path("/tmp"))
            self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
            output.write_text(json.dumps(report()))
            output.chmod(0o600)
            return subprocess.CompletedProcess(args, 0, b"fixed metadata", b"")

        with patch.object(fixture.subprocess, "run", side_effect=command), patch("sys.stdout", io.StringIO()):
            fixture.main()
        args, kwargs = observed[0]
        self.assertEqual(args[:5], ["devres-server", "diagnose-collection", "/fixture/backend.toml", "--provider", "npm"])
        self.assertIn("--latest-failure", args)
        self.assertEqual(kwargs["timeout"], 40)
        self.assertFalse(Path(args[-1]).parent.exists())

    def test_nonprivate_or_oversized_output_cannot_pass(self):
        for private in (False, True):
            def command(args, **_kwargs):
                output = Path(args[-1])
                output.write_bytes(b"x" * (fixture.MAX_REPORT + 1) if private else json.dumps(report()).encode())
                output.chmod(0o600 if private else 0o644)
                return subprocess.CompletedProcess(args, 0, b"", b"")

            with self.subTest(private=private), patch.object(fixture.subprocess, "run", side_effect=command), self.assertRaises(AssertionError):
                fixture.main()


if __name__ == "__main__":
    unittest.main()
