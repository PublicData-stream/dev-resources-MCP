import importlib.util
import io
import pathlib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("mcp_smoke", pathlib.Path(__file__).parents[1] / "mcp_smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class Response(io.BytesIO):
    def __init__(self, body, content_type="application/json"):
        super().__init__(body)
        self.content_type = content_type

    def getheader(self, _name, _default=None):
        return self.content_type


class DecodeResponseTests(unittest.TestCase):
    def test_resource_read_routes_by_uri_in_modern_mcp_name_header(self):
        uri = "devres://source/?name=example&version=1.0.0&path=src%2Flib.rs"
        response = Response(b'{"jsonrpc":"2.0","id":1,"result":{"contents":[]}}')
        response.status = 200
        with patch.object(smoke.http.client, "HTTPConnection") as connection:
            connection.return_value.getresponse.return_value = response
            client = smoke.Client("http://fixture.invalid/mcp")
            client.exchange("resources/read", {"uri": uri})
            headers = connection.return_value.request.call_args.args[3]
            self.assertEqual(headers["Mcp-Method"], "resources/read")
            self.assertEqual(headers["Mcp-Name"], uri)
        response = Response(b'{"jsonrpc":"2.0","id":1,"result":{"contents":[]}}')
        response.status = 200
        with patch.object(smoke.http.client, "HTTPConnection") as connection:
            connection.return_value.getresponse.return_value = response
            client = smoke.Client("http://fixture.invalid/mcp")
            client.exchange("resources/read", {"uri": uri}, smoke.LEGACY)
            self.assertNotIn("Mcp-Name", connection.return_value.request.call_args.args[3])
    def test_text_only_rfc_recheck_still_requires_live_opt_in(self):
        with patch.object(smoke, "Client") as client, patch.object(smoke.signal, "signal"), patch("sys.argv", ["mcp_smoke.py", "--url", "https://edge/mcp", "--rfc-text-only"]), patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                smoke.main()
            self.assertEqual(result.exception.code, 2)
            client.assert_not_called()
    def test_sse_ignores_progress_and_stops_at_result(self):
        body = b'data: {"method":"notifications/progress"}\n\ndata: {"id":2,"result":{}}\n\n'
        self.assertEqual(smoke.decode_response(Response(body, "text/event-stream"), 2), {"id": 2, "result": {}})

    def test_oversized_json_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "bound"):
            smoke.decode_response(Response(b" " * (smoke.MAX_RESPONSE + 1)), 1)

    def test_truncated_sse_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "did not contain"):
            smoke.decode_response(Response(b'data: {"id":3}\n', "text/event-stream"), 1)

    def test_non_http_url_is_rejected(self):
        with self.assertRaises(ValueError):
            smoke.Client("file:///etc/passwd")

    def test_incomplete_advisory_assessment_cannot_pass_live_acceptance(self):
        with self.assertRaisesRegex(AssertionError, "incomplete"):
            smoke.require_snapshot({"complete": False, "status": "incomplete"})

    def test_stale_advisory_assessment_cannot_establish_live_freshness(self):
        with self.assertRaisesRegex(AssertionError, "fresh"):
            smoke.require_snapshot({"complete": True, "snapshot": {"revision": "a" * 40, "stale": True}})

    def test_unassessed_fixture_cannot_pass_live_audit(self):
        with self.assertRaisesRegex(AssertionError, "not assessed"):
            smoke.require_audit({"complete": True, "snapshot": {"revision": "a" * 40, "stale": False},
                                 "package_count": 1, "assessed_count": 0}, "a" * 40)

    def test_synthetic_evidence_cannot_pass_live_provider_acceptance(self):
        report = {"complete": True, "snapshot": {"revision": "a" * 40, "stale": False,
                  "coverage": {"synthetic": True}}}
        with self.assertRaisesRegex(AssertionError, "synthetic"):
            smoke.require_snapshot(report)
        self.assertEqual(smoke.require_snapshot(report, allow_synthetic=True), "a" * 40)

    def test_routing_readiness_retries_only_server_identity(self):
        class RecoveringClient:
            timeout = 45
            calls = []

            def tool(self, name, arguments):
                self.calls.append((name, arguments))
                if len(self.calls) == 1:
                    raise OSError("endpoint propagation")
                return {"product": "dev-resources-MCP", "license": "AGPL-3.0-only"}

        client = RecoveringClient()
        with patch.object(smoke.time, "sleep"):
            smoke.wait_ready(client, 2)
        self.assertEqual(client.calls, [("server_info", {}), ("server_info", {})])
        self.assertEqual(client.timeout, 45)


class SyntheticClient:
    """Fixture replies for validating the acceptance assertions, without I/O."""
    def __init__(self, leak=False, vulnerability_count=1, invalid_status=None, leak_invalid=False):
        self.calls = []
        self.private_comment_seen = False
        self.leak = leak
        self.vulnerability_count = vulnerability_count
        self.invalid_status = invalid_status
        self.leak_invalid = leak_invalid
        self.text = "Synthetic storage-probe advisory\nOffline fixture only."
        self.snapshot = {"id": smoke.SYNTHETIC_SNAPSHOT, "revision": "a" * 40,
                         "stale": False, "coverage": {"synthetic": True}}

    def tool(self, name, arguments, revision=smoke.MODERN):
        self.calls.append((name, revision))
        if name != "advisory_corpus_status":
            selected = arguments.get("snapshot", arguments.get("advisory_snapshot"))
            if selected != smoke.SYNTHETIC_SNAPSHOT:
                raise AssertionError("synthetic request did not pin the fixture")
        if name == "advisory_get":
            return {"id": smoke.SYNTHETIC_ADVISORY, "snapshot": self.snapshot,
                    "source_url": "https://fixtures.invalid/devres/storage-probe/advisory",
                    "page": {"text": self.text},
                    "resource_uri": f"devres://advisory/rustsec/{smoke.SYNTHETIC_ADVISORY}/{smoke.SYNTHETIC_SNAPSHOT}"}
        if name == "advisory_catalog_search":
            return {"total": 1}
        if name == "advisory_lookup":
            total = int(arguments["version"] == "1.0.0")
            return {"complete": True, "total": total, "items": [{"id": smoke.SYNTHETIC_ADVISORY}] if total else []}
        if name == "audit_lockfile":
            self.private_comment_seen |= arguments["lockfile"].startswith("# " + smoke.AUDIT_PRIVACY_MARKER)
            report = {"complete": True, "snapshot": self.snapshot, "package_count": 1,
                      "assessed_count": 1, "unassessed_count": 0, "input_retention": "request_lifetime_only",
                      "vulnerability_count": self.vulnerability_count, "status": "known_vulnerabilities",
                      "total_findings": 1, "findings": [{"advisory": {"id": smoke.SYNTHETIC_ADVISORY}}]}
            if self.leak:
                report["diagnostic"] = smoke.AUDIT_PRIVACY_MARKER
            return report
        if name == "advisory_corpus_status":
            return {"counts": {"snapshots": 1}}
        raise AssertionError("unexpected synthetic fixture tool")

    def call(self, method, params, revision=smoke.MODERN):
        self.calls.append((method, revision))
        if method == "resources/read":
            return {"contents": [{"text": self.text}]}
        if method == "tools/call" and params["name"] == "fetch":
            return {"structuredContent": {"contents": [{"text": self.text}]}}
        raise AssertionError("unexpected synthetic fixture RPC")

    def exchange(self, method, params, revision=smoke.MODERN):
        if method != "tools/call" or params["name"] != "audit_lockfile":
            raise AssertionError("unexpected synthetic fixture exchange")
        self.calls.append(("invalid_audit", revision))
        message = smoke.AUDIT_PRIVACY_MARKER if self.leak_invalid else "Invalid Cargo.lock."
        status = self.invalid_status if self.invalid_status is not None else (400 if revision == smoke.MODERN else 200)
        return status, {"error": {"code": -32602, "message": message}}


class SyntheticAdvisoryTests(unittest.TestCase):
    def test_seeded_snapshot_exercises_both_revisions_and_typed_resources(self):
        client = SyntheticClient()
        smoke.synthetic_advisory(client)
        self.assertTrue(client.private_comment_seen)
        self.assertEqual({revision for name, revision in client.calls if name == "audit_lockfile"},
                         {smoke.MODERN, smoke.LEGACY})
        self.assertEqual(sum(name == "resources/read" for name, _revision in client.calls), 2)
        self.assertEqual({revision for name, revision in client.calls if name == "invalid_audit"},
                         {smoke.MODERN, smoke.LEGACY})

    def test_private_comment_leak_cannot_pass_transport_acceptance(self):
        with self.assertRaisesRegex(AssertionError, "private comment"):
            smoke.synthetic_advisory(SyntheticClient(leak=True))

    def test_missing_positive_finding_cannot_pass_seeded_acceptance(self):
        with self.assertRaises(AssertionError):
            smoke.synthetic_advisory(SyntheticClient(vulnerability_count=0))

    def test_modern_malformed_audit_requires_existing_http_400_mapping(self):
        with self.assertRaisesRegex(AssertionError, "HTTP 400"):
            smoke.synthetic_advisory(SyntheticClient(invalid_status=200))

    def test_legacy_malformed_audit_keeps_existing_http_200_error_mapping(self):
        with self.assertRaisesRegex(AssertionError, "2025-11-25.*HTTP 200"):
            smoke.synthetic_advisory(SyntheticClient(invalid_status=400))

    def test_invalid_audit_error_must_not_reflect_private_comment(self):
        with self.assertRaisesRegex(AssertionError, "audit error reflected"):
            smoke.synthetic_advisory(SyntheticClient(leak_invalid=True))
