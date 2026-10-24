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
