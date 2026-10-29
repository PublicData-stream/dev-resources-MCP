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


class ToolInventoryTests(unittest.TestCase):
    def test_exact_dotted_inventory(self):
        tools = [{"name": name} for name in smoke.EXPECTED_TOOLS]
        smoke.assert_tool_inventory(tools)
        self.assertEqual(len(tools), 88)

    def test_legacy_alias_extra_missing_and_duplicate_are_rejected(self):
        tools = [{"name": name} for name in sorted(smoke.EXPECTED_TOOLS)]
        for invalid in (tools + [{"name": "server_info"}], tools[:-1], tools + [tools[0]],
                        [{"name": tool["name"].replace(".", "_", 1)} for tool in tools]):
            with self.subTest(count=len(invalid)), self.assertRaises(AssertionError):
                smoke.assert_tool_inventory(invalid)


class StoredIdentityTests(unittest.TestCase):
    def test_fresh_storage_identity_requires_tagged_lowercase_blake3(self):
        value = "blake3:" + "a" * 64
        self.assertEqual(smoke.require_blake3(value), value)
        for invalid in ("a" * 64, "sha256:" + "a" * 64, "blake3:" + "A" * 64,
                        "blake3:" + "a" * 63, "blake3:" + "a" * 65,
                        value + "\n", " " + value, None, 123):
            with self.subTest(value=invalid), self.assertRaisesRegex(AssertionError, "tagged BLAKE3"):
                smoke.require_blake3(invalid)


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
        self.assertEqual(client.calls, [("server.info", {}), ("server.info", {})])
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
        if name != "advisory.corpus_status":
            selected = arguments.get("snapshot", arguments.get("advisory_snapshot"))
            if selected != smoke.SYNTHETIC_SNAPSHOT:
                raise AssertionError("synthetic request did not pin the fixture")
        if name == "advisory.get":
            return {"id": smoke.SYNTHETIC_ADVISORY, "snapshot": self.snapshot,
                    "source_url": "https://fixtures.invalid/devres/storage-probe/advisory",
                    "page": {"text": self.text},
                    "resource_uri": f"devres://advisory/rustsec/{smoke.SYNTHETIC_ADVISORY}/{smoke.SYNTHETIC_SNAPSHOT}"}
        if name == "advisory.catalog_search":
            return {"total": 1}
        if name == "advisory.lookup":
            total = int(arguments["version"] == "1.0.0")
            return {"complete": True, "total": total, "items": [{"id": smoke.SYNTHETIC_ADVISORY}] if total else []}
        if name == "audit.lockfile":
            self.private_comment_seen |= arguments["lockfile"].startswith("# " + smoke.AUDIT_PRIVACY_MARKER)
            report = {"complete": True, "snapshot": self.snapshot, "package_count": 1,
                      "assessed_count": 1, "unassessed_count": 0, "input_retention": "request_lifetime_only",
                      "vulnerability_count": self.vulnerability_count, "status": "known_vulnerabilities",
                      "total_findings": 1, "findings": [{"advisory": {"id": smoke.SYNTHETIC_ADVISORY}}]}
            if self.leak:
                report["diagnostic"] = smoke.AUDIT_PRIVACY_MARKER
            return report
        if name == "advisory.corpus_status":
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
        if method != "tools/call" or params["name"] != "audit.lockfile":
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
        self.assertEqual({revision for name, revision in client.calls if name == "audit.lockfile"},
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

class SyntheticMdnClient:
    def __init__(self, false_provenance=False, wrong_support=False):
        self.calls = []
        self.false_provenance = false_provenance
        self.wrong_support = wrong_support
        self.resources = {}

    def tool(self, name, arguments, revision=smoke.MODERN):
        self.calls.append((name, revision))
        if name == "mdn.corpus_status":
            return {"collection_enabled": False}
        expected = (smoke.SYNTHETIC_MDN_COMPAT if name in
                    ("mdn.compat_get", "mdn.compat_search", "mdn.browser_get") else smoke.SYNTHETIC_MDN_CONTENT)
        if arguments.get("snapshot") != expected:
            raise AssertionError("MDN fixture request did not pin its source snapshot")
        if name == "mdn.get":
            original = arguments.get("representation") == "source"
            text = ("---\ntitle: Synthetic MDN storage fixture\n---\nsource" if original else
                    smoke.SYNTHETIC_MDN_TEXT + "\nfixture_browser: version_added=1")
            uri = f"devres://mdn/content/{expected}/{'source' if original else 'text'}/Zml4dHVyZQ"
            provenance = {"snapshot": expected, "coverage": {"synthetic": True}}
            self.resources[uri] = {"text": text, "_meta": {"provenance": provenance,
                                                          "license": {"synthetic": True}}}
            return {"provenance": provenance, "source_url": ("https://github.com/mdn/content" if self.false_provenance else
                    "https://fixtures.invalid/mdn/content"), "page": {"text": text}, "resource_uri": uri}
        if name == "mdn.search":
            return {"total": 1, "results": [{"slug": "Web/Fixture"}]}
        if name == "mdn.compat_get":
            statement = {"fixture_browser": {"version_added": "2" if self.wrong_support else "1"}}
            return {"original": statement, "resolved": statement}
        if name == "mdn.compat_search":
            return {"total": 1}
        if name == "mdn.browser_get":
            return {"releases": [{"version": "1"}]}
        raise AssertionError("unexpected MDN fixture operation")

    def call(self, method, params, revision=smoke.MODERN):
        self.calls.append((method, revision))
        if method == "resources/read":
            return {"contents": [self.resources[params["uri"]]]}
        if method == "tools/call" and params["name"] == "fetch":
            return {"structuredContent": {"contents": [self.resources[params["arguments"]["id"]]]}}
        raise AssertionError("unexpected MDN fixture RPC")


class SyntheticMdnTests(unittest.TestCase):
    def test_seeded_mdn_exercises_both_revisions_and_original_resources(self):
        client = SyntheticMdnClient()
        smoke.synthetic_mdn(client)
        self.assertEqual({revision for name, revision in client.calls if name == "mdn.get"},
                         {smoke.MODERN, smoke.LEGACY})
        self.assertEqual(sum(name == "resources/read" for name, _ in client.calls), 4)

    def test_synthetic_mdn_cannot_claim_upstream_provenance(self):
        with self.assertRaisesRegex(AssertionError, "invented upstream"):
            smoke.synthetic_mdn(SyntheticMdnClient(false_provenance=True))

    def test_changed_compatibility_evidence_fails_acceptance(self):
        with self.assertRaisesRegex(AssertionError, "statement changed"):
            smoke.synthetic_mdn(SyntheticMdnClient(wrong_support=True))


class SyntheticWhatwgClient:
    def __init__(self, upstream=False, script_leak=False, wrong_symbol=False, changed_resource=False):
        self.calls = []
        self.upstream = upstream
        self.script_leak = script_leak
        self.wrong_symbol = wrong_symbol
        self.changed_resource = changed_resource
        self.resources = {}

    def tool(self, name, arguments, revision=smoke.MODERN):
        self.calls.append((name, revision))
        if arguments.get("snapshot") != smoke.SYNTHETIC_WHATWG:
            raise AssertionError("WHATWG fixture request must pin its snapshot")
        if name == "whatwg.search":
            return {"total": 1, "results": [{"standard": "fixture"}]}
        if name == "whatwg.symbol_get":
            representation = "symbol"
            text = "WrongToken" if self.wrong_symbol else "FixtureToken"
        elif name == "whatwg.get":
            representation = arguments.get("representation", "text")
            text = ("<h1 id=fixture>Synthetic WHATWG storage fixture</h1><script>fixture_hidden_script()</script>"
                    if representation == "source" else smoke.SYNTHETIC_WHATWG_TEXT)
            if self.script_leak and representation == "text":
                text += "fixture_hidden_script()"
        else:
            raise AssertionError("unexpected WHATWG fixture operation")
        uri = f"devres://whatwg/fixture/{smoke.SYNTHETIC_WHATWG}/{representation}/aW5kZXguaHRtbA"
        self.resources[uri] = {"text": "changed" if self.changed_resource else text}
        return {"selection": {"snapshot": smoke.SYNTHETIC_WHATWG,
                "source_url": "https://dom.spec.whatwg.org/" if self.upstream else "https://fixtures.invalid/whatwg",
                "coverage": {"synthetic": True}}, "page": {"text": text}, "resource_uri": uri}

    def call(self, method, params, revision=smoke.MODERN):
        self.calls.append((method, revision))
        if method == "resources/read":
            return {"contents": [self.resources[params["uri"]]]}
        if method == "tools/call" and params["name"] == "fetch":
            return {"structuredContent": {"contents": [self.resources[params["arguments"]["id"]]]}}
        raise AssertionError("unexpected WHATWG fixture RPC")


class SyntheticWhatwgTests(unittest.TestCase):
    def test_fixture_covers_both_revisions_and_all_immutable_representations(self):
        client = SyntheticWhatwgClient()
        smoke.synthetic_whatwg(client)
        self.assertEqual({revision for name, revision in client.calls if name == "whatwg.get"},
                         {smoke.MODERN, smoke.LEGACY})
        self.assertEqual(sum(name == "resources/read" for name, _ in client.calls), 6)
        self.assertEqual(sum(name == "tools/call" for name, _ in client.calls), 6)

    def test_fixture_cannot_claim_official_upstream_provenance(self):
        with self.assertRaisesRegex(AssertionError, "invented upstream"):
            smoke.synthetic_whatwg(SyntheticWhatwgClient(upstream=True))

    def test_script_text_leak_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "inert text"):
            smoke.synthetic_whatwg(SyntheticWhatwgClient(script_leak=True))

    def test_changed_symbol_or_immutable_resource_fails(self):
        with self.assertRaisesRegex(AssertionError, "symbol changed"):
            smoke.synthetic_whatwg(SyntheticWhatwgClient(wrong_symbol=True))
        with self.assertRaisesRegex(AssertionError, "immutable resource changed"):
            smoke.synthetic_whatwg(SyntheticWhatwgClient(changed_resource=True))


class SyntheticW3cClient:
    def __init__(self, upstream=False, script_leak=False, wrong_symbol=False, changed_resource=False):
        self.calls = []
        self.upstream = upstream
        self.script_leak = script_leak
        self.wrong_symbol = wrong_symbol
        self.changed_resource = changed_resource
        self.resources = {}

    def tool(self, name, arguments, revision=smoke.MODERN):
        self.calls.append((name, revision))
        if arguments.get("snapshot") != smoke.SYNTHETIC_W3C:
            raise AssertionError("W3C fixture request must pin its snapshot")
        if name == "w3c.search":
            return {"total": 1, "results": [{"specification": "fixture"}]}
        if name == "w3c.symbol_get":
            representation = "symbol"
            text = "WrongToken" if self.wrong_symbol else "FixtureToken"
        elif name == "w3c.get":
            representation = arguments.get("representation", "text")
            text = ("<h1 id=fixture>Synthetic W3C storage fixture</h1><script>fixture_hidden_script()</script>"
                    if representation == "source" else smoke.SYNTHETIC_W3C_TEXT)
            if self.script_leak and representation == "text":
                text += "fixture_hidden_script()"
        else:
            raise AssertionError("unexpected W3C fixture operation")
        uri = f"devres://w3c/fixture/{smoke.SYNTHETIC_W3C}/{representation}/aW5kZXguaHRtbA"
        metadata = {"copyright": "Synthetic fixture authors", "publication_status": "synthetic"}
        self.resources[uri] = {"text": "changed" if self.changed_resource else text, "_meta": {"source_metadata": metadata}}
        if representation == "bytes":
            self.resources[uri + "?limit=8"] = {"blob": "changed" if self.changed_resource else "PGgxIGlkPWY=", "_meta": {"source_metadata": metadata}}
        return {"selection": {"snapshot": smoke.SYNTHETIC_W3C,
                "source_url": "https://www.w3.org/TR/dom/" if self.upstream else "https://fixtures.invalid/w3c",
                "coverage": {"synthetic": True}}, "source_metadata": metadata, "derived_notice": "Synthetic derivation notice", "page": {"text": text, "base64": "PGgxIGlkPWY="}, "resource_uri": uri}

    def call(self, method, params, revision=smoke.MODERN):
        self.calls.append((method, revision))
        if method == "resources/read":
            return {"contents": [self.resources[params["uri"]]]}
        if method == "tools/call" and params["name"] == "fetch":
            return {"structuredContent": {"contents": [self.resources[params["arguments"]["id"]]]}}
        raise AssertionError("unexpected W3C fixture RPC")


class SyntheticW3cTests(unittest.TestCase):
    def test_fixture_covers_both_revisions_and_all_immutable_representations(self):
        client = SyntheticW3cClient()
        smoke.synthetic_w3c(client)
        self.assertEqual({revision for name, revision in client.calls if name == "w3c.get"},
                         {smoke.MODERN, smoke.LEGACY})
        self.assertEqual(sum(name == "resources/read" for name, _ in client.calls), 8)
        self.assertEqual(sum(name == "tools/call" for name, _ in client.calls), 8)

    def test_fixture_cannot_claim_official_upstream_provenance(self):
        with self.assertRaisesRegex(AssertionError, "invented upstream"):
            smoke.synthetic_w3c(SyntheticW3cClient(upstream=True))

    def test_script_text_leak_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "inert text"):
            smoke.synthetic_w3c(SyntheticW3cClient(script_leak=True))

    def test_changed_symbol_or_immutable_resource_fails(self):
        with self.assertRaisesRegex(AssertionError, "symbol changed"):
            smoke.synthetic_w3c(SyntheticW3cClient(wrong_symbol=True))
        with self.assertRaisesRegex(AssertionError, "immutable resource changed"):
            smoke.synthetic_w3c(SyntheticW3cClient(changed_resource=True))


class SyntheticW3cNoticeTests(unittest.TestCase):
    def test_missing_copyright_and_derived_notices_fail_acceptance(self):
        class MissingNotice(SyntheticW3cClient):
            def tool(self, name, arguments, revision=smoke.MODERN):
                result=super().tool(name,arguments,revision)
                if name=="w3c.get":
                    result.pop("source_metadata",None)
                return result
        with self.assertRaisesRegex(AssertionError,"copyright notice missing"):
            smoke.synthetic_w3c(MissingNotice())

    def test_missing_resource_notice_fails_acceptance(self):
        class MissingResourceNotice(SyntheticW3cClient):
            def call(self, method, params, revision=smoke.MODERN):
                result=super().call(method,params,revision)
                value=result.get("structuredContent",result)
                if "contents" in value:
                    value["contents"][0].pop("_meta",None)
                return result
        with self.assertRaisesRegex(AssertionError,"resource copyright missing"):
            smoke.synthetic_w3c(MissingResourceNotice())
