#!/usr/bin/env python3
"""Bounded native MCP HTTP acceptance. No provider calls unless --live is set."""
import argparse
import hashlib
import http.client
import json
import ssl
import signal
import time
import urllib.parse

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
MAX_RESPONSE = 8 * 1024 * 1024
SYNTHETIC_MDN_CONTENT = hashlib.sha256(b"devres:storage-probe:mdn-content:v1").hexdigest()
SYNTHETIC_MDN_COMPAT = hashlib.sha256(b"devres:storage-probe:mdn-compat:v1").hexdigest()
SYNTHETIC_MDN_TEXT = "Synthetic MDN storage fixture"
SYNTHETIC_ADVISORY = "RUSTSEC-2024-0001"
SYNTHETIC_SNAPSHOT = hashlib.sha256(b"devres:storage-probe:rustsec:v1").hexdigest()
AUDIT_PRIVACY_MARKER = "devres-smoke-private-comment-4d1a8e7c"


def decode_response(response, request_id):
    """Read one bounded JSON/SSE RPC response, without waiting for SSE EOF."""
    if response.getheader("content-type", "").startswith("text/event-stream"):
        remaining = MAX_RESPONSE
        while remaining > 0:
            line = response.readline(remaining + 1)
            remaining -= len(line)
            if remaining < 0:
                raise ValueError("response exceeds bound")
            if not line:
                break
            if line.startswith(b"data:"):
                value = json.loads(line[5:].strip())
                if value.get("id") == request_id:
                    return value
        raise ValueError("SSE response did not contain this request's result")
    raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("response exceeds bound")
    return json.loads(raw) if raw else None


class Client:
    def __init__(self, url, ca=None, cert=None, key=None, origin="https://client.example"):
        self.url = urllib.parse.urlsplit(url)
        if self.url.scheme not in ("http", "https") or not self.url.hostname:
            raise ValueError("HTTP(S) URL required")
        self.context = ssl.create_default_context(cafile=ca)
        if cert:
            self.context.load_cert_chain(cert, key)
        self.origin = origin
        self.ident = 0
        self.timeout = 45

    def exchange(self, method, params=None, revision=MODERN, path=None, host=None, origin=None):
        self.ident += 1
        params = dict(params or {})
        if revision == MODERN:
            params.setdefault("_meta", {}).update({
                "io.modelcontextprotocol/protocolVersion": revision,
                "io.modelcontextprotocol/clientInfo": {"name": "devres-smoke", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {},
            })
        body = {"jsonrpc": "2.0", "id": self.ident, "method": method, "params": params}
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": revision, "Origin": origin or self.origin}
        if host:
            headers["Host"] = host
        if revision == MODERN:
            headers["Mcp-Method"] = method
            if "name" in params:
                headers["Mcp-Name"] = params["name"]
            elif "uri" in params:
                headers["Mcp-Name"] = params["uri"]
        args = (self.url.hostname, self.url.port)
        connection = (http.client.HTTPSConnection(*args, context=self.context, timeout=self.timeout)
                      if self.url.scheme == "https" else http.client.HTTPConnection(*args, timeout=self.timeout))
        try:
            connection.request("POST", path or self.url.path or "/mcp", json.dumps(body), headers)
            response = connection.getresponse()
            status = response.status
            if response.getheader("content-type", "").startswith(("application/json", "text/event-stream")):
                value = decode_response(response, self.ident)
            else:
                response.read(MAX_RESPONSE + 1)
                value = None
            return status, value
        finally:
            connection.close()

    def call(self, method, params=None, revision=MODERN):
        status, value = self.exchange(method, params, revision)
        if status != 200 or not value or "error" in value:
            raise AssertionError(f"{method}: expected successful RPC, HTTP {status}")
        return value["result"]

    def tool(self, name, arguments, revision=MODERN):
        result = self.call("tools/call", {"name": name, "arguments": arguments}, revision)
        if result.get("isError"):
            error = result.get("structuredContent", {})
            # Server contract guarantees sanitized errors. Never log arguments,
            # entire response bodies, submitted lockfiles, or dependency graphs.
            raise AssertionError(f"tool {name} failed: {error.get('code')}: {error.get('message')}")
        return result.get("structuredContent", result)


def smoke(client, negative=True):
    for revision in (MODERN, LEGACY):
        if revision == MODERN:
            client.call("server/discover", revision=revision)
        else:
            client.call("initialize", {"protocolVersion": revision, "capabilities": {},
                        "clientInfo": {"name": "devres-smoke", "version": "1"}}, revision)
        tools = client.call("tools/list", revision=revision)["tools"]
        names = {tool["name"] for tool in tools}
        assert {"server_info", "search", "fetch", "audit_lockfile"} <= names, names
        assert {"crate_versions", "crate_catalog_search", "crate_document_get", "crate_dependencies",
                "crate_compare", "crate_content_search", "crate_api_search", "crate_api_get",
                "crate_corpus_status"} <= names, names
        assert {"advisory_get", "advisory_catalog_search", "advisory_history",
                "advisory_snapshots", "advisory_corpus_status"} <= names, names
        assert {"mdn_search", "mdn_get", "mdn_compat_search", "mdn_compat_get",
                "mdn_browser_get", "mdn_history", "mdn_snapshots", "mdn_corpus_status"} <= names, names
        mdn = client.tool("mdn_corpus_status", {}, revision)
        assert isinstance(mdn.get("collection_enabled"), bool), "MDN collection status missing"
        mdn_schema = next(tool["inputSchema"] for tool in tools if tool["name"] == "mdn_get")
        assert mdn_schema.get("additionalProperties") is False and len(mdn_schema.get("oneOf", [])) == 2, "MDN document selector schema missing"
        code, rejected = client.exchange("tools/call", {"name": "mdn_get", "arguments": {"slug": "Web/Fixture", "url": "https://untrusted.invalid"}}, revision)
        assert code == (400 if revision == MODERN else 200) and rejected.get("error", {}).get("code") == -32602, "MDN schema admitted an arbitrary destination"
        advisories = client.call("tools/call", {"name": "advisory_corpus_status", "arguments": {}}, revision)
        assert not advisories.get("isError"), "advisory corpus status failed"
        assert isinstance(advisories.get("structuredContent", {}).get("counts"), dict), "missing advisory corpus counts"
        corpus = client.call("tools/call", {"name": "crate_corpus_status", "arguments": {}}, revision)
        assert not corpus.get("isError"), "crate corpus status failed"
        assert isinstance(corpus.get("structuredContent", {}).get("collection_enabled"), bool)
        info = client.call("tools/call", {"name": "server_info", "arguments": {}}, revision)
        assert not info.get("isError"), "server_info failed"
        identity = info.get("structuredContent", {})
        assert identity.get("product") == "dev-resources-MCP", "wrong service identity"
        assert identity.get("license") == "AGPL-3.0-only", "missing source-license offer"
        assert identity.get("sourceUrl", "").startswith("https://"), "missing corresponding-source URL"
    if negative:
        for overrides in ({"origin": "https://untrusted.invalid"}, {"host": "untrusted.invalid"},
                          {"path": "/live"}, {"path": "/ready"}, {"path": "/metrics"}):
            status, value = client.exchange("tools/list", **overrides)
            assert status >= 400 or (value and "error" in value), "boundary accepted invalid request"


def require_snapshot(report, allow_synthetic=False):
    assert report.get("complete") is True, "live RustSec assessment was incomplete"
    snapshot = report.get("snapshot", {})
    assert allow_synthetic or snapshot.get("coverage", {}).get("synthetic") is not True, "synthetic advisory evidence cannot establish live provider acceptance"
    revision = snapshot.get("revision", "")
    assert len(revision) == 40 and all(char in "0123456789abcdef" for char in revision), "missing immutable RustSec revision"
    assert snapshot.get("stale") is False, "live smoke did not establish fresh RustSec data"
    return revision


def synthetic_advisory(client):
    """Exercise seeded public fixture evidence and the actual sibling audit helper.

    Called only after --capture identifies a storage-probe fixture. Ordinary empty
    startup never requires fixture data and every request remains local.
    """
    lockfile = (f"# {AUDIT_PRIVACY_MARKER}\nversion = 4\n[[package]]\n"
                'name = "example"\nversion = "1.0.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
    for revision in (MODERN, LEGACY):
        detail = client.tool("advisory_get", {"id": SYNTHETIC_ADVISORY, "snapshot": SYNTHETIC_SNAPSHOT}, revision)
        assert detail.get("id") == SYNTHETIC_ADVISORY, "wrong synthetic advisory identity"
        assert detail.get("snapshot", {}).get("id") == SYNTHETIC_SNAPSHOT, "synthetic advisory snapshot changed"
        assert detail["snapshot"].get("coverage", {}).get("synthetic") is True, "synthetic evidence lost its fixture label"
        assert detail.get("source_url") == "https://fixtures.invalid/devres/storage-probe/advisory", "synthetic evidence invented upstream provenance"
        text = detail.get("page", {}).get("text", "")
        assert "Synthetic storage-probe advisory" in text, "synthetic advisory body missing"
        catalog = client.tool("advisory_catalog_search", {"snapshot": SYNTHETIC_SNAPSHOT,
                              "filters": {"name": "example", "id": SYNTHETIC_ADVISORY}}, revision)
        assert catalog.get("total") == 1, "synthetic catalog membership changed"
        lookup = client.tool("advisory_lookup", {"name": "example", "version": "1.0.0",
                             "advisory_snapshot": SYNTHETIC_SNAPSHOT}, revision)
        assert lookup.get("complete") is True and lookup.get("total") == 1, "synthetic vulnerable version was not matched"
        assert lookup.get("items", [{}])[0].get("id") == SYNTHETIC_ADVISORY, "synthetic lookup matched the wrong advisory"
        patched = client.tool("advisory_lookup", {"name": "example", "version": "1.0.1",
                              "advisory_snapshot": SYNTHETIC_SNAPSHOT}, revision)
        assert patched.get("complete") is True and patched.get("total") == 0, "synthetic patched version still matched"
        report = client.tool("audit_lockfile", {"lockfile": lockfile, "advisory_snapshot": SYNTHETIC_SNAPSHOT}, revision)
        require_audit(report, detail["snapshot"]["revision"], allow_synthetic=True)
        assert report.get("snapshot", {}).get("id") == SYNTHETIC_SNAPSHOT, "audit changed its pinned synthetic snapshot"
        assert report.get("vulnerability_count") == 1 and report.get("total_findings") == 1, "audit helper did not produce the synthetic finding"
        assert report.get("findings", [{}])[0].get("advisory", {}).get("id") == SYNTHETIC_ADVISORY, "audit helper returned the wrong advisory"
        assert AUDIT_PRIVACY_MARKER not in json.dumps(report), "audit response reflected the private comment"
        status_code, invalid = client.exchange("tools/call", {"name": "audit_lockfile", "arguments": {
                              "lockfile": f"# {AUDIT_PRIVACY_MARKER}\nnot a Cargo.lock",
                              "advisory_snapshot": SYNTHETIC_SNAPSHOT}}, revision)
        # http_status::preserve_invalid_params_status rewrites modern errors;
        # the admitted legacy binding retains HTTP 200 with a JSON-RPC error.
        expected_status = 400 if revision == MODERN else 200
        assert status_code == expected_status, f"malformed audit input for {revision} did not return HTTP {expected_status}"
        assert isinstance(invalid, dict) and invalid.get("error", {}).get("code") == -32602, "malformed audit input did not return a sanitized invalid-params error"
        assert AUDIT_PRIVACY_MARKER not in json.dumps(invalid), "audit error reflected the private comment"
        resource = detail.get("resource_uri", "")
        assert resource.startswith("devres://advisory/rustsec/"), "missing typed advisory resource"
        for method, params in (("resources/read", {"uri": resource}),
                               ("tools/call", {"name": "fetch", "arguments": {"id": resource}})):
            result = client.call(method, params, revision)
            if method == "tools/call":
                assert not result.get("isError"), "typed advisory fetch failed"
                result = result.get("structuredContent", result)
            assert result.get("contents", [{}])[0].get("text") == text, "typed advisory content changed"
            assert AUDIT_PRIVACY_MARKER not in json.dumps(result), "advisory resource reflected audit input"
        status = client.tool("advisory_corpus_status", {}, revision)
        assert AUDIT_PRIVACY_MARKER not in json.dumps(status), "advisory status reflected audit input"


def synthetic_mdn(client):
    """Exercise retained synthetic MDN evidence without network acquisition."""
    for revision in (MODERN, LEGACY):
        arguments = {"slug": "Web/Fixture", "snapshot": SYNTHETIC_MDN_CONTENT,
                     "compatibility_snapshot": SYNTHETIC_MDN_COMPAT}
        detail = client.tool("mdn_get", arguments, revision)
        assert detail.get("provenance", {}).get("snapshot") == SYNTHETIC_MDN_CONTENT, "MDN document snapshot changed"
        assert detail["provenance"].get("coverage", {}).get("synthetic") is True, "MDN fixture lost its synthetic label"
        assert detail.get("source_url", "").startswith("https://fixtures.invalid/"), "MDN fixture invented upstream provenance"
        assert SYNTHETIC_MDN_TEXT in detail.get("page", {}).get("text", ""), "MDN fixture text missing"
        assert "fixture_browser" in detail["page"]["text"], "pinned BCD table was not expanded"
        found = client.tool("mdn_search", {"query": "fetch", "snapshot": SYNTHETIC_MDN_CONTENT}, revision)
        assert found.get("total") == 1 and found["results"][0].get("slug") == "Web/Fixture", "MDN selected-snapshot search changed"
        compat = client.tool("mdn_compat_get", {"feature": "api.fixtureFetch", "snapshot": SYNTHETIC_MDN_COMPAT}, revision)
        assert compat.get("original", {}).get("fixture_browser", {}).get("version_added") == "1", "synthetic BCD statement changed"
        assert compat.get("resolved") == compat.get("original"), "explicit BCD evidence was incorrectly transformed"
        features = client.tool("mdn_compat_search", {"query": "fetch", "snapshot": SYNTHETIC_MDN_COMPAT}, revision)
        assert features.get("total") == 1, "synthetic BCD feature did not enter its index"
        browser = client.tool("mdn_browser_get", {"browser": "fixture_browser", "snapshot": SYNTHETIC_MDN_COMPAT}, revision)
        assert browser.get("releases", [{}])[0].get("version") == "1", "synthetic browser release changed"
        original = client.tool("mdn_get", {"slug": "Web/Fixture", "snapshot": SYNTHETIC_MDN_CONTENT,
                                           "representation": "source"}, revision)
        assert original.get("page", {}).get("text", "").startswith("---\ntitle: Synthetic MDN"), "original MDN Markdown was replaced by a projection"
        for selected in (detail, original):
            resource = selected.get("resource_uri", "")
            assert resource.startswith("devres://mdn/content/"), "missing immutable MDN resource"
            for method, params in (("resources/read", {"uri": resource}),
                                   ("tools/call", {"name": "fetch", "arguments": {"id": resource}})):
                result = client.call(method, params, revision)
                if method == "tools/call":
                    assert not result.get("isError"), "typed MDN fetch failed"
                    result = result.get("structuredContent", result)
                content = result.get("contents", [{}])[0]
                assert content.get("text") == selected["page"]["text"], "immutable MDN resource changed"
                assert content.get("_meta", {}).get("provenance", {}).get("coverage", {}).get("synthetic") is True, "resource lost MDN fixture provenance"
                assert content.get("_meta", {}).get("license"), "resource dropped source attribution"
        assert AUDIT_PRIVACY_MARKER not in json.dumps(client.tool("mdn_corpus_status", {}, revision)), "MDN status reflected audit input"


def wait_ready(client, seconds):
    """Wait only for offline semantic routing readiness, never replay source work."""
    deadline = time.monotonic() + seconds
    original_timeout = client.timeout
    client.timeout = 2
    signal.alarm(seconds)
    try:
        while time.monotonic() < deadline:
            try:
                info = client.tool("server_info", {})
                if info.get("product") == "dev-resources-MCP" and info.get("license") == "AGPL-3.0-only":
                    return
            except (OSError, http.client.HTTPException, ValueError, AssertionError):
                pass
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    finally:
        signal.alarm(0)
        client.timeout = original_timeout
    raise AssertionError("edge semantic readiness exceeded its bounded deadline")


def require_audit(report, revision, allow_synthetic=False):
    assert require_snapshot(report, allow_synthetic) == revision, "audit changed advisory snapshot"
    assert report.get("package_count") == report.get("assessed_count") == 1, "public fixture package was not assessed"
    assert report.get("unassessed_count") == 0, "public fixture unexpectedly unassessed"
    assert report.get("input_retention") == "request_lifetime_only", "audit privacy contract mismatch"
    vulnerabilities = report.get("vulnerability_count")
    assert isinstance(vulnerabilities, int) and vulnerabilities >= 0
    expected_status = "known_vulnerabilities" if vulnerabilities else "no_known_vulnerabilities_in_snapshot"
    assert report.get("status") == expected_status, "audit status did not reflect its assessment"


def live(client, rfc_text_only=False):
    # Fixed requests; adapter admission/retries have their own finite budget.
    # No user-supplied package, URL, lockfile, or bulk enumeration is accepted.
    started = time.monotonic()
    signal.alarm(300)
    status = client.tool("rfc_corpus_status", {})
    assert status.get("collection_enabled") is False, "bounded live smoke requires paused automatic RFC collection"
    assert client.tool("crate_corpus_status", {}).get("collection_enabled") is False, "bounded live smoke requires paused crate collection"
    assert client.tool("mdn_corpus_status", {}).get("collection_enabled") is False, "bounded live smoke requires paused MDN collection"
    rfc_search = client.tool("rfc_search", {"query": "QUIC", "offset": 0, "limit": 3})
    assert rfc_search.get("items") and rfc_search.get("total", 0) > 0, "RFC discovery returned no matching documents"
    assert rfc_search.get("capture", {}).get("source_url") == "https://www.rfc-editor.org/rfc-index.xml", "RFC discovery did not use the canonical index"
    rfc = client.tool("rfc_get", {"number": 9000, "offset": 0, "limit": 1024})
    assert rfc.get("id") == "rfc:9000", "wrong RFC identity"
    assert rfc.get("capture", {}).get("source_url") == "https://www.rfc-editor.org/rfc/rfc9000.txt"
    assert "9000" in rfc.get("page", {}).get("text", "") and "QUIC" in rfc["page"]["text"], "RFC response did not contain the selected document"
    metadata_rfc = client.tool("rfc_metadata", {"number": 9000})
    assert metadata_rfc.get("metadata", {}).get("number") == 9000
    assert metadata_rfc.get("snapshot"), "RFC metadata did not pin a snapshot"
    for format_name in (("txt",) if rfc_text_only else ("txt", "html", "xml", "pdf")):
        representation = client.tool("rfc_format_get", {"number": 9000, "format": format_name, "limit": 1024})
        assert representation.get("format") == format_name and representation.get("assurance") == "https"
        captured = representation.get("capture", {}).get("id")
        assert captured, "RFC format omitted its capture"
        pinned = client.tool("rfc_format_get", {"number": 9000, "format": format_name, "capture": captured, "limit": 1024})
        assert pinned == representation, "capture-pinned RFC format changed"
    errata_rfc = client.tool("rfc_errata", {"number": 9000, "limit": 1})
    assert errata_rfc.get("capture", {}).get("source_url") == "https://www.rfc-editor.org/api/v1/errata.json"
    fulltext_rfc = client.tool("rfc_fulltext_search", {"query": "multiplexed", "limit": 3})
    assert fulltext_rfc.get("snapshot") and any(item.get("number") == 9000 for item in fulltext_rfc.get("items", [])), "fixed RFC text did not enter the partial search snapshot"
    crate_search = client.tool("crate_search", {"query": "itoa", "offset": 0, "limit": 3})
    assert crate_search.get("items") and crate_search.get("total", 0) > 0, "crate discovery returned no packages"
    metadata = client.tool("crate_metadata", {"name": "itoa", "version": "1.0.15"})
    assert metadata.get("id") == "crate:itoa@1.0.15"
    assert metadata.get("metadata", {}).get("name") == "itoa" and metadata["metadata"].get("vers") == "1.0.15", "wrong published package version"
    checksum = metadata["metadata"].get("cksum", "")
    assert len(checksum) == 64 and all(char in "0123456789abcdef" for char in checksum), "missing published archive checksum"
    listing = client.tool("crate_source_list", {"name": "itoa", "version": "1.0.15", "offset": 0, "limit": 20})
    assert listing.get("checksum_verified") is True and listing.get("archive_capture", {}).get("body_hash") == checksum
    assert any(item.get("path") == "src/lib.rs" for item in listing.get("files", [])), "published source listing lacks the selected member"
    source = client.tool("crate_source_read", {"name": "itoa", "version": "1.0.15", "path": "src/lib.rs",
                                               "offset": 0, "limit": 1024})
    assert source.get("path") == "src/lib.rs" and source.get("page", {}).get("text"), "source member was not retrieved"
    assert source.get("checksum_verified") is True and source.get("archive_capture", {}).get("body_hash") == checksum
    assert source.get("metadata_capture", {}).get("id") == metadata.get("capture", {}).get("id"), "source projection changed its metadata capture"
    pinned = client.tool("crate_source_read", {"name": "itoa", "version": "1.0.15", "path": "src/lib.rs",
                         "metadata_capture": source["metadata_capture"]["id"],
                         "archive_capture": source["archive_capture"]["id"], "offset": 0, "limit": 1024})
    assert pinned == source, "capture-fixed source changed"
    for method, params in (("resources/read", {"uri": source["resource_uri"]}),
                           ("tools/call", {"name": "fetch", "arguments": {"id": source["resource_uri"]}})):
        value = client.call(method, params)
        if method == "tools/call":
            assert not value.get("isError"), "pinned source fetch failed"
            value = value.get("structuredContent", value)
        assert value.get("contents", [{}])[0].get("text") == source["page"]["text"], "source resource content changed"
    lookup = client.tool("advisory_lookup", {"name": "itoa", "version": "1.0.15", "offset": 0, "limit": 20})
    revision = require_snapshot(lookup)
    lockfile = ('version = 4\n[[package]]\nname = "itoa"\nversion = "1.0.15"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
    audit = client.tool("audit_lockfile", {"lockfile": lockfile, "offset": 0, "limit": 20})
    require_audit(audit, revision)
    # A repeated fetch proves the public API still resolves the same record; request
    # counters/storage tests separately establish zero upstream calls for warm hits.
    repeat = client.tool("rfc_get", {"number": 9000, "offset": 0, "limit": 1024})
    assert rfc == repeat, "warm retrieval changed its captured representation"
    assert time.monotonic() - started < 300, "live smoke exceeded its five-minute budget"
    signal.alarm(0)


def main():
    # Python can be container PID 1, where default-action signals are ignored.
    # An explicit handler makes both readiness and live deadlines effective.
    def deadline_expired(_signal, _frame):
        raise TimeoutError("smoke deadline exceeded")

    signal.signal(signal.SIGALRM, deadline_expired)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--ca")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--origin", default="https://client.example")
    parser.add_argument("--no-negative", action="store_true")
    parser.add_argument("--live", action="store_true", help="opt in to fixed public-provider requests")
    parser.add_argument("--rfc-text-only", action="store_true", help="with --live, omit already qualified alternate RFC formats to preserve a shared attempt budget")
    parser.add_argument("--capture", help="verify a pre-existing synthetic capture after restart/restore")
    parser.add_argument("--wait-ready", type=int, choices=range(1, 61), metavar="SECONDS",
                        help="offline server identity readiness only; bounded at 60 seconds")
    options = parser.parse_args()
    if options.rfc_text_only and not options.live:
        parser.error("--rfc-text-only requires --live")
    client = Client(options.url, options.ca, options.cert, options.key, options.origin)
    if options.wait_ready:
        wait_ready(client, options.wait_ready)
        print("HTTP MCP semantic routing readiness established; no provider calls")
        return
    smoke(client, not options.no_negative)
    if options.capture:
        value = client.tool("fetch", {"id": "devres://capture/" + options.capture})
        assert "Synthetic dev-resources persistence acceptance fixture" in json.dumps(value)
        synthetic_advisory(client)
        synthetic_mdn(client)
    if options.live:
        live(client, options.rfc_text_only)
    print("HTTP MCP acceptance passed" + ("; bounded live smoke passed (RFC text only)" if options.live and options.rfc_text_only else "; bounded live smoke passed" if options.live else "; no provider calls"))


if __name__ == "__main__":
    main()
