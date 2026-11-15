#!/usr/bin/env python3
"""Check private npm metadata diagnosis in an isolated reader fixture pod/container."""
import json
import re
import subprocess
import tempfile
from pathlib import Path


MAX_REPORT = 1024 * 1024
MAX_INPUT = 64 * 1024 * 1024
FORBIDDEN_KEYS = frozenset(("path", "relative_path", "member_path", "filename", "message",
                            "source_url", "url", "configuration", "database_url", "lockfile",
                            "dependency_graph", "audit_report", "body", "source_text"))


def validate_report(report):
    """Require metadata-only success; a fixture is never real export acceptance."""
    assert report.get("version") == 1 and report.get("provider") == "npm", "wrong diagnosis identity"
    assert type(report.get("schema")) is int and 14 <= report["schema"] <= 18, "unsupported diagnosis schema"
    assert report.get("complete") is True and report.get("outcome") == "inspected", "npm metadata diagnosis incomplete"
    assert type(report.get("bytes_read")) is int and 0 <= report["bytes_read"] <= MAX_INPUT, "diagnosis input bound missing"
    diagnostics = report.get("diagnostics", [])
    assert len(diagnostics) == 1, "npm metadata diagnosis missing or ambiguous"
    selected = diagnostics[0]
    assert selected.get("operation") == "npm_advisory_metadata", "wrong diagnosis operation"
    assert selected.get("provider_requests") == 0, "diagnosis made provider requests"
    for field in ("export_bytes", "full_membership", "attribution_qualified"):
        assert selected.get(field) == "not_checked", "metadata diagnosis claimed unverified export coverage"
    assert selected.get("job") is None, "synthetic fixture unexpectedly has an acquisition job"
    default = selected.get("default", {})
    assert re.fullmatch(r"blake3:[0-9a-f]{64}", default.get("id", "")), "npm default identity missing"
    assert default.get("ready") == "verified" and default.get("snapshot_metadata") == "verified", "npm default/ready linkage unverified"
    assert default.get("synthetic") is True, "fixture diagnosis lost synthetic scope"
    assert default.get("export_artifact") is None, "synthetic fixture invented an upstream export"

    def metadata_only(value):
        if isinstance(value, dict):
            assert FORBIDDEN_KEYS.isdisjoint(value), "diagnosis exposed a forbidden metadata field"
            for item in value.values():
                metadata_only(item)
        elif isinstance(value, list):
            for item in value:
                metadata_only(item)
        elif isinstance(value, str):
            assert len(value) <= 4096, "diagnosis exposed unbounded text"
            assert not any(marker in value for marker in (
                "/fixture/", "postgres://", "https://", "http://", "Synthetic npm acceptance fixture",
                "devres-smoke-private-comment-4d1a8e7c")), "diagnosis exposed source, credentials or private input"

    metadata_only(report)


def main():
    # The same SELECT-only configuration as serving; never attach a writer/cache.
    with tempfile.TemporaryDirectory(prefix="devres-npm-diagnosis.", dir="/tmp") as scratch:
        root = Path(scratch)
        root.chmod(0o700)
        output = root / "report.json"
        result = subprocess.run([
            "devres-server", "diagnose-collection", "/fixture/backend.toml", "--provider", "npm",
            "--latest-failure", "--max-total-bytes", str(MAX_INPUT), "--timeout-secs", "30",
            "--output", str(output),
        ], capture_output=True, timeout=40, check=False)
        assert result.returncode == 0, "npm private metadata diagnosis command failed"
        assert root.stat().st_mode & 0o777 == 0o700, "diagnosis directory is not private"
        assert not output.is_symlink() and output.stat().st_mode & 0o777 == 0o600, "diagnosis report is not private"
        with output.open("rb") as source:
            payload = source.read(MAX_REPORT + 1)
        assert len(payload) <= MAX_REPORT, "diagnosis report exceeds its bound"
        validate_report(json.loads(payload))
    print("npm private metadata diagnosis passed; export bytes and qualification not checked")


if __name__ == "__main__":
    main()
