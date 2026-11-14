"""The pinned path SDK remains visible to the registry advisory scanner."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "audit_vendored", Path(__file__).parents[1] / "audit-vendored.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

MANIFEST = b'[package]\nname = "rmcp"\nversion = "3.9.0"\n'
LOCKFILE = b'''# Preserve this exact locked graph, comments and dependency edges.
version = 4

[[package]]
name = "first-party"
version = "0.0.0"
dependencies = [
 "rmcp",
]

[[package]]
name = "rmcp"
version = "3.9.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "untouched-other-package"
'''


class VendoredAuditTests(unittest.TestCase):
    def test_projection_changes_only_original_sdk_registry_identity(self):
        projected = audit.project(LOCKFILE, MANIFEST)
        identity = (f'source = "{audit.SOURCE}"\nchecksum = "{audit.CHECKSUM}"\n').encode()
        self.assertEqual(projected.replace(identity, b"", 1), LOCKFILE)
        sdk = next(item for item in tomllib.loads(projected.decode())["package"]
                   if item["name"] == "rmcp")
        self.assertEqual(sdk["version"], "3.9.0")
        self.assertEqual(sdk["dependencies"], ["serde"])
        self.assertEqual(sdk["source"], audit.SOURCE)
        self.assertEqual(sdk["checksum"], audit.CHECKSUM)
        self.assertEqual(audit.project(LOCKFILE.replace(b"\n", b"\r\n"), MANIFEST),
                         projected.replace(b"\n", b"\r\n"))

    def test_unknown_version_source_duplicate_and_malformed_inputs_fail_closed(self):
        for lock in (
            LOCKFILE.replace(b'"3.9.0"', b'"3.10.0"'),
            LOCKFILE.replace(b'name = "rmcp"', b'name = "other-sdk"'),
            LOCKFILE.replace(b'version = "3.9.0"', b'version = "3.9.0"\nsource = "registry+https://unapproved.invalid"'),
            LOCKFILE.replace(b'version = "3.9.0"', b'version = "3.9.0"\nchecksum = "unexpected"'),
            LOCKFILE + b'\n[[package]]\nname = "rmcp"\nversion = "3.9.0"\n',
            LOCKFILE + b'\n[[package]]\nname = "rmcp"\nversion = "3.8.0"\n',
            LOCKFILE.replace(b"version = 4", b"version = 99"),
            b"not TOML",
            b"version = 4\npackage = 1\n",
        ):
            with self.subTest(lock=lock[:80]):
                with self.assertRaises(ValueError):
                    audit.project(lock, MANIFEST)
        for manifest in (MANIFEST.replace(b'"3.9.0"', b'"3.8.0"'),
                         MANIFEST.replace(b'"rmcp"', b'"other"'), b"not TOML",
                         b"package = 1\n"):
            with self.subTest(manifest=manifest):
                with self.assertRaises(ValueError):
                    audit.project(LOCKFILE, manifest)

    def fixture(self, root):
        (root / "Cargo.lock").write_bytes(LOCKFILE)
        (root / "vendor/rmcp").mkdir(parents=True)
        (root / "vendor/rmcp/Cargo.toml").write_bytes(MANIFEST)

    def test_cli_propagates_audit_exit_and_cleans_private_tmp_projection(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            self.fixture(root)
            observed = []

            def run(command, **options):
                self.assertEqual(command[:3], ["cargo", "audit", "--file"])
                self.assertEqual(command[4:], ["--db", "/tmp/frozen-advisories", "--no-fetch"])
                self.assertEqual(options, {"cwd": root, "check": False})
                projected = Path(command[3])
                self.assertTrue(projected.is_relative_to("/tmp"))
                self.assertEqual(os.stat(projected.parent).st_mode & 0o777, 0o700)
                self.assertEqual(os.stat(projected).st_mode & 0o777, 0o600)
                self.assertEqual(projected.read_bytes(), audit.project(LOCKFILE, MANIFEST))
                observed.append(projected)
                return subprocess.CompletedProcess(command, 7)

            with patch.object(audit, "ROOT", root), patch.object(audit.subprocess, "run", side_effect=run):
                self.assertEqual(audit.main(["--db", "/tmp/frozen-advisories", "--no-fetch"]), 7)
            self.assertEqual((root / "Cargo.lock").read_bytes(), LOCKFILE)
            self.assertEqual((root / "vendor/rmcp/Cargo.toml").read_bytes(), MANIFEST)
            self.assertEqual(len(observed), 1)
            self.assertFalse(observed[0].parent.exists())

    def test_invalid_inputs_and_launch_errors_fail_without_leaving_temporary_files(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            self.fixture(root)
            observed = []

            def failed_launch(command, **_):
                observed.append(Path(command[3]))
                raise OSError("unavailable test executable")

            with patch.object(audit, "ROOT", root), patch.object(audit.subprocess, "run", side_effect=failed_launch), patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(audit.main([]), 2)
            self.assertFalse(observed[0].parent.exists())
            (root / "Cargo.lock").write_text("malformed = [")
            with patch.object(audit, "ROOT", root), patch.object(audit.subprocess, "run") as run, patch("sys.stderr", new=io.StringIO()):
                self.assertEqual(audit.main([]), 2)
                run.assert_not_called()

    def test_cli_rejects_audit_bypass_and_arbitrary_file_arguments(self):
        for options in (["--ignore", "RUSTSEC-fixture"], ["--file", "/tmp/other.lock"],
                        ["--", "--ignore", "RUSTSEC-fixture"], ["--db"], ["--no"]):
            with self.subTest(options=options), patch("sys.stderr", new=io.StringIO()):
                with self.assertRaises(SystemExit) as failure:
                    audit.main(options)
                self.assertEqual(failure.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
