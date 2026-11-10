"""Offline checks; optional compiled CLI tests initialize state without network."""
import os
import json
from pathlib import Path
import subprocess
import tempfile
import stat
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "deployment-live-probe.sh"


class DeploymentLiveProbeTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("DEVRES_DEPLOYMENT_PROBE_BIN"), "compiled probe CLI not selected")
    def test_real_cli_initializes_private_files_under_group_writable_umask(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as root:
            evidence = Path(root) / "evidence"
            result = subprocess.run([os.environ["DEVRES_DEPLOYMENT_PROBE_BIN"], "--initialize", str(evidence)],
                                    preexec_fn=lambda: os.umask(0o002), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"no provider requests", result.stdout)
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
            for name in ("owner-v1", "attempts.json", "run.lock"):
                self.assertEqual(stat.S_IMODE((evidence / name).stat().st_mode), 0o600)
            ledger = json.loads((evidence / "attempts.json").read_text())
            self.assertEqual(ledger["families"], {})
            self.assertEqual(ledger["github"], 0)
            repeated = subprocess.run([os.environ["DEVRES_DEPLOYMENT_PROBE_BIN"], "--initialize", str(evidence)], capture_output=True)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(json.loads((evidence / "attempts.json").read_text()), ledger)

    @unittest.skipUnless(os.environ.get("DEVRES_DEPLOYMENT_PROBE_BIN"), "compiled probe CLI not selected")
    def test_real_cli_rejects_shared_nested_parent_before_creating_evidence(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as root:
            parent = Path(root) / "shared"
            parent.mkdir(mode=0o777)
            parent.chmod(0o770)
            evidence = parent / "evidence"
            result = subprocess.run([os.environ["DEVRES_DEPLOYMENT_PROBE_BIN"], "--initialize", str(evidence)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(evidence.exists())

    def test_released_source_accepts_tooling_and_forces_tmp_build_outputs(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as root:
            directory = Path(root)
            cargo = directory / "cargo"
            cargo.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "pathlib.Path(os.environ['PROBE_CALLED']).write_text(json.dumps({"
                "'args': sys.argv[1:], 'target': os.environ['CARGO_TARGET_DIR'],"
                "'tmp': os.environ['TMPDIR']}))\n"
            )
            cargo.chmod(0o700)
            called = directory / "called"
            evidence = directory / "evidence"
            environment = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}",
                               PROBE_CALLED=str(called), CARGO_TARGET_DIR="/unexpected")
            result = subprocess.run(["bash", str(SCRIPT), "--live", str(evidence)],
                                    env=environment, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            invocation = json.loads(called.read_text())
            self.assertEqual(invocation["target"], "/tmp/rust/target")
            self.assertEqual(invocation["tmp"], "/tmp")
            self.assertEqual(invocation["args"][-3:], ["--", "--live", str(evidence)])
            self.assertIn("--locked", invocation["args"])
            self.assertFalse(evidence.exists())

    def test_live_work_requires_explicit_mode_and_tmp_root(self):
        for arguments in ([], ["--live"], ["--live", "/var/lib/public"],
                          ["--resume", "relative"], ["--full", "/tmp/example"],
                          ["--live", "/tmp/example", "extra"]):
            result = subprocess.run(["bash", str(SCRIPT), *arguments], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"usage:", result.stderr)

    def test_changed_runtime_prevents_execution_before_cargo(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as root:
            directory = Path(root)
            git = directory / "git"
            git.write_text("#!/bin/sh\ncase \"$1\" in cat-file) exit 0;; diff) exit 1;; esac\nexit 99\n")
            git.chmod(0o700)
            cargo = directory / "cargo"
            cargo.write_text("#!/bin/sh\ntouch \"$PROBE_CALLED\"\nexit 0\n")
            cargo.chmod(0o700)
            called = directory / "called"
            environment = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}", PROBE_CALLED=str(called))
            result = subprocess.run(["bash", str(SCRIPT), "--live", str(directory / "evidence")], env=environment, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(called.exists())


if __name__ == "__main__":
    unittest.main()
