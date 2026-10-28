"""Storage counters stay bounded and best-effort, without reading fixture contents."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "e2e-storage.sh"


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-storage-test.")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls.jsonl"
        fake = f'''#!{sys.executable}
import json, os
from pathlib import Path
import sys
name = Path(sys.argv[0]).name
with open(os.environ["CALLS"], "a") as stream:
    stream.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
print("private-stderr-marker", file=sys.stderr)
print("x" * int(os.environ.get("OUTPUT_BYTES", "20")))
sys.exit(int(os.environ.get("COUNTER_STATUS", "0")))
'''
        for name in ("df", "du", "docker"):
            path = self.bin / name
            path.write_text(fake)
            path.chmod(0o755)

    def run_storage(self, phase="after-artifact-load", **settings):
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
               "CALLS": str(self.calls), "DEVRES_TMP_ROOT": str(self.root),
               "DEVRES_DOCKER_HOST": f"unix://{self.root}/docker.sock",
               "DEVRES_E2E_DIAGNOSTICS_DIR": str(self.root / "diagnostics"),
               **settings}
        result = subprocess.run(["bash", str(SCRIPT), phase, "fixture:test", str(self.root)],
                                env=env, text=True, capture_output=True, timeout=10)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []
        return result, calls

    def test_allowlisted_counters_and_owned_roots_only(self):
        result, calls = self.run_storage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [
            ["df", "-Pk", "/tmp", str(self.root)],
            ["df", "-Pi", "/tmp", str(self.root)],
            ["docker", "image", "inspect", "--format", "{{.Size}}", "--", "fixture:test"],
            ["du", "-skx", "--", str(self.root)],
        ])
        self.assertNotIn("private-stderr-marker", result.stderr)
        self.assertIn("Storage after-artifact-load/space (status=0)", result.stderr)
        self.assertEqual(len(list((self.root / "diagnostics/storage").iterdir())), 4)

    def test_capture_is_bounded(self):
        result, _ = self.run_storage(OUTPUT_BYTES="100000")
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in (self.root / "diagnostics/storage").iterdir():
            self.assertLessEqual(path.stat().st_size, 65536)
        self.assertLess(len(result.stderr), 4 * (65536 + 100))

    def test_counter_failure_is_partial_and_nonfatal(self):
        result, calls = self.run_storage(COUNTER_STATUS="23")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 4)
        self.assertIn("status=23", result.stderr)

    def test_artifact_write_failure_keeps_console_output(self):
        destination = self.root / "not-a-directory"
        destination.write_text("fixture")
        result, _ = self.run_storage(DEVRES_E2E_DIAGNOSTICS_DIR=str(destination))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Storage after-artifact-load/image-bytes", result.stderr)
        self.assertEqual(destination.read_text(), "fixture")

    def test_shared_and_external_roots_are_not_summarized(self):
        result, calls = self.run_storage(DEVRES_TMP_ROOT="/tmp", DEVRES_DOCKER_HOST="unix:///var/run/docker.sock")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call for call in calls if call[0] == "du"], [["du", "-skx", "--", str(self.root)]])

    def test_unknown_phase_fails_without_counters(self):
        result, calls = self.run_storage(phase="../invalid")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
