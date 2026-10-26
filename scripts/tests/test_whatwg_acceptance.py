import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/accept-whatwg.sh"
MARKER = "devres-whatwg-retained-acceptance-v1\n"


class RetainedWhatwgAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-whatwg-test.")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.retained = self.root / "retained"
        self.retained.mkdir()
        (self.retained / "owner-v1").write_text(MARKER)
        binaries = self.root / "bin"
        binaries.mkdir()
        self.log = self.root / "calls.jsonl"
        docker = binaries / "docker"
        docker.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
with open(os.environ['DEVRES_TEST_LOG'],'a') as output:
    output.write(json.dumps(['docker',*sys.argv[1:]])+'\\n')
command = sys.argv[1]
if command == 'ps':
    if os.environ.get('DEVRES_TEST_ORPHAN'): print('owned-running-container')
elif command == 'inspect':
    print(os.environ.get('DEVRES_TEST_INSPECT_OWNER',os.environ['DEVRES_WHATWG_ACCEPTANCE_ROOT']))
elif command == 'port': print('127.0.0.1:54321')
elif command == 'run': print('synthetic-container-id')
''')
        docker.chmod(0o755)
        cargo = binaries / "cargo"
        cargo.write_text('''#!/usr/bin/env python3
import json,os,pathlib,shutil,sys
with open(os.environ['DEVRES_TEST_LOG'],'a') as output:
    output.write(json.dumps(['cargo',*sys.argv[1:]])+'\\n')
target = pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'release/examples/whatwg-probe'
target.parent.mkdir(parents=True,exist_ok=True)
shutil.copyfile(os.environ['DEVRES_TEST_PROBE'],target)
target.chmod(0o755)
worker = pathlib.Path(os.environ['CARGO_TARGET_DIR'])/'release/devres-pdf-worker'
worker.write_text('#!/bin/sh\\nexit 0\\n')
worker.chmod(0o755)
''')
        cargo.chmod(0o755)
        probe = self.root / "probe"
        probe.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
with open(os.environ['DEVRES_TEST_LOG'],'a') as output:
    output.write(json.dumps(['probe',*sys.argv[1:]])+'\\n')
root = pathlib.Path(os.environ['DEVRES_WHATWG_ACCEPTANCE_ROOT'])
(root/'retained-public-capture').write_text('synthetic public evidence')
print(json.dumps({'complete':not bool(os.environ.get('DEVRES_TEST_PROBE_FAIL'))}))
sys.exit(int(os.environ.get('DEVRES_TEST_PROBE_FAIL','0')))
''')
        self.env = {
            **os.environ,
            "PATH": f"{binaries}:{os.environ['PATH']}",
            "DEVRES_TMP_ROOT": str(self.root / "tool-state"),
            "DEVRES_WHATWG_ACCEPTANCE_ROOT": str(self.retained),
            "DEVRES_TEST_LOG": str(self.log),
            "DEVRES_TEST_PROBE": str(probe),
        }
        self.env.pop("DEVRES_TMP_STATE", None)

    def run_script(self, *args):
        return subprocess.run([str(SCRIPT), *args], env=self.env,
                              text=True, capture_output=True, timeout=10, check=False)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_orphaned_owned_postgres_prevents_build_and_new_container(self):
        self.env["DEVRES_TEST_ORPHAN"] = "1"
        result = self.run_script("--live", "current")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("PostgreSQL is still running", result.stderr)
        self.assertEqual([call[:2] for call in self.calls()], [["docker", "ps"]])
        self.assertFalse((self.retained / "postgres").exists())

    def test_concurrent_run_stops_before_provider_or_storage_work(self):
        with (self.retained / "acceptance.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_script("--live", "full")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("already running", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.retained / "blobs").exists())

    def test_resume_requires_existing_frozen_observation(self):
        result = self.run_script("--resume", "full")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("retained frozen observation", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_live_cannot_replace_frozen_observation(self):
        frozen = self.retained / "frozen.json"
        frozen.write_text('{"version":1,"mode":"full","frozen":{}}')
        result = self.run_script("--live", "full")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(json.loads(frozen.read_text())["mode"], "full")

    def test_unowned_or_symlinked_data_is_rejected(self):
        (self.retained / "owner-v1").write_text("other owner\n")
        result = self.run_script("--live", "current")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.calls(), [])
        (self.retained / "owner-v1").write_text(MARKER)
        (self.retained / "postgres").symlink_to("/var", target_is_directory=True)
        result = self.run_script("--live", "current")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("must not be symlinked", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_probe_failure_stops_only_owned_container_and_preserves_evidence(self):
        self.env["DEVRES_TEST_PROBE_FAIL"] = "37"
        result = self.run_script("--live", "full")
        self.assertEqual(result.returncode, 37, result.stderr)
        calls = self.calls()
        self.assertIn(["probe", "--live", "full"], calls)
        self.assertTrue(any(call[:2] == ["docker", "stop"] for call in calls))
        self.assertTrue(any(call[:2] == ["docker", "rm"] for call in calls))
        self.assertEqual((self.retained / "retained-public-capture").read_text(), "synthetic public evidence")
        self.assertTrue((self.retained / "postgres").is_dir())

    def test_cleanup_does_not_stop_a_container_with_another_owner(self):
        self.env["DEVRES_TEST_INSPECT_OWNER"] = "another-root"
        result = self.run_script("--live", "current")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[:2] in (["docker", "stop"], ["docker", "rm"]) for call in self.calls()))

    def test_resume_passes_frozen_mode_and_preserves_manifest(self):
        frozen = self.retained / "frozen.json"
        original = '{"version":1,"mode":"full","frozen":{"fixture":true}}'
        frozen.write_text(original)
        result = self.run_script("--resume", "full")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["probe", "--resume", "full"], self.calls())
        self.assertEqual(frozen.read_text(), original)

    def test_resume_current_is_rejected_before_work(self):
        result = self.run_script("--resume", "current")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_recovery_requires_parent_and_resume_pointer_before_work(self):
        for flag in ("--recover", "--resume-recovery"):
            with self.subTest(flag=flag):
                result = self.run_script(flag, "full")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(self.calls(), [])
        (self.retained / "frozen.json").write_text('{"version":1,"mode":"full","frozen":{}}')
        result = self.run_script("--resume-recovery", "full")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.calls(), [])

    def test_recovery_modes_preserve_original_manifest_and_failure(self):
        frozen = self.retained / "frozen.json"
        original = '{"version":1,"mode":"full","frozen":{"fixture":true}}'
        frozen.write_text(original)
        failed = self.retained / "acceptance.json"
        failed.write_text('{"complete":false,"unavailable_publications":8}')
        (self.retained / "recovery-current.json").write_text(json.dumps({
            "version": 1, "frozen_id": "b" * 64,
        }))
        for flag in ("--recover", "--resume-recovery"):
            with self.subTest(flag=flag):
                result = self.run_script(flag, "full")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(["probe", flag, "full"], self.calls())
                self.assertEqual(frozen.read_text(), original)
                self.assertEqual(json.loads(failed.read_text()), {
                    "complete": False, "unavailable_publications": 8,
                })

    def test_recovery_pointer_symlinks_are_rejected_before_work(self):
        (self.retained / "frozen.json").write_text('{"version":1,"mode":"full","frozen":{}}')
        target = self.root / "other-pointer.json"
        target.write_text('{"version":1}')
        (self.retained / "recovery-current.json").symlink_to(target)
        result = self.run_script("--resume-recovery", "full")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(target.read_text(), '{"version":1}')

    def test_recovery_current_is_rejected_before_work(self):
        for flag in ("--recover", "--resume-recovery"):
            with self.subTest(flag=flag):
                result = self.run_script(flag, "current")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
