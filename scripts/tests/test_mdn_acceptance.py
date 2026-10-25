import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class RetainedMdnAcceptanceTests(unittest.TestCase):
    def test_orphaned_owned_postgres_prevents_another_container(self):
        script = Path(__file__).resolve().parents[1] / "accept-mdn.sh"
        with tempfile.TemporaryDirectory(prefix="devres-mdn-orphan-test.") as name:
            root = Path(name)
            (root / "owner-v1").write_text("devres-mdn-retained-acceptance-v1\n")
            binaries = root / "bin"
            binaries.mkdir()
            docker = binaries / "docker"
            docker.write_text(
                '#!/bin/sh\nif [ "$1" = ps ]; then echo owned-container; exit 0; fi\n'
                'touch "$DEVRES_TEST_DOCKER_CALLED"\nexit 99\n'
            )
            docker.chmod(0o755)
            called = root / "docker-called"
            env = {
                **os.environ,
                "PATH": f"{binaries}:{os.environ['PATH']}",
                "DEVRES_MDN_ACCEPTANCE_ROOT": name,
                "DEVRES_TEST_DOCKER_CALLED": str(called),
            }
            result = subprocess.run(
                ["bash", str(script), "--resume", "full"], env=env,
                capture_output=True, text=True, timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("PostgreSQL is still running", result.stderr)
            self.assertFalse(called.exists())
            self.assertFalse((root / "postgres").exists())

    def test_concurrent_run_fails_before_storage_or_docker(self):
        script = Path(__file__).resolve().parents[1] / "accept-mdn.sh"
        with tempfile.TemporaryDirectory(prefix="devres-mdn-lock-test.") as name:
            root = Path(name)
            (root / "owner-v1").write_text("devres-mdn-retained-acceptance-v1\n")
            binaries = root / "bin"
            binaries.mkdir()
            docker = binaries / "docker"
            docker.write_text('#!/bin/sh\ntouch "$DEVRES_TEST_DOCKER_CALLED"\nexit 99\n')
            docker.chmod(0o755)
            called = root / "docker-called"
            env = {
                **os.environ,
                "PATH": f"{binaries}:{os.environ['PATH']}",
                "DEVRES_MDN_ACCEPTANCE_ROOT": name,
                "DEVRES_TEST_DOCKER_CALLED": str(called),
            }
            with (root / "acceptance.lock").open("w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = subprocess.run(
                    ["bash", str(script), "--resume", "full"],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("already running", result.stderr)
            self.assertFalse(called.exists())
            self.assertFalse((root / "postgres").exists())
            self.assertFalse((root / "blobs").exists())
