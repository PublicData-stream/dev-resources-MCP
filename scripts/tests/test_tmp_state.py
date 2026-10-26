import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/with-tmp-state.sh"
STATE_FIELDS = (
    "CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR", "OXIBELT_TARGET_DIR",
    "TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR",
    "PYTHONPYCACHEPREFIX", "DOCKER_CONFIG", "MINIKUBE_HOME", "KUBECONFIG",
    "PNPM_HOME", "npm_config_cache", "npm_config_store_dir",
)


class TemporaryStateTests(unittest.TestCase):
    def run_wrapper(self, root, *command):
        return subprocess.run(
            [str(WRAPPER), *command],
            env={**os.environ, "DEVRES_TMP_ROOT": str(root)},
            text=True, capture_output=True, timeout=5, check=False,
        )

    def test_tools_use_tmp_while_identity_and_arguments_are_preserved(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-state-test.") as name:
            root = Path(name)
            script = (
                "import json,os,sys; "
                "print(json.dumps({'env':dict(os.environ),'argv':sys.argv[1:]}))"
            )
            result = self.run_wrapper(root, "python3", "-c", script, "two words", "$(false)")
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            for field in STATE_FIELDS:
                self.assertTrue(Path(output["env"][field]).is_relative_to(root), field)
            self.assertEqual(output["env"]["HOME"], os.environ["HOME"])
            self.assertEqual(output["env"].get("CODEX_HOME"), os.environ.get("CODEX_HOME"))
            self.assertEqual(output["argv"], ["two words", "$(false)"])
            self.assertTrue((root / "devres-tmp-state-v1").is_file())

    def test_command_failure_preserves_state_and_exit_status(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-state-test.") as name:
            root = Path(name)
            evidence = root / "acceptance-evidence"
            result = self.run_wrapper(
                root, "python3", "-c",
                "import os,pathlib,sys; "
                "pathlib.Path(os.environ['DEVRES_TMP_ROOT'],'acceptance-evidence').write_text('retained'); "
                "sys.exit(37)",
            )
            self.assertEqual(result.returncode, 37, result.stderr)
            self.assertEqual(evidence.read_text(), "retained")
            self.assertTrue((root / "target").is_dir())

    def test_repeated_entry_reuses_preseeded_cache(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-state-test.") as name:
            root = Path(name)
            for _ in range(2):
                result = self.run_wrapper(root, "true")
                self.assertEqual(result.returncode, 0, result.stderr)
                cache = root / "cargo" / "cached-record"
                if cache.exists():
                    self.assertEqual(cache.read_text(), "seed")
                cache.write_text("seed")

    def test_non_tmp_root_is_rejected_before_command(self):
        result = self.run_wrapper("/var/devres-forbidden", "sh", "-c", "exit 99")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("below /tmp", result.stderr)
        self.assertFalse(Path("/var/devres-forbidden").exists())

    def test_marker_mismatch_is_rejected_before_command(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-state-test.") as name:
            root = Path(name)
            (root / "devres-tmp-state-v1").write_text("someone else's state\n")
            result = self.run_wrapper(root, "sh", "-c", "exit 99")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("marker mismatch", result.stderr)
            self.assertFalse((root / "cargo").exists())

    def test_symlinked_tool_state_is_rejected(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-state-test.") as name:
            root = Path(name)
            (root / "cargo").symlink_to("/var", target_is_directory=True)
            result = self.run_wrapper(root, "sh", "-c", "exit 99")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("must not be a symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
