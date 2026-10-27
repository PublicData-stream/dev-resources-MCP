"""Fixture-only wrapper checks. The fake Cargo command never accesses providers."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/live-smoke.sh"


class NpmFixedAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-npm-wrapper-test.")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.log = self.root / "calls.json"
        binaries = self.root / "bin"
        binaries.mkdir()
        cargo = binaries / "cargo"
        cargo.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
root=pathlib.Path(sys.argv[-1])
marker=root/'owner-v1'
receipt={'args':sys.argv[1:],'root':str(root),'root_mode':root.stat().st_mode&0o777,
         'marker':marker.read_text() if marker.is_file() else None,
         'marker_mode':marker.stat().st_mode&0o777 if marker.exists() else None}
(root/'synthetic-wrapper-test').write_text(os.environ['DEVRES_TEST_LOG'])
pathlib.Path(os.environ['DEVRES_TEST_LOG']).write_text(json.dumps(receipt))
''')
        cargo.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{binaries}:{os.environ['PATH']}",
                    "DEVRES_TEST_LOG": str(self.log)}
        self.addCleanup(self.cleanup_probe_root)

    def cleanup_probe_root(self):
        if self.log.exists():
            root = Path(json.loads(self.log.read_text())["root"])
            marker = root / "synthetic-wrapper-test"
            if (root.parent == Path("/tmp") and root.name.startswith("devres-npm-live.")
                    and marker.is_file() and marker.read_text() == str(self.log)):
                shutil.rmtree(root)

    def run_script(self, *args):
        return subprocess.run([str(SCRIPT), *args], env=self.env, text=True,
                              capture_output=True, timeout=10, check=False)

    def test_npm_requires_explicit_live_opt_in(self):
        result = self.run_script("--npm")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.log.exists())

    def test_fixed_probe_uses_owned_temporary_root_and_locked_build(self):
        result = self.run_script("--live", "--npm")
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.log.read_text())
        self.assertEqual(receipt["args"][:-1], ["run", "--locked", "-p", "devres-adapters",
                                               "--example", "npm-live-probe", "--", "--live"])
        self.assertEqual(Path(receipt["root"]).parent, Path("/tmp"))
        self.assertEqual(receipt["root_mode"], 0o700)
        self.assertEqual(receipt["marker"], "devres-npm-live-v1\n")
        self.assertEqual(receipt["marker_mode"], 0o600)

    def test_provider_targets_cannot_be_supplied_to_fixed_probe(self):
        result = self.run_script("--live", "--npm", "--url", "https://example.invalid")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
