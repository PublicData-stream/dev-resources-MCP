"""Exercise harness binary staging without compiling or starting Docker."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
BINARIES = ("devres-server", "devres-probe", "storage-probe",
            "devres-audit-worker", "devres-pdf-worker", "oxibelt")
DEBUG = b"\n# fixture debug information\n"


class BuildHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-build-harness-test.")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copy2(SCRIPTS / "build-harness.sh", scripts / "build-harness.sh")
        (scripts / "mcp_smoke.py").write_text("# smoke fixture\n")
        deploy = self.root / "deploy" / "oxibelt"
        deploy.mkdir(parents=True)
        (deploy / "Dockerfile.harness").write_text("FROM fixture\n")
        self.target = self.root / "target"
        (self.target / "debug" / "examples").mkdir(parents=True)
        self.scratch = self.root / "scratch"
        self.log = self.root / "calls.jsonl"
        self.sources = {}
        for name in BINARIES:
            path = self.target / "debug" / ("examples/storage-probe" if name == "storage-probe" else name)
            contents = b"#!/bin/sh\nexit 0\n"
            if name == "oxibelt":
                contents = ("#!/bin/sh\nprintf '%s\\n' 'OXIBELT_BUILD_IDENTITY_V1="
                            '{"revision":"4f3154d8db0e0a49bce7a528c0a0f4c36d169040","dirty":"clean"}'
                            "'\n").encode()
            path.write_bytes(contents + DEBUG)
            path.chmod(0o755)
            self.sources[name] = path
        self.executable("cargo", '''
if sys.argv[1] == "metadata":
    print(json.dumps({"target_directory": os.environ["TEST_TARGET"]}))
''')
        self.executable("docker", '''
if sys.argv[1:3] == ["image", "inspect"]:
    sys.exit(1)
''')
        self.executable("strip", '''
assert sys.argv[1] == "--strip-debug"
path = Path(sys.argv[2])
if path.name == os.environ.get("TEST_STRIP_FAIL"):
    sys.exit(42)
path.write_bytes(path.read_bytes().replace(b"\\n# fixture debug information\\n", b""))
''')

    def executable(self, name, body):
        path = self.bin / name
        path.write_text(f'''#!{sys.executable}
import json, os, sys
from pathlib import Path
with open(os.environ["TEST_LOG"], "a") as output:
    output.write(json.dumps([{name!r}, *sys.argv[1:]]) + "\\n")
{body}
''')
        path.chmod(0o755)

    def run_build(self, supplied=False, **extra_env):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                   TEST_LOG=str(self.log), TEST_TARGET=str(self.target),
                   OXIBELT_BINARY=str(self.sources["oxibelt"]))
        for variable in ("SERVER_BINARY", "PROBE_BINARY", "TEST_STRIP_FAIL"):
            env.pop(variable, None)
        if supplied:
            for variable, name in (("SERVER_BINARY", "devres-server"), ("PROBE_BINARY", "devres-probe")):
                path = self.root / f"supplied-{name}"
                shutil.copy2(self.sources[name], path)
                self.sources[name] = path
                env[variable] = str(path)
        env.update(extra_env)
        original = {name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                    for name, path in self.sources.items()}
        result = subprocess.run(["/bin/bash", str(self.root / "scripts" / "build-harness.sh"),
                                 str(self.scratch), "harness:test"],
                                cwd=self.root, env=env, capture_output=True, text=True, timeout=10)
        for name, path in self.sources.items():
            self.assertEqual((path.read_bytes(), stat.S_IMODE(path.stat().st_mode)), original[name])
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls, original

    def test_strips_all_staged_copies_and_preserves_sources_and_modes(self):
        for supplied in (False, True):
            with self.subTest(supplied=supplied):
                self.log.unlink(missing_ok=True)
                result, calls, original = self.run_build(supplied=supplied)
                self.assertEqual(result.returncode, 0, result.stderr)
                staged = self.scratch / "build" / "bin"
                self.assertEqual([call[2] for call in calls if call[0] == "strip"],
                                 [str(staged / name) for name in BINARIES])
                for name in BINARIES:
                    self.assertEqual((staged / name).read_bytes(), original[name][0].replace(DEBUG, b""))
                    self.assertEqual(stat.S_IMODE((staged / name).stat().st_mode), original[name][1])
                build = next(i for i, call in enumerate(calls) if call[:2] == ["docker", "build"])
                self.assertTrue(all(i < build for i, call in enumerate(calls) if call[0] == "strip"))

    def test_strip_failure_prevents_image_build(self):
        result, calls, _ = self.run_build(TEST_STRIP_FAIL="storage-probe")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertFalse(any(call[:2] == ["docker", "build"] for call in calls))
        self.assertEqual([Path(call[2]).name for call in calls if call[0] == "strip"],
                         list(BINARIES[:3]))

    def test_missing_strip_fails_before_compilation(self):
        (self.bin / "strip").unlink()
        # Only dirname is needed before the early strip prerequisite check.
        (self.bin / "dirname").symlink_to(shutil.which("dirname"))
        result, calls, _ = self.run_build(PATH=str(self.bin))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("strip is required", result.stderr)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
