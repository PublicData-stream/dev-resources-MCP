"""Exercise CI driver admission and release preparation without installs or Docker."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40


class CiE2eTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-ci-driver-test.")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.log = self.root / "calls.jsonl"
        for name in ("ci-e2e.sh", "with-tmp-state.sh"):
            shutil.copy2(SCRIPTS / name, self.scripts / name)
        # Keep the real state wrapper, but confine its mktemp allocation to the fixture.
        self.executable(self.bin / "mktemp", '#!/bin/sh\nprintf "%s\\n" "$TEST_STATE"\n')
        self.executable(self.bin / "sudo", f'''#!{sys.executable}
import json, os, sys
with open(os.environ["TEST_LOG"], "a") as output:
    output.write(json.dumps(["sudo", *sys.argv[1:]]) + "\\n")
sys.exit(73)
''')
        # Any accidental path beyond the install boundary must fail without side effects.
        for name in ("rustup", "docker", "curl"):
            self.executable(self.bin / name, '#!/bin/sh\nexit 99\n')
        self.executable(self.scripts / "verify-release-tag.sh", f'''#!{sys.executable}
import json, os, sys
with open(os.environ["TEST_LOG"], "a") as output:
    output.write(json.dumps(["tag", *sys.argv[1:]]) + "\\n")
sys.exit(int(os.environ.get("TEST_TAG_STATUS", "0")))
''')
        (self.scripts / "release_contract.py").write_text('''import json, os, sys
with open(os.environ["TEST_LOG"], "a") as output:
    output.write(json.dumps(["release", *sys.argv[1:]]) + "\\n")
if os.environ.get("TEST_RELEASE_STATUS"):
    sys.exit(int(os.environ["TEST_RELEASE_STATUS"]))
print("1.2.3")
''')

    def executable(self, path, contents):
        path.write_text(contents)
        path.chmod(0o755)

    def run_driver(self, *args, **extra_env):
        env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "GITHUB_SHA": COMMIT,
            "RELEASE_TAG": "",
            "TEST_LOG": str(self.log),
            "TEST_STATE": str(self.state),
            **extra_env,
        }
        result = subprocess.run(
            ["bash", str(self.scripts / "ci-e2e.sh"), *args],
            cwd=self.root, env=env, text=True, capture_output=True,
            timeout=10, check=False,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls

    def test_invalid_argument_counts_and_modes_fail_before_install(self):
        for args in ((), ("unknown",), ("build",),
                     ("build", "linux/amd64", "artifact", "extra"),
                     ("test", "docker", "linux/amd64"),
                     ("test", "docker", "linux/amd64", "artifact", "extra")):
            with self.subTest(args=args):
                result, calls = self.run_driver(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("usage:", result.stderr)
                self.assertEqual(calls, [])

    def test_invalid_platform_fails_before_release_or_install(self):
        for args in (("build", "linux/386", "artifact"),
                     ("test", "docker", "darwin/arm64", "artifact")):
            with self.subTest(args=args):
                result, calls = self.run_driver(*args, RELEASE_TAG="v1.2.3")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("Unsupported native platform", result.stderr)
                self.assertEqual(calls, [])

    def test_invalid_scenario_fails_before_release_or_install(self):
        result, calls = self.run_driver("test", "unknown", "linux/amd64", "artifact", RELEASE_TAG="v1.2.3")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Unsupported CI scenario", result.stderr)
        self.assertEqual(calls, [])

    def test_release_build_verifies_tag_then_stamps_before_install(self):
        result, calls = self.run_driver("build", "linux/amd64", "artifact", RELEASE_TAG="v1.2.3")
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(calls, [
            ["tag", "v1.2.3", COMMIT],
            ["release", "stamp", "--tag", "v1.2.3", "--commit", COMMIT],
            ["sudo", "-n", "apt-get", "update"],
        ])

    def test_release_consumer_validates_without_tag_check_or_stamp(self):
        for scenario, platform in (("docker", "linux/amd64"), ("minikube", "linux/arm64")):
            with self.subTest(scenario=scenario):
                self.log.unlink(missing_ok=True)
                result, calls = self.run_driver("test", scenario, platform, "artifact", RELEASE_TAG="v1.2.3")
                self.assertEqual(result.returncode, 73, result.stderr)
                self.assertEqual(calls, [
                    ["release", "validate", "--tag", "v1.2.3", "--commit", COMMIT],
                    ["sudo", "-n", "apt-get", "update"],
                ])

    def test_release_failure_prevents_install(self):
        for args, settings, expected in (
            (("build", "linux/amd64", "artifact"), {"TEST_TAG_STATUS": "41"}, ["tag"]),
            (("build", "linux/arm64", "artifact"), {"TEST_RELEASE_STATUS": "42"}, ["tag", "release"]),
            (("test", "docker", "linux/amd64", "artifact"), {"TEST_RELEASE_STATUS": "42"}, ["release"]),
        ):
            with self.subTest(args=args, settings=settings):
                self.log.unlink(missing_ok=True)
                result, calls = self.run_driver(*args, RELEASE_TAG="v1.2.3", **settings)
                self.assertEqual(result.returncode, int(next(iter(settings.values()))), result.stderr)
                self.assertEqual([call[0] for call in calls], expected)

    def test_ordinary_build_skips_release_preparation(self):
        result, calls = self.run_driver("build", "linux/arm64", "artifact")
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(calls, [["sudo", "-n", "apt-get", "update"]])

    def test_consumer_storage_failures_preserve_verification_and_scenario_status(self):
        # Exercise the real child-shell driver without host installs or daemon setup.
        for name in ("sudo", "rustup"):
            self.executable(self.bin / name, "#!/bin/sh\nexit 0\n")
        self.executable(self.scripts / "with-local-docker.sh", '#!/bin/sh\nexec "$@"\n')
        self.executable(self.scripts / "check-native-platform.sh", '#!/bin/sh\necho native >> "$TEST_LOG"\n')
        self.executable(self.scripts / "e2e-storage.sh", '#!/bin/sh\necho "storage $1" >> "$TEST_LOG"\nexit 97\n')
        self.executable(self.scripts / "test-oxibelt.sh", '#!/bin/sh\necho "scenario $*" >> "$TEST_LOG"\nexit 44\n')
        (self.scripts / "e2e-artifact.py").write_text('''import os, sys
with open(os.environ["TEST_LOG"], "a") as stream:
    stream.write("verify\\n")
if os.environ.get("VERIFY_FAIL"):
    sys.exit(42)
print("fixture:test")
''')
        for failure in (False, True):
            with self.subTest(failure=failure):
                self.log.unlink(missing_ok=True)
                env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                           GITHUB_SHA=COMMIT, RELEASE_TAG="", TEST_LOG=str(self.log),
                           DEVRES_TMP_ROOT=str(self.state), VERIFY_FAIL="1" if failure else "")
                result = subprocess.run(["bash", str(self.scripts / "ci-e2e.sh"), "--inside-state",
                                         "test", "docker", "linux/amd64", "artifact"],
                                        env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 42 if failure else 44, result.stderr)
                self.assertEqual(self.log.read_text().splitlines(), [
                    "native", "storage before-artifact-load", "verify",
                    *(["storage artifact-load-failed"] if failure else
                      ["storage after-artifact-load", "scenario --image fixture:test"]),
                ])


if __name__ == "__main__":
    unittest.main()
