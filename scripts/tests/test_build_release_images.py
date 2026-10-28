"""Exercise the native release-image producer with bounded command fixtures."""
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


class ReleaseImageBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-release-build-test.")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        self.log = self.root / "calls.jsonl"
        self.output = self.root / "images"
        shutil.copy2(SCRIPTS / "build-release-images.sh", self.scripts)
        for name, kind in (("check-native-platform.sh", "native"), ("verify-release-tag.sh", "tag"),
                           ("test-image.sh", "image"), ("release_contract.py", "stamp"),
                           ("release_images.py", "verify")):
            path = self.scripts / name
            path.write_text(f'''#!{sys.executable}
import json, os, sys
from pathlib import Path
with open(os.environ["TEST_LOG"], "a") as output:
    output.write(json.dumps(["{kind}", *sys.argv[1:]]) + "\\n")
if os.environ.get("TEST_FAIL") == "{kind}":
    sys.exit(41)
if "{kind}" == "stamp":
    print("1.2.3")
if "{kind}" == "image":
    Path(sys.argv[sys.argv.index("--oci-output") + 1]).mkdir()
    if os.environ["TMPDIR"] != "/tmp" or os.environ["CARGO_TARGET_DIR"] != "/buildcache/rust/target":
        sys.exit(42)
''')
            path.chmod(0o755)

    def invoke(self, *arguments, failure=""):
        result = subprocess.run(["bash", str(self.scripts / "build-release-images.sh"), *arguments],
                                cwd=self.root, env={**os.environ, "TEST_LOG": str(self.log),
                                                    "TEST_FAIL": failure},
                                capture_output=True, text=True, timeout=10, check=False)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result, calls

    def test_builds_and_verifies_all_targets_for_each_native_architecture(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                output = self.root / arch
                self.log.unlink(missing_ok=True)
                result, calls = self.invoke("linux/" + arch, str(output), "1.2.3", COMMIT)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls[:3], [["native", "linux/" + arch], ["tag", "1.2.3", COMMIT],
                                             ["stamp", "stamp", "--tag", "1.2.3", "--commit", COMMIT]])
                self.assertEqual([call[0] for call in calls[3:]], ["image", "verify"] * 3)
                for index, target in enumerate(("server", "probe", "audit-worker")):
                    self.assertEqual(calls[3 + index * 2], ["image", "--platform", "linux/" + arch,
                                      "--target", target, "--revision", COMMIT, "--version", "1.2.3",
                                      "--oci-output", str(output / target)])
                    self.assertEqual(calls[4 + index * 2], ["verify", "verify", "--directory", str(output / target),
                                      "--target", target, "--arch", arch, "--tag", "1.2.3", "--commit", COMMIT,
                                      "--output", str(output / f"verified-{target}.json")])

    def test_invalid_arguments_paths_and_existing_outputs_never_start_builds(self):
        self.output.mkdir()
        for arguments in ((), ("linux/amd64",),
                          ("linux/386", str(self.root / "invalid"), "1.2.3", COMMIT),
                          ("linux/amd64", "relative", "1.2.3", COMMIT),
                          ("linux/amd64", "/tmp", "1.2.3", COMMIT),
                          ("linux/amd64", "/var/tmp/devres-images", "1.2.3", COMMIT),
                          ("linux/amd64", str(self.output), "1.2.3", COMMIT)):
            with self.subTest(arguments=arguments):
                result, calls = self.invoke(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_admission_build_and_artifact_failures_stop_later_work(self):
        for failure, expected in (("native", ["native"]), ("tag", ["native", "tag"]),
                                  ("stamp", ["native", "tag", "stamp"]),
                                  ("image", ["native", "tag", "stamp", "image"]),
                                  ("verify", ["native", "tag", "stamp", "image", "verify"])):
            with self.subTest(failure=failure):
                self.log.unlink(missing_ok=True)
                result, calls = self.invoke("linux/amd64", str(self.root / failure), "1.2.3", COMMIT,
                                            failure=failure)
                self.assertEqual(result.returncode, 41, result.stderr)
                self.assertEqual([call[0] for call in calls], expected)

    def test_symlinked_output_cannot_escape_tmp(self):
        link = self.root / "outside"
        link.symlink_to("/var/tmp", target_is_directory=True)
        result, calls = self.invoke("linux/amd64", str(link / "images"), "1.2.3", COMMIT)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
