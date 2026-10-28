"""Exercise release tag identity fences against a disposable local Git origin."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).parents[1]


class ReleaseTagTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.origin = Path(self.temp.name) / "origin.git"
        self.root.mkdir()
        (self.root / "scripts").mkdir()
        for name in ("verify-release-tag.sh", "release_contract.py"):
            shutil.copyfile(SCRIPTS / name, self.root / "scripts" / name)
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.name", "Release fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "Fixture baseline")
        self.commit = self.git("rev-parse", "HEAD")
        self.git("init", "--quiet", "--bare", str(self.origin))
        self.git("remote", "add", "origin", str(self.origin))
        self.git("push", "--quiet", "--set-upstream", "origin", "main")
        self.tag = "1.2.3"

    def git(self, *arguments):
        return subprocess.check_output(["git", "-C", str(self.root), *arguments], stderr=subprocess.PIPE).decode().strip()

    def annotated_tag(self):
        self.git("tag", "--annotate", self.tag, "--message", "Release fixture")
        self.git("push", "--quiet", "origin", "refs/tags/" + self.tag)
        return self.git("rev-parse", "refs/tags/" + self.tag)

    def fence(self, tag_object=None):
        arguments = ["bash", str(self.root / "scripts" / "verify-release-tag.sh"), self.tag, self.commit]
        if tag_object is not None:
            arguments.append(tag_object)
        return subprocess.run(arguments, cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def test_annotated_main_tag_returns_and_rechecks_exact_tag_object(self):
        tag_object = self.annotated_tag()
        initial = self.fence()
        self.assertEqual(initial.returncode, 0, initial.stderr.decode())
        self.assertEqual(initial.stdout.decode().strip(), tag_object)
        recheck = self.fence(tag_object)
        self.assertEqual(recheck.returncode, 0, recheck.stderr.decode())
        self.assertEqual(recheck.stdout.decode().strip(), tag_object)

    def test_lightweight_tag_is_rejected(self):
        self.git("tag", self.tag)
        self.git("push", "--quiet", "origin", "refs/tags/" + self.tag)
        self.assertNotEqual(self.fence(self.commit).returncode, 0)

    def test_tagged_commit_outside_origin_main_is_rejected(self):
        self.git("checkout", "--quiet", "-b", "unmerged")
        (self.root / "unmerged.txt").write_text("Unmerged fixture source\n")
        self.git("add", "unmerged.txt")
        self.git("commit", "--quiet", "-m", "Unmerged fixture")
        self.commit = self.git("rev-parse", "HEAD")
        tag_object = self.annotated_tag()
        self.assertNotEqual(self.fence(tag_object).returncode, 0)

    def test_moved_remote_tag_cannot_reuse_captured_identity(self):
        tag_object = self.annotated_tag()
        self.assertEqual(self.fence(tag_object).returncode, 0)
        self.git("tag", "--annotate", "replacement", "--message", "Different tag object at same commit")
        replacement = self.git("rev-parse", "refs/tags/replacement")
        self.assertNotEqual(replacement, tag_object)
        self.git("push", "--quiet", "origin", "+refs/tags/replacement:refs/tags/" + self.tag)
        # Local tag and HEAD stay valid; only the origin's tag identity changed.
        self.assertEqual(self.git("rev-parse", "refs/tags/" + self.tag), tag_object)
        self.assertNotEqual(self.fence(tag_object).returncode, 0)

    def test_deleted_remote_tag_cannot_reuse_captured_identity(self):
        tag_object = self.annotated_tag()
        self.git("push", "--quiet", "origin", ":refs/tags/" + self.tag)
        self.assertNotEqual(self.fence(tag_object).returncode, 0)

    def test_wrong_expected_tag_object_is_rejected(self):
        self.annotated_tag()
        self.assertNotEqual(self.fence("0" * 40).returncode, 0)

    def test_checkout_must_match_tagged_commit(self):
        tag_object = self.annotated_tag()
        self.git("commit", "--quiet", "--allow-empty", "-m", "Different checkout")
        self.assertNotEqual(self.fence(tag_object).returncode, 0)


if __name__ == "__main__":
    unittest.main()
