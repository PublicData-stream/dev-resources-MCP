import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import unittest


spec = importlib.util.spec_from_file_location("release_contract", Path(__file__).parents[1] / "release_contract.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class TagTests(unittest.TestCase):
    def test_stable_beta_and_build_versions(self):
        sha = "ab123456" + "0" * 32
        for tag in ("1.2.3", "1.2.3-beta.0", "1.2.3-build.ab123456"):
            self.assertEqual(release.validate(tag, sha), tag)

    def test_disallowed_or_mismatched_tags(self):
        sha = "ab123456" + "0" * 32
        for tag in ("v1.2.3", "01.2.3", "1.2.3-beta.01", "1.2.3-rc.1", "1.2.3+meta",
                    "1.2.3-build.AB123456", "1.2.3-build.ab1234567", "1.2.3\n",
                    "1.2.3-build.deadbeef", "1.2.3; touch /tmp/injection"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.validate(tag, sha)
        for sha in ("ab123456", "a" * 39, "A" * 40, "g" * 40):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                release.validate("1.2.3", sha)

    def test_numeric_build_suffix_obeys_semver(self):
        with self.assertRaisesRegex(ValueError, "leading zeros"):
            release.validate("1.2.3-build.01234567", "01234567" + "a" * 32)
        self.assertEqual(release.validate("1.2.3-build.12345678", "12345678" + "a" * 32), "1.2.3-build.12345678")


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.write("Cargo.toml", '[workspace]\nmembers = ["crates/domain", "apps/server"]\n[workspace.package]\nversion = "0.0.0"\n')
        self.write("crates/domain/Cargo.toml", '[package]\nname = "devres-domain"\nversion.workspace = true\n')
        self.write("apps/server/Cargo.toml", '[package]\nname = "devres-server"\nversion.workspace = true\n[dependencies]\ndevres-domain = { version = "0.0.0", path = "../../crates/domain" }\nthird-party = "0.0.0"\n')
        self.write("Cargo.lock", 'version = 4\n\n[[package]]\nname = "devres-domain"\nversion = "0.0.0"\n\n[[package]]\nname = "devres-server"\nversion = "0.0.0"\ndependencies = ["devres-domain 0.0.0", "third-party 0.0.0"]\n\n[[package]]\nname = "third-party"\nversion = "0.0.0"\nsource = "registry+https://example.invalid/index"\nchecksum = "abc"\n')
        self.write("deny.toml", '[licenses]\nallow = ["MIT"]\nexceptions = [\n { crate = "devres-domain@0.0.0", allow = ["AGPL-3.0-only"] },\n { crate = "devres-server@0.0.0", allow = ["AGPL-3.0-only"] },\n]\n')
        self.write("README.md", "Released source\n")
        self.git("init", "-q")
        self.commit()
        self.tag = "1.2.3-beta.1"

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.PIPE).decode().strip()

    def commit(self):
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "Fixture")
        self.sha = self.git("rev-parse", "HEAD")

    def write(self, relative, contents):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def text(self, relative):
        return (self.root / relative).read_text()

    def test_stamp_changes_all_first_party_surfaces_only(self):
        release.stamp(self.root, self.tag, self.sha)
        self.assertEqual(release.verify_stamped(self.root, self.tag, self.sha), self.tag)
        packages = tomllib.loads(self.text("Cargo.lock"))["package"]
        self.assertEqual([p["version"] for p in packages], ["1.2.3-beta.1", "1.2.3-beta.1", "0.0.0"])
        self.assertEqual(packages[1]["dependencies"], ["devres-domain 1.2.3-beta.1", "third-party 0.0.0"])
        self.assertIn('third-party = "0.0.0"', self.text("apps/server/Cargo.toml"))
        exceptions = tomllib.loads(self.text("deny.toml"))["licenses"]["exceptions"]
        self.assertEqual({e["crate"] for e in exceptions}, {"devres-domain@1.2.3-beta.1", "devres-server@1.2.3-beta.1"})

    def test_partial_baseline_fails_without_writes(self):
        original = self.text("Cargo.toml")
        self.write("apps/server/Cargo.toml", self.text("apps/server/Cargo.toml").replace('version = "0.0.0"', 'version = "1.0.0"'))
        with self.assertRaisesRegex(ValueError, "unexpected source"):
            release.stamp(self.root, self.tag, self.sha)
        self.assertEqual(self.text("Cargo.toml"), original)

    def test_changed_third_party_lock_fails_without_writes(self):
        original = self.text("Cargo.toml")
        self.write("Cargo.lock", self.text("Cargo.lock").replace('checksum = "abc"', 'checksum = "changed"'))
        with self.assertRaisesRegex(ValueError, "unexpected source"):
            release.stamp(self.root, self.tag, self.sha)
        self.assertEqual(self.text("Cargo.toml"), original)

    def test_changed_stamped_lock_and_dependency_are_rejected(self):
        release.stamp(self.root, self.tag, self.sha)
        self.write("Cargo.lock", self.text("Cargo.lock").replace('checksum = "abc"', 'checksum = "changed"'))
        with self.assertRaisesRegex(ValueError, "Cargo.lock"):
            release.verify_stamped(self.root, self.tag, self.sha)

    def test_baseline_requires_every_exact_license_exception(self):
        for contents in (self.text("deny.toml").replace("devres-domain@0.0.0", "devres-domain"),
                         self.text("deny.toml").replace('allow = ["AGPL-3.0-only"]', 'allow = ["MIT"]')):
            self.write("deny.toml", contents)
            self.commit()
            original = self.text("Cargo.toml")
            with self.assertRaises(ValueError):
                release.stamp(self.root, self.tag, self.sha)
            self.assertEqual(self.text("Cargo.toml"), original)

    def test_workspace_must_start_at_placeholder(self):
        self.write("Cargo.toml", self.text("Cargo.toml").replace('"0.0.0"', '"2.0.0"'))
        self.commit()
        with self.assertRaisesRegex(ValueError, "baseline version"):
            release.stamp(self.root, self.tag, self.sha)

    def test_archive_is_deterministic_and_excludes_private_and_untracked_files(self):
        self.write(".agents/private.md", "private")
        self.write(".env", "credential")
        self.commit()
        self.write("untracked-private.txt", "credential")
        release.stamp(self.root, self.tag, self.sha)
        first, second = Path(self.temp.name) / "a", Path(self.temp.name) / "b"
        metadata = release.archive(self.root, self.tag, self.sha, first)
        release.archive(self.root, self.tag, self.sha, second)
        for filename in ("source.tar.gz", "source.tar.gz.sha256", "release.json"):
            self.assertEqual((first / filename).read_bytes(), (second / filename).read_bytes())
        self.assertEqual(metadata["source_sha256"], hashlib.sha256((first / "source.tar.gz").read_bytes()).hexdigest())
        self.assertEqual(json.loads((first / "release.json").read_text())["commit"], self.sha)
        with tarfile.open(first / "source.tar.gz") as tar:
            names = tar.getnames()
            self.assertFalse(any(".agents" in name or ".env" in name or "untracked" in name for name in names))
            manifest = tar.extractfile("dev-resources-MCP-1.2.3-beta.1/Cargo.toml").read().decode()
            self.assertIn('version = "1.2.3-beta.1"', manifest)
            self.assertTrue(all(member.mtime == 0 and member.uid == 0 for member in tar.getmembers()))
        with self.assertRaisesRegex(ValueError, "overwrite"):
            release.archive(self.root, self.tag, self.sha, first)

    def test_archive_rejects_unreviewed_source_and_symlinks(self):
        release.stamp(self.root, self.tag, self.sha)
        self.write("README.md", "unreviewed")
        with self.assertRaisesRegex(ValueError, "unreviewed source"):
            release.archive(self.root, self.tag, self.sha, Path(self.temp.name) / "a")
        self.write("README.md", "Released source\n")
        (self.root / "link").symlink_to("README.md")
        # Commit only the link; keep the original placeholder baseline in Git.
        self.git("add", "link")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "Link")
        self.sha = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ValueError, "regular tracked files"):
            release.archive(self.root, self.tag, self.sha, Path(self.temp.name) / "b")


if __name__ == "__main__":
    unittest.main()
