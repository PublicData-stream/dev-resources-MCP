"""Offline platform package and standalone skill archive contracts."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch


scripts = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("customer_plugin", scripts / "package-plugin.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class CustomerPluginTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "output"
        self.url = "https://127.0.0.1:8443/mcp"

    def build(self, target="all", **kwargs):
        return package.build(self.url, self.output, target, **kwargs)

    def sources(self):
        source = self.root / "source"
        shutil.copytree(package.SOURCE, source)
        return source

    def test_all_targets_share_identity_endpoint_and_skill_content(self):
        archives = self.build()
        self.assertEqual(len(archives), 5)
        openai = self.output / "openai/dev-resources"
        claude = self.output / "claude-code/dev-resources"
        portable = json.loads((openai / "plugin.json").read_text())
        manifests = [json.loads(path.read_text()) for path in (
            openai / ".codex-plugin/plugin.json", claude / ".claude-plugin/plugin.json")]
        for manifest in manifests:
            for field in ("name", "version", "description", "license"):
                self.assertEqual(manifest[field], portable[field])
        for folder, filename, transport in ((openai, "mcp.json", "streamable-http"),
                                              (openai, ".mcp.json", "http"),
                                              (claude, ".mcp.json", "http")):
            connection = json.loads((folder / filename).read_text())["mcpServers"][package.SERVER]
            self.assertEqual(connection["url"], self.url)
            self.assertEqual(connection["type"], transport)
            self.assertNotIn("headers", connection)
        auth = json.loads((openai / "mcp.json").read_text())["mcpServers"][package.SERVER]
        self.assertEqual(auth["extensions"]["com.openai"]["auth"]["type"], "none")
        self.assertEqual(json.loads((openai / ".codex-plugin/plugin.json").read_text())["skills"], "./skills/")
        for name in package.SKILLS:
            standalone = self.output / "claude-skills" / name
            for relative, content in package.skill_files(package.SOURCE, name).items():
                for folder in (openai / "skills" / name, claude / "skills" / name, standalone):
                    self.assertEqual((folder / relative).read_bytes(), content)
            metadata = (openai / "skills" / name / "agents/openai.yaml").read_text()
            self.assertIn(json.dumps(self.url), metadata)
            self.assertFalse((claude / "skills" / name / "agents").exists())
            self.assertFalse((standalone / "agents").exists())
        for archive in archives:
            expanded = archive.with_suffix("")
            with zipfile.ZipFile(archive) as bundle:
                expected = {str(path.relative_to(expanded.parent)): path.read_bytes()
                            for path in expanded.rglob("*") if path.is_file()}
                self.assertEqual(set(bundle.namelist()), set(expected))
                self.assertEqual(len(bundle.namelist()), len(expected))
                for relative, content in expected.items():
                    self.assertEqual(bundle.read(relative), content)
                self.assertIsNone(bundle.testzip())

    def test_target_selection_and_reproducible_archives(self):
        for target in package.TARGETS:
            self.output = self.root / target
            archives = self.build(target)
            first = [path.read_bytes() for path in archives]
            self.output = self.root / (target + "-again")
            second = self.build(target)
            self.assertEqual(first, [path.read_bytes() for path in second])
            self.assertEqual({p.name for p in self.output.iterdir()}, {target})

    def test_claude_upload_description_limit_counts_decoded_characters(self):
        source = self.sources()
        name = next(iter(package.SKILLS))
        skill = source / "skills" / name / "SKILL.md"
        original = skill.read_text()
        prefix, description = original.split("description: ", 1)
        _, body = description.split("\n", 1)
        for length in (200, 201, 1024, 1025):
            # Escaped Unicode is decoded before counting; bytes and YAML source
            # length are not the host's character limit.
            skill.write_text(prefix + "description: " + json.dumps("\uac00" * length) + "\n" + body)
            for target in (*package.TARGETS, "all"):
                self.output = self.root / f"{target}-{length}"
                with self.subTest(target=target, length=length):
                    limit = 200 if target in ("claude-skills", "all") else 1024
                    if length > limit:
                        with self.assertRaises(ValueError):
                            self.build(target, source=source)
                        self.assertFalse(self.output.exists())
                    else:
                        self.assertTrue(self.build(target, source=source))

    def test_invalid_endpoints_publish_nothing_and_cli_does_not_echo_credentials(self):
        invalid = ("http://host/mcp", "https://user:private-value@host/mcp", "https://host/mcp?key=private-value",
                   "https://host/mcp#secret", "https://host/mcp?", "https://host/mcp#", "https://host/",
                   "https://{hostname}/mcp", "https://${HOST}/mcp", "https://host:/mcp", "https://host:0/mcp",
                   "https://host:65536/mcp", "https://host /mcp", "https://host/mcp\n", "https://bad_host/mcp")
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(ValueError):
                package.build(url, self.output)
            self.assertFalse(self.output.exists())
        result = subprocess.run([sys.executable, str(scripts / "package-plugin.py"),
                                 "--mcp-url", invalid[1], "--output", str(self.output)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("private-value", result.stdout + result.stderr)

    def test_new_tmp_output_only_and_no_source_recursion(self):
        self.output.mkdir()
        sentinel = self.output / "sentinel"
        sentinel.write_text("preserve")
        with self.assertRaises(ValueError):
            self.build()
        self.assertEqual(sentinel.read_text(), "preserve")
        for path in (Path("/tmp"), scripts / "unwanted-output"):
            with self.assertRaises(ValueError):
                package.build(self.url, path)
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            package.build(self.url, link / "output-two")
        source = self.sources()
        with self.assertRaises(ValueError):
            package.build(self.url, source / "output", source=source)

    def test_private_output_and_owned_ancestors_even_with_permissive_umask(self):
        previous = os.umask(0)
        try:
            self.output = self.root / "new-parent" / "output"
            self.build("claude-code")
        finally:
            os.umask(previous)
        for path in (self.output.parent, self.output):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        unsafe = self.root / "shared-parent"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        with self.assertRaises(ValueError):
            package.build(self.url, unsafe / "output")
        self.assertFalse((unsafe / "output").exists())

    def test_changed_expanded_package_is_rejected_and_removed(self):
        write = package.write_bundle

        def tamper(directory, archive, files):
            write(directory, archive, files)
            next(directory.rglob("SKILL.md")).write_text("changed after ZIP validation")

        with patch.object(package, "write_bundle", side_effect=tamper):
            with self.assertRaises(ValueError):
                self.build("claude-code")
        self.assertFalse(self.output.exists())

    def test_parent_symlink_inserted_during_creation_cannot_redirect_output(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        mkdir = os.mkdir

        def insert_link(path, mode=0o777, *, dir_fd=None):
            if path == "raced-parent":
                os.symlink(str(elsewhere), path, dir_fd=dir_fd)
                raise FileExistsError("simulated concurrent directory creation")
            return mkdir(path, mode, dir_fd=dir_fd)

        with patch.object(package.os, "mkdir", side_effect=insert_link):
            with self.assertRaises(OSError):
                package.reserve_output(self.root / "raced-parent" / "output")
        self.assertFalse((elsewhere / "output").exists())

    def test_missing_components_symlinks_and_escaping_references_fail_before_output(self):
        source = self.sources()
        name = next(iter(package.SKILLS))
        skill = source / "skills" / name / "SKILL.md"
        original = skill.read_bytes()
        skill.unlink()
        with self.assertRaises(ValueError):
            self.build(source=source)
        skill.symlink_to(package.SOURCE / "skills" / name / "SKILL.md")
        with self.assertRaises(ValueError):
            self.build(source=source)
        skill.unlink()
        for target in ("../other/SKILL.md", "%2e%2e/secret", "/etc/passwd", "missing.md", "file:///etc/passwd"):
            skill.write_bytes(original + f"\n[reference]({target})\n".encode())
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.build(source=source)
            self.assertFalse(self.output.exists())
        skill.write_bytes(original)
        unwanted = skill.parent / ".env"
        unwanted.write_text("not package content")
        with self.assertRaises(ValueError):
            self.build(source=source)
        self.assertFalse(self.output.exists())

    def test_unrelated_root_files_are_never_archived(self):
        source = self.sources()
        (source / "operator-secret.txt").write_text("never distribute")
        for archive in self.build(source=source):
            with zipfile.ZipFile(archive) as bundle:
                self.assertFalse(any("operator-secret" in path for path in bundle.namelist()))
                self.assertFalse(any(b"never distribute" in bundle.read(path) for path in bundle.namelist()))

    def test_invalid_canonical_identity_is_rejected(self):
        source = self.sources()
        path = source / "plugin.json"
        original = json.loads(path.read_text())
        for field, value in (("version", "01.0.0"), ("version", "1.0"),
                             ("name", "another-plugin"), ("$schema", "unknown")):
            path.write_text(json.dumps({**original, field: value}))
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.build(source=source)
            self.assertFalse(self.output.exists())

    def test_failed_archive_write_cleans_staging_without_publishing(self):
        with patch.object(package, "write_bundle", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError):
                self.build()
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
