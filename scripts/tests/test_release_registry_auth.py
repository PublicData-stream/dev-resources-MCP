"""Disposable filesystem/client tests for hosted release credential discovery."""
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import errno
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release_registry_auth.py"
spec = importlib.util.spec_from_file_location("release_registry_auth", SCRIPT)
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)
TOKEN = "fixture-only-secret:with-colon"


class RegistryAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-registry-auth-test.")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o755)
        self.scratch = self.root / "release"
        self.scratch.mkdir(mode=0o755)
        self.config = self.home / ".docker/config.json"
        self.private = self.scratch / "auth"
        self.log = self.root / "calls.jsonl"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("docker", "skopeo"):
            client = self.bin / name
            client.write_text(f'''#!{sys.executable}
import base64, json, os
from pathlib import Path
import sys
token = sys.stdin.read()
with open(os.environ["TEST_LOG"], "a") as output:
    output.write(json.dumps({{"client": Path(sys.argv[0]).name, "args": sys.argv[1:],
        "stdin_ok": token == {TOKEN!r}, "token_env": "REGISTRY_TOKEN" in os.environ,
        "home": os.environ.get("HOME")}}) + "\\n")
if os.environ.get("FAIL_CLIENT") == Path(sys.argv[0]).name:
    print(token, file=sys.stderr)
    sys.exit(19)
path = (Path(os.environ["DOCKER_CONFIG"]) / "config.json" if Path(sys.argv[0]).name == "docker"
        else Path(os.environ["REGISTRY_AUTH_FILE"]))
path.write_text(json.dumps({{"auths": {{"ghcr.io": {{"auth": base64.b64encode(
    ("fixture-actor:" + token).encode()).decode()}}}}}}))
''')
            client.chmod(0o755)
        self.environment = patch.dict(os.environ, {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "REGISTRY_TOKEN": TOKEN, "TEST_LOG": str(self.log),
            "DOCKER_CONFIG": str(self.private / "docker"),
            "REGISTRY_AUTH_FILE": str(self.private / "registry-auth.json"),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.manager = auth.RegistryAuth(self.scratch, self.home)

    def prepare(self):
        self.manager.prepare(TOKEN, "fixture-actor")

    def original(self):
        self.config.parent.mkdir(mode=0o755, exist_ok=True)
        self.config.write_text('{"auths":{"unrelated.example":{"auth":"fixture"}}}\n')
        self.config.chmod(0o640)
        return self.config.read_bytes(), self.config.stat()

    def test_login_stdin_and_real_filesystem_bridge(self):
        home_before = os.environ.get("HOME")
        self.prepare()
        self.manager.check()
        self.assertTrue(self.config.is_symlink())
        self.assertEqual(self.config.resolve(), self.private / "docker/config.json")
        record = json.loads(self.config.read_text())["auths"]["ghcr.io"]
        self.assertEqual(base64.b64decode(record["auth"]).decode(), "fixture-actor:" + TOKEN)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual({call["client"] for call in calls}, {"docker", "skopeo"})
        for call in calls:
            self.assertEqual(call["args"], ["login", "--username", "fixture-actor", "--password-stdin", "ghcr.io"])
            self.assertTrue(call["stdin_ok"])
            self.assertFalse(call["token_env"])
            self.assertEqual(call["home"], home_before)
        for directory in (self.private, self.private / "docker", self.scratch / "attest"):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for config in (self.private / "docker/config.json", self.private / "registry-auth.json"):
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.manager.cleanup()
        self.manager.cleanup()
        self.assertFalse(self.config.parent.exists())
        self.assertFalse(self.private.exists())
        self.assertEqual(os.environ.get("HOME"), home_before)

    def test_original_restored_with_inode_bytes_and_permissions(self):
        content, before = self.original()
        retained = self.scratch / "oci-images"
        retained.mkdir()
        (retained / "tested.oci").write_bytes(b"retain tested artifact")
        self.prepare()
        self.manager.cleanup()
        after = self.config.stat()
        self.assertFalse(self.config.is_symlink())
        self.assertEqual(self.config.read_bytes(), content)
        self.assertEqual((after.st_ino, after.st_dev, after.st_mode, after.st_uid, after.st_mtime_ns),
                         (before.st_ino, before.st_dev, before.st_mode, before.st_uid, before.st_mtime_ns))
        self.assertEqual((retained / "tested.oci").read_bytes(), b"retain tested artifact")

    def test_existing_docker_directory_and_unrelated_files_are_preserved(self):
        self.config.parent.mkdir(mode=0o755)
        unrelated = self.config.parent / "unrelated"
        unrelated.write_text("retain")
        self.prepare()
        self.manager.cleanup()
        self.assertFalse(self.config.exists())
        self.assertEqual(unrelated.read_text(), "retain")

    def test_missing_token_or_actor_never_changes_original(self):
        content, before = self.original()
        for token, actor in (("", "fixture-actor"), (TOKEN, "")):
            with self.subTest(actor=actor), self.assertRaises((ValueError, RuntimeError)):
                self.manager.prepare(token, actor)
        self.assertEqual(self.config.read_bytes(), content)
        self.assertEqual(self.config.stat().st_ino, before.st_ino)
        self.assertFalse(self.log.exists())

    def test_login_failures_are_sanitized_and_restore_original(self):
        content, before = self.original()
        for name in ("docker", "skopeo"):
            output = io.StringIO()
            with self.subTest(client=name), patch.dict(os.environ, {"FAIL_CLIENT": name}), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                with self.assertRaises((ValueError, RuntimeError)) as caught:
                    self.prepare()
                self.assertNotIn(TOKEN, str(caught.exception) + output.getvalue())
                self.manager.cleanup()
                self.assertEqual(self.config.read_bytes(), content)
                self.assertEqual(self.config.stat().st_ino, before.st_ino)

    def test_symlinked_config_or_parent_rejected_without_touching_target(self):
        target = self.root / "external"
        target.mkdir()
        destination = target / "config.json"
        destination.write_text("retain")
        self.config.parent.symlink_to(target, target_is_directory=True)
        with self.assertRaises((ValueError, RuntimeError)):
            self.prepare()
        self.assertEqual(destination.read_text(), "retain")
        self.config.parent.unlink()
        self.config.parent.mkdir(mode=0o755)
        self.config.symlink_to(destination)
        with self.assertRaises((ValueError, RuntimeError)):
            self.prepare()
        self.assertTrue(self.config.is_symlink())
        self.assertEqual(destination.read_text(), "retain")

    def test_symlinked_scratch_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.scratch, target_is_directory=True)
        with self.assertRaises((ValueError, RuntimeError)):
            auth.RegistryAuth(alias, self.home).prepare(TOKEN, "fixture-actor")
        self.assertFalse(self.config.exists())

    def test_writable_shared_directory_is_rejected_before_login(self):
        self.config.parent.mkdir(mode=0o777)
        self.config.parent.chmod(0o777)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.log.exists())
        self.assertFalse(self.config.exists())

    def test_preexisting_auth_state_is_not_reused_or_deleted(self):
        self.private.mkdir(mode=0o700)
        unrelated = self.private / "unrelated"
        unrelated.write_text("retain")
        with self.assertRaises((ValueError, RuntimeError, FileExistsError)):
            self.prepare()
        self.assertEqual(unrelated.read_text(), "retain")

    def test_cross_filesystem_backup_fails_before_home_mutation_or_login(self):
        content, before = self.original()
        original_directory = auth.owned_directory

        def different_device(path, **keywords):
            value = original_directory(path, **keywords)
            if path == self.config.parent:
                fields = list(value)
                fields[2] = self.scratch.stat().st_dev + 1
                return os.stat_result(fields)
            return value

        with patch.object(auth, "owned_directory", side_effect=different_device):
            with self.assertRaisesRegex(ValueError, "same filesystem"):
                self.prepare()
        self.assertEqual(self.config.read_bytes(), content)
        self.assertEqual(self.config.stat().st_ino, before.st_ino)
        self.assertFalse(self.log.exists())
        self.assertFalse(self.private.exists())

    def test_cleanup_recovers_abrupt_interruption_around_backup_and_bridge(self):
        class Interrupted(BaseException):
            pass

        original_rename = os.rename
        original_link = os.link
        for point in ("before_backup", "after_backup", "after_bridge"):
            with self.subTest(point=point):
                content, before = self.original()

                def rename(source, destination, *args, **keywords):
                    backup = Path(destination) == self.private / "original-config.json"
                    if point == "before_backup" and backup:
                        raise Interrupted()
                    result = original_rename(source, destination, *args, **keywords)
                    if point == "after_backup" and backup:
                        raise Interrupted()
                    return result

                def link(source, destination, *args, **keywords):
                    result = original_link(source, destination, *args, **keywords)
                    if point == "after_bridge" and Path(destination) == self.config:
                        raise Interrupted()
                    return result

                with patch.object(auth.os, "rename", side_effect=rename), patch.object(auth.os, "link", side_effect=link):
                    with self.assertRaises(Interrupted):
                        self.prepare()
                self.manager.cleanup()
                self.manager.cleanup()
                self.assertEqual(self.config.read_bytes(), content)
                self.assertEqual(self.config.stat().st_ino, before.st_ino)
                self.assertFalse(self.private.exists())

    def test_concurrent_config_appearing_during_install_is_never_overwritten(self):
        content, before = self.original()
        original_link = os.link

        def interfere(source, destination, *args, **keywords):
            if Path(destination) == self.config:
                self.config.write_text("concurrent replacement")
            return original_link(source, destination, *args, **keywords)

        with patch.object(auth.os, "link", side_effect=interfere):
            with self.assertRaises(ValueError):
                self.prepare()
        self.assertEqual(self.config.read_text(), "concurrent replacement")
        backup = self.private / "original-config.json"
        self.assertEqual(backup.read_bytes(), content)
        self.assertEqual(backup.stat().st_ino, before.st_ino)

    def test_failed_restoration_retains_backup_and_is_retryable(self):
        content, before = self.original()
        self.prepare()
        original_link = os.link

        def cannot_restore(source, destination, *args, **keywords):
            if Path(source) == self.private / "original-config.json":
                raise OSError(errno.EIO, "fixture restoration failure")
            return original_link(source, destination, *args, **keywords)

        with patch.object(auth.os, "link", side_effect=cannot_restore):
            with self.assertRaises(OSError):
                self.manager.cleanup()
        self.assertFalse(self.config.exists())
        self.assertEqual((self.private / "original-config.json").read_bytes(), content)
        self.manager.cleanup()
        self.assertEqual(self.config.stat().st_ino, before.st_ino)

    def test_cleanup_recovers_interruption_after_original_inode_is_linked_back(self):
        class Interrupted(BaseException):
            pass

        content, before = self.original()
        self.prepare()
        original_link = os.link

        def interrupted(source, destination, *args, **keywords):
            result = original_link(source, destination, *args, **keywords)
            if Path(source) == self.private / "original-config.json":
                raise Interrupted()
            return result

        with patch.object(auth.os, "link", side_effect=interrupted):
            with self.assertRaises(Interrupted):
                self.manager.cleanup()
        self.assertEqual(self.config.stat().st_nlink, 2)
        self.assertEqual(self.config.read_bytes(), content)
        self.manager.cleanup()
        self.assertEqual(self.config.stat().st_ino, before.st_ino)
        self.assertEqual(self.config.stat().st_nlink, 1)
        self.assertFalse(self.private.exists())

    def test_concurrent_config_appearing_during_restore_preserves_both_files(self):
        content, before = self.original()
        self.prepare()
        original_link = os.link

        def interfere(source, destination, *args, **keywords):
            if Path(source) == self.private / "original-config.json":
                self.config.write_text("concurrent replacement")
            return original_link(source, destination, *args, **keywords)

        with patch.object(auth.os, "link", side_effect=interfere):
            with self.assertRaises(FileExistsError):
                self.manager.cleanup()
        self.assertEqual(self.config.read_text(), "concurrent replacement")
        self.assertEqual((self.private / "original-config.json").read_bytes(), content)
        self.assertEqual((self.private / "original-config.json").stat().st_ino, before.st_ino)

    def test_preflight_failure_rolls_back_without_publishing_credentials(self):
        content, before = self.original()
        with patch.object(self.manager, "check", side_effect=ValueError("fixture preflight failure")):
            with self.assertRaises(ValueError):
                self.prepare()
        self.assertEqual(self.config.read_bytes(), content)
        self.assertEqual(self.config.stat().st_ino, before.st_ino)
        self.assertFalse(self.private.exists())

    def test_unjournaled_new_directory_is_left_untouched(self):
        class Interrupted(BaseException):
            pass

        original_save = self.manager._save

        def interrupted(state):
            if state["docker_directory"] is not None:
                raise Interrupted()
            return original_save(state)

        with patch.object(self.manager, "_save", side_effect=interrupted):
            with self.assertRaises(Interrupted):
                self.prepare()
        directory_inode = self.config.parent.stat().st_ino
        unrelated = self.config.parent / "external"
        unrelated.write_text("retain")
        self.manager.cleanup()
        self.assertEqual(self.config.parent.stat().st_ino, directory_inode)
        self.assertEqual(unrelated.read_text(), "retain")
        self.assertFalse(self.private.exists())

    def test_cleanup_before_preparation_is_a_noop(self):
        self.manager.cleanup()
        self.scratch.rmdir()
        self.manager.cleanup()
        self.assertFalse(self.scratch.exists())

    def test_hosted_cli_lifecycle_uses_fixed_scratch_and_preserves_home_environment(self):
        home_before = os.environ.get("HOME")
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                                    "GITHUB_ACTOR": "fixture-actor", "RELEASE_SCRATCH": str(self.scratch)}), patch.object(auth.Path, "home", return_value=self.home):
            for operation in ("prepare", "check", "cleanup"):
                with patch.object(sys, "argv", [str(SCRIPT), operation]):
                    auth.main()
        self.assertEqual(os.environ.get("HOME"), home_before)
        self.assertFalse(self.private.exists())

    def test_check_rejects_missing_or_malformed_credentials(self):
        self.prepare()
        credential = self.private / "docker/config.json"
        original = credential.read_bytes()
        for value in (b"not json", b'{"auths":{}}', b'{"auths":{"ghcr.io":{"auth":"!!"}}}'):
            with self.subTest(value=value):
                credential.write_bytes(value)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.manager.check()
        credential.write_bytes(original)
        self.manager.cleanup()

    def test_cleanup_refuses_unrelated_replacement_and_retains_backup(self):
        content, before = self.original()
        self.prepare()
        self.config.unlink()
        self.config.write_text("external replacement")
        with self.assertRaises((ValueError, RuntimeError)):
            self.manager.cleanup()
        self.assertEqual(self.config.read_text(), "external replacement")
        backup = self.private / "original-config.json"
        self.assertEqual(backup.read_bytes(), content)
        self.assertEqual(backup.stat().st_ino, before.st_ino)
        self.assertTrue((self.private / "state.json").is_file())

    def test_cli_refuses_local_home_mutation(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "prepare"],
                                env={**os.environ, "GITHUB_ACTIONS": "false", "RELEASE_SCRATCH": str(self.scratch)},
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)


class RegistryAuthWorkflowTests(unittest.TestCase):
    def test_both_publication_stages_keep_auth_attestation_and_success_gates(self):
        workflow = (ROOT / ".github/workflows/publish-images.yml").read_text()
        for job, following, publisher, output in (
            ("platforms", "indexes", "Promote exact tested artifact", "promoted-${{ matrix.target }}-${{ matrix.arch }}"),
            ("indexes", "acceptance", "Publish verified platform index", "digest-${{ matrix.target }}"),
        ):
            with self.subTest(job=job):
                body = workflow.split("\n  " + job + ":\n", 1)[1].split("\n  " + following + ":\n", 1)[0]
                sequence = [body.index(fragment) for fragment in (
                    'run: install -d -m 700 "$RELEASE_SCRATCH"', "uses: actions/download-artifact@",
                    "release_registry_auth.py prepare", "release_registry_auth.py check", publisher,
                    "uses: actions/attest@", "name: " + output, "release_registry_auth.py cleanup")]
                self.assertEqual(sequence, sorted(sequence))
                self.assertIn("push-to-registry: true", body)
                self.assertIn("create-storage-record: false", body)
                self.assertIn("RUNNER_TEMP: ${{ env.RELEASE_SCRATCH }}/attest", body)
                self.assertIn("if: always()\n        run: python3 scripts/release_registry_auth.py cleanup", body)
                self.assertNotIn("continue-on-error:", body)
                self.assertNotIn("HOME:", body)
        self.assertIn("needs.platforms.result == 'success'", workflow)
        self.assertIn("needs.indexes.result == 'success'", workflow)
        self.assertIn("needs.acceptance.result == 'success'", workflow)


if __name__ == "__main__":
    unittest.main()
