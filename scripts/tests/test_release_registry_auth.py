"""Disposable filesystem/client tests for isolated release authentication."""
import base64
import errno
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
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
ENCODED = base64.b64encode(("fixture-actor:" + TOKEN).encode()).decode()


class Interrupted(BaseException):
    """Model abrupt process loss rather than a handled preparation failure."""


class RegistryAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-registry-auth-test.")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner_home = self.root / "runner-home"
        self.runner_home.mkdir(mode=0o755)
        self.runner_config = self.runner_home / ".docker/config.json"
        self.scratch = self.root / "release"
        self.scratch.mkdir(mode=0o700)
        self.private = self.scratch / "auth"
        self.isolated_home = self.private / "home"
        self.config = self.isolated_home / ".docker/config.json"
        self.marker = self.private / "state.json"
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
client = Path(sys.argv[0]).name
with open(os.environ["TEST_LOG"], "a") as output:
    output.write(json.dumps({{"client": client, "args": sys.argv[1:],
        "stdin_ok": token == {TOKEN!r},
        "token_env": any(key in os.environ for key in
            ("REGISTRY_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "DOCKER_AUTH_CONFIG")),
        "home": os.environ.get("HOME"), "docker": os.environ.get("DOCKER_CONFIG"),
        "registry": os.environ.get("REGISTRY_AUTH_FILE")}}) + "\\n")
if os.environ.get("FAIL_CLIENT") == client:
    print("untrusted-client-output:" + token, file=sys.stderr)
    sys.exit(19)
path = (Path(os.environ["DOCKER_CONFIG"]) / "config.json" if client == "docker"
        else Path(os.environ["REGISTRY_AUTH_FILE"]))
if client == "docker" and json.loads(path.read_text()) != {{"auths": {{"ghcr.io": {{}}}}}}:
    print("Docker inline-store seed is missing", file=sys.stderr)
    sys.exit(23)
if os.environ.get("MALFORMED_CLIENT") == client:
    path.write_text("untrusted-config:" + token)
else:
    path.write_text(json.dumps({{"auths": {{"ghcr.io": {{"auth": base64.b64encode(
        ("fixture-actor:" + token).encode()).decode()}}}}}}))
if os.environ.get("PUBLIC_CLIENT") == client:
    path.chmod(0o644)
''')
            client.chmod(0o755)
        self.environment = patch.dict(os.environ, {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "HOME": str(self.runner_home), "REGISTRY_TOKEN": TOKEN,
            "GH_TOKEN": TOKEN, "GITHUB_TOKEN": TOKEN, "DOCKER_AUTH_CONFIG": TOKEN,
            "TEST_LOG": str(self.log),
            "DOCKER_CONFIG": str(self.config.parent),
            "REGISTRY_AUTH_FILE": str(self.private / "registry-auth.json"),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.manager = auth.RegistryAuth(self.scratch)

    def prepare(self):
        self.manager.prepare(TOKEN, "fixture-actor")

    def original(self):
        self.runner_config.parent.mkdir(mode=0o755, exist_ok=True)
        self.runner_config.write_text('{"auths":{"unrelated.example":{"auth":"fixture"}}}\n')
        self.runner_config.chmod(0o640)
        return self.runner_config.read_bytes(), self.runner_config.stat()

    def assert_original(self, content, before):
        after = self.runner_config.stat()
        self.assertEqual(self.runner_config.read_bytes(), content)
        self.assertEqual((after.st_ino, after.st_dev, after.st_mode, after.st_uid, after.st_mtime_ns),
                         (before.st_ino, before.st_dev, before.st_mode, before.st_uid, before.st_mtime_ns))

    def assert_sanitized(self, output):
        for forbidden in (TOKEN, ENCODED, "untrusted-client-output", "untrusted-config"):
            self.assertNotIn(forbidden, output)

    def cli(self, operation, **overrides):
        environment = {**os.environ, "GITHUB_ACTIONS": "true",
                       "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_ACTOR": "fixture-actor",
                       "RELEASE_SCRATCH": str(self.scratch), **overrides}
        return subprocess.run([sys.executable, str(SCRIPT), operation], env=environment,
                              capture_output=True, text=True, timeout=10, check=False)

    def test_login_stdin_isolated_paths_and_private_files(self):
        self.prepare()
        self.manager.check()
        self.assertFalse(self.config.is_symlink())
        self.assertEqual(json.loads(self.config.read_text())["auths"]["ghcr.io"]["auth"], ENCODED)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual({call["client"] for call in calls}, {"docker", "skopeo"})
        for call in calls:
            self.assertEqual(call["args"], ["login", "--username", "fixture-actor", "--password-stdin", "ghcr.io"])
            self.assertTrue(call["stdin_ok"])
            self.assertFalse(call["token_env"])
            self.assertEqual(call["home"], str(self.runner_home))
            self.assertEqual(call["docker"], str(self.config.parent))
            self.assertEqual(call["registry"], str(self.private / "registry-auth.json"))
        for directory in (self.private, self.isolated_home, self.config.parent, self.manager.attest):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for config in (self.config, self.manager.registry, self.marker):
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.runner_config.parent.exists())
        self.manager.cleanup()
        self.manager.cleanup()
        self.assertFalse(self.private.exists())
        self.assertEqual(os.environ["HOME"], str(self.runner_home))

    def test_existing_runner_config_and_oci_digest_artifacts_are_untouched(self):
        content, before = self.original()
        retained = []
        for name in ("oci-images", "promoted", "digests"):
            directory = self.scratch / name
            directory.mkdir()
            artifact = directory / "tested-artifact"
            artifact.write_bytes(b"retain tested artifact")
            retained.append(artifact)
        self.prepare()
        self.assert_original(content, before)
        self.manager.cleanup()
        self.assert_original(content, before)
        for artifact in retained:
            self.assertEqual(artifact.read_bytes(), b"retain tested artifact")

    def test_missing_or_unsafe_runner_home_never_needs_inspection(self):
        for mode in ("missing", "writable", "symlink"):
            with self.subTest(mode=mode):
                candidate = self.root / ("home-" + mode)
                if mode == "writable":
                    candidate.mkdir(mode=0o777)
                    candidate.chmod(0o777)
                elif mode == "symlink":
                    candidate.symlink_to(self.runner_home, target_is_directory=True)
                with patch.dict(os.environ, {"HOME": str(candidate)}), patch.object(
                        auth.Path, "home", side_effect=AssertionError("runner home must not be read")):
                    self.prepare()
                    self.manager.check()
                    self.manager.cleanup()
                if mode == "missing":
                    self.assertFalse(candidate.exists())
                elif mode == "writable":
                    self.assertEqual(candidate.stat().st_mode & 0o777, 0o777)
                else:
                    self.assertTrue(candidate.is_symlink())

    def test_symlinked_runner_config_and_docker_parent_are_untouched(self):
        external = self.root / "external"
        external.mkdir()
        target = external / "config.json"
        target.write_text("retain")
        self.runner_config.parent.symlink_to(external, target_is_directory=True)
        self.prepare()
        self.manager.cleanup()
        self.assertTrue(self.runner_config.parent.is_symlink())
        self.assertEqual(target.read_text(), "retain")
        self.runner_config.parent.unlink()
        self.runner_config.parent.mkdir()
        self.runner_config.symlink_to(target)
        self.prepare()
        self.manager.cleanup()
        self.assertTrue(self.runner_config.is_symlink())
        self.assertEqual(target.read_text(), "retain")

    def test_replaced_runner_config_during_auth_is_not_restored_or_deleted(self):
        self.original()
        self.prepare()
        self.runner_config.unlink()
        self.runner_config.write_text("external replacement")
        self.manager.cleanup()
        self.assertEqual(self.runner_config.read_text(), "external replacement")

    def test_node_discovers_credentials_from_step_scoped_home(self):
        self.prepare()
        result = subprocess.run(["node", "-e", '''
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const config = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.docker', 'config.json'), 'utf8'));
const user = Buffer.from(config.auths['ghcr.io'].auth, 'base64').toString().split(':')[0];
if (user !== 'fixture-actor') process.exit(2);
'''], env={**os.environ, "HOME": str(self.isolated_home)}, capture_output=True,
                                text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout + result.stderr, "")
        self.assertEqual(os.environ["HOME"], str(self.runner_home))
        self.manager.cleanup()

    def test_invalid_login_inputs_do_not_create_auth_state(self):
        for token, actor in (("", "fixture-actor"), (TOKEN, ""), (TOKEN, "bad\nactor")):
            with self.subTest(actor=actor), self.assertRaises(ValueError):
                self.manager.prepare(token, actor)
        self.assertFalse(self.private.exists())
        self.assertFalse(self.log.exists())

    def test_client_failures_report_fixed_code_and_remove_credentials(self):
        codes = []
        for name in ("docker", "skopeo"):
            with self.subTest(client=name), patch.dict(os.environ, {"FAIL_CLIENT": name}):
                with self.assertRaises(auth.AuthFailure) as caught:
                    self.prepare()
                self.assert_sanitized(str(caught.exception))
                self.assertFalse(caught.exception.cleanup_failed)
                self.assertRegex(caught.exception.code, r"^[a-z][a-z0-9_-]*$")
                codes.append(caught.exception.code)
                self.assertFalse(self.private.exists())
        self.assertNotEqual(codes[0], codes[1])

    def test_cli_client_failures_do_not_print_client_output_or_secret(self):
        for name in ("docker", "skopeo"):
            with self.subTest(client=name):
                result = self.cli("prepare", FAIL_CLIENT=name)
                self.assertNotEqual(result.returncode, 0)
                self.assert_sanitized(result.stdout + result.stderr)
                self.assertIn("failed", result.stderr)
                self.assertIn(name, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(self.private.exists())

    def test_malformed_or_public_client_credentials_fail_preflight_and_roll_back(self):
        for variable in ("MALFORMED_CLIENT", "PUBLIC_CLIENT"):
            for name in ("docker", "skopeo"):
                with self.subTest(variable=variable, client=name), patch.dict(os.environ, {variable: name}):
                    with self.assertRaises(ValueError) as caught:
                        self.prepare()
                    self.assert_sanitized(str(caught.exception))
                    self.assertFalse(self.private.exists())

    def test_cli_reports_invalid_credentials_without_raw_contents(self):
        result = self.cli("prepare", MALFORMED_CLIENT="docker")
        self.assertNotEqual(result.returncode, 0)
        self.assert_sanitized(result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.private.exists())

    def test_symlinked_or_shared_scratch_rejected_before_login(self):
        alias = self.root / "alias"
        alias.symlink_to(self.scratch, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            auth.RegistryAuth(alias).prepare(TOKEN, "fixture-actor")
        self.scratch.chmod(0o777)
        with self.assertRaises((ValueError, OSError)):
            self.prepare()
        self.scratch.chmod(0o700)
        self.assertFalse(self.log.exists())
        self.assertFalse(self.private.exists())

    def test_scratch_must_be_a_child_of_tmp(self):
        for path in (Path("/tmp"), Path("/"), Path("relative"), self.scratch / ".." / "release"):
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                auth.RegistryAuth(path).prepare(TOKEN, "fixture-actor")
        self.assertFalse(self.log.exists())

    def test_preexisting_unmarked_auth_root_is_never_reused_or_deleted(self):
        self.private.mkdir(mode=0o700)
        unrelated = self.private / "unrelated"
        unrelated.write_text("retain")
        for operation in (self.prepare, self.manager.cleanup):
            with self.assertRaises((ValueError, OSError)):
                operation()
        self.assertEqual(unrelated.read_text(), "retain")
        self.assertFalse(self.log.exists())

    def test_symlinked_auth_root_is_never_followed(self):
        external = self.root / "external-auth"
        external.mkdir()
        target = external / "unrelated"
        target.write_text("retain")
        self.private.symlink_to(external, target_is_directory=True)
        for operation in (self.prepare, self.manager.cleanup):
            with self.assertRaises((ValueError, OSError)):
                operation()
        self.assertTrue(self.private.is_symlink())
        self.assertEqual(target.read_text(), "retain")

    def test_auth_root_replacement_is_rejected_even_with_copied_marker(self):
        self.prepare()
        retained = self.scratch / "retained-auth"
        self.private.rename(retained)
        self.private.mkdir(mode=0o700)
        shutil.copyfile(retained / "state.json", self.marker)
        self.marker.chmod(0o600)
        unrelated = self.private / "unrelated"
        unrelated.write_text("retain")
        for operation in (self.manager.check, self.manager.cleanup):
            with self.assertRaises((ValueError, OSError)):
                operation()
        self.assertEqual(unrelated.read_text(), "retain")
        self.assertTrue((retained / "home/.docker/config.json").is_file())

    def test_cleanup_rejects_unexpected_entries_before_deleting_credentials(self):
        self.prepare()
        unexpected = self.private / "unrelated"
        unexpected.write_text("retain")
        with self.assertRaises(ValueError):
            self.manager.cleanup()
        self.assertEqual(unexpected.read_text(), "retain")
        self.assertTrue(self.config.is_file())
        self.assertTrue(self.marker.is_file())
        unexpected.unlink()
        self.manager.cleanup()

    def test_cleanup_root_replaced_during_removal_preserves_replacement(self):
        self.prepare()
        original_rmtree = auth.shutil.rmtree
        retained = self.scratch / "retained-auth"
        replaced = False

        def replace_root(path, *args, **keywords):
            nonlocal replaced
            if not replaced:
                self.private.rename(retained)
                self.private.mkdir(mode=0o700)
                (self.private / "unrelated").write_text("concurrent replacement")
                replaced = True
            return original_rmtree(path, *args, **keywords)

        with patch.object(auth.shutil, "rmtree", side_effect=replace_root):
            with self.assertRaises(ValueError):
                self.manager.cleanup()
        self.assertEqual((self.private / "unrelated").read_text(), "concurrent replacement")
        self.assertTrue((retained / "state.json").is_file())

    def test_marker_corruption_and_hardlinks_prevent_cleanup(self):
        self.prepare()
        original = self.marker.read_bytes()
        for content in (b"not json", b"{}", original.replace(b'"version": 2', b'"version": 1')):
            if content == original:
                continue
            with self.subTest(content=content):
                self.marker.write_bytes(content)
                with self.assertRaises((ValueError, OSError)):
                    self.manager.cleanup()
                self.assertTrue(self.config.is_file())
        self.marker.write_bytes(original)
        linked = self.root / "linked-marker"
        os.link(self.marker, linked)
        with self.assertRaises((ValueError, OSError)):
            self.manager.cleanup()
        self.assertTrue(self.config.is_file())
        linked.unlink()
        self.manager.cleanup()

    def test_check_rejects_malformed_missing_inconsistent_and_oversized_credentials(self):
        self.prepare()
        original = self.config.read_bytes()
        for value in (b"not json", b'{"auths":{}}', b'{"auths":{"ghcr.io":{"auth":"!!"}}}',
                      b'{"auths":{"ghcr.io":{"auth":"b3RoZXI6cGFzc3dvcmQ="}}}',
                      b" " * (auth.MAX_CONFIG_BYTES + 1)):
            with self.subTest(value_size=len(value)):
                self.config.write_bytes(value)
                with self.assertRaises((ValueError, OSError)):
                    self.manager.check()
        self.config.unlink()
        with self.assertRaises((ValueError, OSError)):
            self.manager.check()
        self.config.write_bytes(original)
        self.config.chmod(0o600)
        self.manager.cleanup()

    def test_check_rejects_symlinked_credentials_without_reading_target(self):
        self.prepare()
        target = self.root / "outside-config"
        target.write_text("retain")
        self.config.unlink()
        self.config.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            self.manager.check()
        self.manager.cleanup()
        self.assertEqual(target.read_text(), "retain")

    def test_check_rejects_hardlinked_or_public_credentials(self):
        self.prepare()
        linked = self.root / "linked-credential"
        os.link(self.config, linked)
        with self.assertRaises((ValueError, OSError)):
            self.manager.check()
        linked.unlink()
        self.config.chmod(0o644)
        with self.assertRaises((ValueError, OSError)):
            self.manager.check()
        self.config.chmod(0o600)
        self.manager.cleanup()

    def test_interrupted_preparation_before_credentials_is_recoverable(self):
        original_save = self.manager._save

        def interrupted(state):
            original_save(state)
            raise Interrupted()

        with patch.object(self.manager, "_save", side_effect=interrupted):
            with self.assertRaises(Interrupted):
                self.prepare()
        self.assertTrue(self.marker.is_file())
        self.assertFalse(self.config.exists())
        self.assertFalse(self.log.exists())
        self.manager.cleanup()
        self.assertFalse(self.private.exists())

    def test_login_timeout_is_sanitized_and_removes_owned_state(self):
        with patch.object(auth.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                "untrusted-client-output:" + TOKEN, timeout=60, stderr=TOKEN)):
            with self.assertRaises(auth.AuthFailure) as caught:
                self.prepare()
        self.assertEqual(caught.exception.code, "docker-login")
        self.assert_sanitized(str(caught.exception))
        self.assertFalse(self.private.exists())

    def test_interrupted_preparation_after_login_is_recoverable(self):
        original_login = self.manager._login

        def interrupted(client, token, actor):
            original_login(client, token, actor)
            raise Interrupted()

        with patch.object(self.manager, "_login", side_effect=interrupted):
            with self.assertRaises(Interrupted):
                self.prepare()
        self.assertTrue(self.config.is_file())
        self.assertTrue(self.marker.is_file())
        self.manager.cleanup()
        self.manager.cleanup()
        self.assertFalse(self.private.exists())

    def test_preflight_failure_rolls_back_only_new_auth_state(self):
        with patch.object(self.manager, "check", side_effect=ValueError("untrusted-config:" + TOKEN)):
            with self.assertRaises(ValueError) as caught:
                self.prepare()
        self.assert_sanitized(str(caught.exception))
        self.assertFalse(self.private.exists())

    def test_prepare_reports_primary_and_secondary_cleanup_failure_safely(self):
        with patch.dict(os.environ, {"FAIL_CLIENT": "docker"}), patch.object(
                self.manager, "cleanup", side_effect=OSError(errno.EIO, "untrusted-config:" + TOKEN)):
            with self.assertRaises(auth.AuthFailure) as caught:
                self.prepare()
        self.assertTrue(caught.exception.cleanup_failed)
        self.assertIn("docker", caught.exception.code)
        self.assert_sanitized(str(caught.exception))
        self.assertTrue(self.marker.exists())
        self.manager.cleanup()

    def test_cleanup_interruption_before_marker_removal_is_retryable(self):
        self.prepare()
        original_unlink = auth.os.unlink

        def interrupted(path, *args, **keywords):
            if Path(path).name == "state.json":
                self.assertTrue(self.marker.is_file())
                self.assertFalse(self.config.exists())
                self.assertFalse(self.manager.registry.exists())
                raise Interrupted()
            return original_unlink(path, *args, **keywords)

        with patch.object(auth.os, "unlink", side_effect=interrupted):
            with self.assertRaises(Interrupted):
                self.manager.cleanup()
        self.assertTrue(self.marker.is_file())
        self.manager.cleanup()
        self.assertFalse(self.private.exists())

    def test_cleanup_interruption_before_credentials_removed_retains_marker(self):
        self.prepare()
        calls = []

        def interrupted(path, *args, **keywords):
            calls.append(path)
            raise Interrupted()

        with patch.object(auth.shutil, "rmtree", side_effect=interrupted):
            with self.assertRaises(Interrupted):
                self.manager.cleanup()
        self.assertTrue(calls)
        self.assertTrue(self.marker.is_file())
        self.assertTrue(self.config.is_file())
        self.manager.cleanup()
        self.assertFalse(self.private.exists())

    def test_final_empty_root_without_marker_fails_closed(self):
        self.prepare()
        original_rmdir = auth.os.rmdir

        def interrupted(path, *args, **keywords):
            if Path(path).name == "auth":
                raise Interrupted()
            return original_rmdir(path, *args, **keywords)

        with patch.object(auth.os, "rmdir", side_effect=interrupted):
            with self.assertRaises(Interrupted):
                self.manager.cleanup()
        self.assertTrue(self.private.is_dir())
        self.assertEqual(list(self.private.iterdir()), [])
        with self.assertRaises((ValueError, OSError)):
            self.manager.cleanup()
        self.assertTrue(self.private.exists())

    def test_cleanup_before_preparation_is_a_noop(self):
        self.manager.cleanup()
        self.scratch.rmdir()
        self.manager.cleanup()
        self.assertFalse(self.scratch.exists())

    def test_hosted_cli_lifecycle_preserves_runner_home_environment(self):
        content, before = self.original()
        for operation in ("prepare", "check", "cleanup"):
            result = self.cli(operation)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_sanitized(result.stdout + result.stderr)
            self.assertEqual(os.environ["HOME"], str(self.runner_home))
            self.assert_original(content, before)
        self.assertFalse(self.private.exists())

    def test_cli_reports_cleanup_failure_without_printing_recovery_contents(self):
        self.private.mkdir(mode=0o700)
        self.marker.write_text("untrusted-config:" + TOKEN)
        self.marker.chmod(0o600)
        result = self.cli("cleanup")
        self.assertNotEqual(result.returncode, 0)
        self.assert_sanitized(result.stdout + result.stderr)
        self.assertIn("cleanup", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertTrue(self.private.exists())

    def test_cli_refuses_nonhosted_preparation(self):
        result = self.cli("prepare", GITHUB_ACTIONS="false")
        self.assertNotEqual(result.returncode, 0)
        self.assert_sanitized(result.stdout + result.stderr)
        self.assertFalse(self.private.exists())
        self.assertFalse(self.log.exists())


class RegistryAuthWorkflowTests(unittest.TestCase):
    def test_both_publication_stages_keep_auth_attestation_and_success_gates(self):
        workflow = (ROOT / ".github/workflows/publish-images.yml").read_text()
        self.assertIn("/auth/home/.docker", workflow.split("\njobs:", 1)[0])
        home_entries = re.findall(r"^\s+HOME: (.+)$", workflow, re.MULTILINE)
        self.assertEqual(home_entries, ["${{ env.RELEASE_SCRATCH }}/auth/home"] * 2)
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
                attestation = body.split("uses: actions/attest@", 1)[1].split("\n      -", 1)[0]
                self.assertIn("HOME: ${{ env.RELEASE_SCRATCH }}/auth/home", attestation)
                self.assertIn("RUNNER_TEMP: ${{ env.RELEASE_SCRATCH }}/auth/attest", attestation)
                self.assertIn("push-to-registry: true", body)
                self.assertIn("create-storage-record: false", body)
                self.assertIn("if: always()\n        run: python3 scripts/release_registry_auth.py cleanup", body)
                self.assertNotIn("continue-on-error:", body)
        self.assertIn("needs.platforms.result == 'success'", workflow)
        self.assertIn("needs.indexes.result == 'success'", workflow)
        self.assertIn("needs.acceptance.result == 'success'", workflow)


if __name__ == "__main__":
    unittest.main()
