import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("e2e_artifact", Path(__file__).parents[1] / "e2e-artifact.py")
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.image_id = 'sha256:' + 'a' * 64
        self.edge = {'revision': artifact.OXIBELT_REVISION, 'dirty': 'clean'}
        self.calls = []

    def docker(self, *args):
        self.calls.append(args)
        if args[:2] == ('image', 'inspect'):
            return json.dumps([{'Id': self.image_id, 'Os': 'linux', 'Architecture': 'amd64'}])
        if args[:2] == ('image', 'save'):
            Path(args[3]).write_bytes(b'image archive fixture')
        if args[0] == 'run':
            return 'OxiBelt\nOXIBELT_BUILD_IDENTITY_V1=' + json.dumps(self.edge)
        return ''

    def export(self):
        artifact.export(self.directory, 'harness:test', 'linux/amd64', 'commit', 'version')

    def verify(self):
        return artifact.verify(self.directory, 'linux/amd64', 'commit', 'version')

    def mutate(self, **changes):
        path = self.directory / 'metadata.json'
        data = json.loads(path.read_text())
        data.update(changes)
        path.write_text(json.dumps(data))

    def test_roundtrip(self):
        with patch.object(artifact, 'docker', self.docker):
            self.export()
            self.assertEqual(self.verify(), 'harness:test')
        self.assertIn(('image', 'load', '--input', str(self.directory / 'image.tar')), self.calls)
        self.assertEqual(json.loads((self.directory / 'metadata.json').read_text())['oxibelt_identity'], self.edge)

    def test_corruption_rejected_before_load(self):
        with patch.object(artifact, 'docker', self.docker):
            self.export()
            (self.directory / 'image.tar').write_bytes(b'corrupt')
            self.calls.clear()
            with self.assertRaisesRegex(ValueError, 'checksum'):
                self.verify()
            self.assertEqual(self.calls, [])

    def test_metadata_rejected_before_load(self):
        for changes in ({'commit': 'other'}, {'version': 'other'}, {'platform': 'linux/arm64'},
                        {'schema_version': 2}, {'image_tag': '-bad'}, {'oxibelt_identity': []},
                        {'oxibelt_identity': {'revision': 'wrong', 'dirty': 'clean'}}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory(dir="/tmp") as temp:
                self.directory = Path(temp)
                with patch.object(artifact, 'docker', self.docker):
                    self.export()
                    self.mutate(**changes)
                    self.calls.clear()
                    with self.assertRaises(ValueError):
                        self.verify()
                    self.assertEqual(self.calls, [])

    def test_loaded_id_and_identity_must_match(self):
        with patch.object(artifact, 'docker', self.docker):
            self.export()
            self.image_id = 'sha256:' + 'b' * 64
            with self.assertRaisesRegex(ValueError, 'ID mismatch'):
                self.verify()
            self.image_id = 'sha256:' + 'a' * 64
            self.edge['extra'] = 'changed'
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                self.verify()

    def test_wrong_export_platform_and_dirty_edge(self):
        with patch.object(artifact, 'docker', self.docker):
            with self.assertRaisesRegex(ValueError, 'platform mismatch'):
                artifact.export(self.directory, 'harness:test', 'linux/arm64', 'commit', 'version')
            self.edge['dirty'] = 'dirty'
            with self.assertRaisesRegex(ValueError, 'identity'):
                self.export()
        self.assertFalse((self.directory / 'metadata.json').exists())

    def test_default_and_explicit_architecture_variants(self):
        info = json.dumps([{'Id': self.image_id, 'Os': 'linux', 'Architecture': 'arm64', 'Variant': 'v8'}])
        with patch.object(artifact, 'docker', return_value=info):
            self.assertEqual(artifact.inspect('harness:test', 'linux/arm64'), self.image_id)
            self.assertEqual(artifact.inspect('harness:test', 'linux/arm64/v8'), self.image_id)
            with self.assertRaisesRegex(ValueError, 'platform mismatch'):
                artifact.inspect('harness:test', 'linux/arm64/v7')

    def test_refuse_overwrite_and_symlinks(self):
        with patch.object(artifact, 'docker', self.docker):
            self.export()
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                self.export()
            (self.directory / 'image.tar').unlink()
            (self.directory / 'image.tar').symlink_to('/nonexistent')
            with self.assertRaisesRegex(ValueError, 'regular'):
                self.verify()

    def test_cli_stdout_is_only_tag(self):
        with patch.object(artifact, 'docker', self.docker):
            self.export()
            with patch('sys.argv', ['e2e-artifact.py', 'verify', str(self.directory), 'linux/amd64', 'commit', 'version']), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(artifact.main(), 0)
            self.assertEqual(output.getvalue(), 'harness:test\n')

    def test_image_artifact_ignores_tool_companion(self):
        companion = self.directory / "minikube"
        companion.mkdir()
        (companion / "minikube").write_bytes(b"unused tool companion")
        with patch.object(artifact, "docker", self.docker):
            self.export()
            self.assertEqual(self.verify(), "harness:test")


class MinikubeArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp", prefix="devres-minikube-test.")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / "artifact"
        self.payloads = {platform: f"fixture {platform}".encode()
                         for platform in ("linux/amd64", "linux/arm64")}
        self.digests = {platform: hashlib.sha256(value).hexdigest()
                        for platform, value in self.payloads.items()}
        pins = patch.object(artifact, "MINIKUBE_SHA256", self.digests)
        pins.start()
        self.addCleanup(pins.stop)
        self.calls = []

    def download(self, command, **kwargs):
        self.calls.append((command, kwargs))
        platform = "linux/" + command[command.index("--url") + 1].rsplit("-", 1)[1]
        Path(command[command.index("--output") + 1]).write_bytes(self.payloads[platform])
        return subprocess.CompletedProcess(command, 0)

    def acquire(self, platform="linux/amd64"):
        with patch.object(artifact.subprocess, "run", self.download):
            artifact.acquire_minikube(self.directory, platform, "commit", "version")

    def verify(self, platform="linux/amd64"):
        return artifact.verify_minikube(self.directory, platform, "commit", "version")

    def cli(self, command, platform="linux/amd64"):
        with patch("sys.argv", ["e2e-artifact.py", command, str(self.directory), platform,
                                "commit", "version"]), contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()) as error:
            status = artifact.main()
        return status, output.getvalue(), error.getvalue()

    def test_both_architectures_roundtrip_and_pinned_download_contract(self):
        for platform in self.payloads:
            with self.subTest(platform=platform):
                self.directory = self.root / platform.rsplit("/", 1)[1]
                self.acquire(platform)
                binary = self.directory / "minikube" / "minikube"
                self.assertEqual(self.verify(platform), str(binary))
                self.assertEqual(binary.read_bytes(), self.payloads[platform])
                self.assertEqual(binary.stat().st_mode & 0o111, 0)
                metadata = json.loads((binary.parent / "metadata.json").read_text())
                self.assertEqual(metadata, dict(schema_version=1, platform=platform,
                                 commit="commit", version="version", minikube_version="v1.39.0",
                                 sha256=self.digests[platform]))
                command, options = self.calls[-1]
                self.assertEqual(command[command.index("--url") + 1],
                                 "https://github.com/kubernetes/minikube/releases/download/"
                                 f"v1.39.0/minikube-linux-{platform.rsplit('/', 1)[1]}")
                self.assertEqual(command[command.index("--proto") + 1], "=https")
                self.assertEqual(command[command.index("--proto-redir") + 1], "=https")
                self.assertEqual(options["timeout"], 240)
                self.assertTrue(Path(command[-1]).is_relative_to("/tmp"))

    def test_metadata_identity_and_checked_in_digest_are_required(self):
        self.acquire()
        metadata = self.directory / "minikube" / "metadata.json"
        original = metadata.read_text()
        for key, value in (("schema_version", 2), ("platform", "linux/arm64"),
                           ("commit", "wrong"), ("version", "wrong"),
                           ("minikube_version", "v0.0.0"), ("sha256", "0" * 64)):
            with self.subTest(key=key):
                data = json.loads(original)
                data[key] = value
                metadata.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError, key):
                    self.verify()
        metadata.write_text(original)
        (metadata.parent / "minikube").write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.verify()
        data = json.loads(original)
        data["sha256"] = hashlib.sha256(b"corrupt").hexdigest()
        metadata.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "sha256"):
            self.verify()

    def test_missing_oversized_nonobject_and_malformed_metadata(self):
        with self.assertRaises(ValueError):
            self.verify()
        self.acquire()
        metadata = self.directory / "minikube" / "metadata.json"
        original = metadata.read_bytes()
        for content in (b" " * 65537, b"[]", b"{", b"\xff", b"[" * 10000):
            with self.subTest(content=content[:10]):
                metadata.write_bytes(content)
                self.assertEqual(self.cli("verify-minikube")[0], 1)
        metadata.write_bytes(original)
        (metadata.parent / "minikube").unlink()
        with self.assertRaisesRegex(ValueError, "regular"):
            self.verify()

    def test_unsupported_platform_prevents_download(self):
        with patch.object(artifact.subprocess, "run") as run:
            self.assertEqual(self.cli("acquire-minikube", "linux/386")[0], 1)
        run.assert_not_called()
        self.assertFalse(self.directory.exists())

    def test_refuse_overwrite_and_symlinks(self):
        self.acquire()
        original = (self.directory / "minikube" / "minikube").read_bytes()
        with self.assertRaisesRegex(ValueError, "overwrite"):
            self.acquire()
        self.assertEqual((self.directory / "minikube" / "minikube").read_bytes(), original)
        for filename in ("minikube", "metadata.json"):
            with self.subTest(filename=filename):
                path = self.directory / "minikube" / filename
                contents = path.read_bytes()
                path.unlink()
                path.symlink_to(self.root / "missing")
                with self.assertRaisesRegex(ValueError, "regular"):
                    self.verify()
                path.unlink()
                path.write_bytes(contents)
        linked = self.root / "linked"
        linked.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            artifact.verify_minikube(linked, "linux/amd64", "commit", "version")
        with self.assertRaisesRegex(ValueError, "symlink"):
            artifact.acquire_minikube(linked / "new", "linux/amd64", "commit", "version")
        for name in ("minikube", "metadata.json"):
            (self.directory / "minikube" / name).unlink()
        (self.directory / "minikube").rmdir()
        (self.directory / "minikube").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.verify()
        with self.assertRaisesRegex(ValueError, "overwrite"):
            self.acquire()

    def test_checksum_failure_does_not_publish_tool(self):
        with patch.object(artifact, "MINIKUBE_SHA256", {"linux/amd64": "0" * 64}):
            with self.assertRaisesRegex(ValueError, "checksum"):
                self.acquire()
        self.assertFalse((self.directory / "minikube").exists())

    def test_download_failure_and_timeout_preserve_status_without_sensitive_output(self):
        diagnostics = self.root / "diagnostics"
        for exception, expected in ((subprocess.CalledProcessError(22, ["private command"]), 22),
                                    (subprocess.TimeoutExpired(["private command"], 240), 124)):
            with self.subTest(expected=expected), \
                    patch.object(artifact.subprocess, "run", side_effect=exception), \
                    patch.dict(os.environ, DEVRES_E2E_DIAGNOSTICS_DIR=str(diagnostics)):
                status, output, error = self.cli("acquire-minikube")
                self.assertEqual(status, expected)
                self.assertEqual(output, "")
                self.assertNotIn("private", error)
                self.assertFalse((self.directory / "minikube").exists())
                diagnostic = diagnostics / "bootstrap" / "acquire-minikube.json"
                self.assertEqual(json.loads(diagnostic.read_text()), dict(
                    stage="acquire-minikube", tool="minikube", minikube_version="v1.39.0",
                    platform="linux/amd64", status=expected))
                diagnostic.unlink()
        blocked = self.root / "blocked"
        blocked.write_text("not a directory")
        with patch.dict(os.environ, DEVRES_E2E_DIAGNOSTICS_DIR=str(blocked)), \
                patch.object(artifact.subprocess, "run", side_effect=subprocess.CalledProcessError(22, [])):
            self.assertEqual(self.cli("acquire-minikube")[0], 22)

    def test_cli_stdout_and_diagnostics_do_not_follow_existing_links(self):
        with patch.object(artifact.subprocess, "run", self.download):
            self.assertEqual(self.cli("acquire-minikube"), (0, "", ""))
        self.assertEqual(self.cli("verify-minikube"),
                         (0, str(self.directory / "minikube" / "minikube") + "\n", ""))
        diagnostics = self.root / "diagnostics" / "bootstrap"
        diagnostics.mkdir(parents=True)
        private = self.root / "private"
        private.write_text("sensitive fixture")
        (diagnostics / "verify-minikube.json").symlink_to(private)
        with patch.dict(os.environ, DEVRES_E2E_DIAGNOSTICS_DIR=str(diagnostics.parent)):
            self.assertEqual(self.cli("verify-minikube")[0], 0)
        self.assertEqual(private.read_text(), "sensitive fixture")

    @contextlib.contextmanager
    def http_fixture(self, statuses):
        payload = self.payloads["linux/amd64"]
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                status = statuses[min(len(requests), len(statuses) - 1)]
                requests.append(status)
                self.send_response(status)
                self.send_header("Content-Length", str(len(payload) if status == 200 else 0))
                self.end_headers()
                if status == 200:
                    self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        real_run = subprocess.run

        def local_download(command, **kwargs):
            command = list(command)
            # Only tests substitute a local HTTP fixture; production has no URL override.
            command[command.index("--url") + 1] = f"http://127.0.0.1:{server.server_port}/tool"
            command[command.index("--proto") + 1] = "=http"
            command[command.index("--proto-redir") + 1] = "=http"
            return real_run([*command, "--retry-delay", "0.01", "--noproxy", "127.0.0.1"], **kwargs)

        try:
            with patch.object(artifact.subprocess, "run", local_download):
                yield requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_real_curl_recovers_transient_504(self):
        with self.http_fixture([504, 200]) as requests:
            self.assertEqual(self.cli("acquire-minikube"), (0, "", ""))
        self.assertEqual(requests, [504, 200])
        self.verify()

    def test_real_curl_exhaustion_and_permanent_failure(self):
        for status, attempts in ((504, 5), (404, 1)):
            with self.subTest(status=status), self.http_fixture([status]) as requests:
                self.assertEqual(self.cli("acquire-minikube")[0], 22)
                self.assertEqual(requests, [status] * attempts)
                self.assertFalse((self.directory / "minikube").exists())


if __name__ == '__main__':
    unittest.main()
