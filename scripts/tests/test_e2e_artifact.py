import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("e2e_artifact", Path(__file__).parents[1] / "e2e-artifact.py")
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
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
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temp:
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


if __name__ == '__main__':
    unittest.main()
