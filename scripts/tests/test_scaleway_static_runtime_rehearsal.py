"""Offline inert-rendering checks. No Docker, database, keys or provider traffic."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import tomllib
import unittest
from urllib.parse import urlsplit
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'scaleway-static-runtime-rehearsal.py'
spec = importlib.util.spec_from_file_location('rotation_rehearsal', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SCOPE = '1234567890abcdef12345678'


class RehearsalTests(unittest.TestCase):
    def test_frozen_configs_disable_all_sources_and_expose_no_ports_or_admin_keys(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            # Rendering invariants assume the separate frozen-library gate was admitted.
            with patch.object(module, 'verify_libraries', return_value=None) as admission:
                root = module.render(Path(temporary) / 'candidate', SCOPE)
            admission.assert_called_once_with()
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            for path in root.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            for role in ('writer', 'serving'):
                config = tomllib.loads((root / f'{role}.toml.example').read_text())
                for provider in module.production().PROVIDERS:
                    self.assertFalse(config[provider]['enabled'])
                self.assertFalse(config['npm']['advisories_enabled'])
                self.assertEqual(config['storage']['s3']['prefix'], f'production/.acceptance/runtime-{SCOPE}')
                self.assertEqual(config['storage']['s3']['credentials']['mode'], 'files')
            for phase in ('temporary', 'final'):
                compose = json.loads((root / f'compose-{phase}.json').read_text())
                for name, service in compose['services'].items():
                    self.assertEqual(service['scale'], 0)
                    self.assertEqual(service['profiles'], ['explicit-rehearsal'])
                    self.assertNotIn('ports', service)
                    self.assertIn('@sha256:', service['image'])
                    if name != 'postgres':
                        self.assertEqual(service['image'], module.production().SERVER)
                        self.assertEqual(service['user'], '65532:65532')
                        keys = [x for x in service['volumes'] if '/keys/' in x]
                        self.assertEqual(len(keys), 1)
                        self.assertIn(f'/{phase}-{name}:', keys[0])
                        self.assertTrue(keys[0].endswith(':ro'))
                        self.assertEqual(service['environment']['TMPDIR'], '/tmp/work')
            postgres = compose['services']['postgres']
            self.assertEqual(postgres['environment']['POSTGRES_USER'], 'postgres')
            self.assertEqual(postgres['environment']['POSTGRES_DB'], 'postgres')
            self.assertIn(f'{root}/private/postgres-admin-password:/run/fixture-db/password:ro', postgres['volumes'])
            self.assertIn(f'{root}/private/postgres-init.sql:/run/init.sql:ro', postgres['volumes'])
            for role in ('writer', 'serving'):
                self.assertFalse(any('postgres-admin-password' in x or '/run/init.sql' in x
                                     for x in compose['services'][role]['volumes']))
                config = tomllib.loads((root / f'{role}.toml.example').read_text())
                self.assertEqual(urlsplit(config['storage']['database_url']).username,
                                 'devres_rotation_writer' if role == 'writer' else 'devres_rotation_reader')
            self.assertFalse((root / 'private').exists())
            self.assertFalse((root / 'postgres').exists())

    def test_readers_have_distinct_empty_cache_names_and_same_private_publication_state(self):
        final = tomllib.loads(module.seed(SCOPE, 'read', 'final'))
        after = tomllib.loads(module.seed(SCOPE, 'read', 'final', 'postrevocation'))
        writer = tomllib.loads(module.seed(SCOPE, 'write', 'temporary'))
        self.assertNotEqual(final['cache_dir'], after['cache_dir'])
        self.assertNotEqual(final['cache_dir'], writer['cache_dir'])
        self.assertEqual(final['state_dir'], writer['state_dir'])
        self.assertEqual(final['s3']['prefix'], writer['s3']['prefix'])
        self.assertNotEqual(final['s3']['credentials']['access_key_file'], writer['s3']['credentials']['access_key_file'])

    def test_changed_sdk_refuses_before_creating_any_candidate(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary) / 'candidate'
            with patch.object(module, 'verify_libraries', side_effect=ValueError('changed SDK')):
                with self.assertRaises(ValueError):
                    module.render(root, SCOPE)
            self.assertFalse(root.exists())

    @patch.object(module, 'verify_libraries', return_value=None)
    def test_unsafe_paths_refuse_after_library_admission(self, admission):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root = Path(temporary) / 'candidate'
            for scope in ('bad', 'A' * 24, '../production'):
                with self.assertRaises(ValueError):
                    module.render(root, scope)
                self.assertFalse(root.exists())
            alias = Path(temporary) / 'alias'
            alias.symlink_to(temporary, target_is_directory=True)
            with self.assertRaises(ValueError):
                module.render(alias / 'candidate', SCOPE)
            os.chmod(temporary, 0o770)
            with self.assertRaises(ValueError):
                module.render(root, SCOPE)
            self.assertFalse(root.exists())
            self.assertTrue(admission.called)

    def test_real_git_guard_accepts_exact_revision_and_refuses_library_change_before_render(self):
        # A disposable repository tests the real guard independently of this checkout's
        # intentional post-release changes. No production hashes or guard code change.
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            repository = Path(temporary) / 'repository'
            repository.mkdir(mode=0o700)
            manifest = repository / 'crates/adapters/Cargo.toml'
            manifest.parent.mkdir(parents=True)
            manifest.write_text('[package]\nname = "synthetic-sdk"\nversion = "0.0.0"\n')
            source = repository / 'crates/adapters/src/lib.rs'
            source.parent.mkdir()
            source.write_text('// Original synthetic library.\n')
            git = ['git', '-C', str(repository)]
            subprocess.run(git + ['init', '-q'], check=True)
            subprocess.run(git + ['add', '.'], check=True)
            subprocess.run(git + ['-c', 'user.name=Fixture',
                                 '-c', 'user.email=fixture@example.invalid',
                                 'commit', '--no-gpg-sign', '-qm', 'synthetic baseline'], check=True)
            revision = subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip()
            release = module.production()
            output = Path(temporary) / 'candidate'
            with patch.object(module, 'ROOT', repository), \
                    patch.object(module, 'production', return_value=release), \
                    patch.object(release, 'REVISION', revision):
                module.verify_libraries()
                source.write_text('// Changed synthetic library.\n')
                with self.assertRaises(subprocess.CalledProcessError):
                    module.render(output, SCOPE)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
