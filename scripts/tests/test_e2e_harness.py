"""Exercise cleanup against fake engines, without launching containers or clusters."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]


class CleanupTests(unittest.TestCase):
    def run_cleanup(self, kind, status):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'bin').mkdir()
            (root / 'scratch').mkdir()
            fake = '''#!/bin/bash
printf '%s\\n' "$*" >> "$CALLS"
if [[ $1 == inspect && $* == *devres.test-owner* ]]; then echo test-run; else printf 'fixture diagnostic\\n'; fi
'''
            for name in ('docker', 'minikube'):
                file = root / 'bin' / name
                file.write_text(fake)
                file.chmod(0o755)
            source = (SCRIPTS / f'test-{kind}.sh').read_text()
            functions = source[source.index('# Fixed allowlist'):source.index('trap cleanup EXIT')]
            script = '''set -uo pipefail
run_id=test-run
profile=test-run
namespace=devres-acceptance
image=supplied:test
supplied_image=$image
created=1
scratch=$ROOT/scratch
k() { minikube "$@"; }
'''+functions+f'\n(exit {status})\ncleanup\n'
            env = dict(os.environ, ROOT=str(root), CALLS=str(root / 'calls'),
                       DEVRES_E2E_DIAGNOSTICS_DIR=str(root / 'diagnostics'),
                       PATH=str(root / 'bin') + ':' + os.environ['PATH'])
            env.pop('DEVRES_TMP_ROOT', None)
            result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, status, result.stderr.decode())
            calls = (root / 'calls').read_text()
            self.assertNotIn('image rm', calls)
            self.assertFalse((root / 'scratch').exists())
            output = root / 'diagnostics' / 'test-run'
            if status:
                self.assertTrue((output / 'postgres.log').exists())
                for path in output.iterdir():
                    self.assertLessEqual(path.stat().st_size, 65536)
                self.assertNotIn('get secrets', calls)
                if kind == 'minikube':
                    self.assertTrue((output / 'pvc.txt').exists())
                    self.assertTrue((output / 'container-state.txt').exists())
                    self.assertIn('--cache-dir=' + str(root / 'scratch/kube/cache'), calls)
                    self.assertLess(calls.index('logs deploy/postgres'), calls.index('delete'))
                else:
                    self.assertLess(calls.index('logs --tail 100 test-run-postgres'), calls.index('rm -fv'))
            else:
                self.assertFalse(output.exists())

    def test_failure_diagnostics_preserve_status_and_image(self):
        for kind in ('oxibelt', 'minikube'):
            with self.subTest(kind=kind):
                self.run_cleanup(kind, 23)

    def test_success_does_not_collect(self):
        for kind in ('oxibelt', 'minikube'):
            with self.subTest(kind=kind):
                self.run_cleanup(kind, 0)

    def test_supplied_and_default_build_paths_and_kubernetes_pin(self):
        self.run_startup_paths()

    def test_minikube_startup_and_import_failures_preserve_status_and_cleanup(self):
        for phase in ('start', 'image'):
            with self.subTest(phase=phase):
                self.run_startup_paths(kinds=('minikube',), failure=phase)

    def run_startup_paths(self, kinds=('oxibelt', 'minikube'), failure=''):
        for kind in kinds:
            for supplied in (False, True):
                with self.subTest(kind=kind, supplied=supplied), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    (root / 'scripts').mkdir()
                    (root / 'bin').mkdir()
                    source = (SCRIPTS / f'test-{kind}.sh').read_text()
                    stop = 'docker network create' if kind == 'oxibelt' else 'k create namespace'
                    source = source[:source.index(stop)]
                    harness = root / 'scripts' / 'harness.sh'
                    harness.write_text(source)
                    for name in ('make-fixture.sh', 'build-harness.sh'):
                        file = root / 'scripts' / name
                        file.write_text('#!/bin/bash\nprintf "%s\\n" "' + name + ' $*" >> "$CALLS"\n')
                        file.chmod(0o755)
                    diagnostic = root / 'scripts' / 'e2e-storage.sh'
                    diagnostic.write_text('#!/bin/bash\nprintf "storage %s\\n" "$1" >> "$CALLS"\nexit 97\n')
                    diagnostic.chmod(0o755)
                    for name in ('docker', 'minikube'):
                        file = root / 'bin' / name
                        file.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\nif [[ $1 == profile ]]; then echo \'{"valid":[]}\'; fi\n'
                                        'if [[ ${3:-} == "${FAIL_PHASE:-unused}" ]]; then exit 43; fi\n')
                        file.chmod(0o755)
                    env = dict(os.environ, CALLS=str(root / 'calls'), PATH=str(root / 'bin') + ':' + os.environ['PATH'])
                    env.pop('DEVRES_KUBERNETES_VERSION', None)
                    env.pop('DEVRES_E2E_DIAGNOSTICS_DIR', None)
                    env['FAIL_PHASE'] = failure or 'unused'
                    args = ['--image', 'supplied:test'] if supplied else []
                    if kind == 'minikube':
                        args += ['--rfc-text-only', '--live']
                    result = subprocess.run(['bash', str(harness), *args], env=env, capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, 43 if failure else 0, result.stderr.decode())
                    calls = (root / 'calls').read_text()
                    self.assertEqual('build-harness.sh' in calls, not supplied)
                    if supplied:
                        self.assertIn('image inspect supplied:test', calls)
                        self.assertNotIn('image rm supplied:test', calls)
                    if kind == 'minikube':
                        self.assertIn('--kubernetes-version=v1.37.0', calls)
                        self.assertIn('storage before-minikube-start', calls)
                        if failure:
                            expected = 'minikube-start-failed' if failure == 'start' else 'minikube-import-failed'
                            self.assertIn('storage ' + expected, calls)
                            self.assertIn(' delete', calls)
                            self.assertNotIn('storage after-minikube-import', calls)
                        else:
                            self.assertIn('storage after-minikube-import', calls)
                        if supplied and failure != 'start':
                            self.assertIn('image load supplied:test', calls)

    def test_invalid_arguments(self):
        for kind in ('oxibelt', 'minikube'):
            for arguments in (['--image'], ['--unknown']):
                result = subprocess.run(['bash', str(SCRIPTS / f'test-{kind}.sh'), *arguments], capture_output=True)
                self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
