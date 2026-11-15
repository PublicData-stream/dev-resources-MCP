"""Real Python startup regressions for fallback identity and guarded execution."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / 'deploy/production/acceptance_1d76fbcc'
sys.path.insert(0, str(SOURCE))
try:
    import acceptance_common as common
    spec = importlib.util.spec_from_file_location('fallback_bootstrap_deployment', SOURCE/'deploy.py')
    deployment = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = deployment
    spec.loader.exec_module(deployment)
finally:
    sys.path.pop(0)


def private_save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


class FallbackBootstrap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='fallback-bootstrap-1d76-', dir='/tmp')
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.work = self.root/'target'
        (self.work/'command-evidence').mkdir(parents=True, mode=0o700)
        self.work.chmod(0o700)
        for name in ('acceptance_common.py', 'sitecustomize.py', 'process-launch.py', 'process-watch.py', 'deploy.py'):
            body = (SOURCE/name).read_text()
            if name == 'acceptance_common.py':
                body = body.replace("ROOT = Path('/tmp/devres-upgrade-1d76fbcc-20261115')",
                                    'ROOT = Path('+repr(str(self.root))+')')
            path = self.root/name
            path.write_text(body)
            path.chmod(0o600)
        self.probe = self.root/'bootstrap-probe.py'
        self.probe.write_text('''import importlib.util,json,os,sys
preloaded = 'acceptance_common' in sys.modules
startup_environment = os.environ.get('DEVRES_ACCEPTANCE_RUNTIME')
import acceptance_common as common
startup_cached_runtime = common.RUNTIME
spec=importlib.util.spec_from_file_location('real_deployment_bootstrap', __file__.replace('bootstrap-probe.py','deploy.py'))
deploy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)
rejection=None
if common.RUNTIME != 'fallback':
    try:
        deploy.run('fallback','a'*64)
    except RuntimeError as error:
        rejection=str(error)
print(json.dumps({'common_preloaded_by_sitecustomize':preloaded,
    'startup_environment':startup_environment,'startup_cached_runtime':startup_cached_runtime,
    'runtime':common.RUNTIME,'environment_runtime':os.environ.get('DEVRES_ACCEPTANCE_RUNTIME'),
    'version':common.VERSION,'schema':common.SCHEMA,'work':str(common.WORK),
    'probe_directory':common.IDENTITY['probe_directory'],'source_url':common.SOURCE_URL,
    'subprocess_guard_installed':getattr(__import__('subprocess').Popen,'_devres_parent_guard',False),
    'parent_identity_matches':int(os.environ['DEVRES_ACCEPTANCE_PARENT_PID'])==os.getppid(),
    'startup_guard_rejection':rejection},sort_keys=True),flush=True)
''')
        self.probe.chmod(0o600)
        self.state = {'runtime':'fallback','phase':'complete','pods':{'postgres':{}}}
        self.controller = Mock()
        self.controller.locked.side_effect = contextlib.nullcontext
        self.controller.state.side_effect = lambda: dict(self.state)
        self.controller.withdraw.side_effect = lambda: self.state.update(phase='withdrawn')
        self.supervisor = types.SimpleNamespace(private_save=private_save, parent_bound_command=common.parent_command)
        self.patches = [patch.object(common,'ROOT',self.root), patch.object(common,'WORK',self.work),
                        patch.object(common,'manifest_sources',return_value={}),
                        patch.dict(os.environ,{'DEVRES_ACCEPTANCE_RUNTIME':'target'})]
        for value in self.patches:
            value.start()

    def tearDown(self):
        for value in reversed(self.patches):
            value.stop()
        self.tmp.cleanup()

    def command(self):
        return [sys.executable,'-B',str(self.probe),'--runtime','fallback']

    def test_original_launch_reproduces_cached_target_startup_rejection(self):
        # This is the old launcher environment and actual Python/sitecustomize
        # import order. No controller or deployment operation is reached.
        result = subprocess.run(common.parent_command(self.command()),
            stdin=subprocess.DEVNULL,capture_output=True,timeout=8,env=dict(os.environ))
        self.assertEqual(result.returncode,0,result.stderr.decode())
        value = json.loads(result.stdout)
        self.assertTrue(value['common_preloaded_by_sitecustomize'])
        self.assertEqual(value['startup_environment'],'target')
        self.assertEqual(value['startup_cached_runtime'],'target')
        self.assertEqual(value['environment_runtime'],'fallback')
        self.assertEqual(value['runtime'],'target')
        self.assertEqual(value['startup_guard_rejection'],'runtime_environment_mismatch')
        self.controller.withdraw.assert_not_called()

    def test_real_fallback_child_selects_identity_before_sitecustomize(self):
        self.assertTrue(deployment.supervise_fallback(self.controller,self.supervisor,self.command(),timeout=8))
        directory = self.work/'command-evidence/deploy-fallback'
        value = json.loads((directory/'stdout.log').read_bytes())
        self.assertTrue(value['common_preloaded_by_sitecustomize'])
        self.assertEqual(value['startup_environment'],'fallback')
        self.assertEqual(value['startup_cached_runtime'],'fallback')
        self.assertEqual(value['environment_runtime'],'fallback')
        self.assertEqual(value['runtime'],'fallback')
        self.assertEqual(value['version'],'0.1.0-build.91c7bcb7')
        self.assertEqual(value['schema'],18)
        self.assertEqual(value['work'],str(self.root/'fallback'))
        self.assertEqual(value['probe_directory'],'/tmp/devres-public-probe-91c7bcb7')
        self.assertEqual(value['source_url'],'https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.91c7bcb7/source.tar.gz')
        self.assertTrue(value['subprocess_guard_installed'])
        self.assertTrue(value['parent_identity_matches'])
        self.assertIsNone(value['startup_guard_rejection'])
        self.assertEqual((directory/'stderr.log').read_bytes(),b'')
        self.assertEqual(os.environ['DEVRES_ACCEPTANCE_RUNTIME'],'target')
        self.assertEqual(common.RUNTIME,'target')
        self.controller.withdraw.assert_not_called()

    def test_failed_real_child_still_withdraws_without_changing_parent_identity(self):
        self.state['phase']='collectors_active'
        command=[sys.executable,'-B','-c','import sys;sys.exit(7)']
        with self.assertRaisesRegex(RuntimeError,'fallback_deployment_failed'):
            deployment.supervise_fallback(self.controller,self.supervisor,command,timeout=8)
        self.controller.withdraw.assert_called_once()
        self.assertEqual(self.state['phase'],'withdrawn')
        self.assertEqual(os.environ['DEVRES_ACCEPTANCE_RUNTIME'],'target')
        value=json.loads((self.work/'command-evidence/deploy-fallback/result.json').read_bytes())
        self.assertFalse(value['success'])
        self.assertTrue(value['withdrawal_completed'])
        self.assertEqual(value['exit_code'],7)

    def test_timeout_still_kills_child_and_withdraws(self):
        self.state['phase']='collectors_active'
        command=[sys.executable,'-B','-c','import time;time.sleep(30)']
        with self.assertRaisesRegex(RuntimeError,'fallback_deployment_failed'):
            deployment.supervise_fallback(self.controller,self.supervisor,command,timeout=0.2)
        self.controller.withdraw.assert_called_once()
        self.assertEqual(self.state['phase'],'withdrawn')
        self.assertEqual(os.environ['DEVRES_ACCEPTANCE_RUNTIME'],'target')
        value=json.loads((self.work/'command-evidence/deploy-fallback/result.json').read_bytes())
        self.assertFalse(value['success'])
        self.assertTrue(value['withdrawal_completed'])
        self.assertEqual(value['exit_code'],-9)


if __name__ == '__main__':
    unittest.main()
