"""External service failure fence distinguishes acceptance and uncertain restore."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('service_fence',ROOT/'deploy/production/supervisor_1d76fbcc.py')
n=importlib.util.module_from_spec(s);s.loader.exec_module(n)

class Fence(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.bundle=Path(self.temp.name)
        p=patch.object(n,'BUNDLE',self.bundle);p.start();self.addCleanup(p.stop)
        from contextlib import nullcontext
        self.controller=SimpleNamespace(withdraw=Mock(),locked=nullcontext,rollback=Mock())
        self.module=SimpleNamespace(CONTROLLER=Path('/trusted/controller.py'),manifest_sources=lambda:{'upgrade-controller.py':'hash'},
            bound_module=lambda *args:SimpleNamespace(Controller=lambda *args:self.controller))

    def test_accepted_fallback_is_not_started_or_fenced_again(self):
        with patch.object(n,'state',return_value={'runtime':'fallback','phase':'complete'}):
            result=n.fence(self.module,'external')
        self.assertEqual(result,{'fenced':False,'accepted_runtime':'fallback'})
        self.controller.withdraw.assert_not_called();self.controller.rollback.assert_not_called()

    def test_consumed_restore_does_not_call_sql_or_replay_mutation(self):
        (self.bundle/'rollback-intent.json').write_text('{}')
        with patch.object(n,'state',return_value={'runtime':'target','phase':'withdrawn'}):
            result=n.fence(self.module,'external')
        self.assertTrue(result['directory_identity_reconciliation_required'])
        self.controller.withdraw.assert_not_called();self.controller.rollback.assert_not_called()

    def test_failure_before_accepted_checkpoint_only_withdraws(self):
        with patch.object(n,'state',return_value={'runtime':'target','phase':'stopped'}):
            result=n.fence(self.module,'external')
        self.assertTrue(result['pre_activation_stopped'])
        self.controller.withdraw.assert_called_once();self.controller.rollback.assert_not_called()

    def test_failed_fallback_never_initiates_another_restore(self):
        with patch.object(n,'state',return_value={'runtime':'fallback','phase':'reader_ready'}):
            result=n.fence(self.module,'external')
        self.assertFalse(result['fallback_service_accepted'])
        self.controller.withdraw.assert_called_once();self.controller.rollback.assert_not_called()

if __name__=='__main__':unittest.main()
