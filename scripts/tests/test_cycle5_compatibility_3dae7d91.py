"""C5 private constructor binding and inherited baseline/lifecycle contracts."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from scripts.tests import test_cycle4_acceptance_3dae7d91 as a4
from scripts.tests.test_cycle4_runtime_3dae7d91 import OperationalBaselineGate
from scripts.tests.test_cycle5_3dae7d91 import Rendering,module,r,ROOT


def setup_sources(cls):
    Rendering.setUpClass.__func__(cls)
    cls.sources={name:Path(info['local']).read_text() for name,info in cls.files.items()}


class Cycle5Baseline(OperationalBaselineGate):
    @classmethod
    def setUpClass(cls):setup_sources(cls)
    @classmethod
    def tearDownClass(cls):Rendering.tearDownClass.__func__(cls)


class Cycle5Lifecycle(a4.Lifecycle,a4.Recovery,a4.BaselineDeploymentEntry,a4.BaselineProducer,a4.SameProcessMigration):
    @classmethod
    def setUpClass(cls):setup_sources(cls)
    @classmethod
    def tearDownClass(cls):Rendering.tearDownClass.__func__(cls)


class FrozenCompatibility(Rendering):
    def setUp(self):
        self.scratch=tempfile.TemporaryDirectory(prefix='cycle5-frozen-fixture-',dir='/tmp');self.addCleanup(self.scratch.cleanup)
        self.root=Path(self.scratch.name);self.install=self.root/'install';self.install.mkdir();self.bundle=self.root/'bundle';self.bundle.mkdir()
        self.source=self.install/'upgrade-controller.py'
        body=b'''import os\nEDGE_CALLS=[]\ndef cycle4_edge_bridge():\n assert os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256']=='old-c4-env'\n return None,'original'\ndef predecessor(context):return 'standalone-legacy'\nclass Base:\n def __init__(self,bundle,plan,context):\n  self.root=bundle;self.plan=plan;self.context=context;self.prior_controller=predecessor(context)\n def boundary_guard(self):return 'base-boundary'\n def guard(self):return self.boundary_guard()\n def snapshot(self):return self.edge()\n def protected_snapshot(self):return self.edge()\n def run(self,*args):raise AssertionError('historical mutation')\n def record(self,*args):raise AssertionError('historical mutation')\nclass Controller(Base):\n def edge(self):\n  bridge,pin=cycle4_edge_bridge();return pin\n def boundary_guard(self):\n  assert super().boundary_guard()=='base-boundary'\n  bridge,pin=cycle4_edge_bridge();return pin\n def start_observer(self):raise AssertionError('historical mutation')\nPRIOR_CONTROLLER='/usr/local/libexec/devres-upgrade-91c7bcb7/upgrade-controller.py'\nPRIOR_SHA='frozen-legacy'\nPRIOR_BUNDLE='/var/lib/devres-production-upgrades/91c7bcb7-20261115'\n'''
        self.source.write_bytes(body);self.body=body
        self.edge=module('cycle5_real_readonly_edge_helper',ROOT/'deploy/production/cycle4_edge_3dae7d91.py')
        self.edge.native_guard=Mock(return_value={'edge':'current-native'})
        self.edge.load_controller=Mock(return_value='bound-legacy')
        self.edge._receipt=Mock()  # Never invoked: the source callback below is the modeled admission boundary.
        values={'C5_PREVIOUS_INSTALL':self.install,'C5_PREVIOUS_BUNDLE':self.bundle,
                'C5_PREVIOUS_CONTROLLER_SHA':hashlib.sha256(body).hexdigest()}
        patcher=patch.multiple(self.u,**values);patcher.start();self.addCleanup(patcher.stop)
        patcher=patch.object(self.u,'cycle5_source_bytes',side_effect=lambda path,*args:Path(path).read_bytes())
        patcher.start();self.addCleanup(patcher.stop)
        patcher=patch.object(self.u,'cycle5_bound_frozen_edge',return_value=(self.edge,self.u.C5_EDGE_SHA))
        self.bound=patcher.start();self.addCleanup(patcher.stop)

    def test_private_clones_keep_original_code_globals_environment_and_file(self):
        with patch.dict(os.environ,{'DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256':'new-c5-env'}):
            before=dict(os.environ);value=self.u.cycle5_previous_controller('default')
            self.assertEqual(dict(os.environ),before)
            self.assertEqual(value.guard(),self.u.C5_EDGE_SHA)
            original=sys.modules['cycle5_frozen_consumed_cycle4']
            self.assertEqual(original.__file__,str(self.source))
            self.assertEqual(original.Controller.__init__.__globals__['predecessor'].__name__,'predecessor')
            adapted=value.__class__.__bases__[0]
            self.assertIs(adapted.__init__.__code__,original.Controller.__init__.__code__)
            self.assertIs(adapted.edge.__code__,original.Controller.edge.__code__)
            self.assertIs(adapted.boundary_guard.__code__,original.Controller.boundary_guard.__code__)
            self.assertIsNot(adapted.edge.__globals__,original.Controller.edge.__globals__)
            self.assertIs(adapted.edge.__closure__,original.Controller.edge.__closure__)
            self.assertIs(adapted.boundary_guard.__closure__,original.Controller.boundary_guard.__closure__)
            self.assertIsNotNone(adapted.boundary_guard.__closure__)  # Zero-argument super keeps its original class cell.
            self.assertEqual(adapted.edge.__globals__['__file__'],str(self.source))
            self.assertEqual(value.prior_controller,'bound-legacy')
            for operation in ('run','record','start_observer'):
                with self.assertRaisesRegex(RuntimeError,'historical_facade_is_read_only'):getattr(value,operation)('forbidden')
        # The original module and its standalone behavior were never rebound.
        with patch.dict(os.environ,{'DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256':'old-c4-env'}):
            untouched=original.Controller('old-root','old-plan','default')
            self.assertEqual(untouched.guard(),'original')
            self.assertEqual(untouched.prior_controller,'standalone-legacy')
        self.assertEqual(self.source.read_bytes(),self.body)

    def test_bad_source_native_drift_or_dependency_guard_prevents_constructor(self):
        self.edge.native_guard.side_effect=RuntimeError('new_native_edge_changed')
        with patch.object(self.u.importlib.util,'spec_from_file_location') as loader:
            with self.assertRaisesRegex(RuntimeError,'new_native_edge_changed'):self.u.cycle5_previous_controller('default')
            loader.assert_not_called()
        self.edge.native_guard.side_effect=None
        with patch.object(self.u,'cycle5_bound_frozen_edge',side_effect=RuntimeError('fixed_cycle4_source_changed')),patch.object(self.u.importlib.util,'spec_from_file_location') as loader:
            with self.assertRaisesRegex(RuntimeError,'fixed_cycle4_source_changed'):self.u.cycle5_previous_controller('default')
            loader.assert_not_called()
        self.source.write_bytes(b'changed')
        with patch.object(self.u.importlib.util,'spec_from_file_location') as loader:
            with self.assertRaisesRegex(RuntimeError,'fixed_cycle4_controller'):self.u.cycle5_previous_controller('default')
            loader.assert_not_called()


class HistoricalClosure(Rendering):
    """Hash-reader fixtures exercise the exact union algorithm, not live authority."""
    def setUp(self):
        self.work=Path('/tmp/frozen-cycle4-source-fixture')
        self.install=Path('/usr/local/libexec/frozen-cycle4-source-fixture')
        self.bodies={};self.manifest={}
        for name in (*self.u.HISTORY_SPECIAL_NAMES['cycle4'],*self.u.HISTORY_SOURCE_NAMES['cycle4']):
            body=('# source-bound fixture '+name).encode();path=(self.install if name in self.u.C5_SPECIAL_NAMES else self.work)/name
            self.bodies[path]=body;self.manifest[name]=hashlib.sha256(body).hexdigest()
        self.previous={f'/usr/local/libexec/historical-{i}.py':hashlib.sha256(f'old-{i}'.encode()).hexdigest() for i in range(29)}
        self.bodies.update({Path(name):f'old-{i}'.encode() for i,name in enumerate(self.previous)})
        public=json.dumps({'dependency_sources':self.previous},sort_keys=True).encode()
        manifest=json.dumps(self.manifest,sort_keys=True).encode()
        self.bodies[self.work/'source-manifest.json']=manifest
        self.bodies[self.work/'public-upgrade-identity.json']=public
        values={'C5_PREVIOUS_WORK':self.work,'C5_PREVIOUS_INSTALL':self.install,
            'C5_PREVIOUS_CONTROLLER_SHA':self.manifest['upgrade-controller.py'],
            'C5_PREVIOUS_MANIFEST_SHA':hashlib.sha256(manifest).hexdigest(),
            'C5_PREVIOUS_PUBLIC_SHA':hashlib.sha256(public).hexdigest()}
        p=patch.multiple(self.u,**values);p.start();self.addCleanup(p.stop)
        p=patch.object(self.u,'cycle5_source_bytes',side_effect=lambda path,*args:self.bodies[Path(path)])
        p.start();self.addCleanup(p.stop)
        self.bridge=SimpleNamespace(__file__=str(self.install/'edge-readmission.py'),native_guard=Mock())
        p=patch.object(self.u,'cycle4_edge_bridge',return_value=(self.bridge,self.u.C5_EDGE_SHA))
        p.start();self.addCleanup(p.stop)

    def test_full29_and_exact37_are_verified_before_frozen_constructor(self):
        manifest,deps=self.u.cycle5_historical_closure()
        self.assertEqual(manifest,self.manifest);self.assertEqual(len(deps),37)
        self.assertTrue(self.previous.items()<=deps.items())
        self.assertEqual(self.u.cycle5_bound_frozen_edge(),(self.bridge,self.u.C5_EDGE_SHA))
        self.bodies[self.install/'edge-qualification.py']=b'unadmitted source'
        with patch.object(self.u.importlib.util,'spec_from_file_location') as constructor:
            with self.assertRaisesRegex(RuntimeError,'fixed_cycle4_source_changed'):self.u.cycle5_previous_controller('default')
            constructor.assert_not_called();self.bridge.native_guard.assert_not_called()

    def test_corrupt_historical_dependency_or_unlisted38th_or_receipt_refuses_before_import(self):
        old=next(iter(self.previous));original=self.bodies[Path(old)]
        self.bodies[Path(old)]=b'changed dependency'
        with patch.object(self.u.importlib.util,'spec_from_file_location') as constructor:
            with self.assertRaisesRegex(RuntimeError,'historical_dependency_changed'):self.u.cycle5_previous_controller('default')
            constructor.assert_not_called()
        self.bodies[Path(old)]=original
        with patch.object(self.u,'cycle4_edge_bridge',return_value=(self.bridge,'0'*64)),patch.object(self.u.importlib.util,'spec_from_file_location') as constructor:
            with self.assertRaisesRegex(RuntimeError,'fixed_reused_edge'):self.u.cycle5_previous_controller('default')
            constructor.assert_not_called()
        extra={**self.previous,'/usr/local/libexec/unlisted-38th.py':'0'*64}
        raw=json.dumps({'dependency_sources':extra},sort_keys=True).encode()
        self.bodies[self.work/'public-upgrade-identity.json']=raw
        with patch.object(self.u,'C5_PREVIOUS_PUBLIC_SHA',hashlib.sha256(raw).hexdigest()),patch.object(self.u.importlib.util,'spec_from_file_location') as constructor:
            with self.assertRaisesRegex(RuntimeError,'fixed_cycle4_dependencies'):self.u.cycle5_previous_controller('default')
            constructor.assert_not_called()


if __name__=='__main__':unittest.main()
