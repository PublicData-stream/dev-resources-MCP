"""Verify the generated assessment against the exact candidate helper."""

import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest

from deploy.production.cycle6_assessment_ce5745e0 import (
    ASSESSMENT_HELPER_PATH,
    ASSESSMENT_HELPER_SHA256,
    patch_assessment,
)
from scripts.tests.test_cycle4_assessment_3dae7d91 import backend_template
from scripts.tests.test_cycle5_3dae7d91 import r as fifth_renderer


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = 'ce5745e0a0a5914dad62cd24f8655276b6f780ce'


class AssessmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix='cycle6-assessment-', dir='/tmp')
        cls.addClassCleanup(directory.cleanup)
        closure = fifth_renderer.render(
            Path(directory.name) / 'closure',
            fifth_renderer.PREVIOUS_CONTROLLER_SHA,
            fifth_renderer.PREVIOUS_MANIFEST_SHA,
        )
        cls.predecessor = Path(closure['npm-recovery.py']['local']).read_text()
        cls.candidate_helper = subprocess.check_output(
            ['git', 'show', f'{CANDIDATE}:{ASSESSMENT_HELPER_PATH}'], cwd=ROOT,
        )
        cls.predecessor_helper = Path(closure[ASSESSMENT_HELPER_PATH]['local']).read_bytes()

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='cycle6-helper-', dir='/tmp')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.helper = self.root / ASSESSMENT_HELPER_PATH
        self.helper.parent.mkdir(parents=True)
        self.manifest = self.root / 'source-manifest.json'
        self.stage_helper(self.candidate_helper)

    def stage_helper(self, body, manifest_hash=None):
        self.helper.write_bytes(body)
        self.manifest.write_text(json.dumps({
            ASSESSMENT_HELPER_PATH: manifest_hash or hashlib.sha256(body).hexdigest(),
        }))

    def generated(self, source):
        module = ModuleType('cycle6_generated_assessment_test')
        filename = str(self.root / 'npm-recovery.py')
        exec(compile(source, filename, 'exec', dont_inherit=True), module.__dict__)
        module.WORK = self.root
        return module

    def test_generated_candidate_pod_changes_only_startup_connection_option(self):
        # Compare both invocations using the exact same helper and template.
        # The old frozen helper is checked separately by the admission test.
        prior = self.generated(self.predecessor)
        target = self.generated(patch_assessment(self.predecessor))
        self.addCleanup(sys.modules.pop, 'cycle4_exact_maintained_assessment', None)
        self.addCleanup(sys.modules.pop, 'cycle6_exact_maintained_assessment', None)
        template = backend_template()
        image = 'registry.example/server@sha256:' + 'a' * 64
        template['spec']['containers'][0]['image'] = image
        old_pod = prior.assessment_pod(template, image)
        pod = target.assessment_pod(template, image)
        container = pod['spec']['containers'][0]
        wrapper = container['command'][-1]
        cli = [shlex.split(line) for line in wrapper.splitlines()
               if line.startswith('set -- /usr/local/bin/devres-server ')]
        self.assertEqual(len(cli), 1)
        self.assertEqual(cli[0][3:5], ['recover-collection', 'dry-run'])
        self.assertEqual(cli[0][-2:], ['--connect-readiness', 'wait'])
        self.assertEqual(wrapper.count('--connect-readiness'), 1)
        self.assertEqual(container['command'][:-1],
                         ['/usr/bin/timeout', '--signal=TERM', '--kill-after=5s', '420s',
                          '/bin/sh', '-c'])
        self.assertEqual(pod['spec']['activeDeadlineSeconds'], 450)
        self.assertEqual(pod['spec']['restartPolicy'], 'Never')
        self.assertNotIn('--connect-readiness', old_pod['spec']['containers'][0]['command'][-1])
        container['command'][-1] = wrapper.replace(' --connect-readiness wait', '')
        self.assertEqual(pod, old_pod)
        self.assertEqual(target.assessment_network_policies(), prior.assessment_network_policies())

    def test_requires_candidate_helper_and_matching_manifest_before_loading(self):
        self.assertEqual(hashlib.sha256(self.candidate_helper).hexdigest(), ASSESSMENT_HELPER_SHA256)
        target = self.generated(patch_assessment(self.predecessor))
        self.addCleanup(sys.modules.pop, 'cycle6_exact_maintained_assessment', None)
        self.assertIn('sql_connect_retry', target.maintained().PHASES)
        for body, manifest_hash in ((self.predecessor_helper, None), (self.candidate_helper, '0' * 64)):
            with self.subTest(manifest_hash=manifest_hash):
                self.stage_helper(body, manifest_hash)
                with self.assertRaisesRegex(RuntimeError, 'assessment_helper_source_changed'):
                    target.maintained()

    def test_refuses_missing_duplicate_and_already_applied_anchors(self):
        missing = self.predecessor.replace('pod=helper.build_assessment_pod(', 'pod=build_pod(')
        duplicate = self.predecessor + next(
            line for line in self.predecessor.splitlines(keepends=True)
            if 'pod=helper.build_assessment_pod(' in line
        )
        for source in (missing, duplicate, patch_assessment(self.predecessor)):
            with self.subTest(), self.assertRaisesRegex(RuntimeError, 'exact_cycle5_assessment_source_required'):
                patch_assessment(source)
