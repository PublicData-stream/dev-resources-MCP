"""This exact schema18 incident must stay legacy; never fabricate rearm authority."""
import importlib.util
import copy
import json
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('npm_rollout',ROOT/'deploy/production/npm_recovery_1d76fbcc.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)

class Recovery(unittest.TestCase):
    def test_only_exact_migrated_non_authoritative_revision_is_admitted(self):
        value={'job_id':n.JOB,'revision':1,'authoritative':False}
        with patch.object(n,'sql',return_value=[value]):self.assertEqual(n.selection(object()),value)
        for rows in ([],[{**value,'revision':2}],[{**value,'authoritative':True}],[{**value,'job_id':'blake3:'+'1'*64}],[value,value]):
            with self.subTest(rows=rows),patch.object(n,'sql',return_value=rows):
                with self.assertRaisesRegex(RuntimeError,'exact_migrated_legacy_incident_required'):n.selection(object())

    def test_sealed_legacy_report_is_deferred_without_recovery(self):
        value={'job_id':n.JOB,'revision':1,'eligible':False,'reason':'legacy_unknown','recipe':'npm-materialization-deadline-v1'}
        self.assertEqual(n.validate_report(value)['reason'],'legacy_unknown')
        for change in ({'eligible':True},{'reason':'evidence_not_verified'},{'recipe':'new'},{'revision':2}):
            with self.subTest(change=change),self.assertRaisesRegex(RuntimeError,'sealed_legacy_ineligibility_required'):
                n.validate_report({**value,**change})

class Cleanup(unittest.TestCase):
    def test_lost_create_scheduled_node_selector_is_reconciled_with_uid_delete(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root=Path(directory)
            expected={'spec':{'containers':[{'image':'pinned','command':['dry-run'],'volumeMounts':[]}],
                'nodeSelector':{'kubernetes.io/hostname':'node'},'volumes':[{'name':'config','secret':{'secretName':'reader'}}],
                'securityContext':{'runAsUser':65532},'serviceAccountName':'devres-serving'}}
            (root/'npm-assessment-pod-admission.json').write_text(json.dumps({'name':n.POD,'pod':expected}))
            current=copy.deepcopy(expected)
            current['metadata']={'name':n.POD,'uid':'owned-uid','labels':{'app':'backend','devres-rollout':'1d76fbcc-assessment'}}
            current['spec']['nodeName']='node'
            current['spec']['volumes'][0]['secret']['defaultMode']=288
            k=Mock(side_effect=[json.dumps({'items':[current]}).encode(),b'{}',b''])
            c=SimpleNamespace(root=root,old=SimpleNamespace(k=k,settings=lambda:{'node_name':'node'}))
            api=SimpleNamespace(load=lambda path:json.loads(path.read_text()),encoded=lambda value:json.dumps(value).encode())
            with patch('importlib.import_module',return_value=api):n.cleanup(c)
            deletion=k.call_args_list[1]
            self.assertEqual(json.loads(deletion.kwargs['data'])['preconditions'],{'uid':'owned-uid'})
            self.assertEqual(deletion.args[:2],('delete','--raw'))

if __name__=='__main__':unittest.main()
