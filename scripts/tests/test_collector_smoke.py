"""Validate collector acceptance selections and evidence checks without providers."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('collector_smoke', SCRIPTS / 'collector-smoke.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
sys.path.pop(0)


def receipts():
    return [dict(provider=p, tool=p + '.get', arguments={'snapshot': 'blake3:' + '1' * 64},
                 resource='devres://' + p + '/fixture', expected='synthetic-collector-token')
            for p in ('w3c', 'chromium')]


class Client:
    def __init__(self, *, notice=True, resource=True, snapshot=True, resource_notice=True):
        self.notice, self.resource, self.snapshot = notice, resource, snapshot
        self.resource_notice = resource_notice
        self.calls = []

    def tool(self, tool, args, revision):
        self.calls.append((tool, revision))
        return {'selection': {'snapshot': args['snapshot'] if self.snapshot else 'changed'},
                'page': {'text': 'synthetic-collector-token'},
                'attribution': {'readable_notice': 'first-party fixture' if self.notice else ''}}

    def call(self, method, args, revision):
        self.calls.append((method, revision))
        if method == 'initialize':
            return {}
        return {'contents': [{'text': 'synthetic-collector-token' if self.resource else 'changed',
                              '_meta': {'license': 'AGPL-3.0-only'}}, {'text': 'first-party fixture' if self.resource_notice else ''}]}


class CollectorSmokeTests(unittest.TestCase):
    def load(self, value):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            path = Path(directory) / 'receipt.json'
            path.write_text(json.dumps(value))
            return smoke.load_receipts(path)

    def test_fixed_pinned_reads_and_notices_in_both_revisions(self):
        selected = self.load(receipts())
        client = Client()
        smoke.verify(client, selected)
        self.assertEqual(len(client.calls), 9)
        self.assertEqual({r for _, r in client.calls}, {smoke.MODERN, smoke.LEGACY})

    def test_missing_notice_changed_snapshot_or_resource_fails(self):
        for option in ('notice', 'resource', 'snapshot', 'resource_notice'):
            with self.subTest(option=option), self.assertRaises(AssertionError):
                smoke.verify(Client(**{option: False}), receipts())

    def test_rejects_unpinned_unknown_or_cross_provider_selection(self):
        for field, value in (('arguments', {}), ('tool', 'fetch'),
                             ('resource', 'devres://capture/' + '1' * 64),
                             ('expected', ''), ('provider', 'npm')):
            selected = copy.deepcopy(receipts())
            selected[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(selected)

    def test_oversized_receipt_is_rejected(self):
        selected = receipts()
        selected[0]['expected'] = 'x' * 65537
        with self.assertRaises(ValueError):
            self.load(selected)
