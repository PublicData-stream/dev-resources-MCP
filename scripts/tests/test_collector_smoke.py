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
    selected = [dict(provider=p, tool=p + '.get', arguments={'snapshot': 'blake3:' + '1' * 64},
                     resource='devres://' + p + '/fixture', expected='synthetic-collector-token')
                for p in ('w3c', 'chromium')]
    selected.append(dict(provider='rfc', tool='rfc.fulltext_search',
                         arguments={'snapshot': 'blake3:' + '1' * 64,
                                    'query': 'fixturetransport', 'limit': 10},
                         resource='devres://rfc/9000/txt/blake3:' + '2' * 64,
                         expected='historicalfixturebody'))
    return selected


class Client:
    def __init__(self, *, notice=True, resource=True, snapshot=True, resource_notice=True,
                 rfc_failure=None):
        self.notice, self.resource, self.snapshot = notice, resource, snapshot
        self.resource_notice = resource_notice
        self.rfc_failure = rfc_failure
        self.calls = []

    def tool(self, tool, args, revision):
        self.calls.append((tool, revision))
        if tool == 'rfc.fulltext_search':
            pinned = 'snapshot' in args
            selected = args['snapshot'] if pinned else 'blake3:' + '3' * 64
            capture = 'blake3:' + ('2' if pinned else '4') * 64
            items = [{'number': number, 'capture': {'id': capture},
                      'excerpt': smoke.RFC_BODY} for number in (9000, 9001)]
            value = {'snapshot': selected, 'items': items, 'total': 2,
                     'coverage': {'acquisition_complete': False, 'searchable_documents': 2},
                     'next_offset': None,
                     'attribution': {'readable_notice': smoke.RFC_NOTICE}}
            if self.rfc_failure == 'pinned_notice':
                value['attribution']['readable_notice'] += 'unexpected suffix'
            if self.rfc_failure == 'partial':
                value['coverage']['acquisition_complete'] = True
            if pinned and self.rfc_failure == 'pinned_snapshot':
                value['snapshot'] = 'blake3:' + '5' * 64
            if pinned and self.rfc_failure == 'membership':
                value['items'] = list(reversed(items))
            if pinned and self.rfc_failure == 'historical_capture':
                items[0]['capture']['id'] = 'blake3:' + '5' * 64
            if pinned and self.rfc_failure == 'snippet':
                items[0]['excerpt'] = 'changed'
            if not pinned and self.rfc_failure == 'current_snapshot':
                value['snapshot'] = 'blake3:' + '1' * 64
            if not pinned and self.rfc_failure == 'current_capture':
                items[0]['capture']['id'] = 'blake3:' + '2' * 64
            if not pinned and self.rfc_failure == 'current_total':
                value['total'] = 0
            if args.get('offset') == 1:
                value['items'] = items[:1] if self.rfc_failure == 'pagination' else items[1:]
                if self.rfc_failure == 'final_page':
                    value['next_offset'] = 2
            return value
        if tool == 'rfc.format_get':
            return {'page': {'text': smoke.RFC_BODY + ('unexpected suffix' if self.rfc_failure == 'body' else '')},
                    'attribution': {'readable_notice': smoke.RFC_NOTICE + ('unexpected suffix' if self.rfc_failure == 'notice' else '')}}
        return {'selection': {'snapshot': args['snapshot'] if self.snapshot else 'changed'},
                'page': {'text': 'synthetic-collector-token'},
                'attribution': {'readable_notice': 'first-party fixture' if self.notice else ''}}

    def call(self, method, args, revision):
        self.calls.append((method, revision))
        if method == 'initialize':
            return {}
        if args.get('uri', '').startswith('devres://rfc/'):
            metadata = {
                'source_evidence': {'capture': {'id': args['uri'].rsplit('/', 1)[-1]}},
                'attribution': {'status': 'ready', 'generations': [
                    {'notices': [{'license': 'AGPL-3.0-only'}]}]},
            }
            if self.rfc_failure == 'resource_capture':
                metadata['source_evidence']['capture']['id'] = 'blake3:' + '9' * 64
            if self.rfc_failure == 'resource_qualification':
                metadata['attribution']['status'] = 'pending'
            if self.rfc_failure == 'resource_generations':
                metadata['attribution']['generations'] = []
            if self.rfc_failure == 'resource_notices':
                metadata['attribution']['generations'][0]['notices'] = []
            if self.rfc_failure == 'resource_license':
                metadata['attribution']['generations'][0]['notices'][0]['license'] = 'unexpected-license'
            if self.rfc_failure == 'resource_license_missing':
                del metadata['attribution']['generations'][0]['notices'][0]['license']
            return {'contents': [{'text': smoke.RFC_BODY + ('unexpected suffix' if self.rfc_failure == 'resource_body' else ''),
                                  '_meta': metadata},
                                 {'text': smoke.RFC_NOTICE + ('unexpected suffix' if self.rfc_failure == 'resource_notice' else '')}]}
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
        self.assertEqual(len(client.calls), 19)
        self.assertEqual(sum(name == 'rfc.fulltext_search' for name, _ in client.calls), 6)
        self.assertEqual(sum(name == 'rfc.format_get' for name, _ in client.calls), 2)
        self.assertEqual({r for _, r in client.calls}, {smoke.MODERN, smoke.LEGACY})

    def test_legacy_two_provider_receipts_remain_compatible(self):
        selected = self.load(receipts()[:2])
        client = Client()
        smoke.verify(client, selected)
        self.assertEqual(len(client.calls), 9)
        self.assertFalse(any(name.startswith('rfc.') for name, _ in client.calls))

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

    def test_rfc_pinned_partial_search_history_and_pagination_are_required(self):
        receipt = receipts()[2]
        for failure in ('partial', 'pinned_notice', 'pinned_snapshot', 'membership', 'historical_capture',
                        'snippet', 'current_snapshot', 'current_capture', 'current_total',
                        'pagination', 'final_page', 'body', 'notice'):
            with self.subTest(failure=failure), self.assertRaises(AssertionError):
                client = Client(rfc_failure=failure)
                pinned = client.tool(receipt['tool'], receipt['arguments'], smoke.MODERN)
                smoke.verify_rfc(client, receipt, pinned, smoke.MODERN)

    def test_rfc_resource_rejects_body_or_notice_suffixes(self):
        for failure in ('resource_body', 'resource_notice'):
            with self.subTest(failure=failure), self.assertRaises(AssertionError):
                smoke.verify(Client(rfc_failure=failure), receipts())

    def test_rfc_resource_requires_capture_qualified_notice_and_license_metadata(self):
        for failure in ('resource_capture', 'resource_qualification', 'resource_generations',
                        'resource_notices', 'resource_license', 'resource_license_missing'):
            with self.subTest(failure=failure), self.assertRaises(AssertionError):
                smoke.verify(Client(rfc_failure=failure), receipts())
        metadata = Client().call('resources/read', {'uri': receipts()[2]['resource']}, smoke.MODERN)['contents'][0]['_meta']
        self.assertNotIn('license', metadata)

    def test_rfc_receipt_requires_fixed_query_and_capture_resource(self):
        for field, value in (
                ('arguments', {'snapshot': 'blake3:' + '1' * 64, 'query': 'other'}),
                ('resource', 'devres://rfc/9001/txt/blake3:' + '2' * 64),
                ('resource', 'devres://rfc/9000/txt/not-a-capture'),
                ('tool', 'rfc.get')):
            selected = receipts()
            selected[2][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.load(selected)
        with self.assertRaises(ValueError):
            self.load(receipts()[:1])
        selected = receipts()
        selected[2] = copy.deepcopy(selected[0])
        with self.assertRaises(ValueError):
            self.load(selected)

    def test_oversized_receipt_is_rejected(self):
        selected = receipts()
        selected[0]['expected'] = 'x' * 65537
        with self.assertRaises(ValueError):
            self.load(selected)
