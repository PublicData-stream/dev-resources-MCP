"""Validate collector acceptance selections and evidence checks without providers."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.parse

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

    def test_rustsec_pinned_catalog_resource_and_all_utf8_notices(self):
        snapshot='blake3:'+'3'*64
        uri='devres://advisory/rustsec/RUSTSEC-2026-9001/'+snapshot
        notice_uri='devres://attribution/blake3:'+'4'*64
        notice_body=('First-party synthetic RustSec fixture notice CC-BY-4.0 GHSA-synthetic-fixture 원문\n'*40)
        notice='https://fixtures.invalid/original\n'+notice_body
        subject = {'provider': 'rustsec', 'namespace': 'source', 'key': 'fixture-source', 'fingerprint': 'blake3:' + '5' * 64}
        class RustsecClient(Client):
            corrupt=False
            def __init__(self):
                super().__init__()
                self.notice_pages = []
            def attribution(self):
                return {'status':'ready', 'policy_epoch':1 if self.corrupt=='outer_epoch' else 2,
                        'policy_fingerprint':'wrong' if self.corrupt=='fingerprint' else smoke.ATTRIBUTION_POLICY_FINGERPRINT}
            def tool(self,tool,args,revision):
                if tool=='packages.crate.advisory_catalog_search':
                    return {'snapshot':{'id':snapshot},'items':[{'id':'RUSTSEC-2026-9001'}], 'attribution':dict(self.attribution(), readable_notice=notice)}
                if tool=='packages.crate.advisory_get':
                    return {'snapshot':{'id':snapshot},'resource_uri':uri,'page':{'text':'rustsecfixturebody'},
                            'attribution':dict(self.attribution(), resource_uris=[notice_uri], readable_notice=notice,
                                           generations=[{'id':notice_uri.rsplit('/',1)[-1],'subject':subject,'notices':[{'source_url':'https://fixtures.invalid/original','text':notice_body}]}])}
                return super().tool(tool,args,revision)
            def call(self,method,args,revision):
                if args.get('uri','').startswith(notice_uri):
                    parsed=urllib.parse.urlparse(args['uri']);params=urllib.parse.parse_qs(parsed.query)
                    start=int(params['offset'][0]);end=min(start+int(params['limit'][0]),len(notice.encode()))
                    while end>start:
                        try:chunk=notice.encode()[start:end].decode();break
                        except UnicodeDecodeError:end-=1
                    if self.corrupt=='text':chunk=chunk.replace('First-party','Wrong-party')
                    if self.corrupt=='no_progress':chunk='';end=start
                    self.notice_pages.append((revision, chunk))
                    return {'contents':[{'uri':notice_uri,'text':chunk,'_meta':{'offset':start,'total_bytes':len(notice.encode())+(1 if self.corrupt=='total' else 0),
                            'attribution':{'policy_epoch':1 if self.corrupt=='epoch' else 2,'subject':{} if self.corrupt=='subject' else subject,'id':'wrong' if self.corrupt=='id' else notice_uri.rsplit('/',1)[-1]},'next_offset':0 if self.corrupt is True else None if self.corrupt=='premature_final' else end if end<len(notice.encode()) else None}}]}
                if args.get('uri')==uri:
                    return {'contents':[{'text':'rustsecfixturebody','_meta':{'attribution':self.attribution(),'source_evidence':{'snapshot':{'id':snapshot}}}}, {'text':notice}]}
                return super().call(method,args,revision)
        selected=receipts()+[dict(provider='rustsec',tool='packages.crate.advisory_get',arguments={'snapshot':snapshot,'id':'RUSTSEC-2026-9001'},resource=uri,expected='rustsecfixturebody')]
        smoke.verify(RustsecClient(),self.load(selected))
        for failure in (True,'id','total','text','epoch','subject','outer_epoch','fingerprint',
                        'no_progress','premature_final'):
            broken=RustsecClient();broken.corrupt=failure
            with self.subTest(failure=failure),self.assertRaises(AssertionError):
                smoke.verify(broken,selected)
            for revision in (smoke.MODERN, smoke.LEGACY):
                broken=RustsecClient();broken.corrupt=failure
                attribution=broken.tool('packages.crate.advisory_get', {}, revision)['attribution']
                with self.subTest(failure=failure, revision=revision),self.assertRaises(AssertionError):
                    smoke.verify_rustsec_notices(broken,attribution,revision)
        required='First-party synthetic RustSec fixture notice CC-BY-4.0 GHSA-synthetic-fixture 원문\n'
        for kind in ('utf8_maximum', 'ascii_maximum', 'small'):
            notice_body=required
            if kind != 'small':
                remaining=65536-len(('https://fixtures.invalid/original\n'+notice_body).encode())
                notice_body+=('원'*(remaining//3)+'x'*(remaining%3) if kind=='utf8_maximum' else 'x'*remaining)
            notice='https://fixtures.invalid/original\n'+notice_body
            client=RustsecClient()
            smoke.verify(client,selected)
            for revision in (smoke.MODERN,smoke.LEGACY):
                pages=[chunk for actual,chunk in client.notice_pages if actual==revision]
                with self.subTest(kind=kind,revision=revision):
                    self.assertEqual(''.join(pages),notice)
                    self.assertEqual(len(pages),65 if kind=='utf8_maximum' else 64 if kind=='ascii_maximum' else 1)
        notice_body+='x'*(65537-len(notice.encode()))
        notice='https://fixtures.invalid/original\n'+notice_body
        for revision in (smoke.MODERN,smoke.LEGACY):
            oversized=RustsecClient()
            attribution=oversized.tool('packages.crate.advisory_get',{},revision)['attribution']
            with self.subTest(oversized=True,revision=revision),self.assertRaises(AssertionError):
                smoke.verify_rustsec_notices(oversized,attribution,revision)
            self.assertEqual(oversized.notice_pages,[])
        wrong=copy.deepcopy(selected);wrong[-1]['arguments']['id']='RUSTSEC-2026-9002'
        with self.assertRaises(ValueError):self.load(wrong)
