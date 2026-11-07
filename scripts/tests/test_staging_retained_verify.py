"""Fixed restored content and complete notice readback; synthetic fixtures only."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
from urllib.parse import urlsplit, urlparse, parse_qs

spec=importlib.util.spec_from_file_location('staging_retained',Path(__file__).resolve().parents[1]/'staging-retained-verify.py')
mdn=importlib.util.module_from_spec(spec);spec.loader.exec_module(mdn)
m=mdn

class MdnFixtures(unittest.TestCase):
    def setUp(self):
        self.legacy, self.projection = 'a' * 64, 'b' * 64
        self.canonical, self.canonical_projection = 'blake3:' + 'c' * 64, 'blake3:' + 'd' * 64
        value = {'path': 'files/en-us/fixture/index.md', 'oid': 'fixture-source-oid', 'source_url': 'https://example.invalid/fixture',
                 'gaps': [], 'license': {'fixture': True}, 'provenance': {'revision': 'fixture-revision'},
                 'page': {'offset': 0, 'next_offset': None, 'total_bytes': 7}}
        text = copy.deepcopy(value)
        text.update(representation='text')
        text['page']['text'] = 'fixture'
        raw = copy.deepcopy(value)
        raw.update(representation='bytes')
        raw['page']['data'] = 'Zml4dHVyZQ=='
        item = {'path': value['path'], 'slug': 'Fixture', 'title': 'Fixture', 'snippet': 'fixture', 'kind': 'article', 'metadata': {}}
        revision = {'text': text, 'bytes': raw, 'search': {'results': [item]},
                    'history': {'history_snapshot': 'frozen-fixture-cutoff', 'results': [{'id': self.legacy}]}}
        self.before = {'snapshot': self.legacy, 'projection': self.projection, 'path': value['path'],
                       'revisions': {r: copy.deepcopy(revision) for r in ('2026-07-28', '2025-11-25')}}
        self.damage = None
        self.notice_id = 'blake3:' + 'e' * 64
        self.notice_uri = 'devres://attribution/' + self.notice_id
        self.notice_subject = {'provider':'mdn','namespace':'retained','key':'fixture-retained-mdn',
                               'fingerprint':'blake3:'+'f'*64}
        notice = {'source_url':'https://fixtures.invalid/retained-mdn-notice',
                  'text':'First-party synthetic attribution fixture. 고정 출처 안내.\n'*1400}
        self.notice_text = notice['source_url'] + '\n' + notice['text']
        self.attribution = {'status':'ready','policy_epoch':1,'policy_fingerprint':mdn.POLICY,
                            'resource_uri':self.notice_uri,'resource_uris':[self.notice_uri],
                            'readable_notice':self.notice_text,
                            'generations':[{'id':self.notice_id,'subject':self.notice_subject,'notices':[notice]}]}
        self.notice_reads = []
        outer = self
        class Client:
            def attributed(self, result):
                result['attribution'] = copy.deepcopy(outer.attribution)
                return result
            def tool(self, name, args, protocol):
                old = outer.before['revisions'][protocol]
                if name == 'mdn.get':
                    result = copy.deepcopy(old[args['representation']])
                    result.update(snapshot=args['snapshot'], resource_uri='fixture://' + args['representation'])
                    result['provenance']['snapshot'] = args['snapshot']
                    if outer.damage == 'oid': result['oid'] = 'changed'
                    if outer.damage == 'revision': result['provenance']['revision'] = 'changed'
                    return self.attributed(result)
                if name == 'mdn.search':
                    result = copy.deepcopy(old['search'])
                    result.update(total=1, snapshot=args['snapshot'])
                    result['results'][0]['id'] = outer.projection if args['snapshot'] == outer.legacy else outer.canonical_projection
                    if outer.damage == 'search': result['results'][0]['snippet'] = 'changed'
                    return self.attributed(result)
                if name == 'mdn.snapshots':
                    if 'history_snapshot' in args:
                        result = copy.deepcopy(old['history'])
                        if outer.damage == 'history': result['results'] = []
                        return self.attributed(result)
                    return self.attributed({'results': [{'id': outer.canonical}]})
                raise AssertionError(name)
            def call(self, method, args, protocol):
                outer.assertEqual(method, 'resources/read')
                if args['uri'].startswith(outer.notice_uri + '?'):
                    parsed = urlsplit(args['uri']); query = parse_qs(parsed.query)
                    outer.assertEqual(set(query), {'offset','limit'})
                    offset, limit = int(query['offset'][0]), int(query['limit'][0])
                    outer.assertEqual(limit, 32768)
                    raw = outer.notice_text.encode(); end = min(offset + limit, len(raw))
                    while True:
                        try: chunk = raw[offset:end].decode(); break
                        except UnicodeDecodeError: end -= 1
                    outer.notice_reads.append((protocol, offset, end))
                    return {'contents':[{'uri':outer.notice_uri,'mimeType':'text/plain','text':chunk,
                        '_meta':{'attribution':{'id':outer.notice_id,'subject':copy.deepcopy(outer.notice_subject),'policy_epoch':1},
                                 'offset':offset,'total_bytes':len(raw),'next_offset':end if end<len(raw) else None}}]}
                representation = args['uri'].split('://')[1]
                content = {'uri': args['uri']}
                content.update({'text': 'fixture'} if representation == 'text' else {'blob': 'Zml4dHVyZQ=='})
                if outer.damage == 'resource': content.update(text='changed', blob='Y2hhbmdlZA==')
                metadata = copy.deepcopy(outer.attribution)
                metadata.pop('readable_notice')
                # Match attach_resource_attribution: per-item metadata contains
                # notice references, while complete copied notice text is appended.
                for generation in metadata['generations']:
                    for notice in generation['notices']: notice.pop('text')
                content['_meta'] = {'attribution':metadata}
                return self.attributed({'contents':[content, {'uri':outer.notice_uri,'mimeType':'text/plain','text':outer.notice_text}]})
        self.client = Client()
        self.operator = mock.Mock()
        self.operator.k.return_value = json.dumps({'mdn:snapshots': self.canonical, 'mdn:projections': self.canonical_projection})

    def run_verify(self):
        mdn._NOTICE_CACHE.clear()
        with mock.patch.object(mdn, 'baseline', return_value=self.before):
            return mdn.verify(self.client, self.operator)

    def test_both_revisions_legacy_canonical_text_bytes_resources_and_frozen_history(self):
        result = self.run_verify()
        self.assertEqual(result['protocol_revisions'], 2)
        self.assertEqual({r[0] for r in self.notice_reads}, {'2026-07-28','2025-11-25'})
        self.assertTrue(any(offset > 0 for _, offset, _ in self.notice_reads))
        self.assertGreaterEqual(len(self.notice_reads), 6)
        self.assertTrue(all(result[key] for key in ('mdn_retained', 'legacy_and_canonical', 'text_and_bytes_resources', 'search', 'frozen_history')))

    def test_changed_source_revision_resource_search_or_history_fails(self):
        for damage in ('oid', 'revision', 'resource', 'search', 'history'):
            self.damage = damage
            with self.subTest(damage=damage), self.assertRaises(AssertionError):
                self.run_verify()

class NoticeTests(unittest.TestCase):
    def setUp(self):
        m._NOTICE_CACHE.clear()
        self.identity = 'blake3:' + 'a'*64
        self.subject = {'provider':'rfc', 'namespace':'capture','key':'fixed','fingerprint':'blake3:'+'b'*64}
        # Force a UTF-8 boundary and several complete pages.
        self.text = 'https://www.rfc-editor.org/rfc/rfc9000.txt\n' + '고정 출처 notice\n'*6000
        self.a = {'status':'ready','policy_epoch':1,'policy_fingerprint':m.POLICY,
                  'resource_uri':'devres://attribution/'+self.identity,
                  'resource_uris':['devres://attribution/'+self.identity],
                  'readable_notice':self.text,
                  'generations':[{'id':self.identity,'subject':self.subject,
                    'notices':[{'source_url':self.text.split('\n')[0], 'text':self.text.split('\n',1)[1]}]}]}
        self.calls = 0
        self.corrupt = None
    def call(self, method, params, revision):
        self.calls += 1
        self.assertEqual(method, 'resources/read')
        parsed = urlparse(params['uri']); q = parse_qs(parsed.query)
        offset, limit = int(q['offset'][0]), int(q['limit'][0])
        raw = self.text.encode(); end = min(offset+limit,len(raw))
        while True:
            try: chunk = raw[offset:end].decode(); break
            except UnicodeDecodeError: end -= 1
        item = {'uri':self.a['resource_uri'],'mimeType':'text/plain','text':chunk,
                '_meta':{'attribution':{'id':self.identity,'subject':self.subject,'policy_epoch':1},
                         'offset':offset,'total_bytes':len(raw),'next_offset':end if end<len(raw) else None}}
        if self.corrupt: self.corrupt(item)
        return {'contents':[item]}
    def test_complete_utf8_pagination_and_cache(self):
        m.qualified(self, {'attribution':self.a}, '2026-07-28')
        self.assertGreater(self.calls, 2)
        count = self.calls
        m.qualified(self, {'attribution':self.a}, '2026-07-28')
        self.assertEqual(self.calls,count)
    def test_pending_is_not_success(self):
        self.a['status'] = 'unavailable'
        with self.assertRaises(AssertionError): m.qualified(self, {'attribution':self.a}, '2026-07-28')
    def test_rejects_tampered_page_metadata_and_text(self):
        for mutate in (lambda x: x['_meta'].update(offset=999),
                       lambda x: x['_meta'].update(total_bytes=1),
                       lambda x: x['_meta']['attribution'].update(id='blake3:'+'c'*64),
                       lambda x: x.update(text='corrupted'),
                       lambda x: x['_meta'].update(next_offset=None)):
            with self.subTest(mutate=mutate):
                m._NOTICE_CACHE.clear();self.corrupt=mutate
                with self.assertRaises(AssertionError): m.qualified(self, {'attribution':self.a}, '2026-07-28')
    def test_resource_preserves_original_and_appends_exact_notice(self):
        metadata = copy.deepcopy(self.a);metadata.pop('readable_notice')
        for generation in metadata['generations']:
            for notice in generation['notices']:notice.pop('text')
        value = {'attribution':self.a,'contents':[{'uri':'devres://capture/fixed','text':'original',
                     '_meta':{'attribution':metadata}},
                    {'uri':self.a['resource_uri'],'mimeType':'text/plain','text':self.text}]}
        m.qualified(self,value,'2026-07-28',resource=True)
        self.assertEqual(value['contents'][0]['text'],'original')
        value['contents'][1]['text']='missing'
        with self.assertRaises(AssertionError): m.qualified(self,value,'2026-07-28',resource=True)
    def test_cache_does_not_accept_changed_notice(self):
        m.qualified(self,{'attribution':self.a},'2026-07-28')
        self.a['generations'][0]['notices'][0]['text']='changed'
        with self.assertRaises(AssertionError): m.qualified(self,{'attribution':self.a},'2026-07-28')

if __name__=='__main__':unittest.main()
