"""Synthetic bounded RFC acceptance tests; no network requests or provider data."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('rfc_acceptance', SCRIPTS / 'rfc_acceptance.py')
rfc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rfc)

CAPTURE = 'blake3:' + 'a' * 64
SNAPSHOT = 'blake3:' + 'b' * 64
NOTICE_ID = 'blake3:' + 'c' * 64
NOTICE_URI = 'devres://attribution/' + NOTICE_ID
NOTICE = 'https://fixtures.invalid/notice\nSynthetic first-party RFC fixture notice.'
BODY = ('RFC9000 QUIC Multiplexed synthetic first-party fixture. ' * 80).encode()
FORMATS = {fmt: (b'%PDF-1.7\n' + BODY + b'\n%%EOF' if fmt == 'pdf' else BODY)
           for fmt in ('txt', 'html', 'xml', 'pdf')}


def attribution():
    return {'status': 'ready', 'readable_notice': NOTICE, 'resource_uri': NOTICE_URI,
            'resource_uris': [NOTICE_URI], 'generations': [{'id': NOTICE_ID,
            'notices': [{'source_url': 'https://fixtures.invalid/notice',
                         'text': 'Synthetic first-party RFC fixture notice.'}]}]}


def envelope(data, error=False):
    blocks = [{'type': 'text', 'text': json.dumps(data)}]
    if not error:
        if data.get('attribution', {}).get('status') == 'ready':
            blocks.append({'type': 'text', 'text': data['attribution']['readable_notice']})
        blocks += [{'type': 'resource_link', 'uri': uri, 'name': 'fixture'}
                   for uri in sorted(rfc.owned_links(data))]
    return {'isError': error, 'structuredContent': data, 'content': blocks}


def page(fmt='txt', offset=0, limit=1024):
    raw = FORMATS[fmt]
    chunk = raw[offset:offset + limit]
    value = {'offset': offset, 'total_bytes': len(raw),
             'next_offset': offset + len(chunk) if offset + len(chunk) < len(raw) else None}
    value.update({'encoding': 'base64', 'data': base64.b64encode(chunk).decode()} if fmt == 'pdf'
                 else {'encoding': 'utf-8', 'text': chunk.decode()})
    return value


def representation(fmt='txt', offset=0, limit=1024, legacy=False):
    uri = ('devres://capture/' + CAPTURE if legacy else f'devres://rfc/9000/{fmt}/{CAPTURE}')
    uri += f'?offset={offset}&limit={limit}'
    return {'id': 'rfc:9000', 'format': fmt, 'media_type': {'txt': 'text/plain', 'html': 'text/html',
            'xml': 'application/xml', 'pdf': 'application/pdf'}[fmt], 'page': page(fmt, offset, limit),
            'capture': {'id': CAPTURE, 'source_url': rfc.REFERENCE_URLS[fmt]},
            'resource_uri': uri, 'attribution': attribution()}


class FakeClient:
    def __init__(self, defect=None):
        self.ident = 0
        self.calls = []
        self.timeout = 45
        self.defect = defect

    def exchange(self, method, args, revision):
        self.ident += 1
        self.calls.append((method, copy.deepcopy(args), revision))
        if method == 'tools/call':
            name, parameters = args['name'], args['arguments']
            if ('url' in parameters or parameters.get('limit') == 0 or parameters.get('number') == 0
                    or parameters.get('query') == '' or parameters.get('number') == 9001):
                return self.rejection(revision)
            if self.defect == name:
                return 200, self.rpc(envelope({'code': 'unavailable', 'message': 'fixture unavailable'}, True))
            value = self.tool(name, parameters)
            return 200, self.rpc(envelope(value))
        if method == 'resources/read':
            if 'invalid' in args['uri']:
                return self.rejection(revision)
            return 200, self.rpc(self.resource(args['uri']))
        if method in ('server/discover', 'initialize'):
            result = {'capabilities': {'tools': {}, 'resources': {}}}
            result.update({'supportedVersions': list(rfc.REVISIONS)} if method == 'server/discover'
                          else {'protocolVersion': revision})
            return 200, self.rpc(result)
        if method == 'tools/list':
            return 200, self.rpc({'tools': [{'name': name, 'inputSchema': {
                'type': 'object', 'additionalProperties': False}} for name in rfc.RFC_TOOLS]})
        return 200, self.rpc({})

    def rpc(self, result):
        return {'jsonrpc': '2.0', 'id': self.ident, 'result': result}

    def rejection(self, revision):
        return (400 if revision == rfc.MODERN else 200), {'jsonrpc': '2.0', 'id': self.ident,
                'error': {'code': -32602, 'message': 'invalid fixture request'}}

    def listed(self, items, args):
        offset, limit = args.get('offset', 0), args.get('limit', 20)
        return {'items': items[offset:offset + limit], 'offset': offset, 'total': len(items),
                'next_offset': offset + limit if offset + limit < len(items) else None,
                'capture': {'id': CAPTURE, 'source_url': rfc.REFERENCE_URLS['index']},
                'snapshot': args.get('snapshot', SNAPSHOT), 'attribution': attribution()}

    def tool(self, name, args):
        metadata = {'number': 9000, 'title': 'QUIC: A UDP-Based Multiplexed and Secure Transport',
                    'status': 'PROPOSED STANDARD', 'stream': 'IETF'}
        if name == 'server.info':
            return {'product': 'dev-resources-MCP', 'version': 'fixture',
                    'sourceUrl': 'https://fixtures.invalid/source', 'protocolVersions': list(rfc.REVISIONS)}
        if name == 'rfc.corpus_status':
            return {'collection_enabled': True, 'captured_rfc_numbers': 1, 'collector': {'active': True}}
        if name == 'rfc.metadata':
            return {'metadata': metadata, 'snapshot': SNAPSHOT, 'attribution': attribution()}
        if name == 'rfc.catalog_search':
            return self.listed([{'metadata': metadata}], args)
        if name == 'rfc.errata':
            return self.listed([{'doc-id': 'RFC9000', 'errata_id': '1'}], args)
        if name == 'rfc.series_get':
            return dict(self.listed([{'number': 2119}, {'number': 8174}], args), series='BCP14')
        if name == 'rfc.fulltext_search':
            return dict(self.listed([{'number': 9000, 'score': 3.0}, {'number': 9001, 'score': 2.0},
                                    {'number': 9002, 'score': 2.0}], args), coverage={'partial': True})
        if name == 'rfc.search':
            return dict(self.listed([{'metadata': {'number': number}} for number in (496, 2178, 2642)], args),
                        search_scope='official_index_metadata')
        if name == 'search':
            return {'sources': [{'source': 'rfc', 'result': self.tool('rfc.search', args)}],
                    'attribution': attribution()}
        if name in ('rfc.get', 'rfc.format_get'):
            return representation(args.get('format', 'txt'), args.get('offset', 0),
                                  args.get('limit', 1024), legacy=name == 'rfc.get')
        if name == 'fetch':
            if args['id'] == 'rfc:9000':
                return representation(legacy=True)
            return self.resource(args['id'])
        raise AssertionError('unexpected fake tool')

    def resource(self, uri):
        parsed = rfc.urllib.parse.urlsplit(uri)
        params = dict(rfc.urllib.parse.parse_qsl(parsed.query))
        offset, limit = int(params.get('offset', 0)), int(params.get('limit', 1024))
        if parsed.netloc == 'attribution':
            text = NOTICE.encode()[offset:offset + limit].decode()
            end = offset + len(text.encode())
            return {'contents': [{'uri': NOTICE_URI, 'text': text, '_meta': {
                    'offset': offset, 'total_bytes': len(NOTICE.encode()),
                    'next_offset': end if end < len(NOTICE.encode()) else None}}]}
        fmt = parsed.path.split('/')[2] if parsed.netloc == 'rfc' else 'txt'
        value = representation(fmt, offset, limit)
        content = {'uri': uri, 'mimeType': 'application/pdf' if fmt == 'pdf' else 'text/plain', '_meta': {'source_evidence': {'capture': {'id': CAPTURE}},
                                        'attribution': attribution()}}
        content.update({'blob': value['page']['data']} if fmt == 'pdf' else {'text': value['page']['text']})
        return {'contents': [content, {'text': NOTICE}], 'attribution': attribution()}


def references():
    return dict(FORMATS, index=[{'number': 9000, 'title': 'QUIC: A UDP-Based Multiplexed and Secure Transport',
                                'status': 'PROPOSED STANDARD', 'stream': 'IETF', 'series': []},
                               {'number': 2119, 'series': ['BCP14']}, {'number': 8174, 'series': ['BCP14']}],
                errata=[{'doc-id': 'RFC9000', 'errata_id': '1'}])


class WireTests(unittest.TestCase):
    def test_json_rpc_id_version_and_result_exclusivity(self):
        good = {'jsonrpc': '2.0', 'id': 1, 'result': {}}
        self.assertEqual(rfc.rpc_payload(200, good, 1, rfc.MODERN), {})
        for bad in ({'jsonrpc': '1.0', 'id': 1, 'result': {}},
                    dict(good, id=2), dict(good, id=True), dict(good, error={}), {'jsonrpc': '2.0', 'id': 1}):
            with self.subTest(value=bad), self.assertRaises(rfc.CheckFailure):
                rfc.rpc_payload(200, bad, 1, rfc.MODERN)

    def test_error_handling_preserves_incomplete_success(self):
        runner, report, budget = self.runner(FakeClient('rfc.get'))
        self.assertIsNone(runner.step('get', rfc.MODERN, lambda: runner.get(rfc.MODERN)))
        self.assertEqual([row['status'] for row in report.checks], ['passed', 'unverified'])
        self.assertFalse(report.as_dict(budget)['acceptance_passed'])

    def runner(self, client=None):
        report, budget = rfc.Report('https://fixture.invalid/mcp'), rfc.Budget()
        return rfc.Acceptance(client or FakeClient(), report, budget, references()), report, budget

    def test_native_structured_text_notices_and_owned_links(self):
        data = representation()
        self.assertEqual(rfc.tool_payload(envelope(data)), data)
        missing = envelope(data)
        missing['content'] = [missing['content'][0]]
        with self.assertRaises(rfc.CheckFailure):
            rfc.tool_payload(missing)
        bad = envelope(data)
        bad['content'][0]['text'] = '{}'
        with self.assertRaises(rfc.CheckFailure):
            rfc.tool_payload(bad)
        metadata = {'attribution': {'status': 'metadata_only', 'copied_content': False}}
        self.assertEqual(rfc.tool_payload(envelope(metadata)), metadata)

    def test_bad_base64_page_offset_and_capture_binding(self):
        value = representation('pdf')
        value['page']['data'] = '%%%'
        with self.assertRaises(rfc.CheckFailure):
            rfc.page_bytes(value, 'pdf')
        runner, _, _ = self.runner()
        with self.assertRaises(rfc.CheckFailure):
            runner.same_capture(representation(), {'capture': {'id': SNAPSHOT}})
        with self.assertRaises(rfc.CheckFailure):
            runner.same_snapshot({'snapshot': CAPTURE}, SNAPSHOT)

    def test_changed_bytes_do_not_claim_historical_corruption(self):
        runner, _, _ = self.runner()
        data = representation()
        data['page']['text'] = 'X' + data['page']['text'][1:]
        with self.assertRaisesRegex(rfc.Unverified, 'current_reference_differs'):
            runner.official_page(data, 'txt')

    def test_source_local_error_and_dependency_are_incomplete(self):
        client = FakeClient()
        original = client.tool
        client.tool = lambda name, args: ({'sources': [{'source': 'rfc', 'error': {'code': 'unavailable'}}]}
                                           if name == 'search' else original(name, args))
        runner, report, _ = self.runner(client)
        with self.assertRaisesRegex(rfc.Unverified, 'rfc_source_unavailable'):
            runner.generic_search(rfc.MODERN)
        with self.assertRaisesRegex(rfc.Unverified, 'dependency_unavailable'):
            runner.resource(None, 'txt', rfc.MODERN)
        self.assertEqual(report.checks[0]['status'], 'passed')

    def test_full_matrix_is_bounded_rfc_only_and_runs_both_revisions(self):
        runner, report, budget = self.runner()
        runner.run()
        failures = [row for row in report.checks if row['status'] != 'passed']
        self.assertEqual(failures, [])
        self.assertTrue(report.as_dict(budget)['acceptance_passed'])
        self.assertLessEqual(budget.calls, 147)  # leaves 13 calls for host connector sampling
        names = {args['name'] for method, args, _ in runner.client.calls if method == 'tools/call'}
        self.assertTrue(rfc.RFC_TOOLS <= names)
        self.assertEqual({revision for _, _, revision in runner.client.calls}, set(rfc.REVISIONS))
        for method, args, _ in runner.client.calls:
            if method == 'tools/call' and args['name'] == 'search':
                self.assertEqual(args['arguments']['sources'], ['rfc'])

    def test_failure_does_not_hide_independent_tools(self):
        runner, report, _ = self.runner(FakeClient('rfc.metadata'))
        runner.run()
        self.assertTrue(any(row['check'] == 'rfc.catalog_search' and row['status'] == 'unverified'
                            for row in report.checks))
        self.assertTrue(any(row['check'] == 'rfc.format_get.pdf' and row['status'] == 'passed'
                            for row in report.checks))


    def test_unqualified_copied_content_is_never_a_success(self):
        for attr in (None, {}, {'status': 'metadata_only', 'copied_content': False}, {'status': 'pending'}):
            data = {'metadata': {'number': 9000, 'title': 'QUIC'}, 'snapshot': SNAPSHOT}
            if attr is not None:
                data['attribution'] = attr
            with self.subTest(attr=attr), self.assertRaises(rfc.CheckFailure):
                rfc.tool_payload(envelope(data))

    def test_wrong_resource_uri_mime_notice_or_attribution_binding_fails(self):
        for defect in ('uri', 'mime', 'notice', 'generation'):
            client = FakeClient()
            original = client.resource
            def changed(uri, defect=defect):
                value = original(uri)
                if defect == 'uri':
                    value['contents'][0]['uri'] = 'devres://capture/wrong'
                elif defect == 'mime':
                    value['contents'][0]['mimeType'] = 'text/html'
                elif defect == 'notice':
                    value['contents'][1]['text'] = 'Unrelated notice'
                else:
                    value['contents'][0]['_meta']['attribution']['resource_uris'] = []
                return value
            client.resource = changed
            runner, _, _ = self.runner(client)
            with self.subTest(defect=defect), self.assertRaises(rfc.CheckFailure):
                runner.resource(representation(), 'txt', rfc.MODERN)

    def test_html_edge_outage_is_availability_and_invalid_method_is_contract_failure(self):
        with self.assertRaisesRegex(rfc.Unverified, 'http_503'):
            rfc.rpc_payload(503, None, 1, rfc.MODERN)
        with self.assertRaises(rfc.CheckFailure):
            rfc.rpc_payload(200, {'jsonrpc': '2.0', 'id': 1,
                'error': {'code': -32601, 'message': 'method not found'}}, 1, rfc.MODERN)

    def test_connector_failures_incomplete_coverage_and_changed_identity_prevent_pass(self):
        report, budget = rfc.Report('https://fixture.invalid/mcp'), rfc.Budget()
        report.add('http.fixture', 'passed')
        report.add_connector('rfc.get', envelope({'code': 'unavailable', 'message': 'fixture'}, True))
        self.assertFalse(report.as_dict(budget)['acceptance_passed'])
        report.connector = []
        report.add_connector('server.info', envelope(FakeClient().tool('server.info', {})))
        self.assertFalse(report.as_dict(budget)['acceptance_passed'])


    def test_handshake_rejects_wrong_revision_and_missing_capabilities(self):
        for revision in rfc.REVISIONS:
            for defect in ('revision', 'capabilities'):
                client = FakeClient()
                original = client.exchange
                def changed(method, args, revision, defect=defect):
                    status, value = original(method, args, revision)
                    if defect == 'capabilities':
                        value['result']['capabilities'] = {}
                    elif revision == rfc.MODERN:
                        value['result']['supportedVersions'] = [rfc.LEGACY]
                    else:
                        value['result']['protocolVersion'] = rfc.MODERN
                    return status, value
                client.exchange = changed
                runner, _, _ = self.runner(client)
                with self.subTest(revision=revision, defect=defect), self.assertRaises(rfc.CheckFailure):
                    runner.open_revision(revision)


    def test_get_failure_does_not_suppress_independent_generic_fetch(self):
        runner, report, _ = self.runner(FakeClient('rfc.get'))
        runner.run()
        fetch_revisions = [revision for method, args, revision in runner.client.calls
                           if method == 'tools/call' and args['name'] == 'fetch'
                           and args['arguments'].get('id') == 'rfc:9000']
        self.assertEqual(fetch_revisions, list(rfc.REVISIONS))
        fetch_results = [row for row in report.checks if row['check'] == 'fetch.rfc']
        self.assertEqual([row['status'] for row in fetch_results], ['passed', 'passed'])
        parity = [row for row in report.checks if row['check'] == 'rfc.get.fetch_parity']
        self.assertEqual([row['status'] for row in parity], ['unverified', 'unverified'])


class LimitsTests(unittest.TestCase):
    def test_deadline_and_budget_stop_before_another_exchange(self):
        clock = [0]
        budget = rfc.Budget(clock=lambda: clock[0], maximum=1, seconds=2)
        budget.admit()
        with self.assertRaisesRegex(rfc.Unverified, 'mcp_request_budget'):
            budget.admit()
        self.assertEqual(budget.calls, 1)
        clock[0] = 3
        with self.assertRaisesRegex(rfc.Unverified, 'overall_deadline'):
            budget.remaining()

    def test_tmp_and_endpoint_restrictions(self):
        for path in ('/tmp', '/etc/report', '/tmp/../home/report'):
            with self.assertRaises(ValueError):
                rfc.tmp_path(path)
        for url in ('http://fixture.invalid/mcp', 'https://user:secret@fixture.invalid/mcp',
                    'https://fixture.invalid/mcp?secret=value', 'https://fixture.invalid/mcp#fragment'):
            with self.assertRaises(ValueError):
                rfc.endpoint(url)
        self.assertEqual(rfc.endpoint('https://fixture.invalid/mcp'), 'https://fixture.invalid/mcp')

    def test_report_and_connector_do_not_copy_response_bodies(self):
        report = rfc.Report('https://fixture.invalid/mcp')
        row = report.add_connector('rfc.get', envelope(representation()))
        self.assertEqual(row['status'], 'envelope_passed')
        self.assertNotIn('Synthetic first-party RFC fixture', json.dumps(report.as_dict(rfc.Budget())))
        report.add('bounded', 'passed')
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            report.write(directory, rfc.Budget())
            data = json.loads((Path(directory) / 'report.json').read_text())
            self.assertEqual(data['schema'], 'devres-rfc-acceptance-v1')

    def test_main_requires_explicit_live_before_network(self):
        with patch.object(rfc, 'Client') as client, patch('sys.stderr'):
            with self.assertRaises(SystemExit):
                rfc.main(['--url', 'https://fixture.invalid/mcp', '--output-dir', '/tmp/fixture'])
            client.assert_not_called()


    def test_report_files_cannot_overwrite_or_follow_symlinks(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            root = Path(directory)
            outside = root / 'outside'
            outside.write_text('retain')
            (root / 'report.json').symlink_to(outside)
            with self.assertRaises(rfc.CheckFailure):
                rfc.Report('https://fixture.invalid/mcp').write(root, rfc.Budget())
            self.assertEqual(outside.read_text(), 'retain')
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            report = rfc.Report('https://fixture.invalid/mcp')
            report.write(directory, rfc.Budget())
            with self.assertRaises(rfc.CheckFailure):
                report.write(directory, rfc.Budget())


    def test_both_connector_import_modes_debit_the_shared_call_budget(self):
        raw = [{'name': 'server_info', 'args': {},
                'result': envelope(FakeClient().tool('server.info', {}))} for _ in range(13)]
        sanitized = [{'tool': 'server.info', 'status': 'envelope_passed', 'version': 'fixture'}
                     for _ in range(13)]
        for option, rows in (('--connector-input', raw), ('--connector-observations', sanitized)):
            with self.subTest(option=option), tempfile.TemporaryDirectory(dir='/tmp') as directory:
                root = Path(directory)
                source = root / 'input.json'
                source.write_text(json.dumps(rows))
                with patch.object(rfc, 'Client'), patch.object(rfc.References, 'collect', return_value={}), \
                     patch.object(rfc.Acceptance, 'run'), patch('sys.stdout'):
                    rfc.main(['--live', '--url', 'https://fixture.invalid/mcp', '--output-dir',
                              str(root / 'output'), option, str(source)])
                report = json.loads((root / 'output' / 'report.json').read_text())
                self.assertEqual(report['mcp_requests'], 13)
                self.assertEqual(report['connector_mcp_requests'], 13)
                self.assertEqual(report['limits']['mcp_requests'] - report['mcp_requests'], 147)


class ReferenceTests(unittest.TestCase):
    def test_xml_namespace_series_and_fixed_metadata(self):
        xml = b'''<rfc-index xmlns="https://fixtures.invalid"><rfc-entry><doc-id>RFC9000</doc-id>
          <title>QUIC</title><current-status>PROPOSED STANDARD</current-status><stream>IETF</stream>
          </rfc-entry><rfc-entry><doc-id>RFC2119</doc-id><title>Fixture</title>
          <is-also><doc-id>BCP0014</doc-id></is-also></rfc-entry></rfc-index>'''
        rows = rfc.parse_index(xml)
        self.assertEqual(rows[1]['series'], ['BCP14'])
        with self.assertRaises(rfc.CheckFailure):
            rfc.parse_index(b'<!DOCTYPE x><rfc-index/>')

    def test_challenge_markup_and_bad_pdf_are_rejected(self):
        for kind, raw in (('html', b'<html>9000 QUIC Just a moment...</html>'),
                          ('txt', b'<html>9000 QUIC</html>'), ('pdf', b'not a pdf')):
            with self.subTest(kind=kind), self.assertRaises(rfc.CheckFailure):
                rfc.parse_reference(kind, raw)

    def test_official_downloads_no_redirects_or_retries_and_retain_hash_only(self):
        class Response:
            status = 302
            def getheader(self, name, default=None):
                return default
        class Connection:
            calls = []
            def __init__(self, host, **kwargs):
                self.host = host
            def request(self, method, path, headers):
                self.calls.append((self.host, path, headers))
            def getresponse(self):
                return Response()
            def close(self):
                pass
        report = rfc.Report('https://fixture.invalid/mcp')
        sources = rfc.References(report, rfc.Budget(), connection=Connection, sleep=lambda _: None)
        self.assertEqual(sources.collect(), {})
        self.assertEqual(sources.attempts, 6)
        self.assertEqual(len(Connection.calls), 6)
        self.assertTrue(all(row['status'] == 'unverified' for row in report.references))
        self.assertEqual({call[0] for call in Connection.calls}, {'www.rfc-editor.org'})


if __name__ == '__main__':
    unittest.main()
