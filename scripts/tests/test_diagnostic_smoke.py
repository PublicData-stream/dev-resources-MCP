"""Real numeric IPv4 loopback HTTP fixtures for the unchanged full smoke sequence."""
import contextlib
import io
import http.server
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from deploy.diagnostics.evidence import EvidenceError
from deploy.diagnostics.runner import DiagnosticRunner
from deploy.diagnostics.smoke import DiagnosticSmokeError, SmokeTrace, canonical, diagnose, loopback_endpoint, main, TracedClient


class FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, fault=None, sse=False):
        super().__init__(('127.0.0.1',0), FixtureHandler)
        self.fault, self.sse = fault, sse
        self.requests = []


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append((request, self.path, dict(self.headers)))
        if self.server.fault == 'no_response':
            time.sleep(0.15)
            self.close_connection = True
            return
        revision = self.headers['MCP-Protocol-Version']
        method, params = request['method'],request['params']
        status, result, error = 200, {}, None
        if (self.path != '/mcp' or self.headers.get('Host')=='untrusted.invalid'
            or self.headers.get('Origin')=='https://untrusted.invalid'):
            status,error = 403, {'code':-32600,'message':'PRIVATE_BOUNDARY_MESSAGE'}
        elif method == 'tools/list':
            result = {'tools':[{'name':name,'inputSchema':{'additionalProperties':False,'oneOf':[{},{}]}}
                               for name in sorted(canonical.EXPECTED_TOOLS)]}
            if self.server.fault == 'assertion':
                result['tools'].pop()
        elif method == 'tools/call':
            name, arguments = params['name'],params['arguments']
            if name not in canonical.EXPECTED_TOOLS or 'url' in arguments:
                status = 400 if revision == canonical.MODERN else 200
                error = {'code':-32602,'message':'unknown tool'}
            elif name == 'server.info':
                result = {'structuredContent':{'product':'dev-resources-MCP','license':'AGPL-3.0-only',
                          'sourceUrl':'https://example.invalid/source.tar.gz','version':'local-fixture',
                          'private':'PRIVATE_RESPONSE_CONTENT'}}
            elif name == 'packages.crate.advisory_corpus_status':
                result = {'structuredContent':{'counts':{}}}
            else:
                result = {'structuredContent':{'collection_enabled':True}}
        value = {'jsonrpc':'2.0','id':request['id']}
        value['error' if error else 'result'] = error if error else result
        body = json.dumps(value).encode()
        content_type = 'application/json'
        if self.server.fault == 'decode':
            body = b'PRIVATE_INVALID_JSON_BODY'
        elif self.server.sse:
            content_type = 'text/event-stream'
            body = b'data: {"method":"notifications/progress"}\n\ndata: '+body+b'\n\n'
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError,ConnectionResetError):
            self.wfile.write(body)


class RealSmokeDiagnostics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp',prefix='diagnostic-real-http-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        sync = patch('os.fsync', return_value=None)
        sync.start()
        self.addCleanup(sync.stop)

    def server(self, **kwargs):
        server = FixtureServer(**kwargs)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join,1)
        self.addCleanup(server.shutdown)
        return server, 'http://127.0.0.1:'+str(server.server_port)+'/mcp'

    def records(self, root=None):
        return [json.loads(line) for line in ((root or self.root)/'smoke-trace.jsonl').read_text().splitlines()]

    def test_real_json_runs_exact_original_full_smoke_then_identity_and_receipt(self):
        server,endpoint = self.server()
        result = diagnose(endpoint,self.root)
        actual = list(server.requests)
        self.assertTrue(result['known_complete'])
        self.assertFalse(result['production_acceptance'])
        server.requests.clear()
        canonical.smoke(canonical.Client(endpoint),negative=True)
        expected = server.requests
        self.assertEqual(len(actual),len(expected)+2)
        # Request construction, headers, negative overrides and every assertion
        # are kept equal to the original first-party smoke, not copied fixtures.
        self.assertEqual(actual[:len(expected)],expected)
        records = self.records()
        self.assertEqual({r['stage'] for r in records},{'smoke','identity','receipt'})
        requests = [r for r in records if r['method']!='none']
        self.assertEqual(len([r for r in requests if r['event']=='begin']),len(actual))
        for operation in {r['operation'] for r in requests}:
            events = [r['event'] for r in requests if r['operation']==operation]
            self.assertEqual(events,['begin','response','decode','complete'])
        self.assertTrue(any(r['tool']=='packages.crate.advisory_corpus_status' for r in records))
        self.assertTrue(any(r['tool']=='obsolete' for r in records))
        self.assertEqual(records[-1]['stage'],'receipt')
        self.assertEqual(records[-1]['event'],'complete')
        receipt = json.loads((self.root/'smoke-receipt.json').read_text())
        self.assertEqual(receipt['tool_inventory'],98)
        raw = (self.root/'smoke-trace.jsonl').read_text()+(self.root/'smoke-receipt.json').read_text()
        for forbidden in ('PRIVATE_','http://','https://','arguments','headers','untrusted.invalid'):
            self.assertNotIn(forbidden,raw)

    def test_real_sse_uses_original_decoder_and_full_assertions(self):
        _,endpoint = self.server(sse=True)
        self.assertTrue(diagnose(endpoint,self.root)['known_complete'])
        self.assertEqual(self.records()[-1]['event'],'complete')

    def test_real_no_response_has_request_identity_and_no_success_receipt(self):
        _,endpoint = self.server(fault='no_response')
        started = time.monotonic()
        with self.assertRaisesRegex(DiagnosticSmokeError,'transport'):
            diagnose(endpoint,self.root,timeout=0.03)
        self.assertLess(time.monotonic()-started,0.5)
        records = self.records()
        self.assertTrue(any(r['event']=='begin' and r['method']=='server/discover' for r in records))
        self.assertTrue(any(r['event']=='failure' and r['code']=='transport' for r in records))
        self.assertFalse((self.root/'smoke-receipt.json').exists())

    def test_real_decode_and_original_inventory_assertion_fail_closed(self):
        for fault,code in [('decode','decode'),('assertion','assertion')]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir='/tmp') as directory:
                _,endpoint = self.server(fault=fault)
                root = Path(directory)
                with self.assertRaisesRegex(DiagnosticSmokeError,code):
                    diagnose(endpoint,root)
                text = (root/'smoke-trace.jsonl').read_text()
                self.assertEqual(json.loads(text.splitlines()[-1])['code'],code)
                self.assertNotIn('PRIVATE_',text)
                self.assertFalse((root/'smoke-receipt.json').exists())

    def test_receipt_failure_retains_stage_without_exception_message(self):
        _,endpoint = self.server()
        def fail():
            raise ValueError('PRIVATE_RECEIPT_ERROR')
        with self.assertRaisesRegex(DiagnosticSmokeError,'receipt'):
            diagnose(endpoint,self.root,receipt_check=fail)
        row = self.records()[-1]
        self.assertEqual((row['stage'],row['event'],row['code']),('receipt','failure','receipt'))
        self.assertNotIn('PRIVATE_',(self.root/'smoke-trace.jsonl').read_text())
        self.assertFalse((self.root/'smoke-receipt.json').exists())

    def test_existing_receipt_is_not_overwritten_on_real_receipt_io_failure(self):
        _,endpoint = self.server()
        old = self.root/'smoke-receipt.json'
        old.write_bytes(b'retained previous receipt')
        old.chmod(0o600)
        with self.assertRaisesRegex(DiagnosticSmokeError,'receipt'):
            diagnose(endpoint,self.root)
        self.assertEqual(old.read_bytes(),b'retained previous receipt')
        self.assertEqual(self.records()[-1]['event'],'failure')
        self.assertEqual(self.records()[-1]['stage'],'receipt')

    def test_runner_runs_real_smoke_command_with_closed_output(self):
        _,endpoint = self.server(sse=True)
        traces = self.root/'smoke';traces.mkdir(mode=0o700)
        def collect(recorder,stop):
            recorder.record('edge',{'code':'started'})
            stop.wait()
        result = DiagnosticRunner(self.root,evidence_timeout=1.0).run(
            [sys.executable,'-B','-m','deploy.diagnostics.smoke','--endpoint',endpoint,'--output-dir',str(traces)],
            timeout_seconds=15,collect=collect,fence=lambda:True)
        self.assertEqual(result.code,'ok')
        self.assertTrue(result.persisted)
        self.assertTrue(json.loads((self.root/'stdout.log').read_text())['known_complete'])
        self.assertTrue((traces/'smoke-receipt.json').exists())
        self.assertEqual((self.root/'stderr.log').read_bytes(),b'')

    def test_endpoint_validation_forbids_external_ipv6_credentials_and_routing_inputs(self):
        for endpoint in ['https://127.0.0.1:1234/mcp','http://localhost:1234/mcp',
                         'http://[::1]:1234/mcp','http://169.254.169.254:80/mcp',
                         'http://127.0.0.1:1234/mcp?PRIVATE_QUERY',
                         'http://PRIVATE_USER:PRIVATE_PASSWORD@127.0.0.1:1234/mcp',
                         'http://127.0.0.1:1234/ready','http://127.0.0.1:1234/mcp#fragment']:
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(DiagnosticSmokeError,'input'):
                loopback_endpoint(endpoint)

    def test_client_refuses_non_smoke_arguments_before_opening_a_socket(self):
        trace = SmokeTrace(self.root)
        self.addCleanup(trace.close)
        client = TracedClient('http://127.0.0.1:1/mcp',trace)
        with patch('http.client.HTTPConnection') as connection:
            for method,params in [
                ('tools/call',{'name':'rfc.get','arguments':{'number':9000}}),
                ('tools/call',{'name':'server.info','arguments':{'lockfile':'PRIVATE_LOCKFILE'}}),
                ('resources/read',{'uri':'PRIVATE_URI'}),
                ('tools/call',{'name':'packages.npm.metadata','arguments':{'name':'PRIVATE_PACKAGE'}}),
            ]:
                with self.assertRaisesRegex(DiagnosticSmokeError,'input'):
                    client.exchange(method,params)
            connection.assert_not_called()
        self.assertEqual((self.root/'smoke-trace.jsonl').read_bytes(),b'')

    def test_cli_parse_and_endpoint_errors_never_echo_private_values(self):
        for args in [['--PRIVATE_ARGUMENT','PRIVATE_VALUE'],
                     ['--endpoint','http://PRIVATE_USER:PRIVATE_PASSWORD@127.0.0.1:1/mcp',
                      '--output-dir',str(self.root)]]:
            output,error = io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(output),contextlib.redirect_stderr(error):
                self.assertEqual(main(args),1)
            self.assertEqual(json.loads(output.getvalue())['code'],'input')
            self.assertNotIn('PRIVATE_',output.getvalue()+error.getvalue())

    def test_smoke_sink_charges_failed_attempt_and_is_poisoned(self):
        trace = SmokeTrace(self.root,limit=1024)
        self.addCleanup(trace.close)
        with patch('os.fsync',side_effect=OSError('PRIVATE_SYNC_ERROR')):
            with self.assertRaises(EvidenceError):
                trace.emit('begin')
        size = (self.root/'smoke-trace.jsonl').stat().st_size
        charged = trace.written
        self.assertGreater(charged,0)
        for _ in range(20):
            with self.assertRaises(EvidenceError):
                trace.emit('begin')
        with self.assertRaises(EvidenceError):
            trace.receipt()
        self.assertEqual(trace.written,charged)
        self.assertEqual((self.root/'smoke-trace.jsonl').stat().st_size,size)
        self.assertFalse((self.root/'smoke-receipt.json').exists())

    def test_unknown_trace_values_are_refused_before_writing(self):
        trace = SmokeTrace(self.root)
        self.addCleanup(trace.close)
        for kwargs in [{'tool':'PRIVATE_TOOL'},{'method':'PRIVATE_METHOD'},{'code':'PRIVATE_ERROR'}]:
            with self.assertRaises(EvidenceError):
                trace.emit('begin',**kwargs)
        self.assertEqual((self.root/'smoke-trace.jsonl').read_bytes(),b'')


if __name__ == '__main__':
    unittest.main()
