"""Closed IPv4 HTTP fault fixtures; injected exchanges open no network sockets."""
import json
from pathlib import Path
import tempfile
import unittest
import traceback
from unittest.mock import patch

from deploy.diagnostics.evidence import EventRecorder, EvidenceError
from deploy.diagnostics.http_trace import FixedHttpProbe, HttpProbeError, Operation


class HttpDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp', prefix='diagnostic-http-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.recorder = EventRecorder(self.path, 'http')
        self.addCleanup(self.recorder.close)

    def events(self):
        return [json.loads(line) for line in (self.path/'http.jsonl').read_text().splitlines()]

    def exchange(self, request):
        self.assertEqual(request.revision, '2026-07-28')
        self.assertEqual(request.tool, 'server.info')
        return 200, b'{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"private":"PRIVATE_BODY"}}}'

    def test_success_records_start_response_decode_assertion_and_receipt_without_body(self):
        value = FixedHttpProbe(self.recorder, self.exchange, assert_response=lambda request,value: True).run(Operation.SERVER_INFO, '2026-07-28')
        self.assertEqual(value['result']['structuredContent']['private'], 'PRIVATE_BODY')
        self.assertEqual([v['stage'] for v in self.events()], ['start','response','decode','assertion','receipt'])
        raw = (self.path/'http.jsonl').read_text()
        self.assertNotIn('PRIVATE_', raw)
        self.assertTrue(all(v['family']=='ipv4' for v in self.events()))
        self.assertTrue(all(v['method']=='tools/call' for v in self.events()))

    def test_transport_fault_does_not_persist_or_propagate_exception_message(self):
        def fail(_):
            raise TimeoutError('PRIVATE_URI_HEADERS_LOCKFILE')
        with self.assertRaises(HttpProbeError) as caught:
            FixedHttpProbe(self.recorder, fail, assert_response=lambda request,value: True).run(Operation.LIST_TOOLS, '2025-11-25')
        self.assertEqual(str(caught.exception), 'transport')
        self.assertEqual([(r['stage'],r['code']) for r in self.events()], [('start','ok'),('failure','transport')])
        self.assertNotIn('PRIVATE_', (self.path/'http.jsonl').read_text())

    def test_http_status_decode_assertion_and_oversize_faults_are_distinct(self):
        cases = [(503, b'PRIVATE_RESPONSE','http_status'),
                 (200,b'PRIVATE_INVALID_JSON','decode'),
                 (200,b'{"jsonrpc":"2.0","result":{},"error":{"message":"PRIVATE_RPC"}}','assertion'),
                 (200,b'x'*1025,'response_bound')]
        for index, (status, body, code) in enumerate(cases):
            root = self.path/str(index);root.mkdir(mode=0o700)
            recorder = EventRecorder(root, 'http')
            try:
                with self.assertRaisesRegex(HttpProbeError, code):
                    FixedHttpProbe(recorder, lambda _: (status,body), response_limit=1024, assert_response=lambda request,value: True).run(Operation.DISCOVER,'2026-07-28')
                text = (root/'http.jsonl').read_text()
                self.assertNotIn('PRIVATE_', text)
                self.assertEqual(json.loads(text.splitlines()[-1])['code'], code)
                self.assertNotIn('receipt', text)
            finally:
                recorder.close()

    def test_single_sse_message_decodes_and_multiple_messages_fail_closed(self):
        message = b'{"jsonrpc":"2.0","result":{"tools":[]}}'
        FixedHttpProbe(self.recorder, lambda _: (200,b'event: message\ndata: '+message+b'\n\n'), assert_response=lambda request,value: True).run(Operation.LIST_TOOLS,'2026-07-28')
        with self.assertRaisesRegex(HttpProbeError,'decode'):
            FixedHttpProbe(self.recorder, lambda _: (200,b'data: '+message+b'\n\ndata: '+message+b'\n\n'), assert_response=lambda request,value: True).run(Operation.LIST_TOOLS,'2026-07-28')

    def test_unknown_methods_revisions_and_trace_fields_are_rejected(self):
        probe = FixedHttpProbe(self.recorder, lambda _: self.fail('exchange must not run'), assert_response=lambda request,value: True)
        with self.assertRaisesRegex(ValueError,'fixed_operation_required'):
            probe.run('PRIVATE_METHOD','2026-07-28')
        with self.assertRaisesRegex(ValueError,'fixed_operation_required'):
            probe.run(Operation.INITIALIZE,'PRIVATE_REVISION')
        with self.assertRaises(EvidenceError):
            self.recorder.record('http', {'headers':'PRIVATE_HEADER'})
        self.assertEqual((self.path/'http.jsonl').read_bytes(), b'')

    def test_failure_trace_sink_error_never_replaces_sanitized_transport_error(self):
        calls = [0]
        def record(*_args):
            calls[0] += 1
            if calls[0] > 1:
                raise OSError('PRIVATE_TRACE_SINK_ERROR')
        def exchange(_request):
            raise TimeoutError('PRIVATE_TRANSPORT_ERROR')
        with patch.object(self.recorder,'record',side_effect=record):
            with self.assertRaises(HttpProbeError) as caught:
                FixedHttpProbe(self.recorder,exchange,assert_response=lambda request,value:True).run(Operation.DISCOVER,'2026-07-28')
        self.assertEqual(str(caught.exception),'transport')
        rendered = ''.join(traceback.format_exception(caught.exception))
        self.assertNotIn('PRIVATE_',rendered)

    def test_initial_trace_sink_error_is_also_closed(self):
        with patch.object(self.recorder,'record',side_effect=OSError('PRIVATE_TRACE_SINK_ERROR')):
            with self.assertRaisesRegex(HttpProbeError,'trace') as caught:
                FixedHttpProbe(self.recorder,lambda request:self.fail('transport must not run'),assert_response=lambda request,value:True).run(Operation.DISCOVER,'2026-07-28')
        self.assertNotIn('PRIVATE_',''.join(traceback.format_exception(caught.exception)))

    def test_trusted_assertion_failure_is_closed_and_no_receipt_is_emitted(self):
        def assertion(request, value):
            raise AssertionError('PRIVATE_EXPECTED_IDENTITY')
        with self.assertRaisesRegex(HttpProbeError, 'assertion'):
            FixedHttpProbe(self.recorder, self.exchange, assert_response=assertion).run(Operation.SERVER_INFO, '2026-07-28')
        self.assertEqual(self.events()[-1]['stage'], 'failure')
        self.assertNotIn('receipt', (self.path/'http.jsonl').read_text())
        self.assertNotIn('PRIVATE_', (self.path/'http.jsonl').read_text())

    def test_structured_tool_error_has_no_success_receipt(self):
        body=b'{"jsonrpc":"2.0","result":{"isError":true,"structuredContent":{"message":"PRIVATE_TOOL_ERROR"}}}'
        with self.assertRaisesRegex(HttpProbeError,'assertion'):
            FixedHttpProbe(self.recorder,lambda _: (200,body), assert_response=lambda request,value: True).run(Operation.SERVER_INFO,'2026-07-28')
        self.assertEqual(self.events()[-1]['stage'], 'failure')
        self.assertNotIn('PRIVATE_', (self.path/'http.jsonl').read_text())


if __name__ == '__main__':
    unittest.main()
