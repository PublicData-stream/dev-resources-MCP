"""Failure locations and closed RPC metadata must not retain request/report bodies."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'deploy/production/acceptance_1d76fbcc'
sys.path.insert(0,str(SOURCE))
try:
    spec=importlib.util.spec_from_file_location('private_closed_diagnostics',SOURCE/'target-private-acceptance.py')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
finally:sys.path.pop(0)

class PrivateDiagnostics(unittest.TestCase):
    def setUp(self):helper.RECENT_EXCHANGES.clear()

    def test_failed_rpc_retains_only_closed_metadata_and_original_behavior(self):
        secret='private-lockfile-and-password-body'
        class Client:
            def exchange(self,*args):
                return 200,{'result':{'isError':True,'structuredContent':{'code':'unavailable','message':secret,'graph':secret}}}
        client=helper.traced_client(Client,{'server.info'})()
        status,body=client.exchange('tools/call',{'name':'server.info','arguments':{'lockfile':secret}},host=secret,origin=secret,path=secret)
        self.assertEqual(status,200);self.assertEqual(body['result']['structuredContent']['message'],secret)
        trace=helper.RECENT_EXCHANGES[-1]
        self.assertEqual(trace['tool'],'server.info');self.assertTrue(trace['tool_is_error'])
        self.assertEqual(trace['tool_error_code'],'unavailable');self.assertNotIn(secret,json.dumps(trace))
        self.assertEqual(set(trace),{'method','revision','tool','event','status','rpc_error_code','tool_is_error','tool_error_code'})

    def test_assertion_location_and_exception_trace_never_serialize_message_or_locals(self):
        secret='submitted-graph-and-secret'
        class Client:
            def exchange(self,*args):raise AssertionError(secret)
        client=helper.traced_client(Client,{'server.info'})()
        try:client.exchange('tools/call',{'name':secret,'arguments':{'lockfile':secret}},revision=secret)
        except AssertionError as error:
            self.assertEqual(str(error),secret)
            metadata=helper.failure_metadata(error)
        self.assertEqual(metadata['error_type'],'AssertionError')
        self.assertTrue(metadata['failure_locations']);self.assertNotIn(secret,json.dumps(metadata))
        self.assertEqual(metadata['recent_exchanges'][-1]['event'],'exception')
        self.assertEqual(metadata['recent_exchanges'][-1]['revision'],'unknown')
        self.assertIsNone(metadata['recent_exchanges'][-1]['tool'])
        self.assertTrue(all(set(item)=={'file','line','function'} for item in metadata['failure_locations']))

    def test_ring_and_untrusted_error_values_are_bounded(self):
        class Client:
            def exchange(self,*args):return 999,{'error':{'code':10**100},'result':{'structuredContent':{'code':{'private':'secret'}}}}
        client=helper.traced_client(Client,set())()
        for _ in range(100):client.exchange('private-secret',{'name':'private-secret'})
        self.assertEqual(len(helper.RECENT_EXCHANGES),8)
        self.assertNotIn('private-secret',json.dumps(helper.RECENT_EXCHANGES))
        self.assertTrue(all(item['status'] is None and item['rpc_error_code'] is None and item['tool_error_code'] is None for item in helper.RECENT_EXCHANGES))
        client.exchange({'private':'method'},{'name':['private']},revision=['private'])
        self.assertEqual(helper.RECENT_EXCHANGES[-1]['method'],'unknown')

if __name__=='__main__':unittest.main()
