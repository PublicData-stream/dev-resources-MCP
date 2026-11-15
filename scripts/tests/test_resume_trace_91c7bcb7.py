"""Payload-free public exchange tracing preserves all original smoke semantics."""
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
trace=load('resume_public_trace',ROOT/'deploy/production/acceptance_91c7bcb7/resume-v1-public-matrix.py')
receipt=load('resume_public_receipt',ROOT/'deploy/production/acceptance_91c7bcb7/resume-v1-acceptance-receipt.py')
class Base:
 result=(200,{'jsonrpc':'2.0','id':1,'result':{'secret_response':'DO_NOT_RETAIN_RESPONSE'}})
 error=None
 calls=[]
 def exchange(self,*args):
  self.calls.append(args)
  if self.error:raise self.error
  return self.result
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir='/tmp');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  Base.calls=[];Base.error=None;Base.result=(200,{'jsonrpc':'2.0','id':1,'result':{'secret_response':'DO_NOT_RETAIN_RESPONSE'}})
  self.path=self.root/'trace.jsonl'
 def client(self):return trace.traced_client(Base,self.path,'ipv6',{'server.info'})()
 def records(self):return [json.loads(v) for v in self.path.read_text().splitlines()]
 def test_exchange_returns_exact_original_tuple_and_never_logs_arguments_or_body(self):
  c=self.client();params={'name':'server.info','arguments':{'lockfile':'DO_NOT_RETAIN_INPUT'}};before=copy.deepcopy(params)
  actual=c.exchange('tools/call',params);self.assertEqual(actual,Base.result);self.assertIs(actual[1],Base.result[1]);self.assertEqual(params,before)
  self.assertEqual(Base.calls[0],('tools/call',params,'2026-07-28',None,None,None))
  raw=self.path.read_text();self.assertNotIn('DO_NOT_RETAIN',raw);self.assertNotIn('arguments',raw)
  row=self.records()[0];self.assertEqual(row['tool'],'server.info');self.assertEqual(row['family'],'ipv6');self.assertEqual(row['status'],200)
 def test_error_enums_are_logged_without_error_messages_or_result_payload(self):
  Base.result=(503,{'error':{'code':-32603,'message':'DO_NOT_RETAIN_MESSAGE'},'result':{'isError':True,'structuredContent':{'code':'unavailable','message':'DO_NOT_RETAIN_OTHER'}}})
  self.client().exchange('tools/call',{'name':'server.info'});r=self.records()[0]
  self.assertEqual((r['status'],r['rpc_error_code'],r['tool_error_code'],r['tool_is_error']),(503,-32603,'unavailable',True));self.assertNotIn('DO_NOT_RETAIN',self.path.read_text())
 def test_exception_records_only_type_and_reraises_original(self):
  error=ValueError('DO_NOT_RETAIN_SECRET');Base.error=error
  with self.assertRaises(ValueError) as caught:self.client().exchange('tools/list')
  self.assertIs(caught.exception,error);self.assertEqual(self.records()[0]['exception_type'],'ValueError');self.assertNotIn('DO_NOT_RETAIN_SECRET',self.path.read_text())
 def test_unknown_selectors_and_stage_are_not_persisted(self):
  c=self.client();c.trace_stage='DO_NOT_RETAIN_STAGE';c.exchange('DO_NOT_RETAIN_METHOD',{'name':'DO_NOT_RETAIN_TOOL'},'DO_NOT_RETAIN_REVISION')
  self.assertNotIn('DO_NOT_RETAIN',self.path.read_text());row=self.records()[0]
  self.assertEqual([row[k] for k in ('method','tool','revision','stage')],['unknown']*4)
 def test_arbitrary_trace_fields_are_rejected(self):
  with self.assertRaisesRegex(RuntimeError,'trace_field_refused'):trace.append_trace(self.path,{'arguments':'private'})
  self.assertFalse(self.path.exists())
 def test_trace_rejects_symlinks_hardlinks_group_access_and_bounds(self):
  original=self.root/'original';original.write_text('unchanged');original.chmod(0o600);self.path.symlink_to(original)
  with self.assertRaises(OSError):trace.append_trace(self.path,{'event':'test'})
  self.path.unlink();os.link(original,self.path)
  with self.assertRaisesRegex(RuntimeError,'unsafe_or_excessive_trace'):trace.append_trace(self.path,{'event':'test'})
  self.path.unlink();self.path.write_text('');self.path.chmod(0o640)
  with self.assertRaisesRegex(RuntimeError,'unsafe_or_excessive_trace'):trace.append_trace(self.path,{'event':'test'})
  self.path.chmod(0o600)
  with patch.object(trace,'TRACE_LIMIT',1):
   with self.assertRaisesRegex(RuntimeError,'unsafe_or_excessive_trace'):trace.append_trace(self.path,{'event':'test'})
  self.assertEqual(original.read_text(),'unchanged')
 def test_append_retains_preceding_outcomes(self):
  self.client().exchange('tools/list');self.client().exchange('tools/list')
  self.assertEqual(len(self.records()),2);self.assertEqual(self.path.stat().st_mode&0o777,0o600)
 def write(self,p,v,mode=0o600):
  p.write_bytes(v if isinstance(v,bytes) else json.dumps(v).encode());p.chmod(mode)
 def public_fixture(self):
  folder=self.root/'public';folder.mkdir(mode=0o700);when=dt.datetime.now(dt.timezone.utc).isoformat();compression='a'*64
  for family,address in [('ipv4','62.210.240.40'),('ipv6','2001:bc8:701:65:56fb:66ff:fe00:da0d')]:
   hosts=('127.0.0.1 localhost\n::1 localhost\n'+address+' dev-resources.mcp.publicdata.stream\n').encode();self.write(folder/('hosts-'+family),hosts,0o644)
   t=folder/('trace-'+family+'.jsonl');self.write(t,b'{"event":"checks_passed"}\n')
   self.write(folder/('http-'+family+'.json'),{'family':family,'http_contract_passed':True,'tool_inventory':98,'release':receipt.VERSION,'protocols':list(receipt.REVISIONS),'no_source_acquisition':True,'observed_at':when,'exchange_trace_sha256':hashlib.sha256(t.read_bytes()).hexdigest()})
   for rev in receipt.REVISIONS:self.write(folder/('wt-'+family+'-'+rev+'.json'),{'family':family,'revision':rev,'exit':0,'released_probe_sha256':receipt.PROBE_SHA,'client_transport_override':False,'family_mapping_verified':True,'hosts_sha256':hashlib.sha256(hosts).hexdigest(),'stdout':'WebTransport '+rev+': discovery, tool listing, and server identity verified.','observed_at':when})
  cells=[{'family':f,'revision':r,'encoding':e,'http_status':200,'content_encoding':e,'framing':'sse','cache_control_no_store':True,'vary_accept_encoding':True,'tool_inventory':98,'decoded_bytes':1024,'canonical_result_sha256':'b'*64,'observed_at':when} for f in receipt.FAMILIES for r in receipt.REVISIONS for e in ('gzip','br','zstd')]
  self.write(folder/'compression.json',{'version':1,'verified':True,'release':receipt.VERSION,'producer_sha256':compression,'no_provider_acquisition':True,'started_at':when,'observed_at':when,'cells':cells})
  return folder,compression
 def test_aggregate_hash_binds_successful_exchange_ledgers(self):
  folder,h=self.public_fixture();artifacts=[];op=types.SimpleNamespace(raw=lambda p:Path(p).read_bytes())
  self.assertTrue(receipt.public_proofs(op,folder,artifacts,compression_sha=h))
  self.assertTrue(any(a['path'].endswith('trace-ipv6.jsonl') for a in artifacts))
  self.write(folder/'trace-ipv6.jsonl',b'{"event":"changed"}\n')
  with self.assertRaisesRegex(receipt.Stop,'artifact_hash'):receipt.public_proofs(op,folder,[],compression_sha=h)
 def test_versioned_aggregator_uses_actual_public_producer_hash(self):
  p=ROOT/'deploy/production/acceptance_91c7bcb7/resume-v1-public-matrix.py'
  self.assertEqual(receipt.PRODUCERS['resume-v1-public-matrix.py'],hashlib.sha256(p.read_bytes()).hexdigest())
if __name__=='__main__':unittest.main()
