#!/usr/bin/env python3
"""Twelve fixed public tools/list reads; require actual negotiated codec decoding."""
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,re,stat,subprocess,sys,time
sys.dont_write_bytecode=True
import acceptance_common as common

WORK=common.WORK
HOST='dev-resources.mcp.publicdata.stream'
VERSION=common.VERSION
REVISIONS=('2025-11-25','2026-07-28')
ENCODINGS=('gzip','br','zstd')
ADDRESSES={'ipv4':'62.210.240.40','ipv6':'2001:bc8:701:65:56fb:66ff:fe00:da0d'}
SMOKE_SHA='0a7db0771b066e5cb74e08c3a7d01d5098da0eea0962c67ccaa8271d63e7e601'
MAX=8*1024**2
class Stop(RuntimeError):pass
def need(v,code):
 if not v:raise Stop(code)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(v):return hashlib.sha256(v).hexdigest()
def save(p,v):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(json.dumps(v,sort_keys=True,separators=(',',':')).encode());f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def headers(raw):
 need(len(raw)<=65536,'header_bound')
 blocks=raw.replace(b'\r\n',b'\n').strip().split(b'\n\n');final=blocks[-1].split(b'\n')
 need(final[0].startswith(b'HTTP/1.1 200 '),'http_status')
 result={}
 for line in final[1:]:
  key,sep,value=line.partition(b':');need(bool(sep),'header_shape')
  name=key.decode('ascii').lower();text=value.decode('latin1').strip();result[name]=result.get(name,'')+(',' if name in result else '')+text
 return result
def decode(body,head,encoding,expected_tools):
 need(0<len(body)<=MAX,'body_bound')
 need(head.get('content-encoding','').lower()==encoding,'selected_codec_required')
 need('accept-encoding' in [v.strip().lower() for v in head.get('vary','').split(',')],'vary_required')
 need('no-store' in [x.strip().lower() for x in head.get('cache-control','').split(',')],'no_store_required')
 media=head.get('content-type','').split(';',1)[0].lower()
 need(media=='text/event-stream','sse_required')
 if media=='application/json':value=json.loads(body);framing='json'
 else:
  need(media=='text/event-stream','content_type')
  values=[json.loads(line[5:].strip()) for line in body.splitlines() if line.startswith(b'data:')]
  selected=[v for v in values if v.get('id')==17];need(len(selected)==1,'one_rpc_result_required');value=selected[0];framing='sse'
 need(isinstance(value,dict) and value.get('jsonrpc')=='2.0' and value.get('id')==17 and 'error' not in value,'successful_rpc_required')
 result=value.get('result',{});tools=result.get('tools',[])
 need(len(tools)==98 and {t.get('name') for t in tools}==expected_tools,'exact_tool_inventory')
 return {'framing':framing,'canonical_result_sha256':digest(json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())}
def request(folder,family,revision,encoding,expected_tools):
 params={}
 if revision=='2026-07-28':params['_meta']={'io.modelcontextprotocol/protocolVersion':revision,'io.modelcontextprotocol/clientInfo':{'name':'devres-codec-acceptance','version':'1'},'io.modelcontextprotocol/clientCapabilities':{}}
 rpc={'jsonrpc':'2.0','id':17,'method':'tools/list','params':params}
 name=family+'-'+revision+'-'+encoding;request_path=folder/(name+'-request.json');save(request_path,rpc)
 head_path=folder/(name+'-headers.txt');need(not head_path.exists(),'fresh_header_path')
 address=ADDRESSES[family];resolved=HOST+':443:'+('['+address+']' if family=='ipv6' else address)
 args=['curl','--disable','--silent','--show-error','--http1.1','--compressed','--noproxy','*','--ipv4' if family=='ipv4' else '--ipv6','--resolve',resolved,'--connect-timeout','10','--max-time','45','--max-filesize',str(MAX),'--dump-header',str(head_path),'-H','Content-Type: application/json','-H','Accept: application/json, text/event-stream','-H','Accept-Encoding: '+encoding,'-H','MCP-Protocol-Version: '+revision,'-H','Origin: https://'+HOST,'-H','Mcp-Method: tools/list','--data-binary','@'+str(request_path),'https://'+HOST+'/mcp']
 start=time.monotonic();process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:
  body=process.stdout.read(MAX+1)
  need(len(body)<=MAX,'decoded_response_bound')
  code=process.wait(timeout=10);errors=process.stderr.read(65537)
  need(code==0 and len(errors)<=65536 and time.monotonic()-start<=60,'bounded_native_decode_failed')
 finally:
  if process.poll() is None:process.kill();process.wait(timeout=10)
  process.stdout.close();process.stderr.close()
 os.chmod(head_path,0o600);rawhead=head_path.read_bytes();head=headers(rawhead);value=decode(body,head,encoding,expected_tools)
 return {'family':family,'revision':revision,'encoding':encoding,'content_encoding':head['content-encoding'].lower(),'http_status':200,'vary_accept_encoding':True,'tool_inventory':98,'decoded_bytes':len(body),'decoded_body_sha256':digest(body),'canonical_result_sha256':value['canonical_result_sha256'],'framing':value['framing'],'cache_control_no_store':True,'headers_sha256':digest(rawhead),'observed_at':now()}
def main():
 common.manifest_sources()
 p=argparse.ArgumentParser();p.add_argument('--public',required=True);a=p.parse_args()
 need(os.geteuid()==0 and re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',a.public) is not None,'root_and_label_required')
 folder=WORK/a.public
 need(not any(p.is_symlink() for p in (folder,*folder.parents)),'private_path')
 info=folder.stat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077,'private_directory')
 os.umask(0o077)
 smoke=common.ROOT/'mcp_smoke.py';need(digest(smoke.read_bytes())==SMOKE_SHA,'smoke_source_changed')
 sp=importlib.util.spec_from_file_location('exact_tools',smoke);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
 started=now();save(folder/'compression-intent.json',{'version':1,'started_at':started,'maximum_requests':12,'source_sha256':digest(pathlib.Path(__file__).read_bytes())})
 try:
  cells=[request(folder,family,revision,encoding,m.EXPECTED_TOOLS) for family in ADDRESSES for revision in REVISIONS for encoding in ENCODINGS]
  for revision in REVISIONS:need(len({c['canonical_result_sha256'] for c in cells if c['revision']==revision})==1,'codec_payloads_differ')
  value={'version':1,'verified':True,'release':VERSION,'producer_sha256':digest(pathlib.Path(__file__).read_bytes()),'started_at':started,'observed_at':now(),'no_provider_acquisition':True,'cells':cells}
  save(folder/'compression.json',value)
 except Exception as error:
  code=str(error);save(folder/'compression-failed.json',{'verified':False,'code':code if re.fullmatch('[a-z0-9_]+',code) else 'codec_probe_failed','observed_at':now()});raise
 print(json.dumps({'verified':True,'cells':12,'encodings':list(ENCODINGS),'no_provider_acquisition':True}))
if __name__=='__main__':
 try:main()
 except Exception as error:
  code=str(error);print(json.dumps({'verified':False,'code':code if re.fullmatch('[a-z0-9_]+',code) else 'codec_probe_failed'}));sys.exit(1)
