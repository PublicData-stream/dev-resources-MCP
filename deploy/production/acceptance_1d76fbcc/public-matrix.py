#!/usr/bin/env python3
"""Released native WT and matching bounded HTTP smoke; public reads only."""
import pathlib,subprocess,json,os,hashlib,datetime,importlib.util,socket,sys,re,stat
import acceptance_common as common

base=common.WORK

TRACE_LIMIT = 2 * 1024 ** 2

def append_trace(path, value):
 # Never accept headers, arguments, payloads or exception text here.
 allowed = {'family','revision','method','tool','stage','event','status','rpc_error_code',
            'tool_is_error','tool_error_code','exception_type','observed_at','elapsed_seconds'}
 if not set(value) <= allowed:
  raise RuntimeError('trace_field_refused')
 body=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
 try:
  import stat
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size+len(body)>TRACE_LIMIT:
   raise RuntimeError('unsafe_or_excessive_trace')
  with os.fdopen(fd,'ab',closefd=False) as stream:
   stream.write(body);stream.flush();os.fsync(stream.fileno())
 finally:os.close(fd)

def traced_client(client_type, trace_path, family, allowed_tools):
 if family not in ('ipv4','ipv6'):raise ValueError('unknown_family')
 class TracedClient(client_type):
  trace_stage='smoke'
  def exchange(self,method,params=None,revision='2026-07-28',path=None,host=None,origin=None):
   import time
   start=time.monotonic()
   name=params.get('name') if isinstance(params,dict) else None
   entry={'family':family,'revision':revision if revision in ('2025-11-25','2026-07-28') else 'unknown','method':method if method in ('server/discover','initialize','tools/list','tools/call','resources/read') else 'unknown',
          'tool':name if name in allowed_tools else ('unknown' if name is not None else None),
          'stage':self.trace_stage if self.trace_stage in ('smoke','identity','receipt') else 'unknown','observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
   try:
    status,value=super().exchange(method,params,revision,path,host,origin)
   except Exception as error:
    append_trace(trace_path,{**entry,'event':'exchange_exception','exception_type':type(error).__name__,'elapsed_seconds':time.monotonic()-start})
    raise
   result=value.get('result',{}) if isinstance(value,dict) else {}
   result=result if isinstance(result,dict) else {}
   details=result.get('structuredContent',{})
   details=details if isinstance(details,dict) else {}
   code=details.get('code')
   rpc=value.get('error') if isinstance(value,dict) else None
   rpc_code=rpc.get('code') if isinstance(rpc,dict) else None
   append_trace(trace_path,{**entry,'event':'exchange_returned','status':status,
       'rpc_error_code':rpc_code if isinstance(rpc_code,int) else None,
       'tool_is_error':result.get('isError') is True,
       'tool_error_code':code if code in {'unavailable','capacity','invalid_input','not_found','cancelled','integrity'} else None,
       'elapsed_seconds':time.monotonic()-start})
   return status,value
 return TracedClient

def checked_probe(path, expected, original=None):
 path=pathlib.Path(path)
 if not path.is_absolute() or pathlib.Path('/tmp') not in path.parents or any(p.is_symlink() for p in (path,*path.parents)):
  raise RuntimeError('native_probe_path')
 for parent in path.parents:
  value=parent.stat()
  if parent==pathlib.Path('/tmp'):
   if value.st_uid!=0 or not value.st_mode&stat.S_ISVTX:raise RuntimeError('native_probe_tmp')
   break
  if not stat.S_ISDIR(value.st_mode) or value.st_uid!=os.geteuid() or value.st_mode&0o022:
   raise RuntimeError('native_probe_directory')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as stream:
  value=os.fstat(stream.fileno())
  if not stat.S_ISREG(value.st_mode) or value.st_uid!=os.geteuid() or value.st_nlink!=1 or value.st_mode&0o022 or not value.st_mode&0o001 or value.st_size>64*1024**2:
   raise RuntimeError('native_probe_metadata')
  digest=hashlib.sha256()
  for block in iter(lambda:stream.read(1024**2),b''):digest.update(block)
  final=os.fstat(stream.fileno())
  identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_uid,v.st_gid,v.st_mode)
  if identity(value)!=identity(final) or digest.hexdigest()!=expected or original is not None and identity(final)!=original:
   raise RuntimeError('native_probe_changed')
 return identity(final)

def main():
 common.need(os.geteuid()==0,'root_required')
 common.manifest_sources()
 qualification=common.runtime_qualification()
 label=sys.argv[1];assert re.fullmatch('[a-z0-9-]+',label)
 full=sys.argv[2]=='full';assert sys.argv[2] in ('full','bounded')
 r=base/label;r.mkdir(mode=0o700)
 binary=pathlib.Path(common.IDENTITY['probe_directory'])/'devres-probe';probe_identity=checked_probe(binary,qualification['binary_sha256'])
 for family in ('ipv4','ipv6'):
  for rev in ('2025-11-25','2026-07-28'):
   hosts=r/('hosts-'+family)
   hostbytes=('127.0.0.1 localhost\n::1 localhost\n'+('62.210.240.40' if family=='ipv4' else '2001:bc8:701:65:56fb:66ff:fe00:da0d')+' dev-resources.mcp.publicdata.stream\n').encode()
   if not hosts.exists():
    fd=os.open(hosts,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as f:f.write(hostbytes);f.flush();os.fsync(f.fileno())
    os.chmod(hosts,0o644)
   assert not hosts.is_symlink() and hosts.read_bytes()==hostbytes and hosts.stat().st_uid==0 and hosts.stat().st_mode & 0o777==0o644
   hostsha=hashlib.sha256(hostbytes).hexdigest()
   cmd=['unshare','--mount','--propagation','private','--','/bin/sh','-c','set -eu; mount --bind "$1" /etc/hosts; exec /usr/bin/setpriv --reuid=1000 --regid=1000 --init-groups --pdeathsig KILL "$2" "$3" "$4" "$5" "$6"','devres-native-upgrade',str(hosts),str(binary),'https://dev-resources.mcp.publicdata.stream/mcp-wt/v1','/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt',rev,'https://dev-resources.mcp.publicdata.stream']
   checked_probe(binary,qualification['binary_sha256'],probe_identity)
   p=subprocess.run(cmd,capture_output=True,timeout=45)
   checked_probe(binary,qualification['binary_sha256'],probe_identity)
   v={'family':family,'revision':rev,'exit':p.returncode,'stdout':p.stdout.decode()[:2048],'stderr':p.stderr.decode()[:2048],'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'released_probe_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'client_transport_override':False,'hosts_sha256':hostsha,'family_mapping_verified':True}
   with (r/('wt-'+family+'-'+rev+'.json')).open('x') as f:os.chmod(f.fileno(),0o600);json.dump(v,f,sort_keys=True)
   print(json.dumps({'family':family,'revision':rev,'exit':p.returncode}),flush=True);assert p.returncode==0
 assert hashlib.sha256((common.ROOT/'mcp_smoke.py').read_bytes()).hexdigest()=='0a7db0771b066e5cb74e08c3a7d01d5098da0eea0962c67ccaa8271d63e7e601'
 spec=importlib.util.spec_from_file_location('target_smoke',common.ROOT/'mcp_smoke.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 original=socket.getaddrinfo
 for family,af in [('ipv4',socket.AF_INET),('ipv6',socket.AF_INET6)]:
  def lookup(host,port,*args,**kw):
   values=original(host,port,*args,**kw)
   return [x for x in values if x[0]==af] if host=='dev-resources.mcp.publicdata.stream' else values
  socket.getaddrinfo=lookup
  trace_path=r/('trace-'+family+'.jsonl')
  append_trace(trace_path,{'family':family,'stage':'smoke','event':'begin','observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()})
  client_type=traced_client(m.Client,trace_path,family,m.EXPECTED_TOOLS)
  c=client_type('https://dev-resources.mcp.publicdata.stream/mcp',origin='https://dev-resources.mcp.publicdata.stream')
  try:
   m.smoke(c,negative=full)
   c.trace_stage='identity'
   for rev in (m.LEGACY,m.MODERN):
    info=c.tool('server.info',{},rev);assert info['version']==common.VERSION
    assert info['sourceUrl']==common.SOURCE_URL
   c.trace_stage='receipt'
   append_trace(trace_path,{'family':family,'stage':'receipt','event':'checks_passed','observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()})
   v={'exchange_trace_sha256':hashlib.sha256(trace_path.read_bytes()).hexdigest(),'family':family,'http_contract_passed':True,'exhaustive_obsolete_name_negatives':full,'tool_inventory':98,'protocols':[m.MODERN,m.LEGACY],'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'no_source_acquisition':True,'release':common.VERSION}
   with (r/('http-'+family+'.json')).open('x') as f:os.chmod(f.fileno(),0o600);json.dump(v,f,sort_keys=True)
   print(json.dumps(v),flush=True)
  except Exception as error:
   append_trace(trace_path,{'family':family,'stage':c.trace_stage,'event':'assertion_or_receipt_failure','exception_type':type(error).__name__,'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()})
   raise
 socket.getaddrinfo=original
if __name__=='__main__':
 try:main()
 except Exception:
  print(json.dumps({'verified':False,'code':'public_matrix_failed'}));sys.exit(1)
