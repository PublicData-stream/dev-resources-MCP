#!/usr/bin/env python3
"""Bounded first-party private acceptance. No source acquisition or credential output."""
import pathlib,json,subprocess,ssl,socket,http.client,hashlib,os,sys,importlib.util,datetime,re
N=pathlib.Path('/tmp/devres-upgrade-91c7bcb7-20261115')
B=pathlib.Path('/var/lib/devres-production-upgrades/91c7bcb7-20261115')
T=pathlib.Path('/var/lib/devres-production-preparation/a938112b-7c7a24f/tls')
CID='blake3:f561023b34507798258530bff923c41bab5d092d71b2cae7da484e6d5ce6d0e0'
def need(v,code):
 if not v:raise RuntimeError(code)
def command(args,data=None,timeout=30):
 r=subprocess.run(args,input=data,capture_output=True,timeout=timeout)
 need(len(r.stdout)+len(r.stderr)<=2*1024**2,'command_bound')
 return r
def main():
 need(len(sys.argv) in (1,2),'output_label_arity')
 output_label=sys.argv[1] if len(sys.argv)==2 else 'actual'
 need(re.fullmatch('[a-z0-9-]+',output_label) is not None,'output_label')
 p=N/'mcp_smoke.py';need(hashlib.sha256(p.read_bytes()).hexdigest()=='0a7db0771b066e5cb74e08c3a7d01d5098da0eea0962c67ccaa8271d63e7e601','client_identity')
 spec=importlib.util.spec_from_file_location('target_smoke',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 podread=command(['kubectl','--context','default','-n','devres','get','pods','-o','json'])
 need(podread.returncode==0,'pod_lookup')
 items=json.loads(podread.stdout)['items'];need(len(items)==3 and {p['metadata']['labels']['app'] for p in items}=={'backend','writer','postgres'},'exact_three_unique_roles')
 pods={v['metadata']['labels']['app']:v for v in items}
 need(set(pods)=={'backend','writer','postgres'},'three_roles')
 ips={k:v['status']['podIP'] for k,v in pods.items()}
 original=socket.getaddrinfo
 def lookup(host,port,*args,**kw):
  mapping={'devres-k8s':ips['backend'],'writer.devres.svc':ips['writer']}
  return original(mapping.get(host,host),port,*args,**kw)
 socket.getaddrinfo=lookup
 class Client(m.Client):
  def exchange(self,method,params=None,revision=m.MODERN,path=None,host=None,origin=None):
   return super().exchange(method,params,revision,path,host or 'devres-k8s:30081',origin)
 def client(cert=None,key=None):
  return Client('https://devres-k8s:8080/mcp',ca=str(T/'backend-ca.crt'),cert=cert,key=key,origin='https://dev-resources.mcp.publicdata.stream')
 c=client(str(T/'edge-client.crt'),str(T/'edge-client.key'))
 m.smoke(c,negative=False)
 pinned={}
 for rev in (m.LEGACY,m.MODERN):
  info=c.tool('server.info',{},rev);need(info['version']=='0.1.0-build.91c7bcb7','target_version')
  need(info['sourceUrl']=='https://github.com/PublicData-stream/dev-resources-MCP/releases/download/0.1.0-build.91c7bcb7/source.tar.gz','target_source_offer')
  historical='devres://attribution/blake3:254338b7453b0764ba106f0298fd5113f4d90f9aca8028761372660e1614ec81'
  notice=c.call('resources/read',{'uri':historical},rev)
  body=notice['contents'][0]['text'].encode()
  need(len(body)==735 and hashlib.sha256(body).hexdigest()=='e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156','historical_notice_identity')
  response=c.call('tools/call',{'name':'rfc.format_get','arguments':{'number':9000,'format':'txt','capture':CID,'offset':0,'limit':1024}},rev)
  need(not response.get('isError'),'baseline_readable_capture_regressed')
  if response.get('isError'):
   err=response.get('structuredContent',{})
   need(err.get('code')=='unavailable' and ('Attribution' in err.get('message','') or err.get('details',{}).get('attribution_status')=='unavailable'),'unexpected_content_failure')
   pinned[rev]={'capture':CID,'historical_notice_sha256':hashlib.sha256(body).hexdigest(),'current_policy_read':'explicit_attribution_unavailable'}
  else:
   val=response['structuredContent']
   need(val['capture']['id']==CID and val['capture']['body_hash']=='blake3:58f50168dc03a034edf54305bbf7dd71e1e1f91cb942d5e8e401ab8939890c1a' and val['attribution']['status']=='ready','pinned_capture')
   need(hashlib.sha256(val['page']['text'].encode()).hexdigest()=='6026989d1430343743b2c712d7cea16e0fd7a600110623a7a2f9e9cc6944d190','page_identity')
   current=c.call('resources/read',{'uri':val['attribution']['resource_uri']},rev)
   parts=current.get('contents',[])
   need(len(parts)==1,'current_policy_notice_readable')
   meta=parts[0]['_meta'];notice_bytes=parts[0]['text'].encode()
   need(meta['offset']==0 and meta['next_offset'] is None and len(notice_bytes)==meta['total_bytes']
        and hashlib.sha256(notice_bytes).hexdigest()=='e3023e4c9c26222fad0449a77d6d7243849a819d3d9ab7af4d2d20a277740156','complete_current_notice_identity')
   pinned[rev]={'capture':val['capture']['id'],'body_hash':val['capture']['body_hash'],'generation':val['attribution']['resource_uri'],'historical_notice_sha256':hashlib.sha256(body).hexdigest(),'current_policy_read':'ready'}
 tls={}
 for name,bad in [('missing',client()),('wrong',client(str(T/'backend.crt'),str(T/'backend.key')))]:
  rejected=False
  try:
   status,value=bad.exchange('tools/list')
   rejected=status in (401,403)
  except (ssl.SSLError,BrokenPipeError,ConnectionResetError,http.client.RemoteDisconnected):rejected=True
  need(rejected,'client_certificate_'+name)
  need(len(c.call('tools/list')['tools'])==98,'positive_tls_bookend')
  tls[name]='rejected'
 ctx=ssl.create_default_context(cafile=str(T/'coordination-ca.crt'))
 writer={}
 for label,auth in [('missing',None),('invalid','Bearer deliberately-invalid-fixture')]:
  connection=http.client.HTTPSConnection('writer.devres.svc',9443,context=ctx,timeout=15)
  try:
   headers={'Content-Type':'application/json'}
   if auth:headers['Authorization']=auth
   connection.request('POST','/v1/acquire',b'{}',headers);answer=connection.getresponse();answer.read(65537)
   need(answer.status==401,'writer_auth_'+label);writer[label]=answer.status
  finally:connection.close()
 role=command(['kubectl','--context','default','-n','devres','exec','deployment/postgres','--','psql','-X','-q','-U','devres_admin','-d','devres','-At','-v','ON_ERROR_STOP=1','-c',"BEGIN READ ONLY;SELECT coalesce(rolconfig @> ARRAY['default_transaction_read_only=on'],false) AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls FROM pg_roles WHERE rolname='devres_reader';COMMIT;"])
 need(role.returncode==0 and role.stdout.strip()==b't','actual_reader_role_defaults')
 sqlcodes={}
 for label,begin,expected in [('explicit_read_only','BEGIN READ ONLY;','25006'),('privilege','BEGIN READ WRITE;','42501')]:
  sql="\\set VERBOSITY verbose\n"+begin+" SET LOCAL statement_timeout='2s'; SET LOCAL ROLE devres_reader; UPDATE devres_schema SET version=version WHERE false; ROLLBACK;\n"
  result=command(['kubectl','--context','default','-n','devres','exec','-i','deployment/postgres','--','psql','-X','-q','-U','devres_admin','-d','devres','-v','ON_ERROR_STOP=0'],sql.encode())
  need(result.returncode==0 and expected.encode() in result.stderr,'reader_sql_'+label);sqlcodes[label]=expected
 docker=command(['docker','compose','-f','/serve/docker-compose.yml','ps','-q','oxibelt'])
 need(docker.returncode==0,'edge_lookup');edgeid=docker.stdout.decode().strip();need(len(edgeid)==64,'edge_identity')
 isolated={}
 for name,ip,port in [('postgres',ips['postgres'],5432),('writer',ips['writer'],9443),('private_health',ips['backend'],9090)]:
  r=command(['docker','exec',edgeid,'/usr/bin/nc','-z','-w','3',ip,str(port)],timeout=10)
  need(r.returncode==1,'edge_private_'+name);isolated[name]='blocked'
 positive=command(['docker','exec',edgeid,'/usr/bin/nc','-z','-w','3','devres-k8s','30081'],timeout=10)
 need(positive.returncode==0,'edge_admitted_nodeport')
 socket.getaddrinfo=original
 out={'version':1,'release':'0.1.0-build.91c7bcb7','observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'private_mcp_both_revisions':True,'tool_inventory':98,'source_offer_verified':True,'pinned':pinned,'client_certificate':tls,'writer_authorization':writer,'reader_sqlstates':sqlcodes,'reader_noop_transactions_rolled_back':True,'edge_private_denials':isolated,'edge_nodeport_positive':True,'no_provider_acquisition':True}
 fd=os.open(N/('target-private-acceptance-'+output_label+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(out,f,sort_keys=True);f.flush();os.fsync(f.fileno())
 print(json.dumps({'verified':True,'private_both_protocols':True,'boundary_controls':True,'pinned_notice':True}))
if __name__=='__main__':
 try:main()
 except Exception as e:
  code=str(e) if type(e) is RuntimeError and str(e).replace('_','').isalnum() else 'private_acceptance_failed'
  print(json.dumps({'verified':False,'code':code,'error_type':type(e).__name__}));sys.exit(1)
