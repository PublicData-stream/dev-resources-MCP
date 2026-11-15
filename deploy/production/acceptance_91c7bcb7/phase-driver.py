#!/usr/bin/env python3
"""One source-bound approved phase; durable private outcome survives SSH loss."""
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,re,sys
sys.dont_write_bytecode=True
N=pathlib.Path('/tmp/devres-upgrade-91c7bcb7-20261115')
B=pathlib.Path('/var/lib/devres-production-upgrades/91c7bcb7-20261115')
C=pathlib.Path('/usr/local/libexec/devres-upgrade-91c7bcb7/upgrade-controller.py')
RECEIPTS={'apply':N/'checkpoint-state/backup-receipt.json','start-reader':N/'operational-proofs/migration/migration-receipt.json','runtime-ready':N/'private-receipt.json','activate-existing':N/'activation-receipt.json','finish':N/'observation-receipt.json'}
OPS=('stop','apply','start-writer','start-reader','runtime-ready','activate-existing','finish','withdraw')
def main():
 p=argparse.ArgumentParser();p.add_argument('operation',choices=OPS);p.add_argument('--controller-sha',required=True);a=p.parse_args()
 if os.geteuid()!=0 or re.fullmatch('[a-f0-9]{64}',a.controller_sha) is None:raise RuntimeError('root_and_source_hash_required')
 if any(x.is_symlink() for x in (C,*C.parents)) or hashlib.sha256(C.read_bytes()).hexdigest()!=a.controller_sha:raise RuntimeError('controller_source_changed')
 sp=importlib.util.spec_from_file_location('source_bound_phase',C);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
 if m.BUNDLE!=str(B) or m.WORK!=str(N) or m.REVISION!='91c7bcb7aed8eede1627bf87254c0567ef48ab7b':raise RuntimeError('deployment_identity')
 c=m.Controller(str(B),str(B/'plan.json'),'default');op=a.operation
 with c.locked():
  state=c.state()
  m.save(N/('driver-'+op+'-intent.json'),{'version':1,'operation':op,'source_sha256':a.controller_sha,'prepared_sha256':state['prepared_sha256'],'maximum_attempts':1,'started_at':m.stamp()})
  try:
   approval=N/('approval-'+op+'.json')
   m.save(approval,{'version':1,'operation':op,'reviewed':True,'source_sha256':a.controller_sha,'prepared_sha256':state['prepared_sha256']})
   receipt=RECEIPTS.get(op)
   c.run(op,str(approval),m.digest(m.read(approval)),str(receipt) if receipt else None,m.digest(m.read(receipt)) if receipt else None)
   result={'operation':op,'known_complete':True,'phase':c.state()['phase'],'completed_at':m.stamp(),'private_data_exported':False}
  except Exception as error:
   code=str(error)
   fenced=False
   try:
    if op != 'withdraw':
     c.withdraw()
     fenced=True
   except Exception: fenced=False
   result={'withdrawal_completed':fenced,'operation':op,'known_complete':False,'code':code if re.fullmatch('[a-z0-9_]+',code) else 'phase_dispatch_failed','error_type':type(error).__name__,'completed_at':m.stamp()}
  m.save(N/('driver-'+op+'-result.json'),result)
 print(json.dumps(result,sort_keys=True));return 0 if result['known_complete'] else 1
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as error:
  code=str(error)
  print(json.dumps({'known_complete':False,'code':code if re.fullmatch('[a-z0-9_]+',code) else 'phase_setup_failed','error_type':type(error).__name__}));sys.exit(1)
