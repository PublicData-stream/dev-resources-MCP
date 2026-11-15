#!/usr/bin/env python3
"""One exact-target fresh acceptance, with durable child outcomes and new fences."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode=True
WORK=Path('/tmp/devres-upgrade-91c7bcb7-20261115')
BUNDLE=Path('/var/lib/devres-production-upgrades/91c7bcb7-20261115')
MANIFEST=WORK/'resume-v1-sources.json'
LOGS=WORK/'resume-v1-command-evidence'
CONTROLLER=Path('/usr/local/libexec/devres-upgrade-91c7bcb7/upgrade-controller.py')
CHECKPOINT=CONTROLLER.parent/'physical-checkpoint.py'
RESUME=CONTROLLER.parent/'resume-controller.py'
NEW_PATHS={'helper':RESUME,'public':WORK/'resume-v1-public-matrix.py',
           'receipt':WORK/'resume-v1-acceptance-receipt.py','runner':WORK/'resume-v1-runner.py'}
MAX_LOG=4*1024**2

class Error(RuntimeError):pass

def need(value,code):
 if not value:raise Error(code)

def sha(data):return hashlib.sha256(data).hexdigest()

def read(path):
 need(not any(p.is_symlink() for p in (path,*path.parents)),'source_symlink')
 with path.open('rb') as f:
  info=os.fstat(f.fileno());need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1 and not info.st_mode&0o077 and info.st_size<=8*1024**2,'unsafe_source_or_receipt')
  data=f.read(8*1024**2+1);need(len(data)==info.st_size,'source_changed');return data

def save(path,data):
 data=data if isinstance(data,bytes) else json.dumps(data,sort_keys=True).encode()
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def checked_sources(expected):
 body=read(MANIFEST);need(re.fullmatch('[0-9a-f]{64}',expected or '') and sha(body)==expected,'source_manifest_hash')
 new=json.loads(body);need(set(new)==set(NEW_PATHS),'fixed_resume_sources')
 for key,path in NEW_PATHS.items():need(sha(read(path))==new[key],'resume_source_changed')
 old=json.loads(read(WORK/'source-manifest.json'))
 for name,h in old.items():
  need(name in {'upgrade-controller.py','physical-checkpoint.py','mcp_smoke.py','target-private-acceptance.py','operational-proof.py','public-matrix.py','compressed-probe.py','acceptance-receipt.py','observation-loop.py','store-claim.py','phase-driver.py'},'unknown_frozen_source')
  path=CONTROLLER.parent/name if name in ('upgrade-controller.py','physical-checkpoint.py') else WORK/name
  need(sha(read(path))==h,'frozen_source_changed')
 need(len(old)==11,'all_frozen_sources_required')
 return new,old

def module(path,expected,name):
 need(sha(read(path))==expected,'import_source_hash')
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def step(label,command,timeout):
 need(re.fullmatch('[a-z0-9-]{1,64}',label) is not None,'bounded_stage_label')
 save(LOGS/(label+'-intent.json'),{'stage':label,'started_at':dt.datetime.now(dt.timezone.utc).isoformat(),'maximum_attempts':1})
 timed_out=False
 try:
  result=subprocess.run(command,capture_output=True,timeout=timeout);out,err,code=result.stdout,result.stderr,result.returncode
 except subprocess.TimeoutExpired as error:
  out,err,code=error.stdout or b'',error.stderr or b'',None;timed_out=True
 save(LOGS/(label+'-stdout.log'),out[:MAX_LOG]);save(LOGS/(label+'-stderr.log'),err[:MAX_LOG])
 record={'stage':label,'exit_code':code,'timed_out':timed_out,'stdout_sha256':sha(out[:MAX_LOG]),'stderr_sha256':sha(err[:MAX_LOG]),'stdout_bytes':len(out),'stderr_bytes':len(err),'log_truncated':len(out)>MAX_LOG or len(err)>MAX_LOG,'ended_at':dt.datetime.now(dt.timezone.utc).isoformat()}
 save(LOGS/(label+'-result.json'),record);print(json.dumps(record),flush=True)
 need(not timed_out and code==0 and not record['log_truncated'],'child_step_failed')
 return record

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-manifest-sha256',required=True);args=p.parse_args()
 need(os.geteuid()==0,'root_required');new,old=checked_sources(args.source_manifest_sha256)
 resume=module(RESUME,new['helper'],'admitted_resume_helper');frozen=resume.controller_module();c=frozen.Controller(str(BUNDLE),str(BUNDLE/'plan.json'),'default')
 with c.locked():
  c.guard();state=c.state();need(state['phase']=='collectors_active' and state.get('resume_continuation'),'resumed_active_runtime_required')
  admitted=resume.load(resume.JOURNAL/'resumed.json');need(admitted['known_complete'] is True and admitted['pods']==state['pods'],'resumed_process_bookend')
 need(not LOGS.exists() and not LOGS.is_symlink(),'one_acceptance_runner_attempt_only')
 LOGS.mkdir(mode=0o700)
 common=['--controller',str(CONTROLLER),'--controller-sha',old['upgrade-controller.py'],'--checkpoint',str(CHECKPOINT),'--checkpoint-sha',old['physical-checkpoint.py']]
 commands=[
 ('early-before',['operational-proof.py','sample','--label','resume-v1-early-before',*common],120),
 ('early-private',['target-private-acceptance.py','resume-v1-early'],180),
 ('early-public',['resume-v1-public-matrix.py','resume-v1-early-public','full'],300),
 ('early-codecs',['compressed-probe.py','--public','resume-v1-early-public'],180),
 ('early-after',['operational-proof.py','sample','--label','resume-v1-early-after',*common],120),
 ('observation',['observation-loop.py','--label','resume-v1-observation','--compression-sha',old['compressed-probe.py'],*common],1100),
 ('late-before',['operational-proof.py','sample','--label','resume-v1-late-before',*common],120),
 ('late-private',['target-private-acceptance.py','resume-v1-late'],180),
 ('late-public',['resume-v1-public-matrix.py','resume-v1-late-public','bounded'],300),
 ('late-codecs',['compressed-probe.py','--public','resume-v1-late-public'],180),
 ('late-after',['operational-proof.py','sample','--label','resume-v1-late-after',*common],120),
 ('aggregate',['resume-v1-acceptance-receipt.py','finish','--label','resume-v1-final','--early','resume-v1-early','resume-v1-early-public','resume-v1-early-before','resume-v1-early-after','--late','resume-v1-late','resume-v1-late-public','resume-v1-late-before','resume-v1-late-after','--observation','resume-v1-observation','--compression-sha',old['compressed-probe.py'],*common],120)]
 try:
  for label,arguments,timeout in commands:
   checked_sources(args.source_manifest_sha256)
   step(label,[sys.executable,'-B',str(WORK/arguments[0]),*arguments[1:]],timeout)
  checked_sources(args.source_manifest_sha256)
  with c.locked():
   c.guard();state=c.state();approval=WORK/'resume-v1-finish-approval.json';receipt=WORK/'resume-v1-observation-receipt.json'
   save(approval,{'version':1,'operation':'finish','reviewed':True,'source_sha256':state['source_sha256'],'prepared_sha256':state['prepared_sha256']})
   save(LOGS/'finish-intent.json',{'maximum_attempts':1,'receipt_sha256':sha(read(receipt)),'state_sha256':sha(read(BUNDLE/'state.json'))})
   c.run('finish',str(approval),sha(read(approval)),str(receipt),sha(read(receipt)))
   c.guard();need(c.state()['phase']=='complete','completed_phase_required')
   save(LOGS/'completed.json',{'known_complete':True,'phase':'complete','observed_at':dt.datetime.now(dt.timezone.utc).isoformat(),'state_sha256':sha(read(BUNDLE/'state.json'))})
  print(json.dumps({'known_complete':True,'phase':'complete'}));return 0
 except Exception as error:
  fenced=False
  try:
   result=resume.emergency_withdraw(c,frozen,sha(read(BUNDLE/'state.json')));fenced=result.get('withdrawal_completed') is True
  except Exception:pass
  save(LOGS/'failed.json',{'known_complete':False,'withdrawal_completed':fenced,'manual_reconciliation_required':not fenced,'code':str(error) if isinstance(error,Error) else 'resume_acceptance_failed','exception_type':type(error).__name__})
  print(json.dumps({'known_complete':False,'withdrawal_completed':fenced,'manual_reconciliation_required':not fenced}));return 1

if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as error:
  print(json.dumps({'known_complete':False,'code':str(error) if isinstance(error,Error) else 'runner_setup_failed','runtime_not_claimed':True}));raise SystemExit(1)
