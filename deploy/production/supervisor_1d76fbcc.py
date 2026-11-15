#!/usr/bin/env python3
"""Versioned systemd entrypoint and post-exit fence for this one admitted rollout.

Install run as ExecStart and fence as ExecStopPost in the same root-only oneshot
unit. KillMode=control-group ensures the original children are gone before fence.
A consumed restore intent is never replayed here: ambiguous restoration stays
withdrawn for explicit directory-identity reconciliation by the restore helper.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path('/tmp/devres-upgrade-1d76fbcc-20261115')
BUNDLE=Path('/var/lib/devres-production-upgrades/1d76fbcc-20261115')


def common(expected):
    import hashlib
    path=ROOT/'acceptance_common.py'
    manifest=ROOT/'source-manifest.json'
    # Root-owned private installation is the trust anchor; the externally
    # supplied digest binds its complete source inventory before import.
    for file in (path,manifest):
        if any(p.is_symlink() for p in (file,*file.parents)):raise RuntimeError('source_symlink')
        info=file.stat()
        if info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1:raise RuntimeError('private_source_required')
    raw=manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected:raise RuntimeError('external_manifest_hash')
    values=json.loads(raw)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=values['acceptance_common.py']:raise RuntimeError('common_source_changed')
    spec=importlib.util.spec_from_file_location('supervisor_exact_common',path)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256']=expected
    module.manifest_sources(expected)
    return module


def state():
    return json.loads((BUNDLE/'state.json').read_bytes())


def fence(module,expected):
    current=state()
    if current['phase']=='complete':
        return {'fenced':False,'accepted_runtime':current['runtime']}
    os.environ['DEVRES_ACCEPTANCE_RUNTIME']=current['runtime']
    # The supervisor module may have been imported for the target. Bind the
    # actual current runtime through a fresh checked interpreter instead.
    controller_module=module.bound_module(module.CONTROLLER,module.manifest_sources()['upgrade-controller.py'],'safety_exact_controller')
    controller=controller_module.Controller(str(BUNDLE),str(BUNDLE/'plan.json'),'default')
    if (BUNDLE/'rollback-intent.json').exists() and current['runtime']=='target':
        return {'fenced':False,'restore_incomplete':True,'directory_identity_reconciliation_required':True}
    with controller.locked():controller.withdraw()
    if current['runtime']=='fallback':
        return {'fenced':True,'fallback_service_accepted':False}
    if (BUNDLE/'rollback-intent.json').exists():
        return {'fenced':True,'restore_incomplete':True,'directory_identity_reconciliation_required':True}
    if not (BUNDLE/'accepted-backup.json').exists():
        return {'fenced':True,'pre_activation_stopped':True}
    controller.rollback()
    env=os.environ.copy();env['DEVRES_ACCEPTANCE_RUNTIME']='fallback'
    result=subprocess.run([sys.executable,'-B',str(ROOT/'deploy.py'),'--runtime','fallback',
        '--source-manifest-sha256',expected],env=env,timeout=7200)
    return {'fenced':True,'fallback_service_accepted':result.returncode==0 and state()['phase']=='complete'}


def run(module,expected):
    return subprocess.run([sys.executable,'-B',str(ROOT/'deploy.py'),'--runtime','target',
        '--source-manifest-sha256',expected],timeout=21600).returncode


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('run','fence'))
    parser.add_argument('--source-manifest-sha256',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:raise RuntimeError('root_required')
    module=common(args.source_manifest_sha256)
    if args.operation=='run':return run(module,args.source_manifest_sha256)
    result=fence(module,args.source_manifest_sha256)
    print(json.dumps(result,sort_keys=True))
    return 1 if result.get('restore_incomplete') else 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print(json.dumps({'known_complete':False,'code':'supervised_deployment_incomplete'}))
        raise SystemExit(1)
