#!/usr/bin/env python3
"""One source-bound phase with separate target/fallback single-use evidence."""
import argparse
import json
import os
import sys

import acceptance_common as common

sys.dont_write_bytecode = True
OPS = ('stop', 'apply', 'start-writer', 'start-reader', 'runtime-ready', 'activate-existing', 'finish', 'withdraw', 'npm-recovery')


def receipt_path(operation):
    if operation == 'apply':
        return common.ROOT / 'checkpoint-state' / 'backup-receipt-after-rehearsal.json'
    names = {'start-reader': 'operational-proofs/migration/migration-receipt.json',
             'runtime-ready': 'private-receipt.json', 'activate-existing': 'activation-receipt.json',
             'finish': 'observation-receipt.json'}
    return common.WORK / names[operation] if operation in names else None


def dispatch(operation):
    common.need(operation in OPS, 'fixed_phase_required')
    module, controller = common.controller()
    if operation == 'npm-recovery':
        with controller.locked():
            state = controller.state()
            common.need(state.get('runtime') == 'target' and state.get('phase') == 'writer_ready', 'npm_maintenance_entry_required')
            module.save(common.WORK / 'driver-npm-recovery-intent.json',
                {'version': 1, 'runtime': 'target', 'prepared_sha256': state['prepared_sha256'], 'maximum_attempts': 1})
        result = controller.npm_recovery()
        common.need(isinstance(result, dict) and result.get('eligible') is False
                    and result.get('deferred') is True, 'exact_npm_recovery_admission_unavailable')
        value = {'operation': operation, 'runtime': 'target', 'known_complete': True, 'eligible': False, 'deferred': True}
        module.save(common.WORK / 'driver-npm-recovery-result.json', value)
        return value
    with controller.locked():
        state = controller.state()
        approval = common.WORK / ('approval-' + operation + '.json')
        module.save(common.WORK / ('driver-' + operation + '-intent.json'),
            {'version': 1, 'operation': operation, 'runtime': common.RUNTIME,
             'source_sha256': state['source_sha256'], 'prepared_sha256': state['prepared_sha256'],
             'maximum_attempts': 1, 'started_at': module.stamp()})
        module.save(approval, {'version': 1, 'operation': operation, 'reviewed': True,
            'source_sha256': state['source_sha256'], 'prepared_sha256': state['prepared_sha256']})
        receipt = receipt_path(operation)
        controller.run(operation, str(approval), module.digest(module.read(approval)),
            str(receipt) if receipt else None, module.digest(module.read(receipt)) if receipt else None)
        result = {'operation': operation, 'runtime': common.RUNTIME, 'known_complete': True,
                  'phase': controller.state()['phase'], 'completed_at': module.stamp()}
        module.save(common.WORK / ('driver-' + operation + '-result.json'), result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=OPS)
    p.add_argument('--controller-sha', required=True)
    args = p.parse_args()
    common.need(os.geteuid() == 0, 'root_required')
    sources = common.manifest_sources()
    common.need(args.controller_sha == sources['upgrade-controller.py'], 'controller_source_hash')
    print(json.dumps(dispatch(args.operation), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # The supervising runner owns withdrawal/restore; never start a second
        # competing restore process from an individual failed phase.
        print(json.dumps({'known_complete': False, 'code': 'phase_dispatch_failed'}))
        sys.exit(1)
