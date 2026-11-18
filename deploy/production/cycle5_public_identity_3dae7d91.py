#!/usr/bin/env python3
"""Prepare one fresh public identity without replaying a consumed operation."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

WORK = Path('/tmp/devres-upgrade-3dae7d91-cycle5-20261118')
INSTALL = Path('/usr/local/libexec/devres-upgrade-3dae7d91-cycle5')
BUNDLE = Path('/var/lib/devres-production-upgrades/3dae7d91-cycle5-20261118')
PRIOR = Path('/tmp/devres-upgrade-3dae7d91-20261117')
PRIOR_INSTALL = Path('/usr/local/libexec/devres-upgrade-3dae7d91')
PRIOR_BUNDLE = Path('/var/lib/devres-production-upgrades/3dae7d91-20261117')
LEGACY = WORK/'legacy-public-identity-builder.py'
LEGACY_SHA = '58c70e657bad9eb5fc3186486e38d4dc43d20e28c334779a591315661a35b2ef'
PRIOR_MANIFEST_SHA = 'a23b1015e38926627bfe2d8883d3ebe46d9c23dadcbe68ba1695529f0808be5e'
PRIOR_PUB_SHA = 'e102b153c9ab638ecaa1deaf3f5326129ed38f20a57cdcc37e03842da0f3ccf7'
PRIOR_RESULT_SHA = '6bcc40099f85336bd5713ad1aa1de8c9d60a8a9c1168c3810e0f87dfb0c3c8a8'
RESTORED_SHA = 'bd466f56be125f7f15aed1fc3b55a6a52a54cfdc8cfe37b5fb6a57364961b555'
STAGE_INVENTORY_SHA = '8f9cfd1fe9c40b190dd0ef093b6e51b97a731456ce8fbf65c8e150abc16284bf'
EDGE_SHA = 'e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a'
CACHE = Path('/tmp/devres-reclaim-discovery-3dae7d91-20261117')
PROBE = Path('/tmp/devres-public-probe-3dae7d91-cycle5-20261118/devres-probe')
PINS = {
    'source-manifest.json': PRIOR_MANIFEST_SHA,
    'public-upgrade-identity.json': PRIOR_PUB_SHA,
    'checkpoint-approval.json': '04613bbb6de95cf025265adc5234a957aabe8ac8bc478684ed2af7bed957f9cd',
    'store-claim-withdrawn-intent.json': 'fbee0ba6e6b1875df049a2abf351507f2afb86fa451327c0ac81bacf54a78d98',
    'source-store-claim-qualified.json': '272754f79ff98d0aef9026cd1394bc9be69d091379324ea8b9ee2f724355aff1',
}
STAGES = ['deploy-apply', 'deploy-migration-before-npm', 'deploy-start-writer']
STAGE_FILES = ['final-result.json', 'outcome.json', 'runtime.jsonl', 'stderr.log', 'stdout.log']


def need(value, code):
    if not value:
        raise RuntimeError(code)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def frozen_helpers():
    # The reviewed helper is preparation-only, never an imported runtime facade.
    need(not any(p.is_symlink() for p in (LEGACY, *LEGACY.parents)), 'legacy_helper_symlink')
    fd = os.open(LEGACY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and not s.st_mode & 0o077 and s.st_nlink == 1
             and 0 < s.st_size <= 128 * 1024, 'legacy_helper_private_source_required')
        body = stream.read(128 * 1024 + 1)
    need(sha(body) == LEGACY_SHA, 'legacy_helper_source_changed')
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('cycle5_public_frozen_helpers', loader=None))
    module.__file__ = str(LEGACY)
    exec(compile(body, str(LEGACY), 'exec'), module.__dict__)
    return module


def fresh(h, inputs):
    for path in (WORK/'public-upgrade-identity.json', WORK/'source-store-claim-qualified.json',
                 WORK/'checkpoint-approval.json', WORK/'store-claim-withdrawn-intent.json',
                 WORK/'store-claim-withdrawn-failed.json', WORK/'target', BUNDLE):
        h.canonical(path)
        inputs.absent(path)


def prior_cycle(h, inputs, prior):
    values = {name: inputs.json(PRIOR/name, wanted, private=True) for name, wanted in PINS.items()}
    intent, claim = values['store-claim-withdrawn-intent.json'], values['source-store-claim-qualified.json']
    need({k: intent.get(k) for k in ('method', 'maximum_attempts', 'reader_only', 'url')} == {
                    'method': 'GET', 'maximum_attempts': 1, 'reader_only': True,
                    'url': 'https://s3.fr-par.scw.cloud/dev-resources-mcp/production/store.json'}
         and intent.get('version') == 1 and intent.get('boundary_mode') == 'withdrawn',
         'prior_single_claim_intent_changed')
    # The exact receipt pin binds the body and prior native-helper request.
    need(claim.get('status') == 200 and claim.get('key') == 'production/store.json', 'prior_claim_changed')
    result = inputs.json(PRIOR/'target/deployment-result.json', PRIOR_RESULT_SHA, private=True)
    need(result == {'fallback_deployed': False, 'known_complete': False,
                    'outcome': 'target_failed_restored_withdrawn', 'runtime': 'restored',
                    'schema18_restored': True, 'target_deployed': False, 'withdrawal_completed': True},
         'prior_failed_restored_result_changed')
    restored = inputs.json(PRIOR_BUNDLE/'restore/restored.json', RESTORED_SHA, private=True)
    need(restored.get('verified') is True and restored.get('database_restored') is True
         and restored.get('schema') == 18 and restored.get('baseline_caches_restored') is True
         and restored.get('s3_rewound') is False and restored.get('fallback_accepted') is False
         and restored.get('preservation') == 'manifest_verified' and restored.get('preserved_directory') is True
         and restored.get('application_roles_stopped') is True,
         'prior_restoration_required')
    root = PRIOR/'target/command-evidence'
    need(inputs.directory(root) == STAGES, 'prior_public_or_extra_stage_present')
    rows = []
    for label in STAGES:
        directory = root/label
        need(inputs.files(directory) == STAGE_FILES, 'prior_stage_membership_changed')
        for name in STAGE_FILES:
            path = directory/name
            body = inputs.read(path, private=True, allow_empty=name == 'stderr.log')
            record = inputs.records[path][0]
            rows.append({'path': str(path.relative_to(root)), 'sha256': sha(body), 'bytes': len(body),
                         'uid': record[3], 'gid': record[4], 'mode': record[2] & 0o7777, 'links': record[5]})
            if name == 'final-result.json':
                value = h.decode(body)
                failed = label == 'deploy-migration-before-npm'
                status = value['supervision']
                need(value.get('version') == 1 and value.get('stage') == label
                     and value.get('runtime') == 'target' and value.get('final_outcome') is True
                     and status.get('code') == ('child_failed' if failed else 'ok')
                     and type(status.get('exit_code')) is int and status['exit_code'] == int(failed)
                     and all(status.get(k) is True for k in ('child_cleanup_complete', 'persisted', 'runtime_evidence_complete'))
                     and all(status.get(k) is False for k in ('timed_out', 'interrupted', 'truncated', 'descendant_pipes'))
                     and status.get('withdrawal_completed') is failed,
                     'prior_stage_result_changed')
    need(len(rows) == 15 and sha(h.encode(rows)) == STAGE_INVENTORY_SHA, 'prior_stage_inventory_changed')
    for runtime in ('target', 'fallback'):
        for name in ('paused-runner-intent.json', 'active-runner-intent.json',
                     'driver-activate-existing-intent.json', 'driver-finish-intent.json'):
            inputs.absent(PRIOR/runtime/name)
    ledger = copy.deepcopy(prior['prior_cycle_ledgers'])
    need(len(ledger) == 3, 'prior_history_count_changed')
    ledger.append({'cycle': '3dae7d91-20261117', 'source_manifest_sha256': PRIOR_MANIFEST_SHA,
                   'public_identity_sha256': PRIOR_PUB_SHA,
                   'checkpoint_approval_sha256': PINS['checkpoint-approval.json'],
                   'store_claim_intent_sha256': PINS['store-claim-withdrawn-intent.json'],
                   'store_claim_receipt_sha256': PINS['source-store-claim-qualified.json'],
                   's3_store_get_spent': 1, 'source_provider_requests_spent': 0, 'public_probe_stages_started': 0})
    return values['source-manifest.json'], ledger


def candidate(h, prior, dependencies, ledger, pins):
    result = copy.deepcopy(prior)
    result.update(controller_source_sha256=pins['controller'], source_manifest_sha256=pins['manifest'],
                  previous_cycle_source_manifest_sha256=PRIOR_MANIFEST_SHA,
                  dependency_sources=dependencies, previous_cycle_s3_store_get_spent=4,
                  counter_scope='cycle1_cycle2_cycle3_and_cycle4_only_legacy91_not_reset',
                  prior_cycle_ledgers=ledger, cycle5_render_manifest_sha256=pins['render'])
    changed = {k for k in prior if result[k] != prior[k]}
    need(changed == {'controller_source_sha256', 'source_manifest_sha256',
                    'previous_cycle_source_manifest_sha256', 'dependency_sources',
                    'previous_cycle_s3_store_get_spent', 'counter_scope', 'prior_cycle_ledgers'}
         and set(result)-set(prior) == {'cycle5_render_manifest_sha256'}, 'identity_diff_outside_allowlist')
    need(result['approved_new_cycle_s3_store_get_maximum'] == 1 and result['schema_before'] == 18,
         'single_cycle_schema18_scope_required')
    return result, sorted(changed | {'cycle5_render_manifest_sha256'})


def dependencies(h, prior, previous_manifest):
    result = copy.deepcopy(prior['dependency_sources'])
    need(len(result) == 29 and len(h.INSTALLED) == 8, 'exact_dependency_inventory_required')
    for name in sorted(h.INSTALLED):
        path = str(PRIOR_INSTALL/name)
        need(path not in result, 'prior_dependency_duplicate')
        result[path] = previous_manifest[name]
    need(len(result) == 37 and all(re.fullmatch('[0-9a-f]{64}', value or '') for value in result.values()),
         'exact_dependency_inventory_required')
    return result


def build(h, inputs, pins):
    need(all(re.fullmatch('[0-9a-f]{64}', v or '') for v in pins.values()), 'external_source_pins_required')
    need(os.environ.get('DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256') == pins['manifest']
         and os.environ.get('DEVRES_EDGE_READMISSION_SHA256') == EDGE_SHA
         and os.environ.get('KUBECACHEDIR') == str(CACHE), 'fixed_environment_required')
    initial = (h.identity(WORK), h.identity(INSTALL), h.identity(CACHE))
    fresh(h, inputs)
    inputs.read(LEGACY, LEGACY_SHA, private=True)
    inputs.read(Path('/var/lib/devres-production-edge-admissions/3dae7d91-20261117/admission.json'), EDGE_SHA, private=True)
    manifest = inputs.json(WORK/'source-manifest.json', pins['manifest'], private=True)
    need(set(manifest) == h.SOURCE_NAMES and len(manifest) == 29
         and manifest['upgrade-controller.py'] == pins['controller'], 'exact_current_source_inventory_required')
    for name, wanted in manifest.items():
        need(re.fullmatch('[0-9a-f]{64}', wanted or ''), 'source_hash_required')
        inputs.read((INSTALL if name in h.INSTALLED else WORK)/name, wanted, private=True)
    inputs.read(WORK/'render-manifest.json', pins['render'], private=True)
    inputs.read(WORK/'source.tar.gz', h.SOURCE_ARCHIVE_SHA, maximum=256*1024**2, private=True)
    need(manifest['target-native-qualification.json'] == h.NATIVE_JSON_SHA, 'native_qualification_changed')
    inputs.read(PROBE, h.NATIVE_ELF_SHA, maximum=64*1024**2)
    need(PROBE.stat().st_mode & 0o001, 'native_probe_executable_required')
    for parent in PROBE.parents:
        info = parent.stat()
        if parent == Path('/tmp'):
            need(info.st_uid == 0 and info.st_mode & stat.S_ISVTX, 'native_probe_tmp_required')
            break
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
             and not info.st_mode & 0o022 and info.st_mode & 0o001, 'native_probe_traversable_directory_required')
    prior = inputs.json(PRIOR/'public-upgrade-identity.json', PRIOR_PUB_SHA, private=True)
    old_prior = inputs.json(h.PRIOR/'public-upgrade-identity.json', h.PRIOR_PUB_SHA, private=True)
    old_ledger = h.ledgers(inputs, old_prior)
    old_dependencies = copy.deepcopy(old_prior['dependency_sources'])
    old_manifest = inputs.json(h.PRIOR/'source-manifest.json', h.PRIOR_MANIFEST_SHA, private=True)
    for name in h.SPECIAL:
        old_dependencies[str(h.PRIOR_INSTALL/name)] = old_manifest[name]
    expected_prior, _ = h.candidate_identity(old_prior, old_dependencies, old_ledger)
    need(prior == expected_prior and len(prior['dependency_sources']) == 29, 'prior_identity_or_ledger_changed')
    previous_manifest, ledger = prior_cycle(h, inputs, prior)
    need(set(previous_manifest) == h.SOURCE_NAMES and len(previous_manifest) == 29, 'prior_source_inventory_changed')
    for name, wanted in previous_manifest.items():
        inputs.read((PRIOR_INSTALL if name in h.INSTALLED else PRIOR)/name, wanted, private=True)
    source_dependencies = dependencies(h, prior, previous_manifest)
    for path, wanted in source_dependencies.items():
        inputs.read(Path(path), wanted)
    result, changed = candidate(h, prior, source_dependencies, ledger, pins)
    inputs.bookend()
    need(initial == (h.identity(WORK), h.identity(INSTALL), h.identity(CACHE)), 'environment_identity_changed')
    fresh(h, inputs)
    return result, changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--render-sha256', required=True)
    parser.add_argument('--controller-sha256', required=True)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    need(os.geteuid() == 0, 'root_required')
    h = frozen_helpers()
    inputs = h.Inputs()
    pins = {'manifest': args.manifest_sha256, 'render': args.render_sha256, 'controller': args.controller_sha256}
    result, changed = build(h, inputs, pins)
    body = h.encode(result)
    if args.write:
        fresh(h, inputs)
        fd = os.open(WORK/'public-upgrade-identity.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        need(inputs.read(WORK/'public-upgrade-identity.json', sha(body), private=True) == body, 'identity_readback_changed')
    print(json.dumps({'candidate_sha256': sha(body), 'changed_keys': changed,
                      'dependency_count': 37, 'ledger_count': 4, 'written': args.write}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'verified': False, 'code': 'public_identity_preparation_refused'}))
        sys.exit(1)
