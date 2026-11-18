#!/usr/bin/env python3
"""Prepare the ce5745e0 archive identity without issuing a store GET."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

WORK = Path('/tmp/devres-upgrade-ce5745e0-cycle6')
INSTALL = Path('/usr/local/libexec/devres-upgrade-ce5745e0-cycle6')
BUNDLE = Path('/var/lib/devres-production-upgrades/ce5745e0-cycle6')
PRIOR = Path('/tmp/devres-upgrade-3dae7d91-cycle5-20261118')
PRIOR_INSTALL = Path('/usr/local/libexec/devres-upgrade-3dae7d91-cycle5')
PRIOR_BUNDLE = Path('/var/lib/devres-production-upgrades/3dae7d91-cycle5-20261118')
PRIOR_MANIFEST = '607307c4dc64c90b9efedc14b709012843e1ee14d1842cb5e2b562b9a089d491'
PRIOR_PUBLIC = '6a8665c5a994bb148c831565af4747bb8ccbf9b48605314401c6566968986229'
PRIOR_RESTORE = '3cfa88baff2a2c4f074c066626c2f1bdad5bf3c699603a1733f9c28b3ccad0eb'
PRIOR_STATE = '7462e62c802d12bb9bf929956265a3cec63e9249f5944104e389fe4be066855d'
PRIOR_RESULT = '6bcc40099f85336bd5713ad1aa1de8c9d60a8a9c1168c3810e0f87dfb0c3c8a8'
PRIOR_APPROVAL = 'df88f92fbf34a0310b0626d6fc840ccbd995bc3c38da9f33b5c1f46dff62d10f'
PRIOR_INTENT = 'db17b61bbab2e85b9610733434263860ac52b851d845a9df906c67c56b9f9736'
PRIOR_CLAIM = 'bd88107bc5a98678169640528737810874653ddc078b41cb4bf605bbc40ffa47'
PRIOR_STAGE_SHA = '99c2e8c6759a709efa999b049e3a52e91e19f74ba763ed7f929699c5fed9ad80'
PRIOR_STAGES = ('deploy-apply', 'deploy-start-writer', 'deploy-migration-before-npm', 'deploy-npm-recovery')
STAGE_FILES = ('final-result.json', 'outcome.json', 'runtime.jsonl', 'stderr.log', 'stdout.log')
PROBE_AMD64 = 'sha256:9bb972afa8ae19697f7faf6d858f5242a21b94c3dfc0648bf7fb2897f111977b'
TARGET = {
    'version': '0.1.0-build.ce5745e0',
    'revision': 'ce5745e0a0a5914dad62cd24f8655276b6f780ce',
    'server_image': 'ghcr.io/publicdata-stream/dev-resources-server@sha256:05f8880386d7e96ddc75d165475ac410800932eb0848dbde99174182a125ac1f',
    'probe_image': 'ghcr.io/publicdata-stream/dev-resources-probe@sha256:563895fff1925afc00947659aafdc01dc4136cb76bd583a4772b2d73f811de08',
    'source_archive_sha256': '5b465a79e9f798457f7eb92dd3231ca97a8dfd5da8bab9aed0e4f3524ba9af77',
    'native_probe_sha256': 'f7b1b4f1d50b9d7a7cf96cee9c2616d0ac86ab57ddd1c134581d7472c9dfc732',
}
EDGE = 'e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a'
EDGE_RECEIPT = Path('/var/lib/devres-production-edge-admissions/3dae7d91-20261117/admission.json')
CACHE = '/tmp/devres-reclaim-discovery-3dae7d91-20261117'
PROBE = Path('/tmp/devres-public-probe-ce5745e0-cycle6/devres-probe')


def need(value, code):
    if not value:
        raise RuntimeError(code)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_record(path, *, private=True, maximum=8*1024**2, allow_empty=False):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'canonical_file_required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
             and not before.st_mode & (0o077 if private else 0o022)
             and (0 if allow_empty else 1) <= before.st_size <= maximum,
             'bound_file_authority_changed')
        body = stream.read(maximum + 1)
        need(len(body) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
             and identity(before) == identity(path.stat(follow_symlinks=False)),
             'bound_file_changed')
    return body, before


def read(path, expected, *, private=True, maximum=8*1024**2):
    need(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected), 'exact_digest_required')
    body, _ = file_record(path, private=private, maximum=maximum)
    need(digest(body) == expected, 'bound_file_hash_changed')
    return body


def current_closure(manifest_hash, render_hash, own_hash):
    read(Path(__file__), own_hash)
    render = json.loads(read(WORK / 'render-manifest.json', render_hash))
    manifest = json.loads(read(WORK / 'source-manifest.json', manifest_hash))
    need(render['cycle'] == 6 and render['release_commit'] == TARGET['revision']
         and render['previous_manifest_sha256'] == PRIOR_MANIFEST
         and render['files']['source-manifest.json']['sha256'] == manifest_hash
         and render['files']['prepare-public-identity.py']['sha256'] == own_hash, 'fixed_render_required')
    path = WORK / 'acceptance_common.py'
    body = read(path, manifest[path.name])
    spec = importlib.util.spec_from_file_location('cycle6_identity_bound_common', path)
    common = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = common
    exec(compile(body, str(path), 'exec'), common.__dict__)
    need(common.ROOT == WORK and common.CONTROLLER.parent == INSTALL and common.BUNDLE == BUNDLE
         and common.REVISION == TARGET['revision'], 'fixed_acceptance_common_required')
    need(common.manifest_sources(manifest_hash) == manifest and len(manifest) == 29, 'exact_candidate_source_set_required')
    for name, expected in manifest.items():
        path = common.SPECIAL_NAMES.get(name, WORK / name)
        need(render['files'][name] == {'remote': str(path), 'sha256': expected}, 'render_manifest_binding_changed')
    read(WORK / 'source.tar.gz', TARGET['source_archive_sha256'], maximum=256*1024**2)
    read(PROBE, TARGET['native_probe_sha256'], private=False, maximum=64*1024**2)
    need(PROBE.stat().st_mode & 0o001, 'probe_executable_required')
    for path in PROBE.parents:
        info = path.stat()
        if path == Path('/tmp'):
            need(info.st_uid == 0 and info.st_mode & stat.S_ISVTX, 'probe_tmp_boundary_changed')
            break
        need(info.st_uid == 0 and not info.st_mode & 0o022 and info.st_mode & 0o001, 'probe_path_authority_changed')
    qualification = common.runtime_qualification()
    need(qualification['binary_sha256'] == TARGET['native_probe_sha256'] and qualification['image'] == TARGET['probe_image']
         and qualification['platform_manifest_digest'] == PROBE_AMD64 and qualification['anonymous_full_pull'] is True,
         'target_native_qualification_changed')
    return common, manifest


def prior_stage_inventory():
    root = PRIOR / 'target/command-evidence'
    need({p.name for p in root.iterdir()} == set(PRIOR_STAGES), 'exact_previous_stages_required')
    rows = []
    for stage in PRIOR_STAGES:
        directory = root / stage
        need({p.name for p in directory.iterdir()} == set(STAGE_FILES), 'previous_stage_files_changed')
        for name in STAGE_FILES:
            path = directory / name
            body, info = file_record(path, allow_empty=name.endswith('.log'))
            rows.append({'path': str(path.relative_to(root)), 'sha256': digest(body), 'bytes': info.st_size,
                         'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'links': info.st_nlink})
            if name == 'final-result.json':
                value = json.loads(body)
                status = value['supervision']
                failed = stage == 'deploy-npm-recovery'
                need(value['stage'] == stage and value['runtime'] == 'target' and value['final_outcome'] is True
                     and status['code'] == ('child_failed' if failed else 'ok')
                     and type(status['exit_code']) is int and status['exit_code'] == int(failed)
                     and status['withdrawal_completed'] is failed
                     and all(status[k] is True for k in ('child_cleanup_complete', 'persisted', 'runtime_evidence_complete'))
                     and all(status[k] is False for k in ('timed_out', 'interrupted', 'truncated', 'descendant_pipes')),
                     'previous_stage_result_changed')
    need(len(rows) == 20 and digest(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()) == PRIOR_STAGE_SHA,
         'previous_stage_inventory_changed')
    for runtime in ('target', 'fallback'):
        for name in ('paused-runner-intent.json', 'active-runner-intent.json',
                     'driver-activate-existing-intent.json', 'driver-finish-intent.json'):
            need(not os.path.lexists(PRIOR / runtime / name), 'previous_acceptance_intent_present')


def historical(common):
    prior = json.loads(read(PRIOR / 'public-upgrade-identity.json', PRIOR_PUBLIC))
    manifest = json.loads(read(PRIOR / 'source-manifest.json', PRIOR_MANIFEST))
    need(len(manifest) == 29 and set(manifest) == common.SOURCE_NAMES | set(common.SPECIAL_NAMES),
         'exact_previous_source_set_required')
    need(prior['source_manifest_sha256'] == PRIOR_MANIFEST and
         prior['controller_source_sha256'] == manifest['upgrade-controller.py'] and
         prior['approved_new_cycle_s3_store_get_maximum'] == 1 and prior['schema_before'] == 18 and
         prior['previous_cycle_s3_store_get_spent'] == 4 and len(prior['prior_cycle_ledgers']) == 4,
         'exact_previous_identity_required')
    dependencies = dict(prior['dependency_sources'])
    need(len(dependencies) == 37, 'exact_previous_dependencies_required')
    for name, expected in manifest.items():
        path = (PRIOR_INSTALL if name in common.SPECIAL_NAMES else PRIOR) / name
        read(path, expected)
        if name in common.SPECIAL_NAMES:
            need(str(path) not in dependencies, 'previous_dependency_collision')
            dependencies[str(path)] = expected
    need(len(dependencies) == 45, 'exact_candidate_dependencies_required')
    for name, expected in dependencies.items():
        path = Path(name)
        need(path.is_relative_to('/usr/local/libexec') and path.suffix == '.py', 'fixed_dependency_file_required')
        read(path, expected, private=False)
    restored = json.loads(read(PRIOR_BUNDLE / 'restore/restored.json', PRIOR_RESTORE))
    state = json.loads(read(PRIOR_BUNDLE / 'state.json', PRIOR_STATE))
    result = json.loads(read(PRIOR / 'target/deployment-result.json', PRIOR_RESULT))
    need(restored['schema'] == 18 and restored['verified'] is True and restored['preserved_directory'] is True
         and restored['baseline_caches_restored'] is True and restored['application_roles_stopped'] is True
         and restored['s3_rewound'] is False and result['outcome'] == 'target_failed_restored_withdrawn'
         and state['phase'] == 'withdrawn' and state['runtime'] == 'restored'
         and state['restore_receipt_sha256'] == PRIOR_RESTORE, 'completed_previous_withdrawal_required')
    read(PRIOR / 'checkpoint-approval.json', PRIOR_APPROVAL)
    intent = json.loads(read(PRIOR / 'store-claim-withdrawn-intent.json', PRIOR_INTENT))
    claim = json.loads(read(PRIOR / 'source-store-claim-qualified.json', PRIOR_CLAIM))
    need(intent['method'] == 'GET' and intent['maximum_attempts'] == 1 and intent['reader_only'] is True
         and claim['status'] == 200 and claim['key'] == 'production/store.json', 'previous_single_store_claim_required')
    prior_stage_inventory()
    ledger = [*prior['prior_cycle_ledgers'], {
        'cycle': '3dae7d91-cycle5-20261118', 'source_manifest_sha256': PRIOR_MANIFEST,
        'public_identity_sha256': PRIOR_PUBLIC, 'checkpoint_approval_sha256': PRIOR_APPROVAL,
        'store_claim_intent_sha256': PRIOR_INTENT, 'store_claim_receipt_sha256': PRIOR_CLAIM,
        's3_store_get_spent': 1, 'source_provider_requests_spent': 0, 'public_probe_stages_started': 0,
    }]
    return prior, dependencies, ledger


def prepare(manifest_sha, render_sha, own_sha, write):
    need(os.geteuid() == 0 and os.environ.get('DEVRES_ACCEPTANCE_RUNTIME') == 'target'
         and os.environ.get('DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256') == manifest_sha
         and os.environ.get('DEVRES_EDGE_READMISSION_SHA256') == EDGE and os.environ.get('KUBECACHEDIR') == CACHE,
         'explicit_root_cycle_environment_required')
    absent = [BUNDLE, WORK / 'public-upgrade-identity.json', WORK / 'target', WORK / 'source-store-claim-qualified.json',
              WORK / 'checkpoint-approval.json', WORK / 'store-claim-withdrawn-intent.json',
              WORK / 'store-claim-withdrawn-failed.json']
    need(not any(os.path.lexists(path) for path in absent), 'fresh_cycle_only')
    read(EDGE_RECEIPT, EDGE)
    common, manifest = current_closure(manifest_sha, render_sha, own_sha)
    prior, dependencies, ledger = historical(common)
    candidate = dict(prior, revision=TARGET['revision'], target_release=TARGET,
                     controller_source_sha256=manifest['upgrade-controller.py'], source_manifest_sha256=manifest_sha,
                     previous_cycle_source_manifest_sha256=PRIOR_MANIFEST, dependency_sources=dependencies,
                     previous_cycle_s3_store_get_spent=5,
                     counter_scope='cycles_1_through_5_only_legacy91_not_reset', prior_cycle_ledgers=ledger,
                     cycle6_render_manifest_sha256=render_sha)
    body = json.dumps(candidate, sort_keys=True, separators=(',', ':')).encode()
    need(not any(os.path.lexists(path) for path in absent), 'cycle_admission_changed')
    if write:
        path = WORK / 'public-upgrade-identity.json'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        read(path, digest(body))
    return {'candidate_sha256': digest(body), 'historical_dependencies': len(dependencies),
            'historical_ledger_rows': len(ledger), 'written': write}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--render-sha256', required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    result = prepare(args.manifest_sha256, args.render_sha256, args.source_sha256, args.write)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'verified': False, 'code': 'public_identity_preparation_refused'}))
        sys.exit(1)
