#!/usr/bin/env python3
"""Render the fresh, restore-and-withdraw production cycle; never execute it."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
REVISION = '3dae7d914baa9379abc402c5a3bcf311e0db01bf'
VERSION = '0.1.0-build.3dae7d91'
WORK = '/tmp/devres-upgrade-3dae7d91-20261117'
BUNDLE = '/var/lib/devres-production-upgrades/3dae7d91-20261117'
INSTALL = '/usr/local/libexec/devres-upgrade-3dae7d91'
TRANSFER = '/tmp/devres-3dae7d91-transfer-20261117'
IMAGE = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:49a899c3c4f0b5d13532ff641f7583b329adea930d1e3877de07a3e5fde91d17'
PROBE = 'ghcr.io/publicdata-stream/dev-resources-probe@sha256:de8663204451207ede70d790942fa5903a640ecbd3430967915f806b15dc5f4f'
SOURCE_SHA = '8fbbe7978c6ebf061d803c38d7b8e79205e68433e0c0ed0eb5a59da2b22e0782'
PREVIOUS_CONTROLLER_SHA = 'b98d2a02804feba7ba12a45fc539879ef435c74951dbfd20a68d999b3a745957'
PREVIOUS_MANIFEST_SHA = '5dbf9d3be45cd6222eda9d36cc2d59b0dcd580b65143743933cc5d4b33a23a4b'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def need(value, code):
    if not value:
        raise RuntimeError(code)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def once(source, old, new):
    need(source.count(old) == 1, 'one_reviewed_transform_required:' + old[:64])
    return source.replace(old, new)


def function(source, name, replacement, cls=None):
    tree = ast.parse(source)
    nodes = tree.body if cls is None else next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls).body
    matches = [n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == name]
    need(len(matches) == 1, 'one_reviewed_function_required:' + name)
    lines = source.splitlines(keepends=True)
    node = matches[0]
    return ''.join(lines[:node.lineno - 1]) + replacement + '\n' + ''.join(lines[node.end_lineno:])


def render(output, previous_controller_sha, previous_manifest_sha):
    """Bind live predecessor hashes supplied after independent immutable checks."""
    import re
    need(all(re.fullmatch('[0-9a-f]{64}', v) for v in (previous_controller_sha, previous_manifest_sha)), 'previous_source_hashes_required')
    need((previous_controller_sha, previous_manifest_sha) == (PREVIOUS_CONTROLLER_SHA, PREVIOUS_MANIFEST_SHA), 'exact_withdrawn_predecessor_required')
    output = Path(output)
    need(output.is_absolute() and Path('/tmp') in output.parents and '..' not in output.parts
         and not any(p.is_symlink() for p in (output, *output.parents)) and not output.exists(), 'fresh_private_output_required')
    c3 = module('cycle4_frozen_renderer', HERE / 'cycle3_9373f71e.py')
    acceptance = module('cycle4_acceptance', HERE / 'cycle4_acceptance_3dae7d91.py')
    assessment = module('cycle4_assessment', HERE / 'cycle4_assessment_3dae7d91.py')
    substitutions = {
        c3.WORK: WORK, c3.BUNDLE: BUNDLE, c3.INSTALL: INSTALL,
        c3.TARGET_REVISION: REVISION, c3.TARGET_VERSION: VERSION,
        c3.TARGET_IMAGE: IMAGE, c3.TARGET_PROBE: PROBE, c3.TARGET_SOURCE_SHA: SOURCE_SHA,
        c3.CHECKPOINT_SCOPE: 'physical-pg-checkpoint-3dae7d91',
        c3.PROBE_DIRECTORIES['target']: '/tmp/devres-public-probe-3dae7d91-20261117',
        c3.PROBE_DIRECTORIES['fallback']: '/tmp/devres-public-probe-91c7bcb7-3dae7d91-20261117',
        'devres-npm-assessment-9373f71e': 'devres-npm-assessment-3dae7d91',
        '9373f71e-assessment': '3dae7d91-assessment',
    }
    source_map = dict(c3.SOURCE_MAP)
    source_map['deploy/diagnostics/npm_assessment.py'] = 'deploy/diagnostics/npm_assessment.py'
    source_map['edge-readmission.py'] = 'deploy/production/cycle4_edge_3dae7d91.py'
    source_map['edge-qualification.py'] = 'deploy/production/cycle4_edge_qualification_3dae7d91.py'
    output.mkdir(mode=0o700, parents=True)
    results = {}
    for name, path in sorted(source_map.items()):
        original = ((REPOSITORY / path).read_bytes() if name in ('edge-readmission.py', 'edge-qualification.py') else
            subprocess.run(['git', 'show', REVISION + ':' + path], cwd=REPOSITORY,
                           capture_output=True, timeout=30, check=True).stdout)
        # c3's exact transformations still own the immutable schema-19 baseline.
        body = original if name in ('deploy/diagnostics/npm_assessment.py', 'edge-readmission.py', 'edge-qualification.py') else c3.transform(name, original)
        source = body.decode()
        if name not in ('edge-readmission.py', 'edge-qualification.py'):
            for old, new in sorted(substitutions.items(), key=lambda x: -len(x[0])):
                source = source.replace(old, new)
        if name == 'upgrade-controller.py':
            histories = (*c3.HISTORIES, {'name': 'cycle3', 'work': c3.WORK, 'bundle': c3.BUNDLE,
                'install': c3.INSTALL, 'controller_sha256': previous_controller_sha,
                'manifest_sha256': previous_manifest_sha})
            source = once(source, 'HISTORIES=' + repr(c3.HISTORIES), 'HISTORIES=' + repr(histories))
            source = once(source, "PREVIOUS_REVISION='1d76fbcc5693efc9ca927fd05f942078f667f056'", 'PREVIOUS_REVISION=' + repr(c3.TARGET_REVISION))
            source = source.replace("'cycle':3", "'cycle':4")
            source = once(source, '        artifacts=self.prior_hashes()', '        observer_variants(variants)\n        artifacts=self.prior_hashes()')
            source = once(source,
                "'desired_active_source_sha256':digest(original),'previous_cycle_source_sha256':PREVIOUS_CONTROLLER_SHA,",
                "'desired_active_source_sha256':digest(original),'previous_cycle_source_sha256':PREVIOUS_CONTROLLER_SHA,\n"
                "            'edge_readmission_sha256':cycle4_edge_bridge()[1],")
            source = function(source, 'predecessor', '''def predecessor(context):
    bridge, receipt_sha = cycle4_edge_bridge()
    return bridge.load_controller(Path(PRIOR_CONTROLLER), PRIOR_SHA, PRIOR_BUNDLE, context, receipt_sha=receipt_sha)
''')
            source = function(source, 'previous_cycle', '''def previous_cycle(context):
    require(digest(read(PREVIOUS_CONTROLLER)) == PREVIOUS_CONTROLLER_SHA, 'previous_cycle_controller_changed')
    require(digest(read(PREVIOUS_WORK/'source-manifest.json')) == PREVIOUS_MANIFEST_SHA, 'previous_cycle_manifest_changed')
    bridge, receipt_sha = cycle4_edge_bridge()
    return bridge.load_controller(PREVIOUS_CONTROLLER, PREVIOUS_CONTROLLER_SHA,
        str(PREVIOUS_BUNDLE), context, receipt_sha=receipt_sha)
''')
            source = once(source, "        require(snap==previous.snapshot() and snap['pods']==before['pods'],'previous_cycle_runtime_changed')",
                "        historical = previous.snapshot()\n"
                "        require({**snap, 'edge': historical['edge']} == historical and snap['pods'] == before['pods'], 'previous_cycle_runtime_changed')")
            # Keep all base guards; extend their accepted observer/candidate shapes.
            source = once(source, "value.get('runtime') in ('target','fallback')", "value.get('runtime') in ('target','fallback','restored')")
            source = once(source, "value['configs'] in ('old','paused','active')", "value['configs'] in ('old','paused','active','observer')")
            source = once(source, "set(value['pods']) == {r for r,n in value['replicas'].items() if n}",
                "set(value['pods']) == ({r for r,n in value['replicas'].items() if n} | ({'status-observer'} if value.get('observer') else set()))")
            source = once(source, "for variant in ('paused','active','fallback-paused','fallback-active'):",
                "for variant in ('paused','active','fallback-paused','fallback-active','observer'):")
            source = once(source, "('old','paused','active','fallback-paused','fallback-active').index", "('old','paused','active','fallback-paused','fallback-active','observer').index")
            # Read-only observer receipts cannot masquerade as sole-writer receipts.
            source = once(source, "'policy2', 'sole_writer', 'read_only_serving', 'private_boundary', 'capture_notice_preserved', 'tool_contract'",
                "'policy2', 'paused_read_only_observer', 'no_publication_owner', 'read_only_serving', 'private_boundary', 'capture_notice_preserved', 'tool_contract'")
            source = once(source, "'policy2', 'sole_writer', 'private_boundary', 'public_http_both_families_revisions'",
                "'policy2', 'paused_read_only_observer', 'no_publication_owner', 'private_boundary', 'public_http_both_families_revisions'")
            old = """        elif operation == 'activate-existing':
            self.scale('backend', 0, 'activation-stop-backend')
            self.scale('writer', 0, 'activation-stop-writer')
            require(set(self.pods()) == {'postgres'}, 'owner_remaining')
            self.change_config('active', 'active-config')
            self.pacing_delay()
            self.scale('writer', 1, 'activation-start-writer')
            self.scale('backend', 1, 'activation-start-backend')"""
            new = """        elif operation == 'activate-existing':
            self.stop_observer()
            require(set(self.pods()) == {'postgres'}, 'owner_remaining')
            self.change_config('active', 'active-config')
            self.pacing_delay()
            self.scale('writer', 1, 'activation-start-writer')
            self.renew_active_migration()
            self.scale('backend', 1, 'activation-start-backend')"""
            source = once(source, old, new)
            runtime = (HERE / 'cycle4_runtime_3dae7d91.py').read_text()
            source = once(source, '\ndef main():', '\n' + runtime + '\n\ndef main():')
        elif name == 'npm-recovery.py':
            source = assessment.transform(source)
        elif name == 'acceptance_common.py':
            source = once(source, "'deploy/diagnostics/__init__.py', 'deploy/diagnostics/evidence.py', 'deploy/diagnostics/runner.py',",
                "'deploy/diagnostics/__init__.py', 'deploy/diagnostics/evidence.py', 'deploy/diagnostics/runner.py', 'deploy/diagnostics/npm_assessment.py',")
            source = once(source, "SPECIAL_NAMES = {'upgrade-controller.py': CONTROLLER,",
                "SPECIAL_NAMES = {'edge-readmission.py': CONTROLLER.parent / 'edge-readmission.py', 'edge-qualification.py': CONTROLLER.parent / 'edge-qualification.py', 'upgrade-controller.py': CONTROLLER,")
        elif name == 'safety-supervisor.py':
            source = function(source, 'fence', '''def fence(module, expected):
    current = state()
    controller_module = module.bound_module(module.CONTROLLER,
        module.manifest_sources()['upgrade-controller.py'], 'safety_exact_controller')
    controller = controller_module.Controller(str(BUNDLE), str(BUNDLE/'plan.json'), 'default')
    if current['phase'] == 'complete':
        controller.guard()
        return {'fenced': False, 'accepted_runtime': current['runtime']}
    if current['runtime'] == 'restored':
        controller.guard(); controller.storage_guard(18, owner=False)
        return {'fenced': True, 'schema18_restored': True, 'fallback_service_accepted': False}
    with controller.locked():
        controller.withdraw()
    if (BUNDLE/'rollback-intent.json').exists():
        return {'fenced': True, 'restore_incomplete': True, 'directory_identity_reconciliation_required': True}
    if not (BUNDLE/'accepted-backup.json').exists():
        return {'fenced': True, 'pre_activation_stopped': True}
    controller.rollback()
    return {'fenced': True, 'schema18_restored': state()['runtime'] == 'restored',
        'fallback_service_accepted': False}
''')
        source = acceptance.transform(name, source)
        ast.parse(source, filename=name)
        target = output / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(source.encode()); stream.flush(); os.fsync(stream.fileno())
        results[name] = {'source': path, 'source_sha256': digest(original), 'sha256': digest(source.encode()),
            'local': str(target), 'remote': str(Path(INSTALL if name in c3.SPECIAL_NAMES or name in ('edge-readmission.py', 'edge-qualification.py') else WORK) / name)}
    manifest = {'version': 1, 'release_commit': REVISION, 'renderer_sha256': digest(Path(__file__).read_bytes()),
        'transform_sources': {p.name: digest(p.read_bytes()) for p in [HERE / n for n in (
            'cycle3_9373f71e.py', 'cycle4_runtime_3dae7d91.py', 'cycle4_acceptance_3dae7d91.py',
            'cycle4_assessment_3dae7d91.py', 'cycle4_edge_3dae7d91.py', 'cycle4_edge_qualification_3dae7d91.py')]},
        'scope': {'work': WORK, 'bundle': BUNDLE, 'install': INSTALL, 'transfer': TRANSFER}, 'files': results}
    (output / 'render-manifest.json').write_bytes(encoded(manifest))
    (output / 'render-manifest.json').chmod(0o600)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--previous-controller-sha256', required=True)
    parser.add_argument('--previous-manifest-sha256', required=True)
    args = parser.parse_args()
    result = render(args.output, args.previous_controller_sha256, args.previous_manifest_sha256)
    print(json.dumps({'rendered': True, 'files': len(result), 'release_commit': REVISION}))


if __name__ == '__main__':
    main()
