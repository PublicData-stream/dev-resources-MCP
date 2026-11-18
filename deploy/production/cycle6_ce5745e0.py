#!/usr/bin/env python3
"""Render the ce5745e0 production cycle into an exclusively created /tmp directory."""

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile

import cycle5_3dae7d91 as predecessor
from cycle6_assessment_ce5745e0 import ASSESSMENT_HELPER_PATH, ASSESSMENT_HELPER_SHA256, patch_assessment
from cycle6_restore_ce5745e0 import patch_restore

HERE = Path(__file__).resolve().parent
WORK = '/tmp/devres-upgrade-ce5745e0-cycle6'
BUNDLE = '/var/lib/devres-production-upgrades/ce5745e0-cycle6'
INSTALL = '/usr/local/libexec/devres-upgrade-ce5745e0-cycle6'
PROBE_DIRECTORY = '/tmp/devres-public-probe-ce5745e0-cycle6'
REVISION = 'ce5745e0a0a5914dad62cd24f8655276b6f780ce'
VERSION = '0.1.0-build.ce5745e0'
IMAGE = 'ghcr.io/publicdata-stream/dev-resources-server@sha256:05f8880386d7e96ddc75d165475ac410800932eb0848dbde99174182a125ac1f'
SERVER_AMD64 = 'sha256:eaf15f4bf4ab402ffbf2376c3dc2b050dbe5aad7335f86f2662bd0c35634f57d'
PROBE = 'ghcr.io/publicdata-stream/dev-resources-probe@sha256:563895fff1925afc00947659aafdc01dc4136cb76bd583a4772b2d73f811de08'
PROBE_AMD64 = 'sha256:9bb972afa8ae19697f7faf6d858f5242a21b94c3dfc0648bf7fb2897f111977b'
PROBE_ELF_SHA = 'f7b1b4f1d50b9d7a7cf96cee9c2616d0ac86ab57ddd1c134581d7472c9dfc732'
SOURCE_SHA = '5b465a79e9f798457f7eb92dd3231ca97a8dfd5da8bab9aed0e4f3524ba9af77'
SMOKE_SHA = '0a7db0771b066e5cb74e08c3a7d01d5098da0eea0962c67ccaa8271d63e7e601'
PREVIOUS_CONTROLLER_SHA = '53fe422ef58dfd34183a9dc0851ddd6700af9bf1eea2b7b929f5fb71fbc3b9bf'
PREVIOUS_MANIFEST_SHA = '607307c4dc64c90b9efedc14b709012843e1ee14d1842cb5e2b562b9a089d491'
PREVIOUS_PUBLIC_SHA = '6a8665c5a994bb148c831565af4747bb8ccbf9b48605314401c6566968986229'
PREVIOUS_STATE_SHA = '7462e62c802d12bb9bf929956265a3cec63e9249f5944104e389fe4be066855d'
PREVIOUS_RESTORE_SHA = '3cfa88baff2a2c4f074c066626c2f1bdad5bf3c699603a1733f9c28b3ccad0eb'
PREVIOUS_NATIVE_SHA = '2f4cb61ae4d0f1e14d2843a57346aaf6932ed082fe97489aa0ec72537c627cc1'
FROZEN_EDGE = {'edge-readmission.py', 'edge-qualification.py'}
previous = predecessor.c4
need, once, function = previous.need, previous.once, previous.function


def sha(body):
    return hashlib.sha256(body).hexdigest()


def release_members(body):
    need(sha(body) == SOURCE_SHA, 'exact_candidate_source_archive_required')
    prefix = f'dev-resources-MCP-{VERSION}/'
    members = {
        prefix + 'scripts/mcp_smoke.py': ('mcp_smoke.py', SMOKE_SHA),
        prefix + ASSESSMENT_HELPER_PATH: (ASSESSMENT_HELPER_PATH, ASSESSMENT_HELPER_SHA256),
    }
    result = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        for item in archive:
            if item.name not in members:
                continue
            name, expected = members[item.name]
            need(name not in result and item.isfile() and 0 < item.size < 1024**2, 'invalid_candidate_source_member')
            with archive.extractfile(item) as stream:
                source = stream.read(1024**2)
            need(len(source) == item.size and sha(source) == expected, 'candidate_source_member_changed')
            result[name] = source
    need(len(result) == len(members), 'candidate_source_member_missing')
    return result


def replace_assignment(source, key, change):
    assignments = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == key]
    need(len(assignments) == 1, 'fixed_predecessor_assignment_required')
    node = assignments[0]
    return once(source, ast.get_source_segment(source, node), f'{key} = {change(ast.literal_eval(node.value))!r}')


def controller_source(source):
    history = {'name': 'cycle5', 'work': predecessor.WORK, 'bundle': predecessor.BUNDLE,
               'install': predecessor.INSTALL, 'controller_sha256': PREVIOUS_CONTROLLER_SHA,
               'manifest_sha256': PREVIOUS_MANIFEST_SHA}
    source = replace_assignment(source, 'HISTORIES', lambda value: (*value, history))
    for key in ('HISTORY_SPECIAL_NAMES', 'HISTORY_SOURCE_NAMES'):
        source = replace_assignment(source, key, lambda value: {**value, 'cycle5': value['cycle4']})
    source = function(source, 'previous_cycle', 'def previous_cycle(context):\n    return cycle6_previous_controller(context)\n')
    # Withdrawn workload preimages carry the former target. The old reader and
    # writer image remains separately pinned by the isolated checkpoint proof.
    source = once(source, "and all(value['images'][r] in (OLD_IMAGE,IMAGE) for r in ROLES)",
                  "and all(value['images'][r] in (PREVIOUS_IMAGE, IMAGE) for r in ROLES)")
    source = once(source, 'image in (OLD_IMAGE,IMAGE) if withdrawing', 'image in (PREVIOUS_IMAGE, IMAGE) if withdrawing')
    source = once(source, 'image in (OLD_IMAGE, IMAGE), \'withdraw_deployment_boundary\'',
                  'image in (PREVIOUS_IMAGE, IMAGE), \'withdraw_deployment_boundary\'')
    source = once(source, "initial_images = {'postgres': PG_IMAGE, 'writer': IMAGE, 'backend': IMAGE}",
                  "initial_images = {'postgres': PG_IMAGE, 'writer': PREVIOUS_IMAGE, 'backend': PREVIOUS_IMAGE}")
    source = once(source, "require(before['revision'] == REVISION", "require(before['revision'] == PREVIOUS_REVISION")
    source = once(source, "original = read(C5_PREVIOUS_BUNDLE / 'configs-fallback-active.json')",
                  "original = read(PREVIOUS_BUNDLE / 'configs-fallback-active.json')")
    source = once(source, "previous_prepared = load(C5_PREVIOUS_BUNDLE / 'prepared.json')",
                  "previous_prepared = load(PREVIOUS_BUNDLE / 'prepared.json')")
    source = once(source, "'captured_at': observed, 'cycle': 5", "'captured_at': observed, 'cycle': 6")
    source = once(source, "'previous_cycle_source_sha256': C5_PREVIOUS_CONTROLLER_SHA",
                  "'previous_cycle_source_sha256': PREVIOUS_CONTROLLER_SHA")
    source = once(source, "        if operation == 'apply':\n            self.require_operational_baseline()",
                  "        if operation not in ('prepare', 'stop'):\n            require_service_unit(require)\n"
                  "        if operation == 'apply':\n            self.require_operational_baseline()")
    source = once(source, "            require((self.root / 'npm-assessment-completed.json').exists(), 'assessment_required')",
                  "            cycle6_check_assessment(self)")
    source = once(source, "        state = self.state(); state.update(runtime='restored', phase='withdrawn', configs='old',",
                  "        cycle6_restore_template_images(self, prepared)\n"
                  "        state = self.state()\n"
                  "        state['images'] = prepared['initial_images']\n"
                  "        state.update(runtime='restored', phase='withdrawn', configs='old',")
    constants = (f'PREVIOUS_IMAGE = {previous.IMAGE!r}\n'
                 f'PREVIOUS_STATE_SHA = {PREVIOUS_STATE_SHA!r}\n'
                 f'PREVIOUS_RESTORE_SHA = {PREVIOUS_RESTORE_SHA!r}\n')
    additions = (HERE / 'cycle6_runtime_ce5745e0.py').read_text()
    return once(source, '\ndef main():', '\n' + constants + service_gate() + additions + '\n\ndef main():')


def checkpoint_source(source):
    source = once(source, 'type(previous) is dict and len(previous)==29', 'type(previous) is dict and len(previous)==37')
    source = once(source, 'len(expected)==37', 'len(expected)==45')
    source = source.replace('exact_cycle5_dependency_union_required', 'exact_cycle6_dependency_union_required')
    source = source.replace('cycle5_dependency_union(', 'cycle6_dependency_union(')
    source = once(source, repr(previous.WORK), repr(predecessor.WORK))
    need(source.count(repr(previous.INSTALL)) == 2, 'fixed_checkpoint_dependency_paths_required')
    source = source.replace(repr(previous.INSTALL), repr(predecessor.INSTALL))
    source = once(source, predecessor.PREVIOUS_PUBLIC_SHA, PREVIOUS_PUBLIC_SHA)
    return once(source, predecessor.PREVIOUS_MANIFEST_SHA, PREVIOUS_MANIFEST_SHA)


def service_gate():
    return '''

def require_service_unit(check):
    import re
    unit = 'devres-upgrade-ce5745e0-cycle6.service'
    invocation = os.environ.get('INVOCATION_ID', '')
    group = Path('/proc/self/cgroup').read_text().splitlines()
    check(re.fullmatch('[0-9a-f]{32}', invocation) and
          any(row.rsplit(':', 1)[-1] == '/system.slice/' + unit for row in group),
          'fixed_systemd_invocation_required')
    return unit


'''


def launch_gate():
    return service_gate() + f'''
def require_launch_intent(common):
    unit = require_service_unit(common.need)
    intent = json.loads(common.private_bytes(common.BUNDLE / 'launch-intent.json'))
    common.need(intent.get('version') == 1 and intent.get('kind') == 'cycle6-launch-intent'
                and intent.get('approved') is True and intent.get('runtime') == 'target'
                and intent.get('unit') == unit and intent.get('maximum_attempts') == 1
                and intent.get('target') == {{'commit': {REVISION!r}, 'version': {VERSION!r}, 'image': {IMAGE!r}}}
                and intent.get('edge_receipt_sha256') == {predecessor.EDGE_RECEIPT_SHA!r}
                and intent.get('source_manifest_sha256') == os.environ['DEVRES_ACCEPTANCE_SOURCE_MANIFEST_SHA256'],
                'fixed_launch_intent_required')
    for key, path in {{'approval_sha256': common.BUNDLE / 'launch-approval.json',
                       'rehearsal_sha256': common.ROOT / 'restore-rehearsal-receipt.json',
                       'launcher_sha256': common.CONTROLLER.parent / 'launch.py',
                       'supervisor_sha256': common.CONTROLLER.parent / 'safety-supervisor.py'}}.items():
        common.need(intent.get(key) == common.sha(common.private_bytes(path)), 'launch_intent_input_changed')


def target_mutation_admitted(common, controller):
    # The paused Secret writes are the first mutation of any target resource.
    # An intent is durable before the API call, including an uncertain response.
    seen = False
    for role in ('backend', 'writer'):
        label = 'target-paused-config-' + role
        path = controller.root / (label + '-intent.json')
        if os.path.lexists(path):
            intent = json.loads(common.private_bytes(path))
            common.need(set(intent) == {{'version', 'label', 'at', 'maximum_attempts'}}
                        and intent['version'] == 1 and intent['label'] == label
                        and intent['maximum_attempts'] == 1, 'target_mutation_intent_changed')
            seen = True
    if seen:
        backup = json.loads(common.private_bytes(controller.root / 'accepted-backup.json'))
        common.need(backup.get('verified') is True and backup.get('schema') == 18
                    and backup.get('revision') == common.REVISION
                    and backup.get('prepared_sha256') == controller.state()['prepared_sha256'],
                    'target_mutation_backup_binding_changed')
    return seen


def verify_preactivation_withdrawal(common, controller):
    controller.guard()
    state = controller.state()
    prepared = json.loads(common.private_bytes(controller.root / 'prepared.json'))
    common.need(state['configs'] == 'old' and state['images'] == prepared['initial_images'],
                'preactivation_boundary_uncertain')
    controller.storage_guard(18, owner=False)


'''


def deploy_source(source):
    source = once(source, '    sources = common.manifest_sources(manifest_sha)',
                  '    common.require_launch_intent(common)\n    sources = common.manifest_sources(manifest_sha)')
    source = once(source, "    common.need(enforce_withdrawal(controller), 'withdrawal_incomplete')\n    controller.rollback()",
                  "    common.need(enforce_withdrawal(controller), 'withdrawal_incomplete')\n"
                  "    if not common.target_mutation_admitted(common, controller):\n"
                  "        common.verify_preactivation_withdrawal(common, controller)\n        return False\n"
                  "    controller.rollback()")
    source = once(source, '            recover_target(controller)',
                  "            if not recover_target(controller):\n"
                  "                return {'known_complete': False, 'target_deployed': False, 'fallback_deployed': False,\n"
                  "                        'runtime': 'target', 'outcome': 'pre_activation_withdrawn',\n"
                  "                        'withdrawal_completed': True, 'schema18_restored': False}")
    return once(source, '                fenced = enforce_withdrawal(controller)',
                "                if (controller.root / 'rollback-intent.json').exists():\n"
                "                    with controller.locked():\n"
                "                        controller.restore_guard(stage='reconciliation-required')\n"
                "                    fenced = True\n"
                "                else:\n                    fenced = enforce_withdrawal(controller)")


def transform(name, source):
    if name in FROZEN_EDGE:
        return source
    for old, new in {
        predecessor.WORK: WORK, predecessor.BUNDLE: BUNDLE, predecessor.INSTALL: INSTALL,
        '/tmp/devres-public-probe-3dae7d91-cycle5-20261118': PROBE_DIRECTORY,
        'devres-npm-assessment-3dae7d91-c5': 'devres-npm-assessment-ce5745e0-c6',
        '3dae7d91-cycle5-assessment': 'ce5745e0-cycle6-assessment',
        'physical-pg-checkpoint-3dae7d91-cycle5': 'physical-pg-checkpoint-ce5745e0-cycle6',
        previous.VERSION: VERSION, previous.IMAGE: IMAGE, previous.PROBE: PROBE,
        previous.SOURCE_SHA: SOURCE_SHA,
    }.items():
        source = source.replace(old, new)
    # Keep the consumed release identity in the explicit predecessor binding.
    source = source.replace(f"= '{previous.REVISION}'", f"= '{REVISION}'")
    if name == 'upgrade-controller.py':
        return controller_source(source)
    if name == 'physical-checkpoint.py':
        return checkpoint_source(source)
    if name == 'npm-recovery.py':
        return patch_assessment(source)
    if name == 'restore-controller.py':
        return patch_restore(source)
    if name == 'acceptance_common.py':
        source = once(source, "if RUNTIME not in RUNTIMES:", "if RUNTIME != 'target':")
        return once(source, '\ndef controller():', '\n' + launch_gate() + 'def controller():')
    if name == 'deploy.py':
        return deploy_source(source)
    if name == 'phase-driver.py':
        return once(source, "    common.need(operation in OPS, 'fixed_phase_required')\n",
                    "    common.need(operation in OPS, 'fixed_phase_required')\n"
                    "    if operation != 'stop':\n        common.require_service_unit(common.need)\n")
    if name == 'safety-supervisor.py':
        source = once(source, "    if args.operation=='run':return run(module,args.source_manifest_sha256)",
                      "    if args.operation=='run':\n"
                      "        module.require_launch_intent(module)\n"
                      "        return run(module,args.source_manifest_sha256)\n"
                      "    module.require_service_unit(module.need)")
        source = once(source, "        return {'fenced': False, 'accepted_runtime': current['runtime']}",
                      "        path = ROOT / 'target/deployment-result.json'\n"
                      "        if not path.exists():\n"
                      "            return {'fenced': False, 'acceptance_evidence_incomplete': True}\n"
                      "        result = json.loads(module.private_bytes(path))\n"
                      "        module.need(result == {'known_complete': True, 'target_deployed': True,\n"
                      "                    'fallback_deployed': False, 'runtime': 'target', 'revision': module.REVISION,\n"
                      "                    'outcome': 'target_accepted'}, 'accepted_deployment_result_changed')\n"
                      "        return {'fenced': False, 'accepted_runtime': current['runtime']}")
        source = once(source, "    return 1 if result.get('restore_incomplete') else 0",
                      "    return 1 if result.get('restore_incomplete') or result.get('acceptance_evidence_incomplete') else 0")
        source = once(source, "    if not (BUNDLE/'accepted-backup.json').exists():\n        return {'fenced': True, 'pre_activation_stopped': True}",
                      "    if not module.target_mutation_admitted(module, controller):\n"
                      "        module.verify_preactivation_withdrawal(module, controller)\n"
                      "        return {'fenced': True, 'pre_activation_stopped': True}")
        return once(source, "    with controller.locked():\n        controller.withdraw()\n    if (BUNDLE/'rollback-intent.json').exists():\n        return {'fenced': True, 'restore_incomplete': True, 'directory_identity_reconciliation_required': True}",
                    "    if (BUNDLE/'rollback-intent.json').exists():\n"
                    "        with controller.locked():\n"
                    "            controller.restore_guard(stage='reconciliation-required')\n"
                    "        return {'fenced': True, 'restore_incomplete': True, 'directory_identity_reconciliation_required': True}\n"
                    "    with controller.locked():\n        controller.withdraw()")
    return source


def private_write(output, name, body):
    target = output / name
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    return sha(body)


def read_bounded(path, maximum):
    with Path(path).open('rb') as stream:
        data = stream.read(maximum + 1)
    need(0 < len(data) <= maximum, 'bounded_render_input_required')
    return data


def render(output, source_archive, probe, target_qualification, fallback_qualification):
    output = Path(output)
    need(output.is_absolute() and Path('/tmp') in output.parents and '..' not in output.parts
         and not any(p.is_symlink() for p in (output, *output.parents)) and not output.exists(), 'fresh_private_output_required')
    archive = read_bounded(source_archive, 256*1024**2)
    release_sources = release_members(archive)
    probe_bytes = read_bounded(probe, 64*1024**2)
    need(sha(probe_bytes) == PROBE_ELF_SHA, 'published_native_probe_required')
    target_bytes = read_bounded(target_qualification, 1024**2)
    fallback_bytes = read_bounded(fallback_qualification, 1024**2)
    need(sha(fallback_bytes) == PREVIOUS_NATIVE_SHA, 'frozen_isolated_native_metadata_required')
    value = json.loads(target_bytes)
    need(value.get('anonymous_full_pull') is True and
         {k: value.get(k) for k in ('commit', 'architecture', 'binary_sha256', 'image', 'platform_manifest_digest')} ==
         {'commit': REVISION, 'architecture': 'amd64', 'binary_sha256': PROBE_ELF_SHA,
          'image': PROBE, 'platform_manifest_digest': PROBE_AMD64}, 'target_native_qualification_changed')
    staged = {}
    with tempfile.TemporaryDirectory(prefix='cycle6-base-', dir='/tmp') as scratch:
        files = predecessor.render(Path(scratch) / 'closure', predecessor.PREVIOUS_CONTROLLER_SHA,
                                   predecessor.PREVIOUS_MANIFEST_SHA)
        need(files['upgrade-controller.py']['sha256'] == PREVIOUS_CONTROLLER_SHA, 'exact_frozen_render_base_required')
        for name, item in files.items():
            body = release_sources.get(name)
            if body is None:
                body = transform(name, Path(item['local']).read_text()).encode()
            ast.parse(body, filename=name)
            directory = INSTALL if Path(item['remote']).parent == Path(predecessor.INSTALL) else WORK
            staged[name] = (body, str(Path(directory) / name))
    for name, body in (('target-native-qualification.json', target_bytes), ('fallback-native-qualification.json', fallback_bytes)):
        staged[name] = (body, str(Path(WORK) / name))
    need(len(staged) == 29, 'exact_candidate_source_inventory_required')
    manifest = {name: sha(body) for name, (body, _) in staged.items()}
    extras = {
        'source.tar.gz': (archive, str(Path(WORK) / 'source.tar.gz')),
        'devres-probe': (probe_bytes, str(Path(PROBE_DIRECTORY) / 'devres-probe')),
        'source-manifest.json': (previous.encoded(manifest), str(Path(WORK) / 'source-manifest.json')),
    }
    for local, remote, directory in (
        ('cycle6_identity_ce5745e0.py', 'prepare-public-identity.py', WORK),
        ('cycle6_launch_ce5745e0.py', 'launch.py', INSTALL),
        ('cycle6_reclaim_ce5745e0.py', 'reclaim.py', INSTALL),
        ('cycle5_reclaim_3dae7d91.py', 'reclaim-engine.py', INSTALL),
    ):
        body = (HERE / local).read_bytes()
        ast.parse(body, filename=local)
        extras[remote] = (body, str(Path(directory) / remote))
    output.mkdir(mode=0o700)
    artifacts = {}
    for name, (body, remote) in sorted({**staged, **extras}.items()):
        artifacts[name] = {'sha256': private_write(output, name, body), 'remote': remote}
    rendered = {'version': 1, 'cycle': 6, 'release_commit': REVISION, 'renderer_sha256': sha(Path(__file__).read_bytes()),
                'previous_manifest_sha256': PREVIOUS_MANIFEST_SHA, 'files': artifacts}
    private_write(output, 'render-manifest.json', previous.encoded(rendered))
    return rendered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'source-archive', 'probe', 'target-qualification', 'fallback-qualification'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = render(args.output, args.source_archive, args.probe, args.target_qualification, args.fallback_qualification)
    print(json.dumps({'rendered': True, 'cycle': 6, 'files': len(result['files']), 'revision': REVISION}))


if __name__ == '__main__':
    main()
