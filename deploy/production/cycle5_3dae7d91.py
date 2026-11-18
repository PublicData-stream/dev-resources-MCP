#!/usr/bin/env python3
"""Render the authorized fresh fifth cycle locally; never run or install it."""
import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
WORK = '/tmp/devres-upgrade-3dae7d91-cycle5-20261118'
BUNDLE = '/var/lib/devres-production-upgrades/3dae7d91-cycle5-20261118'
INSTALL = '/usr/local/libexec/devres-upgrade-3dae7d91-cycle5'
TRANSFER = '/tmp/devres-3dae7d91-cycle5-transfer-20261118'
PREVIOUS_WORK = '/tmp/devres-upgrade-3dae7d91-20261117'
PREVIOUS_BUNDLE = '/var/lib/devres-production-upgrades/3dae7d91-20261117'
PREVIOUS_INSTALL = '/usr/local/libexec/devres-upgrade-3dae7d91'
PREVIOUS_CONTROLLER_SHA = '8290b5388a4a02391d441dd56bd803830389e01d3037bb30916de487559c8a4e'
PREVIOUS_MANIFEST_SHA = 'a23b1015e38926627bfe2d8883d3ebe46d9c23dadcbe68ba1695529f0808be5e'
PREVIOUS_PUBLIC_SHA = 'e102b153c9ab638ecaa1deaf3f5326129ed38f20a57cdcc37e03842da0f3ccf7'
EDGE_RECEIPT_SHA = 'e1134a7092ac1e05ec97128bda976c174fc25e6b83d98cf9844bee575e57540a'


def module(name, path):
    import sys
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


c4 = module('cycle5_current_c4_renderer', HERE / 'cycle4_3dae7d91.py')
REVISION, VERSION, IMAGE, PROBE, SOURCE_SHA = c4.REVISION, c4.VERSION, c4.IMAGE, c4.PROBE, c4.SOURCE_SHA


def transform(name, source, c4_histories, base_special, base_sources):
    if name not in ('edge-readmission.py', 'edge-qualification.py'):
        for old, new in sorted({PREVIOUS_WORK: WORK, PREVIOUS_BUNDLE: BUNDLE,
                PREVIOUS_INSTALL: INSTALL, '/tmp/devres-public-probe-3dae7d91-20261117':
                '/tmp/devres-public-probe-3dae7d91-cycle5-20261118',
                '/tmp/devres-public-probe-91c7bcb7-3dae7d91-20261117':
                '/tmp/devres-public-probe-91c7bcb7-3dae7d91-cycle5-20261118',
                'devres-npm-assessment-3dae7d91': 'devres-npm-assessment-3dae7d91-c5',
                '3dae7d91-assessment': '3dae7d91-cycle5-assessment',
                'physical-pg-checkpoint-3dae7d91': 'physical-pg-checkpoint-3dae7d91-cycle5'}.items(), key=lambda p: -len(p[0])):
            source = source.replace(old, new)
    if name == 'upgrade-controller.py':
        history = {'name': 'cycle4', 'work': PREVIOUS_WORK, 'bundle': PREVIOUS_BUNDLE,
            'install': PREVIOUS_INSTALL, 'controller_sha256': PREVIOUS_CONTROLLER_SHA,
            'manifest_sha256': PREVIOUS_MANIFEST_SHA}
        histories = (*c4_histories, history)
        source = c4.once(source, 'HISTORIES=' + repr(c4_histories), 'HISTORIES=' + repr(histories))
        source = c4.once(source, "PREVIOUS_REVISION='9373f71e06936970b4a8dc4ca30584b9d464a5b9'",
                         'PREVIOUS_REVISION=' + repr(REVISION))
        source = c4.function(source, 'previous_cycle', '''def previous_cycle(context):
    return cycle5_previous_controller(context)
''')
        old_special = tuple(sorted(base_special))
        old_sources = tuple(sorted(base_sources))
        special = tuple(sorted((*old_special, 'edge-readmission.py', 'edge-qualification.py')))
        current_sources = tuple(sorted(set(old_sources) | {'deploy/diagnostics/npm_assessment.py'}))
        tables = '\nHISTORY_SPECIAL_NAMES=' + repr({h['name']: special if h['name'] == 'cycle4' else old_special for h in histories})
        tables += '\nHISTORY_SOURCE_NAMES=' + repr({h['name']: current_sources if h['name'] == 'cycle4' else old_sources for h in histories}) + '\n'
        source = c4.once(source, '\ndef history_metadata_rules():', tables + '\ndef history_metadata_rules():')
        source = c4.once(source, 'set(PREVIOUS_SPECIAL_NAMES)|set(PREVIOUS_SOURCE_NAMES)',
                         "set(HISTORY_SPECIAL_NAMES[history['name']])|set(HISTORY_SOURCE_NAMES[history['name']])")
        source = c4.once(source, 'result.update(install/name for name in PREVIOUS_SPECIAL_NAMES)',
                         "result.update(install/name for name in HISTORY_SPECIAL_NAMES[history['name']])")
        source = c4.once(source, 'result.update(work/name for name in PREVIOUS_SOURCE_NAMES)',
                         "result.update(work/name for name in HISTORY_SOURCE_NAMES[history['name']])")
        source = c4.once(source, 'path=install/name if name in PREVIOUS_SPECIAL_NAMES else work/name',
                         "path=install/name if name in HISTORY_SPECIAL_NAMES[history['name']] else work/name")
        source = c4.once(source, "{'op': 'test', 'path': '/spec/template/spec/containers/0/image', 'value': OLD_IMAGE}",
                         "{'op': 'test', 'path': '/spec/template/spec/containers/0/image', 'value': load(self.root/'prepared.json')['initial_images'][name]}")
        source = source.replace("else {'postgres': PG_IMAGE, 'writer': OLD_IMAGE, 'backend': OLD_IMAGE}",
                                "else {'postgres': PG_IMAGE, 'writer': IMAGE, 'backend': IMAGE}")
        fragment = (HERE / 'cycle5_runtime_3dae7d91.py').read_text()
        source = c4.once(source, '\ndef main():', '\n' + fragment + '\n\ndef main():')
    adapter = module('cycle5_acceptance_adapter', HERE / 'cycle5_acceptance_3dae7d91.py')
    return adapter.transform(name, source)


def render(output, previous_controller_sha, previous_manifest_sha):
    c4.need((previous_controller_sha, previous_manifest_sha) == (PREVIOUS_CONTROLLER_SHA, PREVIOUS_MANIFEST_SHA),
            'exact_consumed_cycle4_required')
    output = Path(output)
    c4.need(output.is_absolute() and Path('/tmp') in output.parents and '..' not in output.parts
        and not any(p.is_symlink() for p in (output, *output.parents)) and not output.exists(), 'fresh_private_output_required')
    with tempfile.TemporaryDirectory(prefix='cycle5-base-', dir='/tmp') as scratch:
        files = c4.render(Path(scratch) / 'closure', c4.PREVIOUS_CONTROLLER_SHA, c4.PREVIOUS_MANIFEST_SHA)
        namespace = {}
        tree = ast.parse(Path(files['upgrade-controller.py']['local']).read_text())
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in
                    ('HISTORIES', 'PREVIOUS_SPECIAL_NAMES', 'PREVIOUS_SOURCE_NAMES') for t in node.targets):
                namespace[node.targets[0].id] = ast.literal_eval(node.value)
        output.mkdir(mode=0o700, parents=True); results = {}
        for name, item in sorted(files.items()):
            body = transform(name, Path(item['local']).read_text(), namespace['HISTORIES'],
                namespace['PREVIOUS_SPECIAL_NAMES'], namespace['PREVIOUS_SOURCE_NAMES']).encode()
            ast.parse(body, filename=name)
            target = output / name; target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
            results[name] = {**item, 'sha256': c4.digest(body), 'local': str(target),
                'remote': str(Path(INSTALL if Path(item['remote']).parent == Path(c4.INSTALL) else WORK) / name)}
    manifest = {'version': 1, 'cycle': 5, 'release_commit': REVISION,
        'renderer_sha256': c4.digest(Path(__file__).read_bytes()),
        'transform_sources': {p.name: c4.digest(p.read_bytes()) for p in [HERE / name for name in (
            'cycle3_9373f71e.py', 'cycle4_3dae7d91.py', 'cycle4_runtime_3dae7d91.py',
            'cycle4_acceptance_3dae7d91.py', 'cycle4_assessment_3dae7d91.py',
            'cycle4_edge_3dae7d91.py', 'cycle4_edge_qualification_3dae7d91.py',
            'cycle5_runtime_3dae7d91.py', 'cycle5_acceptance_3dae7d91.py')]},
        'scope': {'work': WORK, 'bundle': BUNDLE, 'install': INSTALL, 'transfer': TRANSFER}, 'files': results}
    (output / 'render-manifest.json').write_bytes(c4.encoded(manifest)); (output / 'render-manifest.json').chmod(0o600)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--previous-controller-sha256', required=True)
    parser.add_argument('--previous-manifest-sha256', required=True)
    args = parser.parse_args()
    result = render(args.output, args.previous_controller_sha256, args.previous_manifest_sha256)
    print(json.dumps({'rendered': True, 'cycle': 5, 'files': len(result), 'release_commit': REVISION}))


if __name__ == '__main__':main()
