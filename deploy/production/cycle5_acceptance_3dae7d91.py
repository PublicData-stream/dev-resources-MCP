"""Narrow C5 producer adaptation; the exact historical dependency union is 37."""
import ast
from pathlib import Path


DEPENDENCIES = '''def cycle5_dependency_union(previous,manifest):
    need(type(previous) is dict and len(previous)==29,'exact_previous_dependencies_required')
    expected=dict(previous)
    for name in ('upgrade-controller.py','physical-checkpoint.py','restore-controller.py','restore-rehearsal.py',
                 'npm-recovery.py','safety-supervisor.py','edge-readmission.py','edge-qualification.py'):
        path=str(P('/usr/local/libexec/devres-upgrade-3dae7d91')/name)
        need(path not in expected,'historical_dependency_collision')
        expected[path]=manifest[name]
    need(len(expected)==37,'exact_cycle5_dependency_union_required')
    return expected

def checked_dependencies(public):
    prior_work=P('/tmp/devres-upgrade-3dae7d91-20261117')
    prior_install=P('/usr/local/libexec/devres-upgrade-3dae7d91')
    prior_raw=raw(prior_work/'public-upgrade-identity.json')
    need(sha(prior_raw)=='e102b153c9ab638ecaa1deaf3f5326129ed38f20a57cdcc37e03842da0f3ccf7','fixed_previous_public_required')
    previous=decode(prior_raw)['dependency_sources']
    manifest_raw=raw(prior_work/'source-manifest.json')
    need(sha(manifest_raw)=='a23b1015e38926627bfe2d8883d3ebe46d9c23dadcbe68ba1695529f0808be5e','fixed_previous_manifest_required')
    expected=cycle5_dependency_union(previous,decode(manifest_raw))
    need(public.get('dependency_sources')==expected,'exact_cycle5_dependency_union_required')
    for name,wanted in expected.items():
        path=P(name)
        need(path.is_absolute() and path.is_relative_to('/usr/local/libexec') and path.suffix=='.py'
             and re.fullmatch('[0-9a-f]{64}',wanted or ''),'fixed_dependency_source_required')
        need(not any(p.is_symlink() for p in (path,*path.parents)),'dependency_symlink_refused')
        info=path.stat()
        need(info.st_uid==0 and not info.st_mode&0o022 and sha(raw(path,private=False))==wanted,'dependency_source_changed')
    return expected
'''


def transform(name, source):
    if name == 'physical-checkpoint.py':
        old = "projection == prepared['deployments'][role]['projection'] and image == (PG if role == 'postgres' else OLD)"
        if source.count(old) != 1:raise RuntimeError('one_checkpoint_initial_image_site_required')
        source = source.replace(old, "projection == prepared['deployments'][role]['projection'] and image == prepared['initial_images'][role]")
        tree = ast.parse(source); matches = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'checked_dependencies']
        if len(matches) != 1:raise RuntimeError('one_dependency_validator_required')
        node = matches[0]; lines = source.splitlines(keepends=True)
        source = ''.join(lines[:node.lineno-1]) + DEPENDENCIES + '\n' + ''.join(lines[node.end_lineno:])
    ast.parse(source, filename=name)
    return source
