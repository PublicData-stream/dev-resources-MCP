#!/usr/bin/env python3
"""Report bounded synthetic migration measurements; never infer corpus speedup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics


def load_runs(root):
    runs = []
    for path in sorted(Path(root).glob('workers-*/repeat-*/result.json')):
        item = json.loads(path.read_text())
        if (item.get('fixture') not in ('pending-schema10-synthetic-v1', 'pending-schema10-graph-v1', 'pending-schema10-crates-v1')
                or item.get('full_schema9_corpus') is not False
                or not isinstance(item.get('workers'), int)
                or not 1 <= item['workers'] <= 64
                or not isinstance(item.get('durable_fingerprint'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', item['durable_fingerprint'])):
            raise ValueError('invalid synthetic benchmark result')
        # Earlier shared-generation fixtures omitted this field; their profile is one.
        generations = item.setdefault('graph_generations', 1)
        if not isinstance(generations, int) or isinstance(generations, bool) or generations < 1:
            raise ValueError('invalid graph generation count')
        if item['fixture'] != 'pending-schema10-graph-v1' and generations != 1:
            raise ValueError('invalid graph generation count for empty graphs')
        if item['fixture'] == 'pending-schema10-graph-v1':
            if (not isinstance(item.get('graph_snapshots'), int)
                    or not 1 <= item['graph_snapshots'] <= 64
                    or generations > item['graph_snapshots']
                    or not isinstance(item.get('graph_memory_budget_mib'), int)
                    or not 1 <= item['graph_memory_budget_mib'] <= 65536
                    or not isinstance(item.get('graph_jobs_high_water'), int)
                    or not 1 <= item['graph_jobs_high_water'] <= item['workers']
                    or not isinstance(item.get('graph_jobs_admitted'), int)
                    or item['graph_jobs_admitted'] < item['graph_snapshots']
                    or not isinstance(item.get('graph_memory_high_water'), int)
                    or item['graph_memory_high_water'] <= 0):
                raise ValueError('invalid graph benchmark resource evidence')
        if item['fixture'] == 'pending-schema10-crates-v1':
            timings = item.get('crate_phase_micros', {})
            if (type(item.get('graph_jobs_high_water')) is not int
                    or not 0 <= item['graph_jobs_high_water'] <= item['workers']
                    or type(item.get('crate_artifacts')) is not int
                    or not 1 <= item['crate_artifacts'] <= 16384
                    or not isinstance(timings, dict)
                    or type(timings.get('graph_crate_artifacts')) is not int
                    or timings['graph_crate_artifacts'] <= 0):
                raise ValueError('invalid crate benchmark timing/profile evidence')
        phases = item.get('phases', [])
        required = {'migrate_including_graph_and_finish_verification',
                    'standalone_verification', 'activation_including_verification',
                    'startup_readback_and_durable_fingerprint'}
        if {phase['phase'] for phase in phases} != required or len(phases) != len(required):
            raise ValueError('missing or duplicate timed phase')
        times = [phase['wall_secs'] for phase in phases]
        if any(not isinstance(value, (float, int)) or not 0 < value < float('inf') for value in times):
            raise ValueError('invalid phase time')
        restored = json.loads(path.with_name('restored.json').read_text())
        if (restored.get('durable_fingerprint') != item.get('durable_fingerprint')
                or restored.get('restored_startup_readback') is not True):
            raise ValueError('restored fixture fingerprint mismatch')
        item['total_secs'] = sum(times)
        runs.append(item)
    if (not runs or len({run['durable_fingerprint'] for run in runs}) != 1
            or len({(run['fixture'], run.get('graph_snapshots', 0),
                     run.get('graph_memory_budget_mib', 0), run['graph_generations'], run.get('crate_artifacts', 0)) for run in runs}) != 1):
        raise ValueError('missing runs or differing durable fixture results')
    return runs


def summarize(root, repeats):
    if not 3 <= repeats <= 10:
        raise ValueError('between three and ten repeats are required')
    groups = {}
    for run in load_runs(root):
        groups.setdefault(run['workers'], []).append(run)
    if 1 not in groups or any(len(values) != repeats for values in groups.values()):
        raise ValueError('serial reference and all requested repeats are required')
    candidates = []
    for workers, runs in sorted(groups.items()):
        phases = {phase['phase']: statistics.median(
            next(value['wall_secs'] for value in run['phases'] if value['phase'] == phase['phase'])
            for run in runs) for phase in runs[0]['phases']}
        candidates.append({'workers': workers, 'repeats': repeats,
                           'median_total_secs': statistics.median(run['total_secs'] for run in runs),
                           'run_total_secs': [run['total_secs'] for run in runs],
                           'median_phase_secs': phases,
                           'median_crate_phase_secs': {name: statistics.median(
                               run.get('crate_phase_micros', {}).get(name, 0) / 1_000_000
                               for run in runs) for name in runs[0].get('crate_phase_micros', {})}})
    baseline = next(item['median_total_secs'] for item in candidates if item['workers'] == 1)
    best = min(candidates, key=lambda item: (item['median_total_secs'], item['workers']))
    profile = load_runs(root)[0]
    graph = profile['fixture'] == 'pending-schema10-graph-v1'
    crates = profile['fixture'] == 'pending-schema10-crates-v1'
    return {'fixture': profile['fixture'],
            'crate_artifacts': profile.get('crate_artifacts', 0),
            'graph_snapshots': profile.get('graph_snapshots', 0),
            'graph_generations': profile['graph_generations'],
            'graph_memory_budget_mib': profile.get('graph_memory_budget_mib', 0), 'full_corpus_speedup': 'unmeasured',
            'all_normalized_durable_results_equal': True,
            'durable_fingerprint': load_runs(root)[0]['durable_fingerprint'],
            'candidates': candidates, 'selected_workers': best['workers'],
            'fixture_speedup_ratio': baseline / best['median_total_secs'],
            'reproducible_improvement_over_two_percent': max(best['run_total_secs']) < min(run['total_secs'] for run in groups[1]) * 0.98,
            'cache_mode': 'warm cache; fresh DB/blob pair for every repeat; no host cache drop',
            'limits': ('synthetic RFC frozen-index replay with shared/changing generations plus npm/RustSec evidence; excludes complete schema9 replay'
                       if graph else 'synthetic crate artifacts, duplicate observations and inventory staging; excludes complete schema9 replay'
                       if crates else 'synthetic sealing/files with empty provider graphs; excludes complete schema9 replay'),
            'graph_parallel_activity_observed': (graph or crates) and any(run['graph_jobs_high_water'] > 1 for run in load_runs(root)),
            'graph_memory_high_water_bytes': max((run.get('graph_memory_high_water', 0) for run in load_runs(root)), default=0),
            'improvement_note': 'every selected repeat must beat every serial repeat by more than two percent',
            'resource_note': 'phase RSS is process cumulative high water; CPU/I/O exclude PostgreSQL; WAL includes background activity',
            'backup_restore_note': 'separate backup/restore time files; excluded from migration speedup'}


def compare(root, repeats):
    """Compare complete, equivalent artifact phases; worker scaling is separate."""
    if not 3 <= repeats <= 10:
        raise ValueError('between three and ten repeats are required')
    baseline = load_runs(Path(root) / 'baseline')
    candidate = load_runs(Path(root) / 'candidate')
    if (any(run['fixture'] != 'pending-schema10-crates-v1' for run in baseline + candidate)
            or any(run['workers'] != 8 for run in baseline)
            or len(baseline) != repeats
            or {run['workers'] for run in candidate} != {1, 2, 4, 8}
            or any(sum(run['workers'] == workers for run in candidate) != repeats
                   for workers in (1, 2, 4, 8))):
        raise ValueError('comparison requires baseline8 and complete candidate1/2/4/8 repeats')
    if (len({run['durable_fingerprint'] for run in baseline + candidate}) != 1
            or len({run['crate_artifacts'] for run in baseline + candidate}) != 1
            or len({run['graph_memory_budget_mib'] for run in baseline + candidate}) != 1
            or len({run['payload_budget_mib'] for run in baseline + candidate}) != 1):
        raise ValueError('baseline/candidate workload, budget or durable result differs')
    timings = lambda runs: [run['crate_phase_micros']['graph_crate_artifacts'] / 1_000_000
                           for run in runs]
    old = timings(baseline)
    new = timings([run for run in candidate if run['workers'] == 8])
    ratio = statistics.median(old) / statistics.median(new)
    return {'fixture': 'pending-schema10-crates-v1',
            'crate_artifacts': baseline[0]['crate_artifacts'],
            'baseline_workers': 8, 'candidate_workers': 8, 'repeats': repeats,
            'baseline_artifact_secs': old, 'candidate_artifact_secs': new,
            'baseline_median_crate_phase_secs': {name: statistics.median(
                run['crate_phase_micros'].get(name, 0) / 1_000_000 for run in baseline)
                for name in baseline[0]['crate_phase_micros']},
            'candidate8_median_crate_phase_secs': {name: statistics.median(
                run['crate_phase_micros'].get(name, 0) / 1_000_000
                for run in candidate if run['workers'] == 8)
                for name in candidate[0]['crate_phase_micros']},
            'baseline_median_artifact_secs': statistics.median(old),
            'candidate_median_artifact_secs': statistics.median(new),
            'artifact_speedup_ratio': ratio, 'artifact_speedup_target': 4,
            'artifact_speedup_target_met': ratio >= 4,
            'reproducible_improvement_over_two_percent': max(new) < min(old) * 0.98,
            'candidate_scaling': summarize(Path(root) / 'candidate', repeats),
            'all_normalized_durable_results_equal': True,
            'durable_fingerprint': baseline[0]['durable_fingerprint'],
            'full_corpus_speedup': 'unmeasured',
            'timing_boundary': 'complete artifact-only replay, first metadata query through final publication; excludes observations',
            'backup_restore_note': 'each pair separately backed up/restored and read back; times excluded from artifact speedup',
            'cache_mode': 'warm cache; fresh pairs; alternating baseline/candidate order; no host cache drop'}


def continue_matrix(summary, latest):
    candidates = summary['candidates']
    if latest == 1:
        return True
    current = next(item['median_total_secs'] for item in candidates if item['workers'] == latest)
    previous = [item['median_total_secs'] for item in candidates if item['workers'] < latest]
    return bool(previous) and current < min(previous) * 0.98


def metadata(binary, revision, args):
    result = {'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              'revision': revision, 'kernel': platform.release(), 'architecture': platform.machine(),
              'logical_cpus': os.cpu_count(),
              'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
              'allowed_cpus': len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
              'options': args, 'cache_mode': 'warm cache; no host cache drop',
              'full_corpus_benchmark': False}
    try:
        result['cpu_model'] = next(line.split(':', 1)[1].strip()
            for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name'))
        result['host_memory_kib'] = int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1])
    except (OSError, StopIteration, ValueError, IndexError):
        result['cpu_model'] = 'unavailable'
    for name, path in [('memory_limit', '/sys/fs/cgroup/memory.max'),
                       ('cpu_quota', '/sys/fs/cgroup/cpu.max')]:
        try:
            result[name] = Path(path).read_text().strip()
        except OSError:
            result[name] = 'unavailable'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    report = commands.add_parser('summarize')
    report.add_argument('root')
    report.add_argument('--repeats', type=int, required=True)
    report.add_argument('--continue-after', type=int)
    comparison = commands.add_parser('compare')
    comparison.add_argument('root')
    comparison.add_argument('--repeats', type=int, required=True)
    meta = commands.add_parser('metadata')
    meta.add_argument('binary')
    meta.add_argument('revision')
    meta.add_argument('options', nargs='*')
    args = parser.parse_args()
    if args.command == 'metadata':
        print(json.dumps(metadata(args.binary, args.revision, args.options), sort_keys=True))
    elif args.command == 'compare':
        print(json.dumps(compare(args.root, args.repeats), sort_keys=True, indent=2))
    else:
        summary = summarize(args.root, args.repeats)
        if args.continue_after is not None:
            raise SystemExit(0 if continue_matrix(summary, args.continue_after) else 3)
        print(json.dumps(summary, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
