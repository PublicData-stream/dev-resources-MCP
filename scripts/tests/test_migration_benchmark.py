"""Behavior tests for benchmark parity, repeats and conservative comparison."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import unittest

SPEC = importlib.util.spec_from_file_location('migration_benchmark_report',
    Path(__file__).resolve().parents[1] / 'migration-benchmark-report.py')
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class BenchmarkReportTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def run_result(self, workers, repeat, seconds, fingerprint='a' * 64):
        output = self.root / f'workers-{workers}' / f'repeat-{repeat}'
        output.mkdir(parents=True)
        phases = ['migrate_including_graph_and_finish_verification', 'standalone_verification',
                  'activation_including_verification', 'startup_readback_and_durable_fingerprint']
        (output / 'result.json').write_text(json.dumps({
            'fixture': 'pending-schema10-synthetic-v1', 'full_schema9_corpus': False,
            'workers': workers, 'durable_fingerprint': fingerprint,
            'phases': [{'phase': phase, 'wall_secs': seconds / 4} for phase in phases]}))
        (output / 'restored.json').write_text(json.dumps({
            'durable_fingerprint': fingerprint, 'restored_startup_readback': True}))
        return output

    def fixture(self, workers, seconds):
        for repeat in range(1, 4):
            self.run_result(workers, repeat, seconds)

    def test_uses_medians_and_reports_only_fixture_improvement(self):
        self.fixture(1, 12)
        self.fixture(4, 6)
        report = REPORT.summarize(self.root, 3)
        self.assertEqual(report['selected_workers'], 4)
        self.assertEqual(report['fixture_speedup_ratio'], 2)
        self.assertEqual(report['full_corpus_speedup'], 'unmeasured')
        self.assertTrue(REPORT.continue_matrix(report, 4))

    def test_plateau_stops_matrix_and_keeps_best_setting(self):
        self.fixture(1, 12)
        self.fixture(4, 6)
        self.fixture(8, 6.1)
        report = REPORT.summarize(self.root, 3)
        self.assertFalse(REPORT.continue_matrix(report, 8))
        self.assertEqual(report['selected_workers'], 4)

    def test_failed_speedup_is_reported(self):
        self.fixture(1, 6)
        self.fixture(4, 7)
        report = REPORT.summarize(self.root, 3)
        self.assertFalse(report['reproducible_improvement_over_two_percent'])
        self.assertEqual(report['fixture_speedup_ratio'], 1)

    def test_noisy_overlapping_runs_do_not_establish_reproducible_improvement(self):
        for repeat, seconds in enumerate((12, 6, 12), 1):
            self.run_result(1, repeat, seconds)
        self.fixture(4, 7)
        report = REPORT.summarize(self.root, 3)
        self.assertEqual(report['selected_workers'], 4)
        self.assertFalse(report['reproducible_improvement_over_two_percent'])

    def test_missing_repeats_fail(self):
        self.run_result(1, 1, 6)
        with self.assertRaisesRegex(ValueError, 'repeats'):
            REPORT.summarize(self.root, 3)

    def test_differing_durable_results_fail(self):
        self.fixture(1, 6)
        self.run_result(4, 1, 4, 'b' * 64)
        with self.assertRaisesRegex(ValueError, 'differing durable'):
            REPORT.summarize(self.root, 3)

    def test_restore_mismatch_fails(self):
        output = self.run_result(1, 1, 6)
        (output / 'restored.json').write_text(json.dumps({
            'durable_fingerprint': 'different', 'restored_startup_readback': True}))
        with self.assertRaisesRegex(ValueError, 'restored fixture'):
            REPORT.summarize(self.root, 3)

    def test_nonfinite_phase_time_fails(self):
        self.run_result(1, 1, float('nan'))
        with self.assertRaisesRegex(ValueError, 'phase time'):
            REPORT.summarize(self.root, 3)

    def graph_fixture(self, workers, seconds, generations=1):
        for repeat in range(1, 4):
            output = self.run_result(workers, repeat, seconds)
            result = json.loads((output / 'result.json').read_text())
            result.update(fixture='pending-schema10-graph-v1', graph_snapshots=8,
                          graph_generations=generations,
                          graph_memory_budget_mib=1024, graph_jobs_high_water=min(workers, 4),
                          graph_jobs_admitted=72, graph_memory_high_water=512 * 1024 * 1024)
            (output / 'result.json').write_text(json.dumps(result))

    def test_nonempty_graph_workload_reports_resources_and_observed_parallelism(self):
        self.graph_fixture(1, 12)
        self.graph_fixture(4, 7)
        report = REPORT.summarize(self.root, 3)
        self.assertEqual(report['fixture'], 'pending-schema10-graph-v1')
        self.assertTrue(report['graph_parallel_activity_observed'])
        self.assertEqual(report['graph_memory_high_water_bytes'], 512 * 1024 * 1024)
        self.assertIn('RFC frozen-index replay', report['limits'])
        self.assertEqual(report['full_corpus_speedup'], 'unmeasured')

    def test_graph_resource_counts_and_mixed_workloads_are_rejected(self):
        self.graph_fixture(1, 12)
        self.fixture(4, 7)
        with self.assertRaisesRegex(ValueError, 'differing durable'):
            REPORT.summarize(self.root, 3)
        path = self.root / 'workers-1/repeat-1/result.json'
        result = json.loads(path.read_text())
        result['graph_jobs_high_water'] = 2
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'resource evidence'):
            REPORT.summarize(self.root, 3)

    def test_changing_generations_profile_is_preserved_and_cannot_mix(self):
        self.graph_fixture(1, 12, generations=8)
        self.graph_fixture(4, 7, generations=8)
        report = REPORT.summarize(self.root, 3)
        self.assertEqual(report['graph_snapshots'], 8)
        self.assertEqual(report['graph_generations'], 8)
        self.assertEqual(report['graph_memory_budget_mib'], 1024)
        path = self.root / 'workers-4/repeat-1/result.json'
        result = json.loads(path.read_text())
        result['graph_generations'] = 1
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'differing durable'):
            REPORT.summarize(self.root, 3)

    def test_old_shared_generation_results_keep_their_original_profile(self):
        self.graph_fixture(1, 12)
        self.graph_fixture(4, 7)
        for path in self.root.glob('workers-*/repeat-*/result.json'):
            result = json.loads(path.read_text())
            del result['graph_generations']
            path.write_text(json.dumps(result))
        report = REPORT.summarize(self.root, 3)
        self.assertEqual(report['graph_generations'], 1)

    def test_invalid_generation_counts_are_rejected(self):
        self.graph_fixture(1, 12)
        path = self.root / 'workers-1/repeat-1/result.json'
        original = json.loads(path.read_text())
        for generations in (0, -1, True, '1', 9):
            result = dict(original, graph_generations=generations)
            path.write_text(json.dumps(result))
            with self.subTest(generations=generations), self.assertRaisesRegex(
                    ValueError, 'generation count|resource evidence'):
                REPORT.summarize(self.root, 3)

    def test_metadata_records_profile_options_without_binary_path(self):
        binary = self.root / 'private-binary-name'
        binary.write_bytes(b'synthetic benchmark binary')
        options = ['graph_snapshots=8', 'graph_generations=8', 'graph_memory_budget_mib=2048']
        metadata = REPORT.metadata(binary, 'reviewed-source', options)
        self.assertEqual(metadata['options'], options)
        self.assertGreater(metadata['clock_ticks_per_second'], 0)
        self.assertEqual(metadata['revision'], 'reviewed-source')
        self.assertNotIn(str(binary), json.dumps(metadata))


class BenchmarkCliTests(unittest.TestCase):
    script = Path(__file__).resolve().parents[1] / 'benchmark-migration.sh'

    def rejected(self, *arguments):
        result = subprocess.run(['bash', str(self.script), '--binary', '/bin/true', *arguments],
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn('Retained isolated Docker state', result.stderr)
        return result

    def test_help_needs_neither_docker_nor_built_binary(self):
        result = subprocess.run(['bash', str(self.script), '--help'],
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn('--workers', result.stdout)

    def test_repeat_range_is_checked_before_infrastructure(self):
        self.assertIn('bounded range', self.rejected('--repeats', '2').stderr)

    def test_serial_reference_and_increasing_workers_are_required(self):
        self.assertIn('serial reference', self.rejected('--workers', '4').stderr)
        self.assertIn('strictly increasing', self.rejected('--workers', '1 1').stderr)
        self.assertIn('strictly increasing', self.rejected('--workers', '1 65').stderr)

    def test_generation_count_is_checked_before_infrastructure(self):
        self.assertIn('requires a value', self.rejected('--graph-generations').stderr)
        self.assertIn('positive', self.rejected('--graph-generations', '0').stderr)
        self.assertIn('enabled graph snapshots', self.rejected('--graph-generations', '2').stderr)
        self.assertIn('cannot exceed', self.rejected('--graph-snapshots', '8', '--graph-generations', '9').stderr)
        self.assertIn('serial reference', self.rejected('--graph-generations', '1', '--workers', '4').stderr)
        self.assertIn('serial reference', self.rejected('--graph-snapshots', '8', '--graph-generations', '8', '--workers', '4').stderr)

    def test_malformed_workload_is_checked_before_infrastructure(self):
        self.assertIn('positive', self.rejected('--rows', '0').stderr)
        self.assertIn('bounded range', self.rejected('--file-mib', '33').stderr)
        self.assertIn('requires a value', self.rejected('--graph-snapshots', '-1').stderr)
        self.assertIn('bounded range', self.rejected('--graph-snapshots', '65').stderr)
        self.assertIn('positive', self.rejected('--graph-memory-budget-mib', '0').stderr)


if __name__ == '__main__':
    unittest.main()
