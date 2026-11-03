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

    def test_malformed_workload_is_checked_before_infrastructure(self):
        self.assertIn('positive', self.rejected('--rows', '0').stderr)
        self.assertIn('bounded range', self.rejected('--file-mib', '33').stderr)


if __name__ == '__main__':
    unittest.main()
