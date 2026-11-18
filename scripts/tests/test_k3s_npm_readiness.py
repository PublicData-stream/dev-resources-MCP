import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('k3s_npm_readiness', ROOT / 'scripts/test-k3s-npm-readiness.py')
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


def rule(name=readiness.INGRESS, namespace=readiness.NAMESPACE, port=5432, source='ABC'):
    return (f'-A KUBE-NWPLCY-X -m comment --comment "rule to ACCEPT traffic from source pods to dest pods '
            f'selected by policy name {name} namespace {namespace}" -m set --match-set KUBE-SRC-{source} src '
            f'-m set --match-set KUBE-DST-DB dst -p tcp -m tcp --dport {port} -j MARK --set-xmark 0x10000/0x10000\n'
            ).encode()


def event(phase, outcome, reason='none', elapsed=1):
    return {'phase': phase, 'outcome': outcome, 'reason': reason, 'elapsed_ms': elapsed}


def started():
    return [event('cli_start', 'start'), event('sql_connect', 'start')]


def success():
    return [event('sql_connect', 'ok', elapsed=1300), event('sql_setup', 'start'),
            event('transaction', 'start'), event('report_write', 'ok'), event('cli_exit', 'ok')]


class PolicyProjectionTests(unittest.TestCase):
    def test_select_only_exact_postgres_policy_namespace_and_port(self):
        text = rule(name='seed-postgres-ingress') + rule(namespace='other') + rule(port=80) + rule()
        self.assertEqual(readiness.match_sets(text), ('KUBE-SRC-ABC', 'KUBE-DST-DB'))
        self.assertIsNone(readiness.match_sets(rule(namespace='other') + rule(port=80)))

    def test_duplicate_mark_and_return_pair_do_not_look_ambiguous(self):
        self.assertEqual(readiness.match_sets(rule() * 2), ('KUBE-SRC-ABC', 'KUBE-DST-DB'))
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'ambiguous_k3s_postgres_rule'):
            readiness.match_sets(rule() + rule(source='OTHER'))

    def test_assessment_egress_limits_database_to_same_namespace_and_named_dns(self):
        spec = readiness.egress(readiness.EGRESS, readiness.APP)['spec']
        self.assertEqual(spec['podSelector'], {'matchLabels': {'app': 'devres-npm-assessment'}})
        self.assertEqual(spec['policyTypes'], ['Ingress', 'Egress'])
        dns, database = spec['egress']
        self.assertEqual(dns['to'][0]['namespaceSelector'], {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}})
        self.assertEqual(database, {'to': [{'podSelector': {'matchLabels': {'app': 'postgres'}}}],
                                    'ports': [{'port': 5432, 'protocol': 'TCP'}]})


class AssessmentEvidenceTests(unittest.TestCase):
    def test_natural_success_and_observed_delay_are_distinct(self):
        self.assertIsNone(readiness.phase_evidence(started() + success(), 'natural')['first_retry'])
        retry = event('sql_connect_retry', 'error', 'connection', 100)
        delayed = readiness.phase_evidence(started() + [retry] + success(), 'delayed')
        self.assertEqual(delayed, {'first_retry': 'connection', 'first_retry_cli_elapsed_ms': 100,
                                  'connect_elapsed_ms': 1300})
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_assessment_report_not_single'):
            readiness.phase_evidence(started() + success(), 'delayed')

    def test_reject_duplicate_start_or_connect_outcome(self):
        for repeat in (event('cli_start', 'start'), event('sql_connect', 'ok')):
            with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_assessment_repeated'):
                readiness.phase_evidence(started() + [repeat] + success(), 'natural')

    def test_deadline_keeps_sql_and_report_unstarted(self):
        events = started() + [event('sql_connect_retry', 'error', 'timeout'),
                              event('sql_connect', 'error', 'timeout', 30000), event('cli_exit', 'error')]
        self.assertEqual(readiness.phase_evidence(events, 'denied')['connect_elapsed_ms'], 30000)
        with self.assertRaisesRegex(readiness.fixture.FixtureError, 'k3s_denied_assessment_reached_sql'):
            readiness.phase_evidence(events + [event('sql_setup', 'start')], 'denied')


if __name__ == '__main__':
    unittest.main()
