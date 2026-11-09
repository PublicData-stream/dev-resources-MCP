"""Exercise the actual embedded recovery probe without network or wall-clock waits."""
import ast
import contextlib
import copy
import io
from pathlib import Path
import re
import types
import unittest


CAPTURE = 'blake3:' + 'a' * 64
URI = 'devres://capture/' + CAPTURE
BODY = 'Synthetic dev-resources persistence acceptance fixture\n'


def success():
    return 200, {'result': {'structuredContent': {'contents': [
        {'uri': URI, 'mimeType': 'text/plain', 'text': BODY},
        {'uri': 'devres://attribution/fixture-notice', 'mimeType': 'text/plain',
         'text': 'Synthetic attribution notice'}]}}}


def unavailable(code='unavailable'):
    return 200, {'result': {'isError': True, 'structuredContent': {
        'code': code, 'message': 'private synthetic detail must not be logged'}}}


class Clock:
    def __init__(self):
        self.value = 0
        self.sleeps = []

    def monotonic(self):
        return self.value

    def sleep(self, delay):
        self.sleeps.append(delay)
        self.value += delay


class FakeClient:
    def __init__(self, clock, replies, durations=()):
        self.clock = clock
        self.replies = list(replies)
        self.durations = list(durations)
        self.calls = []
        self.timeout = None

    def exchange(self, method, params):
        self.calls.append((method, copy.deepcopy(params), self.timeout))
        self.clock.value += self.durations.pop(0) if self.durations else 0
        value = self.replies.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class CaptureRecoveryTests(unittest.TestCase):
    def setUp(self):
        source = (Path(__file__).resolve().parents[1] / 'test-minikube.sh').read_text()
        block = source.split("<<'PYS3CAPTURE'\n", 1)[1].split('\nPYS3CAPTURE', 1)[0]
        function = next(node for node in ast.parse(block).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'capture_state')
        self.clock = Clock()
        namespace = {'re': re, 'time': types.SimpleNamespace(
            monotonic=self.clock.monotonic, sleep=self.clock.sleep)}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     'embedded-capture-recovery', 'exec'), namespace)
        self.probe = namespace['capture_state']
        self.output = io.StringIO()

    def run_probe(self, replies, durations=(), deadline=180, state='recover', ready=None):
        self.client = FakeClient(self.clock, replies, durations)
        with contextlib.redirect_stdout(self.output):
            self.probe(self.client, CAPTURE, state, deadline_secs=deadline, ready=ready)

    def test_eventual_recovery_keeps_capture_and_caps_each_exchange_to_remaining_time(self):
        self.run_probe([unavailable(), unavailable(), success()], [.5, .5, .1], deadline=4)
        self.assertEqual([call[2] for call in self.client.calls], [4, 2.5, 1])
        self.assertTrue(all(call[:2] == ('tools/call', {
            'name': 'fetch', 'arguments': {'id': URI}}) for call in self.client.calls))
        self.assertLess(self.clock.value, 4)
        self.assertNotIn('private synthetic detail', self.output.getvalue())

    def test_persistent_unavailable_stops_at_deadline(self):
        with self.assertRaisesRegex(AssertionError, 'recovery deadline exceeded'):
            self.run_probe([unavailable()] * 4, deadline=2.5)
        self.assertEqual(len(self.client.calls), 3)
        self.assertEqual(self.clock.value, 2.5)

    def test_other_typed_errors_fail_once_without_sleep_or_response_dump(self):
        with self.assertRaisesRegex(AssertionError, 'code=integrity_error'):
            self.run_probe([unavailable('integrity_error')])
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.clock.sleeps, [])
        self.assertNotIn('private synthetic detail', self.output.getvalue())

    def test_transport_and_invalid_rpc_fail_once(self):
        cases = [OSError('private transport detail'), (503, {}),
                 (200, {'error': {'message': 'private RPC detail'}}),
                 (200, {'result': None}),
                 (200, {'result': {'isError': True, 'structuredContent': {}}})]
        for response in cases:
            with self.subTest(response_type=type(response).__name__):
                with self.assertRaises(AssertionError) as error:
                    self.run_probe([response])
                self.assertNotIn('private', str(error.exception))
                self.assertEqual(len(self.client.calls), 1)
                self.assertEqual(self.clock.sleeps, [])

    def test_wrong_capture_or_body_never_counts_as_recovery(self):
        for key, value in [('uri', 'devres://capture/other'), ('text', 'wrong body')]:
            response = success()
            response[1]['result']['structuredContent']['contents'][0][key] = value
            with self.subTest(field=key), self.assertRaises(AssertionError):
                self.run_probe([response])
            self.assertEqual(len(self.client.calls), 1)

    def test_malformed_duplicate_or_unrelated_resource_items_fail_once(self):
        for item in (None, success()[1]['result']['structuredContent']['contents'][0],
                     {'uri': 'devres://capture/other', 'mimeType': 'text/plain', 'text': BODY}):
            response = success()
            response[1]['result']['structuredContent']['contents'].append(item)
            with self.subTest(item_type=type(item).__name__), self.assertRaises(AssertionError):
                self.run_probe([response])
            self.assertEqual(len(self.client.calls), 1)

    def test_a_late_success_does_not_extend_the_deadline(self):
        with self.assertRaisesRegex(AssertionError, 'recovery deadline exceeded'):
            self.run_probe([success()], durations=[5], deadline=2)
        self.assertEqual(self.client.calls[0][2], 2)

    def test_private_readiness_uses_same_deadline_without_repeating_capture(self):
        answers = iter([False, True])
        timeouts = []

        def ready(timeout):
            timeouts.append(timeout)
            self.clock.value += .25
            return next(answers)

        self.run_probe([success()], durations=[.5], deadline=3, ready=ready)
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(timeouts, [2, 1.25])
        self.assertLess(self.clock.value, 3)

    def test_private_readiness_cannot_outlive_recovery_budget(self):
        with self.assertRaisesRegex(AssertionError, 'readiness recovery deadline exceeded'):
            self.run_probe([success()], deadline=2.5, ready=lambda _: False)
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.clock.value, 2.5)

    def test_outage_assertion_rejects_even_a_valid_warm_capture(self):
        with self.assertRaisesRegex(AssertionError, 'escaped the archive outage gate'):
            self.run_probe([success()], state='unavailable')
        self.assertEqual(len(self.client.calls), 1)


if __name__ == '__main__':
    unittest.main()
