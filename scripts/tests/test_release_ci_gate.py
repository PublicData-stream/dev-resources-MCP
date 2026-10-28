"""The publication gate accepts only one complete native release image path."""
import contextlib
import io
import itertools
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release_ci_gate as gate


class ReleaseCiGateTests(unittest.TestCase):
    def test_only_successful_reuse_or_successful_fresh_ci_is_accepted(self):
        states = ("success", "failure", "cancelled", "skipped", "")
        for reuse, fresh, images in itertools.product(("true", "false", "", "TRUE"), states, states):
            with self.subTest(reuse=reuse, fresh=fresh, images=images):
                environment = {"REUSE_CI": reuse, "FRESH_CI_RESULT": fresh, "RELEASE_IMAGES_RESULT": images,
                               "REUSED_RUN": "42", "REUSED_ATTEMPT": "2"}
                accepted = (reuse, fresh, images) in (("true", "skipped", "success"),
                                                     ("false", "success", "skipped"))
                if accepted:
                    self.assertIn("passed", gate.validate(environment))
                else:
                    with self.assertRaises(ValueError):
                        gate.validate(environment)

    def test_reuse_requires_positive_unambiguous_attempt_and_run_ids(self):
        environment = {"REUSE_CI": "true", "FRESH_CI_RESULT": "skipped", "RELEASE_IMAGES_RESULT": "success",
                       "REUSED_RUN": "42", "REUSED_ATTEMPT": "1"}
        for key in ("REUSED_RUN", "REUSED_ATTEMPT"):
            for value in ("", "0", "-1", "01", "1\n", " 1", "failure"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    gate.validate({**environment, key: value})

    def test_cli_reports_failure_and_success(self):
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(gate.main(), 1)
        with patch.dict(os.environ, {"REUSE_CI": "false", "FRESH_CI_RESULT": "success",
                                     "RELEASE_IMAGES_RESULT": "skipped"}, clear=True), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(gate.main(), 0)
            self.assertIn("Fresh complete release CI", output.getvalue())


if __name__ == "__main__":
    unittest.main()
