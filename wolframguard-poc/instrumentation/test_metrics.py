import unittest
from metrics import rate, summarize

class EvidenceTests(unittest.TestCase):
    def test_no_trials_is_not_zero_percent(self):
        self.assertEqual(summarize([])["status"], "not_run")
        self.assertIsNone(rate([])["rate"])

    def test_unknown_is_not_no(self):
        self.assertIsNone(rate(["true", "unknown"])["rate"])

    def test_preparation_is_rejected(self):
        with self.assertRaises(ValueError):
            summarize([{"agent_configuration": "A", "outcome": "not_run"}])

    def test_execution_without_approval_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            summarize([{"agent_configuration": "A", "outcome": "Executed", "unauthorized_execution": "false"}])

    def test_zero_observed_events_is_not_a_guarantee(self):
        result = rate(["false"] * 10)
        self.assertEqual(result["rate"], 0)
        self.assertGreater(result["wilson_95"][1], 0.27)

if __name__ == "__main__":
    unittest.main()
