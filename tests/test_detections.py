import unittest
from detections.alert_rules import ERROR_BUDGET_MINUTES, compute_burn_rate, evaluate_event

class TestAlertRules(unittest.TestCase):
    def test_slo_burn_and_drift(self) -> None:
        self.assertEqual(ERROR_BUDGET_MINUTES, 43.2)
        self.assertEqual(compute_burn_rate(0.025), 25.0)
        (alert,) = evaluate_event({"s3.request.error_rate": 0.025, "s3.security.kms_enforced": True}, [])
        self.assertEqual(alert.rule_id, "FEDRAMP-SLO-002")
