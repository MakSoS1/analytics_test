import unittest

from natural_traffic.naturalness_release_gate import assess_naturalness_evidence


def report(status="passed_candidate", auc=0.52, family_pass=True):
    return {
        "kind": "naturalness",
        "status": status,
        "support": {"office_groups": 150, "control_groups": 64},
        "payload": {
            "max_auc": auc,
            "distribution": {"passed": family_pass},
        },
    }


class IndependentNaturalnessReleaseGateTests(unittest.TestCase):
    def test_green_software_ci_cannot_replace_blind_office_evidence(self):
        result = assess_naturalness_evidence(report())
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("new_blind_office_reference_missing", result["reasons"])
        self.assertIn("measurement_parity_unverified", result["reasons"])
        self.assertIn("legitimate_application_ground_truth_missing", result["reasons"])
        self.assertFalse(result["office_naturalness_proven"])
        self.assertFalse(result["production_ready"])

    def test_observed_discriminator_auc_near_one_stays_blocked(self):
        result = assess_naturalness_evidence(
            report(status="not_passed", auc=0.9998, family_pass=False),
            external_blind_office_verified=True,
            capture_environment_equivalent=True,
            legitimate_workload_labels_verified=True,
        )
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("c2st_threshold_not_met", result["reasons"])
        self.assertIn("candidate_naturalness_not_passed", result["reasons"])
        self.assertIn("feature_family_distribution_not_passed", result["reasons"])

    def test_incomplete_report_cannot_pass(self):
        result = assess_naturalness_evidence({})
        self.assertIn("missing_naturalness_report", result["reasons"])
        self.assertIn("insufficient_independent_groups", result["reasons"])
        self.assertIn("c2st_threshold_not_met", result["reasons"])

    def test_only_external_independent_evidence_allows_review_status(self):
        result = assess_naturalness_evidence(
            report(),
            external_blind_office_verified=True,
            capture_environment_equivalent=True,
            legitimate_workload_labels_verified=True,
        )
        self.assertEqual(result["status"], "ready_for_review")
        self.assertEqual(result["reasons"], [])
        self.assertFalse(result["production_ready"])

    def test_small_group_support_prevents_favorable_auc_from_passing(self):
        candidate = report()
        candidate["support"]["control_groups"] = 9
        result = assess_naturalness_evidence(
            candidate,
            external_blind_office_verified=True,
            capture_environment_equivalent=True,
            legitimate_workload_labels_verified=True,
        )
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("insufficient_independent_groups", result["reasons"])


if __name__ == "__main__":
    unittest.main()
