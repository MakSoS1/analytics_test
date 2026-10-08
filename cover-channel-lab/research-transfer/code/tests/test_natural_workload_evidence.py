import unittest

import pandas as pd

from natural_traffic.workload_evidence import audit_workload_evidence


def office_frame(tls):
    return pd.DataFrame({"tls_version": tls, "pkt_count": [9] * len(tls)})


class BenignOfficeWorkloadEvidenceTests(unittest.TestCase):
    def test_port_443_without_app_metadata_cannot_train_user_personas(self):
        context = {
            "capture_point": {
                "before_or_after_nat": "unknown",
                "before_or_after_tls_proxy": "unknown",
                "client_os_windows_linux_share": "unknown",
            },
            "measurement_limits": {"ground_truth": "unlabelled"},
        }
        result = audit_workload_evidence(
            context,
            (office_frame([None, None]), office_frame([771, 772])),
        )
        self.assertFalse(result["office_workload_model_ready"])
        self.assertEqual(result["measured_tls_version_rows_by_day"], [0, 2])
        self.assertFalse(result["office_app_mix_inferable_from_port_443"])
        self.assertIn("verified_application_and_user_action_annotation", result["missing_evidence"])
        self.assertIn("mirror_nat_and_tls_proxy_position", result["missing_evidence"])
        self.assertIn("measured_endpoint_os_population", result["missing_evidence"])
        self.assertIn("comparable_observed_tls_across_reference_days", result["missing_evidence"])

    def test_complete_documented_annotations_only_complete_evidence_gate(self):
        context = {
            "capture_point": {
                "before_or_after_nat": "before NAT",
                "before_or_after_tls_proxy": "before TLS proxy",
                "client_os_windows_linux_share": "measured OS shares",
            },
            "application_annotations": {
                "verified": True,
                "provenance": "consented aggregate endpoint inventory",
                "user_action_categories": ["reading", "documents"],
            },
        }
        result = audit_workload_evidence(
            context, (office_frame([771]), office_frame([771, 772]))
        )
        self.assertTrue(result["office_workload_model_ready"])
        self.assertFalse(result["production_ready"])
        self.assertEqual(result["naturalness_status"], "not_passed")

    def test_only_declared_but_unverified_labels_do_not_unlock(self):
        context = {"application_annotations": {
            "verified": False,
            "provenance": "unknown",
            "user_action_categories": ["reading"],
        }}
        result = audit_workload_evidence(
            context, (office_frame([771]), office_frame([771]))
        )
        self.assertFalse(result["verified_application_action_labels"])
        self.assertFalse(result["office_workload_model_ready"])


if __name__ == "__main__":
    unittest.main()
