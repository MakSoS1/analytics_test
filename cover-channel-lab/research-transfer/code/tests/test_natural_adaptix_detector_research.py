"""Research-only paired detector checks; no generated positives are office ground truth."""
from __future__ import annotations

import unittest

import pandas as pd

from natural_traffic.adaptix_detector_research import CaptureFeatures, evaluate_paired_detector


def _fixture(*, rows: int = 1) -> list[CaptureFeatures]:
    captures = []
    for profile in range(3):
        for transport in ("tcp", "mtls"):
            pair_id = f"{transport}-p{profile}"
            for arm in ("control", "scenario"):
                scenario = arm == "scenario"
                # The genuine label effect remains stable across profiles and transports.
                packet_count = 10 + profile + (30 if scenario else 0)
                captures.append(CaptureFeatures(
                    pair_id=pair_id, profile_id=f"p{profile}", transport=transport,
                    arm=arm, features=pd.DataFrame({
                        "pkt_count": [packet_count] * rows,
                        "flow_duration": [5.0 + profile * 100] * rows,
                        "total_bytes": [1000.0 + profile * 10] * rows,
                    }),
                ))
    return captures


class AdaptixDetectorResearchTests(unittest.TestCase):
    def test_rejects_unpaired_capture(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one scenario and control"):
            evaluate_paired_detector(_fixture()[:-1])

    def test_rejects_identity_feature_even_when_it_predicts_label(self) -> None:
        captures = _fixture()
        for capture in captures:
            capture.features["src_ip"] = "10.1.1.1" if capture.arm == "control" else "10.2.2.2"
        with self.assertRaisesRegex(ValueError, "not an eligible transport feature"):
            evaluate_paired_detector(captures, feature_columns=["src_ip"])

    def test_group_holdout_finds_genuine_signal_without_row_leakage(self) -> None:
        result = evaluate_paired_detector(_fixture(rows=7), feature_columns=[
            "pkt_count", "flow_duration", "total_bytes"], max_features=2)
        self.assertEqual(result["independent_pairs"], 6)
        self.assertEqual(result["capture_count"], 12)
        self.assertEqual(result["measured_session_rows"], 84)
        self.assertEqual(len(result["folds"]["leave_one_profile_out"]), 3)
        self.assertEqual(len(result["folds"]["leave_one_transport_out"]), 2)
        for suite in result["folds"].values():
            for fold in suite:
                self.assertTrue(set(fold["train_pair_ids"]).isdisjoint(fold["test_pair_ids"]))
                self.assertIn("pkt_count", fold["selected_features"])
                self.assertGreaterEqual(fold["roc_auc"], 0.5)
                self.assertAlmostEqual(fold["origin_only_roc_auc"], 0.5)
                self.assertGreater(fold["feature_ablation_auc_drop"]["pkt_count"], 0.2)
        self.assertFalse(result["technique_research_validated"])
        self.assertFalse(result["production_ready"])
        self.assertEqual(result["comparison_scope"], "adaptix_vs_isolated_paired_telemetry_control")

    def test_missing_numeric_support_fails_closed(self) -> None:
        captures = _fixture()
        for capture in captures:
            capture.features["pkt_count"] = None
        with self.assertRaisesRegex(ValueError, "no eligible numeric"):
            evaluate_paired_detector(captures, feature_columns=["pkt_count"])

    def test_identical_measured_features_report_no_detector_signal_not_a_success(self) -> None:
        captures = _fixture()
        for capture in captures:
            capture.features["pkt_count"] = 10 + int(capture.profile_id[-1])
        report = evaluate_paired_detector(captures, feature_columns=["pkt_count"])
        self.assertEqual(report["detector_signal_status"], "no_stable_paired_signal")
        self.assertFalse(report["technique_research_validated"])
        for rows in report["folds"].values():
            for fold in rows:
                self.assertEqual(fold["selected_features"], [])
                self.assertEqual(fold["roc_auc"], 0.5)

    def test_office_observations_are_only_post_selection_alert_diagnostics(self) -> None:
        captures = _fixture()
        office_low = {"day-a": pd.DataFrame({
            "pkt_count": [10] * 40, "flow_duration": [2.] * 40,
            "total_bytes": [100.] * 40,
        })}
        office_high = {"day-a": pd.DataFrame({
            "pkt_count": [1000] * 40, "flow_duration": [2.] * 40,
            "total_bytes": [100.] * 40,
        })}
        a = evaluate_paired_detector(captures, office_days=office_low)
        b = evaluate_paired_detector(captures, office_days=office_high)
        self.assertEqual(a["selected_feature_frequency"], b["selected_feature_frequency"])
        self.assertEqual(a["metrics"], b["metrics"])
        self.assertEqual(a["office_labels"], "unknown_unverified")
        self.assertNotIn("false_positive_rate", a["office_diagnostic"]["day-a"])
        self.assertIn("day-a", a["office_diagnostic"])
        self.assertLess(a["office_diagnostic"]["day-a"]["mean_alert_fraction"],
                        b["office_diagnostic"]["day-a"]["mean_alert_fraction"])


if __name__ == "__main__":
    unittest.main()
