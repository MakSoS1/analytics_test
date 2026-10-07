import unittest

import numpy as np
import pandas as pd

from natural_traffic.evaluation import (
    evaluate_c2st,
    evaluate_family_distances,
    evaluate_technique_signal,
    prepare_diagnostic_frame,
)
from natural_traffic.profiles import ProfileRegistry


class NaturalEvaluationTests(unittest.TestCase):
    def paired_domains(self, n=40):
        x = np.linspace(-2.0, 2.0, n)
        office = pd.DataFrame({"x": x, "cat": ["https"] * n})
        control = pd.DataFrame({"x": x.copy(), "cat": ["https"] * n})
        groups = {
            "office": [f"o{i}" for i in range(n)],
            "controls": [f"c{i}" for i in range(n)],
        }
        return office, control, groups

    def test_identical_domains_are_near_chance(self):
        office, control, groups = self.paired_domains()
        report = evaluate_c2st(
            office, control, groups,
            feature_columns=["x", "cat"],
            min_groups=30,
            bootstrap_reps=20,
            random_state=2,
        )
        self.assertEqual(report["status"], "ok")
        self.assertLessEqual(max(m["auc"] for m in report["classifiers"].values()), 0.60)

    def test_injected_origin_artifact_is_detected(self):
        office, control, groups = self.paired_domains()
        control["x"] += 8.0
        report = evaluate_c2st(
            office, control, groups,
            feature_columns=["x"],
            min_groups=30,
            bootstrap_reps=20,
            random_state=3,
        )
        self.assertGreater(max(m["auc"] for m in report["classifiers"].values()), 0.95)

    def test_missingness_is_visible_to_domain_diagnostic(self):
        office, control, groups = self.paired_domains()
        control["x"] = np.nan
        report = evaluate_c2st(
            office, control, groups,
            feature_columns=["x"],
            min_groups=30,
            bootstrap_reps=20,
            random_state=4,
        )
        self.assertGreater(max(m["auc"] for m in report["classifiers"].values()), 0.90)

    def test_pseudonymized_token_values_are_not_model_inputs(self):
        office = pd.DataFrame({"token": ["anon_A", "anon_B", None], "proto": ["tcp", "udp", "tcp"]})
        control = pd.DataFrame({"token": ["anon_C", "anon_D", None], "proto": ["tcp", "udp", "tcp"]})
        matrix, _ = prepare_diagnostic_frame(office, control, ["token", "proto"])
        self.assertTrue(all(np.issubdtype(dtype, np.number) for dtype in matrix.dtypes))
        self.assertFalse(any("anon_" in str(v) for v in matrix.to_numpy().ravel()))
        self.assertFalse(any("token__cat__" in c for c in matrix.columns))
        self.assertTrue(any(c.startswith("token__missing") for c in matrix.columns))

    def test_family_distance_gate_passes_identical_and_rejects_shifted_family(self):
        office, control, groups = self.paired_domains()
        families = {"volume": ["x"]}
        same = evaluate_family_distances(office, control, groups["office"], families)
        self.assertTrue(same["passed"])
        shifted = control.copy()
        shifted["x"] += 10.0
        bad = evaluate_family_distances(office, shifted, groups["office"], families)
        self.assertFalse(bad["passed"])
        self.assertIn("volume", bad["failed_families"])
        self.assertEqual(bad["families"]["volume"]["top_features"][0]["feature"], "x")
        self.assertGreater(bad["families"]["volume"]["top_features"][0]["distance"], 0.9)

    def test_technique_signal_requires_naturalness_and_detects_paired_shift(self):
        n = 40
        x = np.linspace(-1.0, 1.0, n)
        control = pd.DataFrame({"x": x})
        scenario = pd.DataFrame({"x": x + 5.0})
        pairs = [f"p{i}" for i in range(n)]
        manifest = ProfileRegistry.default().manifest(["linux-curl"], seed=9)

        blocked = evaluate_technique_signal(
            manifest, scenario, control, pairs,
            naturalness_status="not_passed",
            feature_columns=["x"],
            bootstrap_reps=20,
        )
        self.assertFalse(blocked.training_eligible)

        report = evaluate_technique_signal(
            manifest, scenario, control, pairs,
            naturalness_status="passed_candidate",
            feature_columns=["x"],
            bootstrap_reps=20,
        )
        self.assertTrue(report.training_eligible)
        self.assertGreater(report.auc, 0.95)


if __name__ == "__main__":
    unittest.main()