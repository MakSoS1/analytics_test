"""Grouped C2ST of real benign workloads against unlabelled office references."""
import unittest

import numpy as np
import pandas as pd

from natural_traffic.benign_transfer_evaluation import (
    _group_folds, evaluate_benign_transfer,
)
from natural_traffic.office_day_transfer import TRANSPORT_FEATURES


FEATURES = list(TRANSPORT_FEATURES[:12])


def _fixture(*, shift: float = 0, groups: int = 9) -> tuple[dict, pd.DataFrame, list]:
    rng = np.random.default_rng(20261009)
    office_days = {}
    for day in ("2026-09-22", "2026-09-28"):
        values = rng.uniform(1, 8, size=(groups * 3, len(FEATURES)))
        office = pd.DataFrame(values, columns=FEATURES)
        office["independent_source_group"] = [f"{day}:office-{i // 3}" for i in range(len(office))]
        office["label"] = -1
        office_days[day] = office
    generated = pd.DataFrame(
        rng.uniform(1, 8, size=(groups * 3, len(FEATURES))) + shift,
        columns=FEATURES,
    )
    benign_groups = [f"fixture-{i // 3}" for i in range(len(generated))]
    generated["source_marker"] = "BENIGN_SOURCE_MUST_NOT_ENTER_X"
    return office_days, generated, benign_groups


class BenignOfficeTransferTests(unittest.TestCase):
    def test_group_split_has_no_source_overlap(self):
        labels = np.array([0] * 24 + [1] * 24)
        groups = [f"office-{i // 3}" for i in range(24)] + [
            f"fixture-{i // 3}" for i in range(24)
        ]
        partitions = _group_folds(labels, groups)
        self.assertEqual(len(partitions), 3)
        for train, test in partitions:
            self.assertFalse({groups[i] for i in train} & {groups[i] for i in test})
            self.assertEqual(set(labels[test]), {0, 1})

    def test_benign_c2st_never_uses_source_ids_or_office_labels(self):
        days, generated, group_ids = _fixture()
        result = evaluate_benign_transfer(days, generated,
                                          feature_columns=FEATURES,
                                          benign_group_ids=group_ids)
        self.assertEqual(result["generated_vs_office"]["status"], "evaluated")
        self.assertEqual(result["office_negative_control"]["status"], "evaluated")
        self.assertEqual(result["office_labels"], "unknown_unverified")
        self.assertFalse(result["production_ready"])
        self.assertEqual(result["feature_columns"], FEATURES)
        self.assertTrue(result["feature_family_shift"])
        self.assertTrue(all(isinstance(v, float) for v in result["feature_family_shift"].values()))
        self.assertNotIn("BENIGN_SOURCE_MUST_NOT_ENTER_X", str(result))
        self.assertEqual(result["naturalness_status"], "not_proven")

    def test_clear_source_shift_detected_on_group_holdouts(self):
        days, generated, group_ids = _fixture(shift=100)
        report = evaluate_benign_transfer(days, generated,
                                          feature_columns=FEATURES,
                                          benign_group_ids=group_ids)
        mean_auc = report["generated_vs_office"]["models"]["extra_trees"]["mean_auc"]
        self.assertGreater(mean_auc, 0.9)
        self.assertTrue(report["generated_vs_office"]["no_group_leakage"])
        self.assertFalse(report["office_naturalness_proven"])

    def test_missing_feature_coverage_fails_closed(self):
        days, generated, group_ids = _fixture()
        generated[FEATURES[0]] = np.nan
        report = evaluate_benign_transfer(days, generated,
                                          feature_columns=FEATURES,
                                          benign_group_ids=group_ids)
        self.assertEqual(report["generated_vs_office"]["status"],
                         "insufficient_support")
        self.assertIsNone(report["generated_vs_office"].get("models"))

    def test_small_number_of_independent_clients_not_called_natural(self):
        days, generated, group_ids = _fixture(groups=2)
        report = evaluate_benign_transfer(days, generated,
                                          feature_columns=FEATURES,
                                          benign_group_ids=group_ids)
        self.assertEqual(report["generated_vs_office"]["status"],
                         "insufficient_support")

    def test_origin_fields_refused_as_features(self):
        days, generated, group_ids = _fixture()
        with self.assertRaisesRegex(ValueError, "transport"):
            evaluate_benign_transfer(days, generated,
                                     feature_columns=["source_marker"] + FEATURES,
                                     benign_group_ids=group_ids)


if __name__ == "__main__":
    unittest.main()
