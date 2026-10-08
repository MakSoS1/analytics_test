"""Held-out MITRE technique metrics and unlabeled office rates are different claims."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import numpy as np
import pandas as pd

from mitre_ml_fixture import FEATURES, TECHNIQUES, make_prepared, sha
from office_injection.technique_training import train_technique_models
from natural_traffic.technique_transfer_evaluation import evaluate_technique_transfer


def office_fixture(n=60, *, add_23=False):
    rng = np.random.default_rng(29)
    days = {}
    for day in ("2026-09-22", "2026-09-28"):
        frame = pd.DataFrame(rng.normal(3, .4, size=(n, len(FEATURES))), columns=FEATURES)
        frame["tls_version"] = np.nan if day == "2026-09-22" else 772
        frame["capture_day_id"] = day
        frame["label_binary"] = 0  # Never a verified office benign label.
        days[day] = frame
    if add_23:
        days["2026-09-23"] = pd.DataFrame({"pkt_count": [3.] * n})
    return days


class TechniqueTransferEvaluationTests(unittest.TestCase):
    def test_test_only_metrics_and_unverified_office_alert_fractions(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = root / "prepared"
            splits, contract = make_prepared(prepared)
            train_technique_models(prepared, splits, contract, root / "models", seed=11)
            days = office_fixture(add_23=True)
            office_before = {day: frame.to_json() for day, frame in days.items()}
            result = evaluate_technique_transfer(prepared, root / "models", days,
                                                  root / "evaluation")
            self.assertTrue(result["pipeline_verified"])
            self.assertFalse(result["production_ready"])
            self.assertFalse(result["technique_research_validated"])  # fixture-only labels
            self.assertTrue(result["office_transfer_diagnostic"])
            self.assertEqual(set(result["per_technique"]), set(TECHNIQUES))
            self.assertEqual(result["office_days"]["2026-09-23"]["status"], "incompatible_features")
            self.assertIn("office_alert_fraction", result["office_days"]["2026-09-28"])
            self.assertEqual({day: frame.to_json() for day, frame in days.items()}, office_before)
            self.assertNotIn("false_positive_rate", json.dumps(result))
            for technique in TECHNIQUES:
                self.assertGreater(result["per_technique"][technique]["roc_auc"], .85)
                self.assertEqual(result["per_technique"][technique]["independent_test_groups"], 2)
                self.assertIn("provenance_only_test_auc", result["per_technique"][technique])
                self.assertIn("shuffled_label_test_auc", result["per_technique"][technique])

    def test_frozen_genuine_signal_can_pass_research_gate_in_hypothetical_verified_fixture(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = root / "prepared"
            splits, contract = make_prepared(prepared, evidence_tier="independently_verified")
            train_technique_models(prepared, splits, contract, root / "models", seed=17)
            result = evaluate_technique_transfer(prepared, root / "models",
                                                  office_fixture(), root / "evaluation")
            self.assertTrue(result["technique_research_validated"])
            self.assertFalse(result["production_ready"])

    def test_origin_only_shortcut_fails_even_with_declared_verified_evidence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = root / "prepared"
            splits, contract = make_prepared(prepared, label_effect=False,
                                             evidence_tier="independently_verified",
                                             provenance_shortcut=True)
            train_technique_models(prepared, splits, contract, root / "models", seed=19)
            report = evaluate_technique_transfer(prepared, root / "models",
                                                 office_fixture(), root / "evaluation")
            self.assertFalse(report["technique_research_validated"])
            self.assertIn("provenance_shortcut", report["per_technique"]["T1001"]["failure_reasons"])

    def test_originless_random_effect_does_not_pass_research_gate(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = root / "prepared"
            splits, contract = make_prepared(prepared, label_effect=False,
                                             evidence_tier="independently_verified")
            train_technique_models(prepared, splits, contract, root / "models", seed=19)
            report = evaluate_technique_transfer(prepared, root / "models",
                                                 office_fixture(), root / "evaluation")
            self.assertFalse(report["technique_research_validated"])
            self.assertLess(report["per_technique"]["T1001"]["roc_auc"], .8)

    def test_tampered_split_or_model_is_rejected_before_loading(self):
        for target in ("splits.parquet", "models/T1001.joblib"):
            with self.subTest(target=target), TemporaryDirectory() as tmp:
                root = Path(tmp)
                prepared = root / "prepared"
                splits, contract = make_prepared(prepared)
                models = root / "models"
                train_technique_models(prepared, splits, contract, models)
                with (models / target).open("ab") as stream:
                    stream.write(b"garbage")
                with self.assertRaisesRegex(ValueError, "checksum"):
                    evaluate_technique_transfer(prepared, models, office_fixture(), root / "eval")


if __name__ == "__main__":
    unittest.main()
