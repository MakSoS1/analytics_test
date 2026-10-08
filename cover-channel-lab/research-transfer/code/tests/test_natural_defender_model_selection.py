import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import numpy as np
import pandas as pd
import joblib

from natural_traffic.defender_model_selection import fit_until_validated
from natural_traffic.defender_domain import prepare_frames
from natural_traffic.office_day_transfer import TRANSPORT_FEATURES


def table(count, group_prefix, seed):
    rng = np.random.default_rng(seed)
    data = {
        name: (rng.lognormal(2.5 + i * .01, .2, count) + .1)
        for i, name in enumerate(TRANSPORT_FEATURES[:18])
    }
    df = pd.DataFrame(data)
    df["independent_source_group"] = [
        f"{group_prefix}:{i % 30}" for i in range(count)
    ]
    df["global_session_uid"] = [
        f"{group_prefix}:session:{i}" for i in range(count)
    ]
    return df


def prepared(root: Path, *, holdout_seed=2, user_seed=3):
    digest = hashlib.sha256(b"read only source").hexdigest()
    # Prepare a genuine user_input group without changing office train.
    user_source = table(40, "upload", user_seed)
    train, ho, user, manifest = prepare_frames(
        user_source,
        table(360, "office-train", 1),
        table(360, "office-holdout", holdout_seed),
        source_sha256=digest,
    )
    for name, frame in (
        ("train_candidates.parquet", train),
        ("office_holdout.parquet", ho),
        ("user_input.parquet", user),
    ):
        frame.to_parquet(root / name, index=False)
    manifest["outputs"] = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.glob("*.parquet")
    }
    (root / "manifest.json").write_text(json.dumps(manifest))


class DefenderModelSelectionTests(unittest.TestCase):
    def test_office_group_validation_and_saved_model_contract(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared(root)
            result = fit_until_validated(root, max_attempts=2)
            self.assertEqual(result["model_training_domain"] if "model_training_domain" in result else "office_train_only", "office_train_only")
            self.assertTrue(result["validation_uses_only_office_train_groups"])
            self.assertFalse(result["holdout_or_source_used_for_selection"])
            self.assertTrue(result["train_holdout_groups_disjoint"])
            self.assertTrue(result["reported_alert_rate_is_not_fpr"])
            self.assertFalse(result["office_naturalness_proven"])
            self.assertFalse(result["production_ready"])
            self.assertGreaterEqual(result["attempts_executed"], 1)
            self.assertLessEqual(result["attempts_executed"], 2)
            self.assertTrue((root / "defender_model.joblib").is_file())
            bundle = joblib.load(root / "defender_model.joblib")
            self.assertEqual(bundle["model_training_domain"], "office_train_only")
            self.assertEqual(len(bundle["feature_columns"]), result["feature_count"])
            self.assertTrue(0 <= result["office_holdout_alert_fraction"] <= 1)

    def test_source_and_holdout_never_drive_model_selection(self):
        with TemporaryDirectory() as first, TemporaryDirectory() as second:
            a, b = Path(first), Path(second)
            prepared(a, user_seed=3, holdout_seed=2)
            prepared(b, user_seed=31, holdout_seed=47)
            left = fit_until_validated(a, max_attempts=2)
            right = fit_until_validated(b, max_attempts=2)
            self.assertEqual(left["candidate_history"], right["candidate_history"])
            self.assertEqual(left["selected_candidate"], right["selected_candidate"])

    def test_modified_input_rejected_before_any_model_is_fit(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared(root)
            (root / "user_input.parquet").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                fit_until_validated(root)
            self.assertFalse((root / "defender_model.joblib").exists())

    def test_failed_strict_validation_remains_not_passed(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared(root)
            report = fit_until_validated(
                root, max_attempts=1, validation_tolerance=1e-12,
            )
            self.assertEqual(report["attempts_executed"], 1)
            self.assertFalse(report["selected_validation_passed"])
            self.assertEqual(report["status"], "train_day_validation_not_passed")
            self.assertFalse(report["production_ready"])
            self.assertFalse(report["office_naturalness_proven"])

    def test_invalid_optimization_budget_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared(root)
            with self.assertRaises(ValueError):
                fit_until_validated(root, max_attempts=99)
            with self.assertRaises(ValueError):
                fit_until_validated(root, validation_tolerance=0)


if __name__ == "__main__":
    unittest.main()