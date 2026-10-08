"""Training must use verified pair labels, frozen X and train/validation only."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import pandas as pd

from mitre_ml_fixture import FEATURES, TECHNIQUES, make_prepared, sha
from office_injection.technique_training import train_technique_models


class TechniqueTrainingTests(unittest.TestCase):
    def test_two_techniques_train_with_frozen_validation_threshold(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared, out = root / "prepared", root / "models"
            splits, contract = make_prepared(prepared)
            result = train_technique_models(prepared, splits, contract, out, seed=11)
            self.assertEqual(set(result["techniques"]), set(TECHNIQUES))
            self.assertEqual(result["threshold_fit"], "validation_controls_only")
            self.assertFalse(result["office_holdout_used_for_model_selection"])
            self.assertFalse(result["production_ready"])
            self.assertFalse(result["technique_research_validated"])  # fixture_only
            self.assertEqual(result["feature_columns"], FEATURES)
            self.assertTrue((out / "splits.parquet").exists())
            self.assertEqual(sha(out / "splits.parquet"), result["split_checksum"])
            for tech in TECHNIQUES:
                measured = result["techniques"][tech]
                self.assertEqual(measured["train_groups"], 8)
                self.assertEqual(measured["validation_groups"], 2)
                self.assertEqual(measured["test_groups"], 2)
                self.assertTrue(0 < measured["validation_threshold"] < 1)
                self.assertLessEqual(measured["max_train_group_weight_fraction"], .15)
                self.assertTrue((out / "models" / (tech + ".joblib")).exists())

    def test_missing_class_in_test_is_not_hidden_with_nan_roc(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = root / "prepared"
            splits, contract = make_prepared(prepared)
            meta = pd.read_parquet(prepared / "labels_metadata.parquet")
            meta.loc[meta["session_key"].str.contains("-11-0-"), "label_binary"] = 1
            meta.loc[meta["session_key"].str.contains("-10-0-"), "label_binary"] = 1
            meta.to_parquet(prepared / "labels_metadata.parquet", index=False)
            self._repin(prepared)
            with self.assertRaisesRegex(ValueError, "both classes"):
                train_technique_models(prepared, splits, contract, root / "models")

    def test_provenance_only_shortcut_gets_measured_separately(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = root / "prepared"
            splits, contract = make_prepared(prepared, label_effect=False,
                                             provenance_shortcut=True)
            result = train_technique_models(prepared, splits, contract, root / "models")
            self.assertGreater(result["techniques"]["T1001"]["provenance_only_validation_auc"], .90)
            self.assertFalse(result["technique_research_validated"])

    def test_test_labels_and_office_holdout_never_drive_validation_cutoff(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / "prepared-1", root / "prepared-2"
            splits, contract = make_prepared(first)
            make_prepared(second)
            fake_office = pd.DataFrame({name: [999.0] for name in FEATURES})
            fake_office.to_parquet(first / "office_holdout.parquet", index=False)
            fake_office.mul(-1).to_parquet(second / "office_holdout.parquet", index=False)
            meta = pd.read_parquet(second / "labels_metadata.parquet")
            meta.loc[splits.eq("test"), "label_binary"] = 1 - meta.loc[splits.eq("test"), "label_binary"]
            meta.to_parquet(second / "labels_metadata.parquet", index=False)
            self._repin(second)
            a = train_technique_models(first, splits, contract, root / "models-1", seed=19)
            b = train_technique_models(second, splits, contract, root / "models-2", seed=19)
            self.assertEqual({tech: a["techniques"][tech]["validation_threshold"] for tech in TECHNIQUES},
                             {tech: b["techniques"][tech]["validation_threshold"] for tech in TECHNIQUES})

    def test_changed_feature_table_is_detected_before_model_artifact(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = root / "prepared"
            splits, contract = make_prepared(prepared)
            (prepared / "features.parquet").write_bytes(b"tamper")
            with self.assertRaisesRegex(ValueError, "checksum"):
                train_technique_models(prepared, splits, contract, root / "models")
            self.assertFalse((root / "models").exists())

    @staticmethod
    def _repin(root):
        path = root / "corpus_manifest.json"
        data = json.loads(path.read_text())
        data["outputs"]["labels_metadata.parquet"] = sha(root / "labels_metadata.parquet")
        path.write_text(json.dumps(data))


if __name__ == "__main__":
    unittest.main()
