"""Pinned office reference is an unlabeled measurement, never benign ground truth."""

import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

import numpy as np
import pandas as pd

from natural_traffic.office_day_transfer import TRANSPORT_FEATURES
from natural_traffic.office_reference import load_office_reference, freeze_feature_contract


ROOT = Path(__file__).resolve().parents[2] / "datasets"
ADDITIONAL = ROOT / "office-additional-days-20261008"
COVER = ROOT / "office-cover-20261006"


def fixture_features(n=30):
    frame = pd.DataFrame({key: [2.0 + i] * n
                          for i, key in enumerate(TRANSPORT_FEATURES[:18])})
    frame["tls_version"] = [772] * n
    frame["capture_day_id"] = ["2026-09-28"] * n
    frame["independent_source_group"] = [f"client-{i}" for i in range(n)]
    frame["label_binary"] = [1] * n  # Never a confirmed office technique label.
    return frame


class FrozenOfficeReferenceTests(unittest.TestCase):
    def test_only_measured_common_transport_features_can_enter_model(self):
        user = fixture_features()
        day22 = fixture_features()
        day22["tls_version"] = np.nan
        day28 = fixture_features()
        result = freeze_feature_contract(user, {
            "2026-09-22": day22, "2026-09-28": day28,
        })
        self.assertEqual(result["feature_columns"], list(TRANSPORT_FEATURES[:18]))
        for excluded in ("tls_version", "label_binary", "capture_day_id", "independent_source_group"):
            self.assertNotIn(excluded, result["feature_columns"])
        self.assertEqual(result["unavailable_families"]["tls"], "unmeasured_on_2026-09-22")
        self.assertEqual(result["office_labels"], "unknown_unverified")
        self.assertEqual(len(result["feature_schema_sha256"]), 64)
        self.assertFalse(result["production_ready"])

    def test_optional_23_september_is_independently_diagnosed(self):
        user = fixture_features()
        day22 = fixture_features()
        day28 = fixture_features()
        broken23 = pd.DataFrame({"pkt_count": [2.0] * 30})
        result = freeze_feature_contract(user, {
            "2026-09-22": day22, "2026-09-28": day28, "2026-09-23": broken23,
        })
        self.assertEqual(result["day_status"]["2026-09-23"], "incompatible_features")
        self.assertEqual(len(result["feature_columns"]), 18)

    def test_less_than_twelve_measured_features_is_rejected(self):
        user = fixture_features()[list(TRANSPORT_FEATURES[:11])]
        with self.assertRaisesRegex(ValueError, "12"):
            freeze_feature_contract(user, {
                "2026-09-22": fixture_features(),
                "2026-09-28": fixture_features(),
            })

    def test_pinned_checked_in_office_days_have_expected_rows(self):
        days = load_office_reference(ADDITIONAL, COVER)
        self.assertEqual(set(days), {"2026-09-22", "2026-09-23", "2026-09-28"})
        self.assertEqual([len(days[key]) for key in ("2026-09-22", "2026-09-23", "2026-09-28")],
                         [4000, 5726, 4002])
        self.assertTrue(days["2026-09-22"]["tls_version"].isna().all())
        result = freeze_feature_contract(fixture_features(), days)
        self.assertNotIn("tls_version", result["feature_columns"])
        self.assertTrue(result["feature_columns"])

    def test_mutated_manifest_and_table_cannot_masquerade_as_office_reference(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(ADDITIONAL / "DATA_MANIFEST.json", root / "DATA_MANIFEST.json")
            (root / "DATA_MANIFEST.json").write_text('{"edited":true}\n')
            with self.assertRaisesRegex(ValueError, "manifest SHA256"):
                load_office_reference(root)

            shutil.copy2(ADDITIONAL / "DATA_MANIFEST.json", root / "DATA_MANIFEST.json")
            shutil.copy2(ADDITIONAL / "office_day_02.parquet", root / "office_day_02.parquet")
            shutil.copy2(ADDITIONAL / "office_day_03.parquet", root / "office_day_03.parquet")
            with (root / "office_day_02.parquet").open("ab") as handle:
                handle.write(b"tampered")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                load_office_reference(root)


if __name__ == "__main__":
    unittest.main()
