import hashlib
import json
import unittest
from pathlib import Path

import pandas as pd

from natural_traffic.reference import load_reference, model_feature_columns


ROOT = Path(__file__).resolve().parents[2] / "datasets" / "office-cover-20261006"


class NaturalTrafficReferenceTests(unittest.TestCase):
    def test_required_reference_shapes(self):
        ref = load_reference(ROOT)
        self.assertEqual(ref.pipeline_office.shape, (5726, 180))
        self.assertEqual(ref.pipeline_added.shape, (2784, 180))
        self.assertEqual(ref.pipeline_original.shape, (8510, 155))
        self.assertEqual(ref.arkime_office.shape, (6053, 833))
        self.assertEqual(ref.arkime_added.shape, (2790, 833))
        self.assertEqual(ref.matched_office.shape, (5723, 990))
        self.assertEqual(ref.matched_added.shape, (2784, 990))
        self.assertEqual(ref.matched_mixed.shape, (8507, 990))
        self.assertEqual(ref.session_comparison.shape, (8843, 50))

    def test_public_parquet_hashes_match_manifest(self):
        manifest = json.loads((ROOT / "DATA_MANIFEST.json").read_text())
        for row in manifest["tables"]:
            path = ROOT / row["file"]
            self.assertTrue(path.is_file(), row["file"])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, row["sha256"], row["file"])

    def test_feature_policy_uses_declared_features_and_excludes_metadata(self):
        df = pd.read_parquet(ROOT / "pipeline_original_155.parquet")
        dictionary = json.loads((ROOT / "pipeline_column_dictionary.json").read_text())
        cols = model_feature_columns(df, dictionary)
        declared = {r["column"] for r in dictionary if r.get("kind") == "feature"}
        self.assertEqual(set(cols), declared.intersection(df.columns))
        forbidden_fragments = ("label", "source", "origin", "uid", "pair", "profile", "anon_")
        for col in cols:
            low = col.lower()
            self.assertFalse(any(x in low for x in forbidden_fragments), col)
            self.assertTrue(pd.api.types.is_numeric_dtype(df[col].dtype) or pd.api.types.is_bool_dtype(df[col].dtype), col)

    def test_numeric_evaluation_does_not_require_decryption(self):
        ref = load_reference(ROOT)
        self.assertGreater(len(ref.feature_columns), 100)
        self.assertFalse(hasattr(ref, "dictionary_plaintext"))


if __name__ == "__main__":
    unittest.main()
