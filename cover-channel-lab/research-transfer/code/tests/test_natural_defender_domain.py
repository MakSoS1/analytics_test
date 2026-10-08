import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import numpy as np
import pandas as pd

from natural_traffic.defender_domain import (
    LABELS,
    diagnostic_office_baseline,
    load_user_input,
    prepare_frames,
    shared_transport_columns,
)
from natural_traffic.office_day_transfer import TRANSPORT_FEATURES


def make_frame(n, prefix, *, shift=0.0):
    frame = pd.DataFrame({
        col: np.linspace(10 + idx, 100 + idx, n) + shift
        for idx, col in enumerate(TRANSPORT_FEATURES[:18])
    })
    frame["independent_source_group"] = [f"{prefix}-{i % 20}" for i in range(n)]
    frame["global_session_uid"] = [f"{prefix}-session-{i}" for i in range(n)]
    return frame


class OfficeDomainPreparationTests(unittest.TestCase):
    def setUp(self):
        self.sha = hashlib.sha256(b"test benign workflow").hexdigest()
        self.a = make_frame(60, "train")
        self.b = make_frame(60, "holdout", shift=10)
        self.source = make_frame(30, "input", shift=4)

    def test_default_label_does_not_assume_benign(self):
        train, holdout, user, report = prepare_frames(
            self.source, self.a, self.b, source_sha256=self.sha,
        )
        self.assertEqual(set(train["label"]), {-1})
        self.assertEqual(set(user["label"]), {-1})
        self.assertEqual(set(holdout["label"]), {-1})
        self.assertEqual(report["office_labels"], "unverified_and_unlabeled")
        self.assertTrue(report["office_holdout_excluded_from_fitting"])
        self.assertFalse(report["production_ready"])
        self.assertTrue(set(report["feature_columns"]).isdisjoint(
            {"domain", "label", "group_id", "capture_day", "label_policy"}
        ))
        self.assertFalse(set(train["group_id"]) & set(holdout["group_id"]))
        self.assertEqual(len(train), 90)

    def test_explicit_verified_input_label_applies_to_source_only(self):
        train, holdout, user, report = prepare_frames(
            self.source, self.a, self.b,
            source_sha256=self.sha, source_label="verified_malicious",
        )
        self.assertEqual(set(user["label"]), {1})
        self.assertEqual(set(holdout["label"]), {-1})
        self.assertEqual(set(train[train["domain"] == "office_train"]["label"]), {-1})
        self.assertEqual(report["source_label"], "verified_malicious")

    def test_group_leakage_is_rejected(self):
        self.b.loc[0, "independent_source_group"] = "train-0"
        with self.assertRaisesRegex(ValueError, "leakage"):
            prepare_frames(self.source, self.a, self.b, source_sha256=self.sha)

    def test_unmeasured_feature_does_not_enter_model(self):
        self.source["tls_version"] = 771
        self.a["tls_version"] = np.nan
        self.b["tls_version"] = 771
        cols = shared_transport_columns(self.source, self.a, self.b)
        self.assertNotIn("tls_version", cols)
        self.assertIn("pkt_count", cols)

    def test_input_parquet_preserved_bitwise(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "upload.parquet"
            self.source.to_parquet(input_path, index=False)
            before = hashlib.sha256(input_path.read_bytes()).hexdigest()
            got, info = load_user_input(input_path, root)
            self.assertEqual(before, info["source_sha256"])
            self.assertEqual(before, hashlib.sha256(input_path.read_bytes()).hexdigest())
            self.assertEqual(info["format"], "parquet")
            self.assertEqual(len(got), 30)

    def test_unknown_format_rejected_without_writing(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "archive.bin"
            p.write_bytes(b"not a pcap")
            with self.assertRaisesRegex(ValueError, "supported inputs"):
                load_user_input(p, Path(tmp))

    def test_training_is_separate_from_holdout_and_never_reports_fpr(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            train, holdout, user, manifest = prepare_frames(
                self.source, self.a, self.b, source_sha256=self.sha,
            )
            for name, frame in (
                ("train_candidates.parquet", train),
                ("office_holdout.parquet", holdout),
                ("user_input.parquet", user),
            ):
                frame.to_parquet(root / name, index=False)
            manifest["outputs"] = {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.glob("*.parquet")
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            report = diagnostic_office_baseline(root)
            self.assertTrue(report["statistics_are_not_fpr_or_recall"])
            self.assertFalse(report["production_ready"])
            self.assertEqual(report["method"], "isolation_forest_train_day_only")
            self.assertEqual(report["model_features"], len(manifest["feature_columns"]))
            self.assertTrue(0 <= report["office_holdout_alert_fraction"] <= 1)
            # Never compute true-positive recall from one arbitrary capture group.
            self.assertNotIn("attack_recall", report)

    def test_tampered_prepared_features_are_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            train, holdout, user, manifest = prepare_frames(
                self.source, self.a, self.b, source_sha256=self.sha,
            )
            for name, frame in (
                ("train_candidates.parquet", train),
                ("office_holdout.parquet", holdout),
                ("user_input.parquet", user),
            ):
                frame.to_parquet(root / name, index=False)
            manifest["outputs"] = {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.glob("*.parquet")
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            (root / "user_input.parquet").write_bytes(b"invalid")
            with self.assertRaisesRegex(ValueError, "checksum"):
                diagnostic_office_baseline(root)


if __name__ == "__main__":
    unittest.main()
