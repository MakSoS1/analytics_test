"""Labels must follow corroborated measured sessions, not uploaded file origin."""

from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import pandas as pd

from natural_traffic.office_day_transfer import TRANSPORT_FEATURES
from natural_traffic.verified_corpus import build_verified_corpus


def _digest(path):
    return sha256(path.read_bytes()).hexdigest()


class VerifiedCorpusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "sources"
        self.root.mkdir()
        self.sources = []
        self.hashes = {}
        for i, (tech, state) in enumerate((("T1001", "verified_positive"),
                                          ("T1001", "matched_control"),
                                          ("T1071.001", "verified_positive"),
                                          ("T1071.001", "matched_control"))):
            row_key = "target" if state == "verified_positive" else "control"
            frame = pd.DataFrame({name: [i + 2.0, i + 3.0] for name in TRANSPORT_FEATURES[:15]})
            frame["global_session_uid"] = [row_key, "background"]
            frame["origin_noise"] = f"lab-{i}"
            source_path = self.root / f"source-{i}.parquet"
            frame.to_parquet(source_path, index=False)
            self.hashes[source_path] = _digest(source_path)
            membership = self.root / f"membership-{i}.jsonl"
            membership.write_text(json.dumps({"source_id": f"source-{i}",
                                               "session_key": row_key,
                                               "label_binary": 1 if state == "verified_positive" else 0,
                                               "technique_id": tech}) + "\n")
            receipt = self.root / f"receipt-{i}.json"
            receipt.write_text('{"fixture_only":true}\n')
            self.sources.append({
                "source_id": f"source-{i}", "relative_path": source_path.name,
                "sha256": self.hashes[source_path], "label_state": state,
                "technique_ids": [tech], "pair_id": f"pair-{i // 2}",
                "parent_campaign_id": f"campaign-{i // 2}",
                "runtime_profile_id": "linux-ssl", "capture_group_id": f"capture-{i}",
                "capture_day_id": "2026-09-22", "measurement_vantage": "lab-nic",
                "extractor_version": "measured-fixture-v1", "evidence_tier": "fixture_only",
                "membership_relative_path": membership.name,
                "membership_sha256": _digest(membership),
                "receipt_relative_path": receipt.name,
                "receipt_sha256": _digest(receipt),
            })

    def manifest(self, sources=None):
        path = self.root / "manifest.json"
        path.write_text(json.dumps({"version": "defender-source-manifest-v1",
                                    "sources": self.sources if sources is None else sources}))
        return path

    def test_labels_only_confirmed_members_and_keeps_X_measured(self):
        out = Path(self.tmp.name) / "corpus"
        report = build_verified_corpus(self.manifest(), self.root, out)
        meta = pd.read_parquet(out / "labels_metadata.parquet")
        x = pd.read_parquet(out / "features.parquet")
        self.assertEqual(len(x), 8)
        self.assertEqual(meta.loc[meta.session_key.eq("target"), "label_binary"].tolist(), [1, 1])
        self.assertEqual(meta.loc[meta.session_key.eq("control"), "label_binary"].tolist(), [0, 0])
        self.assertEqual(meta.loc[meta.session_key.eq("background"), "label_binary"].tolist(), [-1] * 4)
        self.assertEqual(set(meta.loc[meta.label_binary.eq(1), "technique_id"]), {"T1001", "T1071.001"})
        self.assertEqual(list(x.columns), list(TRANSPORT_FEATURES[:15]))
        for private in ("global_session_uid", "label_binary", "source_id", "capture_day_id",
                        "origin_noise", "runtime_profile_id", "technique_id"):
            self.assertNotIn(private, x)
        self.assertFalse(report["production_ready"])
        self.assertEqual(report["label_counts"], {"-1": 4, "0": 2, "1": 2})
        self.assertEqual(len(report["source_hashes"]), 4)
        for path, expected in self.hashes.items():
            self.assertEqual(_digest(path), expected)

    def test_unverified_upload_without_memberships_never_becomes_positive(self):
        extra = self.root / "unverified.csv"
        frame = pd.DataFrame({name: [2.0] for name in TRANSPORT_FEATURES[:15]})
        frame.to_csv(extra, index=False)
        sources = [dict(s) for s in self.sources]
        sources.append({**dict(sources[0]), "source_id": "outside", "relative_path": extra.name,
                        "sha256": _digest(extra), "label_state": "unverified_external",
                        "technique_ids": [], "pair_id": None,
                        "membership_relative_path": None, "membership_sha256": None,
                        "receipt_relative_path": None, "receipt_sha256": None})
        out = Path(self.tmp.name) / "corpus"
        build_verified_corpus(self.manifest(sources), self.root, out)
        meta = pd.read_parquet(out / "labels_metadata.parquet")
        self.assertEqual(meta.loc[meta.source_id.eq("outside"), "label_binary"].tolist(), [-1])

    def test_changed_membership_is_rejected_before_output_is_created(self):
        manifest = self.manifest()
        (self.root / "membership-0.jsonl").write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            build_verified_corpus(manifest, self.root, Path(self.tmp.name) / "corpus")
        self.assertFalse((Path(self.tmp.name) / "corpus").exists())

    def test_wrong_source_membership_and_missing_session_identity_are_rejected(self):
        broken = self.root / "membership-0.jsonl"
        broken.write_text(json.dumps({"source_id": "wrong", "session_key": "target",
                                      "label_binary": 1, "technique_id": "T1001"}) + "\n")
        sources = [dict(s) for s in self.sources]
        sources[0]["membership_sha256"] = _digest(broken)
        with self.assertRaisesRegex(ValueError, "membership"):
            build_verified_corpus(self.manifest(sources), self.root, Path(self.tmp.name) / "corpus")

        source = self.root / "source-0.parquet"
        frame = pd.read_parquet(source).drop(columns="global_session_uid")
        frame.to_parquet(source, index=False)
        sources[0]["sha256"] = _digest(source)
        broken.write_text(json.dumps({"source_id": "source-0", "session_key": "target",
                                      "label_binary": 1, "technique_id": "T1001"}) + "\n")
        sources[0]["membership_sha256"] = _digest(broken)
        with self.assertRaisesRegex(ValueError, "session"):
            build_verified_corpus(self.manifest(sources), self.root, Path(self.tmp.name) / "corpus")

    def test_duplicate_measured_session_identity_cannot_expand_one_verified_membership(self):
        source = self.root / "source-0.parquet"
        frame = pd.read_parquet(source)
        frame["global_session_uid"] = ["target", "target"]
        frame.to_parquet(source, index=False)
        sources = [dict(s) for s in self.sources]
        sources[0]["sha256"] = _digest(source)
        out = Path(self.tmp.name) / "corpus"
        with self.assertRaisesRegex(ValueError, "ambiguous.*session"):
            build_verified_corpus(self.manifest(sources), self.root, out)
        self.assertFalse(out.exists())

    def test_duplicate_source_id_rejected_before_extraction(self):
        sources = [dict(s) for s in self.sources]
        sources[1]["source_id"] = sources[0]["source_id"]
        with self.assertRaisesRegex(ValueError, "duplicate source_id"):
            build_verified_corpus(self.manifest(sources), self.root, Path(self.tmp.name) / "corpus")

    def test_never_overwrites_existing_corpus(self):
        output = Path(self.tmp.name) / "corpus"
        output.mkdir()
        marker = output / "other.txt"
        marker.write_text("unchanged")
        with self.assertRaises(FileExistsError):
            build_verified_corpus(self.manifest(), self.root, output)
        self.assertEqual(marker.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
