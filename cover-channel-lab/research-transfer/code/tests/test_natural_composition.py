import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from natural_traffic.capture import probe_capability, run_capture
from natural_traffic.composition import (
    CompositionIntegrityError,
    compose_feature_alternatives,
    extract_pipeline_capture,
    validate_arkime_table,
    validate_pipeline_table,
    validate_strict_match_table,
)
from natural_traffic.contracts import GenerationContext
from natural_traffic.profiles import ProfileRegistry


ROOT = Path(__file__).resolve().parents[2] / "datasets" / "office-cover-20261006"


def sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class PublicFeatureCompositionTests(unittest.TestCase):
    def test_feature_alternatives_preserve_sources_and_leave_office_unlabelled(self):
        office_path = ROOT / "pipeline_office_full.parquet"
        added = pd.read_parquet(ROOT / "pipeline_added_full.parquet")
        office = pd.read_parquet(office_path)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            scenario_path = root / "scenario.parquet"
            control_path = root / "control.parquet"
            added.iloc[:2].to_parquet(scenario_path, index=False)
            added.iloc[2:4].to_parquet(control_path, index=False)
            before = {
                "office": sha(office_path),
                "scenario": sha(scenario_path),
                "control": sha(control_path),
            }
            report = compose_feature_alternatives(
                office_path,
                scenario_path,
                control_path,
                root / "out",
                pair_id="fixture-pair",
            )
            self.assertEqual(before["office"], sha(office_path))
            self.assertEqual(before["scenario"], sha(scenario_path))
            self.assertEqual(before["control"], sha(control_path))
            self.assertEqual(report["office_rows"], len(office))
            for role, expected_label in (("scenario", 1), ("control", 0)):
                mixed = pd.read_parquet(root / "out" / f"{role}.parquet")
                self.assertEqual(len(mixed), len(office) + 2)
                pd.testing.assert_frame_equal(
                    mixed.loc[: len(office) - 1, office.columns].reset_index(drop=True),
                    office.reset_index(drop=True),
                    check_dtype=True,
                )
                office_meta = mixed.iloc[: len(office)]
                self.assertTrue(office_meta["_natural_training_label"].isna().all())
                self.assertTrue(office_meta["_natural_role"].isna().all())
                generated = mixed.iloc[len(office) :]
                self.assertEqual(set(generated["_natural_origin"]), {"generated"})
                self.assertEqual(set(generated["_natural_role"]), {role})
                self.assertEqual(set(generated["_natural_training_label"]), {expected_label})
                self.assertEqual(set(generated["_natural_pair_id"]), {"fixture-pair"})
            self.assertEqual(
                report["endpoint_collision_check"],
                "not_evaluable_from_pseudonymized_feature_tables",
            )

    def test_schema_mismatch_is_rejected_not_silently_intersected(self):
        office_path = ROOT / "pipeline_office_full.parquet"
        added = pd.read_parquet(ROOT / "pipeline_added_full.parquet").iloc[:1]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bad = root / "bad.parquet"
            added.drop(columns=[added.columns[-1]]).to_parquet(bad, index=False)
            good = root / "good.parquet"
            added.to_parquet(good, index=False)
            with self.assertRaises(CompositionIntegrityError):
                compose_feature_alternatives(office_path, bad, good, root / "out", pair_id="p")


class FullSchemaTests(unittest.TestCase):
    def test_pipeline_contract_is_full_155_with_all_127_declared_features(self):
        report = validate_pipeline_table(
            ROOT / "pipeline_original_155.parquet",
            ROOT / "pipeline_column_dictionary.json",
        )
        self.assertEqual(report["columns"], 155)
        self.assertEqual(report["declared_features"], 127)
        self.assertEqual(report["missing_declared_features"], [])
        self.assertFalse(report["metadata_in_model_x"])

    def test_arkime_contract_preserves_all_emitted_fields_and_presence_mask(self):
        report = validate_arkime_table(ROOT / "arkime_mixed_all_fields.parquet")
        self.assertGreaterEqual(report["arkime_fields"], 813)
        self.assertTrue(report["presence_mask"])
        self.assertEqual(report["rows"], 8843)

    def test_strict_match_contract_preserves_rows_and_direction_caveat(self):
        report = validate_strict_match_table(ROOT / "matched_mixed_pipeline_arkime.parquet")
        self.assertEqual(report["rows"], 8507)
        self.assertGreaterEqual(report["columns"], 990)
        self.assertTrue(report["direction_caveat_documented"])


@unittest.skipUnless(
    os.environ.get("NATURAL_TRAFFIC_FULL_PIPELINE") == "1",
    "full production extractor smoke is CI-gated",
)
class FullPipelineIntegrationTests(unittest.TestCase):
    def test_real_tls_capture_reaches_full_155_column_pipeline_without_pcap_mutation(self):
        from test_natural_capture import NaturalCaptureIntegrationTests

        if shutil.which("openssl") is None or shutil.which("tcpdump") is None:
            self.skipTest("capture dependencies unavailable")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                    "-days", "1",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            profile = ProfileRegistry.default().resolve("linux-python-ssl")
            adapter = NaturalCaptureIntegrationTests.LocalHttpsAdapter(cert, key)
            context = GenerationContext("full-pipeline-e2e", "control", profile, 99, root / "capture")
            capability = probe_capability(profile)
            self.assertTrue(capability.supported, capability.reason)
            bundle = run_capture(
                profile,
                adapter,
                context,
                capability=capability,
                min_free_gib=0,
            )
            before = sha(bundle.pcap_path)
            result = extract_pipeline_capture(
                bundle,
                root / "extract",
                run_id="natural_e2e",
                min_free_gib=0,
                shards=1,
            )
            self.assertEqual(before, sha(bundle.pcap_path))
            report = validate_pipeline_table(
                result.parquet_path,
                ROOT / "pipeline_column_dictionary.json",
            )
            self.assertEqual(report["columns"], 155)
            self.assertEqual(report["declared_features"], 127)
            self.assertGreater(result.rows, 0)
            self.assertEqual(result.source_pcap_sha256, before)


if __name__ == "__main__":
    unittest.main()
