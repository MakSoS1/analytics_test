import json
import tempfile
import unittest
from pathlib import Path

from natural_traffic.external_reference import (
    build_reference_manifest,
    extract_mitre_technique,
    load_source_descriptor,
)
from office_injection.source import write_pcap


ROOT=Path(__file__).resolve().parents[2]
DESCRIPTOR=ROOT/"references"/"attack-replay-external.json"


class ExternalReferenceTests(unittest.TestCase):
    def test_descriptor_is_commit_pinned_and_disallows_training_calibration(self):
        source=load_source_descriptor(DESCRIPTOR)
        self.assertEqual(source.tool_commit,"5ff437bf136ee3e8c565489ece110beda7228174")
        self.assertEqual(source.pcap_commit,"0b408bff41f04e2ecd198f4e78568686e3cdcc8d")
        self.assertEqual(source.replay_semantics,"stateless_record_replay")
        self.assertFalse(source.training_eligible)
        self.assertFalse(source.naturalness_calibration_eligible)

    def test_technique_is_derived_from_path_not_invented(self):
        self.assertEqual(
            extract_mitre_technique(Path("x/T1595.001_nmap_syn_scan.pcap")),
            "T1595.001",
        )
        self.assertIsNone(extract_mitre_technique(Path("x/no-technique.pcap")))

    def test_manifest_is_ood_only_even_for_high_quality_capture(self):
        source=load_source_descriptor(DESCRIPTOR)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            target=root/"01_T1595.001_nmap_syn.pcap"
            write_pcap(target,[(1.0,b"a"*60),(1.01,b"b"*60)])
            manifest=build_reference_manifest(root,source)
            self.assertEqual(manifest["summary"]["pcaps"],1)
            row=manifest["entries"][0]
            self.assertEqual(row["technique_id"],"T1595.001")
            self.assertFalse(row["training_eligible"])
            self.assertFalse(row["naturalness_calibration_eligible"])
            self.assertTrue(row["ood_eval_eligible"])
            self.assertEqual(row["source_fidelity"],"external_recorded_pcap")
            self.assertEqual(row["replay_semantics"],"stateless_record_replay")

    def test_bad_external_capture_stays_out_of_ood_evaluation(self):
        source=load_source_descriptor(DESCRIPTOR)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            target=root/"T1595.001_bad.pcap"
            write_pcap(target,[(1.0,b"a"*60),(1.1,b"b"*60),(1.0999,b"c"*60)])
            manifest=build_reference_manifest(root,source,max_timestamp_regression_us=50)
            row=manifest["entries"][0]
            self.assertFalse(row["ood_eval_eligible"])
            self.assertEqual(row["quality"]["status"],"rejected")


if __name__=="__main__":
    unittest.main()
