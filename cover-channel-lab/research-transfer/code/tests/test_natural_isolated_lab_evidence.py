"""Research capture evidence must be corroborated, matched and safe to publish."""

from hashlib import sha256
import json
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import unittest

from natural_traffic.isolated_lab_evidence import (
    COVER_MATRIX, ADAPTIX_SOURCE_COMMIT, audit_adaptix, audit_cover,
    select_cover_registry,
)
from office_injection.cover_registry import digest


def pcap_bytes():
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frame = b"\x00" * 12 + b"\x08\x00" + b"\x00" * 46
    return header + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame


class CoverLabEvidenceTests(unittest.TestCase):
    def test_selection_is_pinned_bounded_and_has_four_distinct_stack_variants(self):
        source = Path(__file__).parents[1] / "cover_runtime" / "registry.json"
        base = json.loads(source.read_text())
        selected = select_cover_registry(base)
        self.assertEqual(selected["sha256"], digest({k:v for k,v in selected.items() if k != "sha256"}))
        self.assertEqual(sum(len(entry["profiles"]) for entry in selected["entries"]), 4)
        self.assertEqual({(e["entry_id"], p["profile_id"]) for e in selected["entries"]
                          for p in e["profiles"]}, set(COVER_MATRIX))
        self.assertTrue(all(p["path_profile"] == "lab_fixed_v1" for e in selected["entries"]
                            for p in e["profiles"]))
        self.assertEqual(selected, select_cover_registry(base))
        altered = dict(base)
        altered["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "registry"):
            select_cover_registry(altered)

    def test_cover_requires_every_scenario_and_control_and_pinned_pcap(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            selected = select_cover_registry(json.loads((Path(__file__).parents[1] /
                                                        "cover_runtime" / "registry.json").read_text()))
            for entry in selected["entries"]:
                for profile in entry["profiles"]:
                    for arm in ("scenario", "control"):
                        directory = root / (entry["entry_id"] + profile["profile_id"] + arm)
                        directory.mkdir()
                        job_id = entry["entry_id"] + ":" + profile["profile_id"] + ":" + arm
                        (directory / "job.json").write_text(json.dumps({
                            "entry_id": entry["entry_id"], "profile_id": profile["profile_id"],
                            "arm": arm, "job_id": job_id, "seed": 8, "profile": profile,
                        }))
                        (directory / "capture.pcap").write_bytes(pcap_bytes())
                        (directory / "result.json").write_text(json.dumps({
                            "status": "captured", "arm": arm, "job_id": job_id,
                            "source_fidelity": "bounded_shape_generator",
                            "capture_sha256": sha256(pcap_bytes()).hexdigest(),
                            "evidence_sha256": {},
                        }))
            result = audit_cover(root, selected)
            self.assertEqual(result["verified_pairs"], 4)
            self.assertEqual(result["captures"], 8)
            self.assertFalse(result["production_ready"])
            self.assertFalse(result["office_naturalness_proven"])
            self.assertNotIn(str(root), json.dumps(result))
            self.assertNotIn("pcap_path", json.dumps(result))
            candidate = next(root.glob("*/capture.pcap"))
            candidate.write_bytes(pcap_bytes() + b"tampering")
            with self.assertRaisesRegex(ValueError, "hash"):
                audit_cover(root, selected)

    def test_missing_arm_is_not_counted_as_a_pair(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            selected = select_cover_registry(json.loads((Path(__file__).parents[1] /
                                                        "cover_runtime" / "registry.json").read_text()))
            with self.assertRaisesRegex(ValueError, "missing.*capture"):
                audit_cover(root, selected)


class AdaptixLabEvidenceTests(unittest.TestCase):
    def test_adaptix_requires_six_complete_pinned_pairs_without_exposing_task_data(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for transport in ("tcp", "mtls"):
                for profile in range(3):
                    for arm in ("scenario", "control"):
                        directory = root / f"{transport}_p{profile}" / arm
                        directory.mkdir(parents=True)
                        payload = pcap_bytes()
                        (directory / "capture.pcap").write_bytes(payload)
                        (directory / "receipt.json").write_text(json.dumps({
                            "framework": "Adaptix", "source_commit": ADAPTIX_SOURCE_COMMIT,
                            "transport": transport, "profile": profile, "arm": arm,
                            "capture_sha256": sha256(payload).hexdigest(), "verified": True,
                            "submitted": [{"at": i, "result": "SECRET_VALUE"} for i in range(6)],
                            "wire_verification": {"packet_count": 20, "whole_flow_syn": True,
                                                  "ethernet_mtu_verified": True,
                                                  "kernel_drops": 0},
                        }))
            result = audit_adaptix(root)
            self.assertEqual(result["captures"], 12)
            self.assertEqual(result["verified_pairs"], 6)
            self.assertNotIn("SECRET_VALUE", json.dumps(result))
            self.assertNotIn(str(root), json.dumps(result))
            first = root / "mtls_p1" / "scenario" / "receipt.json"
            bad = json.loads(first.read_text())
            bad["verified"] = False
            first.write_text(json.dumps(bad))
            with self.assertRaisesRegex(ValueError, "unverified"):
                audit_adaptix(root)

    def test_adaptix_does_not_accept_an_absent_run(self):
        with TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "missing"):
                audit_adaptix(Path(temp))


if __name__ == "__main__":
    unittest.main()
