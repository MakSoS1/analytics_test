"""A source manifest cannot manufacture corroborated MITRE evidence or escape its root."""

from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from natural_traffic.source_manifest import load_source_manifest, verify_sources


def _sha(path):
    return sha256(path.read_bytes()).hexdigest()


class SourceManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "sources"
        self.root.mkdir()
        self.sources = []
        for i, (tech, role) in enumerate((("T1001", "verified_positive"),
                                          ("T1001", "matched_control"),
                                          ("T1071.001", "verified_positive"),
                                          ("T1071.001", "matched_control"))):
            path = self.root / f"input-{i}.csv"
            path.write_text(f"measured,{i}\n")
            source = {
                "source_id": f"source-{i}", "relative_path": path.name,
                "sha256": _sha(path), "label_state": role,
                "technique_ids": [tech], "pair_id": f"pair-{i // 2}",
                "parent_campaign_id": f"campaign-{i // 2}",
                "runtime_profile_id": "linux-ssl", "capture_group_id": f"capture-{i}",
                "capture_day_id": "2026-09-22", "measurement_vantage": "lab-nic",
                "extractor_version": "office-sessions-v1", "evidence_tier": "fixture_only",
            }
            if role == "verified_positive":
                member = self.root / f"members-{i}.jsonl"
                member.write_text(json.dumps({"source_id": f"source-{i}",
                                              "session_key": "target", "label_binary": 1,
                                              "technique_id": tech}) + "\n")
                receipt = self.root / f"receipt-{i}.json"
                receipt.write_text('{"local_fixture":true}\n')
                source.update(membership_relative_path=member.name,
                              membership_sha256=_sha(member), receipt_relative_path=receipt.name,
                              receipt_sha256=_sha(receipt))
            self.sources.append(source)

    def _manifest(self, sources=None, version="defender-source-manifest-v1"):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"version": version,
                                        "sources": self.sources if sources is None else sources}))
        return manifest

    def test_loads_independently_pinned_two_technique_pairs(self):
        result = load_source_manifest(self._manifest(), allowed_root=self.root)
        self.assertEqual(result["version"], "defender-source-manifest-v1")
        self.assertEqual({t for s in result["sources"] for t in s["technique_ids"]},
                         {"T1001", "T1071.001"})
        self.assertEqual(result["sources"][0]["path"], (self.root / "input-0.csv").resolve())
        verify_sources(result)

    def test_refuses_unrecognized_version_label_and_technique(self):
        with self.assertRaisesRegex(ValueError, "version"):
            load_source_manifest(self._manifest(version="v0"), allowed_root=self.root)
        broken = [dict(s) for s in self.sources]
        broken[0]["label_state"] = "trusted_attack"
        with self.assertRaisesRegex(ValueError, "label_state"):
            load_source_manifest(self._manifest(broken), allowed_root=self.root)
        broken[0]["label_state"] = "verified_positive"
        broken[0]["technique_ids"] = ["INVALID-T123"]
        with self.assertRaisesRegex(ValueError, "technique"):
            load_source_manifest(self._manifest(broken), allowed_root=self.root)

    def test_pinned_bytes_are_rechecked_after_loading(self):
        result = load_source_manifest(self._manifest(), allowed_root=self.root)
        (self.root / "input-0.csv").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            verify_sources(result)

    def test_refuses_positive_without_membership_evidence(self):
        broken = [dict(s) for s in self.sources]
        broken[0].pop("membership_relative_path")
        with self.assertRaisesRegex(ValueError, "membership"):
            load_source_manifest(self._manifest(broken), allowed_root=self.root)

    def test_refuses_unmatched_or_incompatible_pair(self):
        with self.assertRaisesRegex(ValueError, "pair"):
            load_source_manifest(self._manifest(self.sources[:-1]), allowed_root=self.root)
        broken = [dict(s) for s in self.sources]
        broken[1]["measurement_vantage"] = "upstream-proxy"
        with self.assertRaisesRegex(ValueError, "pair"):
            load_source_manifest(self._manifest(broken), allowed_root=self.root)

    def test_refuses_traversal_and_symlink_escape(self):
        outside = Path(self.tmp.name) / "outside.csv"
        outside.write_text("outside\n")
        broken = [dict(s) for s in self.sources]
        broken[0]["relative_path"] = "../outside.csv"
        broken[0]["sha256"] = _sha(outside)
        with self.assertRaisesRegex(ValueError, "outside source root"):
            load_source_manifest(self._manifest(broken), allowed_root=self.root)
        (self.root / "link.csv").symlink_to(outside)
        broken[0]["relative_path"] = "link.csv"
        with self.assertRaisesRegex(ValueError, "outside source root"):
            load_source_manifest(self._manifest(broken), allowed_root=self.root)

    def test_refuses_unextracted_eve_and_pcapng(self):
        for ext in (".pcapng", ".eve"):
            with self.subTest(ext=ext):
                candidate = self.root / ("unsupported" + ext)
                candidate.write_bytes(b"not measured")
                broken = [dict(s) for s in self.sources]
                broken[0]["relative_path"] = candidate.name
                broken[0]["sha256"] = _sha(candidate)
                with self.assertRaisesRegex(ValueError, "unsupported"):
                    load_source_manifest(self._manifest(broken), allowed_root=self.root)

    def test_refuses_duplicate_source_ids(self):
        broken = [dict(s) for s in self.sources]
        broken[1]["source_id"] = broken[0]["source_id"]
        with self.assertRaisesRegex(ValueError, "duplicate source_id"):
            load_source_manifest(self._manifest(broken), allowed_root=self.root)


if __name__ == "__main__":
    unittest.main()
