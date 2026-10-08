import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from natural_traffic.corpus import (
    aggregate_extracted_tables,
    classify_cover_runtime_profile,
    discover_cover_captures,
)
from office_injection.source import write_pcap


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class NaturalCorpusTests(unittest.TestCase):
    def make_job(self, root, job_id, arm, source_profile, seed=1, status="captured"):
        d = Path(root) / job_id
        d.mkdir(parents=True)
        pcap = d / "capture.pcap"
        write_pcap(pcap, [(1.0, b"\x00" * 60), (1.1, b"\x01" * 60)])
        job = {
            "job_id": job_id,
            "entry_id": "M-HTTPS-BEACON",
            "profile_id": source_profile,
            "arm": arm,
            "seed": seed,
        }
        (d / "job.json").write_text(json.dumps(job))
        result = {
            "job_id": job_id,
            "entry_id": "M-HTTPS-BEACON",
            "profile_id": source_profile,
            "arm": arm,
            "status": status,
            "capture_sha256": sha(pcap),
            "source_fidelity": "wire_real_network",
            "evidence_sha256": {"job.json": sha(d / "job.json")},
        }
        (d / "result.json").write_text(json.dumps(result))
        return d

    def test_client_stack_is_mapped_to_declared_high_level_runtime_profile(self):
        cases = {
            "browser_chromium": "linux-chromium",
            "chromium_websocket": "linux-chromium",
            "curl_linux": "linux-curl",
            "python_httpx": "linux-python-ssl",
            "python_stdlib": "linux-python-ssl",
            "go_nethttp": "linux-protocol-native",
            "java_httpclient": "linux-protocol-native",
            "node_fetch": "linux-protocol-native",
            "rust_reqwest": "linux-protocol-native",
        }
        for client, expected in cases.items():
            self.assertEqual(classify_cover_runtime_profile({"client": client}), expected)

    def test_discovery_can_classify_high_level_profile_from_job_client(self):
        with tempfile.TemporaryDirectory() as d:
            job = self.make_job(d, "control-job", "control", "stage-profile", seed=7)
            body = json.loads((job / "job.json").read_text())
            body["profile"] = {"client": "browser_chromium"}
            (job / "job.json").write_text(json.dumps(body))
            result = json.loads((job / "result.json").read_text())
            result["evidence_sha256"]["job.json"] = sha(job / "job.json")
            (job / "result.json").write_text(json.dumps(result))
            captures = discover_cover_captures(
                Path(d), high_level_profile_id=None, role="control"
            )
            self.assertEqual(len(captures), 1)
            self.assertEqual(captures[0].high_level_profile_id, "linux-chromium")
            self.assertEqual(captures[0].bundle.profile_id, "linux-chromium")

    def test_discovery_selects_only_requested_role_and_pins_ancestor(self):
        with tempfile.TemporaryDirectory() as d:
            self.make_job(d, "control-job", "control", "curl-profile", seed=7)
            self.make_job(d, "scenario-job", "scenario", "curl-profile", seed=7)
            captures = discover_cover_captures(
                Path(d), high_level_profile_id="linux-curl", role="control"
            )
            self.assertEqual(len(captures), 1)
            capture = captures[0]
            self.assertEqual(capture.role, "control")
            self.assertEqual(capture.source_profile_id, "curl-profile")
            self.assertEqual(capture.high_level_profile_id, "linux-curl")
            self.assertEqual(capture.ancestor_id, "control-job")
            self.assertEqual(capture.bundle.pcap_sha256, sha(Path(d) / "control-job" / "capture.pcap"))

    def test_discovery_rejects_tampered_capture_and_failed_result(self):
        with tempfile.TemporaryDirectory() as d:
            good = self.make_job(d, "bad-hash", "control", "curl-profile")
            with (good / "capture.pcap").open("ab") as fh:
                fh.write(b"tamper")
            with self.assertRaisesRegex(ValueError, "hash"):
                discover_cover_captures(Path(d), high_level_profile_id="linux-curl", role="control")
        with tempfile.TemporaryDirectory() as d:
            self.make_job(d, "failed", "control", "curl-profile", status="failed")
            self.assertEqual(
                discover_cover_captures(Path(d), high_level_profile_id="linux-curl", role="control"),
                [],
            )

    def test_aggregate_adds_profile_role_seed_and_capture_ancestor(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            job = self.make_job(root / "run", "control-job", "control", "curl-profile", seed=13)
            capture = discover_cover_captures(
                root / "run", high_level_profile_id="linux-curl", role="control"
            )[0]
            features = root / "features.parquet"
            pd.DataFrame({"pkt_count": [2, 3], "flow_duration": [0.1, 0.2]}).to_parquet(features)
            out = root / "controls.parquet"
            report = aggregate_extracted_tables([(capture, features)], out)
            frame = pd.read_parquet(out)
            self.assertEqual(report["rows"], 2)
            self.assertEqual(set(frame["profile_id"]), {"linux-curl"})
            self.assertEqual(set(frame["source_profile_id"]), {"curl-profile"})
            self.assertEqual(set(frame["role"]), {"control"})
            self.assertEqual(set(frame["capture_group"]), {"control-job"})
            self.assertEqual(set(frame["seed"]), {13})
            self.assertEqual(set(frame["entry_id"]), {"M-HTTPS-BEACON"})

    def test_benign_aggregate_refuses_scenario_rows(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.make_job(root / "run", "scenario-job", "scenario", "curl-profile")
            capture = discover_cover_captures(
                root / "run", high_level_profile_id="linux-curl", role="scenario"
            )[0]
            features = root / "features.parquet"
            pd.DataFrame({"pkt_count": [2]}).to_parquet(features)
            with self.assertRaisesRegex(ValueError, "benign"):
                aggregate_extracted_tables([(capture, features)], root / "out.parquet", benign_only=True)


if __name__ == "__main__":
    unittest.main()