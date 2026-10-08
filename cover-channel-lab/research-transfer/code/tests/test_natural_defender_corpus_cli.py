"""User-facing CLI connects immutable files, group-held-out models and office diagnostics."""

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import pandas as pd

from mitre_ml_fixture import FEATURES, TECHNIQUES, make_prepared


ROOT = Path(__file__).resolve().parents[2]
OFFICE = ROOT / "datasets" / "office-additional-days-20261008"
COVER = ROOT / "datasets" / "office-cover-20261006"


def _sha(path):
    return sha256(path.read_bytes()).hexdigest()


def _invoke(*args):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join((str(ROOT / "code"), env.get("PYTHONPATH", "")))
    return subprocess.run(
        [sys.executable, "-m", "natural_traffic.defender_corpus_cli", *map(str, args)],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=90,
    )


def _small_manifest(root):
    sources = []
    for i, (tech, label) in enumerate((("T1001", 1), ("T1001", 0),
                                      ("T1071.001", 1), ("T1071.001", 0))):
        src = root / f"source{i}.csv"
        pd.DataFrame({**{n: [1.0, 2.0] for n in FEATURES},
                      "global_session_uid": [f"member-{i}", "background"]}).to_csv(src, index=False)
        member = root / f"member{i}.jsonl"
        member.write_text(json.dumps({"source_id": f"s{i}", "session_key": f"member-{i}",
                                      "label_binary": label, "technique_id": tech}) + "\n")
        receipt = root / f"receipt{i}.json"
        receipt.write_text('{"fixture_only":true}\n')
        sources.append({
            "source_id": f"s{i}", "relative_path": src.name, "sha256": _sha(src),
            "label_state": "verified_positive" if label else "matched_control",
            "technique_ids": [tech], "pair_id": f"pair-{i // 2}",
            "parent_campaign_id": f"campaign-{i // 2}",
            "runtime_profile_id": f"run-{i // 2}", "capture_group_id": f"capture-{i}",
            "capture_day_id": "2026-09-22", "measurement_vantage": "test-nic",
            "extractor_version": "measured-fixture-v1", "evidence_tier": "fixture_only",
            "membership_relative_path": member.name, "membership_sha256": _sha(member),
            "receipt_relative_path": receipt.name, "receipt_sha256": _sha(receipt),
        })
    manifest = root / "sources.json"
    manifest.write_text(json.dumps({"version": "defender-source-manifest-v1", "sources": sources}))
    return manifest


class DefenderCorpusCliTests(unittest.TestCase):
    def test_prepare_accepts_two_mitre_techniques_and_preserves_sources(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_root = root / "sources"
            source_root.mkdir()
            manifest = _small_manifest(source_root)
            hashes = {p.name: _sha(p) for p in source_root.iterdir() if p.is_file()}
            out = root / "corpus"
            process = _invoke("prepare", "--manifest", manifest,
                              "--source-root", source_root, "--out", out)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertTrue((out / "corpus_manifest.json").exists())
            result = json.loads(process.stdout)
            self.assertEqual(result["label_counts"], {"-1": 4, "0": 2, "1": 2})
            self.assertFalse(result["production_ready"])
            self.assertEqual({p.name: _sha(p) for p in source_root.iterdir() if p.is_file()}, hashes)

    def test_invalid_manifest_and_unsupported_format_fail_without_outputs(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = root / "sources"
            sources.mkdir()
            manifest = _small_manifest(sources)
            data = json.loads(manifest.read_text())
            data["sources"][0]["sha256"] = "0" * 64
            manifest.write_text(json.dumps(data))
            out = root / "out"
            process = _invoke("prepare", "--manifest", manifest, "--source-root", sources,
                              "--out", out)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("SHA256", process.stderr)
            self.assertFalse(out.exists())

            data["sources"][0]["relative_path"] = "unsupported.pcapng"
            unsupported = sources / "unsupported.pcapng"
            unsupported.write_bytes(b"not supported")
            data["sources"][0]["sha256"] = _sha(unsupported)
            manifest.write_text(json.dumps(data))
            process = _invoke("prepare", "--manifest", manifest, "--source-root", sources,
                              "--out", out)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("unsupported source format", process.stderr)
            self.assertFalse(out.exists())

    def test_train_evaluate_and_report_use_real_pinned_office_days(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepared = root / "prepared"
            make_prepared(prepared)
            models, evaluation = root / "models", root / "evaluation"
            train = _invoke("train", "--prepared", prepared,
                            "--office-dir", OFFICE, "--out", models)
            self.assertEqual(train.returncode, 0, train.stderr)
            self.assertTrue((models / "feature_contract.json").exists())
            evaluated = _invoke("evaluate", "--prepared", prepared, "--models", models,
                                "--office-dir", OFFICE, "--office-cover-dir", COVER,
                                "--out", evaluation)
            self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
            report = json.loads((evaluation / "evaluation_report.json").read_text())
            self.assertTrue(report["pipeline_verified"])
            self.assertFalse(report["technique_research_validated"])
            self.assertFalse(report["production_ready"])
            self.assertEqual(set(report["per_technique"]), set(TECHNIQUES))
            self.assertEqual(report["office_days"]["2026-09-22"]["rows"], 4000)
            self.assertEqual(report["office_days"]["2026-09-28"]["rows"], 4002)
            printed = _invoke("report", "--evaluation", evaluation)
            self.assertEqual(printed.returncode, 0, printed.stderr)
            self.assertEqual(json.loads(printed.stdout), report)


if __name__ == "__main__":
    unittest.main()
