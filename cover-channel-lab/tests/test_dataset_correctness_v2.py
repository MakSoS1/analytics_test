from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from coverlab.pipeline_v2 import assign_split, leakage_audit
from coverlab.train_baseline_v2 import numeric_matrix
from coverlab.validate_dataset_contract import validate


def test_trusted_background_is_challenge_only():
    row = pd.Series(
        {
            "campaign_id": "g-001-00-0",
            "experiment_stage": "G_trusted_background",
            "dataset_role": "hard_negative",
            "client_impl": "python_httpx",
            "carrier": "chatops_poll",
            "transform_chain": ["raw_utf8"],
        }
    )
    assert assign_split(row) == "challenge"

    df = pd.DataFrame(
        [
            {
                **row.to_dict(),
                "seed": 1,
                "plaintext_sha256": "x",
            }
        ]
    )
    report = leakage_audit(df, {"train": 0, "validation": 0, "test": 0, "challenge": 1})
    assert report["passed"] is True
    assert report["hard_negative_outside_challenge"] == []


def test_contract_rejects_positive_trusted_background(tmp_path: Path):
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    campaign = {
        "campaign_id": "g-001",
        "scenario_id": "CC_LOTS_01",
        "label_binary": 1,
        "label_intent": "c2",
        "attack_mapping": ["T1102"],
        "experiment_stage": "G_trusted_background",
        "dataset_role": "hard_negative",
        "expected_events": 1,
    }
    event = {"campaign_id": "g-001", "label_binary": 1}
    (manifests / "campaigns.jsonl").write_text(json.dumps(campaign) + "\n")
    (manifests / "events.jsonl").write_text(json.dumps(event) + "\n")
    report = validate(tmp_path)
    assert report["passed"] is False
    assert report["error_count"] >= 1


def test_contract_rejects_positive_lots_in_mixed(tmp_path: Path):
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    campaign = {
        "campaign_id": "d-10-00001",
        "scenario_id": "CC_LOTS_01",
        "label_binary": 1,
        "label_intent": "c2",
        "attack_mapping": ["T1071.001"],
        "experiment_stage": "D_mixed",
        "expected_events": 1,
    }
    event = {"campaign_id": "d-10-00001", "label_binary": 1}
    (manifests / "campaigns.jsonl").write_text(json.dumps(campaign) + "\n")
    (manifests / "events.jsonl").write_text(json.dumps(event) + "\n")
    report = validate(tmp_path)
    assert report["passed"] is False
    assert any("positive D_mixed" in e for e in report["errors"])


def test_model_matrix_drops_expected_events_and_preserves_missingness():
    df = pd.DataFrame(
        {
            "campaign_id": ["a", "b"],
            "label_binary": [0, 1],
            "expected_events": [3, 60],
            "packet_count": [10.0, np.nan],
            "suricata_events": [0.0, 4.0],
        }
    )
    x, cols = numeric_matrix(df)
    assert "expected_events" not in cols
    assert "packet_count__missing" in cols
    assert x.loc[0, "packet_count__missing"] == 0
    assert x.loc[1, "packet_count__missing"] == 1
