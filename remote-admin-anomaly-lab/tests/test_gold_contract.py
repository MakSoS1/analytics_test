import json
from pathlib import Path

from adminlab.quality import validate_gold_tree

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "scripts/build_gold.py"


def test_gold_builder_requires_many_flow_mapping_and_leakage_gate():
    text = BUILD.read_text(encoding="utf-8")
    assert "map_zeek_flows_to_sessions" in text
    assert "session_mapping_coverage" in text
    assert ">= 0.95" in text or "< 0.95" in text
    assert "assign_grouped_splits" in text
    assert "audit_leakage" in text
    assert "feature_contract.yaml" in text


def test_gold_builder_persists_model_matrix_without_identifiers():
    text = BUILD.read_text(encoding="utf-8")
    assert "flow_features.parquet" in text
    assert "window_features.parquet" in text
    assert "graph_features.parquet" in text
    assert "splits.parquet" in text
    assert "labels.parquet" in text
    assert "model_matrix.parquet" in text
    assert "feature_contract.json" in text
    assert "feature_contract_sha256" in text


def test_gold_validator_accepts_complete_tree(tmp_path: Path):
    shard = tmp_path / "gold" / "A-smoke-00"
    shard.mkdir(parents=True)
    parquet_files = [
        "flow_features.parquet",
        "window_features.parquet",
        "graph_features.parquet",
        "splits.parquet",
        "labels.parquet",
        "model_matrix.parquet",
    ]
    for name in parquet_files:
        (shard / name).write_bytes(b"non-empty")

    (shard / "feature_contract.json").write_text(
        json.dumps(
            {
                "feature_contract_version": "test-v1",
                "feature_contract_sha256": "0" * 64,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    report = validate_gold_tree(shard)
    assert report["ok"] is True
    assert report["required_files"] == len(parquet_files) + 1


def test_gold_validator_rejects_invalid_feature_contract_json(tmp_path: Path):
    shard = tmp_path / "gold" / "invalid-contract"
    shard.mkdir(parents=True)
    for name in [
        "flow_features.parquet",
        "window_features.parquet",
        "graph_features.parquet",
        "splits.parquet",
        "labels.parquet",
        "model_matrix.parquet",
    ]:
        (shard / name).write_bytes(b"x")
    (shard / "feature_contract.json").write_bytes(b"not-json")

    report = validate_gold_tree(shard)
    assert report["ok"] is False
    assert "invalid feature_contract.json" in report["errors"]


def test_gold_validator_rejects_missing_model_matrix(tmp_path: Path):
    shard = tmp_path / "gold" / "broken"
    shard.mkdir(parents=True)
    (shard / "flow_features.parquet").write_bytes(b"x")
    report = validate_gold_tree(shard)
    assert report["ok"] is False
    assert "model_matrix" in " ".join(report["errors"]).lower()
