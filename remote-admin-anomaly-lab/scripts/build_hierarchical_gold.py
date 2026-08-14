#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
import yaml

from adminlab.campaign_gold import build_campaign_gold
from adminlab.session_gold import build_session_gold
from adminlab.v2_modeling import assert_feature_frame_safe


def _model_matrix(features: pd.DataFrame, labels: pd.DataFrame, key: str) -> pd.DataFrame:
    merged = features.merge(
        labels[[key, "label_binary", "split", "environment_id"]],
        on=key,
        how="inner",
        validate="one_to_one",
    )
    if len(merged) != len(features):
        raise ValueError(f"{key} feature/label alignment incomplete")
    model_features = merged.drop(columns=[key, "label_binary", "split", "environment_id"])
    assert_feature_frame_safe(model_features)
    matrix = model_features.copy()
    matrix["label_binary"] = merged["label_binary"].astype(int).to_numpy()
    matrix["split"] = merged["split"].astype(str).to_numpy()
    return matrix


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--contract", type=Path, default=Path("configs/v2_feature_contract.yaml"))
    args = parser.parse_args()

    gold = args.release / "gold" / args.shard
    flow_features_path = gold / "production_flow_features.parquet"
    flow_labels_path = gold / "production_flow_labels.parquet"
    if not flow_features_path.exists() or not flow_labels_path.exists():
        raise SystemExit("production flow Gold is required before hierarchical V2 Gold")

    contract = yaml.safe_load(args.contract.read_text(encoding="utf-8"))
    flow_features = pd.read_parquet(flow_features_path)
    flow_labels = pd.read_parquet(flow_labels_path)
    session_features, session_labels = build_session_gold(flow_features, flow_labels, environment_id="linux_v2")
    campaign_features, campaign_labels = build_campaign_gold(session_features, session_labels, environment_id="linux_v2")

    for required in contract["session_required_features"]:
        if required not in session_features.columns:
            raise SystemExit(f"missing required V2 session feature: {required}")
    for required in contract["campaign_required_features"]:
        if required not in campaign_features.columns:
            raise SystemExit(f"missing required V2 campaign feature: {required}")

    session_matrix = _model_matrix(session_features, session_labels, "session_id")
    campaign_matrix = _model_matrix(campaign_features, campaign_labels, "campaign_id")

    session_features.to_parquet(gold / "session_features.parquet", index=False)
    session_labels.to_parquet(gold / "session_labels.parquet", index=False)
    campaign_features.to_parquet(gold / "campaign_features.parquet", index=False)
    campaign_labels.to_parquet(gold / "campaign_labels.parquet", index=False)
    session_matrix.to_parquet(gold / "session_model_matrix.parquet", index=False)
    campaign_matrix.to_parquet(gold / "campaign_model_matrix.parquet", index=False)

    quality = {
        "schema_version": 2,
        "environment_id": "linux_v2",
        "flow_rows": int(len(flow_features)),
        "session_rows": int(len(session_features)),
        "campaign_rows": int(len(campaign_features)),
        "session_split_counts": {str(k): int(v) for k, v in session_labels["split"].value_counts().to_dict().items()},
        "campaign_split_counts": {str(k): int(v) for k, v in campaign_labels["split"].value_counts().to_dict().items()},
        "session_class_counts": {str(k): int(v) for k, v in session_labels["label_binary"].value_counts().to_dict().items()},
        "campaign_class_counts": {str(k): int(v) for k, v in campaign_labels["label_binary"].value_counts().to_dict().items()},
        "session_feature_count": int(len(session_matrix.columns) - 2),
        "campaign_feature_count": int(len(campaign_matrix.columns) - 2),
        "causal_history_policy": "strictly_prior_session_event_time",
        "external_rows_in_training_gold": 0,
    }
    if quality["session_rows"] <= 0 or quality["campaign_rows"] <= 0:
        raise SystemExit("hierarchical Gold is empty")
    (gold / "hierarchical_gold_quality.json").write_text(json.dumps(quality, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(quality, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
