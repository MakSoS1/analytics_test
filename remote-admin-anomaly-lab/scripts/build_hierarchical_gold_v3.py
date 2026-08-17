#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.campaign_gold import build_campaign_gold
from adminlab.v2_modeling import assert_feature_frame_safe
from adminlab.v3_split_state import apply_research_session_splits, build_split_isolated_session_gold
from adminlab.v3_splits import assign_grouped_splits_v3


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _session_split_frame(flow_labels: pd.DataFrame) -> pd.DataFrame:
    required = [
        "session_id", "campaign_id", "pair_id", "label_binary", "src_host_id", "dst_host_id",
        "start_ts", "persona_id", "protocol", "client_stack", "implementation_id",
    ]
    missing = set(required) - set(flow_labels.columns)
    if missing:
        raise ValueError(f"flow labels missing V3 split metadata: {sorted(missing)}")
    rows = []
    for session_id, part in flow_labels.groupby("session_id", sort=False):
        row = {"session_id": str(session_id)}
        for column in required[1:]:
            values = part[column].dropna().astype(str).unique().tolist()
            if len(values) != 1:
                raise ValueError(f"session {session_id} inconsistent split metadata {column}: {values}")
            row[column] = values[0]
        row["label_binary"] = int(float(row["label_binary"]))
        rows.append(row)
    return pd.DataFrame(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--contract", type=Path, default=ROOT / "configs/v3_feature_contract.yaml")
    parser.add_argument("--split-seed", type=int, default=2026081403)
    args = parser.parse_args()

    gold = args.release / "gold" / args.shard
    flow_features_path = gold / "production_flow_features.parquet"
    flow_labels_path = gold / "production_flow_labels.parquet"
    if not flow_features_path.exists() or not flow_labels_path.exists():
        raise SystemExit("production flow Gold is required before hierarchical V3 Gold")

    contract = yaml.safe_load(args.contract.read_text(encoding="utf-8"))
    flow_features = pd.read_parquet(flow_features_path)
    production_flow_labels = pd.read_parquet(flow_labels_path)
    production_flow_labels_sha_before = _sha256(flow_labels_path)

    # Hierarchical research derives its own grouped session split from the mapped
    # session universe, but MUST NOT rewrite production_flow_labels.parquet. The
    # NGFW flow-primary benchmark has already been materialized against its own
    # production split in build_flow_gold_v2.py.
    session_meta = _session_split_frame(production_flow_labels)
    session_splits, split_report = assign_grouped_splits_v3(session_meta, seed=args.split_seed)
    research_flow_labels = apply_research_session_splits(production_flow_labels, session_splits)

    session_features, session_labels = build_split_isolated_session_gold(
        flow_features,
        research_flow_labels,
        environment_id="linux_v3",
    )
    campaign_features, campaign_labels = build_campaign_gold(session_features, session_labels, environment_id="linux_v3")

    for required in contract["session_required_features"]:
        if required not in session_features.columns:
            raise SystemExit(f"missing required V3 session feature: {required}")
    for required in contract["campaign_required_features"]:
        if required not in campaign_features.columns:
            raise SystemExit(f"missing required V3 campaign feature: {required}")

    session_matrix = _model_matrix(session_features, session_labels, "session_id")
    campaign_matrix = _model_matrix(campaign_features, campaign_labels, "campaign_id")

    session_features.to_parquet(gold / "session_features.parquet", index=False)
    session_labels.to_parquet(gold / "session_labels.parquet", index=False)
    campaign_features.to_parquet(gold / "campaign_features.parquet", index=False)
    campaign_labels.to_parquet(gold / "campaign_labels.parquet", index=False)
    session_matrix.to_parquet(gold / "session_model_matrix.parquet", index=False)
    campaign_matrix.to_parquet(gold / "campaign_model_matrix.parquet", index=False)

    production_flow_labels_sha_after = _sha256(flow_labels_path)
    if production_flow_labels_sha_after != production_flow_labels_sha_before:
        raise SystemExit("hierarchical Gold mutated production flow labels")

    quality = {
        "schema_version": 5,
        "environment_id": "linux_v3",
        "flow_rows": int(len(flow_features)),
        "session_rows": int(len(session_features)),
        "campaign_rows": int(len(campaign_features)),
        "session_split_counts": {str(k): int(v) for k, v in session_labels["split"].value_counts().to_dict().items()},
        "campaign_split_counts": {str(k): int(v) for k, v in campaign_labels["split"].value_counts().to_dict().items()},
        "session_class_counts": {str(k): int(v) for k, v in session_labels["label_binary"].value_counts().to_dict().items()},
        "campaign_class_counts": {str(k): int(v) for k, v in campaign_labels["label_binary"].value_counts().to_dict().items()},
        "session_feature_count": int(len(session_matrix.columns) - 2),
        "campaign_feature_count": int(len(campaign_matrix.columns) - 2),
        "causal_history_policy": "strictly_prior_event_time_with_independent_state_per_split",
        "cross_split_state_dependency": False,
        "state_partition": "split",
        "external_rows_in_training_gold": 0,
        "production_flow_labels_immutable": True,
        "production_flow_labels_sha256": production_flow_labels_sha_after,
        "research_split_scope": "detached flow-label copy for session/campaign research only",
        "split_report": split_report,
    }
    if quality["session_rows"] <= 0 or quality["campaign_rows"] <= 0:
        raise SystemExit("hierarchical V3 Gold is empty")
    (gold / "hierarchical_gold_quality.json").write_text(json.dumps(quality, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(quality, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
