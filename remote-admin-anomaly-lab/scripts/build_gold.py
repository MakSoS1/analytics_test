#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.config import load_yaml, validate_feature_contract  # noqa: E402
from adminlab.features import (  # noqa: E402
    aggregate_flow_features,
    build_temporal_features,
    map_zeek_flows_to_sessions,
    read_zstd_json_lines,
    select_model_columns,
)
from adminlab.quality import validate_gold_tree  # noqa: E402
from adminlab.splits import assign_grouped_splits, audit_leakage  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--feature-contract", type=Path, default=ROOT / "configs/feature_contract.yaml")
    parser.add_argument("--split-seed", type=int, default=20260814)
    args = parser.parse_args()

    release = args.release.resolve()
    bronze = release / "bronze" / args.shard
    silver = release / "silver" / args.shard
    gold = release / "gold" / args.shard
    quality = release / "quality" / args.shard
    gold.mkdir(parents=True, exist_ok=True)
    quality.mkdir(parents=True, exist_ok=True)

    sessions_path = bronze / "manifests/sessions.parquet"
    conn_path = silver / "zeek/conn.log.zst"
    if not sessions_path.is_file():
        raise SystemExit(f"missing Bronze sessions: {sessions_path}")
    if not conn_path.is_file():
        raise SystemExit(f"missing Silver Zeek conn log: {conn_path}")

    contract = load_yaml(args.feature_contract)
    validate_feature_contract(contract)
    sessions = pd.read_parquet(sessions_path)
    conn = read_zstd_json_lines(conn_path)
    if sessions.empty:
        raise SystemExit("Bronze sessions are empty")
    if conn.empty:
        raise SystemExit("Zeek conn log is empty")

    mapped_conn, mapping_report = map_zeek_flows_to_sessions(sessions, conn)
    write_json(quality / "mapping_health.json", mapping_report)
    if mapping_report["session_mapping_coverage"] < 0.95:
        raise SystemExit(
            f"session->flow mapping coverage below 0.95: {mapping_report['session_mapping_coverage']:.6f}"
        )

    flow = aggregate_flow_features(sessions, mapped_conn)
    windows, graph = build_temporal_features(sessions)
    if flow.empty:
        raise SystemExit("flow feature table is empty")

    splits, split_report = assign_grouped_splits(sessions, seed=args.split_seed)
    labels_cols = [
        "session_id",
        "campaign_id",
        "scenario_id",
        "pair_id",
        "label_binary",
        "label_family",
        "mitre_technique",
        "protocol",
        "src_role",
        "dst_role",
        "src_host_id",
        "dst_host_id",
        "netem_profile",
        "wire_fidelity",
        "semantic_fidelity",
        "start_ts",
        "end_ts",
        "status",
    ]
    labels = sessions[[c for c in labels_cols if c in sessions.columns]].merge(
        splits[["session_id", "split", "group_id"]], on="session_id", how="left", validate="one_to_one"
    )

    combined = (
        flow.merge(windows, on="session_id", how="left", validate="one_to_one")
        .merge(graph, on="session_id", how="left", validate="one_to_one")
    )
    combined = combined.sort_values("session_id").reset_index(drop=True)
    labels_for_model = labels.set_index("session_id").reindex(combined["session_id"]).reset_index()
    if labels_for_model["label_binary"].isna().any() or labels_for_model["split"].isna().any():
        raise SystemExit("mapped feature rows lost labels or split assignment")

    model_features = select_model_columns(combined, contract)
    model_matrix = model_features.copy()
    model_matrix["label_binary"] = labels_for_model["label_binary"].astype(int).to_numpy()
    model_matrix["split"] = labels_for_model["split"].astype(str).to_numpy()

    leakage_report = audit_leakage(
        sessions,
        splits,
        list(model_matrix.columns),
        contract,
        split_report,
    )
    if not leakage_report["ok"]:
        write_json(quality / "leakage_checks.json", leakage_report)
        raise SystemExit(json.dumps(leakage_report, sort_keys=True))

    flow.to_parquet(gold / "flow_features.parquet", index=False)
    windows.to_parquet(gold / "window_features.parquet", index=False)
    graph.to_parquet(gold / "graph_features.parquet", index=False)
    splits.to_parquet(gold / "splits.parquet", index=False)
    labels_for_model.to_parquet(gold / "labels.parquet", index=False)
    model_matrix.to_parquet(gold / "model_matrix.parquet", index=False)

    contract_sha = sha256(args.feature_contract)
    contract_payload = {
        "feature_contract_version": int(contract["feature_contract_version"]),
        "feature_contract_sha256": contract_sha,
        "production_allowlist": list(contract["production_allowlist"]),
        "training_only": list(contract.get("training_only", [])),
        "forbidden": list(contract.get("forbidden", [])),
        "available_model_features": list(model_features.columns),
        "missing_allowlisted_features": [
            name for name in contract["production_allowlist"] if name not in model_features.columns
        ],
    }
    write_json(gold / "feature_contract.json", contract_payload)
    write_json(quality / "leakage_checks.json", leakage_report)
    write_json(quality / "split_report.json", split_report)
    write_json(
        quality / "feature_availability.json",
        {
            "feature_contract_sha256": contract_sha,
            "available_model_features": list(model_features.columns),
            "available_count": len(model_features.columns),
            "allowlisted_count": len(contract["production_allowlist"]),
            "missing_allowlisted_features": contract_payload["missing_allowlisted_features"],
            "model_rows": int(len(model_matrix)),
            "flow_rows": int(len(flow)),
            "window_rows": int(len(windows)),
            "graph_rows": int(len(graph)),
        },
    )

    validation = validate_gold_tree(gold)
    write_json(quality / "gold_contract.json", validation)
    if not validation["ok"]:
        raise SystemExit(json.dumps(validation, sort_keys=True))

    print(
        json.dumps(
            {
                "gold": str(gold),
                "rows": int(len(model_matrix)),
                "features": int(len(model_features.columns)),
                "mapping": mapping_report,
                "splits": split_report["split_counts"],
                "leakage_ok": True,
                "feature_contract_sha256": contract_sha,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
