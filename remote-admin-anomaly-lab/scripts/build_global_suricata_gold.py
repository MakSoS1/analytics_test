#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.config import load_yaml, validate_feature_contract  # noqa: E402
from adminlab.features import map_zeek_flows_to_sessions, read_zstd_json_lines, select_model_columns  # noqa: E402
from adminlab.splits import assign_grouped_splits, audit_leakage  # noqa: E402
from adminlab.suricata_gold import attach_behavior_time, build_split_isolated_suricata_features, normalize_suricata_flow_events  # noqa: E402


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def discover_shards(root: Path) -> list[tuple[str, Path, Path]]:
    found: list[tuple[str, Path, Path]] = []
    for sessions_path in sorted(root.rglob("bronze/*/manifests/sessions.parquet")):
        shard = sessions_path.parents[1].name
        release = sessions_path.parents[3]
        eve = release / "silver" / shard / "suricata" / "eve.json.zst"
        if eve.exists() and eve.stat().st_size > 0:
            found.append((shard, sessions_path, eve))
    if not found:
        raise SystemExit(f"no Bronze/Silver shard pairs discovered under {root}")
    names = [x[0] for x in found]
    if len(names) != len(set(names)):
        raise SystemExit(f"duplicate shard names discovered: {names}")
    return found


def namespace_sessions(local: pd.DataFrame, shard: str) -> tuple[pd.DataFrame, dict[str, str]]:
    frame = local.copy()
    local_ids = frame["session_id"].astype(str).tolist()
    session_map = {sid: f"{shard}::{sid}" for sid in local_ids}
    frame["session_id"] = frame["session_id"].astype(str).map(session_map)
    for column in ("campaign_id", "pair_id", "scenario_id"):
        if column in frame.columns:
            frame[column] = frame[column].fillna("").astype(str).map(lambda x: f"{shard}::{x}" if x else "")
    frame["shard_id"] = shard
    return frame, session_map


def scope_event_state_keys(event: dict, shard: str) -> dict:
    scoped = deepcopy(event)
    # Raw addresses remain in immutable Silver. These private replay-only strings
    # prevent independent shard histories from contaminating each other while
    # remaining excluded from the model feature vector.
    scoped["src_ip"] = f"{shard}|{event.get('src_ip','')}"
    scoped["dest_ip"] = f"{shard}|{event.get('dest_ip','')}"
    return scoped


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--feature-contract", type=Path, default=ROOT / "configs/feature_contract.yaml")
    parser.add_argument("--split-seed", type=int, default=20260828)
    args = parser.parse_args()

    contract = load_yaml(args.feature_contract)
    validate_feature_contract(contract)
    if contract.get("production_source") != "suricata_eve_flow":
        raise SystemExit("global production source must remain suricata_eve_flow")

    shard_specs = discover_shards(args.input_root.resolve())
    global_sessions_parts: list[pd.DataFrame] = []
    mapped_parts: list[pd.DataFrame] = []
    mapping_reports: dict[str, dict] = {}

    for shard, sessions_path, eve_path in shard_specs:
        local_sessions = pd.read_parquet(sessions_path)
        global_sessions, session_map = namespace_sessions(local_sessions, shard)
        global_sessions_parts.append(global_sessions)

        eve = read_zstd_json_lines(eve_path)
        normalized = normalize_suricata_flow_events(eve)
        mapped, report = map_zeek_flows_to_sessions(local_sessions, normalized)
        report["production_source"] = "suricata_eve_flow"
        if report["session_mapping_coverage"] < 0.95 or report["conn_mapping_coverage"] < 0.90:
            raise SystemExit(f"mapping gate failed for {shard}: {report}")
        mapped = attach_behavior_time(mapped, local_sessions)
        mapped["session_id"] = mapped["session_id"].astype(str).map(session_map)
        mapped["uid"] = mapped["uid"].astype(str).map(lambda x: f"{shard}::{x}")
        mapped["event"] = mapped["event"].map(lambda e: scope_event_state_keys(e, shard))
        mapped["shard_id"] = shard
        mapped_parts.append(mapped)
        mapping_reports[shard] = report

    sessions = pd.concat(global_sessions_parts, ignore_index=True)
    if sessions["session_id"].duplicated().any():
        raise SystemExit("global session IDs are not unique after namespacing")
    splits, split_report = assign_grouped_splits(sessions, seed=args.split_seed)
    split_index = splits.set_index("session_id")

    mapped = pd.concat(mapped_parts, ignore_index=True)
    mapped["split"] = mapped["session_id"].map(split_index["split"])
    if mapped["split"].isna().any():
        raise SystemExit("some global Suricata flows have no global split")
    if mapped["uid"].duplicated().any():
        raise SystemExit("global flow UID collision")

    features = build_split_isolated_suricata_features(mapped)
    if len(features) != len(mapped):
        raise SystemExit("global feature replay row mismatch")

    label_columns = [
        "session_id", "campaign_id", "scenario_id", "pair_id", "label_binary", "label_family",
        "protocol", "semantic_fidelity", "wire_fidelity", "src_host_id", "dst_host_id", "persona_id",
        "task_id", "campaign_type", "historical_relation", "client_stack", "server_stack", "implementation_id",
        "start_ts", "end_ts", "simulated_day", "campaign_position", "campaign_size", "sequence_profile", "shard_id",
    ]
    labels = (
        mapped[["uid", "session_id", "shard_id"]]
        .rename(columns={"uid": "flow_uid"})
        .merge(sessions[[c for c in label_columns if c in sessions.columns]], on=["session_id", "shard_id"], how="left", validate="many_to_one")
    )
    labels["split"] = labels["session_id"].map(split_index["split"])
    labels["challenge_reason"] = labels["session_id"].map(split_index["challenge_reason"])
    aligned = features[["flow_uid", "session_id"]].merge(labels, on=["flow_uid", "session_id"], how="left", validate="one_to_one")
    if aligned[["label_binary", "split"]].isna().any().any():
        raise SystemExit("global labels incomplete")

    selected = select_model_columns(features, contract)
    missing_required = sorted(set(map(str, contract.get("production_required", []))) - set(selected.columns))
    if missing_required:
        raise SystemExit(f"missing global required features: {missing_required}")
    matrix = selected.copy()
    matrix["label_binary"] = aligned["label_binary"].astype(int).to_numpy()
    matrix["split"] = aligned["split"].astype(str).to_numpy()
    leakage = audit_leakage(sessions, splits, list(matrix.columns), contract, split_report)
    if not leakage["ok"]:
        raise SystemExit(json.dumps(leakage, sort_keys=True))

    args.out.mkdir(parents=True, exist_ok=True)
    sessions.to_parquet(args.out / "global_sessions.parquet", index=False)
    splits.to_parquet(args.out / "global_splits.parquet", index=False)
    features.to_parquet(args.out / "production_flow_features.parquet", index=False)
    aligned.to_parquet(args.out / "production_flow_labels.parquet", index=False)
    matrix.to_parquet(args.out / "production_model_matrix.parquet", index=False)
    write_json(args.out / "mapping_reports.json", mapping_reports)
    write_json(args.out / "split_report.json", split_report)
    write_json(args.out / "leakage.json", leakage)
    summary = {
        "shards": [x[0] for x in shard_specs],
        "shard_count": len(shard_specs),
        "behavioral_sessions": int(len(sessions)),
        "production_flow_rows": int(len(matrix)),
        "feature_count": int(len(selected.columns)),
        "production_source": "suricata_eve_flow",
        "train_serve_feature_code": "adminlab.online_features.EveFeatureState",
        "state_isolation": "split-isolated and shard-scoped raw state keys; raw keys excluded from model",
        "global_splits_recomputed": True,
        "local_shard_splits_reused": False,
        "uid_alignment_coverage": 1.0,
        "leakage_ok": True,
        "heldout_personas": split_report.get("heldout_personas", []),
        "heldout_client_implementations": split_report.get("heldout_client_implementations", []),
        "challenge_reason_counts": split_report.get("challenge_reason_counts", {}),
    }
    write_json(args.out / "GLOBAL_GOLD.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
