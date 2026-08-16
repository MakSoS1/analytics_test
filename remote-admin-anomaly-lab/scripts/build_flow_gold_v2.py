#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.auth_features import build_split_isolated_outcome_features, enrich_ssh_auth_by_uid  # noqa: E402
from adminlab.config import load_yaml, validate_feature_contract  # noqa: E402
from adminlab.features import map_zeek_flows_to_sessions, read_zstd_json_lines, select_model_columns  # noqa: E402
from adminlab.splits import audit_leakage  # noqa: E402
from adminlab.suricata_gold import (  # noqa: E402
    attach_behavior_time,
    build_reference_context_suricata_features,
    map_suricata_flows_to_sessions,
    normalize_suricata_flow_events,
)
from adminlab.v3_splits import assign_grouped_splits_v3  # noqa: E402


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_optional_ssh(silver: Path) -> pd.DataFrame | None:
    path = silver / "zeek/ssh.log.zst"
    if path.exists() and path.stat().st_size > 0:
        return read_zstd_json_lines(path)
    return None


def build_optional_zeek_research(silver: Path, sessions: pd.DataFrame, splits: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    conn_path = silver / "zeek/conn.log.zst"
    if not conn_path.exists() or conn_path.stat().st_size <= 0:
        return pd.DataFrame(), {"status": "unavailable", "reason": "zeek conn.log missing"}
    conn = enrich_ssh_auth_by_uid(read_zstd_json_lines(conn_path), load_optional_ssh(silver))
    mapped, report = map_zeek_flows_to_sessions(sessions, conn)
    if mapped.empty:
        return pd.DataFrame(), {"status": "unavailable", "reason": "no mapped Zeek rows", "mapping": report}
    mapped = attach_behavior_time(mapped, sessions)
    split_map = splits.set_index("session_id")["split"]
    mapped["split"] = mapped["session_id"].map(split_map)
    mapped = mapped.dropna(subset=["split"])
    if mapped.empty:
        return pd.DataFrame(), {"status": "unavailable", "reason": "Zeek rows missing splits", "mapping": report}
    outcome = build_split_isolated_outcome_features(mapped)
    return outcome, {"status": "ok", "mapping": report, "rows": int(len(outcome)), "source": "zeek_conn_state_and_ssh_uid"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--shard", required=True)
    parser.add_argument("--feature-contract", type=Path, default=ROOT / "configs/feature_contract.yaml")
    parser.add_argument("--split-seed", type=int, default=2026081403)
    args = parser.parse_args()

    release = args.release.resolve()
    bronze = release / "bronze" / args.shard
    silver = release / "silver" / args.shard
    gold = release / "gold" / args.shard
    quality = release / "quality" / args.shard
    contract = load_yaml(args.feature_contract)
    validate_feature_contract(contract)
    if str(contract.get("production_source")) != "suricata_eve_flow":
        raise SystemExit("production feature contract must declare suricata_eve_flow")

    sessions = pd.read_parquet(bronze / "manifests/sessions.parquet")
    eve = read_zstd_json_lines(silver / "suricata/eve.json.zst")
    normalized = normalize_suricata_flow_events(eve)
    if normalized.empty:
        raise SystemExit("Suricata EVE contains no flow events")

    mapped, mapping_report = map_suricata_flows_to_sessions(sessions, normalized)
    mapping_report["production_source"] = "suricata_eve_flow"
    write_json(quality / "production_flow_mapping.json", mapping_report)
    if mapping_report["session_mapping_coverage"] < 0.95 or mapping_report["conn_mapping_coverage"] < 0.90:
        raise SystemExit(f"Suricata flow mapping gate failed: {mapping_report}")
    protocol_coverage = mapping_report.get("session_mapping_coverage_by_protocol", {})
    missing_protocols = sorted(
        protocol for protocol in sessions["protocol"].astype(str).unique()
        if float(protocol_coverage.get(protocol, 0.0)) < 0.90
    )
    if missing_protocols:
        raise SystemExit(f"Suricata per-protocol mapping gate failed for {missing_protocols}: {mapping_report}")
    if mapped["uid"].isna().any() or mapped["uid"].astype(str).duplicated().any():
        raise SystemExit("Suricata normalized flow_uid must be non-null and unique")

    mapped = attach_behavior_time(mapped, sessions)
    # Corrected V3 uses the same campaign/pair-connected, impact-bounded split
    # policy for both production flow Gold and hierarchical research views.
    splits, split_report = assign_grouped_splits_v3(sessions, seed=args.split_seed)
    split_index = splits.set_index("session_id")
    mapped["split"] = mapped["session_id"].map(split_index["split"])
    if mapped["split"].isna().any():
        raise SystemExit("mapped Suricata flow missing split before state computation")

    # Deployment-realistic evaluation: each held-out split gets causal prior train
    # context plus its own earlier rows, never another held-out split. This mirrors
    # an NGFW whose state was warmed before scoring future traffic while avoiding
    # validation<->test covariate contamination.
    production_features = build_reference_context_suricata_features(mapped)
    if production_features.empty or len(production_features) != len(mapped):
        raise SystemExit("Suricata train/serve feature replay incomplete")

    label_columns = [
        "session_id", "campaign_id", "scenario_id", "pair_id", "label_binary", "label_family",
        "protocol", "semantic_fidelity", "wire_fidelity", "src_host_id", "dst_host_id",
        "persona_id", "task_id", "calendar_id", "intent_profile", "behavior_profile", "campaign_type",
        "historical_relation", "auth_outcome", "client_stack", "server_stack", "implementation_id",
        "campaign_position", "campaign_size", "sequence_profile", "simulated_day", "start_ts", "end_ts",
    ]
    labels = (
        mapped[["uid", "session_id"]]
        .rename(columns={"uid": "flow_uid"})
        .merge(
            sessions[[c for c in label_columns if c in sessions.columns]],
            on="session_id",
            how="left",
            validate="many_to_one",
        )
    )
    labels["split"] = labels["session_id"].map(split_index["split"])
    labels["challenge_reason"] = labels["session_id"].map(split_index["challenge_reason"])
    aligned = production_features[["flow_uid", "session_id"]].merge(
        labels, on=["flow_uid", "session_id"], how="left", validate="one_to_one"
    )
    if len(aligned) != len(production_features) or aligned[["label_binary", "split"]].isna().any().any():
        raise SystemExit("Suricata UID-based label alignment incomplete")

    selected = select_model_columns(production_features, contract)
    required_features = set(map(str, contract.get("production_required", [])))
    missing_required = sorted(required_features - set(selected.columns))
    if missing_required:
        raise SystemExit(f"production required features unavailable: {missing_required}")
    model_matrix = selected.copy()
    model_matrix["label_binary"] = aligned["label_binary"].astype(int).to_numpy()
    model_matrix["split"] = aligned["split"].astype(str).to_numpy()
    leakage = audit_leakage(sessions, splits, list(model_matrix.columns), contract, split_report)
    if not leakage["ok"]:
        raise SystemExit(json.dumps(leakage, sort_keys=True))

    zeek_research, zeek_report = build_optional_zeek_research(silver, sessions, splits)

    gold.mkdir(parents=True, exist_ok=True)
    quality.mkdir(parents=True, exist_ok=True)
    production_features.to_parquet(gold / "production_flow_features.parquet", index=False)
    aligned.to_parquet(gold / "production_flow_labels.parquet", index=False)
    model_matrix.to_parquet(gold / "production_model_matrix.parquet", index=False)
    splits.to_parquet(gold / "production_splits.parquet", index=False)
    if not zeek_research.empty:
        zeek_research.to_parquet(gold / "research_zeek_outcome_features.parquet", index=False)
    write_json(quality / "research_zeek_features.json", zeek_report)
    write_json(quality / "production_leakage.json", leakage)

    summary = {
        "schema_version": 4,
        "rows": int(len(model_matrix)),
        "feature_count": int(len(selected.columns)),
        "raw_suricata_flow_count": mapping_report["raw_conn_count"],
        "eligible_suricata_flow_count": mapping_report["eligible_conn_count"],
        "background_suricata_flow_count": mapping_report["background_conn_count"],
        "mapped_suricata_flow_count": mapping_report["mapped_conn_count"],
        "session_mapping_coverage": mapping_report["session_mapping_coverage"],
        "flow_mapping_coverage": mapping_report["conn_mapping_coverage"],
        "session_mapping_coverage_by_protocol": protocol_coverage,
        "uid_alignment_coverage": float(len(aligned) / len(production_features)),
        "leakage_ok": True,
        "split_policy": split_report.get("policy"),
        "state_partition_policy": "prior train reference context plus prior rows from target split only; no validation/test/challenge cross-context",
        "cross_heldout_state_dependency": False,
        "time_policy": "Suricata flow.start for execution mapping; captured flow offset projected to simulated organization timestamp",
        "production_unit": "suricata_eve_flow",
        "production_source": "suricata_eve_flow",
        "production_candidate_stream": "remote-admin flows only",
        "train_serve_feature_code": "adminlab.online_features.EveFeatureState",
        "label_join_keys": ["flow_uid", "session_id"],
        "challenge_reason_counts": split_report.get("challenge_reason_counts", {}),
        "zeek_features_in_primary_model": False,
        "zeek_research_status": zeek_report.get("status"),
        "evaluation_metadata_in_model_matrix": False,
        "orchestrator_used_only_for": "labels grouped splits simulated clock and fidelity metadata",
    }
    write_json(quality / "production_flow_gold.json", summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
