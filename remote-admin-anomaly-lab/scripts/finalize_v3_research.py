#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.v3_gate import evaluate_v3_gate


def load_json(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size <= 0:
        raise ValueError(f"required JSON missing/empty: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def nested(value: dict, *keys: str, default=None):
    current = value
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def baseline_score(shortcut: dict, name: str, default: float) -> float:
    direct = shortcut.get(f"{name}_pr_auc")
    if direct is not None:
        return as_float(direct, default)
    return as_float(nested(shortcut, "baselines", name, "validation_pr_auc"), default)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--primary-metrics", type=Path, required=True)
    parser.add_argument("--shortcut", type=Path, required=True)
    parser.add_argument("--hard-benign", type=Path, required=True)
    parser.add_argument("--external", type=Path, required=True)
    parser.add_argument("--learning-curve", type=Path, required=True)
    parser.add_argument("--planner-audit", type=Path, required=True)
    parser.add_argument("--production-quality", type=Path, required=True)
    parser.add_argument("--hierarchical-quality", type=Path, required=True)
    parser.add_argument("--bronze-quality", type=Path, required=True)
    parser.add_argument("--windows-v3", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
    metrics = load_json(args.primary_metrics)
    shortcut = load_json(args.shortcut)
    hard = load_json(args.hard_benign)
    external = load_json(args.external)
    curve = load_json(args.learning_curve)
    planner = load_json(args.planner_audit)
    production = load_json(args.production_quality)
    hierarchical = load_json(args.hierarchical_quality)
    bronze = load_json(args.bronze_quality)
    windows = load_json(args.windows_v3)

    validation_pr = as_float(nested(metrics, "splits", "validation", "pr_auc"))
    test_pr = as_float(nested(metrics, "splits", "test", "pr_auc"))
    challenge_pr = as_float(nested(metrics, "splits", "challenge", "pr_auc"))
    challenge_recall = as_float(
        nested(metrics, "splits", "challenge", "strict_operating_points", "operating_points", "fpr_1pct", "recall"),
        default=as_float(nested(metrics, "splits", "challenge", "recall")),
    )
    hard_fpr = as_float(hard.get("fpr"), 1.0) if hard.get("status") == "ok" else 1.0
    ext_inputs = external.get("external_gate_inputs", {}) if isinstance(external.get("external_gate_inputs"), dict) else {}

    research_cfg = cfg.get("research", {})
    shortcut_cfg = cfg.get("shortcut", {})
    leakage_pass = bool(production.get("leakage_ok", False))
    protocol_coverage = {
        str(key): as_float(value)
        for key, value in (production.get("session_mapping_coverage_by_protocol", {}) or {}).items()
    }
    required_protocols = {"ssh", "smb", "rdp", "vnc"}
    min_protocol_coverage = as_float(research_cfg.get("min_protocol_session_mapping_coverage"), 0.99)
    min_observed_protocol_coverage = min(
        (protocol_coverage.get(name, 0.0) for name in required_protocols),
        default=0.0,
    )
    protocol_mapping_pass = (
        required_protocols <= set(protocol_coverage)
        and min_observed_protocol_coverage >= min_protocol_coverage
    )
    causal_observability_pass = bool(nested(planner, "signal", "causal_observability", "valid", default=False))
    candidate_stream_parity = (
        production.get("production_candidate_stream") == "remote-admin flows only"
        and production.get("train_serve_feature_code") == "adminlab.online_features.EveFeatureState"
    )
    cross_heldout_state_dependency = bool(production.get("cross_heldout_state_dependency", True))
    source_identity_count = int(planner.get("source_identity_count", 0) or 0)

    technical_release_ready = (
        planner.get("status") == "PASS"
        and causal_observability_pass
        and source_identity_count >= int(cfg.get("min_source_identities", 32))
        and leakage_pass
        and as_float(production.get("session_mapping_coverage")) >= as_float(research_cfg.get("min_session_mapping_coverage"), 0.995)
        and as_float(production.get("flow_mapping_coverage")) >= as_float(research_cfg.get("min_flow_mapping_coverage"), 0.98)
        and protocol_mapping_pass
        and candidate_stream_parity
        and cross_heldout_state_dependency is False
        and int(hierarchical.get("session_rows", 0)) > 0
        and int(hierarchical.get("campaign_rows", 0)) > 0
        and bronze.get("status") == "PASS"
        and bool(bronze.get("checksums_verified"))
        and bool(bronze.get("full_raw_traffic_preserved_in_chunks"))
        and not bool(bronze.get("merged_pcap_persisted"))
    )

    quality_inputs = {
        "technical_release_ready": technical_release_ready,
        "leakage_pass": leakage_pass,
        "causal_observability_pass": causal_observability_pass,
        "candidate_stream_parity": candidate_stream_parity,
        "cross_heldout_state_dependency": cross_heldout_state_dependency,
        "session_mapping_coverage": as_float(production.get("session_mapping_coverage")),
        "flow_mapping_coverage": as_float(production.get("flow_mapping_coverage")),
        "min_protocol_mapping_coverage": min_observed_protocol_coverage,
        "hard_benign_fpr": hard_fpr,
    }
    external_inputs = {
        "external_rows_in_train": int(hierarchical.get("external_rows_in_training_gold", 0) or 0),
        "threshold_tuning_on_external": bool(ext_inputs.get("threshold_tuning_on_external", False)),
    }
    metric_inputs = {
        "validation_pr_auc": validation_pr,
        "test_pr_auc": test_pr,
        "challenge_pr_auc": challenge_pr,
        "challenge_recall_fpr_1pct": challenge_recall,
    }
    shortcut_inputs = {
        "full_model_pr_auc": as_float(shortcut.get("full_model_pr_auc"), validation_pr),
        "time_only_pr_auc": baseline_score(shortcut, "time_only", 1.0),
        "protocol_only_pr_auc": baseline_score(shortcut, "protocol_only", 1.0),
        "current_session_only_pr_auc": as_float(shortcut.get("current_session_only_pr_auc"), baseline_score(shortcut, "current_session_only", 1.0)),
        "best_nuisance_pr_auc": as_float(shortcut.get("best_nuisance_pr_auc"), 1.0),
        "prevalence_pr_auc": as_float(shortcut.get("prevalence_pr_auc"), 0.5),
        "history_only_pr_auc": as_float(shortcut.get("history_only_pr_auc"), baseline_score(shortcut, "history_only", 0.0)),
    }
    thresholds = {
        "max_time_only_pr_auc": as_float(shortcut_cfg.get("max_time_only_pr_auc"), 0.55),
        "max_protocol_only_pr_auc": as_float(shortcut_cfg.get("max_protocol_only_pr_auc"), 0.60),
        "min_full_over_current_session_margin": as_float(shortcut_cfg.get("min_full_over_current_session_margin"), 0.05),
        "min_full_over_best_nuisance_margin": as_float(shortcut_cfg.get("min_full_over_best_nuisance_margin"), 0.05),
        "min_history_over_prevalence_margin": as_float(shortcut_cfg.get("min_history_over_prevalence_margin"), 0.05),
        "min_validation_pr_auc": as_float(research_cfg.get("min_validation_pr_auc"), 0.70),
        "min_test_pr_auc": as_float(research_cfg.get("min_test_pr_auc"), 0.65),
        "min_challenge_pr_auc": as_float(research_cfg.get("min_challenge_pr_auc"), 0.65),
        "min_session_mapping_coverage": as_float(research_cfg.get("min_session_mapping_coverage"), 0.995),
        "min_flow_mapping_coverage": as_float(research_cfg.get("min_flow_mapping_coverage"), 0.98),
        "min_protocol_mapping_coverage": min_protocol_coverage,
        "max_hard_benign_fpr": as_float(research_cfg.get("max_hard_benign_fpr"), 0.01),
    }
    decision = evaluate_v3_gate(
        metrics=metric_inputs,
        shortcut=shortcut_inputs,
        quality=quality_inputs,
        external=external_inputs,
        thresholds=thresholds,
    )

    result = {
        "schema_version": 4,
        "dataset_release_status": "READY" if decision["technical_status"] == "READY" else "INCOMPLETE",
        "technical_status": decision["technical_status"],
        "technical_failures": list(dict.fromkeys(decision["technical_failures"])),
        "research_status": decision["research_status"],
        "scale_decision": decision["scale_decision"] if decision["technical_status"] == "READY" else "STOP_AT_1K",
        "research_decision": decision,
        "learning_curve": curve,
        "release_semantics": {
            "research_fail_is_preserved_as_valid_dataset_release": True,
            "primary_model_unit": "suricata_eve_flow",
            "session_model_unit": "research_only",
            "campaign_model_unit": "research_only",
            "orchestrator_session_boundary_required_at_runtime": False,
            "production_candidate_stream": "remote-admin flows only",
            "external_holdouts_used_for_fit": False,
            "external_holdouts_used_for_threshold_tuning": False,
            "merged_bronze_pcap_persisted": False,
            "complete_raw_wire_preserved_as_chunks": True,
        },
        "causal_signal": {
            "planner": planner.get("planner"),
            "label_assignment_policy": planner.get("label_assignment_policy"),
            "causal_observability_pass": causal_observability_pass,
            "source_identity_count": source_identity_count,
        },
        "mapping_fidelity": {
            "session_mapping_coverage": production.get("session_mapping_coverage"),
            "flow_mapping_coverage": production.get("flow_mapping_coverage"),
            "session_mapping_coverage_by_protocol": protocol_coverage,
            "min_protocol_required": min_protocol_coverage,
            "protocol_mapping_pass": protocol_mapping_pass,
        },
        "train_serve": {
            "feature_state": production.get("train_serve_feature_code"),
            "candidate_stream": production.get("production_candidate_stream"),
            "candidate_stream_parity": candidate_stream_parity,
            "cross_heldout_state_dependency": cross_heldout_state_dependency,
        },
        "windows_fidelity": {
            "validated_protocols": windows.get("validated_protocols", []),
            "dcom": windows.get("protocols", {}).get("dcom", {}),
            "rdp": windows.get("protocols", {}).get("rdp", {}),
        },
        "external_gate_inputs": ext_inputs,
        "evidence": {
            "planner": planner,
            "production_flow_gold": production,
            "hierarchical_gold": hierarchical,
            "bronze": bronze,
            "shortcut_audit": shortcut,
            "hard_benign": hard,
            "learning_curve": curve,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "dataset_release_status": result["dataset_release_status"],
        "research_status": result["research_status"],
        "scale_decision": result["scale_decision"],
        "failed_gates": decision["failed_gates"],
        "technical_failures": result["technical_failures"],
        "observed": decision["observed"],
        "causal_signal": result["causal_signal"],
        "mapping_fidelity": result["mapping_fidelity"],
    }, indent=2, sort_keys=True))
    if result["dataset_release_status"] != "READY":
        raise SystemExit("V3 technical release incomplete: " + ",".join(result["technical_failures"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
