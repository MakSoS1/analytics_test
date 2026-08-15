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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--session-metrics", type=Path, required=True)
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
    metrics = load_json(args.session_metrics)
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
    challenge_recall = as_float(
        nested(metrics, "splits", "challenge", "strict_operating_points", "operating_points", "fpr_1pct", "recall"),
        default=as_float(nested(metrics, "splits", "challenge", "recall")),
    )
    hard_fpr = as_float(hard.get("fpr"), 1.0) if hard.get("status") == "ok" else 1.0
    ext_inputs = external.get("external_gate_inputs", {}) if isinstance(external.get("external_gate_inputs"), dict) else {}

    research_cfg = cfg.get("research", {})
    leakage_pass = bool(production.get("leakage_ok", False))
    protocol_coverage = {
        str(key): as_float(value)
        for key, value in (production.get("session_mapping_coverage_by_protocol", {}) or {}).items()
    }
    required_protocols = {"ssh", "smb", "rdp", "vnc"}
    min_protocol_coverage = as_float(research_cfg.get("min_protocol_session_mapping_coverage"), 0.95)
    protocol_mapping_pass = (
        required_protocols <= set(protocol_coverage)
        and min(protocol_coverage[name] for name in required_protocols) >= min_protocol_coverage
    )

    technical_release_ready = (
        planner.get("status") == "PASS"
        and leakage_pass
        and as_float(production.get("session_mapping_coverage")) >= as_float(research_cfg.get("min_session_mapping_coverage"), 0.98)
        and protocol_mapping_pass
        and as_float(production.get("flow_mapping_coverage")) >= 0.90
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
        "session_mapping_coverage": as_float(production.get("session_mapping_coverage")),
        "protocol_mapping_pass": protocol_mapping_pass,
        "min_protocol_mapping_coverage": min((protocol_coverage.get(name, 0.0) for name in required_protocols), default=0.0),
        "hard_benign_fpr": hard_fpr,
    }
    external_inputs = {
        "external_rows_in_train": int(hierarchical.get("external_rows_in_training_gold", 0) or 0),
        "threshold_tuning_on_external": bool(ext_inputs.get("threshold_tuning_on_external", False)),
    }
    metric_inputs = {
        "validation_pr_auc": validation_pr,
        "test_pr_auc": test_pr,
        "challenge_recall_fpr_1pct": challenge_recall,
    }
    shortcut_inputs = {
        "full_model_pr_auc": as_float(shortcut.get("full_model_pr_auc"), validation_pr),
        "time_only_pr_auc": as_float(shortcut.get("time_only_pr_auc"), 1.0),
        "current_session_only_pr_auc": as_float(shortcut.get("current_session_only_pr_auc"), 1.0),
        "best_nuisance_pr_auc": as_float(shortcut.get("best_nuisance_pr_auc"), 1.0),
    }
    thresholds = {
        "max_time_only_pr_auc": as_float(cfg.get("shortcut", {}).get("max_time_only_pr_auc"), 0.55),
        "min_full_over_current_session_margin": as_float(cfg.get("shortcut", {}).get("min_full_over_current_session_margin"), 0.05),
        "min_full_over_best_nuisance_margin": as_float(cfg.get("shortcut", {}).get("min_full_over_best_nuisance_margin"), 0.05),
        "min_validation_pr_auc": as_float(research_cfg.get("min_validation_pr_auc"), 0.60),
        "min_test_pr_auc": as_float(research_cfg.get("min_test_pr_auc"), 0.58),
        "min_session_mapping_coverage": as_float(research_cfg.get("min_session_mapping_coverage"), 0.98),
        "max_hard_benign_fpr": as_float(research_cfg.get("max_hard_benign_fpr"), 0.05),
    }
    decision = evaluate_v3_gate(
        metrics=metric_inputs,
        shortcut=shortcut_inputs,
        quality=quality_inputs,
        external=external_inputs,
        thresholds=thresholds,
    )
    if not protocol_mapping_pass:
        decision["technical_status"] = "INCOMPLETE"
        decision.setdefault("technical_failures", []).append("protocol_mapping_coverage")

    result = {
        "schema_version": 3,
        "dataset_release_status": "READY" if decision["technical_status"] == "READY" else "INCOMPLETE",
        "technical_status": decision["technical_status"],
        "technical_failures": list(dict.fromkeys(decision["technical_failures"])),
        "research_status": decision["research_status"],
        "scale_decision": decision["scale_decision"] if decision["technical_status"] == "READY" else "STOP_AT_1K",
        "research_decision": decision,
        "learning_curve": curve,
        "release_semantics": {
            "research_fail_is_preserved_as_valid_dataset_release": True,
            "primary_model_unit": "session",
            "baseline_model_unit": "flow",
            "sequence_model_unit": "campaign",
            "external_holdouts_used_for_fit": False,
            "external_holdouts_used_for_threshold_tuning": False,
            "merged_bronze_pcap_persisted": False,
            "complete_raw_wire_preserved_as_chunks": True,
        },
        "mapping_fidelity": {
            "session_mapping_coverage": production.get("session_mapping_coverage"),
            "flow_mapping_coverage": production.get("flow_mapping_coverage"),
            "session_mapping_coverage_by_protocol": protocol_coverage,
            "min_protocol_required": min_protocol_coverage,
            "protocol_mapping_pass": protocol_mapping_pass,
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
        "mapping_fidelity": result["mapping_fidelity"],
        "windows_validated": windows.get("validated_protocols", []),
    }, indent=2, sort_keys=True))
    if result["dataset_release_status"] != "READY":
        raise SystemExit("V3 technical release incomplete: " + ",".join(result["technical_failures"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
