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

from adminlab.v2_gate import decide_v2


def load_json(path: Path) -> dict:
    if not path.exists() or path.stat().st_size <= 0:
        raise ValueError(f"required JSON missing or empty: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def nested_float(value: dict, *keys: str, default: float = 0.0) -> float:
    current: object = value
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return float(default)
        current = current[key]
    try:
        return float(current)
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

    validation_pr = nested_float(metrics, "splits", "validation", "pr_auc")
    test_pr = nested_float(metrics, "splits", "test", "pr_auc")
    challenge_recall = nested_float(metrics, "splits", "challenge", "recall")
    hard_fpr = float(hard.get("fpr", 1.0)) if hard.get("status") == "ok" else 1.0
    best_shortcut = shortcut.get("best_baseline_pr_auc")
    best_shortcut_pr = float(best_shortcut) if best_shortcut is not None else 1.0
    ext = external.get("external_gate_inputs", {}) if isinstance(external.get("external_gate_inputs"), dict) else {}
    last_delta_raw = curve.get("last_delta_pr_auc")
    last_delta = float(last_delta_raw) if last_delta_raw is not None else 0.0

    values = {
        "validation_pr_auc": validation_pr,
        "test_pr_auc": test_pr,
        "challenge_recall_at_fpr_1pct": challenge_recall,
        "hard_benign_fpr": hard_fpr,
        "best_shortcut_pr_auc": best_shortcut_pr,
        "windows_mapped_native_protocols": int(ext.get("windows_mapped_native_protocols", 0)),
        "windows_score_distribution_finite": bool(ext.get("windows_score_distribution_finite", False)),
        "lanl_reference_complete": bool(ext.get("lanl_reference_complete", False)),
        "last_delta_pr_auc": last_delta,
    }
    thresholds = {
        key: cfg[key]
        for key in (
            "validation_pr_auc_min",
            "test_pr_auc_min",
            "shortcut_margin_min",
            "hard_benign_fpr_max",
            "challenge_recall_at_fpr_1pct_min_exclusive",
            "learning_curve_delta_for_scale",
            "windows_mapped_native_protocols_min",
        )
        if key in cfg
    }
    decision = decide_v2(values, thresholds)

    technical_failures: list[str] = []
    if planner.get("status") != "PASS":
        technical_failures.append("planner_audit")
    if not bool(production.get("leakage_ok", False)):
        technical_failures.append("production_leakage")
    if float(production.get("session_mapping_coverage", 0.0)) < 0.95:
        technical_failures.append("session_mapping_coverage")
    if float(production.get("flow_mapping_coverage", 0.0)) < 0.90:
        technical_failures.append("flow_mapping_coverage")
    if int(hierarchical.get("session_rows", 0)) <= 0:
        technical_failures.append("session_gold_empty")
    if int(hierarchical.get("campaign_rows", 0)) <= 0:
        technical_failures.append("campaign_gold_empty")

    result = {
        "schema_version": 2,
        "dataset_release_status": "READY" if not technical_failures else "INCOMPLETE",
        "technical_failures": technical_failures,
        "research_status": "PASS" if decision["automatic_gate_pass"] else "FAIL",
        "research_decision": decision,
        "scale_decision": decision["scale_decision"],
        "release_semantics": {
            "research_fail_is_preserved_as_a_valid_negative_dataset_release": True,
            "external_holdouts_used_for_fit": False,
            "external_holdouts_used_for_threshold_tuning": False,
            "primary_model_unit": "session",
            "baseline_model_unit": "flow",
            "sequence_model_unit": "campaign",
        },
        "evidence": {
            "planner": planner,
            "production_flow_gold": production,
            "hierarchical_gold": hierarchical,
            "shortcut_audit": shortcut,
            "hard_benign": hard,
            "external_gate_inputs": ext,
            "learning_curve": curve,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "dataset_release_status": result["dataset_release_status"],
        "research_status": result["research_status"],
        "scale_decision": result["scale_decision"],
        "automatic_failures": decision["automatic_failures"],
        "technical_failures": technical_failures,
        "metrics": decision["metrics"],
    }, indent=2, sort_keys=True))
    if technical_failures:
        raise SystemExit("V2 technical release gate failed: " + ",".join(technical_failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
